"""Base class shared by every decoy service.

A service is a thread that owns a listening socket. Each accepted connection
is served in its own daemon thread, records a ``connection`` event, then hands
control to :meth:`BaseHoneyService.handle_client`. Shutdown is cooperative:
``stop()`` closes the listener and sets a flag; in-flight connections finish
within their socket timeouts.
"""

from __future__ import annotations

import logging
import socket
import threading
from typing import Optional, Tuple

from ..events import Event, EventBus

log = logging.getLogger("honeyforge.service")

MAX_LINE = 8192


class LineReader:
    """Buffered line reader for a connected socket.

    Worms and brute-forcers rarely wait for prompts — they fire several
    commands back to back. A naive one-recv-per-line server discards the
    surplus when lines coalesce into a single TCP segment. This reader keeps
    the unread remainder buffered so every line is eventually consumed.
    """

    def __init__(self, conn: socket.socket, limit: int = MAX_LINE) -> None:
        self.conn = conn
        self.limit = limit
        self._buf = bytearray()

    def readline(self) -> Optional[bytes]:
        """Return one complete line (without the newline).

        Returns the partial buffer if the peer stalls mid-line, or None on
        EOF/timeout with no data at all.
        """
        while b"\n" not in self._buf and len(self._buf) < self.limit:
            try:
                chunk = self.conn.recv(min(1024, self.limit - len(self._buf)))
            except socket.timeout:
                return bytes(self._buf) if self._buf else None
            except OSError:
                return None
            if not chunk:
                return bytes(self._buf) if self._buf else None
            self._buf.extend(chunk)
        line, sep, rest = bytes(self._buf).partition(b"\n")
        if sep:
            self._buf = bytearray(rest)
            return line
        # buffer limit reached without a newline — hand it back and reset
        out = bytes(self._buf)
        self._buf.clear()
        return out

    def pending(self) -> bool:
        return bool(self._buf)


class BaseHoneyService(threading.Thread):
    """A listening decoy protocol handler."""

    name = "base"

    def __init__(self, host: str, port: int, bus: EventBus, service_name: str = "") -> None:
        super().__init__(daemon=True, name=f"honeyforge-{service_name or self.name}")
        self.host = host
        self.port = port
        self.bus = bus
        self.service = service_name or self.name
        self.timeout = 30.0
        self._stop_event = threading.Event()
        self._listener: Optional[socket.socket] = None
        self._listening = threading.Event()
        self.bound_port = port
        self.bind_error: Optional[str] = None

    # ------------------------------------------------------------- lifecycle

    def run(self) -> None:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((self.host, self.port))
            sock.listen(64)
            sock.settimeout(0.5)  # wake the loop so stop() is honoured promptly
        except OSError as exc:
            log.error("%s failed to bind %s:%s: %s", self.service, self.host, self.port, exc)
            self.bind_error = str(exc)
            self._listening.set()
            return
        self._listener = sock
        self.bound_port = sock.getsockname()[1]
        self._listening.set()
        log.debug("%s listening on %s:%s", self.service, self.host, self.bound_port)

        while not self._stop_event.is_set():
            try:
                conn, addr = sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break  # listener closed by stop()
            worker = threading.Thread(
                target=self._serve, args=(conn, addr), daemon=True, name=f"{self.service}-conn"
            )
            worker.start()
        try:
            sock.close()
        except OSError:
            pass

    def stop(self) -> None:
        self._stop_event.set()
        listener, self._listener = self._listener, None
        if listener is not None:
            try:
                listener.close()
            except OSError:
                pass

    def wait_until_listening(self, timeout: float = 5.0) -> bool:
        """Block until the listener socket is up; False if the bind failed."""
        self._listening.wait(timeout)
        return self.bind_error is None

    # -------------------------------------------------------------- helpers

    def _serve(self, conn: socket.socket, addr: Tuple[str, int]) -> None:
        src_ip, src_port = addr
        self.publish(Event(type="connection", src_ip=src_ip, src_port=src_port,
                           service=self.service, dst_port=self.bound_port))
        try:
            conn.settimeout(self.timeout)
            self.handle_client(conn, addr)
        except (socket.timeout, TimeoutError):
            pass
        except (ConnectionError, OSError):
            pass
        except Exception:  # noqa: BLE001 — decoys must survive any client behaviour
            log.exception("%s: handler error from %s", self.service, src_ip)
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def publish(self, event: Event) -> None:
        if not event.service:
            event.service = self.service
        if not event.dst_port:
            event.dst_port = self.bound_port
        try:
            self.bus.publish(event)
        except Exception:  # noqa: BLE001
            log.exception("%s: failed to publish event", self.service)

    def send(self, conn: socket.socket, data: bytes) -> None:
        conn.sendall(data)

    def send_line(self, conn: socket.socket, line: str, crlf: bool = True) -> None:
        suffix = "\r\n" if crlf else "\n"
        self.send(conn, (line + suffix).encode("utf-8", errors="replace"))

    # ----------------------------------------------------------------- api

    def handle_client(self, conn: socket.socket, addr: Tuple[str, int]) -> None:
        raise NotImplementedError("subclasses must implement handle_client")


def strip_telnet_iac(data: bytes) -> bytes:
    """Remove Telnet IAC negotiation sequences from raw client bytes."""
    out = bytearray()
    i = 0
    n = len(data)
    while i < n:
        byte = data[i]
        if byte != 0xFF:
            out.append(byte)
            i += 1
            continue
        if i + 1 >= n:
            break  # truncated IAC at buffer end — drop it
        cmd = data[i + 1]
        if cmd in (251, 252, 253, 254):  # WILL/WONT/DO/DONT <option>
            i += 3
        elif cmd == 250:  # SB ... IAC SE — skip until SE
            i += 2
            while i + 1 < n and not (data[i] == 0xFF and data[i + 1] == 240):
                i += 1
            i += 2
        elif cmd in (236, 237, 238, 239, 242, 243, 249):  # 2-byte commands
            i += 2
        elif cmd == 255:  # escaped 0xFF
            out.append(0xFF)
            i += 2
        else:  # unknown — skip the IAC byte conservatively
            i += 2
    return bytes(out)


def clean_line(data: bytes) -> str:
    """Decode raw bytes as a terminal-style input line."""
    text = strip_telnet_iac(data).decode("utf-8", errors="replace")
    text = text.replace("\r", "").replace("\x00", "")
    # honour simple in-line backspace handling
    while "\x08" in text:
        text = text.replace(" \x08", "").replace("\x08", "")
    return text.strip()
