"""FTP decoy — full command loop with passive-mode transfers.

Accepts any credential (the point is to capture it), then serves a small fake
directory listing and fake files. Uploaded files (``STOR``) are written to the
quarantine dir under their SHA-256, so repeated worm drops of the same sample
deduplicate automatically and the file can be handed to any sandbox or
malware pipeline for analysis.
"""

from __future__ import annotations

import hashlib
import logging
import socket
from pathlib import Path
from typing import Dict, Optional

from ..events import Event
from .base import BaseHoneyService, LineReader, clean_line

log = logging.getLogger("honeyforge.ftp")

MAX_TRANSFER = 16 * 1024 * 1024
FAKE_LISTING = (
    "-rw-r--r-- 1 root root  1024 Jan 01 00:00 firmware.bin\r\n"
    "-rw-r--r-- 1 root root   512 Jan 01 00:00 config_backup.tgz\r\n"
    "drwxr-xr-x 2 root root  4096 Jan 01 00:00 logs\r\n"
)
FAKE_FILES: Dict[str, bytes] = {
    "firmware.bin": b"\x00" * 1024,
    "config_backup.tgz": b"HONEYFORGE-FAKE-BACKUP\n" + b"\x00" * 64,
}


class FtpHoneyService(BaseHoneyService):
    """Classic FTP pot with upload capture."""

    name = "ftp"

    def __init__(self, host: str, port: int, bus, banner: str = "", uploads_dir: str = "",
                 save_uploads: bool = True) -> None:
        super().__init__(host, port, bus, service_name="ftp")
        self.welcome_banner = banner or "220 HoneyForge FTP server ready."
        self.uploads_dir = Path(uploads_dir) if uploads_dir else None
        self.save_uploads = save_uploads

    def handle_client(self, conn, addr) -> None:
        src_ip, src_port = addr
        state = {"user": "", "logged_in": False}
        data_listener: Optional[socket.socket] = None
        reader = LineReader(conn)

        self.send_line(conn, self.welcome_banner)
        while True:
            raw = reader.readline()
            if raw is None:
                return
            line = clean_line(raw)
            if not line:
                continue
            parts = line.split(" ", 1)
            command = parts[0].upper()
            args = parts[1].strip() if len(parts) > 1 else ""
            self.publish(Event(type="ftp_command", src_ip=src_ip, src_port=src_port,
                               service=self.service, details={"command": command,
                                                              "args": args[:256]}))
            if command == "QUIT":
                self.send_line(conn, "221 Goodbye.")
                return
            data_listener = self._handle_command(
                conn, addr, state, data_listener, command, args
            )

    # ------------------------------------------------------------- commands

    def _handle_command(self, conn, addr, state, data_listener, command: str,
                        args: str) -> Optional[socket.socket]:
        src_ip, src_port = addr

        if command == "USER":
            state["user"] = args
            self.send_line(conn, "331 Password required.")
        elif command == "PASS":
            self.publish(Event(
                type="login_attempt", src_ip=src_ip, src_port=src_port,
                service=self.service,
                details={"username": state["user"], "password": args,
                         "success": True, "via": "ftp"},
            ))
            state["logged_in"] = True
            self.send_line(conn, "230 Login successful.")
        elif command == "SYST":
            self.send_line(conn, "215 UNIX Type: L8")
        elif command == "PWD":
            self.send_line(conn, '257 "/" is current directory')
        elif command in ("CWD", "XCWD"):
            self.send_line(conn, "250 Directory changed.")
        elif command == "TYPE":
            self.send_line(conn, "200 Type set.")
        elif command == "PASV":
            data_listener = self._open_pasv_listener(conn)
        elif command in ("LIST", "NLST"):
            self._pasv_send(conn, data_listener, FAKE_LISTING.encode(), "150 Opening data")
            self.send_line(conn, "226 Transfer complete.")
        elif command == "RETR":
            payload = FAKE_FILES.get(args.split("/")[-1], b"")
            self._pasv_send(conn, data_listener, payload, "150 Opening data")
            self.send_line(conn, "226 Transfer complete.")
        elif command == "STOR":
            self._store_upload(conn, addr, data_listener, args)
        elif command == "NOOP":
            self.send_line(conn, "200 OK.")
        elif command == "FEAT":
            self.send(conn, b"211-Features:\r\n UTF8\r\n SIZE\r\n211 End\r\n")
        elif command == "SIZE":
            name = args.split("/")[-1]
            size = len(FAKE_FILES.get(name, b""))
            self.send_line(conn, f"213 {size}" if size else "550 File not found.")
        else:
            self.send_line(conn, "500 Command not understood.")
        return data_listener

    # ----------------------------------------------------------------- pasv

    def _open_pasv_listener(self, conn) -> Optional[socket.socket]:
        try:
            listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(("0.0.0.0", 0))
            listener.listen(1)
            listener.settimeout(15)
        except OSError as exc:
            log.error("ftp: cannot open PASV listener: %s", exc)
            self.send_line(conn, "425 Cannot open data connection.")
            return None
        ip, port = listener.getsockname()[:2]
        if ip == "0.0.0.0" or ip == "::":
            ip = "127.0.0.1"
        octets = ".".join(ip.split(".")) if ":" not in ip else "127.0.0.1"
        h1, h2, h3, h4 = (int(x) for x in octets.split("."))
        self.send_line(conn, f"227 Entering Passive Mode ({h1},{h2},{h3},{h4},"
                             f"{port // 256},{port % 256}).")
        return listener

    def _accept_data(self, listener: Optional[socket.socket]) -> Optional[socket.socket]:
        if listener is None:
            return None
        try:
            return listener.accept()[0]
        except (socket.timeout, OSError):
            return None
        finally:
            try:
                listener.close()
            except OSError:
                pass

    def _pasv_send(self, conn, listener: Optional[socket.socket], payload: bytes,
                   pre_status: str) -> None:
        data_conn = self._accept_data(listener)
        if data_conn is None:
            self.send_line(conn, "425 Data connection failed.")
            return
        self.send_line(conn, pre_status + " connection.")
        try:
            if payload:
                data_conn.sendall(payload)
        except OSError:
            pass
        finally:
            try:
                data_conn.close()
            except OSError:
                pass

    def _store_upload(self, conn, addr, listener: Optional[socket.socket], name: str) -> None:
        src_ip, src_port = addr
        data_conn = self._accept_data(listener)
        if data_conn is None:
            self.send_line(conn, "425 Data connection failed.")
            return
        self.send_line(conn, "150 Ready to receive.")
        chunks = bytearray()
        try:
            while len(chunks) < MAX_TRANSFER:
                block = data_conn.recv(65536)
                if not block:
                    break
                chunks.extend(block)
        except OSError:
            pass
        finally:
            try:
                data_conn.close()
            except OSError:
                pass

        payload = bytes(chunks)
        digest = hashlib.sha256(payload).hexdigest()
        magic = payload[:16].decode("latin-1", errors="replace")
        filename = (name.split("/")[-1] or "unnamed")[:128]
        saved_path = ""
        if self.save_uploads and payload and self.uploads_dir is not None:
            try:
                self.uploads_dir.mkdir(parents=True, exist_ok=True)
                target = self.uploads_dir / f"sha256_{digest}"
                target.write_bytes(payload)
                saved_path = str(target)
            except OSError:
                log.exception("ftp: failed to save upload")

        self.publish(Event(
            type="file_upload", src_ip=src_ip, src_port=src_port, service=self.service,
            details={"filename": filename, "size": len(payload), "sha256": digest,
                     "magic": magic[:8], "saved_path": saved_path},
        ))
        self.send_line(conn, "226 Transfer complete.")
