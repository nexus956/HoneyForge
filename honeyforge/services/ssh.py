"""SSH decoy — banner exchange and KEXINIT fingerprinting.

A full SSH handshake needs crypto that the standard library does not ship, so
this decoy does what no-honeypot scanners and fingerprinters actually need:
it completes the protocol version exchange, captures the client's version
string, then reads the client's unencrypted KEXINIT packet and records the
algorithms it advertises. That is enough to fingerprint the attacking tool
(scripts vs. Paramiko vs. libssh2 all look different) without implementing
any cryptography. The connection is then dropped, which scanners see as a
flaky server — exactly what mass-scanner traps want to look like.
"""

from __future__ import annotations

import logging
import struct
from typing import Dict, List, Optional

from ..events import Event
from .base import BaseHoneyService

log = logging.getLogger("honeyforge.ssh")

SSH_MSG_KEXINIT = 20
MAX_BANNER = 255
MAX_PACKET = 4096


def parse_kexinit(payload: bytes) -> Optional[Dict[str, List[str]]]:
    """Parse an SSH_MSG_KEXINIT payload into its name-lists.

    Returns None if ``payload`` is not a KEXINIT message or is truncated.
    """
    if len(payload) < 17 or payload[0] != SSH_MSG_KEXINIT:
        return None
    names = (
        "kex_algorithms",
        "server_host_key_algorithms",
        "encryption_algorithms_client_to_server",
        "encryption_algorithms_server_to_client",
        "mac_algorithms_client_to_server",
        "mac_algorithms_server_to_client",
        "compression_algorithms_client_to_server",
        "compression_algorithms_server_to_client",
        "languages_client_to_server",
        "languages_server_to_client",
    )
    offset = 1 + 16  # message id + cookie
    out: Dict[str, List[str]] = {}
    for field in names:
        if offset + 4 > len(payload):
            return None
        (length,) = struct.unpack_from(">I", payload, offset)
        offset += 4
        if offset + length > len(payload):
            return None
        out[field] = (payload[offset:offset + length]
                      .decode("ascii", errors="replace").split(",")
                      if length else [])
        offset += length
    return out


class SshHoneyService(BaseHoneyService):
    """Banner-grabbing SSH decoy."""

    name = "ssh"

    def __init__(self, host: str, port: int, bus, banner: str = "SSH-2.0-OpenSSH_9.6p1") -> None:
        super().__init__(host, port, bus, service_name="ssh")
        self.ssh_banner = banner

    def handle_client(self, conn, addr) -> None:
        src_ip, src_port = addr
        # Servers conventionally speak first.
        self.send(conn, (self.ssh_banner + "\r\n").encode("ascii"))

        # The client's version banner and the KEXINIT packet often arrive in
        # the same TCP segment, so reads share one buffer and never over-read.
        buf = bytearray()
        line = self._recv_line_into(conn, buf)
        if line is None:
            return
        client_version = line.strip(b"\r").decode("utf-8", errors="replace")[:MAX_BANNER]
        if not client_version.startswith("SSH-"):
            log.debug("ssh: non-SSH banner from peer: %r", client_version[:64])
        details: Dict[str, object] = {"client_version": client_version}

        kexinit = self._recv_kexinit(conn, buf)
        if kexinit is not None:
            details["kex_algorithms"] = kexinit.get("kex_algorithms", [])[:8]
            details["host_key_algorithms"] = kexinit.get("server_host_key_algorithms", [])[:8]
            details["ciphers"] = kexinit.get("encryption_algorithms_client_to_server", [])[:8]
        self.publish(Event(type="ssh_banner", src_ip=src_ip, src_port=src_port,
                           service=self.service, details=details))

    def _recv_line_into(self, conn, buf: bytearray) -> Optional[bytes]:
        """Read from ``buf``/socket until a newline; the rest stays in ``buf``."""
        while b"\n" not in buf:
            try:
                chunk = conn.recv(MAX_BANNER + 2)
            except OSError:
                return None
            if not chunk:
                return bytes(buf) if buf else None
            buf.extend(chunk)
        line, _, _ = bytes(buf).partition(b"\n")
        del buf[: len(line) + 1]
        return line

    def _recv_kexinit(self, conn, buf: bytearray) -> Optional[Dict[str, List[str]]]:
        """Read one binary packet (from ``buf`` first) and parse it as KEXINIT."""
        try:
            header = self._fill(conn, buf, 5)
            if len(header) < 5:
                return None
            (packet_len,) = struct.unpack(">I", header[:4])
            padding_len = header[4]
            if not 0 < packet_len <= MAX_PACKET:
                return None
            rest = self._fill(conn, buf, packet_len - 1)
            payload = rest[: packet_len - 1 - padding_len]
            return parse_kexinit(payload)
        except (OSError, struct.error):
            return None

    def _fill(self, conn, buf: bytearray, count: int) -> bytes:
        """Take ``count`` bytes from ``buf``, topping it up from the socket."""
        while len(buf) < count:
            try:
                chunk = conn.recv(min(2048, count - len(buf)))
            except OSError:
                break
            if not chunk:
                break
            buf.extend(chunk)
        out = bytes(buf[:count])
        del buf[:count]
        return out
