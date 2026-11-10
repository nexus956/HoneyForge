"""SSH decoy: KEXINIT parser (unit) and live banner exchange (integration)."""

from __future__ import annotations

import socket
import struct
import unittest


def build_kexinit(kex=b"curve25519-sha256,ecdh-sha2-nistp256",
                  host_keys=b"rsa-sha2-512,ssh-ed25519",
                  ciphers=b"aes128-ctr,chacha20-poly1305@openssh.com") -> bytes:
    payload = bytes([20]) + b"\x00" * 16  # SSH_MSG_KEXINIT + cookie
    for name_list in (kex, host_keys, ciphers, ciphers, b"hmac-sha1", b"hmac-sha1",
                      b"none,zlib", b"none", b"", b""):
        payload += struct.pack(">I", len(name_list)) + name_list
    payload += bytes([0]) + struct.pack(">I", 0)  # first_kex_follows + reserved
    padding = b"\x00" * ((8 - (len(payload) + 1) % 8) or 8)
    packet = struct.pack(">I", len(payload) + 1 + len(padding)) + bytes([len(padding)]) + payload
    return packet + padding


from honeyforge.events import EventBus
from honeyforge.services.ssh import SshHoneyService, parse_kexinit

from .util import HoneyTestCase, recv_all


class ParseKexinitTests(unittest.TestCase):
    def test_parses_all_name_lists(self) -> None:
        packet = build_kexinit()
        (packet_len,) = struct.unpack(">I", packet[:4])
        pad_len = packet[4]
        payload = packet[5: 4 + packet_len - pad_len]
        parsed = parse_kexinit(payload)
        assert parsed is not None
        self.assertEqual(parsed["kex_algorithms"], ["curve25519-sha256", "ecdh-sha2-nistp256"])
        self.assertEqual(parsed["server_host_key_algorithms"],
                         ["rsa-sha2-512", "ssh-ed25519"])
        self.assertEqual(parsed["encryption_algorithms_client_to_server"][:2],
                         ["aes128-ctr", "chacha20-poly1305@openssh.com"])
        self.assertEqual(parsed["languages_client_to_server"], [])

    def test_rejects_wrong_message_or_truncated(self) -> None:
        self.assertIsNone(parse_kexinit(b"\x01" + b"\x00" * 40))
        self.assertIsNone(parse_kexinit(b""))
        self.assertIsNone(parse_kexinit(bytes([20]) + b"\x00" * 5))
        self.assertIsNone(parse_kexinit(bytes([20]) + b"\x00" * 16 +
                                       struct.pack(">I", 9999) + b"short"))


class SshHoneyServiceTests(HoneyTestCase):
    def test_banner_exchange_and_client_version_capture(self) -> None:
        service = SshHoneyService("127.0.0.1", 0, self.bus,
                                  banner="SSH-2.0-OpenSSH_9.6p1-Debian")
        self.start_service(service)
        with socket.create_connection(("127.0.0.1", service.bound_port), timeout=5) as sock:
            server_banner = sock.recv(256)
            self.assertIn(b"SSH-2.0-OpenSSH_9.6p1", server_banner)
            sock.sendall(b"SSH-2.0-PuTTY_Release_0.80\r\n")
            sock.sendall(build_kexinit())
            recv_all(sock)
        self.wait_for(lambda: self.events.of_type("ssh_banner"),
                      message="ssh_banner event")
        event = self.events.of_type("ssh_banner")[0]
        self.assertEqual(event.details["client_version"], "SSH-2.0-PuTTY_Release_0.80")
        self.assertIn("curve25519-sha256", event.details.get("kex_algorithms", []))

    def test_connection_event_emitted(self) -> None:
        service = SshHoneyService("127.0.0.1", 0, self.bus)
        self.start_service(service)
        with socket.create_connection(("127.0.0.1", service.bound_port), timeout=5):
            pass
        self.wait_for(lambda: self.events.of_type("connection"),
                      message="connection event")
        self.assertEqual(self.events.of_type("connection")[0].service, "ssh")


    def test_bind_failure_is_reported(self) -> None:
        """Occupying a port must surface as bind_error, not a fake listener."""
        blocker = socket.socket()
        blocker.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        blocker.bind(("127.0.0.1", 0))
        blocker.listen(1)
        self.addCleanup(blocker.close)
        taken_port = blocker.getsockname()[1]

        service = SshHoneyService("127.0.0.1", taken_port, EventBus())
        service.start()
        self.addCleanup(service.join, 2)
        self.assertFalse(service.wait_until_listening(5))
        self.assertIn("Address already in use", service.bind_error or "")


if __name__ == "__main__":
    unittest.main()
