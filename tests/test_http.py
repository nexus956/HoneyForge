"""HTTP decoy end-to-end: page serving, header capture, credential POST."""

from __future__ import annotations

import socket

from honeyforge.services.http import HttpHoneyService

from .util import HoneyTestCase, recv_all


class HttpHoneyServiceTests(HoneyTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.service = HttpHoneyService("127.0.0.1", 0, self.bus,
                                        server_banner="lighttpd/1.4.54",
                                        redirect_after_login="/dashboard.html")
        self.start_service(self.service)
        self.port = self.service.bound_port

    def _request(self, raw: bytes) -> bytes:
        with socket.create_connection(("127.0.0.1", self.port), timeout=5) as sock:
            sock.sendall(raw)
            return recv_all(sock)

    def test_get_root_serves_login_page_with_server_banner(self) -> None:
        response = self._request(
            b"GET / HTTP/1.1\r\nHost: router.local\r\n"
            b"User-Agent: masscan/1.3\r\nConnection: close\r\n\r\n"
        )
        self.assertIn(b"HTTP/1.1 200 OK", response)
        self.assertIn(b"Server: lighttpd/1.4.54", response)
        self.assertIn(b"Router Management Console", response)
        self.wait_for(lambda: self.events.of_type("http_request"),
                      message="http_request event")
        details = self.events.of_type("http_request")[0].details
        self.assertEqual(details["path"], "/")
        self.assertEqual(details["user_agent"], "masscan/1.3")

    def test_post_login_captures_credentials_and_redirects(self) -> None:
        body = b"username=admin&password=hunter2"
        response = self._request(
            b"POST /login HTTP/1.1\r\nHost: router.local\r\n"
            b"Content-Type: application/x-www-form-urlencoded\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body
        )
        self.assertIn(b"HTTP/1.1 302", response)
        self.assertIn(b"Location: /dashboard.html", response)
        self.wait_for(lambda: self.events.of_type("login_attempt"),
                      message="login_attempt event")
        logins = self.events.of_type("login_attempt")
        self.assertEqual(logins[0].details["username"], "admin")
        self.assertEqual(logins[0].details["password"], "hunter2")
        # login reached the storage logins table through the harness bus
        rows = self.storage.recent_logins(10)
        self.assertEqual(len(rows), 1)
        self.assertEqual((rows[0]["username"], rows[0]["password"]), ("admin", "hunter2"))

    def test_scanner_path_triggers_web_scanner_alert(self) -> None:
        self._request(b"GET /wp-login.php HTTP/1.1\r\nHost: x\r\n\r\n")
        self.wait_for(
            lambda: any(a["alert_type"] == "web_scanner" for a in self.storage.recent_alerts(5)),
            message="web_scanner alert",
        )

    def test_get_dashboard_after_login(self) -> None:
        response = self._request(b"GET /dashboard.html HTTP/1.1\r\nHost: x\r\n\r\n")
        self.assertIn(b"System Status", response)

    def test_head_request_sends_headers_only(self) -> None:
        response = self._request(b"HEAD / HTTP/1.1\r\nHost: x\r\n\r\n")
        self.assertTrue(response.startswith(b"HTTP/1.1 200"))
        self.assertNotIn(b"<html>", response)

    def test_garbage_input_is_recorded_and_dropped(self) -> None:
        self._request(b"\x16\x03\x01\x00\x05not-http-at-all\r\n\r\n")
        self.wait_for(lambda: self.events.of_type("connection"),
                      message="connection event")


if __name__ == "__main__":
    unittest.main()
