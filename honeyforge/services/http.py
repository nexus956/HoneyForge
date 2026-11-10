"""HTTP decoy — emulates a small router/NAS admin panel.

Captures the full request line, headers, user agent and any submitted
credentials. GET requests get a believable admin login page; a credential
POST is "accepted" and redirected to a fake dashboard, which keeps automated
 Credential-stuffing tools talking long enough to fingerprint them.
"""

from __future__ import annotations

import logging
import urllib.parse
from typing import Dict, Optional, Tuple

from ..events import Event
from .base import BaseHoneyService

log = logging.getLogger("honeyforge.http")

MAX_HEAD = 16 * 1024
MAX_BODY = 64 * 1024

LOGIN_PAGE = """<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>Router Management Console</title>
<style>body{font-family:sans-serif;background:#f2f2f2;text-align:center;padding-top:8%}
.box{background:#fff;border:1px solid #ccc;border-radius:6px;
width:320px;margin:0 auto;padding:24px}
input{width:100%;margin:6px 0;padding:8px;box-sizing:border-box}
button{width:100%;margin-top:12px;padding:10px;background:#0066cc;color:#fff;
border:0;border-radius:4px}
</style></head><body><div class="box">
<h2>Router Management Console</h2>
<form method="POST" action="/login">
<input type="text" name="username" placeholder="Username" required>
<input type="password" name="password" placeholder="Password" required>
<button type="submit">Login</button>
</form></div></body></html>"""

DASHBOARD_PAGE = """<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>System Status</title></head>
<body><h1>System Status</h1>
<p>Uptime: 41 days | Firmware: 1.2.7 | WAN: connected</p>
<table border="1"><tr><th>Host</th><th>IP</th><th>MAC</th></tr>
<tr><td>desktop-01</td><td>192.168.1.100</td><td>AA:BB:CC:01:00:01</td></tr>
<tr><td>android-9</td><td>192.168.1.101</td><td>AA:BB:CC:01:00:02</td></tr>
</table></body></html>"""

REASONS = {
    200: "OK",
    301: "Moved Permanently",
    302: "Found",
    404: "Not Found",
    405: "Method Not Allowed",
    500: "Internal Server Error",
}

CRED_KEYS = ("username", "user", "login", "password", "pass", "passwd", "admin", "email")


class HttpHoneyService(BaseHoneyService):
    """A decoy web admin console."""

    name = "http"

    def __init__(self, host: str, port: int, bus, server_banner: str = "lighttpd/1.4.54",
                 redirect_after_login: str = "/dashboard.html") -> None:
        super().__init__(host, port, bus, service_name="http")
        self.server_banner = server_banner
        self.redirect_after_login = redirect_after_login

    # ------------------------------------------------------------------ loop

    def handle_client(self, conn, addr) -> None:
        head = self._read_head(conn)
        if head is None:
            return
        (method, path, version, headers), leftover = head
        body = self._read_body(conn, headers, leftover)
        self._dispatch(conn, addr, method, path, version, headers, body)

    # ----------------------------------------------------------------- parse

    def _read_head(self, conn) -> Optional[Tuple[Tuple[str, str, str, Dict[str, str]], bytes]]:
        buf = bytearray()
        while len(buf) < MAX_HEAD:
            try:
                chunk = conn.recv(4096)
            except OSError:
                return None
            if not chunk:
                break
            buf.extend(chunk)
            if b"\r\n\r\n" in buf:
                break
        raw = bytes(buf)
        head_part, sep, leftover = raw.partition(b"\r\n\r\n")
        if not sep:
            leftover = b""
        lines = head_part.decode("latin-1", errors="replace").split("\r\n")
        if not lines or not lines[0]:
            return None
        parts = lines[0].split()
        if len(parts) != 3:
            return None
        method, target, version = parts[0].upper(), parts[1], parts[2]
        path = target.split("?", 1)[0]
        query = target.split("?", 1)[1] if "?" in target else ""
        headers: Dict[str, str] = {"_query": query}
        for line in lines[1:]:
            if ":" in line:
                key, _, value = line.partition(":")
                headers[key.strip().lower()] = value.strip()
        return (method, path, version, headers), leftover

    def _read_body(self, conn, headers: Dict[str, str], leftover: bytes = b"") -> bytes:
        try:
            length = min(int(headers.get("content-length", "0")), MAX_BODY)
        except ValueError:
            length = 0
        if length <= 0:
            return b""
        chunks = bytearray(leftover[:length])
        try:
            while len(chunks) < length:
                chunk = conn.recv(min(4096, length - len(chunks)))
                if not chunk:
                    break
                chunks.extend(chunk)
            return bytes(chunks)
        except OSError:
            return bytes(chunks)

    # ---------------------------------------------------------------- router

    def _dispatch(self, conn, addr, method: str, path: str, version: str,
                  headers: Dict[str, str], body: bytes) -> None:
        src_ip, src_port = addr
        details = {
            "method": method,
            "path": path,
            "query": headers.get("_query", ""),
            "host": headers.get("host", ""),
            "user_agent": headers.get("user-agent", ""),
        }
        status = 200

        if method in ("POST", "PUT"):
            creds = self._extract_credentials(path, body)
            if creds:
                self.publish(Event(type="login_attempt", src_ip=src_ip, src_port=src_port,
                                   service=self.service, details={
                                       "username": creds[0], "password": creds[1],
                                       "success": True, "via": "http-form",
                                   }))
                details["status"] = 302
                self.publish(Event(type="http_request", src_ip=src_ip, src_port=src_port,
                                   service=self.service, details=details))
                self.send_response(conn, 302, [("Location", self.redirect_after_login)])
                return
            details["body_len"] = len(body)
            status = 404
            self.send_response(conn, 404, text="Not Found")
        elif method in ("GET", "HEAD"):
            if path == self.redirect_after_login:
                self.send_response(conn, 200, html=DASHBOARD_PAGE, head_only=(method == "HEAD"))
            else:
                self.send_response(conn, 200, html=LOGIN_PAGE, head_only=(method == "HEAD"))
        else:
            status = 405
            self.send_response(conn, 405, text="Method Not Allowed")

        details["status"] = status
        self.publish(Event(type="http_request", src_ip=src_ip, src_port=src_port,
                           service=self.service, details=details))

    def _extract_credentials(self, path: str, body: bytes) -> Optional[Tuple[str, str]]:
        """Pull a username/password pair out of a form submission."""
        try:
            fields = urllib.parse.parse_qs(body.decode("utf-8", errors="replace"),
                                           keep_blank_values=True)
        except ValueError:
            return None
        user = next((fields[k][0] for k in ("username", "user", "login", "admin", "email")
                     if k in fields), None)
        password = next((fields[k][0] for k in ("password", "pass", "passwd")
                         if k in fields), None)
        if user is None and password is None:
            return None
        return user or "", password or ""

    # --------------------------------------------------------------- response

    def send_response(self, conn, status: int, headers=None, html: str = "",
                      text: str = "", head_only: bool = False) -> None:
        body = (html if html else (text + "\n")).encode("utf-8")
        lines = [
            f"HTTP/1.1 {status} {REASONS.get(status, 'OK')}",
            f"Server: {self.server_banner}",
            "Content-Type: text/html; charset=UTF-8" if html else
            "Content-Type: text/plain; charset=UTF-8",
            f"Content-Length: {len(body)}",
            "Connection: close",
        ]
        for key, value in headers or []:
            lines.append(f"{key}: {value}")
        payload = ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1")
        if not head_only:
            payload += body
        try:
            conn.sendall(payload)
        except OSError:
            log.debug("%s: client went away before response", self.service)
