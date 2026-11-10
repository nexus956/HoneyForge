"""Built-in web dashboard — stdlib HTTP server, zero frontend dependencies.

The dashboard reads the same SQLite database the honeypots write to (WAL mode
makes this safe under load). It serves one HTML page and a small JSON API:

    GET /                dashboard UI
    GET /api/summary     counts, top lists and a 24h activity timeline
    GET /api/events      recent events
    GET /api/logins      captured credentials
    GET /api/alerts      recent alerts
"""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict
from urllib.parse import parse_qs, urlparse

from ..storage import Storage

TEMPLATE_PATH = Path(__file__).parent / "templates" / "dashboard.html"
MAX_LIMIT = 500


class DashboardServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, handler, storage: Storage) -> None:
        super().__init__(address, handler)
        self.storage = storage


class DashboardHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server: "DashboardServer"

    # ------------------------------------------------------------ plumbing

    def log_message(self, fmt: str, *args: Any) -> None:  # silence stdlib noise
        pass

    def _send(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, payload: Any, status: int = 200) -> None:
        self._send(status, json.dumps(payload, default=str).encode(),
                   "application/json")

    # -------------------------------------------------------------- routes

    def do_GET(self) -> None:  # noqa: N802 — stdlib naming
        parsed = urlparse(self.path)
        route = parsed.path
        params = parse_qs(parsed.query)
        limit = max(1, min(MAX_LIMIT, int(params.get("limit", ["50"])[0])))
        storage = self.server.storage

        if route in ("/", "/index.html"):
            try:
                body = TEMPLATE_PATH.read_bytes()
            except OSError:
                self._send(500, b"dashboard template missing", "text/plain")
                return
            self._send(200, body, "text/html; charset=utf-8")
        elif route == "/api/summary":
            self._json(self._summary(storage))
        elif route == "/api/events":
            self._json(storage.recent_events(limit))
        elif route == "/api/logins":
            self._json(storage.recent_logins(limit))
        elif route == "/api/alerts":
            self._json(storage.recent_alerts(limit))
        else:
            self._json({"error": "not found", "path": route}, 404)

    # -------------------------------------------------------------- summary

    @staticmethod
    def _summary(storage: Storage) -> Dict[str, Any]:
        counts = storage.counts()
        return {
            "counts": counts,
            "top_ips": storage.top_ips(10),
            "top_services": storage.top_services(10),
            "top_paths": storage.top_http_paths(10),
            "top_credentials": storage.top_credentials(10),
            "timeline": storage.timeline(24, 24),
            "recent_alerts": storage.recent_alerts(10),
        }


def make_dashboard_server(storage: Storage, host: str, port: int) -> DashboardServer:
    return DashboardServer((host, port), DashboardHandler, storage)


def run_dashboard(storage: Storage, host: str, port: int) -> None:
    server = make_dashboard_server(storage, host, port)
    try:
        server.serve_forever()
    finally:
        server.server_close()
