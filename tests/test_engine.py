"""Full-stack integration test: a real Engine with live decoys on ephemeral ports.

Simulates one small attacker: probes SSH, hits the HTTP decoy with a scanner
path, and brute-forces FTP logins. Verifies events, the credentials table and
correlated alerts all land in SQLite through the real engine wiring.
"""

from __future__ import annotations

import socket
import time

from honeyforge.config import HoneyConfig
from honeyforge.engine import Engine

from .util import HoneyTestCase, recv_all, recv_until


def make_config(tmp: str) -> HoneyConfig:
    cfg = HoneyConfig()
    cfg.storage.db_path = f"{tmp}/integration.db"
    cfg.storage.jsonl_path = f"{tmp}/events.jsonl"
    cfg.storage.uploads_dir = f"{tmp}/uploads"
    cfg.dashboard.enabled = False
    for svc in cfg.services.values():
        svc.host = "127.0.0.1"
        svc.port = 0  # ephemeral
    cfg.alerts.brute_force_threshold = 3
    cfg.alerts.cooldown = 0
    return cfg


class EngineIntegrationTests(HoneyTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.engine_config = make_config(self.tmp.name)
        self.engine = Engine(self.engine_config)
        self.engine.start()
        self.addCleanup(self.engine.stop)
        self.ports = {
            name: svc.bound_port for name, svc in self.engine.services.items()
        }
        self.assertEqual(len(self.ports), 4, "all four decoys should be listening")

    def _tcp(self, service: str) -> socket.socket:
        sock = socket.create_connection(("127.0.0.1", self.ports[service]), timeout=5)
        self.addCleanup(sock.close)
        return sock

    def test_recon_across_services_raises_alert(self) -> None:
        storage = self.engine.storage

        # 1. probe SSH (banner exchange)
        ssh = self._tcp("ssh")
        recv_until(ssh, b"\n")
        ssh.sendall(b"SSH-2.0-nmap\n")
        recv_all(ssh)

        # 2. scanner GET on HTTP
        http = self._tcp("http")
        http.sendall(b"GET /.env HTTP/1.1\r\nHost: x\r\n\r\n")
        recv_all(http)

        # 3. + 4. two FTP logins, then a third to trip brute-force
        for _ in range(3):
            ftp = self._tcp("ftp")
            recv_until(ftp, b"\n")
            ftp.sendall(b"USER admin\r\n")
            recv_until(ftp, b"\n")
            ftp.sendall(b"PASS guess%d\r\n" % int(time.time() % 1000))
            recv_until(ftp, b"\n")
            ftp.sendall(b"QUIT\r\n")
            recv_until(ftp, b"\n")

        deadline = time.time() + 5
        recon = []
        while time.time() < deadline and not recon:
            recon = [a for a in storage.recent_alerts(50) if a["alert_type"] == "recon"]
            time.sleep(0.1)
        self.assertTrue(recon, "expected a recon alert across decoys")

        deadline = time.time() + 5
        brute = []
        while time.time() < deadline and not brute:
            brute = [a for a in storage.recent_alerts(50)
                     if a["alert_type"] == "brute_force"]
            time.sleep(0.1)
        self.assertTrue(brute, "expected a brute-force alert from repeated FTP logins")

        counts = storage.counts()
        self.assertGreater(counts["events"], 0)
        self.assertGreaterEqual(counts["logins"], 3)
        self.assertGreaterEqual(counts["unique_ips"], 1)

        rows = storage.recent_events(200)
        services_seen = {row["service"] for row in rows}
        self.assertIn("ssh", services_seen)
        self.assertIn("http", services_seen)
        self.assertIn("ftp", services_seen)

    def test_engine_stop_is_idempotent(self) -> None:
        self.engine.stop()
        self.engine.stop()  # must not raise


if __name__ == "__main__":
    unittest.main()
