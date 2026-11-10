"""Alert engine: brute force, recon, scanner paths, malware drops, dedupe."""

from __future__ import annotations

import unittest

from honeyforge.config import AlertConfig
from honeyforge.events import Event

from .util import Harness


def login(ip: str, service: str = "telnet") -> Event:
    return Event(type="login_attempt", src_ip=ip, service=service,
                 details={"username": "root", "password": "admin", "success": True})


class AlertEngineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.harness = Harness(AlertConfig(enabled=True, brute_force_threshold=3,
                                           brute_force_window=60, recon_services=3,
                                           recon_window=120, cooldown=999))
        self.addCleanup(self.harness.storage.close)
        self.bus = self.harness.bus
        self.storage = self.harness.storage

    def _alerts(self):
        return self.storage.recent_alerts(50)

    def test_brute_force_fires_at_threshold(self) -> None:
        for _ in range(3):
            self.bus.publish(login("10.9.9.9"))
        brute = [a for a in self._alerts() if a["alert_type"] == "brute_force"]
        self.assertEqual(len(brute), 1)
        self.assertEqual(brute[0]["severity"], "high")
        self.assertEqual(brute[0]["src_ip"], "10.9.9.9")

    def test_below_threshold_is_silent(self) -> None:
        for _ in range(2):
            self.bus.publish(login("10.9.9.8"))
        self.assertEqual([a for a in self._alerts() if a["alert_type"] == "brute_force"], [])

    def test_cooldown_deduplicates_repeated_alerts(self) -> None:
        for _ in range(3):
            self.bus.publish(login("10.9.9.7"))
        for _ in range(3):
            self.bus.publish(login("10.9.9.7"))
        brute = [a for a in self._alerts() if a["alert_type"] == "brute_force"]
        self.assertEqual(len(brute), 1)  # cooldown=999 in setup

    def test_recon_when_multiple_services_touched(self) -> None:
        for service in ("http", "ssh", "ftp"):
            self.bus.publish(Event(type="connection", src_ip="10.7.7.7", service=service))
        recon = [a for a in self._alerts() if a["alert_type"] == "recon"]
        self.assertEqual(len(recon), 1)
        self.assertEqual(recon[0]["severity"], "medium")
        self.assertIn("http", recon[0]["message"])

    def test_no_recon_under_two_services(self) -> None:
        for service in ("http", "ssh"):
            self.bus.publish(Event(type="connection", src_ip="10.7.7.6", service=service))
        self.assertEqual([a for a in self._alerts() if a["alert_type"] == "recon"], [])

    def test_web_scanner_path_detection(self) -> None:
        self.bus.publish(Event(type="http_request", src_ip="10.5.5.5", service="http",
                               details={"method": "GET", "path": "/wp-admin/setup.php"}))
        scan = [a for a in self._alerts() if a["alert_type"] == "web_scanner"]
        self.assertEqual(len(scan), 1)

    def test_benign_path_no_alert(self) -> None:
        self.bus.publish(Event(type="http_request", src_ip="10.5.5.4", service="http",
                               details={"method": "GET", "path": "/"}))
        self.assertEqual([a for a in self._alerts() if a["alert_type"] == "web_scanner"], [])

    def test_malware_drop_on_suspicious_upload(self) -> None:
        self.bus.publish(Event(type="file_upload", src_ip="10.4.4.4", service="ftp",
                               details={"filename": "bot.sh", "size": 12,
                                        "sha256": "ab" * 32, "magic": "#!/bin/sh"}))
        drop = [a for a in self._alerts() if a["alert_type"] == "malware_drop"]
        self.assertEqual(len(drop), 1)
        self.assertEqual(drop[0]["severity"], "critical")

    def test_elf_magic_triggers_even_with_boring_name(self) -> None:
        self.bus.publish(Event(type="file_upload", src_ip="10.4.4.3", service="ftp",
                               details={"filename": "photo.jpg", "size": 8,
                                        "sha256": "cd" * 32, "magic": "\x7fELF\x02\x01"}))
        self.assertEqual(len([a for a in self._alerts()
                              if a["alert_type"] == "malware_drop"]), 1)

    def test_disabled_engine_stays_silent(self) -> None:
        harness = Harness(AlertConfig(enabled=False))
        self.addCleanup(harness.storage.close)
        harness.bus.publish(login("10.0.0.1"))
        harness.bus.publish(login("10.0.0.1"))
        self.assertEqual(harness.storage.recent_alerts(5), [])

    def test_bad_details_do_not_crash_engine(self) -> None:
        # details lacking expected keys must never raise
        self.bus.publish(Event(type="http_request", src_ip="1.1.1.1", service="http"))
        self.bus.publish(Event(type="file_upload", src_ip="1.1.1.1", service="ftp",
                               details={}))
        self.bus.publish(Event(type="login_attempt", src_ip="1.1.1.1"))


if __name__ == "__main__":
    unittest.main()
