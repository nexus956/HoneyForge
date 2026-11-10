"""Configuration defaults, file loading and example generation."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from honeyforge.config import (SERVICE_NAMES, HoneyConfig, default_config,
                               load_config, write_example_config)


class DefaultConfigTests(unittest.TestCase):
    def test_all_services_present_with_defaults(self) -> None:
        cfg = default_config()
        self.assertEqual(set(cfg.services), set(SERVICE_NAMES))
        self.assertEqual(cfg.services["http"].port, 8080)
        self.assertEqual(cfg.services["ssh"].port, 2222)
        self.assertEqual(cfg.services["telnet"].port, 2323)
        self.assertEqual(cfg.services["ftp"].port, 2121)
        self.assertTrue(all(s.enabled for s in cfg.services.values()))

    def test_alert_defaults(self) -> None:
        cfg = default_config()
        self.assertEqual(cfg.alerts.brute_force_threshold, 5)
        self.assertEqual(cfg.alerts.brute_force_window, 300)
        self.assertTrue(cfg.alerts.enabled)

    def test_storage_defaults(self) -> None:
        cfg = default_config()
        self.assertEqual(cfg.storage.db_path, "data/honeyforge.db")
        self.assertEqual(cfg.storage.uploads_dir, "data/uploads")


class LoadConfigTests(unittest.TestCase):
    def test_example_config_round_trip(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = write_example_config(str(Path(tmp) / "honeyforge.json"))
            cfg = load_config(str(path))
            defaults = default_config()
            for name in SERVICE_NAMES:
                self.assertEqual(cfg.services[name].port, defaults.services[name].port)
                self.assertTrue(cfg.services[name].enabled)
            self.assertEqual(cfg.alerts.brute_force_threshold, 5)
            self.assertEqual(cfg.dashboard.host, "127.0.0.1")

    def test_partial_overrides_apply(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "c.json"
            p.write_text(json.dumps({
                "services": {"ssh": {"enabled": False, "port": 2225}},
                "dashboard": {"enabled": True, "port": 9090},
            }))
            cfg = load_config(str(p))
            self.assertFalse(cfg.services["ssh"].enabled)
            self.assertEqual(cfg.services["ssh"].port, 2225)
            self.assertTrue(cfg.dashboard.enabled)
            self.assertEqual(cfg.dashboard.port, 9090)
            self.assertEqual(cfg.services["http"].port, 8080)  # untouched default

    def test_unknown_keys_are_ignored(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "c.json"
            p.write_text(json.dumps({"services": {"http": {"nonsense": 1, "port": 9999}},
                                     "whatever": True}))
            cfg = load_config(str(p))
            self.assertEqual(cfg.services["http"].port, 9999)

    def test_missing_file_raises(self) -> None:
        with self.assertRaises(FileNotFoundError):
            load_config("/nonexistent/honeyforge.json")

    def test_honey_config_post_init_fills_services(self) -> None:
        cfg = HoneyConfig()  # constructed without any service dict
        self.assertEqual(set(cfg.services), set(SERVICE_NAMES))


if __name__ == "__main__":
    unittest.main()
