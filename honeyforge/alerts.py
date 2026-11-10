"""Real-time alert engine.

The engine subscribes to every event on the bus and correlates them per
source IP. It detects:

* brute_force  — repeated login attempts from one IP inside a time window
* recon        — one IP probing several distinct decoy services
* web_scanner  — classic scanner paths hitting the HTTP decoy
* malware_drop — an upload whose content looks like ELF / a shell script

Alerts are deduplicated per (IP, alert_type) with a configurable cooldown so
a noisy attacker does not flood the dashboard. Everything is persisted to the
``alerts`` table for the dashboard and CLI.
"""

from __future__ import annotations

import logging
import time
from collections import defaultdict, deque
from typing import Deque, Dict, List, Optional, Tuple

from .config import AlertConfig
from .events import Event, EventBus
from .storage import Storage

log = logging.getLogger("honeyforge.alerts")

SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}

# Substrings that scream "automated scanner / exploitation attempt".
SUSPICIOUS_PATH_MARKERS = (
    "/wp-admin",
    "/wp-login",
    "/.env",
    "/phpmyadmin",
    "/pma",
    "/.git",
    "/.aws",
    "/etc/passwd",
    "/proc/self",
    "/cgi-bin",
    "/manager/html",
    "/actuator",
    "/boaform",
    "/gponform",
    "/hnap1",
    "/solr",
    "/jenkins",
    "/console",
    "/login.action",
    "/api/v1/pods",
    "/vendor/phpunit",
    "/telescope",
    "/debug/",
    ".php",
    ".asp",
    ".jsp",
    "webshell",
    "shell.",
)

# Magic bytes that mark a captured upload as likely malware.
MALWARE_MAGIC = (b"\x7fELF", b"#!", b"MZ", b"\xca\xfe\xba\xbe", b"\x1f\x8b")
SUSPICIOUS_UPLOAD_NAMES = (".sh", ".bin", ".elf", ".exe", ".cgi", ".pl", ".py", "bot", "arc")


def _prune(seq: Deque[float], window: int) -> Deque[float]:
    cutoff = time.time() - window
    while seq and seq[0] < cutoff:
        seq.popleft()
    return seq


class AlertEngine:
    """Stateful correlation engine fed by the event bus."""

    def __init__(self, bus: EventBus, storage: Storage, config: AlertConfig) -> None:
        self.bus = bus
        self.storage = storage
        self.config = config
        self._logins: Dict[str, Deque[float]] = defaultdict(deque)
        self._services: Dict[str, List[Tuple[float, str]]] = defaultdict(list)
        self._last_fired: Dict[Tuple[str, str], float] = {}
        bus.subscribe(self.on_event)

    # ------------------------------------------------------------------ main

    def on_event(self, event: Event) -> None:
        if not self.config.enabled:
            return
        try:
            if event.type == "login_attempt":
                self._check_brute_force(event)
            elif event.type == "http_request":
                self._check_scanner_path(event)
            elif event.type == "file_upload":
                self._check_upload(event)
            if event.type in ("connection", "login_attempt", "command", "http_request"):
                self._check_recon(event)
        except Exception:  # noqa: BLE001 — correlation must never crash a decoy
            log.exception("alert engine failed processing %s", event.type)

    # ------------------------------------------------------------- detectors

    def _check_brute_force(self, event: Event) -> None:
        ip = event.src_ip
        window = self.config.brute_force_window
        seq = _prune(self._logins[ip], window)
        seq.append(event.ts)
        if len(seq) >= self.config.brute_force_threshold:
            self.fire(
                "brute_force",
                "high",
                ip,
                f"{len(seq)} login attempts within {window}s on "
                f"service '{event.service}'",
                {"service": event.service, "attempts": len(seq), "window": window},
            )

    def _check_recon(self, event: Event) -> None:
        ip = event.src_ip
        window = self.config.recon_window
        cutoff = time.time() - window
        seen = self._services[ip]
        seen.append((event.ts, event.service))
        self._services[ip] = [item for item in seen if item[0] >= cutoff]
        distinct = {svc for _, svc in self._services[ip]}
        if len(distinct) >= self.config.recon_services:
            self.fire(
                "recon",
                "medium",
                ip,
                f"probed {len(distinct)} decoy services within {window}s: "
                + ", ".join(sorted(distinct)),
                {"services": sorted(distinct), "window": window},
            )

    def _check_scanner_path(self, event: Event) -> None:
        if not self.config.scanner_paths:
            return
        path = str(event.details.get("path", "")).lower()
        if not path or not any(marker in path for marker in SUSPICIOUS_PATH_MARKERS):
            return
        self.fire(
            "web_scanner",
            "medium",
            event.src_ip,
            f"suspicious HTTP path probed: {event.details.get('path', '')}",
            {"path": event.details.get("path", ""), "method": event.details.get("method")},
        )

    def _check_upload(self, event: Event) -> None:
        name = str(event.details.get("filename", "")).lower()
        magic = event.details.get("magic") or ""
        magic_bytes = str(magic).encode("latin-1", errors="ignore")
        magic_hit = any(magic_bytes.startswith(m) for m in MALWARE_MAGIC)
        name_hit = any(part in name for part in SUSPICIOUS_UPLOAD_NAMES)
        if not (magic_hit or name_hit):
            return
        self.fire(
            "malware_drop",
            "critical",
            event.src_ip,
            f"likely malware uploaded via {event.service}: {event.details.get('filename', '')}",
            {
                "filename": event.details.get("filename", ""),
                "sha256": event.details.get("sha256", ""),
                "size": event.details.get("size", 0),
                "magic_match": magic_hit,
            },
        )

    # ----------------------------------------------------------------- emit

    def fire(
        self,
        alert_type: str,
        severity: str,
        src_ip: str,
        message: str,
        details: Optional[Dict[str, object]] = None,
    ) -> bool:
        """Record an alert unless an identical one fired recently for this IP."""
        now = time.time()
        key = (src_ip, alert_type)
        last = self._last_fired.get(key)
        if last is not None and now - last < self.config.cooldown:
            return False
        self._last_fired[key] = now
        self.storage.record_alert(now, alert_type, severity, src_ip, message, details)
        log.warning("ALERT [%s] %s from %s: %s", severity.upper(), alert_type, src_ip, message)
        return True

    # -------------------------------------------------------------- testing

    def reset(self) -> None:
        """Clear in-memory state (used between test scenarios)."""
        self._logins.clear()
        self._services.clear()
        self._last_fired.clear()
