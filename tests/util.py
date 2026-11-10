"""Shared helpers for the test suite."""

from __future__ import annotations

import socket
import tempfile
import time
from pathlib import Path
from typing import List, Optional
from unittest import TestCase

from honeyforge.alerts import AlertEngine
from honeyforge.config import AlertConfig
from honeyforge.events import Event, EventBus
from honeyforge.storage import Storage


class Collector:
    """Records every event published on the bus, in order."""

    def __init__(self, bus: EventBus) -> None:
        self.events: List[Event] = []
        bus.subscribe(self.record)

    def record(self, event: Event) -> None:
        self.events.append(event)

    def of_type(self, event_type: str) -> List[Event]:
        return [e for e in self.events if e.type == event_type]


class Harness:
    """A bus + in-memory storage + alert engine wired like the real engine."""

    def __init__(self, alert_config: Optional[AlertConfig] = None,
                 uploads_dir: Optional[str] = None) -> None:
        self.bus = EventBus()
        self.storage = Storage(":memory:")
        self.collector = Collector(self.bus)
        self.bus.subscribe(self.storage.record_event)
        self.alerts = AlertEngine(self.bus, self.storage,
                                  alert_config or AlertConfig(cooldown=0))
        # Mirror Engine._record_login: login events also feed the logins table.
        self.bus.subscribe(self._record_login, "login_attempt")
        if uploads_dir:
            self.uploads_dir = Path(uploads_dir)

    def _record_login(self, event: Event) -> None:
        self.storage.record_login(
            event.ts, event.service, event.src_ip,
            str(event.details.get("username", "")),
            str(event.details.get("password", "")),
            bool(event.details.get("success", False)),
        )


def recv_until(sock: socket.socket, marker: bytes, timeout: float = 5.0) -> bytes:
    """Read from ``sock`` until ``marker`` has been seen (marker included)."""
    sock.settimeout(timeout)
    buf = bytearray()
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            break
        if not chunk:
            break
        buf.extend(chunk)
        if marker in buf:
            break
    return bytes(buf)


def recv_all(sock: socket.socket, timeout: float = 3.0) -> bytes:
    sock.settimeout(timeout)
    buf = bytearray()
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf.extend(chunk)
    except (socket.timeout, OSError):
        pass
    return bytes(buf)


class HoneyTestCase(TestCase):
    """Base test case with a temp dir and a service-starter helper."""

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="honeyforge-test-")
        self.addCleanup(self.tmp.cleanup)
        self.harness = Harness(uploads_dir=self.tmp.name)
        self.addCleanup(self.harness.storage.close)
        self.events = self.harness.collector
        self.storage = self.harness.storage
        self.alerts = self.harness.alerts
        self.bus = self.harness.bus

    def start_service(self, service) -> object:
        service.start()
        # addCleanup runs LIFO, so register join first: stop() then join().
        self.addCleanup(service.join, 2)
        self.addCleanup(service.stop)
        if not service.wait_until_listening(5):
            self.fail(f"{service.name} never started listening")
        return service

    # convenience assertions ----------------------------------------------

    def wait_for(self, predicate, timeout: float = 5.0, message: str = "condition") -> None:
        deadline = time.time() + timeout
        while time.time() < deadline:
            if predicate():
                return
            time.sleep(0.05)
        self.fail(f"timed out waiting for {message}")
