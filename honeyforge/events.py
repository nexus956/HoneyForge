"""Event types and the thread-safe in-process event bus.

Every decoy service publishes events (connections, logins, commands, HTTP
requests, uploads, ...). Subscribers — the SQLite/JSONL writers, the alert
engine and the dashboard — react to them.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import asdict, dataclass, field
from typing import Callable, Dict, List, Optional

log = logging.getLogger("honeyforge.events")


class EventType:
    """String constants for the event types HoneyForge emits."""

    CONNECTION = "connection"
    SSH_BANNER = "ssh_banner"
    HTTP_REQUEST = "http_request"
    LOGIN_ATTEMPT = "login_attempt"
    COMMAND = "command"
    FTP_COMMAND = "ftp_command"
    FILE_UPLOAD = "file_upload"
    DISCONNECT = "disconnect"


@dataclass
class Event:
    """A single observation captured by a decoy service."""

    type: str
    src_ip: str = ""
    src_port: int = 0
    service: str = ""
    dst_port: int = 0
    ts: float = field(default_factory=time.time)
    details: Dict[str, object] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, object]:
        return asdict(self)


# Signature: handler(event). Return values are ignored.
Subscriber = Callable[[Event], None]


class EventBus:
    """A minimal publish/subscribe bus with per-topic and wildcard handlers.

    The bus is deliberately simple: handlers run inline in the publishing
    thread. Slow handlers should queue work themselves; honeypot handlers are
    all fast (SQLite inserts, counter updates), which keeps ordering
    deterministic and makes the system easy to reason about and test.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._subscribers: Dict[Optional[str], List[Subscriber]] = {}

    def subscribe(self, handler: Subscriber, event_type: Optional[str] = None) -> None:
        """Register a handler for one event type, or for all events."""
        with self._lock:
            self._subscribers.setdefault(event_type, []).append(handler)

    def unsubscribe(self, handler: Subscriber, event_type: Optional[str] = None) -> None:
        with self._lock:
            subs = self._subscribers.get(event_type, [])
            if handler in subs:
                subs.remove(handler)

    def publish(self, event: Event) -> None:
        """Deliver ``event`` to its topic subscribers and to wildcard ones."""
        with self._lock:
            targets: List[Subscriber] = list(self._subscribers.get(event.type, ()))
            targets += self._subscribers.get(None, ())
        for handler in targets:
            try:
                handler(event)
            except Exception:  # noqa: BLE001 — a bad subscriber must never kill a decoy
                log.exception("event handler %r failed on %s", handler, event.type)


class EventTypeStats:
    """Small helper that counts published events per type (used in tests/demos)."""

    def __init__(self, bus: EventBus) -> None:
        self._lock = threading.Lock()
        self.counts: Dict[str, int] = {}
        bus.subscribe(self._record)

    def _record(self, event: Event) -> None:
        with self._lock:
            self.counts[event.type] = self.counts.get(event.type, 0) + 1

    def total(self) -> int:
        with self._lock:
            return sum(self.counts.values())


def format_ts(ts: float) -> str:
    """Render a unix timestamp in a stable, human-readable UTC form."""
    return time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(ts)) + " UTC"
