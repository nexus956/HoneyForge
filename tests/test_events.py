"""EventBus routing, wildcards and failure isolation."""

from __future__ import annotations

import threading

from honeyforge.events import Event, EventBus, EventTypeStats

from .util import HoneyTestCase


class EventBusTests(HoneyTestCase):
    def test_type_subscription_receives_matching_events_only(self) -> None:
        bus = EventBus()
        seen = []
        bus.subscribe(lambda e: seen.append(e.type), "command")
        bus.publish(Event(type="connection"))
        bus.publish(Event(type="command", details={"command": "ls"}))
        self.assertEqual(seen, ["command"])

    def test_wildcard_receives_everything(self) -> None:
        bus = EventBus()
        seen = []
        bus.subscribe(lambda e: seen.append(e.type))
        bus.publish(Event(type="connection"))
        bus.publish(Event(type="login_attempt"))
        self.assertEqual(seen, ["connection", "login_attempt"])

    def test_failing_handler_does_not_break_other_subscribers(self) -> None:
        bus = EventBus()
        seen = []

        def boom(event: Event) -> None:
            raise RuntimeError("boom")

        bus.subscribe(boom, "command")
        bus.subscribe(lambda e: seen.append("ok"), "command")
        bus.publish(Event(type="command"))
        self.assertEqual(seen, ["ok"])

    def test_unsubscribe(self) -> None:
        bus = EventBus()
        seen = []

        def handler(event: Event) -> None:
            seen.append(1)

        bus.subscribe(handler, "command")
        bus.unsubscribe(handler, "command")
        bus.publish(Event(type="command"))
        self.assertEqual(seen, [])

    def test_thread_safety_of_subscribe_during_publish(self) -> None:
        bus = EventBus()
        stats = EventTypeStats(bus)
        bus.subscribe(lambda e: None)
        stop = threading.Event()

        def spam() -> None:
            while not stop.is_set():
                bus.publish(Event(type="command"))

        thread = threading.Thread(target=spam, daemon=True)
        thread.start()
        try:
            for _ in range(50):
                bus.subscribe(lambda e: None, "command")
        finally:
            stop.set()
            thread.join(2)
        self.assertGreater(stats.total(), 0)

    def test_event_to_dict_roundtrip(self) -> None:
        event = Event(type="command", src_ip="1.2.3.4", details={"command": "ls"})
        data = event.to_dict()
        self.assertEqual(data["type"], "command")
        self.assertEqual(data["details"], {"command": "ls"})
        restored = Event(**data)
        self.assertEqual(restored.src_ip, "1.2.3.4")
        self.assertEqual(restored.details, {"command": "ls"})

    def test_event_type_stats(self) -> None:
        bus = EventBus()
        stats = EventTypeStats(bus)
        bus.publish(Event(type="command"))
        bus.publish(Event(type="command"))
        bus.publish(Event(type="connection"))
        self.assertEqual(stats.counts, {"command": 2, "connection": 1})
        self.assertEqual(stats.total(), 3)
