"""Engine — wires storage, the event bus, alerts, decoys and the dashboard.

Lifecycle::

    engine = Engine(HoneyConfig())
    engine.start()          # decoys bind; dashboard (if enabled) starts
    ...
    engine.stop()           # graceful shutdown of everything

``Engine.run_forever()`` blocks until Ctrl-C / SIGTERM, which makes it the
default entry point for ``honeyforge run``.
"""

from __future__ import annotations

import logging
import signal
import threading
import time
from types import FrameType
from typing import Dict, Optional

from .alerts import AlertEngine
from .config import HoneyConfig
from .events import Event, EventBus
from .services import SERVICE_CLASSES
from .storage import JsonlEventLog, Storage

log = logging.getLogger("honeyforge.engine")


class Engine:
    """Owns every runtime component of a HoneyForge deployment."""

    def __init__(self, config: HoneyConfig) -> None:
        self.config = config
        self.bus = EventBus()
        self.storage = Storage(config.storage.db_path)
        self.jsonl: Optional[JsonlEventLog] = (
            JsonlEventLog(config.storage.jsonl_path)
            if config.storage.jsonl_path else None
        )
        self.alert_engine = AlertEngine(self.bus, self.storage, config.alerts)

        # Every event lands in SQLite (+ JSONL); logins also feed the logins table.
        self.bus.subscribe(self.storage.record_event)
        if self.jsonl:
            self.bus.subscribe(self.jsonl.record)
        self.bus.subscribe(self._record_login, "login_attempt")

        self.services: Dict[str, object] = {}
        self.dashboard_server = None
        self.dashboard_thread: Optional[threading.Thread] = None
        self._stopped = threading.Event()

    # -------------------------------------------------------------- build

    def _build_services(self) -> None:
        cfg = self.config
        for name, service_cfg in cfg.services.items():
            if not service_cfg.enabled:
                log.info("service '%s' disabled by config", name)
                continue
            service_class = SERVICE_CLASSES[name]
            uploads = cfg.storage.uploads_dir if name == "ftp" else ""
            if name == "http":
                service = service_class(
                    service_cfg.host, service_cfg.port, self.bus,
                    server_banner=service_cfg.banner or "lighttpd/1.4.54",
                    redirect_after_login=getattr(service_cfg, "redirect_after_login",
                                                "/dashboard.html"),
                )
            elif name == "ssh":
                service = service_class(
                    service_cfg.host, service_cfg.port, self.bus,
                    banner=service_cfg.banner or "SSH-2.0-OpenSSH_9.6p1",
                )
            elif name == "telnet":
                service = service_class(
                    service_cfg.host, service_cfg.port, self.bus,
                    banner=service_cfg.banner,
                    prompt=getattr(service_cfg, "prompt", "# "),
                )
            elif name == "ftp":
                service = service_class(
                    service_cfg.host, service_cfg.port, self.bus,
                    banner=service_cfg.banner,
                    uploads_dir=uploads,
                    save_uploads=getattr(service_cfg, "save_uploads", True),
                )
            else:  # pragma: no cover — SERVICE_CLASSES keys are fixed
                raise ValueError(f"unknown service {name!r}")
            self.services[name] = service

    def _record_login(self, event: Event) -> None:
        self.storage.record_login(
            event.ts,
            event.service,
            event.src_ip,
            str(event.details.get("username", "")),
            str(event.details.get("password", "")),
            bool(event.details.get("success", False)),
        )

    # -------------------------------------------------------------- start

    def start(self) -> None:
        self._stopped.clear()
        self._build_services()
        for name, service in self.services.items():
            service.start()  # type: ignore[attr-defined]
            service.wait_until_listening(5)  # type: ignore[attr-defined]
            port = getattr(service, "bound_port", 0)
            bind_error = getattr(service, "bind_error", None)
            if bind_error:
                log.error("[%s] FAILED to bind on %s:%s — %s",
                          name.upper(), service.host, port, bind_error)  # type: ignore[attr-defined]
            else:
                log.info("[%s] listening on %s:%s",
                         name.upper(), service.host, port)  # type: ignore[attr-defined]

        if self.config.dashboard.enabled:
            self.start_dashboard()

    def start_dashboard(self) -> object:
        from .dashboard.app import make_dashboard_server

        self.dashboard_server = make_dashboard_server(
            self.storage, self.config.dashboard.host, self.config.dashboard.port
        )
        self.dashboard_thread = threading.Thread(
            target=self.dashboard_server.serve_forever,
            name="honeyforge-dashboard",
            daemon=True,
        )
        self.dashboard_thread.start()
        log.info("[DASHBOARD] http://%s:%s",
                 self.config.dashboard.host, self.dashboard_server.server_address[1])
        return self.dashboard_server

    # -------------------------------------------------------------- stop

    def stop(self) -> None:
        if self._stopped.is_set():
            return
        self._stopped.set()
        for name, service in self.services.items():
            try:
                service.stop()  # type: ignore[attr-defined]
                service.join(timeout=2)  # type: ignore[attr-defined]
            except Exception:  # noqa: BLE001
                log.exception("error stopping service %s", name)
        if self.dashboard_server is not None:
            try:
                self.dashboard_server.shutdown()
                self.dashboard_server.server_close()
            except Exception:  # noqa: BLE001
                log.exception("error stopping dashboard")
        if self.jsonl:
            self.jsonl.close()
        self.storage.close()
        log.info("engine stopped")

    def run_forever(self) -> None:
        """Block until SIGINT/SIGTERM; install handlers if we own the signal."""
        def handle_signal(signum: int, frame: Optional[FrameType]) -> None:
            log.info("received signal %s, shutting down", signum)
            self._stopped.set()

        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                signal.signal(sig, handle_signal)
            except (ValueError, OSError):  # not the main thread
                pass
        self.start()
        try:
            while not self._stopped.is_set():
                time.sleep(0.5)
        except KeyboardInterrupt:
            pass
        finally:
            self.stop()

    # context manager support
    def __enter__(self) -> "Engine":
        self.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.stop()
