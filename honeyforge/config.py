"""Configuration for HoneyForge.

Configuration is layered: built-in defaults, then an optional JSON config
file, then CLI flags. Everything is plain dataclasses so it is trivially
serialisable and testable. Only the standard library is used.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Dict, Optional

log = logging.getLogger("honeyforge.config")

SERVICE_NAMES = ("http", "ssh", "telnet", "ftp")


@dataclass
class ServiceConfig:
    """Settings for a single decoy service."""

    enabled: bool = True
    host: str = "0.0.0.0"
    port: int = 0  # filled from defaults below
    banner: str = ""  # optional protocol banner override


@dataclass
class HttpConfig(ServiceConfig):
    """HTTP decoy: emulates a small router/NAS admin panel."""

    port: int = 8080
    banner: str = "lighttpd/1.4.54"
    redirect_after_login: str = "/dashboard.html"


@dataclass
class SshConfig(ServiceConfig):
    """SSH decoy: banner + KEXINIT fingerprinting."""

    port: int = 2222
    banner: str = "SSH-2.0-OpenSSH_9.6p1 Debian-3"


@dataclass
class TelnetConfig(ServiceConfig):
    """Telnet decoy: fake BusyBox shell on an IoT-style device."""

    port: int = 2323
    banner: str = "BusyBox v1.22.1 (2026-01-04 15:30:22 UTC) built-in shell"
    prompt: str = "# "


@dataclass
class FtpConfig(ServiceConfig):
    """FTP decoy: full command loop with passive-mode file transfers."""

    port: int = 2121
    banner: str = "220 HoneyForge FTP server ready."
    save_uploads: bool = True


@dataclass
class AlertConfig:
    """Thresholds for the real-time alert engine."""

    enabled: bool = True
    brute_force_threshold: int = 5  # login attempts from one IP ...
    brute_force_window: int = 300  # ... within N seconds
    recon_services: int = 3  # distinct services touched ...
    recon_window: int = 600  # ... within N seconds
    cooldown: int = 120  # min seconds between identical alerts per IP
    scanner_paths: bool = True


@dataclass
class StorageConfig:
    """Where captured data lives."""

    db_path: str = "data/honeyforge.db"
    jsonl_path: Optional[str] = "data/events.jsonl"
    uploads_dir: str = "data/uploads"


@dataclass
class DashboardConfig:
    """Built-in web dashboard."""

    enabled: bool = False
    host: str = "127.0.0.1"
    port: int = 8081


@dataclass
class HoneyConfig:
    """Top-level HoneyForge configuration."""

    services: Dict[str, ServiceConfig] = field(default_factory=dict)
    alerts: AlertConfig = field(default_factory=AlertConfig)
    storage: StorageConfig = field(default_factory=StorageConfig)
    dashboard: DashboardConfig = field(default_factory=DashboardConfig)

    def __post_init__(self) -> None:
        defaults: Dict[str, ServiceConfig] = {
            "http": HttpConfig(),
            "ssh": SshConfig(),
            "telnet": TelnetConfig(),
            "ftp": FtpConfig(),
        }
        for name in SERVICE_NAMES:
            if name not in self.services:
                self.services[name] = defaults[name]
        # Replace bare ServiceConfig placeholders with the concrete defaults.
        for name in SERVICE_NAMES:
            if type(self.services[name]) is ServiceConfig:
                self.services[name] = defaults[name]

    def service(self, name: str) -> ServiceConfig:
        return self.services[name]


def _coerce(cls: Any, data: Dict[str, Any]) -> Any:
    """Build a dataclass instance from a dict, ignoring unknown keys."""
    if not isinstance(data, dict):
        raise ValueError(f"expected object for {cls.__name__}, got {type(data).__name__}")
    valid = {f.name for f in cls.__dataclass_fields__.values()}  # type: ignore[attr-defined]
    unknown = set(data) - valid
    if unknown:
        log.warning("ignoring unknown %s keys: %s", cls.__name__, ", ".join(sorted(unknown)))
    return cls(**{k: v for k, v in data.items() if k in valid})


def default_config() -> HoneyConfig:
    """A fresh configuration with all defaults."""
    return HoneyConfig()


def load_config(path: Optional[str] = None) -> HoneyConfig:
    """Load configuration, layering a JSON file over the defaults."""
    cfg = default_config()
    if not path:
        return cfg
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"config file not found: {p}")
    raw = json.loads(p.read_text(encoding="utf-8"))

    services = raw.pop("services", {}) or {}
    for name in SERVICE_NAMES:
        if name in services:
            cfg.services[name] = _coerce(type(cfg.services[name]), services[name])

    if "alerts" in raw:
        cfg.alerts = _coerce(AlertConfig, raw["alerts"])
    if "storage" in raw:
        cfg.storage = _coerce(StorageConfig, raw["storage"])
    if "dashboard" in raw:
        cfg.dashboard = _coerce(DashboardConfig, raw["dashboard"])

    for name, svc in cfg.services.items():
        svc.host = raw.get("host", svc.host) if isinstance(raw.get("host"), str) else svc.host
    unknown = set(raw) - {"host", "services", "alerts", "storage", "dashboard"}
    if unknown:
        log.warning("ignoring unknown top-level keys: %s", ", ".join(sorted(unknown)))
    return cfg


def write_example_config(path: str) -> Path:
    """Write a commented example config (JSON has no comments, so keys are doubled as docs)."""
    cfg = default_config()
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(_to_dict(cfg), indent=2) + "\n", encoding="utf-8")
    return p


def _to_dict(cfg: HoneyConfig) -> Dict[str, Any]:
    def svc_dict(s: ServiceConfig) -> Dict[str, Any]:
        d: Dict[str, Any] = {"enabled": s.enabled, "host": s.host, "port": s.port}
        if s.banner:
            d["banner"] = s.banner
        if isinstance(s, HttpConfig):
            d["redirect_after_login"] = s.redirect_after_login
        if isinstance(s, TelnetConfig):
            d["prompt"] = s.prompt
        if isinstance(s, FtpConfig):
            d["save_uploads"] = s.save_uploads
        return d

    return {
        "host": cfg.services["http"].host,
        "services": {name: svc_dict(svc) for name, svc in cfg.services.items()},
        "alerts": cfg.alerts.__dict__,
        "storage": cfg.storage.__dict__,
        "dashboard": cfg.dashboard.__dict__,
    }


def with_overrides(cfg: HoneyConfig, **overrides: Any) -> HoneyConfig:
    """Return a copy of ``cfg`` with simple attribute paths replaced."""
    for dotted, value in overrides.items():
        if value is None:
            continue
        obj, _, attr = dotted.rpartition(".")
        section, _, field_name = obj.partition("_")
        if not field_name:
            raise ValueError(f"override key must look like 'section_field_attr', got {dotted!r}")
        target = getattr(cfg, section) if section in ("alerts", "storage", "dashboard") else None
        if target is None:
            raise ValueError(f"unknown config section in override {dotted!r}")
        if not hasattr(target, field_name):
            raise ValueError(f"unknown config field in override {dotted!r}")
        setattr(target, field_name, value)
    return replace(cfg)
