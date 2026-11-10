"""Command-line interface — argparse subcommands, zero dependencies.

    honeyforge run        start honeypot services (the main command)
    honeyforge report     terminal threat summary from the database
    honeyforge logins     captured credential table
    honeyforge alerts     recent alerts
    honeyforge dashboard  standalone web dashboard
    honeyforge init       write an example config file
"""

from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path
from typing import List, Optional

from . import __version__
from .config import SERVICE_NAMES, HoneyConfig, load_config, write_example_config
from .engine import Engine
from .events import format_ts
from .storage import Storage

log = logging.getLogger("honeyforge.cli")

PROGRESS_LINES = {
    "http": "HTTP decoy     : router-style admin panel",
    "ssh": "SSH decoy      : banner + KEXINIT fingerprinting",
    "telnet": "Telnet decoy   : fake BusyBox IoT shell",
    "ftp": "FTP decoy      : fake directory + malware upload capture",
}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="honeyforge",
        description="HoneyForge — a zero-dependency multi-protocol honeypot framework.",
    )
    parser.add_argument("--version", action="version", version=f"honeyforge {__version__}")
    parser.add_argument("-v", "--verbose", action="store_true", help="debug logging")
    sub = parser.add_subparsers(dest="command")

    # ---- run -----------------------------------------------------------
    run = sub.add_parser("run", help="start honeypot services")
    run.add_argument("-c", "--config", help="JSON config file")
    run.add_argument("--host", help="bind address for all services")
    for name in SERVICE_NAMES:
        run.add_argument(f"--{name}-port", type=int, help=f"{name} decoy port")
        run.add_argument(f"--no-{name}", action="store_true", help=f"disable {name} decoy")
    run.add_argument("--dashboard", action="store_true", help="also start the web dashboard")
    run.add_argument("--dashboard-host", help="dashboard bind address")
    run.add_argument("--dashboard-port", type=int, help="dashboard port")
    run.add_argument("--db", help="SQLite database path")
    run.add_argument("--jsonl", help="JSONL event log path")
    run.add_argument("--no-jsonl", action="store_true", help="disable JSONL event export")
    run.add_argument("--uploads", help="directory for captured uploads")

    # ---- queries --------------------------------------------------------
    for name, help_text in (
        ("report", "print a threat summary"),
        ("logins", "list captured credentials"),
        ("alerts", "list recent alerts"),
    ):
        p = sub.add_parser(name, help=help_text)
        p.add_argument("--db", help="SQLite database path")
        p.add_argument("--limit", type=int, default=20, help="rows to show")

    # ---- dashboard -------------------------------------------------------
    dash = sub.add_parser("dashboard", help="run the standalone web dashboard")
    dash.add_argument("--db", help="SQLite database path")
    dash.add_argument("--host", help="bind address")
    dash.add_argument("--port", type=int, help="port")

    # ---- init ------------------------------------------------------------
    init = sub.add_parser("init", help="write an example config file")
    init.add_argument("path", nargs="?", default="honeyforge.json",
                      help="output path (default: ./honeyforge.json)")
    return parser


# --------------------------------------------------------------------- run

def cmd_run(args: argparse.Namespace) -> int:
    config: HoneyConfig = load_config(args.config)
    if args.host:
        for svc in config.services.values():
            svc.host = args.host
    for name in SERVICE_NAMES:
        svc_cfg = config.services[name]
        if getattr(args, f"no_{name.replace('-', '_')}"):
            svc_cfg.enabled = False
        port = getattr(args, f"{name}_port", None)
        if port:
            svc_cfg.port = port
    if args.db:
        config.storage.db_path = args.db
    if args.jsonl:
        config.storage.jsonl_path = args.jsonl
    if args.no_jsonl:
        config.storage.jsonl_path = None
    if args.uploads:
        config.storage.uploads_dir = args.uploads
    if args.dashboard:
        config.dashboard.enabled = True
    if args.dashboard_host:
        config.dashboard.host = args.dashboard_host
    if args.dashboard_port:
        config.dashboard.port = args.dashboard_port

    Path(config.storage.uploads_dir).mkdir(parents=True, exist_ok=True)

    print(_banner(config))
    engine = Engine(config)
    try:
        engine.run_forever()
    except Exception:  # noqa: BLE001 — surface startup errors cleanly
        log.exception("fatal engine error")
        return 1
    return 0


def _banner(config: HoneyConfig) -> str:
    lines = [
        "",
        "  _  _  _ ___ _    _ ___  __  __   _   ",
        " | || || | __| |  | | _ \\/  \\/  | / \\  ",
        " | __ || | _|| |__| |   / -| -| || o | ",
        " |_||_||_|___|____|_|_|\\_||_||_|/   \\ ",
        "                                        ",
        f"  HoneyForge {__version__} — deception, observed.",
        "",
    ]
    for name, desc in PROGRESS_LINES.items():
        svc = config.services[name]
        if svc.enabled:
            lines.append(f"  [+] {desc} on {svc.host}:{svc.port}")
        else:
            lines.append(f"  [-] {desc} (disabled)")
    dest = f"{config.storage.db_path}"
    if config.storage.jsonl_path:
        dest += f", {config.storage.jsonl_path}"
    lines.append(f"  [i] storing to {dest}")
    if config.dashboard.enabled:
        lines.append(f"  [i] dashboard on http://{config.dashboard.host}:"
                     f"{config.dashboard.port}")
    lines.append("")
    return "\n".join(lines)


# ------------------------------------------------------------------ queries

def _open_ro(db_arg: Optional[str]) -> Storage:
    return Storage(db_arg or "data/honeyforge.db")


def _table(headers: List[str], rows: List[List[str]]) -> str:
    widths = [max(len(h), *(len(str(r[i])) for r in rows)) if rows else len(h)
              for i, h in enumerate(headers)]
    sep = "  ".join("-" * w for w in widths)
    head = "  ".join(h.ljust(w) for h, w in zip(headers, widths))
    body = "\n".join(
        "  ".join(str(cell).ljust(w) for cell, w in zip(row, widths)) for row in rows
    )
    return head + "\n" + sep + "\n" + body


def cmd_report(args: argparse.Namespace) -> int:
    storage = _open_ro(args.db)
    try:
        counts = storage.counts()
        print("\n=== HoneyForge threat report ===\n")
        print(f"  events: {counts['events']}  unique attackers: {counts['unique_ips']}  "
              f"logins: {counts['logins']}  alerts: {counts['alerts']}\n")

        ips = storage.top_ips(args.limit)
        if ips:
            print("Top attackers:")
            print(_table(["source ip", "events"], [[r["src_ip"] or "?", str(r["hits"])]
                                                   for r in ips]))
            print()

        services = storage.top_services()
        if services:
            print("Service activity:")
            print(_table(["service", "events"], [[r["service"] or "?", str(r["hits"])]
                                                 for r in services]))
            print()

        paths = storage.top_http_paths(args.limit)
        if paths:
            print("Most-probed HTTP paths:")
            print(_table(["path", "hits"], [[r["path"], str(r["hits"])] for r in paths]))
            print()

        creds = storage.top_credentials(args.limit)
        if creds:
            print("Top credentials tried:")
            print(_table(["username", "password", "uses"],
                         [[r["username"], r["password"], str(r["uses"])] for r in creds]))
            print()

        alerts = storage.recent_alerts(args.limit)
        if alerts:
            print("Recent alerts:")
            print(_table(["time", "severity", "type", "source", "message"],
                         [[format_ts(r["ts"]), r["severity"], r["alert_type"],
                           r["src_ip"] or "-", r["message"][:48]] for r in alerts]))
        else:
            print("No alerts yet.")
    finally:
        storage.close()
    return 0


def cmd_logins(args: argparse.Namespace) -> int:
    storage = _open_ro(args.db)
    try:
        rows = storage.recent_logins(args.limit)
        if not rows:
            print("No credentials captured yet.")
            return 0
        print(_table(["time", "service", "source", "username", "password"],
                     [[format_ts(r["ts"]), r["service"], r["src_ip"],
                       r["username"], r["password"]] for r in rows]))
    finally:
        storage.close()
    return 0


def cmd_alerts(args: argparse.Namespace) -> int:
    storage = _open_ro(args.db)
    try:
        rows = storage.recent_alerts(args.limit)
        if not rows:
            print("No alerts recorded yet.")
            return 0
        print(_table(["time", "severity", "type", "source", "message"],
                     [[format_ts(r["ts"]), r["severity"], r["alert_type"],
                       r["src_ip"] or "-", r["message"]] for r in rows]))
    finally:
        storage.close()
    return 0


def cmd_dashboard(args: argparse.Namespace) -> int:
    from .dashboard.app import run_dashboard

    config_db = args.db or "data/honeyforge.db"
    storage = Storage(config_db)
    host = args.host or "127.0.0.1"
    port = args.port or 8081
    print(f"HoneyForge dashboard on http://{host}:{port} (Ctrl-C to stop)")
    try:
        run_dashboard(storage, host, port)
    except KeyboardInterrupt:
        pass
    finally:
        storage.close()
    return 0


def cmd_init(args: argparse.Namespace) -> int:
    path = write_example_config(args.path)
    print(f"wrote example config to {path}")
    print("start with: honeyforge run -c " + str(path))
    return 0


# --------------------------------------------------------------------- main

COMMANDS = {
    "run": cmd_run,
    "report": cmd_report,
    "logins": cmd_logins,
    "alerts": cmd_alerts,
    "dashboard": cmd_dashboard,
    "init": cmd_init,
}


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )
    if not args.command:
        build_parser().print_help()
        return 2
    handler = COMMANDS[args.command]
    try:
        return handler(args)
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
