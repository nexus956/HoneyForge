# Changelog

All notable changes to HoneyForge are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/) and the project
adheres to [Semantic Versioning](https://semver.org/).

## [1.0.0] — 2026-11-10

First public release.

### Added

* **Four decoy services**, pure standard library:
  * HTTP decoy emulating a router admin panel — page serving, header/user-agent
    capture, credential-POST capture with a believable 302 → dashboard flow.
  * SSH decoy performing version exchange and KEXINIT fingerprinting
    (kex / host-key / cipher algorithm lists) without any crypto dependency.
  * Telnet decoy emulating a BusyBox v1.22.1 IoT shell with IAC negotiation
    stripping, a fake filesystem, canned command output and full command
    recording; multi-line "worm blast" input is buffered and never dropped.
  * FTP decoy with USER/PASS/PASV/LIST/RETR/STOR support; uploads quarantined
    on disk as `sha256_<digest>` with magic-byte inspection.
* **Event-driven core**: thread-safe in-process `EventBus` with per-topic and
  wildcard subscribers, exception isolation, and typed `Event` dataclass.
* **Storage**: thread-safe SQLite (WAL) with events/logins/alerts tables plus a
  JSONL event log for SIEM ingestion.
* **Alert engine** with per-IP correlation: `brute_force` (high),
  `recon` (medium), `web_scanner` (medium), `malware_drop` (critical), with
  per-(IP, type) cooldown deduplication and configurable thresholds.
* **Web dashboard** (stdlib HTTP server + single-file HTML/JS): live counts,
  24 h activity sparkline, top attackers / paths / credentials, event, login
  and alert feeds, auto-refreshing JSON API.
* **CLI**: `run`, `report`, `logins`, `alerts`, `dashboard`, `init` subcommands
  with JSON config file + flag overrides.
* **Engine** orchestrating services, storage, alerts and dashboard with
  cooperative shutdown (SIGINT/SIGTERM).
* **Test suite**: 58 unit + live end-to-end tests, including regression tests
  for TCP-coalesced input and bind-failure reporting.
* Docker packaging (`Dockerfile`, `docker-compose.yml`) and a GitHub Actions
  CI matrix for Python 3.9–3.13.
