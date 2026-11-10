# HoneyForge 🍯

**A zero-dependency, multi-protocol honeypot framework in pure Python.**

[![CI](https://github.com/nexus956/HoneyForge/actions/workflows/ci.yml/badge.svg)](https://github.com/nexus956/HoneyForge/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.9%2B-blue)
![Dependencies](https://img.shields.io/badge/dependencies-0-green)
![License](https://img.shields.io/badge/license-MIT-green)

HoneyForge deploys four decoy services — **SSH, HTTP, Telnet and FTP** — that look like a
small router/NAS box worth attacking. Everything an attacker does is recorded to SQLite and
JSONL, correlated in real time into alerts (brute force, reconnaissance, web scanning,
malware drops), and exposed through a built-in web dashboard and a CLI threat report.
Uploaded malware is quarantined on disk, named by its SHA-256, ready for sandbox analysis.

```
  _  _  _ ___ _    _ ___  __  __   _
 | || || | __| |  | | _ \/  \/  | / \
 | __ || | _|| |__| |   / -| -| || o |
 |_||_||_|___|____|_|_|\_||_||_|/   \
```

---

## Why HoneyForge

* **Zero dependencies.** The entire framework — decoys, storage, alert engine, dashboard —
  is Python standard library only. `pip install` nothing, supply-chain risk ~zero, works on
  a $5 VPS or a Raspberry Pi.
* **Real protocols, real capture.** Not just port listeners: a BusyBox-flavoured Telnet shell
  that records every command, an FTP server that walks `USER/PASS/PASV/STOR` and swallows
  worm payloads, an HTTP admin panel that eats credential POSTs, and an SSH decoy that
  fingerprints attacking clients from their KEXINIT algorithms.
* **Correlated alerts, not raw logs.** An in-process alert engine correlates events per
  source IP: 5 logins in 5 minutes is a **brute_force** (high), one IP touching three
  decoys is **recon** (medium), an ELF or `#!/bin/sh` upload is a **malware_drop**
  (critical).
* **Built-in analytics.** SQLite (WAL) for queries, JSONL for SIEM shipping, a live web
  dashboard, and a `honeyforge report` terminal summary.

## Quickstart

```bash
git clone https://github.com/nexus956/HoneyForge.git
cd HoneyForge

# run all four decoys on their default high ports (no root needed)
python3 -m honeyforge run --dashboard

# in other terminals, attack it:
curl -d "username=admin&password=x" http://localhost:8080/login
ssh -p 2222 nobody@localhost          # watch the banner exchange get fingerprinted
telnet localhost 2323                # login, run 'ls', try 'wget http://x/bot.sh'
ftp -p -P 2121 localhost             # 'anonymous' works; uploads get quarantined
```

Open **http://127.0.0.1:8081** for the live dashboard, or run:

```bash
python3 -m honeyforge report   # terminal threat summary
python3 -m honeyforge logins   # captured credentials table
python3 -m honeyforge alerts   # recent alerts
```

## The decoys

| Service | Default port | Emulates | Captures |
|---------|-------------|----------|----------|
| **HTTP** | `8080` | lighttpd router admin panel; login form → 302 → dashboard | request line, headers, user-agent, credential POSTs |
| **SSH**  | `2222` | OpenSSH 9.6 banner | client version string + advertised KEX/host-key/cipher algorithms (KEXINIT fingerprinting) |
| **Telnet** | `2323` | BusyBox v1.22.1 IoT shell | username/password, every shell command verbatim |
| **FTP**  | `2121` | vsftpd-style FTP with PASV | credentials, full command trace, **uploaded files → quarantine dir by SHA-256** |

All credentials are "accepted" — the goal is to keep the attacker talking and record it.

## Alert rules

| Alert | Severity | Trigger (defaults, configurable) |
|-------|----------|----------------------------------|
| `brute_force` | high | ≥5 login attempts from one IP within 300s |
| `recon` | medium | one IP touching ≥3 distinct decoys within 600s |
| `web_scanner` | medium | classic scanner paths (`/wp-admin`, `/.env`, `/boaform`, `/actuator`, …) |
| `malware_drop` | critical | upload with ELF/MZ/gzip/shebang magic or a suspicious filename (`bot.sh`, `*.bin`, …) |

Alerts are deduplicated per (IP, type) with a cooldown so a noisy scanner can't flood you.

## Architecture

```
                 ┌───────────────────────────────────────────────────────┐
 attackers ────▶ │  decoy services (thread per connection)               │
                 │  http.py   ssh.py   telnet.py   ftp.py                  │
                 └──────────────┬────────────────────────────────────────┘
                                │ Event(type, src_ip, service, details)
                                ▼
                        ┌───────────────┐    subscribe    ┌────────────────┐
                        │   EventBus    │───────────────▶ │  AlertEngine   │
                        └──────┬────────┘                 │ (per-IP state, │
                               │ subscribe                │  correlation)  │
              ┌────────────────┼───────────────┐          └───────┬────────┘
              ▼                ▼               ▼                  ▼
       ┌────────────┐   ┌─────────────┐  ┌──────────────┐  ┌──────────────┐
       │   SQLite   │   │  JSONL log  │  │ logins table │  │ alerts table │
       └─────┬──────┘   └─────────────┘  └──────────────┘  └──────────────┘
             │                    queries                ▲
             ▼                                          │
       ┌──────────────────┐        ┌──────────────┐     │
       │    Dashboard     │        │  CLI report  │─────┘
       │ (stdlib httpd)   │        │ logins/alerts│
       └──────────────────┘        └──────────────┘
```

See [docs/architecture.md](docs/architecture.md) for the component and data-flow details.

## Configuration

Generate a config and edit to taste:

```bash
python3 -m honeyforge init myconfig.json
python3 -m honeyforge run -c myconfig.json
```

```json
{
  "host": "0.0.0.0",
  "services": {
    "http":   { "enabled": true,  "port": 8080, "banner": "lighttpd/1.4.54" },
    "ssh":    { "enabled": true,  "port": 2222, "banner": "SSH-2.0-OpenSSH_9.6p1 Debian-3" },
    "telnet": { "enabled": true,  "port": 2323, "prompt": "# " },
    "ftp":    { "enabled": true,  "port": 2121, "save_uploads": true }
  },
  "alerts": {
    "enabled": true,
    "brute_force_threshold": 5,
    "brute_force_window": 300,
    "recon_services": 3,
    "recon_window": 600,
    "cooldown": 120
  },
  "storage": {
    "db_path": "data/honeyforge.db",
    "jsonl_path": "data/events.jsonl",
    "uploads_dir": "data/uploads"
  },
  "dashboard": { "enabled": false, "host": "127.0.0.1", "port": 8081 }
}
```

CLI flags override the config: `--http-port 80 --ssh-port 22 --no-ftp --db /var/lib/hf.db
--dashboard --dashboard-host 0.0.0.0 --dashboard-port 8081`.

> **Ports:** defaults are high ports so you can run without root. To impersonate the real
> services (21/22/23/80), run under Docker with port mappings (below) or bind low ports as
> root. Every decoy is intentionally **non-interactive** — a honeypot should never execute
> attacker input.

## Docker

```bash
docker compose up -d          # or: docker build -t honeyforge .
```

`docker-compose.yml` maps decoys to the canonical ports so the container looks like a
genuinely exposed device.

## Malware handling

Files uploaded to the FTP decoy are stored in the uploads dir as `sha256_<digest>`, never
executed, and never served back. Identical samples deduplicate automatically. Wire the
directory into your favourite pipeline (Cuckoo, anya, YARA rules, …) — every upload also
lands in the `events` table (`file_upload`) with filename, size, magic bytes and hash, and
raises a `malware_drop` alert when the content smells like a binary or script.

## Testing

```bash
python3 -m unittest discover -t .   # 58 tests: unit + live end-to-end decoy tests
```

The suite boots real decoys on ephemeral ports and drives them with raw sockets, including
regression tests for TCP-coalesced multi-line input (worms don't wait for prompts).

## Legal & responsible use

HoneyForge is a **defensive** research tool. Deploy it only on infrastructure you own or
are authorised to instrument, and check your local jurisdiction's rules on honeypots and
data capture before exposing one. It never executes attacker input; its purpose is
observation. See [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE) © 2026 nexus956
