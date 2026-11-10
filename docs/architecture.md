# Architecture

HoneyForge is a single-process, multi-threaded honeypot framework with an
event-driven core. Everything runs on the Python standard library.

## Components

| Component | File | Role |
|-----------|------|------|
| `BaseHoneyService` | `honeyforge/services/base.py` | Thread-per-connection listener; owns socket lifecycle, `connection` events, stop signalling, and the buffered `LineReader` |
| HTTP decoy | `honeyforge/services/http.py` | Router-admin panel: page serving, header capture, credential POST capture |
| SSH decoy | `honeyforge/services/ssh.py` | Version exchange + unencrypted KEXINIT parsing for client fingerprinting |
| Telnet decoy | `honeyforge/services/telnet.py` | BusyBox login flow + fake shell, IAC stripping, command recording |
| FTP decoy | `honeyforge/services/ftp.py` | Command loop, PASV data connections, upload quarantine |
| `EventBus` | `honeyforge/events.py` | Synchronous publish/subscribe; handlers run inline in the publishing (connection) thread |
| `Storage` | `honeyforge/storage.py` | Thread-safe SQLite (WAL) sink + query surface; `JsonlEventLog` for SIEM export |
| `AlertEngine` | `honeyforge/alerts.py` | Per-IP stateful correlation → alerts table |
| `Engine` | `honeyforge/engine.py` | Wires storage/bus/alerts/services/dashboard; lifecycle |
| Dashboard | `honeyforge/dashboard/` | stdlib `ThreadingHTTPServer` + single-file HTML/JS UI + JSON API |
| CLI | `honeyforge/cli.py` | argparse subcommands: `run`, `report`, `logins`, `alerts`, `dashboard`, `init` |

## Data flow

1. A connection arrives at a decoy listener. `BaseHoneyService.run()` accepts it
   and hands it to a fresh daemon thread.
2. `_serve()` publishes a `connection` event, then delegates to the service's
   `handle_client()`.
3. `handle_client()` speaks the protocol, publishing `login_attempt`,
   `http_request`, `ssh_banner`, `command`, `ftp_command`, `file_upload` … events.
4. Every event is delivered to all subscribers synchronously, in the connection
   thread:
   * `Storage.record_event` — append to `events`
   * `JsonlEventLog.record` — append one JSON line (optional)
   * `Engine._record_login` (login events only) — append to `logins`
   * `AlertEngine.on_event` — per-IP correlation (see below)
5. Handlers are exception-isolated: a failing subscriber can never kill a decoy.

Synchronous delivery is a deliberate choice: all handlers are O(1) work
(one SQLite insert, one counter update), and inline execution keeps event
ordering deterministic, which makes the system testable with plain assertions.

## Alert correlation

`AlertEngine` keeps in-memory state per source IP:

* `_logins[ip]` — deque of login-attempt timestamps (window-pruned)
* `_services[ip]` — list of `(timestamp, service)` observations
* `_last_fired[(ip, type)]` — cooldown dedupe

Detectors:

| Alert | Condition | Severity |
|-------|-----------|----------|
| `brute_force` | `len(_logins[ip]) >= threshold` inside window | high |
| `recon` | distinct services `>= recon_services` inside window | medium |
| `web_scanner` | request path contains a scanner marker | medium |
| `malware_drop` | upload magic bytes match ELF/MZ/gzip/shebang, or suspicious filename | critical |

Alerts are written to the `alerts` table; identical (IP, type) pairs within the
cooldown window are dropped.

## Threading model

* One thread per decoy listener (4), plus one thread per active connection.
* One thread for the dashboard HTTP server (itself threaded per request).
* SQLite is shared with a re-entrant lock and `check_same_thread=False`; WAL
  mode keeps dashboard reads non-blocking while decoys write.
* `Engine.stop()` is cooperative: listeners use a 500 ms accept-timeout loop so
  `stop()` unblocks within half a second; in-flight connections finish within
  their socket timeout.

## Why no real SSH handshake?

A full SSH key exchange requires crypto primitives that the standard library
doesn't ship. Instead of pulling in a dependency (or vendoring crypto), the SSH
dey completes the **protocol version exchange** and parses the client's first
packet — the unencrypted `SSH_MSG_KEXINIT` — recording the exact algorithm
lists the client advertises. This is the same fingerprint the first bytes of any
SSH scan carry (nmap, masscan, Paramiko, libssh2 and Mirai-family loaders all
differ visibly) and is what a scanner sees before dropping the connection
anyway.

## Storage schema

```
events(id, ts, type, service, src_ip, src_port, dst_port, details_json)
logins(id, ts, service, src_ip, username, password, success)
alerts(id, ts, alert_type, severity, src_ip, message, details_json)
```

Indexes on `ts`, `src_ip` and `type`. The dashboard's "top HTTP paths" scans the
most recent bounded window of `http_request` events in Python (SQLite's JSON1
extension is not guaranteed everywhere), which is plenty for a single-node pot.

## Security posture

* Decoys never execute attacker input. `wget`/`tftp` replies claim
  "Permission denied"; uploads go to disk under a hash name, unread by the pot.
* Uploads are size-capped (16 MB) and header/body reads are capped to prevent
  memory exhaustion.
* The dashboard binds `127.0.0.1` by default — expose it deliberately.
* Everything runs in the user space; no privileged ports required.
