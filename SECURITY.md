# Security Policy

## Supported versions

Only the latest release line receives security fixes.

## Reporting a Vulnerability

**Do not open a public issue for anything exploitable.** Contact the maintainer
privately via GitHub security advisories (`Security` → `Report a vulnerability`
on the repo). Include reproduction steps and your assessment of impact. You
will get an acknowledgement within 72 hours.

## Security design notes

HoneyForge's threat model is the entire internet: every byte a decoy receives
is attacker-controlled. Design responses:

* **No execution of attacker input.** Decoys record and echo canned responses.
  `wget`, `tftp`, `curl`-style commands receive a refusal. Uploaded files are
  written to the quarantine dir under a SHA-256 name and are never read back,
  executed, or served.
* **Bounded parsing everywhere.** Banner ≤ 255 B, SSH packets ≤ 4 KiB, HTTP
  headers ≤ 16 KiB, bodies ≤ 64 KiB, FTP transfers ≤ 16 MiB. All reads are
  timeout-guarded (30 s default) so slowloris-style connections die on their own.
* **Fail-closed error handling.** Any unexpected exception in a connection
  handler closes that connection; a broken subscriber (storage, alerts) cannot
  kill a decoy.
* **No privileged requirements.** Decoys default to high ports. The dashboard
  binds `127.0.0.1` and must be exposed deliberately. SQLite runs in WAL mode
  so analytics never block capture.
* **Secrets hygiene.** Honeypots are meant to be breached-capable machines:
  never run HoneyForge on a host with credentials you care about, and never
  point its storage at a directory with other data. Assume anything a honeypot
  host captures can include hostile material (uploaded malware is stored raw).

## Deployment cautions

* Check that operating a honeypot is legal in your jurisdiction and permitted
  by your hosting provider before exposing decoys.
* Restrict egress from the honeypot host if you can — HoneyForge itself makes
  no outbound connections, but defence-in-depth is free.
* The captured-credential and malware data in `data/` are **sensitive**: they
  may contain third-party passwords and live malicious code. Handle and share
  accordingly.
