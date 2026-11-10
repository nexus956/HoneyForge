# Contributing to HoneyForge

Thanks for wanting to help! HoneyForge has two hard rules and a few suggestions.

## Hard rules

1. **Standard library only** for runtime code. No third-party imports anywhere
   under `honeyforge/`. Test-only dependencies are also avoided — the suite is
   plain `unittest`.
2. **Decoys never execute attacker input.** Anything a remote peer sends is
   data: it gets recorded, maybe echoed back as canned text, and never reaches
   `eval`, `system`, file writes outside the quarantine dir, or a shell.

## Development

```bash
git clone https://github.com/nexus956/HoneyForge.git
cd HoneyForge

python3 -m unittest discover -t .    # everything must pass
python3 -m compileall -q honeyforge  # must stay import-clean
```

Before sending a change:

* Run the full suite (`python3 -m unittest discover -t .`).
* Keep lines ≤ 100 characters.
* New decoy features need tests that drive the real socket, not mocks — the
  existing suites boot services on ephemeral ports for a reason.
* Keep `README.md`, `docs/architecture.md` and `CHANGELOG.md` in sync with
  behaviour changes.

## Adding a decoy service

1. Subclass `BaseHoneyService` in `honeyforge/services/`, implement
   `handle_client(conn, addr)`, and publish events via `self.publish(...)`.
2. Register the class in `SERVICE_CLASSES` (`honeyforge/services/__init__.py`).
3. Add a dataclass config in `honeyforge/config.py` + wire it into
   `HoneyConfig.__post_init__`, `load_config` and `_to_dict`.
4. Build it in `Engine._build_services`.
5. Add a live end-to-end test module under `tests/`.

## Reporting a vulnerability

See [SECURITY.md](SECURITY.md). Do not open public issues for exploitable bugs.
