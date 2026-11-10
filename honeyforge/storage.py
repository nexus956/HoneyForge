"""Persistence: SQLite (queries + dashboard) and JSONL (SIEM export).

Both writers are thread-safe — decoy services publish from many connection
threads. SQLite runs in WAL mode so the dashboard can read while the honeypot
writes. Captured malware uploads are stored on disk under the uploads dir,
named by SHA-256 so identical samples deduplicate automatically.
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from .events import Event

log = logging.getLogger("honeyforge.storage")

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    type TEXT NOT NULL,
    service TEXT NOT NULL DEFAULT '',
    src_ip TEXT NOT NULL DEFAULT '',
    src_port INTEGER NOT NULL DEFAULT 0,
    dst_port INTEGER NOT NULL DEFAULT 0,
    details_json TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events (ts);
CREATE INDEX IF NOT EXISTS idx_events_src ON events (src_ip);
CREATE INDEX IF NOT EXISTS idx_events_type ON events (type);

CREATE TABLE IF NOT EXISTS logins (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    service TEXT NOT NULL,
    src_ip TEXT NOT NULL,
    username TEXT NOT NULL,
    password TEXT NOT NULL,
    success INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_logins_ts ON logins (ts);
CREATE INDEX IF NOT EXISTS idx_logins_src ON logins (src_ip);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    alert_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    src_ip TEXT NOT NULL DEFAULT '',
    message TEXT NOT NULL DEFAULT '',
    details_json TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts (ts);
CREATE INDEX IF NOT EXISTS idx_alerts_src ON alerts (src_ip);
"""


class Storage:
    """Thread-safe SQLite sink for events, logins and alerts."""

    def __init__(self, db_path: str) -> None:
        self.db_path = Path(db_path)
        if str(db_path) != ":memory:":
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._db = sqlite3.connect(str(db_path), check_same_thread=False)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=NORMAL")
        with self._lock:
            self._db.executescript(SCHEMA)
            self._db.commit()

    # ---------------------------------------------------------------- writers

    def record_event(self, event: Event) -> int:
        cur = self._insert(
            "INSERT INTO events (ts, type, service, src_ip, src_port, dst_port, details_json)"
            " VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                event.ts,
                event.type,
                event.service,
                event.src_ip,
                event.src_port,
                event.dst_port,
                json.dumps(event.details, default=str),
            ),
        )
        return cur

    def record_login(
        self,
        ts: float,
        service: str,
        src_ip: str,
        username: str,
        password: str,
        success: bool,
    ) -> None:
        with self._lock:
            self._db.execute(
                "INSERT INTO logins (ts, service, src_ip, username, password, success)"
                " VALUES (?, ?, ?, ?, ?, ?)",
                (ts, service, src_ip, username, password, 1 if success else 0),
            )
            self._db.commit()

    def record_alert(
        self,
        ts: float,
        alert_type: str,
        severity: str,
        src_ip: str,
        message: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        with self._lock:
            self._db.execute(
                "INSERT INTO alerts (ts, alert_type, severity, src_ip, message, details_json)"
                " VALUES (?, ?, ?, ?, ?, ?)",
                (
                    ts,
                    alert_type,
                    severity,
                    src_ip,
                    message,
                    json.dumps(details or {}, default=str),
                ),
            )
            self._db.commit()

    # ---------------------------------------------------------------- readers

    def recent_events(self, limit: int = 100) -> List[Dict[str, Any]]:
        return self._select(
            "SELECT ts, type, service, src_ip, src_port, dst_port, details_json"
            " FROM events ORDER BY id DESC LIMIT ?",
            (limit,),
            row_event=True,
        )

    def recent_logins(self, limit: int = 100) -> List[Dict[str, Any]]:
        return self._select(
            "SELECT ts, service, src_ip, username, password, success"
            " FROM logins ORDER BY id DESC LIMIT ?",
            (limit,),
        )

    def recent_alerts(self, limit: int = 100) -> List[Dict[str, Any]]:
        return self._select(
            "SELECT ts, alert_type, severity, src_ip, message, details_json"
            " FROM alerts ORDER BY id DESC LIMIT ?",
            (limit,),
        )

    def counts(self) -> Dict[str, int]:
        queries = {
            "events": "SELECT COUNT(*) AS n FROM events",
            "logins": "SELECT COUNT(*) AS n FROM logins",
            "alerts": "SELECT COUNT(*) AS n FROM alerts",
            "unique_ips": "SELECT COUNT(DISTINCT src_ip) AS n FROM events",
        }
        out: Dict[str, int] = {}
        for key, sql in queries.items():
            row = self._select(sql)
            out[key] = int(row[0]["n"]) if row else 0
        return out

    def top_ips(self, limit: int = 10) -> List[Dict[str, Any]]:
        rows = self._select(
            "SELECT src_ip, COUNT(*) AS hits FROM events GROUP BY src_ip"
            " ORDER BY hits DESC LIMIT ?",
            (limit,),
        )
        for row in rows:
            row["hits"] = row["hits"] if isinstance(row["hits"], int) else row["hits"]
        return rows

    def top_services(self, limit: int = 10) -> List[Dict[str, Any]]:
        return self._select(
            "SELECT service, COUNT(*) AS hits FROM events GROUP BY service"
            " ORDER BY hits DESC LIMIT ?",
            (limit,),
        )

    def top_credentials(self, limit: int = 10) -> List[Dict[str, Any]]:
        return self._select(
            "SELECT username, password, COUNT(*) AS uses FROM logins"
            " GROUP BY username, password ORDER BY uses DESC LIMIT ?",
            (limit,),
        )

    def top_http_paths(self, limit: int = 10, scan: int = 5000) -> List[Dict[str, Any]]:
        """Count the most popular HTTP paths over the recent ``scan`` events.

        Paths live inside ``details_json``; to stay dependency-free we count in
        Python over a bounded window, which is plenty for a single-node pot.
        """
        rows = self._select(
            "SELECT details_json FROM events WHERE type = 'http_request'"
            " ORDER BY id DESC LIMIT ?",
            (scan,),
        )
        counter: Dict[str, int] = {}
        for row in rows:
            try:
                path = str(json.loads(row["details_json"]).get("path", "/"))
            except (json.JSONDecodeError, AttributeError):
                continue
            counter[path] = counter.get(path, 0) + 1
        ranked = sorted(counter.items(), key=lambda kv: kv[1], reverse=True)[:limit]
        return [{"path": p, "hits": c} for p, c in ranked]

    def timeline(self, hours: int = 24, buckets: int = 24) -> List[Dict[str, Any]]:
        """Event counts bucketed over the last ``hours`` hours."""
        since = time.time() - hours * 3600
        rows = self._select(
            "SELECT ts FROM events WHERE ts >= ? ORDER BY ts ASC", (since,)
        )
        width = (hours * 3600) / buckets
        counts = [0] * buckets
        for row in rows:
            idx = min(buckets - 1, int((row["ts"] - since) / width))
            counts[max(0, idx)] += 1
        return [
            {"ts": since + (i + 1) * width, "count": counts[i]} for i in range(buckets)
        ]

    # --------------------------------------------------------------- internals

    def _insert(self, sql: str, params: Iterable[Any]) -> int:
        with self._lock:
            cur = self._db.execute(sql, tuple(params))
            self._db.commit()
            return cur.lastrowid or 0

    def _select(
        self,
        sql: str,
        params: Iterable[Any] = (),
        row_event: bool = False,
    ) -> List[Dict[str, Any]]:
        with self._lock:
            cur = self._db.execute(sql, tuple(params))
            cols = [c[0] for c in cur.description]
            rows = cur.fetchall()
        out: List[Dict[str, Any]] = []
        for raw in rows:
            row = dict(zip(cols, raw))
            if row_event:
                try:
                    row["details"] = json.loads(row.pop("details_json") or "{}")
                except json.JSONDecodeError:
                    row["details"] = {}
            out.append(row)
        return out

    def close(self) -> None:
        with self._lock:
            try:
                self._db.commit()
                self._db.close()
            except sqlite3.Error:
                log.exception("error closing database")


class JsonlEventLog:
    """Append-only JSONL sink — one JSON object per line, SIEM-friendly."""

    def __init__(self, path: str) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def record(self, event: Event) -> None:
        line = json.dumps(event.to_dict(), default=str)
        with self._lock:
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
                fh.flush()
                os.fsync(fh.fileno())

    def close(self) -> None:  # symmetry with Storage; nothing to flush (we fsync)
        pass
