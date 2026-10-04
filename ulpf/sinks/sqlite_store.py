"""Default event store (SQLite, WAL). Serves the API/dashboard and lineage verification.

All queries are parameterized; column names used for filtering come from a fixed
allow-list, never from user input.
"""
from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path

from ..config import Settings

_FILTERS = {"class_uid": "class_uid = ?", "pack": "pack = ?", "severity_min": "severity_id >= ?",
            "src_ip": "src_ip = ?", "dst_ip": "dst_ip = ?", "valid": "valid = ?", "since": "time >= ?",
            "until": "time <= ?", "fallback": "pack IS NULL"}


def _ip(e: dict, side: str) -> str | None:
    ep = e.get(f"{side}_endpoint") or {}
    if ep.get("ip"):
        return ep["ip"]
    ev = (e.get("evidences") or [{}])[0] if isinstance(e.get("evidences"), list) else {}
    return ((ev or {}).get(f"{side}_endpoint") or {}).get("ip")


class SQLiteStore:
    def __init__(self, settings: Settings, path: Path | None = None):
        settings.ensure_dirs()
        self.path = path or settings.data_dir / "events.db"
        self._lock = threading.Lock()
        self._db = sqlite3.connect(self.path, check_same_thread=False, isolation_level=None)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=NORMAL")
        self._db.executescript("""
            CREATE TABLE IF NOT EXISTS events (
                uid TEXT PRIMARY KEY, time INTEGER, class_uid INTEGER, class_name TEXT, pack TEXT,
                severity_id INTEGER, src_ip TEXT, dst_ip TEXT, confidence REAL, valid INTEGER,
                raw_sha256 TEXT, batch_id INTEGER, body TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS ev_time ON events(time);
            CREATE INDEX IF NOT EXISTS ev_class ON events(class_uid);
            CREATE INDEX IF NOT EXISTS ev_src ON events(src_ip);
            CREATE INDEX IF NOT EXISTS ev_raw ON events(raw_sha256);
        """)

    def write(self, events: list[dict]) -> None:
        rows = [(e["metadata"]["uid"], e.get("time"), e["class_uid"], e["class_name"], e["ulpf"].get("pack"),
                 e.get("severity_id"), _ip(e, "src"), _ip(e, "dst"), e["ulpf"].get("confidence"),
                 1 if e["ulpf"]["validation"]["valid"] else 0, e["ulpf"]["raw_sha256"], e["ulpf"].get("batch_id"),
                 json.dumps(e, ensure_ascii=False, separators=(",", ":"), default=str)) for e in events]
        with self._lock:
            self._db.execute("BEGIN")
            self._db.executemany("INSERT OR REPLACE INTO events VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", rows)
            self._db.execute("COMMIT")

    def get(self, uid: str) -> dict | None:
        with self._lock:
            row = self._db.execute("SELECT body FROM events WHERE uid = ?", (uid,)).fetchone()
        return json.loads(row[0]) if row else None

    def query(self, limit: int = 100, offset: int = 0, **filters) -> list[dict]:
        where, args = [], []
        for k, v in filters.items():
            if v is None or k not in _FILTERS:
                continue
            where.append(_FILTERS[k])
            if k != "fallback":
                args.append(v)
        sql = "SELECT body FROM events"
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY rowid DESC LIMIT ? OFFSET ?"
        args += [max(1, min(int(limit), 1000)), max(0, int(offset))]
        with self._lock:
            return [json.loads(r[0]) for r in self._db.execute(sql, args)]

    def count(self) -> int:
        with self._lock:
            return self._db.execute("SELECT COUNT(*) FROM events").fetchone()[0]

    def summary(self) -> dict:
        with self._lock:
            by_class = self._db.execute("SELECT class_name, COUNT(*) FROM events GROUP BY class_name ORDER BY 2 DESC").fetchall()
            by_pack = self._db.execute("SELECT COALESCE(pack,'fallback'), COUNT(*), AVG(confidence), AVG(valid) "
                                       "FROM events GROUP BY 1 ORDER BY 2 DESC").fetchall()
            total = self._db.execute("SELECT COUNT(*), AVG(valid), AVG(confidence) FROM events").fetchone()
        return {"total": total[0], "valid_ratio": round(total[1] or 0, 4), "avg_confidence": round(total[2] or 0, 3),
                "by_class": dict(by_class),
                "by_pack": [{"pack": p, "count": c, "avg_confidence": round(a or 0, 3), "valid_ratio": round(v or 0, 4)}
                            for p, c, a, v in by_pack]}

    def tamper_raw(self, uid: str, new_raw: str) -> bool:
        """Demo helper: simulate an attacker editing a stored log (bypasses the ledger)."""
        e = self.get(uid)
        if not e:
            return False
        e["raw_data"] = new_raw
        with self._lock:
            self._db.execute("UPDATE events SET body = ? WHERE uid = ?", (json.dumps(e, ensure_ascii=False), uid))
        return True
