"""Append-only hash-chained audit log for authentication and admin actions.

Raw log lines are never written here. Each record includes the previous record's
hash, so deleting or editing a line breaks ``verify``.
"""
from __future__ import annotations

import hashlib
import json
import threading
import time
from pathlib import Path

GENESIS = "0" * 64


def _canon(rec: dict) -> str:
    body = {k: rec[k] for k in ("ts", "actor", "action", "detail", "prev")}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), default=str)


class AuditLog:
    def __init__(self, path: Path):
        self.path = path
        self._lock = threading.Lock()
        self._prev = self._head()

    def _head(self) -> str:
        if not self.path.exists():
            return GENESIS
        last = ""
        with self.path.open(encoding="utf-8") as fh:
            for line in fh:
                if line.strip():
                    last = line
        if not last:
            return GENESIS
        try:
            return json.loads(last).get("hash") or GENESIS
        except json.JSONDecodeError:
            return GENESIS

    def write(self, actor: str, action: str, detail: dict | None = None) -> None:
        with self._lock:
            rec = {"ts": int(time.time() * 1000), "actor": actor[:64], "action": action[:64],
                   "detail": detail or {}, "prev": self._prev}
            rec["hash"] = hashlib.sha256(f"{self._prev}|{_canon(rec)}".encode()).hexdigest()
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(rec, default=str) + "\n")
            self._prev = rec["hash"]

    def recent(self, limit: int = 100) -> list[dict]:
        if not self.path.exists():
            return []
        lines = self.path.read_text(encoding="utf-8").splitlines()
        out = []
        for line in lines[-max(1, min(limit, 500)):]:
            if line.strip():
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    out.append({"error": "corrupt audit line"})
        return out

    def verify(self) -> dict:
        if not self.path.exists():
            return {"verified": True, "records": 0}
        prev = GENESIS
        n = 0
        with self.path.open(encoding="utf-8") as fh:
            for line in fh:
                if not line.strip():
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    return {"verified": False, "failed_at": n, "reason": "corrupt line"}
                expect = hashlib.sha256(f"{prev}|{_canon(rec)}".encode()).hexdigest()
                if rec.get("prev") != prev or rec.get("hash") != expect:
                    return {"verified": False, "failed_at": n, "reason": "chain break"}
                prev = rec["hash"]
                n += 1
        return {"verified": True, "records": n, "head": prev}
