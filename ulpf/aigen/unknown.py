"""Store of events no pack recognised, clustered into candidate new sources.

The fallback path still normalizes these events (offline mapper, low
confidence); this store additionally keeps bounded samples per fingerprint so an
analyst can turn a cluster into a parser with one click (aigen.synth).
"""
from __future__ import annotations

import hashlib
import re
import threading
import time
from collections import OrderedDict, deque

from ..extractors import get as extractor

_DIGITS = re.compile(r"\d+")


def fingerprint(raw: str, sn) -> tuple[str, str]:
    """Return (fingerprint, human label)."""
    fmt = sn.format
    body = raw
    label = fmt
    if sn.envelope == "syslog" or fmt == "syslog":
        try:
            f = extractor("syslog")(raw, {})
            body = f.get("message", raw)
            app = f.get("syslog_app")
            label = f"syslog:{app or f.get('syslog_host') or '?'}"
        except Exception:
            pass
    if fmt == "cef" and "CEF:" in raw:
        label = "cef:" + "|".join(raw[raw.find("CEF:"):].split("|")[1:3])
        key = label
    elif fmt == "leef" and "LEEF:" in raw:
        label = "leef:" + "|".join(raw[raw.find("LEEF:"):].split("|")[1:3])
        key = label
    elif fmt == "kv":
        keys = sorted(set(re.findall(r"(?:^|\s)([A-Za-z_][\w.\-]*)=", body)))[:12]
        key = "kv:" + ",".join(keys)
        label = f"{label} kv({len(keys)} keys)"
    elif fmt == "json":
        keys = sorted(set(re.findall(r'"([A-Za-z_][\w.\-]*)"\s*:', body)))[:12]
        key = "json:" + ",".join(keys)
    else:
        toks = _DIGITS.sub("#", body).split()[:3]
        key = f"{label}:" + " ".join(toks)
    return hashlib.sha256(key.encode()).hexdigest()[:12], label


class UnknownStore:
    def __init__(self, max_clusters: int = 200, per_cluster: int = 200):
        self.max_clusters = max_clusters
        self.per_cluster = per_cluster
        self._lock = threading.Lock()
        self.clusters: OrderedDict[str, dict] = OrderedDict()

    def add(self, raw: str, sn) -> None:
        fp, label = fingerprint(raw, sn)
        now = int(time.time() * 1000)
        with self._lock:
            c = self.clusters.get(fp)
            if c is None:
                if len(self.clusters) >= self.max_clusters:
                    self.clusters.popitem(last=False)
                c = {"id": fp, "label": label, "format": sn.format, "count": 0, "first_ms": now,
                     "samples": deque(maxlen=self.per_cluster)}
                self.clusters[fp] = c
            c["count"] += 1
            c["last_ms"] = now
            c["samples"].append(raw)
            self.clusters.move_to_end(fp)

    def list(self) -> list[dict]:
        with self._lock:
            return sorted(({k: v for k, v in c.items() if k != "samples"} | {"preview": c["samples"][-1][:300]}
                           for c in self.clusters.values()), key=lambda c: -c["count"])

    def samples(self, fp: str, limit: int = 200) -> list[str]:
        with self._lock:
            c = self.clusters.get(fp)
            return list(c["samples"])[-limit:] if c else []

    def drop(self, fp: str) -> None:
        with self._lock:
            self.clusters.pop(fp, None)
