"""ULPF processing pipeline: raw -> sniff -> route -> parse -> OCSF -> lineage -> sinks."""
from __future__ import annotations

import logging
import threading
import time
from collections import Counter, deque
from dataclasses import dataclass, field
from typing import Any, Iterable

from . import extractors
from .aigen import mapper
from .config import Settings, settings as default_settings
from .normalizer import ocsf
from .normalizer.envelope import build_event, sha256_hex
from .packs.loader import PackRegistry
from .security import InputRejected, check_line
from .sniffer import sniff

log = logging.getLogger("ulpf.pipeline")


@dataclass
class RawEvent:
    text: str | bytes
    source: dict = field(default_factory=dict)   # transport, peer, source_hint, file ...
    received_ms: int = field(default_factory=lambda: int(time.time() * 1000))


class Stats:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.counters: Counter = Counter()
        self.by_pack: Counter = Counter()
        self.by_class: Counter = Counter()
        self.latency_us: deque = deque(maxlen=5000)
        self.started = time.time()

    def record(self, event: dict, us: float) -> None:
        with self._lock:
            self.counters["processed"] += 1
            self.by_pack[event["ulpf"]["pack"] or "fallback"] += 1
            self.by_class[event["class_name"]] += 1
            if not event["ulpf"]["validation"]["valid"]:
                self.counters["validation_errors"] += 1
            self.latency_us.append(us)

    def inc(self, key: str, n: int = 1) -> None:
        with self._lock:
            self.counters[key] += n

    def snapshot(self) -> dict:
        with self._lock:
            lat = sorted(self.latency_us)
            pct = (lambda q: round(lat[min(len(lat) - 1, int(q * len(lat)))], 1) if lat else 0)
            up = max(1e-6, time.time() - self.started)
            return {
                "counters": dict(self.counters), "by_pack": dict(self.by_pack.most_common()),
                "by_class": dict(self.by_class.most_common()),
                "latency_us": {"p50": pct(0.5), "p99": pct(0.99)},
                "uptime_s": round(up, 1), "avg_eps": round(self.counters["processed"] / up, 1),
            }


class Pipeline:
    def __init__(self, settings: Settings | None = None, registry: PackRegistry | None = None,
                 ledger=None, sinks: list | None = None, unknown_store=None):
        self.settings = settings or default_settings
        self.registry = registry or PackRegistry(self.settings).load()
        self.ledger = ledger
        self.sinks = sinks or []
        self.unknown_store = unknown_store
        self.stats = Stats()
        self.dead_letters: deque = deque(maxlen=1000)
        self._process_lock = threading.Lock()

    # ------------------------------------------------------------ single event
    def normalize(self, raw_in: str | bytes, source: dict | None = None, received_ms: int | None = None) -> dict:
        source = dict(source or {})
        raw = check_line(raw_in, self.settings.max_line_bytes)
        sn = sniff(raw)
        hint = source.get("source_hint")
        failures: list[str] = []
        for pack in self.registry.candidates(raw, sn, hint):
            try:
                r = pack.apply(raw)
            except InputRejected:
                raise
            except Exception as exc:
                failures.append(f"{pack.ref}: {exc}")
                continue
            return build_event(
                raw, class_name=r["class_name"], class_def=r["class_def"], activity_id=r["activity_id"],
                severity_id=r["severity_id"], attrs=r["attrs"], fields=r["fields"], consumed=r["consumed"],
                lineage=r["lineage"], vendor=pack.vendor, product=pack.product, pack_ref=pack.ref,
                pack_signed=pack.signed, class_rule=r["class_rule"], confidence=pack.trust,
                fmt="+".join(sorted(sn.tags)), source=source, parse_errors=r["errors"], received_ms=received_ms)
        return self._fallback(raw, sn, source, failures, received_ms)

    def _fallback(self, raw: str, sn, source: dict, failures: list[str], received_ms: int | None) -> dict:
        fields: dict[str, Any] = {}
        try:
            if sn.envelope == "syslog" or sn.format == "syslog":
                fields = extractors.get("syslog")(raw, {})
                payload = fields.get("message", "")
                if sn.format in ("kv", "cef", "leef", "json", "csv") and payload:
                    fields.pop("message", None)
                    fields.update(extractors.get(sn.format)(payload, {}))
            elif sn.format in ("json", "xml", "kv", "cef", "leef", "csv"):
                fields = extractors.get(sn.format)(raw, {})
        except InputRejected:
            raise
        except Exception as exc:
            failures.append(f"fallback-{sn.format}: {exc}")
        guess = mapper.infer(fields) if fields else mapper.MappingGuess("base_event")
        cname, cdef = ocsf.get_class(guess.class_name)
        attrs: dict[str, Any] = {}
        lineage: dict[str, Any] = {}
        consumed: set[str] = set()
        sev = 1
        for path, m in guess.matches.items():
            v = fields.get(m.raw)
            try:
                if path == "severity_id":
                    sev = mapper.severity_id(v) or 1
                elif path == "disposition":
                    attrs["disposition_id"] = mapper.disposition_id(v)
                    attrs["disposition"] = str(v)
                    lineage["disposition_id"] = m.raw
                else:
                    t = ocsf.attr_type(cname, path) if cname != "base_event" else None
                    attrs[path] = ocsf.coerce(v, t)
                lineage[path] = m.raw
                consumed.add(m.raw)
            except (ValueError, TypeError):
                continue
        if cname == "detection_finding" and "finding_info.title" in attrs and "finding_info.uid" not in attrs:
            attrs["finding_info.uid"] = sha256_hex(str(attrs["finding_info.title"]))[:16]
            lineage["finding_info.uid"] = "derived:sha256(finding_info.title)"
        self.stats.inc("fallback")
        if self.unknown_store is not None:
            self.unknown_store.add(raw, sn)
        return build_event(
            raw, class_name=cname, class_def=cdef, activity_id=0, severity_id=sev, attrs=attrs, fields=fields,
            consumed=consumed, lineage=lineage, vendor=fields.get("device_vendor", "Unknown"),
            product=fields.get("device_product", "Unknown"), pack_ref=None, pack_signed=False,
            class_rule="fallback:" + guess.class_name, confidence=guess.confidence if attrs else 0.0,
            fmt="+".join(sorted(sn.tags)), source={**source, "pack_failures": failures[:5]} if failures else source,
            parse_errors=[], received_ms=received_ms)

    # ------------------------------------------------------------------ batch
    def process(self, events: Iterable[RawEvent]) -> list[dict]:
        with self._process_lock:
            return self._process(events)

    def _process(self, events: Iterable[RawEvent]) -> list[dict]:
        out: list[dict] = []
        for ev in events:
            t0 = time.perf_counter()
            try:
                e = self.normalize(ev.text, ev.source, ev.received_ms)
            except Exception as exc:  # malformed / hostile input -> dead letter, never crash
                self.stats.inc("dead_letter")
                text = ev.text if isinstance(ev.text, str) else ev.text[:2048].decode("utf-8", "replace")
                self.dead_letters.append({"error": str(exc)[:500], "source": ev.source, "raw_preview": text[:512],
                                          "received_ms": ev.received_ms})
                continue
            self.stats.record(e, (time.perf_counter() - t0) * 1e6)
            out.append(e)
        if self.ledger is not None and out:
            self.ledger.append(out)
        for sink in self.sinks:
            try:
                sink.write(out)
            except Exception as exc:
                self.stats.inc(f"sink_error:{type(sink).__name__}")
                log.error("sink %s failed: %s", type(sink).__name__, exc)
        return out

    def process_lines(self, lines: Iterable[str], source: dict | None = None) -> list[dict]:
        return self.process(RawEvent(l, dict(source or {})) for l in lines if l.strip())
