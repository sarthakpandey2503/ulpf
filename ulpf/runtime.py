"""Process-wide objects shared by the API, syslog collector, and CLI."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from .audit import AuditLog
from .auth import TokenStore
from .aigen.unknown import UnknownStore
from .config import Settings
from .lineage import Ledger
from .packs.loader import PackRegistry
from .pipeline import Pipeline, RawEvent
from .security import TokenBucket
from .sinks import build_sinks, find


@dataclass
class SyslogOptions:
    host: str = "0.0.0.0"
    udp_port: int = 5514
    tcp_port: int = 5514
    tls_port: int = 6514
    tls_cert: str | None = None
    tls_key: str | None = None
    tls_ca: str | None = None


class Runtime:
    def __init__(self, settings: Settings):
        settings.ensure_dirs()
        self.settings = settings
        self.auth = TokenStore(settings)
        self.audit = AuditLog(settings.data_dir / "audit.jsonl")
        self.ledger = Ledger(settings)
        self.sinks = build_sinks(settings)
        self.store = find(self.sinks, "SQLiteStore")
        self.unknown = UnknownStore()
        self.registry = PackRegistry(settings).load()
        self.pipeline = Pipeline(settings, registry=self.registry, ledger=self.ledger, sinks=self.sinks,
                                 unknown_store=self.unknown)
        self.limiter = TokenBucket(max(1, settings.rate_limit_eps))
        self.syslog: SyslogOptions | None = None

    def reload_packs(self) -> dict:
        self.registry.load()
        return {"loaded": len(self.registry.packs), "rejected": len(self.registry.rejected)}

    def ingest(self, lines: Iterable[str], source: dict | None = None) -> list[dict]:
        events = [RawEvent(line, dict(source or {})) for line in lines if str(line).strip()]
        return self.pipeline.process(events)

    def preview(self, lines: Iterable[str], source: dict | None = None) -> list[dict]:
        src = dict(source or {})
        return [self.pipeline.normalize(line, src) for line in lines if str(line).strip()]
