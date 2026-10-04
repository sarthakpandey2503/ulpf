"""Output sinks. Each sink exposes ``write(events: list[dict])``."""
from __future__ import annotations

from ..config import Settings, secret_from_file


def build_sinks(settings: Settings, names: list[str] | None = None) -> list:
    names = names if names is not None else settings.sinks
    sinks = []
    for n in names:
        if n == "sqlite":
            from .sqlite_store import SQLiteStore
            sinks.append(SQLiteStore(settings))
        elif n == "jsonl":
            from .files import JSONLSink
            sinks.append(JSONLSink(settings.data_dir / "events"))
        elif n == "parquet":
            from .files import ParquetSink
            sinks.append(ParquetSink(settings))
        elif n == "clickhouse":
            from .clickhouse import ClickHouseSink
            sinks.append(ClickHouseSink(settings.clickhouse_url, password=secret_from_file("CLICKHOUSE_PASSWORD")))
        elif n == "splunk":
            from .siem import SplunkHECSink
            sinks.append(SplunkHECSink(settings.splunk_hec_url, secret_from_file("SPLUNK_HEC_TOKEN") or "",
                                       verify=settings.tls_verify))
        elif n == "elastic":
            from .siem import ElasticSink
            sinks.append(ElasticSink(settings.elastic_url, secret_from_file("ELASTIC_API_KEY"), verify=settings.tls_verify))
        elif n == "cef":
            from .siem import CEFForwarder
            sinks.append(CEFForwarder(settings.cef_forward))
        else:
            raise ValueError(f"unknown sink '{n}'")
    return sinks


def find(sinks: list, cls_name: str):
    return next((s for s in sinks if type(s).__name__ == cls_name), None)
