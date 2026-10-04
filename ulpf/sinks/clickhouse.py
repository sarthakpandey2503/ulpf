"""ClickHouse sink for high-volume analytics (billions of events/day scale-out)."""
from __future__ import annotations

import json
from urllib.parse import urlparse

DDL = """
CREATE TABLE IF NOT EXISTS ocsf_events (
    uid String, time DateTime64(3), class_uid UInt32, class_name LowCardinality(String),
    activity_id Int32, severity_id Int8, src_ip Nullable(String), dst_ip Nullable(String),
    src_port Nullable(Int32), dst_port Nullable(Int32), disposition_id Nullable(Int32),
    vendor LowCardinality(String), product LowCardinality(String), pack LowCardinality(Nullable(String)),
    confidence Float32, raw_sha256 FixedString(64), batch_id Nullable(UInt64),
    event String CODEC(ZSTD(3)), raw_data String CODEC(ZSTD(3))
) ENGINE = MergeTree
PARTITION BY (class_uid, toYYYYMMDD(time))
ORDER BY (class_uid, time, uid)
"""

_COLS = ["uid", "time", "class_uid", "class_name", "activity_id", "severity_id", "src_ip", "dst_ip", "src_port",
         "dst_port", "disposition_id", "vendor", "product", "pack", "confidence", "raw_sha256", "batch_id", "event",
         "raw_data"]


class ClickHouseSink:
    def __init__(self, url: str, password: str | None = None, database: str = "default"):
        import clickhouse_connect

        u = urlparse(url)
        self.client = clickhouse_connect.get_client(
            host=u.hostname or "localhost", port=u.port or 8123, username=u.username or "default",
            password=password or u.password or "", database=database, secure=u.scheme == "https")
        self.client.command(DDL)

    def write(self, events: list[dict]) -> None:
        from datetime import datetime, timezone

        from .files import ParquetSink

        rows = []
        for e in events:
            r = ParquetSink._row(e)
            r["time"] = datetime.fromtimestamp((r["time"] or 0) / 1000, tz=timezone.utc)
            r["event"] = r["event"] if isinstance(r["event"], str) else json.dumps(r["event"])
            rows.append([r[c] for c in _COLS])
        if rows:
            self.client.insert("ocsf_events", rows, column_names=_COLS)
