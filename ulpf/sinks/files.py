"""File-based sinks: JSONL and a partitioned Parquet data lake (local or S3/MinIO)."""
from __future__ import annotations

import json
import threading
import time
import uuid
from pathlib import Path

from ..config import Settings, secret_from_file


class JSONLSink:
    def __init__(self, directory: Path):
        self.dir = directory
        self.dir.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def write(self, events: list[dict]) -> None:
        day = time.strftime("%Y-%m-%d", time.gmtime())
        with self._lock, (self.dir / f"ocsf-{day}.jsonl").open("a", encoding="utf-8") as fh:
            for e in events:
                fh.write(json.dumps(e, ensure_ascii=False, separators=(",", ":"), default=str) + "\n")


class ParquetSink:
    """Hive-partitioned Parquet: class_uid=<n>/dt=<YYYY-MM-DD>/part-*.parquet.

    Hot query columns are typed; the full OCSF event is kept as JSON in ``event``
    and the original log in ``raw_data`` so the lake stays lossless.
    """

    def __init__(self, settings: Settings):
        import pyarrow as pa
        import pyarrow.fs as pafs

        self.pa = pa
        self.schema = pa.schema([
            ("uid", pa.string()), ("time", pa.int64()), ("class_uid", pa.int32()), ("class_name", pa.string()),
            ("activity_id", pa.int32()), ("severity_id", pa.int32()), ("src_ip", pa.string()), ("dst_ip", pa.string()),
            ("src_port", pa.int32()), ("dst_port", pa.int32()), ("disposition_id", pa.int32()),
            ("vendor", pa.string()), ("product", pa.string()), ("pack", pa.string()), ("confidence", pa.float32()),
            ("raw_sha256", pa.string()), ("batch_id", pa.int64()), ("event", pa.string()), ("raw_data", pa.string()),
        ])
        if settings.s3_endpoint:
            self.fs = pafs.S3FileSystem(endpoint_override=settings.s3_endpoint,
                                        access_key=secret_from_file("S3_ACCESS_KEY"),
                                        secret_key=secret_from_file("S3_SECRET_KEY"),
                                        scheme="https" if settings.s3_endpoint.startswith("https") else "http")
            self.base = settings.s3_bucket
        else:
            self.fs = pafs.LocalFileSystem()
            self.base = str(settings.data_dir / "lake")
            Path(self.base).mkdir(parents=True, exist_ok=True)

    @staticmethod
    def _row(e: dict) -> dict:
        src, dst = e.get("src_endpoint") or {}, e.get("dst_endpoint") or {}
        ev = e.get("evidences")
        if isinstance(ev, list) and ev and isinstance(ev[0], dict):
            src = src or ev[0].get("src_endpoint") or {}
            dst = dst or ev[0].get("dst_endpoint") or {}
        return {
            "uid": e["metadata"]["uid"], "time": e.get("time"), "class_uid": e["class_uid"],
            "class_name": e["class_name"], "activity_id": e.get("activity_id"), "severity_id": e.get("severity_id"),
            "src_ip": src.get("ip"), "dst_ip": dst.get("ip"),
            "src_port": src.get("port") if isinstance(src.get("port"), int) else None,
            "dst_port": dst.get("port") if isinstance(dst.get("port"), int) else None,
            "disposition_id": e.get("disposition_id"),
            "vendor": e["metadata"]["product"].get("vendor_name"), "product": e["metadata"]["product"].get("name"),
            "pack": e["ulpf"].get("pack"), "confidence": e["ulpf"].get("confidence"),
            "raw_sha256": e["ulpf"]["raw_sha256"], "batch_id": e["ulpf"].get("batch_id"),
            "event": json.dumps({k: v for k, v in e.items() if k != "raw_data"}, ensure_ascii=False, default=str),
            "raw_data": e.get("raw_data"),
        }

    def write(self, events: list[dict]) -> None:
        import pyarrow.parquet as pq

        if not events:
            return
        groups: dict[tuple[int, str], list[dict]] = {}
        for e in events:
            day = time.strftime("%Y-%m-%d", time.gmtime((e.get("time") or 0) / 1000))
            groups.setdefault((e["class_uid"], day), []).append(self._row(e))
        for (cls, day), rows in groups.items():
            table = self.pa.Table.from_pylist(rows, schema=self.schema)
            d = f"{self.base}/class_uid={cls}/dt={day}"
            self.fs.create_dir(d, recursive=True)
            pq.write_table(table, f"{d}/part-{uuid.uuid4().hex}.parquet", filesystem=self.fs, compression="zstd")
