"""Build the lossless ULPF envelope around an OCSF event.

Guarantees (expected outcomes a-d of PS 26156):
  a) ``raw_data`` holds the exact original bytes (decoded), ``ulpf.raw_sha256`` proves it.
  b) every extracted source field is either mapped to OCSF or kept in ``unmapped``.
  c) the event is typed and validated against OCSF 1.3.
  d) ``ulpf.field_lineage`` links every normalized attribute to its raw field.
"""
from __future__ import annotations

import hashlib
import re
import time
import uuid
from typing import Any

from . import ocsf

_CAMEL1 = re.compile(r"(.)([A-Z][a-z]+)")
_CAMEL2 = re.compile(r"([a-z0-9])([A-Z])")
_NONWORD = re.compile(r"[^0-9a-zA-Z]+")


def snake(name: str) -> str:
    s = _CAMEL2.sub(r"\1_\2", _CAMEL1.sub(r"\1_\2", name))
    return _NONWORD.sub("_", s).strip("_").lower() or "field"


def sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="surrogateescape")).hexdigest()


def _fill_required_enums(data: dict, attrs: dict, lineage: dict, prefix: str, depth: int = 0) -> None:
    """Set required ``*_id`` enums on present objects to 0 (Unknown), as OCSF prescribes
    when the source does not carry the information. Recorded in lineage as a default."""
    objects = ocsf.schema()["objects"]
    for name, val in list(data.items()):
        spec = attrs.get(name)
        if not spec or not isinstance(val, dict) or depth > 3:
            continue
        obj = objects.get(spec["type"])
        if not obj:
            continue
        oattrs = obj["attributes"]
        for aname, aspec in oattrs.items():
            if aspec["requirement"] == "required" and aname.endswith("_id") and aname not in val \
                    and "0" in (aspec.get("enum") or {}):
                val[aname] = 0
                lineage[f"{prefix}{name}.{aname}"] = "default:unknown"
        _fill_required_enums(val, oattrs, lineage, f"{prefix}{name}.", depth + 1)


def build_event(raw: str, *, class_name: str, class_def: dict, activity_id: int, severity_id: int,
                attrs: dict[str, Any], fields: dict[str, Any], consumed: set[str], lineage: dict[str, Any],
                vendor: str, product: str, pack_ref: str | None, pack_signed: bool, class_rule: str | None,
                confidence: float, fmt: str, source: dict | None, parse_errors: list[str],
                received_ms: int | None = None) -> dict:
    now_ms = int(time.time() * 1000)
    received_ms = received_ms or now_ms
    class_uid = class_def["uid"]
    event: dict[str, Any] = {
        "class_uid": class_uid,
        "class_name": class_def["caption"],
        "category_uid": class_def["category_uid"],
        "category_name": class_def["category"].replace("_", " ").title() if class_uid else "Uncategorized",
        "activity_id": activity_id,
        "severity_id": severity_id,
        "severity": ocsf.SEVERITY.get(severity_id, "Other"),
    }
    activity_name = ocsf.enum_caption(class_name, "activity_id", activity_id) if class_uid else None
    if activity_name:
        event["activity_name"] = activity_name
    event["type_uid"] = class_uid * 100 + activity_id
    event["type_name"] = f"{class_def['caption']}: {activity_name or 'Unknown'}"

    for path, value in attrs.items():
        ocsf.set_path(event, path, value)
        # OCSF convention: *_id enums carry a sibling caption attribute.
        if path.endswith("_id") and "." not in path and class_uid:
            cap = ocsf.enum_caption(class_name, path, value)
            if cap and path[:-3] not in attrs:
                event[path[:-3]] = cap

    if class_uid:
        _fill_required_enums(event, class_def["attributes"], lineage, "")

    warnings: list[str] = []
    if "time" not in event:
        event["time"] = received_ms
        lineage["time"] = "ulpf.received_time"
        warnings.append("time not present in source; receipt time used")

    md = event.setdefault("metadata", {})
    md["version"] = ocsf.version()
    prod = md.setdefault("product", {})
    prod.setdefault("vendor_name", vendor)
    prod.setdefault("name", product)
    md["uid"] = str(uuid.uuid4())
    md["logged_time"] = received_ms
    md["processed_time"] = now_ms
    if pack_ref:
        md["log_provider"] = pack_ref
    if class_rule:
        md.setdefault("log_name", class_rule)
    tsrc = lineage.get("time")
    if isinstance(tsrc, str) and tsrc in fields:
        md["original_time"] = str(fields[tsrc])

    unmapped: dict[str, Any] = {}
    for k, v in fields.items():
        if k in consumed or v in (None, ""):
            continue
        key = snake(k)
        n = 2
        while key in unmapped:
            key = f"{snake(k)}_{n}"
            n += 1
        unmapped[key] = v
        lineage[f"unmapped.{key}"] = k
    if unmapped:
        event["unmapped"] = unmapped

    event["raw_data"] = raw
    validation = ocsf.validate(event)
    validation["warnings"] = warnings + validation["warnings"]
    if parse_errors:
        validation["errors"] = parse_errors + validation["errors"]
        validation["valid"] = False
    if not validation["valid"]:
        confidence = round(confidence * 0.9, 3)
    event["ulpf"] = {
        "raw_sha256": sha256_hex(raw),
        "raw_size": len(raw.encode("utf-8", errors="surrogateescape")),
        "pack": pack_ref,
        "pack_signed": pack_signed,
        "format": fmt,
        "source": source or {},
        "confidence": confidence,
        "field_lineage": lineage,
        "field_count": {"extracted": len(fields), "mapped": len(consumed & set(fields)), "unmapped": len(unmapped)},
        "validation": validation,
    }
    return event
