"""OCSF 1.3 schema access, type coercion and validation (fully offline).

The schema bundle is compiled from the official ocsf/ocsf-schema repository by
``tools/build_ocsf_schema.py`` and vendored as ``ocsf_schema.json``.
"""
from __future__ import annotations

import ipaddress
import json
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any

SCHEMA_PATH = Path(__file__).with_name("ocsf_schema.json")

SEVERITY = {0: "Unknown", 1: "Informational", 2: "Low", 3: "Medium", 4: "High", 5: "Critical", 6: "Fatal", 99: "Other"}
BASE_EVENT = {"uid": 0, "caption": "Base Event", "category": "other", "category_uid": 0, "attributes": {}}
_ENVELOPE_KEYS = {"unmapped", "raw_data", "ulpf"}
_INT_TYPES = {"integer_t", "long_t", "port_t", "timestamp_t"}
_PRIMITIVES = {"boolean_t", "bytestring_t", "datetime_t", "email_t", "file_hash_t", "file_name_t", "float_t",
               "hostname_t", "integer_t", "ip_t", "json_t", "long_t", "mac_t", "port_t", "process_name_t",
               "resource_uid_t", "string_t", "subnet_t", "timestamp_t", "url_t", "username_t", "uuid_t"}


@lru_cache(maxsize=1)
def schema() -> dict:
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


def version() -> str:
    return schema()["version"]


def get_class(name_or_uid: str | int) -> tuple[str, dict]:
    classes = schema()["classes"]
    if isinstance(name_or_uid, int) or str(name_or_uid).isdigit():
        uid = int(name_or_uid)
        for n, c in classes.items():
            if c["uid"] == uid:
                return n, c
        if uid == 0:
            return "base_event", BASE_EVENT
        raise KeyError(f"unknown OCSF class uid {uid}")
    if name_or_uid == "base_event":
        return "base_event", BASE_EVENT
    return name_or_uid, classes[name_or_uid]


def class_names() -> list[str]:
    return sorted(schema()["classes"])


@lru_cache(maxsize=4096)
def attr_spec(class_name: str, path: str) -> dict | None:
    """Resolve the OCSF attribute spec for a dotted path (``src_endpoint.ip`` -> ip_t)."""
    _, cls = get_class(class_name)
    attrs = cls["attributes"]
    objects = schema()["objects"]
    parts = path.split(".")
    spec: dict | None = None
    for i, part in enumerate(parts):
        part = _split_index(part)[0]
        spec = attrs.get(part)
        if spec is None:
            return None
        if i < len(parts) - 1:
            t = spec["type"]
            obj = t[:-2] if t.endswith("_t") and t not in _PRIMITIVES else t
            if obj not in objects:
                return None
            attrs = objects[obj]["attributes"]
    return spec


def attr_type(class_name: str, path: str) -> str | None:
    spec = attr_spec(class_name, path)
    return spec["type"] if spec else None


def attr_is_array(class_name: str, path: str) -> bool:
    spec = attr_spec(class_name, path)
    return bool(spec and spec.get("is_array")) and not path.endswith("]")


def known_path(class_name: str, path: str) -> bool:
    return attr_type(class_name, path) is not None


def enum_caption(class_name: str, attr: str, value: Any) -> str | None:
    _, cls = get_class(class_name)
    spec = cls["attributes"].get(attr, {})
    enum = spec.get("enum")
    return enum.get(str(value)) if enum else None


# ---------------------------------------------------------------- timestamps

_MONTHS = {m: i for i, m in enumerate(["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}
_FORMATS = [
    "%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S", "%Y/%m/%d %H:%M:%S", "%d/%b/%Y:%H:%M:%S %z",
    "%b %d %Y %H:%M:%S", "%b %d %H:%M:%S", "%Y-%m-%d %H:%M:%S%z", "%d-%b-%Y %H:%M:%S",
]


def _tz(offset: str | None) -> timezone:
    if not offset or offset in ("Z", "UTC"):
        return timezone.utc
    sign = -1 if offset.startswith("-") else 1
    hh, mm = offset.lstrip("+-").replace(":", "")[:2], offset.lstrip("+-").replace(":", "")[2:4] or "0"
    return timezone(sign * timedelta(hours=int(hh), minutes=int(mm)))


def parse_timestamp(value: Any, fmt: str | None = None, tz: str | None = None, now: datetime | None = None) -> int:
    """Return epoch milliseconds from many vendor timestamp encodings."""
    if value is None or value == "":
        raise ValueError("empty timestamp")
    if isinstance(value, (int, float)) or (isinstance(value, str) and value.replace(".", "", 1).isdigit()):
        v = float(value)
        if v > 1e17:
            return int(v / 1e6)      # ns
        if v > 1e14:
            return int(v / 1e3)      # us
        if v > 1e11:
            return int(v)            # ms
        return int(v * 1000)         # s
    s = str(value).strip()
    if s.endswith("Z"):
        s = s[:-1] + "+0000"
    s = " ".join(s.split())
    candidates = [fmt] if fmt else _FORMATS
    for f in candidates:
        try:
            dt = datetime.strptime(s, f)
        except ValueError:
            continue
        if dt.year == 1900:
            ref = now or datetime.now(timezone.utc)
            dt = dt.replace(year=ref.year)
            if dt.replace(tzinfo=timezone.utc) > ref + timedelta(days=2):
                dt = dt.replace(year=ref.year - 1)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=_tz(tz))
        return int(dt.timestamp() * 1000)
    raise ValueError(f"unparseable timestamp {value!r}")


# ------------------------------------------------------------------ coercion

def coerce(value: Any, ocsf_type: str | None, tz: str | None = None) -> Any:
    if value is None or ocsf_type is None:
        return value
    if ocsf_type in ("integer_t", "long_t", "port_t"):
        if isinstance(value, bool):
            return int(value)
        if isinstance(value, (int, float)):
            return int(value)
        s = str(value).strip()
        return int(float(s)) if "." in s else int(s, 0) if s.lower().startswith("0x") else int(s)
    if ocsf_type == "float_t":
        return float(value)
    if ocsf_type == "boolean_t":
        if isinstance(value, bool):
            return value
        s = str(value).strip().lower()
        if s in ("true", "1", "yes", "y", "t"):
            return True
        if s in ("false", "0", "no", "n", "f"):
            return False
        raise ValueError(f"not a boolean: {value!r}")
    if ocsf_type == "timestamp_t":
        return parse_timestamp(value, tz=tz)
    if ocsf_type == "ip_t":
        return str(ipaddress.ip_address(str(value).strip().strip("[]")))
    if ocsf_type in _PRIMITIVES:
        return value if isinstance(value, str) else json.dumps(value) if isinstance(value, (dict, list)) else str(value)
    return value  # object types are passed through


def _split_index(part: str) -> tuple[str, int | None]:
    """``evidences[0]`` -> (``evidences``, 0); array attributes use an explicit index."""
    if part.endswith("]") and "[" in part:
        name, idx = part[:-1].split("[", 1)
        if idx.isdigit() and int(idx) < 64:
            return name, int(idx)
    return part, None


def set_path(obj: dict, path: str, value: Any) -> None:
    parts = path.split(".")
    cur: Any = obj
    for i, raw_part in enumerate(parts):
        name, idx = _split_index(raw_part)
        last = i == len(parts) - 1
        if idx is None:
            if last:
                cur[name] = value
                return
            nxt = cur.get(name)
            if not isinstance(nxt, dict):
                nxt = {}
                cur[name] = nxt
            cur = nxt
            continue
        arr = cur.get(name)
        if not isinstance(arr, list):
            arr = []
            cur[name] = arr
        while len(arr) <= idx:
            arr.append({})
        if last:
            arr[idx] = value
            return
        if not isinstance(arr[idx], dict):
            arr[idx] = {}
        cur = arr[idx]


def get_path(obj: dict, path: str) -> Any:
    cur: Any = obj
    for raw_part in path.split("."):
        name, idx = _split_index(raw_part)
        if not isinstance(cur, dict) or name not in cur:
            return None
        cur = cur[name]
        if idx is not None:
            if not isinstance(cur, list) or idx >= len(cur):
                return None
            cur = cur[idx]
    return cur


# ---------------------------------------------------------------- validation

def validate(event: dict) -> dict:
    """Check required attributes, unknown attributes and primitive types."""
    errors: list[str] = []
    warnings: list[str] = []
    try:
        cname, cls = get_class(event.get("class_uid", 0))
    except KeyError as exc:
        return {"valid": False, "errors": [str(exc)], "warnings": []}
    objects = schema()["objects"]

    def check(attrs: dict, data: dict, prefix: str, depth: int = 0) -> None:
        for name, spec in attrs.items():
            if spec["requirement"] == "required" and name not in data and depth <= 2:
                errors.append(f"missing required {prefix}{name}")
        for name, val in data.items():
            if depth == 0 and name in _ENVELOPE_KEYS:
                continue
            spec = attrs.get(name)
            if spec is None:
                if attrs:
                    warnings.append(f"unknown attribute {prefix}{name}")
                continue
            t = spec["type"]
            obj = t[:-2] if t.endswith("_t") and t not in _PRIMITIVES else t
            if isinstance(val, dict) and obj in objects:
                check(objects[obj]["attributes"], val, f"{prefix}{name}.", depth + 1)
            elif t in _INT_TYPES and not isinstance(val, int):
                errors.append(f"type {prefix}{name}: expected {t}")
            elif t == "boolean_t" and not isinstance(val, bool):
                errors.append(f"type {prefix}{name}: expected boolean_t")

    if cname != "base_event":
        check(cls["attributes"], event, "")
    return {"valid": not errors, "errors": errors, "warnings": warnings}
