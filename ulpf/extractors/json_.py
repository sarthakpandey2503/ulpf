from __future__ import annotations

from typing import Any

from ..config import settings
from ..security import InputRejected, safe_json_loads


def flatten(obj: Any, prefix: str = "", out: dict | None = None, max_fields: int | None = None) -> dict:
    """Flatten nested dicts to dotted keys. Lists are kept as values (lossless)."""
    out = {} if out is None else out
    limit = max_fields or settings.max_fields
    if isinstance(obj, dict):
        for k, v in obj.items():
            key = f"{prefix}.{k}" if prefix else str(k)
            if isinstance(v, dict) and v:
                flatten(v, key, out, limit)
            else:
                out[key] = v
                if len(out) > limit:
                    raise InputRejected(f"more than {limit} fields")
    else:
        out[prefix or "value"] = obj
    return out


def extract_json(text: str, opts: dict) -> dict[str, Any]:
    obj = safe_json_loads(text.strip(), settings.max_json_depth)
    if opts.get("flatten", True):
        return flatten(obj)
    return obj if isinstance(obj, dict) else {"value": obj}
