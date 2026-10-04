"""IBM QRadar Log Event Extended Format (LEEF 1.0 / 2.0) extractor."""
from __future__ import annotations

from typing import Any


def extract_leef(text: str, opts: dict) -> dict[str, Any]:
    idx = text.find("LEEF:")
    if idx < 0:
        raise ValueError("not a LEEF record")
    body = text[idx + 5:]
    parts = body.split("|")
    version = parts[0]
    out: dict[str, Any] = {"leef_version": version}
    if len(parts) < 5:
        raise ValueError("truncated LEEF header")
    out.update(device_vendor=parts[1], device_product=parts[2], device_version=parts[3], event_id=parts[4])
    delim = "\t"
    rest_idx = 5
    if version.startswith("2") and len(parts) > 6:
        d = parts[5]
        if d.lower().startswith("x") or d.startswith("0x"):
            delim = chr(int(d.lower().lstrip("0").lstrip("x"), 16))
        elif d:
            delim = d
        rest_idx = 6
    attrs = "|".join(parts[rest_idx:])
    for pair in attrs.split(delim):
        if "=" in pair:
            k, v = pair.split("=", 1)
            if k.strip():
                out[k.strip()] = v.strip()
    return out
