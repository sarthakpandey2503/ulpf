"""ArcSight Common Event Format (CEF) extractor."""
from __future__ import annotations

from typing import Any

from ..security import safe_regex

_HEADER = ["cef_version", "device_vendor", "device_product", "device_version",
           "signature_id", "name", "severity"]
_EXT_KEY = safe_regex(r"(?:^|\s)([A-Za-z0-9_.\[\]\-]+)=")
_ESC_EQ = "\x01"


def _split_header(s: str, n: int) -> tuple[list[str], str]:
    parts, cur, i = [], [], 0
    while i < len(s) and len(parts) < n:
        c = s[i]
        if c == "\\" and i + 1 < len(s):
            cur.append(s[i + 1])
            i += 2
            continue
        if c == "|":
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(c)
        i += 1
    return parts, s[i:]


def parse_extension(ext: str) -> dict[str, str]:
    ext = ext.replace("\\=", _ESC_EQ)
    matches = list(_EXT_KEY.finditer(ext))
    out: dict[str, str] = {}
    for idx, m in enumerate(matches):
        end = matches[idx + 1].start() if idx + 1 < len(matches) else len(ext)
        val = ext[m.end():end].strip()
        out[m.group(1)] = val.replace(_ESC_EQ, "=").replace("\\n", "\n").replace("\\\\", "\\")
    return out


def extract_cef(text: str, opts: dict) -> dict[str, Any]:
    idx = text.find("CEF:")
    if idx < 0:
        raise ValueError("not a CEF record")
    prefix = text[:idx].strip()
    header, ext = _split_header(text[idx + 4:], len(_HEADER))
    out: dict[str, Any] = dict(zip(_HEADER, header))
    if prefix:
        out["cef_prefix"] = prefix
    out.update(parse_extension(ext))
    return out
