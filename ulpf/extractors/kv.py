from __future__ import annotations

from functools import lru_cache
from typing import Any

from ..security import safe_regex


@lru_cache(maxsize=64)
def _pattern(pair_sep: str, kv_sep: str, quote: str):
    k = r"([A-Za-z_][\w.\-:/\[\]@]*)"
    ps = "\\s" if pair_sep in (" ", "\\s") else "".join("\\" + c for c in pair_sep)
    ks = "".join("\\" + c for c in kv_sep)
    q = "\\" + quote
    value = f"({q}(?:[^{q}\\\\]|\\\\.)*{q}|[^{ps}]*)"
    # With whitespace-separated pairs an empty value ("a= b=1") must not swallow the next pair.
    after = "" if ps == "\\s" else "\\s*"
    return safe_regex(f"{k}\\s*{ks}{after}{value}")


def extract_kv(text: str, opts: dict) -> dict[str, Any]:
    """Key/value pairs such as FortiGate ``srcip=1.2.3.4 msg="a b"``."""
    pair_sep = opts.get("pair_sep", " ")
    kv_sep = opts.get("kv_sep", "=")
    quote = opts.get("quote", '"')
    out: dict[str, Any] = {}
    for m in _pattern(pair_sep, kv_sep, quote).finditer(text):
        key, val = m.group(1), m.group(2)
        if len(val) >= 2 and val[0] == quote and val[-1] == quote:
            val = val[1:-1].replace("\\" + quote, quote)
        out[key] = val
    return out
