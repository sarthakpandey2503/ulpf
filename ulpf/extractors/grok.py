"""Grok-style and raw regex extractors, compiled with RE2 (ReDoS-safe)."""
from __future__ import annotations

from functools import lru_cache
from typing import Any

from ..security import safe_regex

GROK_PATTERNS: dict[str, str] = {
    "INT": r"[+-]?\d+",
    "POSINT": r"\d+",
    "NUMBER": r"[+-]?\d+(?:\.\d+)?",
    "WORD": r"\w+",
    "NOTSPACE": r"\S+",
    "SPACE": r"\s*",
    "DATA": r".*?",
    "GREEDYDATA": r".*",
    "QS": r'"(?:[^"\\]|\\.)*"',
    "IPV4": r"(?:\d{1,3}\.){3}\d{1,3}",
    "IPV6": r"[0-9A-Fa-f:]*:[0-9A-Fa-f:.]+",
    "IP": r"(?:(?:\d{1,3}\.){3}\d{1,3}|[0-9A-Fa-f:]*:[0-9A-Fa-f:.]+)",
    "HOSTNAME": r"[A-Za-z0-9][A-Za-z0-9.\-_]*",
    "IPORHOST": r"(?:(?:\d{1,3}\.){3}\d{1,3}|[A-Za-z0-9][A-Za-z0-9.\-_]*)",
    "USERNAME": r"[A-Za-z0-9._@\\\-]+",
    "MAC": r"(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}",
    "URIPATH": r"/[^\s?#]*",
    "URI": r"[A-Za-z][A-Za-z0-9+.\-]*://\S+",
    "MONTH": r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)[a-z]*",
    "SYSLOGTIMESTAMP": r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) +\d{1,2} \d{2}:\d{2}:\d{2}",
    "TIMESTAMP_ISO8601": r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?",
    "HTTPDATE": r"\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4}",
}

_TOKEN = safe_regex(r"%\{([A-Z0-9_]+)(?::([A-Za-z0-9_.@\-]+))?\}")


def grok_to_regex(pattern: str) -> tuple[str, dict[str, str]]:
    """Translate ``%{IP:src_ip}`` into ``(?P<g0>...)``; returns regex and group->field map."""
    names: dict[str, str] = {}
    out, pos, idx = [], 0, 0
    for m in _TOKEN.finditer(pattern):
        out.append(pattern[pos:m.start()])
        base = GROK_PATTERNS.get(m.group(1))
        if base is None:
            raise ValueError(f"unknown grok pattern {m.group(1)}")
        if m.group(2):
            g = f"g{idx}"
            names[g] = m.group(2)
            idx += 1
            out.append(f"(?P<{g}>{base})")
        else:
            out.append(f"(?:{base})")
        pos = m.end()
    out.append(pattern[pos:])
    return "".join(out), names


@lru_cache(maxsize=512)
def _compile_grok(pattern: str):
    rx, names = grok_to_regex(pattern)
    return safe_regex(rx), names


@lru_cache(maxsize=512)
def _compile_regex(pattern: str):
    return safe_regex(pattern)


def extract_grok(text: str, opts: dict) -> dict[str, Any]:
    patterns = opts.get("patterns") or [opts["pattern"]]
    for p in patterns:
        rx, names = _compile_grok(p)
        m = rx.search(text)
        if m:
            return {names[g]: v for g, v in m.groupdict().items() if v is not None}
    if opts.get("required", True):
        raise ValueError("no grok pattern matched")
    return {}


def extract_regex(text: str, opts: dict) -> dict[str, Any]:
    patterns = opts.get("patterns") or [opts["pattern"]]
    for p in patterns:
        m = _compile_regex(p).search(text)
        if m:
            return {k: v for k, v in m.groupdict().items() if v is not None}
    if opts.get("required", True):
        raise ValueError("no regex matched")
    return {}
