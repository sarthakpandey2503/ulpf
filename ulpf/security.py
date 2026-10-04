"""Security primitives shared across ULPF.

Every log line is attacker-controlled input. These helpers enforce size and
structure limits, give linear-time regular expressions (RE2, immune to ReDoS),
and load YAML without object construction.
"""
from __future__ import annotations

import json
import threading
import time
from typing import Any

import yaml

try:
    import re2 as _re2  # google-re2: linear-time matching, no catastrophic backtracking

    _re2_options = _re2.Options()
    _re2_options.max_mem = 8 << 20
    HAVE_RE2 = True
except ImportError:  # pragma: no cover
    _re2 = None
    HAVE_RE2 = False

import re as _re


class InputRejected(ValueError):
    """Raised when an event violates an input safety limit."""


def safe_regex(pattern: str, flags: int = 0):
    """Compile an untrusted regex (from packs or AI drafts) with RE2.

    RE2 does not support backreferences or lookaround, which is exactly what makes
    it safe against ReDoS. Falls back to ``re`` only when RE2 is unavailable.
    """
    if HAVE_RE2:
        if flags & _re.IGNORECASE:
            pattern = "(?i)" + pattern
        return _re2.compile(pattern, options=_re2_options)
    return _re.compile(pattern, flags)  # pragma: no cover


def safe_yaml_load(text: str) -> Any:
    """Parse YAML with the safe loader only (no arbitrary Python objects)."""
    if len(text) > 1_000_000:
        raise InputRejected("YAML document too large")
    return yaml.safe_load(text)


def check_line(raw: bytes | str, max_bytes: int) -> str:
    """Decode and bound a single raw event."""
    if isinstance(raw, bytes):
        if len(raw) > max_bytes:
            raise InputRejected(f"event exceeds {max_bytes} bytes")
        text = raw.decode("utf-8", errors="replace")
    else:
        text = raw
        if len(text.encode("utf-8", errors="replace")) > max_bytes:
            raise InputRejected(f"event exceeds {max_bytes} bytes")
    if "\x00" in text:
        text = text.replace("\x00", "\\x00")
    return text


def json_depth(obj: Any, limit: int, _depth: int = 0) -> int:
    if _depth > limit:
        raise InputRejected(f"JSON nesting deeper than {limit}")
    if isinstance(obj, dict):
        return max((json_depth(v, limit, _depth + 1) for v in obj.values()), default=_depth)
    if isinstance(obj, list):
        return max((json_depth(v, limit, _depth + 1) for v in obj), default=_depth)
    return _depth


def safe_json_loads(text: str, max_depth: int) -> Any:
    obj = json.loads(text)
    json_depth(obj, max_depth)
    return obj


class TokenBucket:
    """Per-source rate limiter so one noisy or hostile sender cannot starve others."""

    def __init__(self, rate: float, burst: float | None = None):
        self.rate = rate
        self.burst = burst or rate
        self._state: dict[str, tuple[float, float]] = {}
        self._lock = threading.Lock()

    def allow(self, key: str, cost: float = 1.0) -> bool:
        now = time.monotonic()
        with self._lock:
            tokens, last = self._state.get(key, (self.burst, now))
            tokens = min(self.burst, tokens + (now - last) * self.rate)
            if tokens < cost:
                self._state[key] = (tokens, now)
                return False
            self._state[key] = (tokens - cost, now)
            return True
