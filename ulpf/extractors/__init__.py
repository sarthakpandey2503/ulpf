"""Format extractors. Each turns text into a flat ``{field: value}`` dict.

Extractors never drop information silently: anything they cannot structure stays
in the raw event, which ULPF always preserves alongside the normalized output.
"""
from __future__ import annotations

from typing import Any, Callable

from .cef import extract_cef
from .csv_ import extract_csv
from .grok import extract_grok, extract_regex
from .json_ import extract_json
from .kv import extract_kv
from .leef import extract_leef
from .syslog import extract_syslog
from .xml_ import extract_xml

Extractor = Callable[[str, dict], dict[str, Any]]

REGISTRY: dict[str, Extractor] = {
    "json": extract_json,
    "xml": extract_xml,
    "csv": extract_csv,
    "kv": extract_kv,
    "grok": extract_grok,
    "regex": extract_regex,
    "cef": extract_cef,
    "leef": extract_leef,
    "syslog": extract_syslog,
}


def get(name: str) -> Extractor:
    try:
        return REGISTRY[name]
    except KeyError as exc:
        raise ValueError(f"unknown extractor '{name}'; available: {sorted(REGISTRY)}") from exc
