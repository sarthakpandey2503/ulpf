"""Format sniffer: classifies a raw line into a wire format without a pack.

Output drives pack routing (packs declare which formats they accept) and gives the
AI parser generator its starting extractor for never-seen sources.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ..security import safe_regex

_PRI = safe_regex(r"^<\d{1,3}>")
_KV = safe_regex(r"(?:^|[\s,;])[A-Za-z_][\w.\-]*=(?:\"[^\"]*\"|[^\s,;]*)")
_SYSLOG_TS = safe_regex(r"^(?:<\d{1,3}>)?(?:1 )?(?:(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) +\d{1,2} |\d{4}-\d{2}-\d{2}T)")


@dataclass
class Sniff:
    format: str                    # json | xml | cef | leef | kv | csv | syslog | text
    envelope: str | None = None    # syslog when the payload is wrapped in a syslog header
    confidence: float = 0.5
    hints: dict = field(default_factory=dict)

    @property
    def tags(self) -> set[str]:
        t = {self.format}
        if self.envelope:
            t.add(self.envelope)
        return t


def _payload_format(p: str) -> tuple[str, float, dict]:
    s = p.strip()
    if not s:
        return "text", 0.1, {}
    if s[0] in "{[" and s[-1] in "}]":
        hints = {}
        if '"xml"' in s and "<Event" in s:
            hints["embedded"] = "windows_eventlog_xml"
        return "json", 0.95, hints
    if s.startswith("<") and not _PRI.search(s):
        return "xml", 0.9, {}
    if "CEF:" in s[:200]:
        return "cef", 0.97, {}
    if "LEEF:" in s[:200]:
        return "leef", 0.97, {}
    kv = len(_KV.findall(s))
    commas = s.count(",")
    if kv >= 3 and kv * 2 >= max(1, commas):
        return "kv", min(0.95, 0.5 + kv * 0.05), {"pairs": kv}
    if commas >= 5 and commas > s.count(" "):
        return "csv", min(0.9, 0.5 + commas * 0.02), {"columns": commas + 1}
    if s.count("\t") >= 4:
        return "csv", 0.7, {"delimiter": "\t", "columns": s.count("\t") + 1}
    return "text", 0.4, {}


def sniff(raw: str) -> Sniff:
    s = raw.lstrip("\ufeff")
    envelope = None
    payload = s
    if _PRI.search(s) or _SYSLOG_TS.search(s):
        from ..extractors.syslog import extract_syslog

        try:
            payload = extract_syslog(s, {}).get("message", s)
            envelope = "syslog"
        except Exception:
            payload = s
    fmt, conf, hints = _payload_format(payload)
    if envelope and fmt == "text":
        return Sniff("syslog", None, 0.7, hints)
    return Sniff(fmt, envelope, conf, hints)
