"""Syslog header extractor (RFC 3164, RFC 5424 and common vendor variants).

Returns header fields plus ``message`` (the payload) so a pack can chain a second
extractor (kv, cef, leef, grok ...) on the message body.
"""
from __future__ import annotations

from typing import Any

from ..security import safe_regex

_PRI = safe_regex(r"^<(\d{1,3})>")
_5424 = safe_regex(
    r"^1 (\S+) (\S+) (\S+) (\S+) (\S+) (-|(?:\[(?:[^\]\\]|\\.)*\])+)(?: (.*))?$"
)
_SD_ELEM = safe_regex(r"\[([^\s\]]+)((?:\s+[^=\s]+=\"(?:[^\"\\]|\\.)*\")*)\]")
_SD_PARAM = safe_regex(r"([^=\s]+)=\"((?:[^\"\\]|\\.)*)\"")
_TS = [
    safe_regex(r"^((?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) +\d{1,2}(?: \d{4})? \d{2}:\d{2}:\d{2}(?:\.\d+)?)(?: |:|$)"),
    safe_regex(r"^(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)(?: |:|$)"),
]
_HOST = safe_regex(r"^([A-Za-z0-9][A-Za-z0-9.\-_]*) ")
_TAG = safe_regex(r"^([A-Za-z0-9_\-./%]+?)(?:\[(\d+)\])?: ?")


def extract_syslog(text: str, opts: dict) -> dict[str, Any]:
    out: dict[str, Any] = {}
    s = text.lstrip("\ufeff").rstrip("\r\n")
    m = _PRI.search(s)
    if m:
        pri = int(m.group(1))
        out.update(syslog_pri=pri, syslog_facility=pri >> 3, syslog_severity=pri & 7)
        s = s[m.end():]
    m5 = _5424.search(s)
    if m5:
        ts, host, app, procid, msgid, sd, msg = m5.groups()
        for k, v in (("syslog_timestamp", ts), ("syslog_host", host), ("syslog_app", app),
                     ("syslog_procid", procid), ("syslog_msgid", msgid)):
            if v != "-":
                out[k] = v
        if sd and sd != "-":
            flat = opts.get("sd_prefix", True) is False
            for el in _SD_ELEM.finditer(sd):
                sd_id = el.group(1)
                if flat:
                    out.setdefault("sd_id", sd_id)
                for p in _SD_PARAM.finditer(el.group(2) or ""):
                    key = p.group(1) if flat else f"sd.{sd_id}.{p.group(1)}"
                    out[key] = p.group(2).replace('\\"', '"')
        out["message"] = (msg or "").lstrip("\ufeff")
        out["syslog_format"] = "rfc5424"
        return out

    for rx in _TS:
        mt = rx.search(s)
        if mt:
            out["syslog_timestamp"] = mt.group(1)
            s = s[mt.end(1):].lstrip(" ")
            break
    # Header host/tag are only trusted when a timestamp was present; many devices
    # (e.g. FortiGate) send a bare PRI followed directly by key=value payload.
    if "syslog_timestamp" in out and not s.startswith(("%", ":", "CEF:", "LEEF:")):
        mh = _HOST.search(s)
        if mh and "=" not in mh.group(1) and not opts.get("no_host", False):
            out["syslog_host"] = mh.group(1)
            s = s[mh.end():]
    s = s.lstrip(": ")
    mt = None if s.startswith(("CEF:", "LEEF:", "{")) else _TAG.search(s)
    if mt and "=" not in mt.group(1) and not opts.get("no_tag", False):
        out["syslog_app"] = mt.group(1)
        if mt.group(2):
            out["syslog_procid"] = mt.group(2)
        s = s[mt.end():]
    out["message"] = s
    out["syslog_format"] = "rfc3164"
    return out
