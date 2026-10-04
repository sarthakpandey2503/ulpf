"""Offline field -> OCSF mapper (no network, no model required).

Scores every raw field against a synonym dictionary using exact normalized-name
matches, fuzzy string similarity (difflib) and value-shape checks (is it an IP?
a port? a timestamp?). If ``sentence-transformers`` and a locally cached model are
present it is used as an extra semantic signal; otherwise the mapper runs purely
on the lexical and value signals.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from typing import Any

from ..normalizer import ocsf

# OCSF path -> (value kind, synonyms). Synonyms are compared after normalization
# (lowercase, alphanumerics only), so ``src_ip``, ``srcIp`` and ``src-ip`` are equal.
SYNONYMS: dict[str, tuple[str, list[str]]] = {
    "time": ("time", ["time", "timestamp", "ts", "datetime", "eventtime", "rt", "@timestamp", "receivetime",
                      "eventtimestamp", "utctime", "generatedtime", "logtime", "date", "starttime", "start",
                      "syslogtimestamp", "timecreated", "devtime"]),
    "src_endpoint.ip": ("ip", ["src", "srcip", "srcaddr", "sourceip", "sourceaddress", "sip", "clientip", "cip",
                               "origh", "idorigh", "saddr", "srcipaddr", "sourceipaddress", "remip", "remoteip",
                               "clientaddress", "ipsrc", "agentip", "sourcenetworkaddress", "ipaddress"]),
    "dst_endpoint.ip": ("ip", ["dst", "dstip", "dstaddr", "destip", "destinationip", "destinationaddress", "dip",
                               "serverip", "resph", "idresph", "daddr", "dstipaddr", "ipdst", "targetip"]),
    "src_endpoint.port": ("port", ["spt", "srcport", "sport", "sourceport", "origp", "idorigp", "clientport",
                                   "srcprt", "sourcenetworkport", "portsrc"]),
    "dst_endpoint.port": ("port", ["dpt", "dstport", "dport", "destport", "destinationport", "respp", "idrespp",
                                   "serverport", "dstprt", "portdst", "targetport"]),
    "src_endpoint.mac": ("mac", ["smac", "srcmac", "sourcemac", "sourcemacaddress", "macsrc"]),
    "dst_endpoint.mac": ("mac", ["dmac", "dstmac", "destinationmac", "destinationmacaddress", "macdst"]),
    "src_endpoint.hostname": ("str", ["shost", "srchost", "sourcehost", "sourcehostname", "clienthost"]),
    "dst_endpoint.hostname": ("str", ["dhost", "dsthost", "destinationhost", "destinationhostname", "serverhost",
                                      "hostname", "sni", "servername", "destinationdomain"]),
    "src_endpoint.zone": ("str", ["srczone", "fromzone", "sourcezone", "sourcezonename", "srcintfrole", "inzone"]),
    "dst_endpoint.zone": ("str", ["dstzone", "tozone", "destinationzone", "destinationzonename", "dstintfrole", "outzone"]),
    "src_endpoint.interface_name": ("str", ["srcintf", "inboundif", "ininterface", "ingressinterface", "in", "ifin"]),
    "dst_endpoint.interface_name": ("str", ["dstintf", "outboundif", "outinterface", "egressinterface", "out", "ifout"]),
    "connection_info.protocol_name": ("proto", ["proto", "protocol", "transport", "ipproto", "protocolname",
                                                "networkprotocol", "l4proto"]),
    "traffic.bytes_out": ("int", ["sentbyte", "bytessent", "outbytes", "bytesout", "origbytes", "sentbytes", "out",
                                  "bytestoserver", "sbytes", "txbytes"]),
    "traffic.bytes_in": ("int", ["rcvdbyte", "bytesreceived", "inbytes", "bytesin", "respbytes", "rcvdbytes",
                                 "bytestoclient", "rbytes", "rxbytes", "in", "recvbytes"]),
    "traffic.bytes": ("int", ["bytes", "totalbytes", "len", "length"]),
    "traffic.packets_out": ("int", ["sentpkt", "pktssent", "outpkts", "origpkts", "packetsout", "pktstoserver"]),
    "traffic.packets_in": ("int", ["rcvdpkt", "pktsreceived", "inpkts", "resppkts", "packetsin", "pktstoclient",
                                   "recvpkts", "rxpkts"]),
    "actor.user.name": ("str", ["user", "username", "usrname", "suser", "srcuser", "account", "login", "uid",
                                "accountname", "subjectusername", "sourceuser", "authuser"]),
    "dst_user.name": ("str", ["duser", "dstuser", "targetuser", "targetusername", "destinationuser"]),
    "disposition": ("action", ["act", "action", "disposition", "verdict", "fwaction", "decision", "result",
                               "deviceaction", "status", "logsubtype", "fwstatus"]),
    "message": ("str", ["msg", "message", "description", "logdesc", "reason", "text", "details"]),
    "http_request.url.url_string": ("str", ["url", "request", "requesturl", "uri", "requesturi", "fullurl"]),
    "http_request.http_method": ("method", ["method", "httpmethod", "requestmethod", "verb"]),
    "http_request.user_agent": ("str", ["useragent", "requestclientapplication", "ua", "httpuseragent"]),
    "http_response.code": ("int", ["status", "statuscode", "httpstatus", "responsecode", "httpresponsecode"]),
    "query.hostname": ("str", ["query", "qname", "dnsquery", "queryname", "rrname", "domain"]),
    "finding_info.title": ("str", ["signature", "alertsignature", "signaturename", "rulename", "threatname", "attack",
                                   "attackname", "threat", "name", "virus", "malware", "ruletitle"]),
    "finding_info.uid": ("str", ["signatureid", "alertsignatureid", "sid", "ruleid", "threatid", "attackid",
                                 "eventid", "signature_id"]),
    "device.hostname": ("str", ["devname", "devicename", "dvchost", "computer", "syslog_host", "sysloghost",
                                "host", "observer", "sensor", "agent", "devicehostname"]),
    "device.ip": ("ip", ["dvc", "deviceip", "deviceaddress", "observerip", "origin", "agentip"]),
    "severity_id": ("severity", ["severity", "level", "sev", "priority", "pri", "alertseverity", "severityid"]),
}

_CLEAN = re.compile(r"[^0-9a-z@]")


def norm(name: str) -> str:
    return _CLEAN.sub("", name.lower())


_INDEX: dict[str, list[str]] = {}
for _path, (_kind, _syns) in SYNONYMS.items():
    for _s in _syns:
        _INDEX.setdefault(norm(_s), []).append(_path)

_TS_RX = re.compile(r"^\d{4}[-/]\d{2}[-/]\d{2}[T ]\d{2}:\d{2}|^\w{3} +\d{1,2} \d{2}:\d{2}:\d{2}|^\d{10,19}(\.\d+)?$")
_MAC_RX = re.compile(r"^([0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}$")
_PROTO = {"tcp", "udp", "icmp", "gre", "esp", "sctp", "6", "17", "1", "icmpv6", "58"}
_METHODS = {"get", "post", "put", "delete", "head", "options", "patch", "connect", "trace"}
_ALLOW = {"accept", "allow", "allowed", "permit", "pass", "passed", "success", "built", "ok", "close", "accepted"}
_BLOCK = {"deny", "denied", "drop", "dropped", "block", "blocked", "reject", "rejected", "reset", "fail", "failed",
          "failure", "prevent", "quarantine"}


def value_fits(kind: str, value: Any) -> float:
    """Return 0..1 for how well a value matches the expected kind."""
    if value in (None, ""):
        return 0.0
    s = str(value).strip()
    try:
        if kind == "ip":
            ipaddress.ip_address(s.strip("[]"))
            return 1.0
        if kind == "port":
            return 1.0 if 0 <= int(s) <= 65535 else 0.0
        if kind == "int":
            int(float(s))
            return 1.0
    except ValueError:
        return 0.0
    if kind == "time":
        return 1.0 if _TS_RX.search(s) else 0.2
    if kind == "mac":
        return 1.0 if _MAC_RX.match(s) else 0.0
    if kind == "proto":
        return 1.0 if s.lower() in _PROTO else 0.3
    if kind == "method":
        return 1.0 if s.lower() in _METHODS else 0.0
    if kind == "action":
        return 1.0 if s.lower() in _ALLOW | _BLOCK else 0.4
    if kind == "severity":
        return 0.8
    return 0.7 if len(s) < 4096 else 0.3


def _semantic_model():  # pragma: no cover - optional dependency
    try:
        from sentence_transformers import SentenceTransformer  # type: ignore

        return SentenceTransformer("all-MiniLM-L6-v2", local_files_only=True)
    except Exception:
        return None


@dataclass
class FieldMatch:
    raw: str
    path: str
    score: float
    method: str


@dataclass
class MappingGuess:
    class_name: str
    matches: dict[str, FieldMatch] = field(default_factory=dict)   # path -> match
    confidence: float = 0.0
    disposition_map: dict[str, int] = field(default_factory=dict)

    def mapping(self) -> dict[str, str]:
        return {p: m.raw for p, m in self.matches.items()}


def _candidates(raw: str) -> list[tuple[str, float, str]]:
    n = norm(raw)
    leaf = norm(raw.rsplit(".", 1)[-1])
    out: list[tuple[str, float, str]] = []
    for key, method, base in ((n, "exact", 1.0), (leaf, "leaf", 0.9)):
        for path in _INDEX.get(key, []):
            out.append((path, base, method))
    if not out and len(n) >= 4:
        best: dict[str, float] = {}
        for syn, paths in _INDEX.items():
            if len(syn) < 4:
                continue
            r = SequenceMatcher(None, n, syn).ratio()
            if r >= 0.84:
                for p in paths:
                    best[p] = max(best.get(p, 0), r * 0.8)
        out.extend((p, s, "fuzzy") for p, s in best.items())
    return out


def choose_class(paths: set[str], fields: dict[str, Any]) -> str:
    text = " ".join(str(k).lower() for k in fields)[:4000]
    if "http_request.http_method" in paths or ("http_request.url.url_string" in paths and "http_response.code" in paths):
        return "http_activity"
    if "query.hostname" in paths:
        return "dns_activity"
    if "finding_info.title" in paths and any(w in text for w in ("sig", "threat", "alert", "attack", "virus", "ips")):
        return "detection_finding"
    if "actor.user.name" in paths and any(w in text for w in ("logon", "login", "auth", "session")):
        return "authentication"
    if {"src_endpoint.ip", "dst_endpoint.ip"} & paths:
        return "network_activity"
    return "base_event"


def infer(fields: dict[str, Any]) -> MappingGuess:
    per_path: dict[str, FieldMatch] = {}
    for raw, value in fields.items():
        if isinstance(value, (dict, list)):
            continue
        for path, base, method in _candidates(raw):
            kind = SYNONYMS[path][0]
            fit = value_fits(kind, value)
            if fit < 0.5:
                continue
            score = round(base * fit, 3)
            cur = per_path.get(path)
            if cur is None or score > cur.score:
                per_path[path] = FieldMatch(raw, path, score, method)
    # one raw field -> one path (keep best)
    used: dict[str, FieldMatch] = {}
    for m in sorted(per_path.values(), key=lambda m: -m.score):
        if m.raw not in used:
            used[m.raw] = m
    matches = {m.path: m for m in used.values()}
    cls = choose_class(set(matches), fields)
    if cls != "base_event":
        matches = {p: m for p, m in matches.items() if p in ("severity_id",) or ocsf.known_path(cls, p)}
    guess = MappingGuess(cls, matches)
    if matches:
        guess.confidence = round(min(0.6, 0.35 + 0.25 * sum(m.score for m in matches.values()) / max(4, len(matches))), 3)
    d = matches.get("disposition")
    if d:
        v = str(fields.get(d.raw, "")).lower()
        guess.disposition_map = {v: 1 if v in _ALLOW else 2 if v in _BLOCK else 0}
    return guess


def disposition_id(value: Any) -> int:
    v = str(value).lower()
    return 1 if v in _ALLOW else 2 if v in _BLOCK else 0


def severity_id(value: Any) -> int:
    s = str(value).strip().lower()
    named = {"emergency": 6, "emerg": 6, "alert": 5, "critical": 5, "crit": 5, "error": 4, "err": 4, "high": 4,
             "warning": 3, "warn": 3, "medium": 3, "notice": 2, "low": 2, "information": 1, "informational": 1,
             "info": 1, "debug": 1}
    if s in named:
        return named[s]
    try:
        n = int(float(s))
    except ValueError:
        return 0
    if n <= 10:
        return max(1, min(5, (n + 1) // 2)) if n > 0 else 1
    return 0
