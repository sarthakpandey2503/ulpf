"""SIEM connectors: Splunk HEC, Elasticsearch/OpenSearch bulk, and CEF syslog forwarding."""
from __future__ import annotations

import json
import socket

import httpx


class SplunkHECSink:
    def __init__(self, url: str, token: str, index: str = "ocsf", verify: bool = True):
        if not url:
            raise ValueError("ULPF_SPLUNK_HEC_URL not set")
        self.url = url.rstrip("/") + "/services/collector/event"
        self.client = httpx.Client(headers={"Authorization": f"Splunk {token}"}, verify=verify, timeout=10)
        self.index = index

    def write(self, events: list[dict]) -> None:
        body = "".join(json.dumps({"time": (e.get("time") or 0) / 1000, "sourcetype": "ocsf",
                                   "source": e["ulpf"].get("pack") or "ulpf", "index": self.index, "event": e},
                                  default=str) for e in events)
        if body:
            self.client.post(self.url, content=body).raise_for_status()


class ElasticSink:
    def __init__(self, url: str, api_key: str | None, index_prefix: str = "ocsf", verify: bool = True):
        if not url:
            raise ValueError("ULPF_ELASTIC_URL not set")
        headers = {"Content-Type": "application/x-ndjson"}
        if api_key:
            headers["Authorization"] = f"ApiKey {api_key}"
        self.url = url.rstrip("/") + "/_bulk"
        self.client = httpx.Client(headers=headers, verify=verify, timeout=10)
        self.prefix = index_prefix

    def write(self, events: list[dict]) -> None:
        lines = []
        for e in events:
            idx = f"{self.prefix}-{e['class_name'].lower().replace(' ', '_')}"
            lines.append(json.dumps({"index": {"_index": idx, "_id": e["metadata"]["uid"]}}))
            lines.append(json.dumps(e, default=str))
        if lines:
            self.client.post(self.url, content="\n".join(lines) + "\n").raise_for_status()


def _cef_escape_header(v: object) -> str:
    return str(v).replace("\\", "\\\\").replace("|", "\\|").replace("\n", " ")


def _cef_escape_ext(v: object) -> str:
    return str(v).replace("\\", "\\\\").replace("=", "\\=").replace("\n", "\\n").replace("\r", "\\r")


def to_cef(e: dict) -> str:
    """Render a normalized OCSF event as CEF for legacy SIEMs (ArcSight, QRadar...)."""
    sev = {0: 0, 1: 1, 2: 3, 3: 5, 4: 7, 5: 9, 6: 10}.get(e.get("severity_id", 0), 5)
    prod = e["metadata"]["product"]
    ext = {
        "rt": e.get("time"), "src": (e.get("src_endpoint") or {}).get("ip"),
        "spt": (e.get("src_endpoint") or {}).get("port"), "dst": (e.get("dst_endpoint") or {}).get("ip"),
        "dpt": (e.get("dst_endpoint") or {}).get("port"), "suser": ((e.get("actor") or {}).get("user") or {}).get("name"),
        "act": e.get("disposition"), "msg": e.get("message"),
        "cs1Label": "ocsf_class", "cs1": e.get("class_name"),
        "cs2Label": "ulpf_event_uid", "cs2": e["metadata"]["uid"],
        "cs3Label": "raw_sha256", "cs3": e["ulpf"]["raw_sha256"],
    }
    ext_s = " ".join(f"{k}={_cef_escape_ext(v)}" for k, v in ext.items() if v not in (None, ""))
    name = (e.get("finding_info") or {}).get("title") or e.get("type_name")
    return (f"CEF:0|{_cef_escape_header(prod.get('vendor_name', 'Unknown'))}|{_cef_escape_header(prod.get('name', ''))}|"
            f"ULPF|{e.get('type_uid')}|{_cef_escape_header(name)}|{sev}|{ext_s}")


class CEFForwarder:
    def __init__(self, target: str):
        if not target:
            raise ValueError("ULPF_CEF_FORWARD not set (host:port)")
        host, port = target.rsplit(":", 1)
        self.addr = (host, int(port))
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def write(self, events: list[dict]) -> None:
        for e in events:
            msg = f"<134>1 - ulpf ulpf - - - {to_cef(e)}".encode("utf-8", errors="replace")
            self.sock.sendto(msg[:65000], self.addr)
