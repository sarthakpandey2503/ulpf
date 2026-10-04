"""Event views used by the detection-fidelity validator.

``RawView``   - the vendor-native field view (extractor output, no normalization).
               This is the oracle: rules are written for it.
``OcsfView``  - the ULPF OCSF event. Rule fields are *translated* to OCSF paths.
               Every lookup is attributed to how it was resolved:

    native        rule field is an OCSF path present in the event
    alias         non-standard / vendor field translated to a standard OCSF path
    unmapped      value found in the lossless ``unmapped`` object (full mode only)
    lineage       found through ULPF per-field lineage (full mode only)
    lost          present in the raw event but unreachable in OCSF (true loss)
    absent        absent in the raw event too (not a normalization issue)

mode="native" measures what a pure-OCSF consumer keeps; mode="full" measures
what ULPF's lossless envelope preserves.
"""
from __future__ import annotations

import json
import ntpath
from collections import Counter
from pathlib import Path
from typing import Any

from ..normalizer import ocsf
from ..normalizer.envelope import snake

_MAP_FILE = Path(__file__).with_name("sigma_ocsf_map.json")
_SIGMA_MAP: dict | None = None


def sigma_map() -> dict:
    global _SIGMA_MAP
    if _SIGMA_MAP is None:
        _SIGMA_MAP = json.loads(_MAP_FILE.read_text()) if _MAP_FILE.exists() else {"global": {}, "by_class": {}}
    return _SIGMA_MAP


def B(p: str) -> tuple:  # basename transform
    return ("basename", p)


def E(p: str) -> tuple:  # file extension transform
    return ("ext", p)


_HOST = (["hostname", "host.name", "System.Computer", "computer", "Computer"], ["device.hostname"])
_USER = (["TargetUserName", "User", "SubjectUserName", "user_name", "user"], ["user.name", "actor.user.name"])
_SRC = (["src_ip", "SourceIp", "IpAddress"], ["src_endpoint.ip", "evidences[0].src_endpoint.ip"])
_DST = (["dst_ip", "DestinationIp"], ["dst_endpoint.ip", "evidences[0].dst_endpoint.ip"])
_CMD = (["CommandLine", "cmd_line", "command_line"], ["process.cmd_line", "actor.process.cmd_line"])
_SRCS = (["source", "sensor"], ["finding_info.types"])

# field -> (raw-view candidates, OCSF-view candidates). Shared vocabulary for
# engine-canonical names (IR / legacy rules) and Sigma/Sysmon field names.
DICTIONARY: dict[str, tuple[list, list]] = {
    "command_line": _CMD, "cmd_line": _CMD, "CommandLine": ([], _CMD[1]),
    "process_name": ([B("Image"), "ProcessName"], [B("process.file.path"), "process.name"]),
    "parent_process_name": ([B("ParentImage")], [B("process.parent_process.file.path"), "process.parent_process.name"]),
    "process_path": (["Image"], ["process.file.path"]),
    "process_id": (["ProcessId"], ["process.pid"]),
    "parent_process_id": (["ParentProcessId"], ["process.parent_process.pid"]),
    "process_guid": (["ProcessGuid"], ["process.uid"]),
    "registry_key_path": (["TargetObject"], ["reg_value.path", "reg_key.path"]),
    "event_id": (["System.EventID", "eventId", "EventID"], ["metadata.event_code"]),
    "EventID": (["System.EventID", "eventId"], ["metadata.event_code"]),
    "user_name": _USER, "user": _USER,
    "logon_type": (["LogonType"], ["logon_type_id"]),
    "service_name": (["ServiceName"], ["service.name", "win_service.name"]),
    "file_extension": ([E("TargetFilename")], [E("file.path")]),
    "src_ip": _SRC, "dst_ip": _DST,
    "signature_name": ([], ["finding_info.title"]),
    "tactic": ([], ["finding_info.attacks[0].tactic.uid"]),
    "technique": ([], ["finding_info.attacks[0].technique.uid"]),
    "source": _SRCS, "sensor": _SRCS,
    "severity": (["severity_id"], ["severity_id"]),
    "host.name": _HOST, "hostname": _HOST, "host_id": _HOST, "Computer": _HOST,
    "proto": (["Protocol"], ["connection_info.protocol_name", "evidences[0].connection_info.protocol_name"]),
    "dns_query": (["QueryName"], ["query.hostname", "evidences[0].query.hostname"]),
    "Image": ([], ["process.file.path", "actor.process.file.path"]),
    "ParentImage": ([], ["process.parent_process.file.path"]),
    "ParentCommandLine": ([], ["process.parent_process.cmd_line"]),
    "OriginalFileName": ([], ["process.file.name"]),
    "User": ([], ["actor.user.name", "user.name"]),
    "TargetFilename": ([], ["file.path"]),
    "TargetObject": ([], ["reg_value.path", "reg_key.path"]),
    "Details": ([], ["reg_value.data"]),
    "DestinationIp": ([], ["dst_endpoint.ip"]), "DestinationPort": ([], ["dst_endpoint.port"]),
    "DestinationHostname": ([], ["dst_endpoint.hostname"]),
    "SourceIp": ([], ["src_endpoint.ip"]), "SourcePort": ([], ["src_endpoint.port"]),
    "ImageLoaded": ([], ["module.file.path"]),
    "SourceImage": ([], ["actor.process.file.path"]), "TargetImage": ([], ["process.file.path"]),
    "TargetUserName": ([], ["user.name"]), "SubjectUserName": ([], ["actor.user.name"]),
    "LogonType": ([], ["logon_type_id"]), "WorkstationName": ([], ["src_endpoint.hostname"]),
    "ServiceName": ([], ["service.name"]), "ServiceFileName": ([], ["win_service.cmd_line"]),
    "QueryName": ([], ["query.hostname"]), "IntegrityLevel": ([], ["process.integrity"]),
    "ProcessId": ([], ["process.pid"]), "PipeName": ([], ["file.path"]), "Device": ([], ["file.path"]),
    "GrantedAccess": ([], [("hex", "actual_permissions")]),
    "Initiated": ([], [("map", "connection_info.direction_id", {"2": "true", "1": "false"})]),
}

# Rule vocabulary names that are also OCSF attributes with different semantics
# (engine "severity" is numeric; OCSF ``severity`` is the caption string).
SEMANTIC_COLLISIONS = {"severity", "source"}

# Non-standard paths seen in third-party "OCSF" rules -> OCSF 1.3 standard paths.
PATH_ALIASES: dict[str, list[str]] = {
    "registry.key": ["reg_value.path", "reg_key.path"],
    "registry.data.content": ["reg_value.data"],
    "registry.value": ["reg_value.name"],
    "process.file.path": ["actor.process.file.path"],
    "process.cmd_line": ["actor.process.cmd_line"],
    "unmapped.parent_image": ["process.parent_process.file.path"],
    "unmapped.parent_cmd_line": ["process.parent_process.cmd_line"],
    "unmapped.signature_name": ["finding_info.title"],
    "unmapped.tactic": ["finding_info.attacks[0].tactic.uid"],
}


def _flat(v: Any) -> list:
    if v is None:
        return []
    if isinstance(v, list):
        out = []
        for x in v:
            out.extend(_flat(x))
        return out
    if isinstance(v, dict):
        return []
    return [v]


def _transform(kind: str, vals: list, arg: Any = None) -> list:
    out = []
    for v in vals:
        s = str(v)
        if kind == "hex":
            if isinstance(v, int) and not isinstance(v, bool):
                out.append(f"0x{v:X}")
        elif kind == "map":
            if s in arg:
                out.append(arg[s])
        elif kind == "basename":
            out.append(ntpath.basename(s.rstrip("\\/")))
        elif kind == "ext":
            b = ntpath.basename(s)
            if "." in b:
                out.append(b.rsplit(".", 1)[1])
    return out


def _leaves(obj: Any, out: list) -> list:
    if isinstance(obj, dict):
        for v in obj.values():
            _leaves(v, out)
    elif isinstance(obj, list):
        for v in obj:
            _leaves(v, out)
    elif obj is not None and not isinstance(obj, bool):
        out.append(str(obj))
    return out


class RawView:
    def __init__(self, fields: dict, source: str = ""):
        self.fields = fields
        self.source = source
        self._lower = {k.lower().replace("_", ""): k for k in fields}
        self._values: list[str] | None = None

    def _direct(self, name: str) -> list:
        if name in self.fields:
            return _flat(self.fields[name])
        k = self._lower.get(name.lower().replace("_", ""))
        return _flat(self.fields[k]) if k else []

    def get(self, name: str) -> list:
        vals = self._direct(name)
        if vals:
            return vals
        for cand in DICTIONARY.get(name, ([], []))[0]:
            vals = _transform(cand[0], self._direct(cand[1])) if isinstance(cand, tuple) else self._direct(cand)
            if vals:
                return vals
        return []

    def values(self) -> list[str]:
        if self._values is None:
            self._values = [str(v) for v in self.fields.values() if v is not None and not isinstance(v, (dict, bool))]
        return self._values

    def first(self, *names: str):
        for n in names:
            v = self.get(n)
            if v:
                return v[0]
        return None


class OcsfView:
    def __init__(self, event: dict, mode: str = "full", stats: Counter | None = None,
                 missing: Counter | None = None, raw: RawView | None = None,
                 raw_alias: dict[str, str] | None = None):
        self.e = event
        self.raw = raw
        self.raw_alias = raw_alias or {}
        self.mode = mode
        self.stats = stats if stats is not None else Counter()
        self.missing = missing if missing is not None else Counter()
        self.cls = event.get("class_name", "")
        self._values: list[str] | None = None
        self._inv: dict[str, list[str]] | None = None

    def _path(self, path: str) -> list:
        try:
            return _flat(ocsf.get_path(self.e, path))
        except (KeyError, IndexError, TypeError, ValueError):
            return []

    def _cand(self, cand) -> list:
        if isinstance(cand, tuple):
            return _transform(cand[0], self._path(cand[1]), cand[2] if len(cand) > 2 else None)
        return self._path(cand)

    def _hit(self, kind: str, vals: list) -> list:
        self.stats[kind] += 1
        return vals

    def _inverse(self) -> dict[str, list[str]]:
        if self._inv is None:
            self._inv = {}
            for path, raw in ((self.e.get("ulpf") or {}).get("field_lineage") or {}).items():
                for r in raw if isinstance(raw, list) else [raw]:
                    self._inv.setdefault(str(r).lower(), []).append(path)
        return self._inv

    def _translations(self, name: str) -> list:
        out: list = list(PATH_ALIASES.get(name, [])) + list(DICTIONARY.get(name, ([], []))[1])
        sm = sigma_map()
        mapped = (sm.get("by_class", {}).get(self.cls.lower().replace(" ", "_"), {}).get(name)
                  or sm.get("global", {}).get(name))
        if mapped and mapped != name and not mapped.startswith("unmapped."):
            out += [mapped] + PATH_ALIASES.get(mapped, [])
        if self.cls == "Process Activity":  # actor.process is the *parent* here, never the subject
            out = [c for c in out if not str(c if isinstance(c, str) else c[1]).startswith("actor.process.")]
        return out

    def get(self, name: str) -> list:
        is_unmapped = name.startswith("unmapped.")
        raw_name = self.raw_alias.get(name) or (name[9:] if is_unmapped else name)
        if not is_unmapped and name not in SEMANTIC_COLLISIONS:
            vals = self._path(name)
            if vals:
                return self._hit("native", vals)
        names = [name] + ([raw_name] if raw_name != name else [])
        for n in names:
            for cand in self._translations(n):
                vals = self._cand(cand)
                if vals:
                    return self._hit("alias", vals)
        if self.mode == "full":
            um = self.e.get("unmapped") or {}
            keys = ([name[9:]] if is_unmapped else []) + [snake(raw_name), raw_name]
            for k in keys:
                if k in um and um[k] not in (None, ""):
                    return self._hit("unmapped", _flat(um[k]))
            inv = self._inverse()
            paths = inv.get(raw_name.lower()) or inv.get(raw_name.replace("_", "").lower()) or []
            for p in sorted(paths, key=lambda p: -len(str(self._path(p)))):
                vals = self._path(p)
                if vals:
                    return self._hit("lineage", vals)
        if self.raw is not None and self.raw.get(raw_name):
            self.stats["lost"] += 1       # present in the raw event, unreachable in OCSF
            self.missing[name] += 1
        else:
            self.stats["absent"] += 1     # absent in raw as well: not a normalization loss
        return []

    def values(self) -> list[str]:
        if self._values is None:
            vals: list[str] = []
            for k, v in self.e.items():
                if k in ("raw_data", "ulpf", "metadata") or (k == "unmapped" and self.mode != "full"):
                    continue
                _leaves(v, vals)
            self._values = vals
        return self._values

    def first(self, *names: str):
        for n in names:
            v = self.get(n)
            if v:
                return v[0]
        return None
