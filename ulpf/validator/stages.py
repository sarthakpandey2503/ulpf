"""Evaluator for the correlation-rule formats in the Detection-Engineering-Ruleset:

* IR_v1 JSON  (``stages[].match`` groups/conditions, aggregate, windows)
* legacy stage JSON (``signatureContains`` / ``tactics`` / ``techniques`` /
  ``conditions`` / ``minOccurrences`` / ``windowMinutes``)

Semantics follow the dataset proofs: THRESHOLD rules alert when stage 0 reaches
its threshold; SEQUENCE rules require non-optional stages in order, each within
the stage deadline (``withinSeconds`` / ``maxGapSeconds``) and overall window.
Legacy stage matching: explicit conditions AND (tactic OR technique OR signature),
minus exclusions. Views provide ``get(field) -> list``.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable

from ..security import safe_regex

SOURCE_ALIASES = {"windows_sysmon": "sysmon", "sysmon": "sysmon", "edr": "sysmon", "windows": "sysmon",
                  "wazuh": "wazuh", "hids": "wazuh", "suricata": "suricata", "nids": "suricata", "zeek": "zeek"}


def _norm_src(s: str) -> str:
    return SOURCE_ALIASES.get(str(s).lower(), str(s).lower())


def _s(v: Any) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, float) and v.is_integer():
        return str(int(v))
    return str(v).strip()


def _cond(c: dict) -> Callable[[Any, dict], bool]:
    fld = c.get("field") or ""
    op = str(c.get("operator") or c.get("op") or "equals").lower()
    vals = c.get("values") or ([] if c.get("value") is None else [c.get("value")])
    wants = [_s(v).lower() for v in vals]
    if op.startswith("equals_field:"):
        ref = op.split(":", 1)[1]  # e.g. stage0.host_id
        st, _, rf = ref.partition(".")
        st_idx = int(re.sub(r"\D", "", st) or 0)

        def eqf(view, ctx):
            prev = ctx.get("stage_events", {}).get(st_idx)
            if prev is None:
                return False
            a = {_s(x).lower() for x in view.get(fld)}
            b = {_s(x).lower() for x in prev.get(rf)}
            return bool(a & b)
        return eqf
    neg = op.startswith("not_")
    base = op[4:] if neg else op
    if base in ("regex", "matches"):
        rxs = [safe_regex(_s(v)) for v in vals]
        test = lambda s: any(r.search(s) for r in rxs)
    elif base == "contains":
        test = lambda s: any(w in s for w in wants)
    elif base == "startswith":
        test = lambda s: any(s.startswith(w) for w in wants)
    elif base == "endswith":
        test = lambda s: any(s.endswith(w) for w in wants)
    elif base in ("gt", "gte", "lt", "lte"):
        ref_num = float(wants[0]) if wants else 0.0

        def test(s, base=base, ref_num=ref_num):
            try:
                x = float(s)
            except ValueError:
                return False
            return {"gt": x > ref_num, "gte": x >= ref_num, "lt": x < ref_num, "lte": x <= ref_num}[base]
    elif base == "exists":
        return lambda view, ctx: bool(view.get(fld)) != neg
    else:  # equals / eq / in / in_list
        test = lambda s: s in wants

    def run(view, ctx):
        got = [_s(x).lower() for x in view.get(fld)]
        hit = any(test(s) for s in got)
        return (not hit) if neg else hit
    return run


def _group(g: dict | None) -> Callable[[Any, dict], bool]:
    if not g:
        return lambda v, c: True
    parts = [_cond(c) for c in g.get("conditions") or []] + [_group(x) for x in g.get("groups") or []]
    if not parts:
        return lambda v, c: True
    if str(g.get("operator", "AND")).upper() == "OR":
        return lambda v, c: any(p(v, c) for p in parts)
    return lambda v, c: all(p(v, c) for p in parts)


@dataclass
class Stage:
    index: int
    optional: bool
    threshold: int
    within_s: float | None
    sources: set[str]
    pred: Callable[[Any, dict], bool]
    distinct_field: str | None = None
    min_distinct: int = 0
    fields: set[str] = field(default_factory=set)


def _collect_fields(g: dict | None, out: set[str]) -> None:
    if not g:
        return
    for c in g.get("conditions") or []:
        if c.get("field"):
            out.add(c["field"])
    for x in g.get("groups") or []:
        _collect_fields(x, out)


def _legacy_pred(s: dict) -> tuple[Callable[[Any, dict], bool], set[str]]:
    conds = [_cond(c) for c in s.get("conditions") or []]
    fields = {c["field"] for c in s.get("conditions") or [] if c.get("field")}
    sig = [x.lower() for x in (s.get("signatureContains") or []) + (s.get("signatureEquals") or [])]
    tactics = {x.upper() for x in s.get("tactics") or []}
    techs = {x.upper() for x in s.get("techniques") or []}
    excl = [x.lower() for x in s.get("excludeSignatureContains") or []]
    if sig or excl:
        fields.add("signature_name")
    if tactics:
        fields.add("tactic")
    if techs:
        fields.add("technique")

    def pred(view, ctx):
        if not all(c(view, ctx) for c in conds):
            return False
        sigs = [_s(x).lower() for x in view.get("signature_name")] if (sig or excl) else []
        if excl and any(e in s_ for s_ in sigs for e in excl):
            return False
        if not (sig or tactics or techs):
            return True
        if tactics and any(_s(x).upper() in tactics for x in view.get("tactic")):
            return True
        if techs and any(_s(x).upper().split(".")[0] in techs or _s(x).upper() in techs
                         for x in view.get("technique")):
            return True
        return bool(sig) and any(w in s_ for s_ in sigs for w in sig)
    return pred, fields


class StageRule:
    def __init__(self, doc: dict, rule_type: str | None = None):
        self.doc = doc
        self.id = str(doc.get("ruleId") or doc.get("id") or "")
        self.title = str(doc.get("ruleName") or doc.get("description") or self.id)
        self.format = "IR_v1" if doc.get("ruleFormat") == "IR_v1" or any("match" in s for s in doc["stages"]) \
            else "legacy"
        self.rule_type = str(rule_type or doc.get("ruleType") or
                             ("SEQUENCE" if len(doc["stages"]) > 1 else "THRESHOLD")).upper()
        win = doc.get("window") or {}
        self.window_s = float(win.get("durationSeconds") or (doc.get("windowMinutes") or 0) * 60 or 0) or None
        self.max_gap_s = float(doc.get("maxGapSeconds") or 0) or None
        self.stages: list[Stage] = []
        for i, s in enumerate(doc["stages"]):
            flds: set[str] = set()
            if "match" in s and s["match"] is not None:
                g = _group(s["match"])
                _collect_fields(s["match"], flds)
                lp, lf = _legacy_pred(s)
                pred = (lambda g, lp: lambda v, c: g(v, c) and lp(v, c))(g, lp)
                flds |= lf
            else:
                pred, flds = _legacy_pred(s)
            agg = s.get("aggregate") or {}
            threshold = int(max(float(agg.get("threshold") or 0), float(s.get("minOccurrences") or 0), 1))
            self.stages.append(Stage(
                index=i, optional=bool(s.get("optional")), threshold=threshold,
                within_s=float(s.get("withinSeconds") or s.get("maxGapSeconds") or 0) or None,
                sources={_norm_src(x) for x in s.get("eventSources") or []}, pred=pred,
                distinct_field=s.get("requireDistinctField") or agg.get("distinctField"),
                min_distinct=int(s.get("minDistinctCount") or 0), fields=flds))
        self.fields = set().union(*(s.fields for s in self.stages)) if self.stages else set()

    def _stage_ok(self, st: Stage, view, source: str, ctx: dict) -> bool:
        if st.sources and source and _norm_src(source) not in st.sources:
            return False
        return st.pred(view, ctx)

    def evaluate(self, events: list[tuple[float, str, Any]], source: str) -> int:
        """events: [(time_s, lane, view)] sorted by time. Returns number of alerts."""
        lanes: dict[str, list] = {}
        for t, lane, view in events:
            lanes.setdefault(lane, []).append((t, view))
        alerts = 0
        for evs in lanes.values():
            alerts += self._threshold(evs, source) if self.rule_type != "SEQUENCE" else self._sequence(evs, source)
        return alerts

    def _threshold(self, evs, source) -> int:
        st = self.stages[0]
        hits: list[tuple[float, Any]] = []
        alerts = 0
        for t, view in evs:
            if not self._stage_ok(st, view, source, {}):
                continue
            hits.append((t, view))
            if self.window_s:
                hits = [(ht, hv) for ht, hv in hits if t - ht <= self.window_s]
            if len(hits) >= st.threshold and self._distinct_ok(st, hits):
                alerts += 1
                hits = []
        return alerts

    @staticmethod
    def _distinct_ok(st: Stage, hits) -> bool:
        if not st.distinct_field or st.min_distinct <= 1:
            return True
        vals = {str(x) for _, v in hits for x in v.get(st.distinct_field)}
        return len(vals) >= st.min_distinct

    def _sequence(self, evs, source) -> int:
        required = [s for s in self.stages if not s.optional] or self.stages[:1]
        alerts = 0
        idx, count, start_t, last_t = 0, 0, None, None
        ctx: dict = {"stage_events": {}}
        for t, view in evs:
            st = required[idx]
            if start_t is not None:
                gap = st.within_s or self.max_gap_s
                if (self.window_s and t - start_t > self.window_s) or (gap and last_t is not None and t - last_t > gap):
                    idx, count, start_t, last_t, ctx = 0, 0, None, None, {"stage_events": {}}
                    st = required[0]
            if not self._stage_ok(st, view, source, ctx):
                continue
            count += 1
            if start_t is None:
                start_t = t
            if count >= st.threshold:
                ctx["stage_events"][st.index] = view
                last_t = t
                idx, count = idx + 1, 0
                if idx == len(required):
                    alerts += 1
                    idx, count, start_t, last_t, ctx = 0, 0, None, None, {"stage_events": {}}
        return alerts
