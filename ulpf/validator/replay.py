"""Detection-validated normalization: the Schema Fidelity Score.

For every dataset in the Detection-Engineering-Ruleset (rule + true-positive and
benign telemetry + expected alert counts):

1. Oracle   - evaluate the original rule on the *raw* vendor view. Agreement with
              ``expected.json`` measures how faithful our rule engine is.
2. ULPF     - normalize every event to OCSF, then evaluate the *OCSF* rule:
              the independently authored OCSF twin from the custom-rules repo
              when one exists, otherwise the original rule translated field-by-field.
3. Fidelity - a case is preserved when the OCSF verdict equals the raw verdict.
              Reported for ``native`` (pure OCSF paths) and ``full`` (plus ULPF's
              lossless unmapped/lineage) resolution, with per-field attribution,
              true field losses, and schema drift in third-party OCSF rules.
"""
from __future__ import annotations

import json
import re
import time
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from ..config import Settings, settings as default_settings
from ..normalizer import ocsf
from ..pipeline import Pipeline
from ..sniffer import sniff
from .mapping_extract import _field, _selections, load_rule_pairs
from .sigma_eval import SigmaError, SigmaRule
from .stages import StageRule
from .views import OcsfView, RawView

CASES = ("true_positive_1", "true_positive_2", "benign_1", "benign_2")
MODES = ("native", "full")

# Sigma logsource category -> Windows event IDs (Sysmon / Security / PowerShell)
CATEGORY_EIDS = {
    "process_creation": {"1", "4688"}, "network_connection": {"3"}, "image_load": {"7"},
    "file_event": {"11"}, "file_change": {"2"}, "file_delete": {"23", "26"},
    "registry_set": {"13"}, "registry_add": {"12"}, "registry_delete": {"12"}, "registry_rename": {"14"},
    "registry_event": {"12", "13", "14"}, "process_access": {"10"}, "create_remote_thread": {"8"},
    "driver_load": {"6"}, "dns_query": {"22"}, "ps_script": {"4104"}, "ps_module": {"4103"},
    "pipe_created": {"17", "18"}, "wmi_event": {"19", "20", "21"}, "process_termination": {"5"},
    "raw_access_thread": {"9"}, "create_stream_hash": {"15"},
}


def _sigma_docs(text: str) -> list[dict]:
    docs = []
    for chunk in re.split(r"(?m)^---\s*$", text):
        try:
            d = yaml.safe_load(chunk)
        except yaml.YAMLError:
            continue
        if isinstance(d, dict) and isinstance(d.get("detection"), dict):
            docs.append(d)
    return docs


_LINT_CHECKS = ("dangling_condition", "dangling_detection", "all_of_them_condition", "invalid_modifier_combinations",
                "double_wildcard", "escaped_wildcard", "control_character", "identifier_existence",
                "wildcards_instead_of_modifiers", "duplicate_tag")  # no attacktag: it fetches MITRE data (air-gap)
_VALIDATOR = None


def _pysigma_lint(text: str) -> list[str]:
    """Parse with pySigma (conditions included) and run its structural validators."""
    global _VALIDATOR
    try:
        from sigma.collection import SigmaCollection
        from sigma.plugins import InstalledSigmaPlugins
        from sigma.validation import SigmaValidator

        if _VALIDATOR is None:
            v = InstalledSigmaPlugins.autodiscover().validators
            _VALIDATOR = SigmaValidator([v[k] for k in _LINT_CHECKS if k in v])
        docs = "\n---\n".join(yaml.safe_dump(d, sort_keys=False) for d in _sigma_docs(text))
        coll = SigmaCollection.from_yaml(docs, collect_errors=True)
        out = [f"error: {e}" for r in coll.rules for e in (r.errors or [])]
        for r in coll.rules:
            for c in r.detection.parsed_condition:
                try:
                    c.parse()
                except Exception as exc:
                    out.append(f"condition: {exc}")
        out += [f"{type(i).__name__}" for i in _VALIDATOR.validate_rules(coll)]
        return out
    except Exception as exc:  # pragma: no cover - depends on pySigma internals
        return [f"pysigma: {str(exc)[:200]}"]


def _raw_alias(src_rule: dict, twin: dict) -> dict[str, str]:
    alias: dict[str, str] = {}
    s_sel, o_sel = _selections(src_rule.get("detection", {})), _selections(twin.get("detection", {}))
    for name, s_keys in s_sel.items():
        o_keys = o_sel.get(name)
        if o_keys and len(o_keys) == len(s_keys):
            for sk, ok in zip(s_keys, o_keys):
                if sk != ok:
                    alias.setdefault(ok, sk)
    return alias


@dataclass
class Ev:
    raw: RawView
    event: dict
    t: float
    lane_raw: str
    lane_ocsf: str


class Replayer:
    def __init__(self, datasets: Path, custom_rules: Path | None, settings: Settings | None = None,
                 gate_logsource: bool = False):
        # The reference engine does not gate Sigma rules on logsource category; keep that default.
        self.gate_logsource = gate_logsource
        self.datasets = datasets
        self.settings = settings or default_settings
        self.pipeline = Pipeline(self.settings)
        self.sigma_by_id, self.ocsf_by_id = (load_rule_pairs(custom_rules) if custom_rules and custom_rules.exists()
                                             else ({}, {}))

    # ----------------------------------------------------------------- events
    def _load_events(self, path: Path) -> list[Ev]:
        out: list[Ev] = []
        if not path.exists():
            return out
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            if not line.strip():
                continue
            try:
                event = self.pipeline.normalize(line, {"transport": "replay"})
            except Exception:
                continue
            fields: dict = {}
            sn = sniff(line)
            for pack in self.pipeline.registry.candidates(line, sn):
                try:
                    fields = pack.extract(line)
                    fields.pop("__consumed_sources__", None)
                    break
                except Exception:
                    continue
            rv = RawView(fields)
            t = None
            for k in ("timestamp", "time", "System.TimeCreated.SystemTime", "UtcTime", "@timestamp", "ts"):
                v = rv.first(k)
                if v not in (None, ""):
                    try:
                        t = ocsf.parse_timestamp(v) / 1000.0
                        break
                    except (ValueError, TypeError):
                        continue
            t_ocsf = (event.get("time") or 0) / 1000.0
            out.append(Ev(rv, event, t if t is not None else t_ocsf,
                          str(rv.first("hostname", "System.Computer", "agent_ip") or "_").lower(),
                          str(ocsf.get_path(event, "device.hostname") or ocsf.get_path(event, "device.ip") or "_").lower()))
        out.sort(key=lambda e: e.t)
        return out

    # -------------------------------------------------------------- sigma run
    @staticmethod
    def _gate(rule: SigmaRule, eid: Any) -> bool:
        cat = str(rule.logsource.get("category") or "").lower()
        wanted = CATEGORY_EIDS.get(cat)
        if not wanted or eid in (None, ""):
            return True
        return str(eid) in wanted

    def _sigma_alerts(self, rules: list[SigmaRule], events: list[Ev], view: str, gate_rules: list[SigmaRule],
                      mode: str = "full", stats: Counter | None = None, lost: Counter | None = None,
                      alias: dict | None = None) -> int:
        n = 0
        for ev in events:
            if view == "raw":
                v, eid = ev.raw, ev.raw.first("System.EventID", "eventId", "EventID")
            else:
                v = OcsfView(ev.event, mode, stats, lost, raw=ev.raw, raw_alias=alias)
                eid = ocsf.get_path(ev.event, "metadata.event_code")
            if gate_rules and not all(self._gate(g, eid) for g in gate_rules):
                continue
            try:
                if any(r.match(v) for r in rules):
                    n += 1
            except Exception:
                continue
        return n

    # ------------------------------------------------------------------ main
    def run(self, limit: int | None = None, progress=None) -> dict:
        t0 = time.time()
        rows: list[dict] = []
        attribution = {m: Counter() for m in MODES}
        lost = {m: Counter() for m in MODES}
        drift: Counter = Counter()
        lint_errors = 0
        lint_kinds: Counter = Counter()
        skipped: list[dict] = []
        dirs = sorted(p.parent for p in self.datasets.glob("*/*/expected.json"))
        if limit:
            dirs = dirs[:limit]
        for i, d in enumerate(dirs):
            if progress:
                progress(i, len(dirs), d.name)
            try:
                expected = json.loads((d / "expected.json").read_text())
            except (OSError, ValueError) as exc:
                skipped.append({"dataset": d.name, "reason": f"expected.json: {exc}"})
                continue
            rule_file = d / "rule.yml"
            if not rule_file.exists():
                skipped.append({"dataset": f"{d.parent.name}/{d.name}", "reason": "no rule definition (unmapped)"})
                continue
            text = rule_file.read_text(encoding="utf-8", errors="replace")
            source = str(expected.get("event_source") or "")
            fmt, twin_used = "sigma", False
            try:
                if text.lstrip().startswith("{"):
                    rule = StageRule(json.loads(text), expected.get("rule_type"))
                    fmt = rule.format
                    raw_rules, ocsf_rules, gate = [rule], [rule], []
                    rid, title = rule.id, rule.title
                else:
                    docs = _sigma_docs(text)
                    raw_rules = [SigmaRule(x) for x in docs]
                    if not raw_rules:
                        raise SigmaError("no sigma detection document")
                    issues = _pysigma_lint(text)
                    if issues:
                        lint_errors += 1
                        lint_kinds.update(i.split(":")[0] for i in issues)
                    rid, title = raw_rules[0].id, raw_rules[0].title
                    gate = raw_rules[:1] if self.gate_logsource else []
                    twin_doc = self.ocsf_by_id.get(rid)
                    ocsf_rules, alias = raw_rules, {}
                    if twin_doc:
                        try:
                            ocsf_rules = [SigmaRule(twin_doc)] + raw_rules[1:]  # twin covers doc 1 only
                            alias = _raw_alias(docs[0], twin_doc)
                            twin_used = True
                            cls = (twin_doc.get("logsource") or {}).get("class")
                            for f in ocsf_rules[0].fields:
                                if "." not in f or f.startswith("unmapped.") or not cls:
                                    continue
                                try:
                                    known = ocsf.known_path(cls, f)
                                except KeyError:
                                    drift[f"{cls} (not an OCSF {ocsf.version()} class)"] += 1
                                    break
                                if not known:
                                    drift[f"{cls}:{f}"] += 1
                        except SigmaError:
                            ocsf_rules = raw_rules
            except (SigmaError, ValueError, KeyError, TypeError) as exc:
                skipped.append({"dataset": f"{d.parent.name}/{d.name}", "reason": f"rule parse: {exc}"[:200]})
                continue

            row = {"dataset": f"{d.parent.name}/{d.name}", "rule_id": rid, "title": title[:120], "format": fmt,
                   "rule_type": expected.get("rule_type"), "source": source, "twin": twin_used, "cases": {}}
            for case in CASES:
                meta = expected.get(case) or {}
                if "expected_alerts" not in meta:
                    continue
                events = self._load_events(d / f"{case}.jsonl")
                exp = int(meta["expected_alerts"]) > 0
                res: dict[str, Any] = {"expected": exp, "events": len(events)}
                if fmt == "sigma":
                    res["raw"] = self._sigma_alerts(raw_rules, events, "raw", gate) > 0
                    for m in MODES:
                        res[m] = self._sigma_alerts(ocsf_rules, events, "ocsf", gate, m, attribution[m], lost[m],
                                                    alias if twin_used else None) > 0
                else:
                    rule = raw_rules[0]
                    res["raw"] = rule.evaluate([(e.t, e.lane_raw, e.raw) for e in events], source) > 0
                    for m in MODES:
                        res[m] = rule.evaluate([(e.t, e.lane_ocsf, OcsfView(e.event, m, attribution[m], lost[m],
                                                                             raw=e.raw)) for e in events], source) > 0
                row["cases"][case] = res
            rows.append(row)
        rep = self._report(rows, attribution, lost, drift, skipped, lint_errors, len(dirs), time.time() - t0)
        rep["pysigma_findings_by_type"] = lint_kinds.most_common()
        return rep

    # ---------------------------------------------------------------- report
    @staticmethod
    def _report(rows, attribution, lost, drift, skipped, lint_errors, n_dirs, secs) -> dict:
        cases = [(r, c, v) for r in rows for c, v in r["cases"].items()]
        n = len(cases) or 1
        oracle_ok = [x for x in cases if x[2]["raw"] == x[2]["expected"]]

        def rate(pred, pool):
            pool = list(pool)
            return round(100.0 * sum(1 for x in pool if pred(x)) / (len(pool) or 1), 2)

        modes = {}
        for m in MODES:
            tp = [x for x in cases if x[2]["expected"]]
            bn = [x for x in cases if not x[2]["expected"]]
            att = attribution[m]
            resolved = sum(att[k] for k in ("native", "alias", "unmapped", "lineage"))
            modes[m] = {
                "fidelity_vs_raw": rate(lambda x: x[2][m] == x[2]["raw"], cases),
                "fidelity_on_valid_oracle": rate(lambda x: x[2][m] == x[2]["raw"], oracle_ok),
                "accuracy_vs_expected": rate(lambda x: x[2][m] == x[2]["expected"], cases),
                "tp_detection_rate": rate(lambda x: x[2][m], tp),
                "benign_silence_rate": rate(lambda x: not x[2][m], bn),
                "detections_lost": sum(1 for x in cases if x[2]["raw"] and not x[2][m]),
                "false_alerts_introduced": sum(1 for x in cases if not x[2]["raw"] and x[2][m]),
                "field_resolution": dict(att),
                "ocsf_native_share": round(100.0 * (att["native"] + att["alias"]) / (resolved or 1), 2),
                "top_lost_fields": lost[m].most_common(25),
            }
        by_fmt = defaultdict(lambda: {"cases": 0, "preserved_full": 0, "preserved_native": 0, "oracle_ok": 0})
        for r, c, v in cases:
            b = by_fmt[r["format"]]
            b["cases"] += 1
            b["preserved_full"] += v["full"] == v["raw"]
            b["preserved_native"] += v["native"] == v["raw"]
            b["oracle_ok"] += v["raw"] == v["expected"]
        rules_all_ok = sum(1 for r in rows if r["cases"] and all(v["full"] == v["raw"] for v in r["cases"].values()))
        return {
            "generated_ms": int(time.time() * 1000),
            "ocsf_version": ocsf.version(),
            "datasets_found": n_dirs,
            "rules_evaluated": len(rows),
            "cases_evaluated": len(cases),
            "twin_rules_used": sum(1 for r in rows if r["twin"]),
            "skipped": skipped,
            "pysigma_lint_errors": lint_errors,
            "oracle_agreement": rate(lambda x: x[2]["raw"] == x[2]["expected"], cases),
            "schema_fidelity_score": modes["full"]["fidelity_vs_raw"],
            "native_ocsf_fidelity": modes["native"]["fidelity_vs_raw"],
            "rules_fully_preserved": rules_all_ok,
            "modes": modes,
            "by_format": dict(by_fmt),
            "schema_drift_in_third_party_rules": drift.most_common(30),
            "seconds": round(secs, 1),
            "rows": rows,
        }


def to_markdown(rep: dict) -> str:
    m_full, m_nat = rep["modes"]["full"], rep["modes"]["native"]
    lines = [
        "# ULPF Schema Fidelity Report", "",
        f"OCSF {rep['ocsf_version']} | datasets {rep['datasets_found']} | rules evaluated {rep['rules_evaluated']} | "
        f"cases {rep['cases_evaluated']} | OCSF twin rules used {rep['twin_rules_used']} | {rep['seconds']} s", "",
        "| Metric | Full ULPF (OCSF + lossless envelope) | Native OCSF paths only |", "|---|---|---|",
        f"| **Schema Fidelity** (OCSF verdict == raw verdict) | **{m_full['fidelity_vs_raw']}%** | {m_nat['fidelity_vs_raw']}% |",
        f"| Fidelity where oracle is valid | {m_full['fidelity_on_valid_oracle']}% | {m_nat['fidelity_on_valid_oracle']}% |",
        f"| Accuracy vs expected.json | {m_full['accuracy_vs_expected']}% | {m_nat['accuracy_vs_expected']}% |",
        f"| True-positive detection rate | {m_full['tp_detection_rate']}% | {m_nat['tp_detection_rate']}% |",
        f"| Benign silence rate | {m_full['benign_silence_rate']}% | {m_nat['benign_silence_rate']}% |",
        f"| Detections lost by normalization | {m_full['detections_lost']} | {m_nat['detections_lost']} |",
        f"| False alerts introduced | {m_full['false_alerts_introduced']} | {m_nat['false_alerts_introduced']} |",
        f"| Field lookups resolved via OCSF paths | {m_full['ocsf_native_share']}% | {m_nat['ocsf_native_share']}% |",
        "",
        f"Oracle agreement (our rule engine on raw events vs `expected.json`): **{rep['oracle_agreement']}%** "
        f"| rules with every case preserved: {rep['rules_fully_preserved']}/{rep['rules_evaluated']} "
        f"| Sigma rules with pySigma lint findings: {rep['pysigma_lint_errors']} "
        f"({', '.join(f'{k} x{n}' for k, n in rep.get('pysigma_findings_by_type', [])[:6])})", "",
        "## By rule format", "", "| Format | Cases | Oracle OK | Preserved (full) | Preserved (native) |", "|---|---|---|---|---|",
    ]
    for f, b in rep["by_format"].items():
        lines.append(f"| {f} | {b['cases']} | {b['oracle_ok']} | {b['preserved_full']} | {b['preserved_native']} |")
    lines += ["", "## Fields present in raw events but unreachable in native OCSF (top)", ""]
    lines += [f"- `{f}`: {n}" for f, n in m_nat["top_lost_fields"][:15]] or ["- none"]
    lines += ["", "## Fields lost even with the lossless envelope", ""]
    lines += [f"- `{f}`: {n}" for f, n in m_full["top_lost_fields"][:15]] or ["- none"]
    lines += ["", "## Schema drift: non-OCSF-1.3 paths used by third-party \"OCSF\" rules", ""]
    lines += [f"- `{f}`: {n} rules" for f, n in rep["schema_drift_in_third_party_rules"][:15]] or ["- none"]
    mism = [(r, c, v) for r in rep["rows"] for c, v in r["cases"].items() if v["full"] != v["raw"]]
    lines += ["", f"## Cases where normalization changed the verdict ({len(mism)})", ""]
    for r, c, v in mism[:40]:
        lines.append(f"- {r['dataset']} `{c}` raw={v['raw']} ocsf={v['full']} expected={v['expected']}")
    lines += ["", f"Skipped datasets: {len(rep['skipped'])}"]
    lines += [f"- {s['dataset']}: {s['reason']}" for s in rep["skipped"][:20]]
    return "\n".join(lines) + "\n"


def run_and_save(datasets: Path, custom_rules: Path | None, out_dir: Path, settings: Settings | None = None,
                 limit: int | None = None, progress=None) -> dict:
    rep = Replayer(datasets, custom_rules, settings).run(limit, progress)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "fidelity.json").write_text(json.dumps(rep, indent=1, default=str))
    (out_dir / "FIDELITY.md").write_text(to_markdown(rep))
    return rep
