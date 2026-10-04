"""Self-test a (draft) pack against its samples before a human reviews it.

Gates: pack schema valid, >= 95 % of samples routed + parsed by the pack,
>= 90 % OCSF-valid, >= 3 OCSF attributes mapped per event on average, and a
report of routing conflicts with already-installed packs.
"""
from __future__ import annotations

from statistics import mean

from ..config import Settings
from ..packs.engine import compile_pack
from ..packs.loader import PackRegistry
from ..packs.schema import validate_pack
from ..sniffer import sniff

PARSE_MIN, VALID_MIN, MAPPED_MIN = 0.95, 0.90, 3.0


def selftest(doc: dict, samples: list[str], settings: Settings, existing: PackRegistry | None = None) -> dict:
    from ..pipeline import Pipeline

    rep: dict = {"schema_errors": validate_pack(doc)}
    if rep["schema_errors"]:
        rep.update(passed=False, reason="pack schema invalid")
        return rep
    try:
        cp = compile_pack(doc)
    except Exception as exc:
        rep.update(passed=False, reason=f"compile failed: {exc}")
        return rep
    reg = PackRegistry(settings)
    reg.packs = [cp]
    pipe = Pipeline(settings, registry=reg)
    routed = parsed = valid = 0
    mapped, unmapped = [], []
    errors: dict[str, int] = {}
    example = None
    for s in samples:
        try:
            e = pipe.normalize(s)
        except Exception as exc:
            errors[str(exc)[:80]] = errors.get(str(exc)[:80], 0) + 1
            continue
        u = e["ulpf"]
        if u["pack"] != cp.ref:
            continue
        routed += 1
        if not u.get("parse_errors"):
            parsed += 1
        if u["validation"]["valid"]:
            valid += 1
        else:
            for err in u["validation"]["errors"][:3]:
                errors[err] = errors.get(err, 0) + 1
        mapped.append(sum(1 for v in u["field_lineage"].values()
                          if not str(v).startswith(("default", "const"))))
        unmapped.append(len(e.get("unmapped") or {}))
        example = example or e
    n = max(1, len(samples))
    conflicts: dict[str, int] = {}
    if existing is not None:
        for s in samples[:200]:
            for p in existing.candidates(s, sniff(s)):
                if p.id != cp.id:
                    conflicts[p.ref] = conflicts.get(p.ref, 0) + 1
    rep.update({
        "samples": len(samples), "route_rate": round(routed / n, 4), "parse_rate": round(parsed / n, 4),
        "ocsf_valid_rate": round(valid / n, 4), "avg_mapped_attributes": round(mean(mapped), 2) if mapped else 0,
        "avg_unmapped_fields": round(mean(unmapped), 2) if unmapped else 0,
        "top_errors": sorted(errors.items(), key=lambda kv: -kv[1])[:8], "routing_conflicts": conflicts,
        "example_event": example,
    })
    checks = {"parse_rate": rep["parse_rate"] >= PARSE_MIN, "ocsf_valid_rate": rep["ocsf_valid_rate"] >= VALID_MIN,
              "avg_mapped_attributes": rep["avg_mapped_attributes"] >= MAPPED_MIN, "no_routing_conflicts": not conflicts}
    rep["checks"] = checks
    rep["passed"] = all(v for k, v in checks.items() if k != "no_routing_conflicts")
    return rep
