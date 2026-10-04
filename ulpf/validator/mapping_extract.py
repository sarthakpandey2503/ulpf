"""Derive a Sigma-field -> OCSF-path mapping table from paired rules in the
detection-engineering-custom-rules repository.

Each rule markdown file contains a native Sigma rule and an OCSF-normalized twin
with the same ``id``. Detection selections are aligned key-by-key, which yields
evidence such as ``Image -> process.file.path``. Votes are aggregated per
(logsource class, sigma field) and globally.
"""
from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from pathlib import Path

import yaml

_BLOCK = re.compile(r"```ya?ml\s*\n(.*?)```", re.S)


def _field(key: str) -> str:
    return key.split("|", 1)[0].strip()


def iter_rule_blocks(md_text: str):
    for m in _BLOCK.finditer(md_text):
        try:
            for doc in yaml.safe_load_all(m.group(1)):
                if isinstance(doc, dict) and "detection" in doc:
                    yield doc
        except yaml.YAMLError:
            continue


def _selections(detection: dict) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for name, body in detection.items():
        if name in ("condition", "timeframe"):
            continue
        keys: list[str] = []
        items = body if isinstance(body, list) else [body]
        for item in items:
            if isinstance(item, dict):
                keys.extend(_field(k) for k in item)
        out[name] = keys
    return out


def load_rule_pairs(repo: Path) -> tuple[dict[str, dict], dict[str, dict]]:
    """Return ({id: sigma_rule}, {id: ocsf_rule}) across all markdown files."""
    sigma: dict[str, dict] = {}
    ocsf: dict[str, dict] = {}
    for md in repo.rglob("*.md"):
        try:
            text = md.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for doc in iter_rule_blocks(text):
            rid = str(doc.get("id", "")).strip()
            if not rid:
                continue
            product = str((doc.get("logsource") or {}).get("product", "")).lower()
            (ocsf if product == "ocsf" else sigma)[rid] = doc
    return sigma, ocsf


def build_mapping(repo: Path) -> dict:
    sigma, ocsf = load_rule_pairs(repo)
    by_class: dict[str, Counter] = defaultdict(Counter)
    global_votes: dict[str, Counter] = defaultdict(Counter)
    paired = 0
    for rid, s in sigma.items():
        o = ocsf.get(rid)
        if not o:
            continue
        paired += 1
        cls = str((o.get("logsource") or {}).get("class", "unknown"))
        s_sel, o_sel = _selections(s.get("detection", {})), _selections(o.get("detection", {}))
        for name, s_keys in s_sel.items():
            o_keys = o_sel.get(name)
            if not o_keys or len(o_keys) != len(s_keys):
                continue
            for sk, ok in zip(s_keys, o_keys):
                by_class[cls][(sk, ok)] += 1
                global_votes[sk][ok] += 1
    table_global = {sk: votes.most_common(1)[0][0] for sk, votes in global_votes.items()}
    table_class: dict[str, dict[str, str]] = {}
    for cls, votes in by_class.items():
        best: dict[str, tuple[str, int]] = {}
        for (sk, ok), n in votes.items():
            if sk not in best or n > best[sk][1]:
                best[sk] = (ok, n)
        table_class[cls] = {sk: ok for sk, (ok, _) in sorted(best.items())}
    return {
        "source": "damnkrishna/detection-engineering-custom-rules-",
        "sigma_rules": len(sigma),
        "ocsf_rules": len(ocsf),
        "paired_rules": paired,
        "global": dict(sorted(table_global.items())),
        "by_class": dict(sorted(table_class.items())),
    }


def main() -> None:
    import sys

    repo, out = Path(sys.argv[1]), Path(sys.argv[2])
    table = build_mapping(repo)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(table, indent=2), encoding="utf-8")
    print(f"sigma={table['sigma_rules']} ocsf={table['ocsf_rules']} paired={table['paired_rules']} "
          f"fields={len(table['global'])} -> {out}")


if __name__ == "__main__":
    main()
