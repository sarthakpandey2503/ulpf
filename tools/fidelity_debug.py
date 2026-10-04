"""Inspect one dataset: rule, raw fields, OCSF resolution per rule field."""
import json
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ulpf.validator.replay import Replayer, _raw_alias, _sigma_docs  # noqa: E402
from ulpf.validator.sigma_eval import SigmaRule  # noqa: E402
from ulpf.validator.views import OcsfView  # noqa: E402

ROOT = Path("third_party/Detection-Engineering-Ruleset")
rp = Replayer(ROOT, Path("third_party/custom-rules"))
d = next(ROOT.glob(f"*/{sys.argv[1]}"))
case = sys.argv[2] if len(sys.argv) > 2 else "true_positive_1"
text = (d / "rule.yml").read_text()
docs = _sigma_docs(text) if not text.lstrip().startswith("{") else []
print((text[:1800]))
twin = rp.ocsf_by_id.get(str(docs[0].get("id"))) if docs else None
if twin:
    print("=== TWIN\n", json.dumps(twin["detection"], indent=1)[:1500])
alias = _raw_alias(docs[0], twin) if twin else {}
for ev in rp._load_events(d / f"{case}.jsonl"):
    print("=== RAW", {k: v for k, v in ev.raw.fields.items() if not k.startswith("System.")})
    print("=== CLASS", ev.event["class_name"], ev.event["ulpf"]["pack"], ev.event.get("metadata", {}).get("event_code"))
    rules = [SigmaRule(twin)] if twin else [SigmaRule(x) for x in docs]
    for r in rules:
        for f in sorted(r.fields):
            st = Counter()
            v = OcsfView(ev.event, "full", st, raw=ev.raw, raw_alias=alias)
            print(f"   {f:40s} raw={ev.raw.get(alias.get(f, f))!r:60.60s} ocsf={v.get(f)!r:60.60s} {dict(st)}")
        print("   MATCH raw:", any(SigmaRule(x).match(ev.raw) for x in docs), " ocsf:",
              r.match(OcsfView(ev.event, "full", raw=ev.raw, raw_alias=alias)))
