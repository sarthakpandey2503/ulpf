# Schema Fidelity validator

The claim "normalization is correct" is measured by replaying labelled detection datasets through ULPF and checking that rule verdicts do not change.

Code: `ulpf/validator/`. CLI: `python -m ulpf.cli fidelity`. Dashboard: **Fidelity** tab. Bundled report (so the UI works without a re-run): `ulpf/validator/fidelity_summary.json`. A re-run writes `data/fidelity/fidelity.json` and `FIDELITY.md`, and the dashboard prefers that file.

## Third-party inputs

`third_party/` is gitignored, so these are not in a fresh clone. Expected layout:

| Path | Repo | Role |
|---|---|---|
| `third_party/Detection-Engineering-Ruleset/` | damnkrishna/Detection-Engineering-Ruleset | 551 `expected.json` files; each dataset folder has `rule.yml` and `true_positive_*.jsonl` / `benign_*.jsonl` |
| `third_party/custom-rules/` | damnkrishna/detection-engineering-custom-rules- | Sigma YAML in markdown fences, plus OCSF twins (`logsource.product: ocsf`) |
| `third_party/ocsf-schema/` | ocsf/ocsf-schema | source for `tools/build_ocsf_schema.py` (already compiled into the package) |

CLI defaults: `--datasets third_party/Detection-Engineering-Ruleset --rules third_party/custom-rules --out data/fidelity`.

Most true-positive files are EDR JSON with an `"xml"` field (Windows Event Log). A minority are canonical sensor JSON with `event_uid`. That is why the library includes `microsoft.windows_eventlog` and `sensors.canonical_alert` even though ULPF targets perimeter devices.

Clone them from the repository root:

```bash
git clone https://github.com/damnkrishna/Detection-Engineering-Ruleset third_party/Detection-Engineering-Ruleset
git clone https://github.com/damnkrishna/detection-engineering-custom-rules- third_party/custom-rules
git clone https://github.com/ocsf/ocsf-schema third_party/ocsf-schema   # only needed to rebuild the OCSF schema
```

## Per-dataset flow (`replay.py`)

`Replayer.run` globs `<datasets>/*/*/expected.json`. For each dataset:

1. Load `rule.yml` (Sigma YAML, or JSON if the text starts with `{`). Split multi-doc YAML on `---`.
2. Normalize every line in the four case files with `Pipeline.normalize`.
3. Build a `RawView` from the first candidate pack that extracts successfully.
4. Timestamp from vendor fields, else OCSF `time`. Lanes (correlation grouping) from host / agent IP vs OCSF `device.hostname` / `device.ip`.
5. For Sigma: optional OCSF twin with the same `id` replaces document 1 for the normalized views. `_raw_alias` maps twin keys back for the raw view. pySigma lint runs with `_LINT_CHECKS`; `attacktag` is skipped because it wants the network. Logsource gating by EventID (`CATEGORY_EIDS`) is **off** (`gate_logsource=False`).
6. For each case, compute three verdicts: **raw** (oracle), **native**, **full**.

Exceptions while evaluating a rule are swallowed and count as "no alert".

## Views (`views.py`)

| View | What the rule sees |
|---|---|
| `RawView` | Vendor fields from pack `extract()`. Lookups are case- and underscore-insensitive, with `DICTIONARY` fallbacks |
| `OcsfView` mode=`native` | Native OCSF paths, then aliases (`PATH_ALIASES`, `DICTIONARY`, `sigma_ocsf_map.json`). No `unmapped`, no lineage |
| `OcsfView` mode=`full` | Native + alias, then `unmapped`, then reverse `ulpf.field_lineage` |

`SEMANTIC_COLLISIONS` (`severity`, `source`) are not treated as native paths. Keyword search excludes `raw_data`, `ulpf`, `metadata`.

`sigma_ocsf_map.json` was produced by `mapping_extract.build_mapping()`: 497 Sigma rules, 649 OCSF twins, 497 paired, plus global and per-class field-to-path tables.

## Sigma evaluator (`sigma_eval.py`)

- Selections: map = AND across fields; list of maps = OR; keyword lists match `*...*` across `view.values()`.
- Modifiers: `contains`, `startswith`, `endswith`, `all`, `re` (RE2), `cidr`, `windash`, `exists`, `gt`/`gte`/`lt`/`lte`, `base64`, `base64offset`.
- Unknown modifiers (`cased`, `wide`/`utf16le`, `expand`, `fieldref`) are **ignored**.
- Values: `null` = field absent/empty. Wildcards `*` / `?`, `\*` / `\?` escapes. Case-insensitive. Plain numbers also compare as ints.
- Conditions: recursive descent, `and` / `or` / `not` / `( )` / `1 of X` / `all of X` / `them`. Not `N of` / `any of`. No `|` aggregation or `timeframe` correlation. Multiple `condition` fields: any may match.

## IR_v1 and legacy stages (`stages.py`)

JSON rules: `IR_v1` if `ruleFormat == IR_v1` or a stage has `match`; else `legacy`.

- IR_v1: nested AND/OR groups; equals/in/contains/startswith/endswith/regex/gt/lt/exists/`not_*`; `equals_field:stageN.field` back-references.
- Legacy: all explicit conditions AND (tactic OR technique prefix OR signatureContains/Equals), minus `excludeSignatureContains`.
- **THRESHOLD**: sliding window on stage 0; alert when count and distinct-value conditions hold; then clear hits (no suppression period).
- **SEQUENCE**: greedy automaton over non-optional stages; reset on overall window or per-stage gap. Overlapping partial sequences are dropped.

## Metrics (`Replayer._report`)

Pool = all (dataset, case) pairs. On the bundled run: 539 rules × 4 cases = **2,156** cases. 551 − 539 = **12 skipped** (unmapped placeholders and a few unparseable rules).

| Name in report | Meaning |
|---|---|
| `schema_fidelity_score` | full-mode verdict == raw verdict (**100.0%**) |
| `native_ocsf_fidelity` | same, native paths only (**91.0%**) |
| `oracle_agreement` | raw verdict == `expected.json` (**94.81%**) |
| `fidelity_on_valid_oracle` | fidelity restricted to cases where the oracle was right |
| `tp_detection_rate` | share of expected-positive cases that alerted (full **94.62%**) |
| `benign_silence_rate` | share of expected-negative cases that stayed silent (full **94.99%**) |
| `detections_lost` | raw true, mode false (full **0**, native **174**) |
| `false_alerts_introduced` | raw false, mode true (full **0**, native **20**) |
| `ocsf_native_share` | (native + alias) / (native + alias + unmapped + lineage). Native mode is **always 100%** because unmapped/lineage cannot fire. Full mode **91.81%** is the real measurement |
| `rules_fully_preserved` | 539/539 |
| `twin_rules_used` | 453 |
| `schema_drift_in_third_party_rules` | twin paths that are not OCSF 1.3 |

Reading the numbers: 100% fidelity means normalization never changed a verdict; it does not mean the detections are 100% accurate. The 94.81% figure is oracle agreement, not fidelity. The custom-rules repo contains more rules than the 539 that the replay uses.

`GET /v1/fidelity` serves `data/fidelity/fidelity.json`, else the bundled summary, with `rows` stripped.

## How to re-run

From the repository root, with the virtual environment active and the datasets cloned:

```bash
python -m ulpf.cli fidelity
```

To keep the result out of the dashboard, write it somewhere else with `--out`, for example `--out /tmp/ulpf-fid-out` (Linux) or `--out $env:TEMP\ulpf-fid-out` (PowerShell).

`--limit N` processes only the first N datasets (smoke). `--out` writes `fidelity.json` and `FIDELITY.md`.

## `tools/fidelity_debug.py`

Usage (must be cwd = repo root):

```bash
python tools/fidelity_debug.py <dataset-folder> [case]
```

Prints the rule, the twin detection block, raw fields, class/pack, and per-field raw vs OCSF resolution plus match results. Paths are relative. `read_text()` has no encoding. JSON stage rules leave `docs` empty and then raise `NameError` on `r` — use it for Sigma datasets only.

## Headline numbers (bundled report)

From `ulpf/validator/fidelity_summary.json`. A full re-run reproduces the same percentages; run time depends on the machine (seconds to a few minutes).

- 551 datasets, 539 rules, 2,156 cases, 453 twins
- Full envelope: 100% fidelity, 0 lost, 0 false alerts, TP 94.62%, benign silence 94.99%
- Native OCSF only: 91%, 174 lost, 20 false alerts
- Oracle agreement 94.81% (2,044 / 2,156)
- By format: sigma 1884 cases (all preserved full, 1690 native), legacy 196, IR_v1 76 (both formats fully preserved even native)
