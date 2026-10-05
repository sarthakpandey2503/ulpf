# Problem and approach

## The problem

Security teams collect logs from many perimeter devices: firewalls, IDS sensors, proxies, VPN and SSH gateways. Each vendor writes its own format. Before any SIEM or analytics tool can use those logs, someone has to write and maintain a parser per vendor, fields get dropped along the way, and there is usually no way to show an auditor the original line behind a normalized record.

ULPF is a framework that ingests logs from any of these devices, keeps the original event, parses the vendor fields, maps them into one taxonomy, and keeps a traceable link between the two. It works without outbound network access (air-gapped) and ships as a container.

The requirements map onto the code as follows:

| Requirement | What ULPF does |
|---|---|
| Preserve the raw event | `raw_data` and `raw_sha256` on every event |
| Extract source-specific attributes | YAML pack extractors: JSON, XML, CSV, key=value, Grok/regex, CEF, LEEF, syslog 3164/5424 |
| Normalize to a common taxonomy | OCSF 1.3, schema vendored in `ulpf/normalizer/ocsf_schema.json` |
| Trace a normalized field back to the original | `ulpf.field_lineage` |
| Plug-and-play new sources | One YAML pack. The generator drafts it. An admin signs it |
| Unified visibility | Dashboard: every source in one OCSF table |
| SIEM and data lake output | Sinks: Splunk HEC, Elasticsearch, CEF, ClickHouse, Parquet/MinIO |
| Analytics-ready data | One schema, stable field names, raw text retained |
| Less parser development | A reviewed YAML file instead of a new parser codebase |
| Air-gapped operation | No required outbound calls. Optional LLM is loopback-only |
| Container deployment | `deploy/Dockerfile` and Compose, non-root, read-only |

The focus is **perimeter network devices**. The sample logs cover firewalls, IDS, proxies, and SSH on the edge. Endpoint Windows Event Log datasets are used only by the Schema Fidelity harness, because that is where paired true-positive / benign labels exist.

## Beyond a basic parser pipeline

A basic pipeline collects, parses, maps to a common JSON, and keeps the raw line. ULPF adds three capabilities on top of that.

### 1. Offline parser generator

Show the system a format it has never seen. Drain3 clusters similar lines. A lexical plus value-shape mapper (and optionally a local Ollama model) drafts a YAML source pack. The draft is self-tested and stays inactive until an admin approves and Ed25519-signs it.

This reduces parser development effort without a cloud LLM in the hot path. See [AI_PARSER_GENERATOR.md](AI_PARSER_GENERATOR.md).

### 2. Detection-validated normalization (Schema Fidelity)

Two third-party repos feed the harness:

- [Detection-Engineering-Ruleset](https://github.com/damnkrishna/Detection-Engineering-Ruleset) — 551 replay datasets, each with labelled attack and benign log files plus `expected.json`.
- [detection-engineering-custom-rules-](https://github.com/damnkrishna/detection-engineering-custom-rules-) — Sigma rules and OCSF twins used as the field vocabulary.

Logs go through ULPF, then the same rules run on the raw view and on the normalized view. **Schema fidelity** is the share of cases whose verdict is unchanged by normalization. The bundled report is 100% on the full envelope versus 91% if only native OCSF paths are kept (174 detections lost). See [FIDELITY_VALIDATOR.md](FIDELITY_VALIDATOR.md).

"100%" means normalization did not change the verdict. It does **not** mean the third-party rules are perfect. Agreement with their `expected.json` is 94.81%.

### 3. Tamper-evident lineage

Each batch is a Merkle tree over `sha256(raw) || sha256(normalized)`. Roots are hash-chained and signed with Ed25519. The signing key lives outside the database. SQLite triggers reject updates and deletes. Editing one stored raw byte fails `/verify`. There is no token, no peer network, and no outbound call, so it works air-gapped. See [EVENT_AND_LINEAGE.md](EVENT_AND_LINEAGE.md).

## Design decisions

| Choice | Why |
|---|---|
| Python 3.11+ / FastAPI | Fast to build; ML and Sigma tooling already live here |
| OCSF 1.3, vendored | Vendor-neutral security taxonomy; no schema fetch at runtime |
| Declarative YAML packs | New vendor = config, not code. AI drafts must pass the same schema |
| Drain3 + offline mapper, Ollama optional | Air-gap. The model never has tools or network |
| SQLite for the local store | ClickHouse and Parquet are the production exits; the envelope is the same |
| Ed25519-signed Merkle chain | Tamper evidence on an isolated network, without a public blockchain |
| RE2, defusedxml, `yaml.safe_load` | Log text is treated as hostile |

## Target metrics

These are **targets**, not all measured. Measured numbers are in the bundled fidelity report (`ulpf/validator/fidelity_summary.json`) and in [FIDELITY_VALIDATOR.md](FIDELITY_VALIDATOR.md).

**Accuracy**

- Parse success for a hand-written pack: ≥ 99%
- Field extraction F1 on a golden set: ≥ 0.95 (golden set **not built yet**)
- OCSF mapping accuracy: ≥ 95%
- Event classification accuracy: ≥ 98%
- Schema validity: 100% of events pass OCSF JSON Schema

**Proof**

- Schema Fidelity (verdict preserved): measured, 100% full envelope
- Raw preservation (SHA-256 of stored raw matches): 100% of decoded text (see known issue: not wire bytes)
- Field coverage: every extracted field is mapped or kept under `unmapped`
- Tamper detection: 100% of modified stored raw logs fail verify

**Onboarding**

- New source: ~30 lines of YAML, zero lines of Python
- First-draft parse rate and human edits: shown on the Onboard page self-test, not aggregated

**Performance**

- Throughput: `ulpf bench` measures a single process with ledger and sinks off. Results depend heavily on the machine; it is not a cluster benchmark
- Air-gap: pass/fail (scripts exist in `deploy/airgap/`)

**Confidence score on each event** (from `ulpf.confidence`)

| Parser source | Weight |
|---|---|
| Hand-written pack, or AI pack with `approved_by` | 1.0 |
| AI-drafted pack not yet approved | 0.7 (unsigned packs) — drafts never route at all |
| Fallback fuzzy field matching | capped at 0.6 |
| Nothing matched (raw kept, fields in `unmapped`) | fallback path; still stored |

A human correction always overrides the AI: the analyst edits the draft YAML, it is re-tested, and only an admin signature makes it live.

A possible combined "ULPF Quality Score" (not computed in code): detection fidelity 30%, field/mapping F1 25%, losslessness and lineage 20%, parse success 15%, performance 10%.

## Out of scope for now

- A multi-node ledger. The local store is SQLite.
- Compiling hot packs to Vector VRL or Rust. The YAML contract is meant to allow that later.
- A public blockchain, a coin, or an external notary.
- Cloud LLM calls.
- A hand-labelled golden set for field F1, fuzz tests, and a security scanner report (planned, not built).
