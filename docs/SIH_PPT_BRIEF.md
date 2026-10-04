# SIH PPT brief — ULPF (PS 26156)

Use this as the source for the slides. The official technical presentation is **at most 5 slides**. Everything after the slide drafts is backup: speaker notes, numbers, and jury answers. Do not put all of it on the slides.

Related files already in the repo: `docs/slides.html` (a 5-slide shell), `docs/DEMO.md` (2-minute video script), `docs/ARCHITECTURE.md` (2-page architecture note).

---

## 1. Title block (slide master / first slide)

| Item | Text |
|---|---|
| Problem statement ID | **26156** |
| Title | Universal Log Pre-processing Framework |
| Short name | **ULPF** |
| Organization | National Technical Research Organisation (NTRO) |
| Category | Software |
| Theme | Blockchain & Cybersecurity |
| One-line pitch | Any perimeter log in. One lossless OCSF event out. A signed proof back to the original bytes. Offline. |

**Do not** put team member names in this file. Add them on the title slide yourselves.

---

## 2. The five slides

Official limit is 5. Suggested cut:

### Slide 1 — Problem and what we built

**Title:** One schema for every perimeter log

**Say this, not a paragraph:**

- Firewalls, IDS, VPN, and proxies log in syslog, CEF, LEEF, JSON, CSV, and XML. A SIEM cannot use them until each source has its own parser.
- NTRO asked for a framework that keeps the original event, parses it, maps it to one taxonomy, and stays traceable. It must work air-gapped and can be a container.
- ULPF does that. Every line becomes an **OCSF 1.3** event. The original line is kept. Unmapped fields are kept. Each normalized field points back to the raw field it came from.

**Footer line:** PS 26156 · NTRO · Blockchain & Cybersecurity

### Slide 2 — How a log moves

**Title:** Collect, sniff, map, seal

**Flow to draw (left to right):**

1. **Collect** — syslog (UDP, TCP, or mutual TLS), HTTP, or file.
2. **Sniff** — JSON, XML, CEF, LEEF, key=value, CSV, syslog.
3. **Pack** — a YAML file per vendor. No code change to add a source.
4. **Envelope** — OCSF event + `raw_data` + `unmapped` + `field_lineage`.
5. **Seal** — SHA-256 leaf, Merkle batch, Ed25519 hash chain.
6. **Leave** — dashboard, Parquet, ClickHouse, Splunk, Elastic, or CEF.

**One sentence under the diagram:** If no pack matches, the line is still stored and clustered. A draft pack is proposed offline and does nothing until an admin signs it.

### Slide 3 — What a typical parser project will not show

**Title:** Three checks, all offline

Three columns:

| Offline parser generator | Schema Fidelity | Tamper-evident lineage |
|---|---|---|
| Unknown logs are clustered with Drain3 and mapped to OCSF with no cloud model. | 551 datasets, 539 rules, replayed through the normalized output. | Each batch is a Merkle tree. Roots are hash-chained and signed with Ed25519. |
| A local model may suggest fields. Every suggestion is checked against the OCSF schema. | **100%** of raw detection verdicts preserved. **0** detections lost. | Edit one stored byte and `/verify` fails. No public blockchain and no network. |
| The draft cannot route traffic until an admin approves and signs it. | Native OCSF paths alone lost **174** detections and added **20** false alerts. | Fits the Blockchain theme inside an air-gapped network. |

**Spoken contrast, if asked:** Most teams will demo “we parsed FortiGate into JSON.” We show that the normalized event still detects, and that the original bytes can be proved later.

### Slide 4 — Evidence

**Title:** Measured, not described

Put this table. Do not round the fidelity numbers.

| What we measured | Result |
|---|---|
| Schema fidelity (normalized verdict = raw verdict) | **100%** |
| Same score using only native OCSF paths | **91%** |
| Detections lost by our envelope | **0** |
| Detections lost by native paths only | **174** |
| False alerts introduced by our envelope | **0** |
| False alerts introduced by native paths only | **20** |
| True-positive rate / benign silence (full envelope) | **94.62% / 94.99%** |
| Datasets / rules / cases | **551 / 539 / 2,156** |
| Replay time | **4.7 s** |
| Single-process throughput on this laptop | **~1,000 events/sec** (8,000 FortiGate lines, validation on, sinks and ledger off) |

**Sources already in the repo:** `data/fidelity/FIDELITY.md`. The 1,000 eps figure is a local `ulpf bench --n 8000` run (8,000 events in 7.9 s). It is not a cluster benchmark. Do not say 20–50k.

**Shipped packs (15, all signed):** FortiGate, Palo Alto, Cisco ASA, pfSense, Check Point, Juniper SRX, generic CEF, generic LEEF, Suricata EVE, Zeek, Squid, nginx, OpenSSH, Windows event log, canonical alert.

### Slide 5 — Deployment, security, ask

**Title:** Air-gapped container, same contract at volume

**Deploy**

- `docker compose` image: non-root, read-only root filesystem, all capabilities dropped.
- No outbound network required. Optional Ollama stays on loopback.
- Air-gap path: `deploy/airgap/save-bundle.sh` on a connected machine, `load-bundle.sh` on the isolated one.

**Security (one line each)**

- Log text is treated as hostile: size caps, RE2 (no ReDoS), defused XML, safe YAML.
- API tokens are stored as SHA-256 only. Roles: ingest, viewer, analyst, admin.
- AI drafts never go live by themselves. Approval signs the pack with Ed25519.
- Ledger tables reject update and delete.

**Scale story (one line):** today the demo store is SQLite. The same event is what ClickHouse and Parquet receive. Workers on Redpanda are stateless, so more workers means more throughput.

**Close:** Parser work goes from a new codebase per vendor to one reviewed YAML file, and the SOC can prove which original bytes produced an alert.

---

## 3. Speaker notes (do not paste onto the slides)

**Slide 1.** NTRO’s pain is not “we need another SIEM.” It is the tax paid before the SIEM can see anything: a parser per vendor, fields dropped on the way, and no way to show an auditor the original line. Current scope in the problem statement is perimeter devices, so the demo leads with firewalls, IDS, and proxies, not laptops.

**Slide 2.** Walk one FortiGate line: `srcip` becomes `src_endpoint.ip`, `action=accept` becomes disposition Allowed, leftover vendor fields sit in `unmapped`, and `raw_data` is the original string. `field_lineage` is the traceability the problem statement asks for in item (d).

**Slide 3.** Spend the most time here. The three columns are the differentiator.

- Generator: Sophos XG and MikroTik are **not** in the shipped library. The demo pastes them, shows a self-test (parse rate, OCSF validity), and only then signs the pack. After approval, a new line from that source routes to the new pack instead of `fallback`.
- Fidelity: “100%” means every case where the rule engine fired on the raw event still fired on the ULPF event, and every silent benign case stayed silent. It does **not** mean the third-party rules are perfect. Agreement with their `expected.json` is **94.81%**. Say that if a judge asks. The 174 lost detections are what you get if you throw away `unmapped` and lineage and keep only native OCSF fields.
- Lineage: this is the Blockchain theme without a coin, a network, or an outside chain. An air-gapped SOC can still anchor the signed roots onto write-once media.

**Slide 4.** Read the 100% vs 174 aloud. Mention the throughput number only if asked, and say it is one process on a laptop.

**Slide 5.** If the video is playing nearby, do not repeat it. Point at the container and the air gap. End on the YAML-not-code line.

**Timebox:** about 45–60 seconds per slide if this deck is the whole talk. The recorded demo is a separate 2-minute video (`docs/DEMO.md`). Do not try to live-demo all five slides and the full UI in the same two minutes.

---

## 4. Numbers you must not misquote

| Claim | Safe wording | Do not say |
|---|---|---|
| Fidelity | 100% of raw verdicts preserved on 2,156 cases | “100% accurate detections” |
| Expected-file agreement | 94.81% vs `expected.json` (oracle). 539/539 rules had every case preserved by the envelope | “94% fidelity” |
| Native-only loss | 174 detections lost, 20 false alerts added | “OCSF is bad” — the point is that dropping unmatched fields is what loses them |
| Throughput | ~1,000 events/sec, one process, FortiGate, validation on, sinks and ledger off | “20,000–50,000 eps” or “billions per day on a laptop” |
| Packs | 15 signed built-in packs, plus any admin-approved draft | “we support every vendor” |
| Rules corpus | 551 replay datasets, 539 rules evaluated, 453 had an OCSF twin | “696 rules all ran in the fidelity score” — the custom-rules repo is larger; the fidelity run is the dataset replay |
| Generator | Offline. Local LLM is optional and allow-listed to loopback / the `ollama` service | “ChatGPT writes the parser” |
| Ledger | Ed25519-signed hash chain and Merkle proofs. SQLite triggers make the tables append-only | “we put logs on Ethereum / a public blockchain” |

---

## 5. Map to the problem statement (jury backup)

Use this if a judge reads the PS line by line. Not a slide.

| PS ask | Where ULPF does it |
|---|---|
| (a) Preserve raw event, no information loss | `raw_data` + `raw_sha256` |
| (b) Extract source-specific attributes | YAML pack extractors: JSON, XML, CSV, key=value, Grok, CEF, LEEF, syslog 3164/5424 |
| (c) Normalize to a common taxonomy | OCSF 1.3, schema vendored for offline use |
| (d) Trace normalized field back to original | `ulpf.field_lineage` |
| (e) Plug-and-play new sources | One YAML pack. Generator drafts it. Admin signs it |
| (f) Unified visibility | Dashboard: every source in one OCSF table |
| (g) SIEM and data lake | Sinks: Splunk HEC, Elasticsearch, CEF, ClickHouse, Parquet/MinIO |
| (h) AI/ML-ready analytics | One schema, stable field names, raw text retained for features |
| (i) Less parser development | Days of parser code become a reviewed YAML file |
| (j) Air-gapped | No required outbound calls. Images and wheels can be loaded offline |
| (k) Container, platform independent | `deploy/Dockerfile`, Compose, non-root, read-only |

**Scope line from the PS:** “any perimeter network device-generated log.” The demo sources are firewalls, IDS, proxy, VPN-style CEF/LEEF, and SSH on the edge. Endpoint datasets are used only as the fidelity harness, because that is where the paired true-positive / benign labels exist.

---

## 6. What to show if they ask for the UI

Order matches `docs/DEMO.md`:

1. **Live** — Load sample logs. FortiGate, Palo Alto, and Suricata in one table.
2. **Event** — raw line on the left, OCSF JSON on the right, lineage table underneath.
3. **Onboard** — paste `samples/unknown/sophos_xg.log`, vendor Sophos, product XG Firewall. Self-test passes. Approve and sign. Ingest one more line. Pack column changes from `fallback` to `sophos.xg_firewall`.
4. **Fidelity** — 100% vs 91%, 0 lost vs 174.
5. **Lineage** — Verify (all true). With `ULPF_DEMO=true`, tamper the stored raw text and verify again (fails). Do not show the API token on camera.

---

## 7. Stack (one small slide only if you are allowed a sixth; otherwise say it verbally)

Python 3.12, FastAPI, OCSF 1.3, YAML source packs, Drain3, optional Ollama, pySigma, SQLite ledger, Redpanda (Kafka-compatible), ClickHouse, MinIO/Parquet. Ed25519 via the `cryptography` library. XML via `defusedxml`. Pack regexes via RE2.

Inspiration, not a dependency at runtime:

- [detection-engineering-custom-rules-](https://github.com/damnkrishna/detection-engineering-custom-rules-) — Sigma rules and their OCSF twins, used as the field vocabulary.
- [Detection-Engineering-Ruleset](https://github.com/damnkrishna/Detection-Engineering-Ruleset) — 551 replay datasets with expected alerts. This is the fidelity harness.

---

## 8. Jury questions and short answers

**Why OCSF, not ECS or a custom JSON schema?**  
OCSF is vendor-neutral and already has classes for network activity, DNS, HTTP, authentication, and detection findings. We vendor the schema so the air-gapped box does not fetch it.

**Why not just use Vector / Logstash / Fluent Bit?**  
Those move and parse logs. They do not prove that the parsed event still fires the detection, and they do not give a signed path from a normalized record back to the original bytes. A pack can later be compiled to Vector VRL without changing the YAML.

**Is the 100% fake?**  
No. It is “did normalization change the verdict?” on 2,156 labeled cases. The third-party expected files themselves agree with our raw-event engine 94.81% of the time. We report both.

**Where is the blockchain?**  
There is no token and no peer network. Each batch has a Merkle root. Roots are hash-chained and signed. That is the property NTRO can use on an isolated network. Anchors can be copied to write-once media.

**Can the AI be tricked by a malicious log?**  
The model only suggests field names and OCSF paths. Those are checked against the schema and against fields that were actually extracted. The draft is unsigned and inactive until an admin approves it. Logs are not sent off-box. The allowed LLM hosts are loopback and the in-cluster `ollama` name.

**How do you onboard a vendor you have never seen?**  
Three or more sample lines. Drain3 clusters them. The mapper votes on OCSF paths. Self-test must parse at least 95%, be at least 90% OCSF-valid, and map at least 3 attributes on average. Then a human signs.

**What did you leave out on purpose?**  
The demo database is SQLite, not a multi-node cluster. Hot packs are still interpreted YAML, not native code. The public internet is the wrong place for this service; it belongs on a server or an air-gapped VM, not a static host like Netlify.

**Security?**  
Hostile-input limits, RE2, defused XML, safe YAML, hashed tokens, role split, signed packs, append-only ledger, container hardening (`cap_drop: ALL`, read-only root, uid 10001). Plain syslog is unauthenticated; untrusted segments should use TLS with client certificates.

---

## 9. Visuals worth making

- Slide 2: one horizontal pipeline. Six boxes. No extra clouds.
- Slide 3: three equal columns. The only numbers on this slide are **100%**, **0**, and **174**.
- Slide 4: the comparison table in section 2. Highlight the two fidelity cells.
- Optional screenshot, one only: raw FortiGate line beside the OCSF event, lineage visible. Crop out the token field.
- Do not use a stock “AI brain” or a Bitcoin graphic. The lineage picture is a chain of batch roots, labeled “signed locally.”

---

## 10. Submission checklist next to the deck

| Deliverable | Status in this repo |
|---|---|
| Source code | this repository |
| README with setup | `README.md` |
| Architecture, max 2 pages | `docs/ARCHITECTURE.md` |
| Demo video, max 2 minutes | not recorded yet. Script: `docs/DEMO.md` |
| Technical presentation, max 5 slides | content is this file and `docs/slides.html`. Export to PPT/PDF yourselves |
| Hosting | a VM or the Compose stack. Not Netlify. The API is a long-running process with a SQLite ledger and optional syslog ports |
