# Universal Log Pre-processing Framework (ULPF)

SIH 2026 problem statement **26156** (NTRO). ULPF ingests perimeter-device logs in vendor formats and emits one lossless [OCSF 1.3](https://schema.ocsf.io/) event per line, with a hash-chained proof back to the original bytes.

Three things this prototype does that a typical parser pipeline does not:

1. **Offline parser generator.** An unknown format is clustered with Drain3, mapped to OCSF without a cloud model, and optionally checked by a local Ollama model. The draft cannot route traffic until an admin approves and signs it.
2. **Detection-validated normalization.** The bundled Schema Fidelity report replays the Detection-Engineering-Ruleset datasets. On the last run, full ULPF output preserved every detection the raw logs produced (**100%** schema fidelity, **0** detections lost). Native OCSF paths alone lost **174**.
3. **Tamper-evident lineage.** Each batch is a Merkle tree over `sha256(raw) || sha256(normalized)`, and the roots are hash-chained and signed with Ed25519. Editing a stored raw log fails verification.

## Quick start

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python -m ulpf.cli serve
```

The first start writes `data/tokens.json` (hashes only) and prints an admin token once on stderr. Open http://127.0.0.1:8080 and paste that token.

Useful commands:

```bash
.venv/bin/python -m ulpf.cli ingest samples/perimeter/fortigate.log
.venv/bin/python -m ulpf.cli bench --n 20000
.venv/bin/python -m ulpf.cli fidelity          # needs third_party datasets
.venv/bin/python -m pytest
```

Syslog listens only when you pass `--syslog` (UDP/TCP 5514, TLS 6514 if you also pass a certificate). Plain syslog is unauthenticated; use TLS with a client certificate for untrusted networks.

## Roles

`deploy/make-secrets.sh` creates four tokens. The API uses the same file format.

| Role | Can do |
|---|---|
| `ingest` | `POST /v1/ingest` only |
| `viewer` | Read events, fidelity, lineage, metrics |
| `analyst` | Viewer, plus draft a parser and edit it |
| `admin` | Analyst, plus approve (Ed25519-sign) a pack, reload packs, export anchors |

Send `Authorization: Bearer <token>`. `/health` is the only route without a token.

Set `ULPF_DEMO=true` before `serve` to enable `POST /v1/demo/tamper`, which rewrites one stored raw log so you can show verification failing. The ledger itself stays append-only.

## Docker

```bash
./deploy/make-secrets.sh
docker compose -f deploy/docker-compose.yml up --build ulpf
```

The image runs as uid 10001, read-only, with no extra capabilities. The API is published on `127.0.0.1:8080`. Syslog is on `5514` (UDP and TCP) and `6514` (TLS, client certificates required).

The full profile adds Redpanda, ClickHouse, MinIO, and Ollama:

```bash
docker compose -f deploy/docker-compose.yml --profile full up -d
```

`ulpf-worker` consumes `ulpf.raw` and writes `ulpf.normalized`. Built-in source packs are signed; `ULPF_REQUIRE_SIGNED_PACKS=true` in Compose refuses a pack whose signature does not match `ulpf/packs/trusted/builtin.pub` or a runtime signer.

## Air-gapped install

On a connected machine:

```bash
./deploy/airgap/save-bundle.sh
```

Copy `deploy/airgap/bundle/` and `deploy/airgap/wheels/` to the isolated network, then:

```bash
./deploy/airgap/load-bundle.sh
```

No call leaves the host at runtime. The optional LLM is Ollama on loopback (or the Compose service name `ollama`). Any other host is rejected unless you add it to `ULPF_OLLAMA_ALLOWED_HOSTS`.

## Add a log source

Drop a YAML file in `ulpf/packs/library/` (or generate one from the Onboard page). A pack declares how to match the line, how to parse it, and which raw fields become which OCSF paths. No Python change is required. See `ulpf/packs/library/fortinet/fortigate.yaml`.

Shipped packs: FortiGate, Palo Alto, Cisco ASA, pfSense, Check Point, Juniper SRX, Squid, nginx, OpenSSH, generic CEF, generic LEEF, Suricata EVE, Zeek, Windows event log, and a canonical alert pack.

Everything parsed and not mapped is kept under `unmapped`. `raw_data` is the original line. `ulpf.field_lineage` records which raw field produced each normalized field.

## Layout

```
ulpf/collector     syslog UDP/TCP/TLS, file tail
ulpf/extractors    json, xml, csv, kv, cef, leef, grok, syslog
ulpf/packs         YAML pack engine and the signed library
ulpf/normalizer    OCSF 1.3 envelope
ulpf/lineage       Merkle ledger
ulpf/aigen         Drain3 miner, offline mapper, optional local LLM
ulpf/validator     Schema Fidelity replay
ulpf/sinks         SQLite, JSONL, Parquet, ClickHouse, Splunk HEC, Elastic, CEF
ui/                dashboard
docs/              architecture note, 5 slides, 2-minute demo script
```

`third_party/` is gitignored. Clone these next to the paths the fidelity command expects:

- https://github.com/damnkrishna/Detection-Engineering-Ruleset
- https://github.com/damnkrishna/detection-engineering-custom-rules-
- https://github.com/ocsf/ocsf-schema (vendored copy already used to build `ulpf/normalizer/ocsf_schema.json`)

## Tests

```bash
.venv/bin/python -m pytest
```

Covers syslog framing, signed-pack loading, ingest authorization, lineage failure after a tampered raw log, and parser synthesis for an unseen Sophos XG sample.
