# Security

Log pipelines are a target because every line is attacker-controlled. This page is the threat model, mapped onto what the code actually does. Planned controls that are not built yet are listed at the end.

## Trust boundary

Log text, pack YAML (including AI drafts), and HTTP bodies are untrusted. The signing keys and the token file are trusted. The optional LLM is allowed only on loopback / the Compose service name `ollama`, and its JSON is schema-checked like any other pack.

## Controls that are in the code

### Hostile input

| Risk | Control | Where |
|---|---|---|
| Oversized line | `MAX_LINE_BYTES` (64 KiB default); syslog frame cap | `security.check_line`, `collector/syslog.py` |
| Oversized HTTP | body cap 8 MB; batch 5000 lines; preview 20; synthesize 500 | `api.py` BodyLimit, ingest, preview, drafts |
| JSON bombs | depth 32; field count 1024 | `security.safe_json_loads`, `extractors/json_.py` |
| XML XXE / billion laughs | `defusedxml` `forbid_dtd=True` | `extractors/xml_.py` |
| ReDoS | `google-re2`, `max_mem` 8 MiB; pack regex `maxLength` 1000 | `security.safe_regex`, pack schema. **Silent fallback to `re` if RE2 is missing** |
| YAML code exec | `yaml.safe_load`, 1 MB cap; pack `additionalProperties: false` | `security.safe_yaml_load`, `packs/schema.py` |
| Flood | token bucket per syslog peer and per API token; batcher queue 100k then drop | `TokenBucket`, `AsyncBatcher` |
| TCP resource | max 512 connections, 300 s idle | `SyslogServer` |

Rejected lines become dead letters (`pipeline.dead_letters`, maxlen 1000) instead of crashing the worker.

### Packs and AI

- Packs are data. No eval, no Python, no shell.
- `ULPF_REQUIRE_SIGNED_PACKS` (Compose `true`) refuses unsigned or mismatched `.sig` files. Signatures are Ed25519 over exact YAML bytes. Trusted keys: `ulpf/packs/trusted/*.pub` plus runtime `pack_signers/`.
- AI output must pass the same JSON Schema, is self-tested, and is inactive until an admin signs it.
- The model has no tools. Samples go only to an allow-listed host. Prompt labels samples as untrusted.

### API and dashboard

- Tokens stored as unsalted SHA-256; constant-time compare.
- Roles: ingest / viewer / analyst / admin (see [API_AND_CLI.md](API_AND_CLI.md)).
- CSP forbids inline script. `app.js` never uses `innerHTML`. Log content is `textContent`.
- SQLite queries are parameterized; event filters are allow-listed (`sqlite_store.py`).
- ClickHouse / HEC / Elastic sinks use their client libraries, not string-built SQL from log fields.
- `/health` is public; everything else needs a bearer token (including `/metrics`).
- Failed auth is audited (`auth_failure` / `auth_denied`).

### Lineage

- Leaf = `SHA256(0x00 || raw_sha256 || norm_sha256)`; interiors `0x01`. Chain hash signed with Ed25519. Key outside the DB.
- Triggers abort UPDATE/DELETE on ledger tables.
- Demo tamper rewrites the **event store** only, and only when `ULPF_DEMO=true`.
- Audit log is its own hash chain.

Honest limitation: an insider with DB **and** signing key can rebuild the chain. Production would keep the key in an HSM and export anchors to WORM (`POST /v1/ledger/anchors`).

### Transport

- Syslog TLS 1.2 minimum; CA present → `CERT_REQUIRED` (mTLS).
- Plain UDP/TCP syslog is unauthenticated by design. Use TLS plus client certs on untrusted segments.
- uvicorn `proxy_headers=False`, `server_header=False`.

### Container (intended)

- Non-root uid 10001, read-only root, `cap_drop: ALL`, `no-new-privileges`, tmpfs `/tmp`.
- Secrets via Compose files, not baked into the image.
- Air-gap scripts checksum/save images; runtime needs no outbound network.
- Base image is **not** pinned by digest (Dockerfile comments that you should).

See [KNOWN_ISSUES.md](KNOWN_ISSUES.md) for why a first `docker compose up` can still fail (approved-packs path, secret file mode vs uid 10001).

## Planned, not built

These are on the security roadmap and are not implemented:

| Item | Status |
|---|---|
| Fuzz tests (`hypothesis` / Atheris) on extractors | `hypothesis` is a dev dependency; no tests use it |
| Bandit / Semgrep / pip-audit / gitleaks / Trivy / ZAP report in the repo | tools listed; no report checked in; bandit and pip-audit unpinned |
| Pack YAML as a "signed only" default outside Compose | local default is `REQUIRE_SIGNED_PACKS=false` |
| JWT | API keys (hashed) only |
| At-rest encryption for MinIO / ClickHouse / SQLite | not configured |
| DPDP masking / tokenization of PII in normalized output | not implemented; raw is always kept |
| Rate-limiter eviction (UDP spoof can grow `TokenBucket._state` without bound) | not implemented |
| SBOM (Syft) shipped with the air-gap bundle | not generated |
| Pin base image by digest | comment only |
| Default passwords | Compose uses `make-secrets.sh`; no hardcoded app passwords. ClickHouse URL embeds `ulpf:` with empty password and relies on `_FILE` |

## Operating reminders

- Treat API tokens like passwords; they are printed once and only hashes are stored.
- `ULPF_DEMO=true` (literal) enables the tamper route. `1` leaves it off. Never enable it on a store that holds real logs.
- `/docs` is unauthenticated — turn it off or keep the bind on loopback for anything facing a network.
- Never commit `data/` or `deploy/secrets/`; they hold signing keys and token hashes.
