# API, CLI, and dashboard

The process is `ulpf serve`. Default bind `127.0.0.1:8080`. FastAPI is wrapped in `SecurityHeaders(BodyLimit(app))` (`ulpf/api.py`). OpenAPI `/docs`, `/redoc`, `/openapi.json` stay enabled and unauthenticated.

Auth: `Authorization: Bearer <token>` or `X-API-Token`. `/health` is the only JSON route without a token. Errors are `{"error": "..."}`. Validation failures return generic 422 `"invalid request"`. Unhandled exceptions return 500 `"internal error"`.

## Roles (`ulpf/auth.py`)

Hierarchy: `viewer`(1) < `analyst`(2) < `admin`(3). `ingest` is a side role: it may call `POST /v1/ingest` only. Analyst and admin may ingest too.

Token file (`ULPF_TOKENS_FILE`, default `data/tokens.json`):

```json
{"tokens": [{"name": "admin", "role": "admin", "sha256": "<64 hex>"}]}
```

Only SHA-256 hashes are stored. Compare is `hmac.compare_digest` against every entry (last match wins). Tokens over 512 characters are rejected. First-run: if the file is missing, a `token_urlsafe(24)` admin token is written (mode 0600) and printed once on stderr:

```
First-run admin token (shown once, store it now): …
```

`deploy/make-secrets.sh` creates four tokens: admin, analyst, viewer, ingest.

## HTTP security middleware

- **BodyLimit**: 413 if `Content-Length` or streamed bytes exceed `ULPF_MAX_BODY_BYTES` (default 8,000,000).
- **SecurityHeaders** on every response:
  - `X-Content-Type-Options: nosniff`
  - `Referrer-Policy: no-referrer`
  - `X-Frame-Options: DENY`
  - CSP `default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'`
  - `Permissions-Policy` camera/microphone/geolocation off
  - COOP and CORP `same-origin`
  - `Cache-Control: no-store`
  - HSTS only when `ULPF_HSTS=true`
- CORS: `ULPF_CORS_ORIGINS` is **read and unused** (no CORS middleware).

Lifespan: if `runtime.syslog` is set, starts `AsyncBatcher` + `SyslogServer` (UDP, TCP, TLS if a cert is given). Shutdown cancels the batcher without flushing.

## Routes

| Method | Path | Role | Body / query | Response / side effects |
|---|---|---|---|---|
| GET | `/health` | none | | `{status, version}` |
| GET | `/metrics` | viewer | | Prometheus text: processed, dead_letter, fallback, p50/p99 latency |
| GET | `/v1/whoami` | viewer | | `{name, role, demo}` |
| POST | `/v1/ingest` | ingest | JSON `{lines, source_hint?}` or newline text | `{accepted, dead_letter, uids[≤50]}`. 413 if > `MAX_HTTP_BATCH`. 429 rate limit. 400 `InputRejected`. Audits `ingest` |
| GET | `/v1/events` | viewer | `limit, offset, pack, src_ip, dst_ip, class_uid, severity_min, valid, fallback` | `{events, count}`. 503 without SQLite sink. `fallback` filter is truthy-only (cannot ask for non-fallback) |
| GET | `/v1/events/{uid}` | viewer | | stored event or 404 |
| GET | `/v1/events/{uid}/verify` | viewer | | ledger proof (six checks) |
| GET | `/v1/stats` | viewer | | pipeline, store, ledger, unknown_clusters, packs |
| GET | `/v1/dead-letters` | viewer | | last 100 |
| GET | `/v1/ledger` | viewer | | ledger stats |
| GET | `/v1/ledger/verify` | viewer | | chain verification |
| POST | `/v1/ledger/anchors` | admin | | writes `data/anchors.jsonl` |
| GET | `/v1/packs` | viewer | | pack list; `rejected` only for admin |
| POST | `/v1/packs/reload` | admin | | `{loaded, rejected}` |
| POST | `/v1/preview` | analyst | `IngestBody`, ≤ 20 lines | normalize, do not store |
| GET | `/v1/unknown` | analyst | | clusters |
| DELETE | `/v1/unknown/{fp}` | analyst | | drop cluster (no 404 if missing) |
| POST | `/v1/unknown/{fp}/synthesize` | analyst | query `vendor, product` | draft + self-test; needs ≥ 3 samples |
| POST | `/v1/drafts/synthesize` | analyst | `{lines (3–500), vendor?, product?}` | same |
| GET | `/v1/drafts` | analyst | | list |
| GET | `/v1/drafts/{pack_id}` | analyst | | draft or 404 |
| PUT | `/v1/drafts/{pack_id}` | analyst | `{yaml}` ≤ 1 MB | rewrite, re-selftest on `tests[].input` |
| POST | `/v1/drafts/{pack_id}/approve` | admin | | sign, move, reload packs |
| POST | `/v1/drafts/{pack_id}/reject` | analyst | | delete draft |
| GET | `/v1/fidelity` | viewer | | report without `rows`; `source: "run"` or `"bundled"` |
| GET | `/v1/audit` | admin | `limit` (cap 500) | `{records, chain}` |
| POST | `/v1/demo/tamper` | admin | `{uid, raw}` | 404 unless `ULPF_DEMO=true`. Rewrites stored raw |
| POST | `/v1/demo/load-samples` | admin | | up to 30 lines/file, 400 total, from `samples_dir` (path-traversal guarded). **Does not** check demo mode |
| GET | `/` | none | | `ui/index.html` |
| GET | `/assets/*` | none | | files from `ui/` |

## CLI (`ulpf/cli.py`)

```
ulpf --version
ulpf serve [--host 127.0.0.1] [--port 8080] [--syslog]
           [--syslog-host 0.0.0.0] [--syslog-udp 5514] [--syslog-tcp 5514]
           [--syslog-tls-port 6514] [--syslog-tls-cert] [--syslog-tls-key] [--syslog-tls-ca]
ulpf worker
ulpf ingest FILE [--source PACK_ID]
ulpf fidelity [--datasets third_party/Detection-Engineering-Ruleset]
              [--rules third_party/custom-rules] [--out data/fidelity] [--limit N]
ulpf bench [--n 20000] [--sample samples/perimeter/fortigate.log]
```

- `serve` runs uvicorn with `server_header=False`, `proxy_headers=False`. Syslog TLS requires cert and key files; a CA enables mTLS (`CERT_REQUIRED`).
- `worker` consumes Kafka `ulpf.raw` → `ulpf.normalized` (key `class_uid`), DLQ `ulpf.deadletter`, commit after flush. No flags. **Nothing publishes to `ulpf.raw` today.**
- `ingest --source` is documented as a pack pin; routing compares it to `match.sources`, which no library pack sets, so it is a no-op.
- `bench` repeats the first non-empty sample line n times with ledger and sinks disabled, prints `events= valid= seconds= eps=`.

## Dashboard (`ui/`)

Vanilla HTML/JS/CSS. No `innerHTML` (CSP). Token in `sessionStorage` key `ulpf_token`. Connect calls `GET /v1/whoami`.

| Tab | Shows | Calls |
|---|---|---|
| Live | Six tiles (Stored, OCSF valid %, Avg EPS, Fallback, Packs, Unknown clusters), paste box, last 40 events | `GET /v1/stats`, `GET /v1/events?limit=40`, `POST /v1/ingest`, `POST /v1/demo/load-samples` |
| Event | uid/pack/confidence, raw vs OCSF, lineage table | `GET /v1/events/{uid}` |
| Packs | ref, vendor, product, formats, signed, trust | `GET /v1/packs` |
| Onboard | unknown clusters, generate, YAML editor, Save / Approve / Reject | `GET /v1/unknown`, synthesize routes, `PUT/POST` drafts |
| Fidelity | tiles for the bundled or last-run report | `GET /v1/fidelity` |
| Lineage | verify-by-uid, optional tamper, chain stats | `GET .../verify`, `POST /v1/demo/tamper`, `GET /v1/ledger`, `GET /v1/ledger/verify` |

UI gating: Load samples = admin. Paste box hidden for viewers. Tamper form = demo + admin. Approve = admin. **Reject is not role-gated in JS.** Viewers still see the Onboard tab and get 403 on `/v1/unknown`. Ingest-only tokens cannot log in (`whoami` needs viewer).

Routes with no UI: `/v1/preview`, draft list/get, `DELETE /v1/unknown/{fp}`, `/v1/packs/reload`, `/v1/ledger/anchors`, `/v1/audit`, `/v1/dead-letters`, `/metrics`.
