# Configuration

All settings are read from environment variables prefixed `ULPF_`. Defined in `ulpf/config.py` as the `Settings` dataclass. A module-level `settings = Settings()` is constructed at import; the CLI and tests usually construct a fresh `Settings()` after setting env vars.

## `.env` file

At import, `ulpf/config.py` calls `load_dotenv()`, which reads `<repo>/.env` if it exists. Only `ULPF_*` names are applied, and only when the variable is not already set, so shell exports, Docker, and Compose still win. Lines may use `export `, `#` comments, and quoted values. Start from the committed sample: `copy .env.example .env` (PowerShell) or `cp .env.example .env`. `.env` is gitignored.

`Settings.ensure_dirs()` creates `data_dir`, `drafts_dir`, `approved_dir`, `keys_dir`, then `chmod 0700` on `keys_dir` (silently skipped if that fails — typical on Windows).

## Variables

| Variable | Default | Meaning |
|---|---|---|
| `ULPF_DATA_DIR` | `<repo>/data` | Databases, lake, audit log |
| `ULPF_PACKS_DIR` | `<repo>/ulpf/packs/library` | Built-in packs |
| `ULPF_DRAFTS_DIR` | `<repo>/data/drafts` | AI drafts (never routed) |
| `ULPF_APPROVED_PACKS_DIR` | `<repo>/data/packs` | Approved packs (routed). **Not set in the Dockerfile**; inside an installed package `ROOT` is site-packages, which is read-only — first start can crash. Set this to `/var/lib/ulpf/packs` in Compose if you run the image |
| `ULPF_KEYS_DIR` | `<repo>/data/keys` | Ed25519 keys and `pack_signers/` |
| `ULPF_MAX_LINE_BYTES` | 65536 | Per-event and syslog frame limit |
| `ULPF_MAX_JSON_DEPTH` | 32 | JSON nesting |
| `ULPF_MAX_FIELDS` | 1024 | Extracted field cap (JSON and XML). Extractors read the **global** `settings`, not the Pipeline instance |
| `ULPF_MAX_HTTP_BATCH` | 5000 | Lines per `/v1/ingest` |
| `ULPF_RATE_LIMIT_EPS` | 50000 | Token bucket per syslog peer and per API token name |
| `ULPF_BATCH_SIZE` | 256 | Ledger batch size and syslog batcher `max_batch` |
| `ULPF_REQUIRE_SIGNED_PACKS` | `false` | Reject unsigned / mismatched packs. Compose sets `true` |
| `ULPF_BUS` | `memory` | Documented `memory` \| `kafka`. **Never read.** Kafka ingest is not wired |
| `ULPF_KAFKA_BOOTSTRAP` | `localhost:9092` | Brokers for `ulpf worker` |
| `ULPF_SINKS` | `sqlite` | Comma-separated: `sqlite`, `jsonl`, `parquet`, `clickhouse`, `splunk`, `elastic`, `cef`. Dashboard needs `sqlite` |
| `ULPF_CLICKHOUSE_URL` | `http://localhost:8123` | ClickHouse HTTP |
| `ULPF_S3_ENDPOINT` | empty | When set, Parquet goes to S3/MinIO |
| `ULPF_S3_BUCKET` | `ulpf-lake` | Lake bucket |
| `ULPF_SPLUNK_HEC_URL` | empty | Splunk HEC |
| `ULPF_ELASTIC_URL` | empty | Elasticsearch / OpenSearch |
| `ULPF_CEF_FORWARD` | empty | `host:port` UDP CEF forward |
| `ULPF_TLS_VERIFY` | `true` | TLS checks for Splunk and Elastic. **Not** passed to ClickHouse |
| `ULPF_OLLAMA_URL` | `http://localhost:11434` | Local LLM. Compose does not override this, so the `ollama` service is unused |
| `ULPF_OLLAMA_MODEL` | `qwen2.5-coder:7b` | Model name |
| `ULPF_OLLAMA_ALLOWED_HOSTS` | `localhost,127.0.0.1,::1,ollama` | Hostname allow-list (hostname only, not scheme/port). Also applies to the LM Studio URL |
| `ULPF_LMSTUDIO_API_KEY` | empty | When non-empty, the parser generator uses LM Studio instead of Ollama. Also read from `ULPF_LMSTUDIO_API_KEY_FILE` |
| `ULPF_LMSTUDIO_URL` | `http://127.0.0.1:1234/v1` | LM Studio OpenAI-compatible base URL |
| `ULPF_LMSTUDIO_MODEL` | empty | LM Studio model id. Required when the key is set |
| `ULPF_LMSTUDIO_REASONING_EFFORT` | `none` | Sent as `reasoning_effort`. `none` stops thinking models from spending the token budget on hidden reasoning. Empty omits the field |
| `ULPF_TOKENS_FILE` | `<repo>/data/tokens.json` | API tokens. Compose: `/run/secrets/ulpf_tokens` |
| `ULPF_CORS_ORIGINS` | empty | Parsed into a list. **No CORS middleware uses it** |
| `ULPF_UI_DIR` | `<repo>/ui` | Dashboard files. Docker: `/opt/ulpf/ui` |
| `ULPF_SAMPLES_DIR` | `<repo>/samples` | Load-samples root. Docker: `/opt/ulpf/samples` |
| `ULPF_MAX_BODY_BYTES` | 8000000 | HTTP body cap |
| `ULPF_DEMO` | `false` | Must be the string `true` (not `1`) to enable `POST /v1/demo/tamper` |
| `ULPF_HSTS` | `false` | Add HSTS header |

Boolean flags compare `.lower() == "true"` except `TLS_VERIFY`, which is true unless the value is `false`.

## File-based secrets

`secret_from_file(name)` reads `ULPF_<NAME>_FILE` (contents of that path) then `ULPF_<NAME>`. Used for:

| Name | Typical file |
|---|---|
| `CLICKHOUSE_PASSWORD` | Compose secret |
| `SPLUNK_HEC_TOKEN` | |
| `ELASTIC_API_KEY` | |
| `S3_ACCESS_KEY` | MinIO root user in Compose |
| `S3_SECRET_KEY` | MinIO root password in Compose |
| `LMSTUDIO_API_KEY` | |

API tokens are **not** in this helper; they use `ULPF_TOKENS_FILE` as a JSON document of hashes.

## Docker env actually set

**Dockerfile:** `ULPF_DATA_DIR`, `ULPF_KEYS_DIR`, `ULPF_DRAFTS_DIR`, `ULPF_UI_DIR`, `ULPF_SAMPLES_DIR`. Missing: `ULPF_APPROVED_PACKS_DIR`, `ULPF_TOKENS_FILE` (plain `docker run` therefore tries to write tokens into site-packages).

**Compose `ulpf`:** `ULPF_TOKENS_FILE`, `ULPF_REQUIRE_SIGNED_PACKS=true`, `ULPF_SINKS=sqlite,parquet`.

**Compose `ulpf-worker` (profile `full`):** also `ULPF_BUS=kafka` (ignored), `ULPF_KAFKA_BOOTSTRAP`, `ULPF_SINKS=clickhouse,parquet`, ClickHouse URL/password file, S3 endpoint and key files.
