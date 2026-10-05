# Development and deployment

First-time setup (virtual environment, dependencies, first start, admin token) is the numbered guide in the root [`README.md`](../README.md#setup-step-by-step). This page covers what comes after that.

All commands below assume you are in the repository root with the virtual environment activated, so `python` is the venv interpreter.

## Python

- Declared: `requires-python = ">=3.11"` (`pyproject.toml`).
- Docker image: 3.12-slim-bookworm. Python 3.12 is the recommended local version.
- `pyproject.toml` has **no** `dependencies` list. `pip install .` does not install runtime packages. Always install `requirements.txt` (or `requirements-dev.txt`, which includes it).

## Everyday commands

```
python -m ulpf.cli serve                         # API + dashboard on 127.0.0.1:8080
python -m ulpf.cli serve --syslog                # plus syslog UDP/TCP 5514; TLS 6514 if certs given
python -m ulpf.cli ingest samples/perimeter/fortigate.log
python -m ulpf.cli bench --n 8000
python -m ulpf.cli fidelity                      # needs third_party datasets
python -m pytest
```

To keep experiments away from your normal `data/`, point the runtime directories somewhere else before starting:

```powershell
# Windows (PowerShell)
$env:ULPF_DATA_DIR = "$env:TEMP\ulpf-dev"
$env:ULPF_KEYS_DIR = "$env:TEMP\ulpf-dev\keys"
$env:ULPF_TOKENS_FILE = "$env:TEMP\ulpf-dev\tokens.json"
python -m ulpf.cli serve
```

```bash
# Linux / macOS
export ULPF_DATA_DIR=/tmp/ulpf-dev ULPF_KEYS_DIR=/tmp/ulpf-dev/keys ULPF_TOKENS_FILE=/tmp/ulpf-dev/tokens.json
python -m ulpf.cli serve
```

A new token file means a new first-run admin token is printed.

Demo tamper route: set `ULPF_DEMO` to the string `true` (not `1`).

## Tests

```
python -m pytest
```

Ten test functions in `tests/`. `bench` numbers depend on the machine and are single-process with ledger and sinks off.

| Test | What it checks |
|---|---|
| `test_synth_sophos_passes_without_llm` | Sophos unknown sample drafts a pack, parse_rate 1.0, maps src/dst IP |
| `test_unknown_fingerprint_is_stable` | `fingerprint()` is deterministic |
| `test_health_is_public_and_locked_down` | `/health` 200 + security headers; `/v1/events` 401; `/` contains "Live events" |
| `test_roles_ingest_and_verify` | viewer cannot ingest; ingest role cannot read; FortiGate pack; raw preserved; verify true; `/metrics` 200 |
| `test_demo_tamper_breaks_proof_and_is_hidden_otherwise` | tamper 404 unless demo; after tamper, verify and `raw_bytes_match` false |
| `test_body_limit` | 413 when body > `max_body_bytes` |
| `test_load_samples` | load-samples returns > 10 lines and events query back |
| `test_syslog_udp_tcp_octet_counting` | UDP FortiGate, oversized UDP rejected, TCP ASA LF, TCP FortiGate octet-count → 3 events, `rejected == 1` |
| `test_chain_and_builtin_signatures` | signed packs, event proof, ledger chain, audit chain |
| `test_registry_still_constructs` | FortiGate pack compiles |

`conftest.py` isolates `data_dir`, `keys_dir`, `drafts_dir`, `approved_dir`, `tokens_file` under `tmp_path`, so tests never touch your `data/`.

Dev extras (`requirements-dev.txt`): pytest 9.1.1, hypothesis 6.168.3, bandit (unpinned), pip-audit (unpinned). Hypothesis is installed; there are no fuzz tests yet. Bandit's `exclude_dirs` in `pyproject.toml` covers `.venv`; if you name your venv differently, exclude it too.

## Rebuild the vendored OCSF schema

```
git clone https://github.com/ocsf/ocsf-schema third_party/ocsf-schema
python tools/build_ocsf_schema.py third_party/ocsf-schema ulpf/normalizer/ocsf_schema.json
```

Output is 71 classes / 124 objects, version 1.3.0. Extension class uids are `ext_uid*100000 + cat_uid*1000 + uid`. Profile attributes are forced optional.

## Docker

Secrets first (bash on Linux, macOS, WSL, or Git Bash; uses `/dev/urandom`, openssl, python3):

```bash
./deploy/make-secrets.sh
docker compose -f deploy/docker-compose.yml up --build ulpf
```

Image `ulpf:0.1.0`: uid 10001, read-only root, `cap_drop: ALL`, `no-new-privileges`, tmpfs `/tmp`. Ports: `127.0.0.1:8080`, syslog 5514 UDP/TCP, 6514 TLS. Volume `ulpf-data` → `/var/lib/ulpf`.

Full profile (Redpanda, ClickHouse, MinIO, Ollama, two worker replicas):

```bash
docker compose -f deploy/docker-compose.yml --profile full up -d
```

This profile is **not currently functional** as an ingest path: `ULPF_BUS` is never read and `KafkaPublisher` is never constructed, so workers consume an empty `ulpf.raw`. Other Compose bugs (approved-packs path, secret file mode vs uid 10001, worker HEALTHCHECK on :8080, Ollama URL) are listed in [KNOWN_ISSUES.md](KNOWN_ISSUES.md).

## Air-gap bundle

On a connected machine:

```bash
./deploy/airgap/save-bundle.sh
```

`pip download` → `deploy/airgap/wheels/`, `docker build` with `--no-index --find-links=/wheels`, `docker save` → `bundle/ulpf-0.1.0.tar`, plus dependency images → `bundle/ulpf-deps.tar`.

On the isolated network, copy `bundle/` and `wheels/`, then:

```bash
./deploy/airgap/load-bundle.sh
```

These scripts are bash-only.

## `google-re2`

`requirements.txt` pins `google-re2`. If the wheel is missing, `safe_regex` silently falls back to Python `re` and ReDoS protection is gone. Check:

```
python -c "from ulpf.security import HAVE_RE2; print(HAVE_RE2)"
```

It must print `True`.

## Windows notes

- Clone with `git clone --config core.autocrlf=false ...`. With Git's default CRLF conversion every built-in pack fails its signature check (`.sig` files cover the exact LF bytes), `test_chain_and_builtin_signatures` fails, and `ULPF_REQUIRE_SIGNED_PACKS=true` rejects all 15 packs.
- Activate with `.\.venv\Scripts\Activate.ps1`, or call `.\.venv\Scripts\python.exe` directly.
- `chmod 0600` / `0700` on tokens and keys is a no-op.
- `Path.read_text()` without `encoding="utf-8"` in `replay.py` and `fidelity_debug.py` can follow cp1252.
- `drafts.approve` rename over an existing report file can raise `FileExistsError`.
- Shell scripts under `deploy/` need Git Bash or WSL.
