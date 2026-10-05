# Universal Log Pre-processing Framework (ULPF)

ULPF takes security logs in whatever format a vendor writes them (firewalls, IDS, proxies, SSH servers) and turns each line into one [OCSF 1.3](https://schema.ocsf.io/) event. Nothing is thrown away: the original line stays attached, fields that were parsed but not mapped are kept under `unmapped`, and every normalized field records which raw field it came from. Each batch of events is sealed into a signed Merkle hash chain, so an edited stored log fails verification.

What it does beyond a typical parser pipeline:

1. **Offline parser generator.** Show it a format it has never seen. Drain3 clusters similar lines, an offline mapper drafts a YAML source pack, and an optional local Ollama model can suggest mappings. The draft stays inactive until an admin approves and signs it.
2. **Detection-validated normalization.** The Schema Fidelity harness replays labelled detection datasets and checks that rule verdicts survive normalization. On the bundled run, the full ULPF output preserved every detection the raw logs produced (100%, 0 lost). Native OCSF paths alone lost 174.
3. **Tamper-evident lineage.** Each batch is a Merkle tree over `sha256(raw) || sha256(normalized)`. Batch roots are hash-chained and signed with Ed25519.

Full documentation lives in [`docs/`](docs/README.md).

## Setup (step by step)

Run every command from the repository root (the folder that contains this `README.md`). Windows commands are for PowerShell; Linux and macOS commands are for bash or zsh.

### Step 1. Install the prerequisites

- **Git**, to clone the repository.
- **Python 3.12.** The package accepts 3.11 or newer, but 3.12 is what the Docker image uses and what the pinned dependencies have been installed with. Check with:
  - Windows: `py -3.12 --version`
  - Linux / macOS: `python3 --version`
- Optional, only for the later Docker and air-gap sections: Docker, and a bash shell (Git Bash or WSL on Windows) for the scripts in `deploy/`.

### Step 2. Clone the repository

Windows (PowerShell):

```powershell
git clone --config core.autocrlf=false https://github.com/sarthakpandey2503/ulpf.git
cd ulpf
```

Linux / macOS:

```bash
git clone https://github.com/sarthakpandey2503/ulpf.git
cd ulpf
```

On Windows the `--config core.autocrlf=false` part is required. The built-in parser packs are signed over their exact bytes. Git for Windows converts line endings to CRLF by default, which breaks every signature: the **Packs** tab then shows the packs as unsigned, and one test fails. If you already cloned without it, delete the folder and clone again with the flag.

### Step 3. Create and activate a virtual environment

The repository does not ship a virtual environment. Create one named `.venv` (it is gitignored).

Windows (PowerShell):

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
```

If PowerShell refuses to run `Activate.ps1` because scripts are disabled, allow it for the current window only and try again:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

Linux / macOS:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Your prompt now starts with `(.venv)`. Every later `python` and `pip` command uses this environment. If you open a new terminal, run the activate line again.

### Step 4. Install the dependencies

```bash
python -m pip install --upgrade pip
python -m pip install -r requirements-dev.txt
```

`requirements-dev.txt` includes `requirements.txt`, so this installs the runtime packages plus pytest.

Two things to know:

- Do not use `pip install .` on its own. `pyproject.toml` has no `dependencies` list, so it installs the `ulpf` package without FastAPI, uvicorn, and the rest.
- If `google-re2` fails to install, switch to Python 3.12 rather than removing it. Without it ULPF silently falls back to Python's `re` module and loses its protection against catastrophic regular expressions. Confirm it is present with:

  ```bash
  python -c "from ulpf.security import HAVE_RE2; print(HAVE_RE2)"
  ```

  It must print `True`.

### Step 5. Start the server and save the admin token

```bash
python -m ulpf.cli serve
```

On the first start, ULPF creates `data/` (databases, signing keys, token hashes) and prints one line on stderr:

```
First-run admin token (shown once, store it now): <token>
```

Copy that token somewhere safe. Only its SHA-256 hash is stored in `data/tokens.json`, so it cannot be shown again.

Then open [http://127.0.0.1:8080](http://127.0.0.1:8080), paste the token into the **API token** box, and click **Connect**. The header shows `admin · admin` when it worked.

If you missed the token: stop the server (Ctrl+C), delete `data/tokens.json`, and run `python -m ulpf.cli serve` again. A new admin token is printed. Your events and ledger are kept.

Leave the server running and use a second terminal (with the virtual environment activated) for the next step.

### Step 6. Check that everything works

1. In the dashboard, on the **Live** tab, click **Load sample logs**. Events from about fifteen vendor sample files appear in the table.
2. Or, from the terminal, normalize one file into the same store:

   ```bash
   python -m ulpf.cli ingest samples/perimeter/fortigate.log
   ```

   It prints `normalized N events from samples/perimeter/fortigate.log`.
3. Run the test suite. Stop the server first, or run it in the second terminal; the tests use their own temporary directories.

   ```bash
   python -m pytest
   ```

   All 10 tests should pass.

You now have a working local install. The sections below are optional.

## Try the main features in the dashboard

1. **Live**: click **Load sample logs**. Rows come from FortiGate, Palo Alto, Cisco ASA, Suricata, Zeek, and others.
2. **Event**: click any row. The raw line is on one side, the OCSF event on the other, and a table shows which raw field became which OCSF field.
3. **Onboard**: paste at least three lines from `samples/unknown/sophos_xg.log` (a format with no shipped pack), click **Generate draft pack**, and review the self-test results. Click **Approve and sign** to make it live. New Sophos lines are then parsed by the new pack instead of the fallback.
4. **Fidelity**: shows the Schema Fidelity report bundled in `ulpf/validator/fidelity_summary.json` (or your own re-run, see below).
5. **Lineage**: paste an event uid and click **Verify**. All six checks should be true.

To see verification fail on purpose, start the server with demo mode on. The value must be the string `true`.

```powershell
# Windows
$env:ULPF_DEMO = "true"
python -m ulpf.cli serve
```

```bash
# Linux / macOS
ULPF_DEMO=true python -m ulpf.cli serve
```

The **Lineage** tab then shows a **Tamper stored raw** form. It rewrites the stored raw text of one event in the local event store; verifying that event again fails while the ledger itself stays unchanged.

## Roles and API access

| Role | Can do |
|---|---|
| `ingest` | `POST /v1/ingest` only |
| `viewer` | Read events, fidelity, lineage, metrics |
| `analyst` | Viewer, plus draft and edit parser packs |
| `admin` | Analyst, plus approve (Ed25519-sign) packs, reload packs, export anchors |

Send `Authorization: Bearer <token>` on every request. `/health` is the only route without a token. The local first run creates a single admin token; `deploy/make-secrets.sh` creates one token per role for Docker. Route list and details: [docs/API_AND_CLI.md](docs/API_AND_CLI.md).

## Useful commands

```bash
python -m ulpf.cli serve --syslog            # also listen for syslog on UDP/TCP 5514
python -m ulpf.cli ingest <file>             # normalize one file into the local store
python -m ulpf.cli bench --n 20000           # single-process events/sec (ledger and sinks off)
python -m ulpf.cli fidelity                  # re-run Schema Fidelity (needs the datasets below)
python -m pytest
```

Plain syslog is unauthenticated. On untrusted networks pass `--syslog-tls-cert`, `--syslog-tls-key`, and `--syslog-tls-ca` to listen on TLS port 6514 with client certificates required.

All settings are `ULPF_*` environment variables, listed in [docs/CONFIGURATION.md](docs/CONFIGURATION.md).

## Optional: re-run the Schema Fidelity report

The datasets are not part of this repository (`third_party/` is gitignored). Clone them into the folder names the `fidelity` command expects:

```bash
git clone https://github.com/damnkrishna/Detection-Engineering-Ruleset third_party/Detection-Engineering-Ruleset
git clone https://github.com/damnkrishna/detection-engineering-custom-rules- third_party/custom-rules
python -m ulpf.cli fidelity
```

The report is written to `data/fidelity/` and the dashboard's **Fidelity** tab switches to it. Add `--limit 20` for a quick smoke run. Details: [docs/FIDELITY_VALIDATOR.md](docs/FIDELITY_VALIDATOR.md).

## Optional: Docker

Needs Docker and a bash shell (Linux, macOS, WSL, or Git Bash).

```bash
./deploy/make-secrets.sh
docker compose -f deploy/docker-compose.yml up --build ulpf
```

`make-secrets.sh` prints four API tokens (admin, analyst, viewer, ingest) once; store them. The container runs as uid 10001 with a read-only root filesystem and no extra capabilities. The API is on `127.0.0.1:8080`, syslog on `5514` (UDP and TCP) and `6514` (TLS, client certificates required).

Known limitations before you rely on Docker:

- The first start can fail on file permissions or the approved-packs path. See items 1 and 2 in [docs/KNOWN_ISSUES.md](docs/KNOWN_ISSUES.md).
- The `full` Compose profile (Redpanda, ClickHouse, MinIO, Ollama, workers) does not ingest anything today: `ULPF_BUS` is never read and nothing publishes to the `ulpf.raw` topic the workers consume.

Air-gapped install scripts are in `deploy/airgap/`; see [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md).

## Add a log source

Add one YAML file under `ulpf/packs/library/<vendor>/` (or generate it from the **Onboard** tab). A pack says how to recognize the line, how to parse it, and which raw fields map to which OCSF paths. No Python change is needed. Start from `ulpf/packs/library/fortinet/fortigate.yaml` and read [docs/PACK_AUTHORING.md](docs/PACK_AUTHORING.md).

Shipped packs: FortiGate, Palo Alto, Cisco ASA, pfSense, Check Point, Juniper SRX, Squid, nginx, OpenSSH, generic CEF, generic LEEF, Suricata EVE, Zeek, Windows Event Log, and a canonical alert pack.

## Repository layout

```
ulpf/collector     syslog UDP/TCP/TLS, file tail
ulpf/extractors    json, xml, csv, kv, cef, leef, grok, syslog
ulpf/packs         YAML pack engine and the signed pack library
ulpf/normalizer    OCSF 1.3 envelope
ulpf/lineage       Merkle ledger
ulpf/aigen         Drain3 miner, offline mapper, optional local LLM
ulpf/validator     Schema Fidelity replay
ulpf/sinks         SQLite, JSONL, Parquet, ClickHouse, Splunk HEC, Elastic, CEF
ui/                dashboard
samples/           vendor sample logs (perimeter/ known, unknown/ for onboarding)
tests/             pytest suite
tools/             OCSF schema compiler, fidelity debugger
deploy/            Dockerfile, Compose, secrets and air-gap scripts
docs/              project documentation
```

`data/` is created at runtime and holds the signing keys, token hashes, and databases. It is gitignored; never commit it.
