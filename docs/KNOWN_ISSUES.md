# Known issues

Open bugs and gaps in the current code. Line numbers refer to the tree as it existed when this file was written; search for the quoted names if they drift.

## Deployment blocking

1. **Docker first start can fail creating approved packs.** `deploy/Dockerfile:23` sets `DATA_DIR` / `KEYS_DIR` / `DRAFTS_DIR` but not `ULPF_APPROVED_PACKS_DIR`. Default is `ROOT/data/packs` (`config.py:32`). In an installed wheel `ROOT` is site-packages. `ensure_dirs()` then tries to mkdir there as uid 10001 on a read-only rootfs. Plain `docker run` has the same problem for `ULPF_TOKENS_FILE` (`config.py:66`).
2. **Compose secrets may be unreadable.** `deploy/make-secrets.sh` `chmod 600`s files owned by the host user. File-based secrets keep host ownership. Container user is uid 10001.
3. **Kafka ingest is never fed.** `Settings.bus` (`config.py:47`) is never read. `KafkaPublisher` (`bus.py`) is never instantiated. `ulpf worker` consumes `ulpf.raw`; nothing produces it, so workers never write `ulpf.normalized` with the current wiring.
4. **Ollama in Compose is unused.** Neither `ulpf` nor `ulpf-worker` sets `ULPF_OLLAMA_URL`. Default is `http://localhost:11434` (`config.py:59`).
5. **Worker healthcheck always fails.** Dockerfile `HEALTHCHECK` hits `:8080/health`. `ulpf-worker` command is `worker` (no HTTP).
6. **Shared ledger across processes.** `ulpf` and two worker replicas mount the same `ulpf-data`. Each `Ledger` computes `batch_id` in-process (`ledger.py:81-83`). Chains can fork; `load_or_create` on keys can race. Audit lock is per process (`audit.py`).

## Correctness

7. **Dead-letter Kafka forwarding stops at 1000.** `pipeline.dead_letters` is `deque(maxlen=1000)` (`pipeline.py`). Worker diffs `len(...)` (`bus.py`). Once full, length never grows, so new DLs never reach `ulpf.deadletter`.
8. **Edited draft re-tested on ≤ 3 lines.** `PUT /v1/drafts/{id}` runs `selftest` on `tests[].input` only (`api.py:377-381`). `drafts.approve` trusts `report.passed` (`drafts.py`). Gates 0.95 / 0.90 / 3.0 become weak after an edit. `update_yaml` itself does not refresh the report.
9. **Approve can overwrite an existing pack** of the same id (`drafts.py:89-95`). On Windows, `Path.rename` onto an existing `.report.json` can raise `FileExistsError`. `selftest.py` skips routing conflicts with the same id, so a draft named `fortinet.fortigate` shadows the builtin with no warning.
10. **Ledger failure drops the whole batch.** `pipeline.py` does not catch `ledger.append`; sink errors are caught. Next `batch_id` is local to the process.
11. **Verify ignores key rotation.** `ledger.py:139` always uses `self._pub`, not the stored `key_id`. A missing batch row can `TypeError` instead of a clean failure (`ledger.py:128`).
12. **CLI `--source` is a no-op.** Help says "pack id to pin" (`cli.py:126`). Routing compares the hint to `match.sources` (`loader.py`, `engine.py`). No library pack sets `sources`.
13. **RE2 fallback is silent.** `security.py:43` uses Python `re` if `google-re2` is missing. No log line.
14. **"Exact original bytes" is decoded text.** `envelope.py` docstring vs `check_line` (`security.py:58,64`: invalid UTF-8 → U+FFFD, NUL → `\x00`) and syslog strip of trailing `\r\n\x00` (`collector/syslog.py`). `raw_sha256` hashes that text.
15. **Native `ocsf_native_share` is always 100%.** Formula excludes unmapped/lineage in native mode (`replay.py`). `FIDELITY.md` showing 100% native vs 91.81% full is inverted intuition; full-mode 91.81% is the real share.
16. **Rule eval exceptions count as "no alert"** (`replay.py:190`), which can inflate fidelity if the engine crashes on raw and OCSF the same way.
17. **LLM `rename` is unused** (`llm.py` validates it; `synth.py` never applies). `_semantic_model()` in `mapper.py` is never called. `matches.pop("time")` runs only when `"time" not in matches` (`synth.py:203-204`) — a no-op.
18. **Unknown clusters are memory-only** (`aigen/unknown.py`). Restart loses Onboard state.
19. **CEF unescape** can turn `\\n` into a newline (`extractors/cef.py`). LEEF misses uppercase `0X` delimiter (`leef.py`).
20. **`cast: auto`** is allowed by schema (`schema.py:32`) and is a no-op in `_cast`. `default` bypasses cast and scale (`engine.py`). Unknown mapping paths are dropped silently (`engine.py:289-290`).
21. **Extractors ignore per-instance Settings** (`json_.py`, `xml_.py` import the global `settings`).
22. **`SQLiteStore` required by the API.** `Runtime.store` is None if `sqlite` is not in `ULPF_SINKS`; event routes 503.
23. **`fallback` query param** cannot select non-fallback events (`api.py:265`: `True if fallback else None`).
24. **Sync ingest on the event loop** (`api.py:251`) blocks syslog and other requests during large batches. Dead-letter counters around ingest are racy under concurrency.
25. **Unauthenticated `/docs`** (FastAPI default) and unbounded `auth_failure` audit growth (`api.py:137`, `audit.py:56` reads the whole file).
26. **Audit chain can reset** if the last line is corrupt (`audit.py:39-41` falls back to genesis).
27. **`tools/fidelity_debug.py`** raises `NameError` on JSON stage rules; relative paths; `read_text()` without encoding.

## Windows

28. **CRLF checkout breaks pack signatures.** There is no `.gitattributes`, so Git for Windows with `core.autocrlf=true` (the installer default) rewrites `ulpf/packs/library/**/*.yaml` to CRLF. Signatures are over the exact LF bytes, so all 15 packs load as unsigned, `test_chain_and_builtin_signatures` fails, and `ULPF_REQUIRE_SIGNED_PACKS=true` rejects every pack. Workaround: clone with `--config core.autocrlf=false`. Fix: add a `.gitattributes` with `*.yaml -text` (or `eol=lf`).
29. `chmod` on tokens/keys is skipped (`auth.py:76`, `config.py:78`).
30. `replay.py` / `fidelity_debug.py` / some `drafts.py` reads omit `encoding="utf-8"`.
31. `deploy/*.sh` are bash (`/dev/urandom`, openssl, `python3`). Use Git Bash or WSL.

## Hygiene / packaging

32. **`data/` holds secrets at runtime:** `data/keys/ledger.key`, `data/keys/ledger.pub`, `data/tokens.json`, `data/ledger.db`, `data/events.db`, `data/audit.jsonl`. `.gitignore` excludes `data/`; never commit it or share it. Rotate tokens and ledger keys if it leaks.
33. `pyproject.toml` has no `dependencies`; only `requirements.txt` installs runtime packages. `ui/` and `samples/` are not package data.
34. `.gitignore` has `data/` then `!data/.gitkeep`, which cannot re-include a file under an ignored directory; there is no `data/.gitkeep`.
35. `.dockerignore` does not exclude `deploy/secrets/` or `deploy/airgap/wheels`.
36. Dockerfile `COPY deploy/airgap/wheel[s]` matches nothing when `wheels/` is absent (BuildKit ok; legacy builder fails).
37. Duplicate pack ids across `packs_dir` and `approved_dir` both load; `get()` returns the first.
38. Pack signature is checked on `read_bytes()`, YAML then `read_text()` (`loader.py`) — small TOCTOU.
39. Trust comes from self-declared `provenance`, not from whether the pack is signed.
40. `ULPF_CORS_ORIGINS` unused. `collector.filetail.follow` unused. `Sniff.confidence` / `hints` unused for routing. `AsyncBatcher.dropped` never exposed.
41. Pipeline imports `ulpf.aigen.mapper` for fallback, so the core always depends on the generator package.
42. Rate limiter `_state` grows with every distinct key (`security.py:90`) — spoofed UDP sources.
43. `load-samples` is not gated on demo mode (`api.py:448`), unlike tamper.
44. UI: viewers see Onboard (403); Reject button is not role-gated (`connect()` in `app.js:56-66` hides Approve only); toast timeouts can hide a newer error (`app.js:16`).
45. Lost first-run admin token has no CLI recovery. Workaround: stop the server, delete the tokens file (`data/tokens.json`), start again.

## Planned, never built

Field-extraction F1 golden set, extractor fuzz tests, Bandit/pip-audit/Trivy report in the repo, at-rest encryption, PII masking, JWT, base-image digest pin, SBOM. See also the end of [SECURITY.md](SECURITY.md).
