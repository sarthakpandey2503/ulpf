# Offline parser generator

When no signed pack matches a line, the pipeline still stores it (lossless fallback) and clusters it. An analyst can then draft a pack without leaving the air gap. The draft never routes live traffic until an admin signs it.

Package: `ulpf/aigen/`.

## Capture (`unknown.py`)

`Pipeline._fallback` calls `UnknownStore.add(raw, sn)` after `mapper.infer` fills what it can (confidence capped at 0.6).

`fingerprint(raw, sn)` is a 12-character SHA-256 prefix plus a label:

| Format | Cluster key | Label |
|---|---|---|
| syslog | extracted `message` | `syslog:<app or host>` |
| CEF / LEEF | vendor + product header | `cef:` / `leef:` … |
| kv | first 12 sorted key names | those keys |
| json | first 12 sorted JSON keys | those keys |
| other | first 3 tokens with digits as `#` | the tokens |

`UnknownStore(max_clusters=200, per_cluster=200)` is an in-memory `OrderedDict`. When full it evicts the least-recently-updated cluster. Samples per cluster are a deque of 200. **Restart loses all clusters.**

API: `GET /v1/unknown`, `DELETE /v1/unknown/{fp}`, `POST /v1/unknown/{fp}/synthesize` (needs ≥ 3 samples). `POST /v1/drafts/synthesize` accepts 3–500 pasted lines.

## Drain3 mining (`miner.py`)

`TemplateMinerConfig`: `drain_sim_th = 0.4`, `drain_depth = 4`. Masks applied in order: MAC, IPv4, NUM. If Drain3 is not installed, digits are replaced with `<NUM>`.

`mine(messages, max_samples=50)` → clusters sorted by size. `template_to_regex` turns `<*>` tokens into named groups using common prefixes/suffixes from real samples, names `src_ip`/`dst_ip` around `->`/`=>`, and anchors the result `^...$`. IPv6 is not masked (IPv4 only).

Free-text sources (MikroTik) take this path. Structured sources skip it.

## Synthesis (`synth.py`)

`synthesize(samples, settings, vendor, product, use_llm="auto", registry)`:

1. Cap at 500 lines, require ≥ 3.
2. Sniff every line; majority format/envelope wins. Syslog envelope adds a `{type: syslog}` stage and parses `message`.
3. If the format is json/xml/kv/cef/leef/csv, add that extractor. Otherwise add `{type: regex, patterns: top 12 Drain patterns, required: false}`.
4. Probe-extract fields. `_vote` runs `mapper.infer` per sample; majority class wins; a path is kept if the same raw field was chosen in ≥ 50% of samples; each raw field is used once.
5. Optionally ask the LLM (see below). LLM mappings are added at score 0.55 only for unused paths/fields.
6. Keep paths that `ocsf.known_path` accepts. `time` gets `cast: timestamp`, or template `"{date} {time}"` when both exist (Sophos).
7. `match.formats` from sniff tags; `match.contains` from common tokens. Pack id is `vendor.product` or `draft.src_<hash>`. Priority 30.
8. `provenance` records generator, sample hashes, LLM info, `field_confidence`. `tests` holds the first 3 samples.
9. `selftest` runs last. YAML is emitted with a `NOT ACTIVE` header.

Sample sources without a shipped pack:

- `samples/unknown/sophos_xg.log` — 6 key=value lines. kv path, date+time template.
- `samples/unknown/mikrotik.log` — 20 RouterOS firewall lines. Drain3/regex path.

## Offline mapper (`mapper.py`)

No model required.

- **Synonym table** `SYNONYMS`: ~35 OCSF paths with value kinds and aliases. Names are lowercased and stripped to `[0-9a-z@]`.
- **Lexical score**: exact name 1.0, last dotted segment 0.9, else `difflib` ratio ≥ 0.84 scored as ratio × 0.8.
- **Value-shape score** `value_fits`: ip/port/int/mac parsed strictly; time regex; proto/method/action/severity sets; generic strings 0.7.
- Combined score = lexical × value fit, drop below 0.5, one raw field → one path.
- **Class**: HTTP method or URL+status → `http_activity`; DNS query → `dns_activity`; title + threat words → `detection_finding`; user + auth words → `authentication`; src/dst IP → `network_activity`; else `base_event`. Invalid paths for the class are dropped.
- `MappingGuess.confidence` is capped at 0.6. `disposition_id` is 1 allow / 2 block / 0 else.

A `_semantic_model()` helper (sentence-transformers) exists in comments/docstring but is **never called**. Several synonyms collide (`in`/`out`, `status`, `agentip`); only value shape can separate them.

## Optional local LLM (`llm.py`)

`OllamaClient`:

- Host of `ULPF_OLLAMA_URL` must be in `ULPF_OLLAMA_ALLOWED_HOSTS` (default `localhost,127.0.0.1,::1,ollama`). Any other host raises `LLMUnavailable`.
- `available()` is `GET /api/tags` (3 s). Default model `qwen2.5-coder:7b`.
- `generate_json` streams `POST /api/generate` with `format: json`, temperature 0.1, `num_predict` 1500, reply cap 64 KiB. JSON is parsed with `safe_json_loads`.
- System prompt treats `<samples>` as untrusted data and asks for `{"class","vendor","product","rename","mapping"}`.
- Validation: class in candidates; mapped fields actually extracted; paths pass `ocsf.known_path`; rename identifiers `^[A-Za-z0-9_]{1,48}$`.

**LM Studio.** When `ULPF_LMSTUDIO_API_KEY` is non-empty, the same client switches to LM Studio's OpenAI-compatible API at `ULPF_LMSTUDIO_URL` (default `http://127.0.0.1:1234/v1`) with `Authorization: Bearer <key>`. `available()` is `GET /models` and checks that `ULPF_LMSTUDIO_MODEL` is listed in `data[].id`; `generate_json` is `POST /chat/completions` with system and user messages, a `json_schema` response format (LM Studio rejects `json_object`), `reasoning_effort` from `ULPF_LMSTUDIO_REASONING_EFFORT` (default `none`), temperature 0.1, `max_tokens` 1500, and parses `choices[0].message.content`. Empty content raises `LLMUnavailable`. Mappings returned as field → path are swapped before validation. The host allow-list, reply cap, and validation are the same as for Ollama. A key without `ULPF_LMSTUDIO_MODEL` raises `LLMUnavailable`. The draft's `provenance.llm.backend` records `ollama` or `lmstudio`.

**Rename suggestions are validated and then ignored** (`synth.py` never applies them). Compose does not set `ULPF_OLLAMA_URL`, so the `ollama` service is not reached from the container (default is localhost). The generator still works: `use_llm` falls back to the offline mapper. Tests use `use_llm="off"`.

## Self-test (`selftest.py`)

Gates: `PARSE_MIN, VALID_MIN, MAPPED_MIN = 0.95, 0.90, 3.0`.

1. `validate_pack` + `compile_pack`.
2. A one-pack `Pipeline` normalizes each sample.
3. Counts routed (this pack's ref), parsed (no parse errors), OCSF-valid, mapped (lineage entries that are not `default`/`const`).
4. Routing conflicts against up to 200 samples from `existing` packs are **reported, not gated**.
5. `passed` is true iff parse rate, OCSF-valid rate, and average mapped attributes meet the thresholds.

The module docstring says "routed + parsed"; `route_rate` itself is not a gate.

## Draft lifecycle (`drafts.py`)

Storage: `ULPF_DRAFTS_DIR` (default `data/drafts`). Approved: `ULPF_APPROVED_PACKS_DIR` (default `data/packs`). Ids must match the pack-id regex (also blocks `../`).

| Step | Who | What |
|---|---|---|
| Create | analyst | `save()` writes `<id>.yaml` + `<id>.report.json` |
| List / get | analyst | `list_drafts`, `get` |
| Edit | analyst | `update_yaml` validates, writes `.yaml.tmp`, replaces. API then re-runs `selftest` on `tests[].input` only (**at most 3 lines**) and overwrites the report |
| Approve | **admin** | requires `report.passed`; sets `approved_by` / `approved_at`; bumps `0.x` → `1.0`; writes to `approved_dir`; `sign_pack`; deletes draft; `reload_packs` |
| Reject | analyst | deletes yaml + report |

Until signed, `PackRegistry.load` does not see the draft. After approve, a new Sophos line should show pack `sophos.xg_firewall@1.0` instead of `fallback`.

Caveats (open issues):

- Re-test on 3 `tests[]` lines can keep `passed: true` after a harmful edit.
- `update_yaml` itself does not refresh the report; only the API route does.
- Approving an id that already exists silently overwrites. On Windows, renaming over an existing `.report.json` can raise `FileExistsError`.
- A draft named like a built-in pack (`fortinet.fortigate`) is not treated as a conflict (`selftest` skips same id).
