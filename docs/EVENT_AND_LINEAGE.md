# Event envelope and lineage ledger

Every successful `Pipeline.normalize` call returns one JSON object: an OCSF 1.3 event plus a ULPF envelope. The ledger then seals batches of those objects.

## Envelope (`ulpf/normalizer/envelope.py` → `build_event`)

### Top-level OCSF

- `class_uid`, `class_name` (caption), `category_uid`, `category_name`
- `activity_id`, `activity_name` (if the enum has a caption)
- `severity_id`, `severity`
- `type_uid = class_uid * 100 + activity_id`
- `type_name = "<caption>: <activity or Unknown>"`
- mapped attributes; each top-level `*_id` also gets a sibling caption (for example `disposition`)
- `time` — source timestamp, or receipt time with warning `"time not present in source; receipt time used"`

Required `*_id` enums on present objects that the source did not fill are set to `0` (Unknown) and recorded in lineage as `default:unknown`.

### `metadata`

| Field | Value |
|---|---|
| `version` | OCSF 1.3.0 |
| `product.vendor_name` / `product.name` | pack vendor / product |
| `uid` | uuid4 |
| `logged_time`, `processed_time` | ms |
| `log_provider` | pack ref `id@version`, or fallback |
| `log_name` | class rule name, or `fallback:<class>` |
| `original_time` | source time if present |

### Lossless fields

- `raw_data` — the decoded line (`check_line` already replaced invalid UTF-8 with U+FFFD and NUL with the text `\x00`; trailing syslog `\r\n\x00` is stripped). This is **not** the literal wire bytes. See [KNOWN_ISSUES.md](KNOWN_ISSUES.md).
- `unmapped` — extracted fields that were not consumed, snake_cased, with `_2`, `_3` suffixes on collisions.

### `ulpf` object

| Key | Meaning |
|---|---|
| `raw_sha256` | SHA-256 of `raw_data` (UTF-8, `surrogateescape`) |
| `raw_size` | character length |
| `pack` | `id@version` or `fallback:...` |
| `pack_signed` | bool |
| `format` | sniffer tags joined with `+` (e.g. `kv+syslog`) |
| `source` | collector hint (`transport`, `peer`, …) |
| `confidence` | pack trust; multiplied by 0.9 if OCSF validation failed. Fallback mapper caps at 0.6 |
| `field_lineage` | map of OCSF path → raw field name, list of fields, `const`, `default`, `default:unknown`, `ulpf.received_time`, `derived:sha256(finding_info.title)`, or `unmapped.<key>` |
| `field_count` | `{extracted, mapped, unmapped}` |
| `validation` | `{valid, errors, warnings}` from `ocsf.validate` |
| `parse_errors` | extractor failures on the fallback path |
| `batch_id`, `merkle_leaf`, `norm_sha256` | written by the ledger after seal |

## Merkle ledger (`ulpf/lineage/`)

RFC 6962-style domain separation so a leaf can never be confused with an interior node.

**Leaf**

```
leaf = SHA256( 0x00 || bytes(raw_sha256) || bytes(norm_sha256) )
```

`norm_sha256` is `canonical_digest(event)`: SHA-256 of compact sorted-key JSON with `ulpf.batch_id`, `ulpf.merkle_leaf`, and `ulpf.norm_sha256` stripped so the digest does not depend on the seal.

**Interior nodes**

```
node = SHA256( 0x01 || left || right )
```

An odd last node is promoted unchanged. An empty tree hashes to `SHA256("")`.

**Chain and signature**

```
chain = SHA256( f"{prev}|{root_hex}|{batch_id}|{count}|{created_ms}" )
signature = Ed25519.sign( bytes.fromhex(chain) )
```

Genesis `prev` is 64 zero hex chars. The key is `keys_dir/ledger.key` (created on first run). `key_id` is the first 16 hex chars of SHA-256 of the public PEM.

Signed roots can be copied to write-once media with `POST /v1/ledger/anchors` → `data/anchors.jsonl` (`Ledger.export_anchors`).

Limitation stated in the architecture note: an insider who has both the database **and** the signing key can recompute the chain. The key is stored outside the DB (0600 PEM); production would put it in an HSM.

### SQLite schema (`data/ledger.db`, WAL)

```
batches(batch_id PK, created_ms, count, merkle_root, prev_chain, chain_hash, signature, key_id)
leaves(event_uid PK, batch_id, leaf_index, raw_sha256, norm_sha256, leaf_hash)
index leaves_batch (batch_id, leaf_index)
```

Triggers `batches_no_update`, `batches_no_delete`, `leaves_no_update`, `leaves_no_delete` each `RAISE(ABORT, 'ledger is append-only')`.

The **event store** (`data/events.db`, `SQLiteStore`) is separate. Demo tamper (`POST /v1/demo/tamper`) rewrites `raw_data` in the event store only. The ledger row does not move, so verify fails. That endpoint exists only when `ULPF_DEMO=true`.

### `verify_event` checks

`GET /v1/events/{uid}/verify` returns `{event_uid, checks, verified, batch_id, leaf_index, merkle_root, chain_hash, signature, key_id, merkle_path}`.

| Check | Meaning |
|---|---|
| `raw_bytes_match` | SHA-256 of the stored `raw_data` equals the leaf's `raw_sha256` and `ulpf.raw_sha256` |
| `normalized_event_match` | `canonical_digest(event)` equals the stored `norm_sha256` |
| `leaf_consistent` | recomputed leaf hash equals the stored `leaf_hash` |
| `merkle_proof` | audit path walks to the batch root, and leaf count matches `count` |
| `chain_link` | recomputed chain hash matches, and `prev_chain` equals the previous batch (or genesis) |
| `signature` | Ed25519 over the chain hash verifies with the **current** process public key |

`verified` is true only if every check is true. Missing event: `{verified: false, reason: "event not in ledger"}`.

`GET /v1/ledger/verify` walks every batch from genesis (`verify_chain`).

Known gaps: verification always uses the current key, not the stored `key_id` (key rotation would fail old batches). A missing batch row can raise `TypeError` instead of a clean result. Several processes sharing one `ledger.db` can collide on `batch_id`. See [KNOWN_ISSUES.md](KNOWN_ISSUES.md).

## Audit log (`ulpf/audit.py`)

`data/audit.jsonl`, append-only JSONL, separate from the ledger.

```
{ts, actor, action, detail, prev, hash}
hash = sha256( prev + "|" + canonical_json(ts, actor, action, detail, prev) )
```

Genesis prev is all zeros. `GET /v1/audit` (admin) returns recent records plus a chain-verify result.

Actions recorded: `auth_failure`, `auth_denied`, `ingest`, `export_anchors`, `reload_packs`, `drop_unknown`, `synthesize`, `edit_draft`, `approve_pack`, `reject_draft`, `demo_tamper`, `load_samples`.
