# ULPF architecture

ULPF is a vendor-neutral pipeline that keeps the original log, parses source fields, maps them into one taxonomy, and stays traceable. It runs as one process on a single machine, and is designed to run as a partitioned consumer group when the volume grows.

## Path of one event

A collector accepts a line from syslog (UDP, TCP, or mutual-TLS), an HTTP batch, or a file. The line is bounded (default 64 KB) and rate-limited per sender. A format sniffer tags it (JSON, XML, CEF, LEEF, key=value, CSV, syslog). The pack registry tests signed YAML packs in priority order. The first match extracts fields with a fixed extractor (XML goes through defusedxml; pack regexes compile with RE2) and applies the pack's OCSF mapping.

The normalizer writes an OCSF 1.3 event plus a ULPF envelope: `raw_data`, `raw_sha256`, `unmapped` for every leftover field, and `field_lineage` from each OCSF path back to the raw key. If no pack matches, an offline mapper still fills what it can and the line is stored in an unknown-source cluster. Nothing is dropped on the floor.

Events are sealed in batches. Each leaf is `SHA-256(0x00 || sha256(raw) || sha256(canonical event))`. The batch Merkle root is chained to the previous root and signed with Ed25519. The signing key lives outside the database. SQLite triggers reject updates and deletes on the ledger tables. `GET /v1/events/{uid}/verify` returns the Merkle path, the chain link, and the signature check.

## Scale-out

The default bus is in-process. The scale-out design is `ulpf worker` with Kafka/Redpanda: collectors publish to `ulpf.raw`, stateless workers (consumer group `ulpf-workers`) normalize, and they publish to `ulpf.normalized` only after the sink write succeeds (at-least-once). The worker side exists; the producer side is not wired yet (`ULPF_BUS` is never read), see [KNOWN_ISSUES.md](KNOWN_ISSUES.md). Sinks are SQLite (the dashboard), Parquet on disk or MinIO, ClickHouse, Splunk HEC, Elasticsearch, and CEF forward. Parser workers hold no cross-event state, so adding workers adds throughput. ClickHouse and Parquet are the analytics and data-lake exits.

## Why the three extra pieces are in the hot path

**Parser generator.** Drain3 clusters unknown lines, the synthesizer turns stable tokens into named groups, and a lexical plus value-shape mapper votes on OCSF paths. A local model may suggest mappings; every suggestion is checked against the vendored OCSF schema and the fields actually seen. The draft is self-tested (parse rate, OCSF validity, mapped-field count) and stored unsigned. Approval re-validates the schema, signs the file, and only then reloads the registry.

**Schema Fidelity.** The validator replays paired true-positive and benign datasets through ULPF and through a rule engine that can see either the raw event or the normalized one. The score is the share of cases whose verdict survives normalization. The checked-in summary is 100% fidelity for the full envelope versus 91% when only native OCSF paths are visible, on 551 datasets and 539 rules.

**Lineage.** Tamper evidence comes without an external chain or a network. An auditor can recompute the leaf from the raw bytes and the normalized JSON, check the Merkle path to a signed root, and follow the hash chain to genesis. Anchors can be copied to write-once media.

## Trust boundary

Log text is treated as hostile. Limits cover line size, JSON depth, field count, HTTP body size, and batch size. Tokens are stored as SHA-256 hashes and compared in constant time. The dashboard is same-origin, with a content security policy that allows only local scripts. Pack YAML is loaded with the safe loader. AI drafts never become active packs by themselves. The container image drops all capabilities, runs read-only as a non-root user, and does not require outbound network access.

## What is deliberately not built yet

A single-machine SQLite ledger is the local store. The same envelope is what the ClickHouse and Parquet sinks write; those are the production exits. Hot packs can later be compiled to Vector VRL or Rust without changing the YAML contract. Code-level details are in [CODEBASE_GUIDE.md](CODEBASE_GUIDE.md).
