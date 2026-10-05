# ULPF documentation

This folder documents the Universal Log Pre-processing Framework (ULPF).

ULPF ingests a security log line in whatever format the vendor wrote, and emits one [OCSF 1.3](https://schema.ocsf.io/) event. The original line stays attached. Unmapped fields stay attached. Each normalized field records which raw field it came from. The event is then sealed into a signed Merkle ledger.

The code lives under `ulpf/`. The dashboard lives under `ui/`. Step-by-step setup is in the root [`README.md`](../README.md).

## Reading order

If you are new to the repo, read in this order:

1. [PROBLEM_AND_APPROACH.md](PROBLEM_AND_APPROACH.md) — the problem ULPF solves, its three main capabilities, target metrics, and the third-party datasets.
2. [ARCHITECTURE.md](ARCHITECTURE.md) — short architecture overview: the path of one event, scale-out, and the trust boundary.
3. [CODEBASE_GUIDE.md](CODEBASE_GUIDE.md) — directory layout, how `Runtime` is wired, and the path of one log line through the code.
4. [PACK_AUTHORING.md](PACK_AUTHORING.md) — YAML source packs: the format, operators, signing, and the 15 shipped packs.
5. [EVENT_AND_LINEAGE.md](EVENT_AND_LINEAGE.md) — the output envelope, Merkle batching, hash chain, and verification checks.
6. [AI_PARSER_GENERATOR.md](AI_PARSER_GENERATOR.md) — unknown-source clustering, Drain3, the offline mapper, optional Ollama, and draft approval.
7. [FIDELITY_VALIDATOR.md](FIDELITY_VALIDATOR.md) — how Schema Fidelity is measured against the detection datasets.
8. [API_AND_CLI.md](API_AND_CLI.md) — HTTP routes, roles, CLI, and the dashboard tabs.
9. [CONFIGURATION.md](CONFIGURATION.md) — every `ULPF_*` environment variable.
10. [DEVELOPMENT.md](DEVELOPMENT.md) — tests, schema rebuild, Docker, air-gap, platform notes.
11. [SECURITY.md](SECURITY.md) — threat model and the controls that are in the code.
12. [KNOWN_ISSUES.md](KNOWN_ISSUES.md) — bugs and gaps, with file:line references.

## What is not in this folder

- Source code: `ulpf/`, `ui/`, `tools/`, `tests/`, `deploy/`
- Sample logs: `samples/perimeter/` (known vendors) and `samples/unknown/` (Sophos XG, MikroTik)
- Bundled fidelity report: `ulpf/validator/fidelity_summary.json` (a re-run writes `data/fidelity/fidelity.json` and `FIDELITY.md`)
- Third-party datasets: `third_party/` (gitignored; clone instructions in the root README)
