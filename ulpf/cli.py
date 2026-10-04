"""Command line: ``ulpf serve``, ``worker``, ``ingest``, ``fidelity``, ``bench``."""
from __future__ import annotations

import argparse
import asyncio
import logging
import sys
import time
from pathlib import Path

from . import __version__
from .config import Settings
from .runtime import Runtime, SyslogOptions


def _settings() -> Settings:
    s = Settings()
    s.ensure_dirs()
    return s


def _runtime() -> Runtime:
    rt = Runtime(_settings())
    if rt.auth.bootstrap_plaintext:
        print("First-run admin token (shown once, store it now): " + rt.auth.bootstrap_plaintext, file=sys.stderr)
        rt.auth.bootstrap_plaintext = None
    return rt


def _check_tls(args) -> None:
    if not args.syslog_tls_cert:
        return
    for label, path in (("cert", args.syslog_tls_cert), ("key", args.syslog_tls_key)):
        if not path or not Path(path).is_file():
            raise SystemExit(f"syslog TLS {label} not found: {path}")
    if args.syslog_tls_ca and not Path(args.syslog_tls_ca).is_file():
        raise SystemExit(f"syslog TLS CA not found: {args.syslog_tls_ca}")


def cmd_serve(args) -> None:
    import uvicorn

    _check_tls(args)
    rt = _runtime()
    if args.syslog:
        rt.syslog = SyslogOptions(args.syslog_host, args.syslog_udp, args.syslog_tcp, args.syslog_tls_port,
                                  args.syslog_tls_cert, args.syslog_tls_key, args.syslog_tls_ca)
    from .api import create_app

    uvicorn.run(create_app(rt), host=args.host, port=args.port, log_level="info", server_header=False,
                proxy_headers=False, forwarded_allow_ips="")


def cmd_worker(_args) -> None:
    from .bus import run_worker

    rt = _runtime()
    asyncio.run(run_worker(rt.settings, rt.pipeline))


def cmd_ingest(args) -> None:
    from .collector.filetail import read_file

    rt = _runtime()
    path = Path(args.file)
    if not path.is_file():
        raise SystemExit(f"file not found: {path}")
    out = rt.pipeline.process(read_file(path, args.source))
    print(f"normalized {len(out)} events from {path}")


def cmd_fidelity(args) -> None:
    from .validator.replay import run_and_save

    datasets = Path(args.datasets)
    rules = Path(args.rules) if args.rules else None
    if not datasets.is_dir():
        raise SystemExit(f"datasets not found: {datasets}")
    rep = run_and_save(datasets, rules, Path(args.out), _settings(), limit=args.limit,
                       progress=lambda n, m, d: print(f"\r{n}/{m} {d[:48]:<48}", end="", file=sys.stderr))
    print(file=sys.stderr)
    print(f"schema fidelity {rep['schema_fidelity_score']}%  "
          f"accuracy vs expected {rep['oracle_agreement']}%  "
          f"wrote {args.out}")


def cmd_bench(args) -> None:
    rt = _runtime()
    sample = Path(args.sample)
    if not sample.is_file():
        raise SystemExit(f"sample not found: {sample}")
    line = next(l for l in sample.read_text(encoding="utf-8", errors="replace").splitlines() if l.strip())
    lines = [line] * args.n
    rt.pipeline.ledger = None
    rt.pipeline.sinks = []
    t0 = time.perf_counter()
    out = rt.ingest(lines, {"transport": "bench"})
    dt = time.perf_counter() - t0
    valid = sum(1 for e in out if e["ulpf"]["validation"]["valid"])
    print(f"events={len(out)} valid={valid} seconds={dt:.3f} eps={len(out) / dt:.0f}")


def main(argv: list[str] | None = None) -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    parser = argparse.ArgumentParser(prog="ulpf", description="Universal Log Pre-processing Framework")
    parser.add_argument("--version", action="version", version=f"ulpf {__version__}")
    sub = parser.add_subparsers(dest="cmd", required=True)

    serve = sub.add_parser("serve", help="API, dashboard, and optional syslog receiver")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8080)
    serve.add_argument("--syslog", action="store_true")
    serve.add_argument("--syslog-host", default="0.0.0.0")
    serve.add_argument("--syslog-udp", type=int, default=5514)
    serve.add_argument("--syslog-tcp", type=int, default=5514)
    serve.add_argument("--syslog-tls-port", type=int, default=6514)
    serve.add_argument("--syslog-tls-cert")
    serve.add_argument("--syslog-tls-key")
    serve.add_argument("--syslog-tls-ca")
    serve.set_defaults(func=cmd_serve)

    worker = sub.add_parser("worker", help="Kafka/Redpanda consumer that normalizes ulpf.raw")
    worker.set_defaults(func=cmd_worker)

    ingest = sub.add_parser("ingest", help="Normalize one file into the local store")
    ingest.add_argument("file")
    ingest.add_argument("--source", help="pack id to pin, if the sender is already known")
    ingest.set_defaults(func=cmd_ingest)

    fidelity = sub.add_parser("fidelity", help="Replay detection datasets and write the Schema Fidelity report")
    fidelity.add_argument("--datasets", default="third_party/Detection-Engineering-Ruleset")
    fidelity.add_argument("--rules", default="third_party/custom-rules")
    fidelity.add_argument("--out", default="data/fidelity")
    fidelity.add_argument("--limit", type=int, default=None)
    fidelity.set_defaults(func=cmd_fidelity)

    bench = sub.add_parser("bench", help="Single-process events-per-second measurement")
    bench.add_argument("--n", type=int, default=20000)
    bench.add_argument("--sample", default="samples/perimeter/fortigate.log")
    bench.set_defaults(func=cmd_bench)

    args = parser.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
