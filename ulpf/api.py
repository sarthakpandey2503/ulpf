"""HTTP API and dashboard host.

Authentication is a bearer token. ``/health`` is the only unauthenticated route
(container health checks). Request bodies are size-capped. Responses carry a
locked-down content security policy. OpenAPI is left on so evaluators can read
the contract; every data route still requires a token.
"""
from __future__ import annotations

import json
import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import __version__
from .aigen import drafts
from .aigen.selftest import selftest
from .aigen.synth import synthesize
from .auth import allows
from .collector.batcher import AsyncBatcher
from .collector.syslog import SyslogServer
from .runtime import Runtime
from .security import InputRejected, safe_yaml_load

log = logging.getLogger("ulpf.api")

_SECURITY_HEADERS = (
    (b"x-content-type-options", b"nosniff"),
    (b"referrer-policy", b"no-referrer"),
    (b"x-frame-options", b"DENY"),
    (b"content-security-policy",
     b"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
     b"connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"),
    (b"permissions-policy", b"camera=(), microphone=(), geolocation=()"),
    (b"cross-origin-opener-policy", b"same-origin"),
    (b"cross-origin-resource-policy", b"same-origin"),
    (b"cache-control", b"no-store"),
)


class _Oversize(Exception):
    pass


class BodyLimit:
    def __init__(self, app, max_bytes: int):
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = {k.decode("latin1").lower(): v.decode("latin1") for k, v in scope.get("headers") or []}
        cl = headers.get("content-length")
        if cl and cl.isdigit() and int(cl) > self.max_bytes:
            await _reject(send, 413, "request body too large")
            return
        received = 0

        async def limited():
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body") or b"")
                if received > self.max_bytes:
                    raise _Oversize()
            return message

        try:
            await self.app(scope, limited, send)
        except _Oversize:
            await _reject(send, 413, "request body too large")


class SecurityHeaders:
    def __init__(self, app, hsts: bool):
        self.app = app
        self.hsts = hsts

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def wrapped(message):
            if message["type"] == "http.response.start":
                headers = list(message.get("headers") or [])
                headers.extend(_SECURITY_HEADERS)
                if self.hsts:
                    headers.append((b"strict-transport-security", b"max-age=31536000; includeSubDomains"))
                message["headers"] = headers
            await send(message)

        await self.app(scope, receive, wrapped)


async def _reject(send, status: int, detail: str) -> None:
    body = json.dumps({"error": detail}).encode()
    await send({"type": "http.response.start", "status": status,
                "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())]})
    await send({"type": "http.response.body", "body": body})


class IngestBody(BaseModel):
    lines: list[str] = Field(min_length=1)
    source_hint: str | None = None


class SynthesizeBody(BaseModel):
    lines: list[str] = Field(min_length=3)
    vendor: str | None = None
    product: str | None = None


class YamlBody(BaseModel):
    yaml: str = Field(min_length=1, max_length=1_000_000)


class TamperBody(BaseModel):
    uid: str
    raw: str


def _principal(request: Request, need: str) -> dict:
    rt: Runtime = request.app.state.runtime
    header = request.headers.get("authorization", "")
    token = header[7:].strip() if header.lower().startswith("bearer ") else request.headers.get("x-api-token", "")
    who = rt.auth.check(token.strip())
    if who is None:
        rt.audit.write("anonymous", "auth_failure", {"path": request.url.path})
        raise HTTPException(401, "authentication required")
    if not allows(who["role"], need):
        rt.audit.write(who["name"], "auth_denied", {"path": request.url.path, "need": need})
        raise HTTPException(403, "insufficient role")
    return who


def viewer(request: Request) -> dict:
    return _principal(request, "viewer")


def analyst(request: Request) -> dict:
    return _principal(request, "analyst")


def admin(request: Request) -> dict:
    return _principal(request, "admin")


def ingest_role(request: Request) -> dict:
    return _principal(request, "ingest")


def _store(rt: Runtime):
    if rt.store is None:
        raise HTTPException(503, "event store is not enabled (add sqlite to ULPF_SINKS)")
    return rt.store


def _report(rt: Runtime) -> dict:
    path = rt.settings.data_dir / "fidelity" / "fidelity.json"
    source = "run"
    if not path.exists():
        path = Path(__file__).resolve().parent / "validator" / "fidelity_summary.json"
        source = "bundled"
    if not path.exists():
        raise HTTPException(404, "no fidelity report; run `ulpf fidelity`")
    data = json.loads(path.read_text(encoding="utf-8"))
    data.pop("rows", None)
    data["source"] = source
    return data


def _pack_view(p) -> dict:
    return {"id": p.id, "version": p.version, "ref": p.ref, "vendor": p.vendor, "product": p.product,
            "priority": p.priority, "signed": p.signed, "trust": p.trust, "formats": sorted(p.formats)}


def create_app(runtime: Runtime) -> FastAPI:
    @asynccontextmanager
    async def lifespan(app: FastAPI):
        servers: list = []
        batcher = None
        opts = runtime.syslog
        if opts is not None:
            batcher = AsyncBatcher(runtime.pipeline.process, max_batch=runtime.settings.batch_size)
            batcher.start()
            server = SyslogServer(runtime.settings, batcher)
            tls_port = opts.tls_port if opts.tls_cert else None
            servers = await server.start(opts.host, opts.udp_port, opts.tcp_port, tls_port, opts.tls_cert,
                                         opts.tls_key, opts.tls_ca)
            app.state.syslog_server = server
        yield
        for srv in servers:
            srv.close()
        if batcher is not None and batcher._task is not None:
            batcher._task.cancel()

    app = FastAPI(title="ULPF", version=__version__, lifespan=lifespan)
    app.state.runtime = runtime

    @app.exception_handler(HTTPException)
    async def _http(_request: Request, exc: HTTPException):
        return JSONResponse({"error": exc.detail}, status_code=exc.status_code)

    @app.exception_handler(RequestValidationError)
    async def _validation(_request: Request, _exc: RequestValidationError):
        return JSONResponse({"error": "invalid request"}, status_code=422)

    @app.exception_handler(Exception)
    async def _err(_request: Request, exc: Exception):
        log.exception("request failed")
        return JSONResponse({"error": "internal error"}, status_code=500)

    @app.get("/health")
    def health():
        return {"status": "ok", "version": __version__}

    @app.get("/v1/whoami")
    def whoami(who: dict = Depends(viewer)):
        return {"name": who["name"], "role": who["role"], "demo": runtime.settings.demo_mode}

    @app.post("/v1/ingest")
    async def ingest(request: Request, who: dict = Depends(ingest_role)):
        ctype = request.headers.get("content-type", "")
        source: dict = {"transport": "http", "peer": (request.client.host if request.client else "?")}
        if "application/json" in ctype:
            try:
                payload = IngestBody.model_validate(await request.json())
            except (ValueError, json.JSONDecodeError) as exc:
                raise HTTPException(422, "invalid request") from exc
            lines = payload.lines
            if payload.source_hint:
                source["source_hint"] = payload.source_hint[:128]
        else:
            text = (await request.body()).decode("utf-8", errors="replace")
            lines = text.splitlines()
        if len(lines) > runtime.settings.max_http_batch:
            raise HTTPException(413, f"batch exceeds {runtime.settings.max_http_batch} lines")
        if not runtime.limiter.allow(who["name"], cost=max(1, len(lines))):
            raise HTTPException(429, "rate limit exceeded")
        before = runtime.pipeline.stats.snapshot()["counters"].get("dead_letter", 0)
        try:
            out = runtime.ingest(lines, source)
        except InputRejected as exc:
            raise HTTPException(400, str(exc)) from exc
        dead = runtime.pipeline.stats.snapshot()["counters"].get("dead_letter", 0) - before
        runtime.audit.write(who["name"], "ingest", {"accepted": len(out), "dead_letter": dead})
        return {"accepted": len(out), "dead_letter": max(0, dead),
                "uids": [e["metadata"]["uid"] for e in out[:50]]}

    @app.get("/v1/events")
    def events(limit: int = 50, offset: int = 0, pack: str | None = None, src_ip: str | None = None,
               dst_ip: str | None = None, class_uid: int | None = None, severity_min: int | None = None,
               valid: int | None = None, fallback: int | None = None, _who: dict = Depends(viewer)):
        store = _store(runtime)
        filters = {"pack": pack, "src_ip": src_ip, "dst_ip": dst_ip, "class_uid": class_uid,
                   "severity_min": severity_min, "valid": valid, "fallback": True if fallback else None}
        rows = store.query(limit=limit, offset=offset, **filters)
        return {"events": rows, "count": store.count()}

    @app.get("/v1/events/{uid}")
    def event(uid: str, _who: dict = Depends(viewer)):
        row = _store(runtime).get(uid)
        if row is None:
            raise HTTPException(404, "event not found")
        return row

    @app.get("/v1/events/{uid}/verify")
    def verify_event(uid: str, _who: dict = Depends(viewer)):
        row = _store(runtime).get(uid)
        if row is None:
            raise HTTPException(404, "event not found")
        return runtime.ledger.verify_event(row)

    @app.get("/v1/stats")
    def stats(_who: dict = Depends(viewer)):
        store = runtime.store.summary() if runtime.store else None
        return {"pipeline": runtime.pipeline.stats.snapshot(), "store": store,
                "ledger": runtime.ledger.stats(), "unknown_clusters": len(runtime.unknown.list()),
                "packs": len(runtime.registry.packs), "packs_rejected": len(runtime.registry.rejected)}

    @app.get("/v1/dead-letters")
    def dead_letters(_who: dict = Depends(viewer)):
        return {"dead_letters": list(runtime.pipeline.dead_letters)[-100:]}

    @app.get("/v1/ledger")
    def ledger(_who: dict = Depends(viewer)):
        return runtime.ledger.stats()

    @app.get("/v1/ledger/verify")
    def ledger_verify(_who: dict = Depends(viewer)):
        return runtime.ledger.verify_chain()

    @app.post("/v1/ledger/anchors")
    def anchors(who: dict = Depends(admin)):
        path = runtime.settings.data_dir / "anchors.jsonl"
        n = runtime.ledger.export_anchors(path)
        runtime.audit.write(who["name"], "export_anchors", {"count": n})
        return {"exported": n, "path": str(path)}

    @app.get("/v1/packs")
    def packs(who: dict = Depends(viewer)):
        body = {"packs": [_pack_view(p) for p in runtime.registry.packs]}
        if who["role"] == "admin":
            body["rejected"] = runtime.registry.rejected
        return body

    @app.post("/v1/packs/reload")
    def reload_packs(who: dict = Depends(admin)):
        result = runtime.reload_packs()
        runtime.audit.write(who["name"], "reload_packs", result)
        return result

    @app.post("/v1/preview")
    def preview(body: IngestBody, _who: dict = Depends(analyst)):
        if len(body.lines) > 20:
            raise HTTPException(413, "preview is limited to 20 lines")
        source = {"transport": "preview"}
        if body.source_hint:
            source["source_hint"] = body.source_hint[:128]
        try:
            return {"events": runtime.preview(body.lines, source)}
        except InputRejected as exc:
            raise HTTPException(400, str(exc)) from exc

    @app.get("/v1/unknown")
    def unknown(_who: dict = Depends(analyst)):
        return {"clusters": runtime.unknown.list()}

    @app.delete("/v1/unknown/{fp}")
    def drop_unknown(fp: str, who: dict = Depends(analyst)):
        runtime.unknown.drop(fp)
        runtime.audit.write(who["name"], "drop_unknown", {"id": fp})
        return {"dropped": fp}

    @app.post("/v1/unknown/{fp}/synthesize")
    def synthesize_cluster(fp: str, vendor: str | None = None, product: str | None = None,
                           who: dict = Depends(analyst)):
        samples = runtime.unknown.samples(fp)
        if len(samples) < 3:
            raise HTTPException(400, "cluster needs at least 3 samples")
        return _save_draft(runtime, who, samples, vendor, product)

    @app.post("/v1/drafts/synthesize")
    def synthesize_lines(body: SynthesizeBody, who: dict = Depends(analyst)):
        if len(body.lines) > 500:
            raise HTTPException(413, "at most 500 samples")
        return _save_draft(runtime, who, body.lines, body.vendor, body.product)

    @app.get("/v1/drafts")
    def list_drafts(_who: dict = Depends(analyst)):
        return {"drafts": drafts.list_drafts(runtime.settings)}

    @app.get("/v1/drafts/{pack_id}")
    def get_draft(pack_id: str, _who: dict = Depends(analyst)):
        try:
            return drafts.get(pack_id, runtime.settings)
        except FileNotFoundError:
            raise HTTPException(404, "draft not found") from None
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc

    @app.put("/v1/drafts/{pack_id}")
    def edit_draft(pack_id: str, body: YamlBody, who: dict = Depends(analyst)):
        try:
            doc = safe_yaml_load(body.yaml)
            path = drafts.update_yaml(pack_id, body.yaml, runtime.settings)
        except Exception as exc:
            raise HTTPException(400, str(exc)[:300]) from exc
        samples = [t["input"] for t in (doc.get("tests") or []) if isinstance(t, dict) and t.get("input")]
        if len(samples) < 1:
            raise HTTPException(400, "draft tests must keep at least one sample input")
        rep = selftest(doc, samples, runtime.settings, runtime.registry)
        path.with_suffix(".report.json").write_text(json.dumps(rep, indent=1, default=str), encoding="utf-8")
        runtime.audit.write(who["name"], "edit_draft", {"id": pack_id, "passed": rep.get("passed")})
        return {"id": pack_id, "passed": rep.get("passed"), "report": {k: v for k, v in rep.items() if k != "example_event"}}

    @app.post("/v1/drafts/{pack_id}/approve")
    def approve(pack_id: str, who: dict = Depends(admin)):
        try:
            path = drafts.approve(pack_id, who["name"], runtime.settings)
        except FileNotFoundError:
            raise HTTPException(404, "draft not found") from None
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        runtime.reload_packs()
        runtime.audit.write(who["name"], "approve_pack", {"id": pack_id})
        return {"approved": pack_id, "path": path.name, "signed": True}

    @app.post("/v1/drafts/{pack_id}/reject")
    def reject(pack_id: str, who: dict = Depends(analyst)):
        try:
            drafts.reject(pack_id, runtime.settings)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from exc
        runtime.audit.write(who["name"], "reject_draft", {"id": pack_id})
        return {"rejected": pack_id}

    @app.get("/v1/fidelity")
    def fidelity(_who: dict = Depends(viewer)):
        return _report(runtime)

    @app.get("/metrics")
    def metrics(_who: dict = Depends(viewer)):
        snap = runtime.pipeline.stats.snapshot()
        c = snap["counters"]
        lines = [
            "# HELP ulpf_events_processed_total Events normalized since start",
            "# TYPE ulpf_events_processed_total counter",
            f"ulpf_events_processed_total {c.get('processed', 0)}",
            "# HELP ulpf_events_dead_letter_total Events rejected as hostile or unparseable",
            "# TYPE ulpf_events_dead_letter_total counter",
            f"ulpf_events_dead_letter_total {c.get('dead_letter', 0)}",
            "# HELP ulpf_events_fallback_total Events with no matching source pack",
            "# TYPE ulpf_events_fallback_total counter",
            f"ulpf_events_fallback_total {c.get('fallback', 0)}",
            "# HELP ulpf_latency_us Normalization latency",
            "# TYPE ulpf_latency_us gauge",
            f'ulpf_latency_us{{quantile="0.5"}} {snap["latency_us"]["p50"]}',
            f'ulpf_latency_us{{quantile="0.99"}} {snap["latency_us"]["p99"]}',
        ]
        return PlainTextResponse("\n".join(lines) + "\n", media_type="text/plain; version=0.0.4")

    @app.get("/v1/audit")
    def audit(limit: int = 100, _who: dict = Depends(admin)):
        return {"records": runtime.audit.recent(limit), "chain": runtime.audit.verify()}

    @app.post("/v1/demo/tamper")
    def tamper(body: TamperBody, who: dict = Depends(admin)):
        if not runtime.settings.demo_mode:
            raise HTTPException(404, "not found")
        if len(body.raw) > runtime.settings.max_line_bytes:
            raise HTTPException(400, "replacement exceeds max line size")
        ok = _store(runtime).tamper_raw(body.uid, body.raw)
        if not ok:
            raise HTTPException(404, "event not found")
        runtime.audit.write(who["name"], "demo_tamper", {"uid": body.uid})
        return {"tampered": body.uid}

    @app.post("/v1/demo/load-samples")
    def load_samples(who: dict = Depends(admin)):
        root = runtime.settings.samples_dir.resolve()
        if not root.is_dir():
            raise HTTPException(404, "samples directory not found")
        loaded = 0
        files = 0
        for path in sorted(root.rglob("*")):
            if not path.is_file() or path.suffix.lower() not in {".log", ".json", ".jsonl", ".csv", ".txt"}:
                continue
            if not path.resolve().is_relative_to(root):
                continue
            lines = []
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
                if line.strip():
                    lines.append(line)
                if len(lines) >= 30:
                    break
            if lines:
                runtime.ingest(lines, {"transport": "sample", "file": path.name})
                loaded += len(lines)
                files += 1
            if loaded >= 400:
                break
        runtime.audit.write(who["name"], "load_samples", {"files": files, "lines": loaded})
        return {"files": files, "lines": loaded}

    ui = runtime.settings.ui_dir
    if (ui / "index.html").exists():
        app.mount("/assets", StaticFiles(directory=ui), name="assets")

        @app.get("/")
        def index():
            return FileResponse(ui / "index.html")

    wrapped = SecurityHeaders(BodyLimit(app, runtime.settings.max_body_bytes), runtime.settings.hsts)
    return wrapped  # type: ignore[return-value]


def _save_draft(rt: Runtime, who: dict, samples: list[str], vendor: str | None, product: str | None) -> dict:
    try:
        draft = synthesize(samples, rt.settings, vendor, product, use_llm="auto", registry=rt.registry)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    drafts.save(draft, rt.settings)
    rt.audit.write(who["name"], "synthesize", {"id": draft.id, "passed": draft.report.get("passed")})
    report = {k: v for k, v in draft.report.items() if k != "example_event"}
    return {"id": draft.id, "passed": draft.report.get("passed"), "yaml": draft.yaml(), "report": report}
