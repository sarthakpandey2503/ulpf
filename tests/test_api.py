import json

from fastapi.testclient import TestClient

from ulpf.api import create_app
from ulpf.auth import hash_token
from ulpf.runtime import Runtime

FGT = ('<189>date=2026-09-28 time=10:15:02 devname="FGT" devid="FG1" logid="0000000013" type="traffic" '
       'subtype="forward" level="notice" srcip=10.0.0.1 srcport=1234 dstip=8.8.8.8 dstport=53 proto=17 action="accept"')


def _tokens(path):
    plain = {"admin": "admin-token-value", "viewer": "viewer-token-value", "ingest": "ingest-token-value"}
    roles = {"admin": "admin", "viewer": "viewer", "ingest": "ingest"}
    path.write_text(json.dumps({"tokens": [
        {"name": name, "role": roles[name], "sha256": hash_token(token)} for name, token in plain.items()
    ]}), encoding="utf-8")
    return plain


def _client(settings, **extra):
    settings.sinks = ["sqlite"]
    for k, v in extra.items():
        setattr(settings, k, v)
    _tokens(settings.tokens_file)
    rt = Runtime(settings)
    return TestClient(create_app(rt)), rt


def test_health_is_public_and_locked_down(settings):
    client, _rt = _client(settings)
    res = client.get("/health")
    assert res.status_code == 200
    assert res.json()["status"] == "ok"
    assert res.headers["x-frame-options"] == "DENY"
    assert "default-src 'self'" in res.headers["content-security-policy"]
    assert client.get("/v1/events").status_code == 401
    assert client.get("/").status_code == 200
    assert "Live events" in client.get("/").text


def test_roles_ingest_and_verify(settings):
    client, _rt = _client(settings)
    viewer = {"Authorization": "Bearer viewer-token-value"}
    ingest = {"Authorization": "Bearer ingest-token-value"}
    assert client.post("/v1/ingest", json={"lines": [FGT]}, headers=viewer).status_code == 403
    res = client.post("/v1/ingest", json={"lines": [FGT]}, headers=ingest)
    assert res.status_code == 200, res.text
    uid = res.json()["uids"][0]
    assert client.get(f"/v1/events/{uid}", headers=ingest).status_code == 403
    event = client.get(f"/v1/events/{uid}", headers=viewer).json()
    assert event["ulpf"]["pack"].startswith("fortinet.fortigate")
    assert event["raw_data"] == FGT
    proof = client.get(f"/v1/events/{uid}/verify", headers=viewer).json()
    assert proof["verified"] is True
    assert client.get("/metrics", headers=viewer).status_code == 200


def test_demo_tamper_breaks_proof_and_is_hidden_otherwise(settings):
    client, _rt = _client(settings, demo_mode=False)
    admin = {"Authorization": "Bearer admin-token-value"}
    uid = client.post("/v1/ingest", json={"lines": [FGT]}, headers=admin).json()["uids"][0]
    assert client.post("/v1/demo/tamper", json={"uid": uid, "raw": "tampered"}, headers=admin).status_code == 404

    client, _rt = _client(settings, demo_mode=True)
    admin = {"Authorization": "Bearer admin-token-value"}
    uid = client.post("/v1/ingest", json={"lines": [FGT]}, headers=admin).json()["uids"][0]
    assert client.post("/v1/demo/tamper", json={"uid": uid, "raw": FGT + " x"}, headers=admin).status_code == 200
    proof = client.get(f"/v1/events/{uid}/verify", headers=admin).json()
    assert proof["verified"] is False
    assert proof["checks"]["raw_bytes_match"] is False


def test_body_limit(settings):
    client, _rt = _client(settings, max_body_bytes=64)
    admin = {"Authorization": "Bearer admin-token-value"}
    res = client.post("/v1/ingest", content=b'{"lines":["' + b"A" * 200 + b'"]}', headers={**admin, "content-type": "application/json"})
    assert res.status_code == 413


def test_load_samples(settings, root):
    settings.samples_dir = root / "samples"
    client, _rt = _client(settings)
    admin = {"Authorization": "Bearer admin-token-value"}
    res = client.post("/v1/demo/load-samples", headers=admin)
    assert res.status_code == 200, res.text
    assert res.json()["lines"] > 10
    events = client.get("/v1/events?limit=50", headers=admin).json()["events"]
    assert events
