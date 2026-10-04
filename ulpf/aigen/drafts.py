"""Draft pack lifecycle: save -> review -> approve (sign + activate) / reject."""
from __future__ import annotations

import json
import re
import time
from pathlib import Path

import yaml

from ..config import Settings
from ..packs.loader import load_pack_file, sign_pack
from ..security import safe_yaml_load
from .synth import Draft

_ID = re.compile(r"^[a-z0-9_\-]+(\.[a-z0-9_\-]+)+$")


def _check_id(pack_id: str) -> str:
    if not _ID.match(pack_id or ""):  # also blocks path traversal
        raise ValueError("invalid pack id")
    return pack_id


def save(draft: Draft, settings: Settings) -> Path:
    settings.drafts_dir.mkdir(parents=True, exist_ok=True)
    pid = _check_id(draft.id)
    path = settings.drafts_dir / f"{pid}.yaml"
    path.write_text(draft.yaml(), encoding="utf-8")
    rep = {k: v for k, v in draft.report.items() if k != "example_event"}
    rep["example_event"] = draft.report.get("example_event")
    (settings.drafts_dir / f"{pid}.report.json").write_text(json.dumps(rep, indent=1, default=str), encoding="utf-8")
    return path


def list_drafts(settings: Settings) -> list[dict]:
    out = []
    for p in sorted(settings.drafts_dir.glob("*.yaml")):
        rp = p.with_suffix(".report.json")
        rep = json.loads(rp.read_text()) if rp.exists() else {}
        out.append({"id": p.stem, "passed": rep.get("passed"), "parse_rate": rep.get("parse_rate"),
                    "ocsf_valid_rate": rep.get("ocsf_valid_rate"),
                    "avg_mapped_attributes": rep.get("avg_mapped_attributes"),
                    "modified_ms": int(p.stat().st_mtime * 1000)})
    return out


def get(pack_id: str, settings: Settings) -> dict:
    pid = _check_id(pack_id)
    p = settings.drafts_dir / f"{pid}.yaml"
    if not p.exists():
        raise FileNotFoundError(pid)
    rp = p.with_suffix(".report.json")
    return {"id": pid, "yaml": p.read_text(encoding="utf-8"),
            "report": json.loads(rp.read_text()) if rp.exists() else {}}


def update_yaml(pack_id: str, text: str, settings: Settings) -> Path:
    """Analyst edits a draft; the YAML must still pass the strict pack schema."""
    pid = _check_id(pack_id)
    doc = safe_yaml_load(text)
    if not isinstance(doc, dict) or doc.get("id") != pid:
        raise ValueError("pack id cannot change during review")
    p = settings.drafts_dir / f"{pid}.yaml"
    tmp = p.with_suffix(".yaml.tmp")
    tmp.write_text(text, encoding="utf-8")
    try:
        load_pack_file(tmp)
    except Exception:
        tmp.unlink()
        raise
    tmp.replace(p)
    return p


def approve(pack_id: str, approver: str, settings: Settings) -> Path:
    pid = _check_id(pack_id)
    src = settings.drafts_dir / f"{pid}.yaml"
    doc = load_pack_file(src)  # strict schema validation again
    rp = src.with_suffix(".report.json")
    rep = json.loads(rp.read_text()) if rp.exists() else {}
    if not rep.get("passed"):
        raise ValueError("draft has not passed self-test; fix it before approval")
    prov = dict(doc.get("provenance") or {})
    prov.update(approved_by=approver, approved_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    doc["provenance"] = prov
    doc["version"] = "1.0" if str(doc.get("version", "0")).startswith("0") else doc["version"]
    settings.approved_dir.mkdir(parents=True, exist_ok=True)
    dst = settings.approved_dir / f"{pid}.yaml"
    dst.write_text(f"# Approved by {approver}. Signed with the ULPF pack-signing key.\n"
                   + yaml.safe_dump(doc, sort_keys=False, allow_unicode=True, width=200), encoding="utf-8")
    sign_pack(dst, settings)
    src.unlink()
    if rp.exists():
        rp.rename(settings.approved_dir / f"{pid}.report.json")
    return dst


def reject(pack_id: str, settings: Settings) -> None:
    pid = _check_id(pack_id)
    for suffix in (".yaml", ".report.json"):
        p = settings.drafts_dir / f"{pid}{suffix}"
        if p.exists():
            p.unlink()
