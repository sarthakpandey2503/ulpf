"""Pack registry: loads, validates, signature-checks and routes source packs.

Trust model
-----------
* Each pack may ship with ``<pack>.yaml.sig`` - an Ed25519 signature over the exact
  YAML bytes, made by a key in the trusted signer set (``keys/pack_signers/*.pub``).
* With ``ULPF_REQUIRE_SIGNED_PACKS=true`` unsigned or tampered packs are refused.
* AI-generated drafts live in a separate drafts directory and are never routed
  until an admin approves (and signs) them.
"""
from __future__ import annotations

import logging
import threading
from pathlib import Path

from .. import crypto
from ..config import Settings
from ..security import safe_yaml_load
from ..sniffer import Sniff
from .engine import CompiledPack, compile_pack
from .schema import validate_pack

log = logging.getLogger("ulpf.packs")


class PackError(ValueError):
    pass


def load_pack_file(path: Path) -> dict:
    doc = safe_yaml_load(path.read_text(encoding="utf-8"))
    if not isinstance(doc, dict):
        raise PackError(f"{path}: not a mapping")
    errs = validate_pack(doc)
    if errs:
        raise PackError(f"{path}: " + "; ".join(errs[:5]))
    return doc


def signers_dir(settings: Settings) -> Path:
    return settings.keys_dir / "pack_signers"


_BUILTIN_SIGNERS = Path(__file__).resolve().parent / "trusted"


def trusted_signers(settings: Settings):
    """Built-in pack signer (shipped with the library) plus runtime signers."""
    pubs = []
    if _BUILTIN_SIGNERS.exists():
        pubs.extend(crypto.load_public(p) for p in sorted(_BUILTIN_SIGNERS.glob("*.pub")))
    d = signers_dir(settings)
    if d.exists():
        pubs.extend(crypto.load_public(p) for p in sorted(d.glob("*.pub")))
    return pubs


def verify_signature(path: Path, signers) -> bool:
    sig = path.with_suffix(path.suffix + ".sig")
    if not sig.exists() or not signers:
        return False
    data = path.read_bytes()
    s = sig.read_text(encoding="utf-8").strip()
    return any(crypto.verify(pub, data, s) for pub in signers)


def sign_pack(path: Path, settings: Settings) -> Path:
    key = crypto.load_or_create(settings.keys_dir, "pack_signer")
    d = signers_dir(settings)
    d.mkdir(parents=True, exist_ok=True)
    (d / "pack_signer.pub").write_text(crypto.public_pem(key), encoding="utf-8")
    sig = path.with_suffix(path.suffix + ".sig")
    sig.write_text(crypto.sign(key, path.read_bytes()), encoding="utf-8")
    return sig


class PackRegistry:
    def __init__(self, settings: Settings):
        self.settings = settings
        self._lock = threading.RLock()
        self.packs: list[CompiledPack] = []
        self.rejected: dict[str, str] = {}

    def load(self, extra_dirs: list[Path] | None = None) -> "PackRegistry":
        dirs = [self.settings.packs_dir, self.settings.approved_dir] + list(extra_dirs or [])
        signers = trusted_signers(self.settings)
        packs: list[CompiledPack] = []
        rejected: dict[str, str] = {}
        for d in dirs:
            if not d.exists():
                continue
            for path in sorted(d.rglob("*.yaml")):
                try:
                    signed = verify_signature(path, signers)
                    if self.settings.require_signed_packs and not signed:
                        raise PackError("unsigned or signature mismatch")
                    doc = load_pack_file(path)
                    cp = compile_pack(doc)
                    cp.signed, cp.path = signed, str(path)
                    prov = doc.get("provenance") or {}
                    cp.trust = 1.0 if prov.get("author", "human") == "human" or prov.get("approved_by") else 0.7
                    packs.append(cp)
                except Exception as exc:  # a bad pack must never take down the pipeline
                    rejected[str(path)] = str(exc)
                    log.warning("pack rejected %s: %s", path, exc)
        packs.sort(key=lambda p: -p.priority)
        with self._lock:
            self.packs, self.rejected = packs, rejected
        return self

    def add(self, cp: CompiledPack) -> None:
        with self._lock:
            self.packs = sorted([p for p in self.packs if p.id != cp.id] + [cp], key=lambda p: -p.priority)

    def get(self, pack_id: str) -> CompiledPack | None:
        return next((p for p in self.packs if p.id == pack_id), None)

    def candidates(self, raw: str, sn: Sniff, source: str | None = None) -> list[CompiledPack]:
        tags = sn.tags
        with self._lock:
            packs = list(self.packs)
        if source:
            pinned = [p for p in packs if source in p.sources]
            if pinned:
                return pinned
        return [p for p in packs if p.matches(raw, tags, source)]
