"""API tokens. Only SHA-256 hashes are stored; comparison is constant-time.

Token file (also written by ``deploy/make-secrets.sh``)::

    {"tokens": [{"name": "admin", "role": "admin", "sha256": "<hex>"}]}

Roles: ``viewer`` < ``analyst`` < ``admin``. ``ingest`` may only submit logs.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from pathlib import Path

from .config import Settings

ROLES = ("viewer", "analyst", "admin", "ingest")
_RANK = {"viewer": 1, "analyst": 2, "admin": 3}


class AuthError(ValueError):
    pass


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def allows(role: str, need: str) -> bool:
    if need == "ingest":
        return role in ("ingest", "analyst", "admin")
    if role == "ingest":
        return False
    return _RANK.get(role, 0) >= _RANK.get(need, 99)


class TokenStore:
    def __init__(self, settings: Settings):
        self.path: Path = settings.tokens_file
        self.entries: list[dict] = []
        self.bootstrap_plaintext: str | None = None
        if not self.path.exists():
            self._bootstrap()
        else:
            self._load()

    def _load(self) -> None:
        try:
            doc = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise AuthError(f"cannot read token file {self.path}: {exc}") from exc
        entries = doc.get("tokens") if isinstance(doc, dict) else None
        if not isinstance(entries, list) or not entries:
            raise AuthError(f"token file {self.path} has no tokens")
        clean = []
        for e in entries:
            if not isinstance(e, dict) or e.get("role") not in ROLES or not isinstance(e.get("sha256"), str):
                raise AuthError("token entry must have role and sha256")
            if len(e["sha256"]) != 64:
                raise AuthError("token hash must be sha256 hex")
            clean.append({"name": str(e.get("name") or e["role"])[:64], "role": e["role"], "sha256": e["sha256"]})
        self.entries = clean

    def _bootstrap(self) -> None:
        token = secrets.token_urlsafe(24)
        self.entries = [{"name": "admin", "role": "admin", "sha256": hash_token(token)}]
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._write()
        self.bootstrap_plaintext = token

    def _write(self) -> None:
        self.path.write_text(json.dumps({"tokens": self.entries}, indent=2) + "\n", encoding="utf-8")
        try:
            self.path.chmod(0o600)
        except OSError:
            pass

    def check(self, token: str) -> dict | None:
        if not token or len(token) > 512:
            return None
        digest = hash_token(token)
        found = None
        for entry in self.entries:
            if hmac.compare_digest(digest, entry["sha256"]):
                found = {"name": entry["name"], "role": entry["role"]}
        return found
