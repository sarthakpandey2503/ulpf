"""Tamper-evident lineage ledger.

For every event:   leaf = H(0x00 || sha256(raw) || sha256(canonical normalized event))
For every batch:   root = Merkle(leaves);  chain = sha256(prev_chain || root || batch meta)
                   signature = Ed25519(chain)

Changing a raw byte, a normalized field, a ledger row, or reordering batches breaks
verification. The signing key lives outside the database (``keys/ledger.key``),
so rewriting the whole chain requires the key as well. Signed roots can be exported
to write-once media (``export_anchors``) for independent audit.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
import time
from pathlib import Path

from .. import crypto
from ..config import Settings
from ..normalizer.envelope import sha256_hex
from . import merkle

_LEDGER_KEYS = ("batch_id", "merkle_leaf", "norm_sha256")
GENESIS = "0" * 64


def canonical_digest(event: dict) -> str:
    """SHA-256 of the normalized event with ledger bookkeeping fields removed."""
    ulpf = {k: v for k, v in event.get("ulpf", {}).items() if k not in _LEDGER_KEYS}
    body = {**event, "ulpf": ulpf}
    data = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)
    return hashlib.sha256(data.encode("utf-8", errors="surrogateescape")).hexdigest()


def _chain(prev: str, root_hex: str, batch_id: int, count: int, created_ms: int) -> str:
    return hashlib.sha256(f"{prev}|{root_hex}|{batch_id}|{count}|{created_ms}".encode()).hexdigest()


class Ledger:
    def __init__(self, settings: Settings, path: Path | None = None):
        settings.ensure_dirs()
        self.path = path or settings.data_dir / "ledger.db"
        self._lock = threading.Lock()
        self._db = sqlite3.connect(self.path, check_same_thread=False, isolation_level=None)
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.executescript("""
            CREATE TABLE IF NOT EXISTS batches (
                batch_id INTEGER PRIMARY KEY, created_ms INTEGER NOT NULL, count INTEGER NOT NULL,
                merkle_root TEXT NOT NULL, prev_chain TEXT NOT NULL, chain_hash TEXT NOT NULL,
                signature TEXT NOT NULL, key_id TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS leaves (
                event_uid TEXT PRIMARY KEY, batch_id INTEGER NOT NULL, leaf_index INTEGER NOT NULL,
                raw_sha256 TEXT NOT NULL, norm_sha256 TEXT NOT NULL, leaf_hash TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS leaves_batch ON leaves(batch_id, leaf_index);
            CREATE TRIGGER IF NOT EXISTS batches_no_update BEFORE UPDATE ON batches
                BEGIN SELECT RAISE(ABORT, 'ledger is append-only'); END;
            CREATE TRIGGER IF NOT EXISTS batches_no_delete BEFORE DELETE ON batches
                BEGIN SELECT RAISE(ABORT, 'ledger is append-only'); END;
            CREATE TRIGGER IF NOT EXISTS leaves_no_update BEFORE UPDATE ON leaves
                BEGIN SELECT RAISE(ABORT, 'ledger is append-only'); END;
            CREATE TRIGGER IF NOT EXISTS leaves_no_delete BEFORE DELETE ON leaves
                BEGIN SELECT RAISE(ABORT, 'ledger is append-only'); END;
        """)
        self._key = crypto.load_or_create(settings.keys_dir, "ledger")
        self.public_pem = crypto.public_pem(self._key)
        self.key_id = hashlib.sha256(self.public_pem.encode()).hexdigest()[:16]
        self._pub = self._key.public_key()
        self.batch_size = settings.batch_size

    # ------------------------------------------------------------------ write
    def append(self, events: list[dict]) -> list[int]:
        ids = []
        for i in range(0, len(events), self.batch_size):
            ids.append(self._seal(events[i:i + self.batch_size]))
        return ids

    def _seal(self, events: list[dict]) -> int:
        with self._lock:
            row = self._db.execute("SELECT batch_id, chain_hash FROM batches ORDER BY batch_id DESC LIMIT 1").fetchone()
            batch_id = (row[0] + 1) if row else 1
            prev = row[1] if row else GENESIS
            leaves, rows = [], []
            for idx, e in enumerate(events):
                raw_sha = e["ulpf"]["raw_sha256"]
                norm_sha = canonical_digest(e)
                leaf = merkle.leaf_hash(bytes.fromhex(raw_sha) + bytes.fromhex(norm_sha))
                leaves.append(leaf)
                rows.append((e["metadata"]["uid"], batch_id, idx, raw_sha, norm_sha, leaf.hex()))
                e["ulpf"].update(batch_id=batch_id, merkle_leaf=idx, norm_sha256=norm_sha)
            root_hex = merkle.root(leaves).hex()
            created = int(time.time() * 1000)
            chain = _chain(prev, root_hex, batch_id, len(events), created)
            sig = crypto.sign(self._key, bytes.fromhex(chain))
            self._db.execute("BEGIN")
            try:
                self._db.executemany("INSERT INTO leaves VALUES (?,?,?,?,?,?)", rows)
                self._db.execute("INSERT INTO batches VALUES (?,?,?,?,?,?,?,?)",
                                 (batch_id, created, len(events), root_hex, prev, chain, sig, self.key_id))
                self._db.execute("COMMIT")
            except Exception:
                self._db.execute("ROLLBACK")
                raise
            return batch_id

    # ----------------------------------------------------------------- verify
    def verify_event(self, event: dict) -> dict:
        """Full proof: raw bytes -> leaf -> Merkle root -> hash chain -> signature."""
        uid = event.get("metadata", {}).get("uid")
        checks: dict[str, bool] = {}
        out: dict = {"event_uid": uid, "checks": checks}
        with self._lock:
            leaf_row = self._db.execute(
                "SELECT batch_id, leaf_index, raw_sha256, norm_sha256, leaf_hash FROM leaves WHERE event_uid=?",
                (uid,)).fetchone()
            if not leaf_row:
                out.update(verified=False, reason="event not in ledger")
                return out
            batch_id, idx, raw_sha, norm_sha, leaf_hex = leaf_row
            batch = self._db.execute(
                "SELECT created_ms, count, merkle_root, prev_chain, chain_hash, signature, key_id FROM batches "
                "WHERE batch_id=?", (batch_id,)).fetchone()
            leaf_hexes = [r[0] for r in self._db.execute(
                "SELECT leaf_hash FROM leaves WHERE batch_id=? ORDER BY leaf_index", (batch_id,))]
            prev_row = self._db.execute("SELECT chain_hash FROM batches WHERE batch_id=?", (batch_id - 1,)).fetchone()
        created, count, root_hex, prev_chain, chain_hash, sig, key_id = batch

        checks["raw_bytes_match"] = sha256_hex(event.get("raw_data", "")) == raw_sha == event["ulpf"].get("raw_sha256")
        checks["normalized_event_match"] = canonical_digest(event) == norm_sha
        leaf = merkle.leaf_hash(bytes.fromhex(raw_sha) + bytes.fromhex(norm_sha))
        checks["leaf_consistent"] = leaf.hex() == leaf_hex
        levels = merkle.build_levels([bytes.fromhex(h) for h in leaf_hexes])
        path = merkle.proof(levels, idx)
        checks["merkle_proof"] = merkle.verify_proof(leaf, path, bytes.fromhex(root_hex)) and len(leaf_hexes) == count
        checks["chain_link"] = _chain(prev_chain, root_hex, batch_id, count, created) == chain_hash and \
            (prev_row[0] if prev_row else GENESIS) == prev_chain
        checks["signature"] = crypto.verify(self._pub, bytes.fromhex(chain_hash), sig)
        out.update(verified=all(checks.values()), batch_id=batch_id, leaf_index=idx, merkle_root=root_hex,
                   chain_hash=chain_hash, signature=sig, key_id=key_id, merkle_path=path)
        return out

    def verify_chain(self) -> dict:
        """Walk the whole chain from genesis; detects any rewritten/removed batch."""
        prev = GENESIS
        n = 0
        with self._lock:
            rows = self._db.execute("SELECT batch_id, created_ms, count, merkle_root, prev_chain, chain_hash, signature "
                                    "FROM batches ORDER BY batch_id").fetchall()
            for batch_id, created, count, root_hex, prev_chain, chain_hash, sig in rows:
                leaf_hexes = [r[0] for r in self._db.execute(
                    "SELECT leaf_hash FROM leaves WHERE batch_id=? ORDER BY leaf_index", (batch_id,))]
                ok = (prev_chain == prev and batch_id == n + 1
                      and merkle.root([bytes.fromhex(h) for h in leaf_hexes]).hex() == root_hex
                      and len(leaf_hexes) == count
                      and _chain(prev, root_hex, batch_id, count, created) == chain_hash
                      and crypto.verify(self._pub, bytes.fromhex(chain_hash), sig))
                if not ok:
                    return {"verified": False, "failed_batch": batch_id, "batches_checked": n}
                prev, n = chain_hash, n + 1
        return {"verified": True, "batches_checked": n, "head": prev}

    def stats(self) -> dict:
        with self._lock:
            b = self._db.execute("SELECT COUNT(*), COALESCE(SUM(count),0), MAX(chain_hash) FROM batches").fetchone()
            head = self._db.execute("SELECT batch_id, chain_hash FROM batches ORDER BY batch_id DESC LIMIT 1").fetchone()
        return {"batches": b[0], "events": b[1], "head_batch": head[0] if head else 0,
                "head_chain": head[1] if head else GENESIS, "key_id": self.key_id}

    def export_anchors(self, out: Path, since_batch: int = 0) -> int:
        """Append signed batch roots to an external JSONL file (copy to WORM media)."""
        with self._lock:
            rows = self._db.execute("SELECT batch_id, created_ms, count, merkle_root, chain_hash, signature, key_id "
                                    "FROM batches WHERE batch_id>? ORDER BY batch_id", (since_batch,)).fetchall()
        with out.open("a", encoding="utf-8") as fh:
            for r in rows:
                fh.write(json.dumps(dict(zip(["batch_id", "created_ms", "count", "merkle_root", "chain_hash",
                                              "signature", "key_id"], r))) + "\n")
        return len(rows)
