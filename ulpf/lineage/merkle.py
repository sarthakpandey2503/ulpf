"""Binary Merkle tree over SHA-256 with domain separation (RFC 6962 style).

Leaves are ``H(0x00 || data)`` and interior nodes ``H(0x01 || left || right)`` so a
leaf can never be confused with an interior node (second-preimage defence).
"""
from __future__ import annotations

import hashlib


def leaf_hash(data: bytes) -> bytes:
    return hashlib.sha256(b"\x00" + data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    return hashlib.sha256(b"\x01" + left + right).digest()


def build_levels(leaves: list[bytes]) -> list[list[bytes]]:
    if not leaves:
        return [[hashlib.sha256(b"").digest()]]
    levels = [list(leaves)]
    while len(levels[-1]) > 1:
        cur = levels[-1]
        nxt = []
        for i in range(0, len(cur), 2):
            if i + 1 < len(cur):
                nxt.append(node_hash(cur[i], cur[i + 1]))
            else:
                nxt.append(cur[i])  # odd node is promoted unchanged
        levels.append(nxt)
    return levels


def root(leaves: list[bytes]) -> bytes:
    return build_levels(leaves)[-1][0]


def proof(levels: list[list[bytes]], index: int) -> list[tuple[str, str]]:
    """Audit path as [(side, hex_hash)], side is 'L' or 'R' for the sibling."""
    path: list[tuple[str, str]] = []
    for level in levels[:-1]:
        sib = index ^ 1
        if sib < len(level):
            path.append(("L" if sib < index else "R", level[sib].hex()))
        index //= 2
    return path


def verify_proof(leaf: bytes, path: list[tuple[str, str]], expected_root: bytes) -> bool:
    h = leaf
    for side, sib_hex in path:
        sib = bytes.fromhex(sib_hex)
        h = node_hash(sib, h) if side == "L" else node_hash(h, sib)
    return h == expected_root
