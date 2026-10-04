"""Ed25519 key management for pack signing and ledger (Merkle root) signing."""
from __future__ import annotations

import base64
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


def generate(keys_dir: Path, name: str) -> tuple[Path, Path]:
    keys_dir.mkdir(parents=True, exist_ok=True)
    priv_path, pub_path = keys_dir / f"{name}.key", keys_dir / f"{name}.pub"
    key = Ed25519PrivateKey.generate()
    priv_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                            serialization.NoEncryption()))
    priv_path.chmod(0o600)
    pub_path.write_bytes(key.public_key().public_bytes(serialization.Encoding.PEM,
                                                       serialization.PublicFormat.SubjectPublicKeyInfo))
    return priv_path, pub_path


def load_or_create(keys_dir: Path, name: str) -> Ed25519PrivateKey:
    priv_path = keys_dir / f"{name}.key"
    if not priv_path.exists():
        generate(keys_dir, name)
    return serialization.load_pem_private_key(priv_path.read_bytes(), password=None)  # type: ignore[return-value]


def load_public(path: Path) -> Ed25519PublicKey:
    return serialization.load_pem_public_key(path.read_bytes())  # type: ignore[return-value]


def public_pem(key: Ed25519PrivateKey) -> str:
    return key.public_key().public_bytes(serialization.Encoding.PEM,
                                         serialization.PublicFormat.SubjectPublicKeyInfo).decode()


def sign(key: Ed25519PrivateKey, data: bytes) -> str:
    return base64.b64encode(key.sign(data)).decode()


def verify(pub: Ed25519PublicKey, data: bytes, signature_b64: str) -> bool:
    try:
        pub.verify(base64.b64decode(signature_b64), data)
        return True
    except (InvalidSignature, ValueError):
        return False
