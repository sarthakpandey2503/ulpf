"""Runtime configuration, read from ``ULPF_*`` environment variables.

Secrets (API tokens, signing keys) are read from files so they can be mounted as
Docker secrets rather than passed through the environment or baked into images.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _env(name: str, default: str) -> str:
    return os.environ.get(f"ULPF_{name}", default)


def _int(name: str, default: int) -> int:
    return int(_env(name, str(default)))


def _list(name: str, default: str) -> list[str]:
    return [x.strip() for x in _env(name, default).split(",") if x.strip()]


@dataclass
class Settings:
    data_dir: Path = field(default_factory=lambda: Path(_env("DATA_DIR", str(ROOT / "data"))))
    packs_dir: Path = field(default_factory=lambda: Path(_env("PACKS_DIR", str(ROOT / "ulpf" / "packs" / "library"))))
    drafts_dir: Path = field(default_factory=lambda: Path(_env("DRAFTS_DIR", str(ROOT / "data" / "drafts"))))
    approved_dir: Path = field(default_factory=lambda: Path(_env("APPROVED_PACKS_DIR", str(ROOT / "data" / "packs"))))
    keys_dir: Path = field(default_factory=lambda: Path(_env("KEYS_DIR", str(ROOT / "data" / "keys"))))

    # Input hardening
    max_line_bytes: int = field(default_factory=lambda: _int("MAX_LINE_BYTES", 65536))
    max_json_depth: int = field(default_factory=lambda: _int("MAX_JSON_DEPTH", 32))
    max_fields: int = field(default_factory=lambda: _int("MAX_FIELDS", 1024))
    max_http_batch: int = field(default_factory=lambda: _int("MAX_HTTP_BATCH", 5000))
    rate_limit_eps: int = field(default_factory=lambda: _int("RATE_LIMIT_EPS", 50000))

    # Lineage
    batch_size: int = field(default_factory=lambda: _int("BATCH_SIZE", 256))
    require_signed_packs: bool = field(default_factory=lambda: _env("REQUIRE_SIGNED_PACKS", "false").lower() == "true")

    # Transport / sinks
    bus: str = field(default_factory=lambda: _env("BUS", "memory"))  # memory | kafka
    kafka_bootstrap: str = field(default_factory=lambda: _env("KAFKA_BOOTSTRAP", "localhost:9092"))
    sinks: list[str] = field(default_factory=lambda: _list("SINKS", "sqlite"))
    clickhouse_url: str = field(default_factory=lambda: _env("CLICKHOUSE_URL", "http://localhost:8123"))
    s3_endpoint: str = field(default_factory=lambda: _env("S3_ENDPOINT", ""))
    s3_bucket: str = field(default_factory=lambda: _env("S3_BUCKET", "ulpf-lake"))
    splunk_hec_url: str = field(default_factory=lambda: _env("SPLUNK_HEC_URL", ""))
    elastic_url: str = field(default_factory=lambda: _env("ELASTIC_URL", ""))
    cef_forward: str = field(default_factory=lambda: _env("CEF_FORWARD", ""))  # host:port
    tls_verify: bool = field(default_factory=lambda: _env("TLS_VERIFY", "true").lower() != "false")

    # AI parser generator (local only)
    ollama_url: str = field(default_factory=lambda: _env("OLLAMA_URL", "http://localhost:11434"))
    ollama_model: str = field(default_factory=lambda: _env("OLLAMA_MODEL", "qwen2.5-coder:7b"))
    # Raw log samples are sensitive: the LLM endpoint must be loopback / in-cluster unless explicitly allowed.
    ollama_allowed_hosts: list[str] = field(default_factory=lambda: _list(
        "OLLAMA_ALLOWED_HOSTS", "localhost,127.0.0.1,::1,ollama"))

    # API security
    tokens_file: Path = field(default_factory=lambda: Path(_env("TOKENS_FILE", str(ROOT / "data" / "tokens.json"))))
    cors_origins: list[str] = field(default_factory=lambda: _list("CORS_ORIGINS", ""))
    ui_dir: Path = field(default_factory=lambda: Path(_env("UI_DIR", str(ROOT / "ui"))))
    samples_dir: Path = field(default_factory=lambda: Path(_env("SAMPLES_DIR", str(ROOT / "samples"))))
    max_body_bytes: int = field(default_factory=lambda: _int("MAX_BODY_BYTES", 8_000_000))
    demo_mode: bool = field(default_factory=lambda: _env("DEMO", "false").lower() == "true")
    hsts: bool = field(default_factory=lambda: _env("HSTS", "false").lower() == "true")

    def ensure_dirs(self) -> None:
        for d in (self.data_dir, self.drafts_dir, self.approved_dir, self.keys_dir):
            d.mkdir(parents=True, exist_ok=True)
        try:
            self.keys_dir.chmod(0o700)
        except OSError:
            pass


def secret_from_file(name: str) -> str | None:
    """Read ``ULPF_<NAME>_FILE`` (Docker secret) or fall back to ``ULPF_<NAME>``."""
    path = os.environ.get(f"ULPF_{name}_FILE")
    if path and Path(path).exists():
        return Path(path).read_text(encoding="utf-8").strip()
    return os.environ.get(f"ULPF_{name}")


settings = Settings()
