import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from ulpf.config import Settings  # noqa: E402


@pytest.fixture()
def settings(tmp_path):
    s = Settings()
    s.data_dir = tmp_path / "data"
    s.keys_dir = tmp_path / "keys"
    s.drafts_dir = tmp_path / "drafts"
    s.approved_dir = tmp_path / "packs"
    s.tokens_file = tmp_path / "tokens.json"
    s.ensure_dirs()
    return s


@pytest.fixture(scope="session")
def root():
    return ROOT
