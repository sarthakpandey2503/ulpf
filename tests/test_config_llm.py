import json
import os

import pytest

from ulpf.aigen import llm
from ulpf.aigen.llm import LLMUnavailable, OllamaClient
from ulpf.config import load_dotenv


def test_dotenv_fills_unset_and_keeps_existing(tmp_path, monkeypatch):
    env = tmp_path / ".env"
    env.write_text("# comment\nexport ULPF_TEST_NEW=\"from file\"\nULPF_TEST_KEEP=file\nOTHER_VAR=x\n",
                   encoding="utf-8")
    monkeypatch.delenv("ULPF_TEST_NEW", raising=False)
    monkeypatch.delenv("OTHER_VAR", raising=False)
    monkeypatch.setenv("ULPF_TEST_KEEP", "process")
    applied = load_dotenv(env)
    assert os.environ["ULPF_TEST_NEW"] == "from file"
    assert os.environ["ULPF_TEST_KEEP"] == "process"
    assert "OTHER_VAR" not in os.environ
    assert applied == {"ULPF_TEST_NEW": "from file"}
    monkeypatch.delenv("ULPF_TEST_NEW")


class _Stream:
    is_error = False

    def __init__(self, payload: dict):
        self.body = json.dumps(payload).encode()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def iter_bytes(self):
        yield self.body


def _capture(monkeypatch, payload: dict) -> dict:
    seen: dict = {}

    def fake_stream(method, url, headers=None, timeout=None, json=None):
        seen.update(method=method, url=url, headers=headers or {}, json=json)
        return _Stream(payload)

    monkeypatch.setattr(llm.httpx, "stream", fake_stream)
    return seen


def test_lmstudio_used_when_key_set(settings, monkeypatch):
    settings.lmstudio_api_key = "secret-key"
    settings.lmstudio_model = "qwen2.5-coder-7b-instruct"
    seen = _capture(monkeypatch, {"choices": [{"message": {"content": '{"class": "network_activity"}'}}]})
    client = OllamaClient(settings)
    assert client.backend == "lmstudio"
    assert client.generate_json("sys", "prompt") == {"class": "network_activity"}
    assert seen["url"] == "http://127.0.0.1:1234/v1/chat/completions"
    assert seen["headers"]["Authorization"] == "Bearer secret-key"
    assert seen["json"]["model"] == "qwen2.5-coder-7b-instruct"
    assert seen["json"]["messages"][0] == {"role": "system", "content": "sys"}
    assert seen["json"]["response_format"]["type"] == "json_schema"
    assert seen["json"]["reasoning_effort"] == "none"


def test_lmstudio_empty_content_is_unavailable(settings, monkeypatch):
    settings.lmstudio_api_key = "secret-key"
    settings.lmstudio_model = "m"
    _capture(monkeypatch, {"choices": [{"message": {"content": ""}, "finish_reason": "length"}]})
    with pytest.raises(LLMUnavailable, match="no content"):
        OllamaClient(settings).generate_json("sys", "prompt")


def test_lmstudio_requires_model(settings):
    settings.lmstudio_api_key = "secret-key"
    settings.lmstudio_model = ""
    with pytest.raises(LLMUnavailable):
        OllamaClient(settings)


def test_ollama_used_when_key_empty(settings, monkeypatch):
    settings.lmstudio_api_key = ""
    seen = _capture(monkeypatch, {"response": '{"class": "authentication"}'})
    client = OllamaClient(settings)
    assert client.backend == "ollama"
    assert client.generate_json("sys", "prompt") == {"class": "authentication"}
    assert seen["url"] == f"{settings.ollama_url.rstrip('/')}/api/generate"
    assert "Authorization" not in seen["headers"]
