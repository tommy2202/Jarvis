"""
Test: llama.cpp backend load/unload with mocked llama_cpp.Llama.

No real GGUF model is loaded. Uses a mock Llama class to verify:
- ensure_ready() loads the model
- chat() returns a string
- release() unloads the model and frees resources
- health() reports correctly before/after load
"""
from __future__ import annotations

import sys
import types
from unittest.mock import MagicMock

import pytest


@pytest.fixture()
def mock_llama_cpp(monkeypatch):
    """Inject a fake llama_cpp module so no real model is needed."""
    fake_mod = types.ModuleType("llama_cpp")

    class FakeLlama:
        def __init__(self, **kwargs):
            self.kwargs = kwargs
            self._loaded = True

        def create_chat_completion(self, messages, max_tokens=512, temperature=0.7):
            return {
                "choices": [
                    {"message": {"role": "assistant", "content": '{"reply":"mock_ok"}'}}
                ]
            }

    fake_mod.Llama = FakeLlama
    monkeypatch.setitem(sys.modules, "llama_cpp", fake_mod)

    # Reset the cached module in the llamacpp backend module
    from jarvis.core.llm_backends import llamacpp as lc_mod

    monkeypatch.setattr(lc_mod, "_llama_cpp", None)
    return fake_mod


def test_ensure_ready_loads_model(mock_llama_cpp):
    from jarvis.core.llm_backends.llamacpp import LlamaCppBackend

    backend = LlamaCppBackend(model_path="/fake/model.gguf")
    assert not backend.is_ready()

    backend.ensure_ready()
    assert backend.is_ready()
    assert backend._model is not None


def test_health_reports_correctly(mock_llama_cpp):
    from jarvis.core.llm_backends.llamacpp import LlamaCppBackend

    backend = LlamaCppBackend(model_path="/fake/model.gguf")
    h = backend.health()
    assert h.ok is False
    assert "not_loaded" in h.detail

    backend.ensure_ready()
    h = backend.health()
    assert h.ok is True
    assert "loaded" in h.detail


def test_chat_returns_string(mock_llama_cpp):
    from jarvis.core.llm_backends.llamacpp import LlamaCppBackend

    backend = LlamaCppBackend(model_path="/fake/model.gguf")
    backend.ensure_ready()
    result = backend.chat(
        model="test",
        messages=[{"role": "user", "content": "hi"}],
        options={"temperature": 0.7, "num_predict": 100},
        timeout_seconds=10.0,
        trace_id="test-trace",
    )
    assert isinstance(result, str)
    assert "mock_ok" in result


def test_chat_raises_if_not_loaded(mock_llama_cpp):
    from jarvis.core.llm_backends.llamacpp import LlamaCppBackend

    backend = LlamaCppBackend(model_path="/fake/model.gguf")
    with pytest.raises(RuntimeError, match="not loaded"):
        backend.chat(
            model="test",
            messages=[{"role": "user", "content": "hi"}],
            options={},
            timeout_seconds=10.0,
        )


def test_release_unloads_model(mock_llama_cpp):
    from jarvis.core.llm_backends.llamacpp import LlamaCppBackend

    backend = LlamaCppBackend(model_path="/fake/model.gguf")
    backend.ensure_ready()
    assert backend.is_ready()

    backend.release()
    assert not backend.is_ready()
    assert backend._model is None


def test_ensure_ready_is_idempotent(mock_llama_cpp):
    from jarvis.core.llm_backends.llamacpp import LlamaCppBackend

    backend = LlamaCppBackend(model_path="/fake/model.gguf")
    backend.ensure_ready()
    model_ref = backend._model
    backend.ensure_ready()
    assert backend._model is model_ref  # same instance, no reload


def test_backward_compat_shims(mock_llama_cpp):
    from jarvis.core.llm_backends.llamacpp import LlamaCppBackend

    backend = LlamaCppBackend(model_path="/fake/model.gguf")
    assert backend.start_server() is True
    assert backend.is_server_running() is True
    assert backend.stop_server() is True
    assert backend.is_server_running() is False


def test_timeout_raises_requests_timeout(mock_llama_cpp, monkeypatch):
    """If generation exceeds timeout, a requests.Timeout is raised."""
    import threading

    from jarvis.core.llm_backends.llamacpp import LlamaCppBackend

    backend = LlamaCppBackend(model_path="/fake/model.gguf")
    backend.ensure_ready()

    # Make the model's create_chat_completion block longer than timeout
    import time

    def slow_completion(*a, **kw):
        time.sleep(5)
        return {"choices": [{"message": {"content": "late"}}]}

    backend._model.create_chat_completion = slow_completion

    import requests

    with pytest.raises(requests.Timeout):
        backend.chat(
            model="test",
            messages=[{"role": "user", "content": "hi"}],
            options={},
            timeout_seconds=0.1,
        )
