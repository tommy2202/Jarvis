"""
Test: LLM backend selection based on config.

Verifies that the lifecycle controller routes roles to the correct backend
type (llamacpp vs ollama) based on the role config, and validates the
schema_version requirement.
"""
from __future__ import annotations

import pytest

from jarvis.core.events import EventLogger
from jarvis.core.llm_lifecycle import LLMPolicy, LLMLifecycleController, RoleConfig


class DummyLogger:
    def info(self, *_a, **_k): ...
    def warning(self, *_a, **_k): ...
    def error(self, *_a, **_k): ...


def _make_policy(roles: dict, **kwargs) -> LLMPolicy:
    base = {
        "schema_version": 1,
        "enabled": True,
        "mode": "external",
        "roles": roles,
        "watchdog": {
            "health_check_interval_seconds": 999,
            "restart_on_failure": False,
            "max_restart_attempts": 1,
        },
    }
    base.update(kwargs)
    return LLMPolicy.model_validate(base)


# ── schema_version is required and validated ───────────────────────


def test_policy_requires_schema_version():
    """schema_version must be present and >= 1."""
    policy = _make_policy(
        roles={"chat": {"backend": "ollama", "model": "m", "base_url": "http://x"}}
    )
    assert policy.schema_version >= 1


def test_policy_rejects_zero_schema_version():
    """schema_version=0 should fail validation."""
    with pytest.raises(Exception):
        _make_policy(
            roles={"chat": {"backend": "ollama", "model": "m", "base_url": "http://x"}},
            schema_version=0,
        )


# ── backend selection ──────────────────────────────────────────────


def test_router_selects_ollama_for_ollama_role(tmp_path, monkeypatch):
    """When backend='ollama', _get_backend should instantiate OllamaBackend."""
    policy = _make_policy(
        roles={"chat": {"backend": "ollama", "model": "m", "base_url": "http://x"}}
    )
    ev = EventLogger(str(tmp_path / "ev.jsonl"))
    lc = LLMLifecycleController(policy=policy, event_logger=ev, logger=DummyLogger())
    try:
        backend = lc._get_backend("chat")
        assert backend.name == "ollama"
    finally:
        lc.stop()


def test_router_selects_llamacpp_for_llamacpp_role(tmp_path, monkeypatch):
    """When backend='llamacpp', _get_backend should instantiate LlamaCppBackend."""
    policy = _make_policy(
        roles={
            "chat": {
                "backend": "llamacpp",
                "model": "/fake/model.gguf",
                "model_path": "/fake/model.gguf",
                "base_url": "http://x",
            }
        }
    )
    ev = EventLogger(str(tmp_path / "ev.jsonl"))
    lc = LLMLifecycleController(policy=policy, event_logger=ev, logger=DummyLogger())
    try:
        # Mock the llama_cpp import so it doesn't require the real package
        import sys
        import types

        fake_llama_cpp = types.ModuleType("llama_cpp")

        class FakeLlama:
            def __init__(self, **kwargs):
                self.kwargs = kwargs

        fake_llama_cpp.Llama = FakeLlama
        monkeypatch.setitem(sys.modules, "llama_cpp", fake_llama_cpp)

        backend = lc._get_backend("chat")
        assert backend.name == "llamacpp"
    finally:
        lc.stop()


def test_router_rejects_unknown_backend(tmp_path):
    """Unknown backend type should raise ValueError at factory time."""
    policy = _make_policy(
        roles={"chat": {"backend": "unknown_backend", "model": "m", "base_url": "http://x"}}
    )
    ev = EventLogger(str(tmp_path / "ev.jsonl"))
    lc = LLMLifecycleController(policy=policy, event_logger=ev, logger=DummyLogger())
    try:
        with pytest.raises(ValueError, match="Unsupported backend"):
            lc._get_backend("chat")
    finally:
        lc.stop()


def test_chat_and_coder_can_use_different_backends(tmp_path, monkeypatch):
    """Chat and coder roles can be routed to different backends."""
    policy = _make_policy(
        roles={
            "chat": {
                "backend": "ollama",
                "model": "chat-model",
                "base_url": "http://x",
            },
            "coder": {
                "backend": "llamacpp",
                "model": "/fake/coder.gguf",
                "model_path": "/fake/coder.gguf",
                "base_url": "http://x",
            },
        }
    )
    ev = EventLogger(str(tmp_path / "ev.jsonl"))
    lc = LLMLifecycleController(policy=policy, event_logger=ev, logger=DummyLogger())
    try:
        # Mock llama_cpp
        import sys
        import types

        fake_llama_cpp = types.ModuleType("llama_cpp")

        class FakeLlama:
            def __init__(self, **kwargs):
                self.kwargs = kwargs

        fake_llama_cpp.Llama = FakeLlama
        monkeypatch.setitem(sys.modules, "llama_cpp", fake_llama_cpp)

        chat_backend = lc._get_backend("chat")
        coder_backend = lc._get_backend("coder")
        assert chat_backend.name == "ollama"
        assert coder_backend.name == "llamacpp"
    finally:
        lc.stop()


def test_backend_caching(tmp_path):
    """Same backend config returns same instance (cached)."""
    policy = _make_policy(
        roles={
            "chat": {"backend": "ollama", "model": "m", "base_url": "http://x"},
            "coder": {"backend": "ollama", "model": "m2", "base_url": "http://x"},
        }
    )
    ev = EventLogger(str(tmp_path / "ev.jsonl"))
    lc = LLMLifecycleController(policy=policy, event_logger=ev, logger=DummyLogger())
    try:
        b1 = lc._get_backend("chat")
        b2 = lc._get_backend("chat")
        assert b1 is b2
    finally:
        lc.stop()
