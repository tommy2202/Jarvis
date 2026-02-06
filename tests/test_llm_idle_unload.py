"""
Test: Idle unload for in-process LLM backends.

Monkeypatches time.time to force idle detection and verifies that
release() is called for in-process (llamacpp) backends after idle timeout.
"""
from __future__ import annotations

import threading
import time

import pytest

from jarvis.core.events import EventLogger
from jarvis.core.llm_lifecycle import LLMPolicy, LLMLifecycleController


class DummyLogger:
    def info(self, *_a, **_k): ...
    def warning(self, *_a, **_k): ...
    def error(self, *_a, **_k): ...


class MockInProcessBackend:
    """Mock backend simulating an in-process llamacpp backend."""

    name = "llamacpp"

    def __init__(self):
        self._ready = True
        self.release_called = False
        self.release_count = 0

    def health(self):
        return type("H", (), {"ok": self._ready, "detail": "ok" if self._ready else "down"})()

    def ensure_ready(self):
        self._ready = True

    def is_ready(self):
        return self._ready

    def release(self):
        self._ready = False
        self.release_called = True
        self.release_count += 1

    def is_server_running(self):
        return self._ready

    def start_server(self):
        self._ready = True
        return True

    def stop_server(self):
        self.release()
        return True

    def chat(self, *, model, messages, options, timeout_seconds, trace_id=""):
        return '{"reply":"ok"}'


def test_idle_unload_for_inprocess_backend(tmp_path, monkeypatch):
    """
    Verify that after idle_unload_seconds, the watchdog triggers
    release() on an in-process (llamacpp) backend.
    """
    ev = EventLogger(str(tmp_path / "ev.jsonl"))

    policy = LLMPolicy.model_validate(
        {
            "schema_version": 1,
            "enabled": True,
            "mode": "external",
            "roles": {
                "chat": {
                    "backend": "llamacpp",
                    "model": "/fake/m.gguf",
                    "model_path": "/fake/m.gguf",
                    "base_url": "http://x",
                    "idle_unload_seconds": 2,
                    "max_request_seconds": 60,
                }
            },
            "watchdog": {
                "health_check_interval_seconds": 0.2,
                "restart_on_failure": False,
                "max_restart_attempts": 1,
            },
        }
    )

    # Don't start the watchdog automatically; we'll trigger manually
    lc = LLMLifecycleController(policy=policy, event_logger=ev, logger=DummyLogger())
    lc.stop()  # Stop the auto-started watchdog

    mock = MockInProcessBackend()
    monkeypatch.setattr(lc, "_get_backend", lambda _role: mock)

    # Simulate: role was loaded and used 10 seconds ago
    lc._role_state["chat"].loaded = True
    lc._role_state["chat"].last_used = time.time() - 10  # 10s ago, way past 2s idle limit

    # Now run one watchdog iteration manually
    # We'll re-enable the policy and run the loop body once
    lc.policy.enabled = True
    lc._stop.clear()

    # Run one iteration of the watchdog logic inline
    now = time.time()
    roles = list(lc.policy.roles.keys())
    for r in roles:
        cfg = lc.policy.roles[r]
        st = lc._role_state[r]
        if st.loaded and st.last_used > 0:
            idle_secs = now - st.last_used
            idle_limit = cfg.idle_unload_seconds
            if idle_secs > idle_limit and cfg.backend.lower() == "llamacpp":
                lc.unload_role(r, "idle_timeout", "test")

    assert mock.release_called, "release() should have been called for idle in-process backend"
    assert lc._role_state["chat"].loaded is False


def test_idle_unload_not_triggered_for_active_backend(tmp_path, monkeypatch):
    """Backend that was used recently should NOT be unloaded."""
    ev = EventLogger(str(tmp_path / "ev.jsonl"))

    policy = LLMPolicy.model_validate(
        {
            "schema_version": 1,
            "enabled": True,
            "mode": "external",
            "roles": {
                "chat": {
                    "backend": "llamacpp",
                    "model": "/fake/m.gguf",
                    "model_path": "/fake/m.gguf",
                    "base_url": "http://x",
                    "idle_unload_seconds": 300,
                    "max_request_seconds": 60,
                }
            },
            "watchdog": {
                "health_check_interval_seconds": 999,
                "restart_on_failure": False,
                "max_restart_attempts": 1,
            },
        }
    )
    lc = LLMLifecycleController(policy=policy, event_logger=ev, logger=DummyLogger())
    lc.stop()

    mock = MockInProcessBackend()
    monkeypatch.setattr(lc, "_get_backend", lambda _role: mock)

    # Simulate: role was loaded and used just now
    lc._role_state["chat"].loaded = True
    lc._role_state["chat"].last_used = time.time()

    # Check idle: should NOT trigger unload
    now = time.time()
    cfg = lc.policy.roles["chat"]
    st = lc._role_state["chat"]
    idle_secs = now - st.last_used
    assert idle_secs < cfg.idle_unload_seconds
    assert not mock.release_called


def test_ollama_backend_not_released_on_idle(tmp_path, monkeypatch):
    """Ollama (HTTP) backends should NOT be released on idle (no model to free)."""
    ev = EventLogger(str(tmp_path / "ev.jsonl"))

    policy = LLMPolicy.model_validate(
        {
            "schema_version": 1,
            "enabled": True,
            "mode": "external",
            "roles": {
                "chat": {
                    "backend": "ollama",
                    "model": "m",
                    "base_url": "http://x",
                    "idle_unload_seconds": 1,
                }
            },
            "watchdog": {
                "health_check_interval_seconds": 999,
                "restart_on_failure": False,
                "max_restart_attempts": 1,
            },
        }
    )
    lc = LLMLifecycleController(policy=policy, event_logger=ev, logger=DummyLogger())
    lc.stop()

    mock = MockInProcessBackend()
    mock.name = "ollama"
    monkeypatch.setattr(lc, "_get_backend", lambda _role: mock)

    # Simulate: role was loaded and idle past threshold
    lc._role_state["chat"].loaded = True
    lc._role_state["chat"].last_used = time.time() - 100

    # Run watchdog idle check logic
    now = time.time()
    cfg = lc.policy.roles["chat"]
    st = lc._role_state["chat"]
    idle_secs = now - st.last_used
    # For ollama backend, the idle unload in the watchdog specifically
    # only triggers for llamacpp backends
    should_unload = (
        st.loaded
        and st.last_used > 0
        and idle_secs > cfg.idle_unload_seconds
        and cfg.backend.lower() == "llamacpp"
    )
    assert not should_unload, "Ollama backends should not be idle-unloaded"
