"""
Test: No prompt content appears in any log/audit files.

Sends a prompt containing a known secret marker through the lifecycle
controller and asserts the marker does NOT appear in any event logs.
"""
from __future__ import annotations

import json
import os

import pytest

from jarvis.core.events import EventLogger
from jarvis.core.llm_contracts import LLMRequest, LLMRole, Message, OutputSchema
from jarvis.core.llm_lifecycle import LLMPolicy, LLMLifecycleController


class DummyLogger:
    def __init__(self):
        self.messages: list[str] = []

    def info(self, msg, *_a, **_k):
        self.messages.append(str(msg))

    def warning(self, msg, *_a, **_k):
        self.messages.append(str(msg))

    def error(self, msg, *_a, **_k):
        self.messages.append(str(msg))


class SafeCheckBackend:
    """Backend that echoes a known marker so we can verify it doesn't leak."""

    name = "safe_check"

    def health(self):
        return type("H", (), {"ok": True, "detail": "ok"})()

    def ensure_ready(self):
        pass

    def is_ready(self):
        return True

    def release(self):
        pass

    def is_server_running(self):
        return True

    def start_server(self):
        return True

    def stop_server(self):
        return True

    def chat(self, *, model, messages, options, timeout_seconds, trace_id=""):
        return '{"reply":"safe response"}'


SECRET_MARKER = "SECRET123_NEVER_LOG_THIS"


def test_prompt_content_never_in_event_log(tmp_path, monkeypatch):
    """Send a prompt with SECRET123; verify it never appears in event logs."""
    events_path = str(tmp_path / "events.jsonl")
    ev = EventLogger(events_path)
    logger = DummyLogger()

    policy = LLMPolicy.model_validate(
        {
            "schema_version": 1,
            "enabled": True,
            "mode": "external",
            "debug_log_prompts": False,
            "roles": {"chat": {"backend": "ollama", "model": "m", "base_url": "http://x"}},
            "watchdog": {"health_check_interval_seconds": 999, "restart_on_failure": False, "max_restart_attempts": 1},
            "security": {"never_log_prompts": True},
        }
    )
    lc = LLMLifecycleController(policy=policy, event_logger=ev, logger=logger)
    try:
        backend = SafeCheckBackend()
        monkeypatch.setattr(lc, "_get_backend", lambda _role: backend)

        req = LLMRequest(
            trace_id="t1",
            role=LLMRole.chat,
            messages=[
                Message(role="user", content=f"Please process {SECRET_MARKER} for me")
            ],
            output_schema=OutputSchema.chat_reply,
            safety={"allowed_intents": [], "denylist_phrases": []},
            max_tokens=100,
            temperature=0.0,
        )
        resp = lc.call("chat", req)
        assert resp.status.value == "ok"
    finally:
        lc.stop()

    # Read the events log and check for the secret marker
    assert os.path.exists(events_path), "Event log should exist"
    with open(events_path, "r", encoding="utf-8") as f:
        log_content = f.read()

    assert SECRET_MARKER not in log_content, (
        f"Secret marker '{SECRET_MARKER}' was found in event log! "
        f"Prompt content must never be logged."
    )

    # Also check logger messages
    for msg in logger.messages:
        assert SECRET_MARKER not in msg, (
            f"Secret marker found in logger output: {msg}"
        )


def test_prompt_not_in_response_raw_text(tmp_path, monkeypatch):
    """With debug_log_prompts=False, raw_text should be None."""
    events_path = str(tmp_path / "events.jsonl")
    ev = EventLogger(events_path)
    logger = DummyLogger()

    policy = LLMPolicy.model_validate(
        {
            "schema_version": 1,
            "enabled": True,
            "mode": "external",
            "debug_log_prompts": False,
            "roles": {"chat": {"backend": "ollama", "model": "m", "base_url": "http://x"}},
            "watchdog": {"health_check_interval_seconds": 999, "restart_on_failure": False, "max_restart_attempts": 1},
        }
    )
    lc = LLMLifecycleController(policy=policy, event_logger=ev, logger=logger)
    try:
        backend = SafeCheckBackend()
        monkeypatch.setattr(lc, "_get_backend", lambda _role: backend)

        req = LLMRequest(
            trace_id="t2",
            role=LLMRole.chat,
            messages=[Message(role="user", content=SECRET_MARKER)],
            output_schema=OutputSchema.chat_reply,
            safety={"allowed_intents": [], "denylist_phrases": []},
            max_tokens=100,
            temperature=0.0,
        )
        resp = lc.call("chat", req)
        assert resp.raw_text is None, "raw_text must be None when debug_log_prompts is False"
    finally:
        lc.stop()


def test_error_logs_do_not_contain_prompt(tmp_path, monkeypatch):
    """When backend errors, the error log must not include prompt text."""

    class ErrorBackend(SafeCheckBackend):
        def chat(self, *, model, messages, options, timeout_seconds, trace_id=""):
            raise RuntimeError("Model crashed")

    events_path = str(tmp_path / "events.jsonl")
    ev = EventLogger(events_path)
    logger = DummyLogger()

    policy = LLMPolicy.model_validate(
        {
            "schema_version": 1,
            "enabled": True,
            "mode": "external",
            "roles": {"chat": {"backend": "ollama", "model": "m", "base_url": "http://x"}},
            "watchdog": {"health_check_interval_seconds": 999, "restart_on_failure": False, "max_restart_attempts": 1},
        }
    )
    lc = LLMLifecycleController(policy=policy, event_logger=ev, logger=logger)
    try:
        monkeypatch.setattr(lc, "_get_backend", lambda _role: ErrorBackend())

        req = LLMRequest(
            trace_id="t3",
            role=LLMRole.chat,
            messages=[Message(role="user", content=SECRET_MARKER)],
            output_schema=OutputSchema.chat_reply,
            safety={"allowed_intents": [], "denylist_phrases": []},
            max_tokens=100,
            temperature=0.0,
        )
        resp = lc.call("chat", req)
        assert resp.status.value == "error"
    finally:
        lc.stop()

    with open(events_path, "r", encoding="utf-8") as f:
        log_content = f.read()

    assert SECRET_MARKER not in log_content, (
        "Secret marker was found in error event log!"
    )
