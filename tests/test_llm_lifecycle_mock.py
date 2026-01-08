from __future__ import annotations

import time

import pytest

from jarvis.core.events import EventLogger
from jarvis.core.llm_contracts import LLMRequest, LLMRole, Message, OutputSchema
from jarvis.core.llm_lifecycle import LLMPolicy, LLMLifecycleController


class DummyLogger:
    def info(self, *_a, **_k): ...
    def warning(self, *_a, **_k): ...
    def error(self, *_a, **_k): ...


class MockBackend:
    def __init__(self):
        self.running = True
        self.calls = 0
        self.fail = False
        self.sleep = 0.0

    name = "mock"

    def health(self):
        return type("H", (), {"ok": self.running, "detail": "down" if not self.running else "ok"})()

    def is_server_running(self):
        return self.running

    def start_server(self):
        self.running = True
        return True

    def stop_server(self):
        self.running = False
        return True

    def chat(self, *, model, messages, options, timeout_seconds):
        self.calls += 1
        if self.sleep:
            time.sleep(self.sleep)
        if self.fail:
            raise RuntimeError("boom")
        # first call returns invalid json; second returns valid
        if self.calls == 1:
            return "not json"
        return '{"reply":"ok"}'


def test_lifecycle_retries_invalid_json(tmp_path, monkeypatch):
    ev = EventLogger(str(tmp_path / "events.jsonl"))
    policy = LLMPolicy.model_validate(
        {
            "enabled": True,
            "mode": "external",
            "roles": {"chat": {"backend": "ollama", "model": "m", "base_url": "http://x"}},
            "watchdog": {"health_check_interval_seconds": 999, "restart_on_failure": False, "max_restart_attempts": 1},
        }
    )
    lc = LLMLifecycleController(policy=policy, event_logger=ev, logger=DummyLogger())
    try:
        mock = MockBackend()

        monkeypatch.setattr(lc, "_get_backend", lambda role: mock)

        req = LLMRequest(
            trace_id="t",
            role=LLMRole.chat,
            messages=[Message(role="user", content="hi")],
            output_schema=OutputSchema.chat_reply,
            safety={"allowed_intents": [], "denylist_phrases": []},
            max_tokens=10,
            temperature=0.0,
        )
        resp = lc.call("chat", req)
        assert resp.status.value == "ok"
        assert resp.parsed_json["reply"] == "ok"
        assert mock.calls >= 2
    finally:
        lc.stop()


def test_lifecycle_handles_backend_error(tmp_path, monkeypatch):
    ev = EventLogger(str(tmp_path / "events.jsonl"))
    policy = LLMPolicy.model_validate(
        {
            "enabled": True,
            "mode": "external",
            "roles": {"chat": {"backend": "ollama", "model": "m", "base_url": "http://x"}},
            "watchdog": {"health_check_interval_seconds": 999, "restart_on_failure": False, "max_restart_attempts": 1},
        }
    )
    lc = LLMLifecycleController(policy=policy, event_logger=ev, logger=DummyLogger())
    try:
        mock = MockBackend()
        mock.fail = True
        monkeypatch.setattr(lc, "_get_backend", lambda role: mock)

        req = LLMRequest(
            trace_id="t",
            role=LLMRole.chat,
            messages=[Message(role="user", content="hi")],
            output_schema=OutputSchema.chat_reply,
            safety={"allowed_intents": [], "denylist_phrases": []},
            max_tokens=10,
            temperature=0.0,
        )
        resp = lc.call("chat", req)
        assert resp.status.value == "error"
    finally:
        lc.stop()


def test_intent_fallback_never_allows_unknown_intents(tmp_path, monkeypatch):
    ev = EventLogger(str(tmp_path / "events.jsonl"))
    policy = LLMPolicy.model_validate(
        {
            "enabled": True,
            "mode": "external",
            "roles": {"chat": {"backend": "ollama", "model": "m", "base_url": "http://x"}},
            "watchdog": {"health_check_interval_seconds": 999, "restart_on_failure": False, "max_restart_attempts": 1},
        }
    )
    lc = LLMLifecycleController(policy=policy, event_logger=ev, logger=DummyLogger())
    try:
        mock = MockBackend()
        # return a forbidden intent
        mock.calls = 99
        monkeypatch.setattr(lc, "_get_backend", lambda role: mock)
        monkeypatch.setattr(mock, "chat", lambda **_k: '{"intent_id":"evil","confidence":1,"args":{},"confirmation_text":"x","requires_admin":true}')

        req = LLMRequest(
            trace_id="t",
            role=LLMRole.chat,
            messages=[Message(role="user", content="hi")],
            output_schema=OutputSchema.intent_fallback,
            safety={"allowed_intents": ["music.play"], "denylist_phrases": []},
            max_tokens=10,
            temperature=0.0,
        )
        resp = lc.call("chat", req)
        assert resp.status.value == "ok"
        assert resp.parsed_json["intent_id"] == "unknown"
        assert resp.parsed_json["confidence"] == 0.0
    finally:
        lc.stop()

