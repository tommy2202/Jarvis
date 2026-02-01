from __future__ import annotations

from jarvis.core.llm_contracts import LLMRequest, LLMRole, Message, OutputSchema
from jarvis.core.llm_lifecycle import LLMPolicy, LLMLifecycleController
from jarvis.core.events import EventLogger
from .helpers.fakes import FakeLLMBackend


class DummyLogger:
    def info(self, *_a, **_k): ...
    def warning(self, *_a, **_k): ...
    def error(self, *_a, **_k): ...


def test_lifecycle_retries_invalid_json_then_succeeds(tmp_path, monkeypatch):
    policy = LLMPolicy.model_validate(
        {"enabled": True, "mode": "external", "roles": {"chat": {"backend": "ollama", "model": "m", "base_url": "http://x"}}, "watchdog": {"health_check_interval_seconds": 999, "restart_on_failure": False, "max_restart_attempts": 1}}
    )
    lc = LLMLifecycleController(policy=policy, event_logger=EventLogger(str(tmp_path / "events.jsonl")), logger=DummyLogger())
    try:
        b = FakeLLMBackend()
        b.responses = ["not json", '{"reply":"ok"}']
        monkeypatch.setattr(lc, "_get_backend", lambda _role: b)
        req = LLMRequest(trace_id="t", role=LLMRole.chat, messages=[Message(role="user", content="hi")], output_schema=OutputSchema.chat_reply, safety={"allowed_intents": [], "denylist_phrases": []}, max_tokens=10, temperature=0.0)
        resp = lc.call("chat", req)
        assert resp.status.value == "ok"
        assert resp.parsed_json["reply"] == "ok"
        assert b.calls >= 2
    finally:
        lc.stop()


def test_intent_allowlist_enforced(tmp_path, monkeypatch):
    policy = LLMPolicy.model_validate(
        {"enabled": True, "mode": "external", "roles": {"chat": {"backend": "ollama", "model": "m", "base_url": "http://x"}}, "watchdog": {"health_check_interval_seconds": 999, "restart_on_failure": False, "max_restart_attempts": 1}}
    )
    lc = LLMLifecycleController(policy=policy, event_logger=EventLogger(str(tmp_path / "events.jsonl")), logger=DummyLogger())
    try:
        b = FakeLLMBackend()
        b.responses = ['{"intent_id":"evil","confidence":1,"args":{},"confirmation_text":"x","requires_admin":true}']
        monkeypatch.setattr(lc, "_get_backend", lambda _role: b)
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

