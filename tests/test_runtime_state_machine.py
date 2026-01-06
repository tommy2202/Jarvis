from __future__ import annotations

import time

import pytest

from jarvis.core.events import EventLogger
from jarvis.core.runtime import AssistantState, JarvisRuntime, RuntimeConfig


class DummyLogger:
    def info(self, *_a, **_k): ...
    def warning(self, *_a, **_k): ...
    def error(self, *_a, **_k): ...


class DummyStageB:
    def __init__(self):
        self.loaded = False

    def warmup(self):
        self.loaded = True

    def unload(self):
        self.loaded = False


class DummyJarvisApp:
    def __init__(self):
        self.stage_b = DummyStageB()
        self.calls = []

    def process_message(self, message: str, client=None):
        self.calls.append(message)
        return type(
            "R",
            (),
            {
                "trace_id": "x",
                "reply": f"echo: {message}",
                "intent_id": "system.echo",
                "intent_source": "stage_a",
                "confidence": 1.0,
                "requires_followup": False,
                "followup_question": None,
            },
        )()


def test_text_only_happy_path_transitions_and_result(tmp_path):
    ev = EventLogger(str(tmp_path / "events.jsonl"))
    jarvis = DummyJarvisApp()
    cfg = RuntimeConfig.model_validate(
        {
            "idle_sleep_seconds": 0.2,
            "timeouts": {"UNDERSTANDING": 2, "EXECUTING": 2, "SPEAKING": 2},
            "enable_voice": False,
            "enable_tts": False,
            "enable_wake_word": False,
            "busy_policy": "queue",
            "result_ttl_seconds": 5,
        }
    )
    rt = JarvisRuntime(cfg=cfg, jarvis_app=jarvis, event_logger=ev, logger=DummyLogger(), persist_path=str(tmp_path / "sm.jsonl"))
    rt.start()
    try:
        assert rt.get_status()["state"] == AssistantState.SLEEPING.value
        tid = rt.submit_text("cli", "hello", client_meta={"id": "t"})
        out = rt.wait_for_result(tid, timeout_seconds=2.0)
        assert out is not None
        assert out["reply"] == "echo: hello"
        # eventually returns to SLEEPING after IDLE timeout
        time.sleep(0.4)
        assert rt.get_status()["state"] == AssistantState.SLEEPING.value
    finally:
        rt.stop()


def test_invalid_transition_triggers_recovery(tmp_path):
    ev = EventLogger(str(tmp_path / "events.jsonl"))
    jarvis = DummyJarvisApp()
    cfg = RuntimeConfig.model_validate({"enable_tts": False, "enable_voice": False, "enable_wake_word": False})
    rt = JarvisRuntime(cfg=cfg, jarvis_app=jarvis, event_logger=ev, logger=DummyLogger(), persist_path=str(tmp_path / "sm.jsonl"))
    rt.start()
    try:
        # Force an invalid transition by calling the internal method directly (unit test).
        with pytest.raises(Exception):
            rt._set_state("t", AssistantState.EXECUTING, {})  # noqa: SLF001
        # runtime should remain usable and in SLEEPING
        assert rt.get_status()["state"] == AssistantState.SLEEPING.value
    finally:
        rt.stop()


def test_idle_timeout_unloads_llm(tmp_path):
    ev = EventLogger(str(tmp_path / "events.jsonl"))
    jarvis = DummyJarvisApp()
    cfg = RuntimeConfig.model_validate({"idle_sleep_seconds": 0.2, "enable_tts": False, "enable_voice": False, "enable_wake_word": False})
    rt = JarvisRuntime(cfg=cfg, jarvis_app=jarvis, event_logger=ev, logger=DummyLogger(), persist_path=str(tmp_path / "sm.jsonl"))
    rt.start()
    try:
        tid = rt.submit_text("cli", "hi")
        _ = rt.wait_for_result(tid, timeout_seconds=2.0)
        assert jarvis.stage_b.loaded is True
        time.sleep(0.4)
        # After idle sleep, runtime should unload
        assert jarvis.stage_b.loaded is False
    finally:
        rt.stop()


def test_concurrency_two_text_inputs_queue_in_order(tmp_path):
    ev = EventLogger(str(tmp_path / "events.jsonl"))
    jarvis = DummyJarvisApp()
    cfg = RuntimeConfig.model_validate({"enable_tts": False, "enable_voice": False, "enable_wake_word": False, "busy_policy": "queue"})
    rt = JarvisRuntime(cfg=cfg, jarvis_app=jarvis, event_logger=ev, logger=DummyLogger(), persist_path=str(tmp_path / "sm.jsonl"))
    rt.start()
    try:
        t1 = rt.submit_text("cli", "one")
        t2 = rt.submit_text("cli", "two")
        r1 = rt.wait_for_result(t1, timeout_seconds=2.0)
        r2 = rt.wait_for_result(t2, timeout_seconds=2.0)
        assert r1 and r1["reply"] == "echo: one"
        assert r2 and r2["reply"] == "echo: two"
        assert jarvis.calls == ["one", "two"]
    finally:
        rt.stop()

