from __future__ import annotations

from jarvis.core.dispatcher import Dispatcher
from jarvis.core.events import EventLogger
from jarvis.core.intent_router import StageAIntentRouter
from jarvis.core.jarvis_app import JarvisApp
from jarvis.core.module_registry import ModuleRegistry
from jarvis.core.security import AdminSession, PermissionPolicy, SecurityManager
from jarvis.core.secure_store import SecureStore
from jarvis.core.crypto import generate_usb_master_key_bytes, write_usb_key
from jarvis.core.core_intents import CoreIntent, CoreIntentRegistry


class DummyLogger:
    def info(self, *_a, **_k): ...
    def warning(self, *_a, **_k): ...
    def error(self, *_a, **_k): ...


def _make_security(tmp_path):
    usb = tmp_path / "usb.bin"
    write_usb_key(str(usb), generate_usb_master_key_bytes())
    store = SecureStore(usb_key_path=str(usb), store_path=str(tmp_path / "store.enc"))
    return SecurityManager(secure_store=store, admin_session=AdminSession(timeout_seconds=9999))


def _make_app(tmp_path, *, stage_b, core_registry=None, core_fact_fuzzy_cfg=None) -> JarvisApp:
    sec = _make_security(tmp_path)
    registry = ModuleRegistry()  # modules not needed for core-fact routing tests
    dispatcher = Dispatcher(
        registry=registry,
        policy=PermissionPolicy(intents={}),
        security=sec,
        event_logger=EventLogger(str(tmp_path / "dispatch.jsonl")),
        logger=DummyLogger(),
    )
    return JarvisApp(
        stage_a=StageAIntentRouter([], threshold=0.55),
        stage_b=stage_b,
        dispatcher=dispatcher,
        intent_config_by_id={},
        confirmation_templates={},
        event_logger=EventLogger(str(tmp_path / "events.jsonl")),
        logger=DummyLogger(),
        threshold=0.55,
        core_registry=core_registry,
        core_fact_fuzzy_cfg=core_fact_fuzzy_cfg,
    )


def test_fuzzy_matches_time_variants(tmp_path):
    class StageBNever:
        def route(self, *_a, **_k):  # pragma: no cover
            raise AssertionError("LLM fallback must not be called for core facts")

    jarvis = _make_app(tmp_path, stage_b=StageBNever())
    resp = jarvis.process_message("hey jarvis can you tell me the current time right now please", client={"id": "t"})
    assert resp.intent_id == "core.time.now"
    assert resp.intent_source == "core"


def test_fuzzy_matches_date_variants(tmp_path):
    class StageBNever:
        def route(self, *_a, **_k):  # pragma: no cover
            raise AssertionError("LLM fallback must not be called for core facts")

    jarvis = _make_app(tmp_path, stage_b=StageBNever())
    resp = jarvis.process_message("what day is today right now", client={"id": "t"})
    assert resp.intent_id == "core.date.today"
    assert resp.intent_source == "core"


def test_fuzzy_does_not_match_non_fact_intents(tmp_path):
    class StageBMock:
        def route(self, *_a, **_k):
            return None

    jarvis = _make_app(tmp_path, stage_b=StageBMock())
    resp = jarvis.process_message("generate an image of a cat", client={"id": "t"})
    assert not str(resp.intent_id).startswith("core.")


def test_fuzzy_ambiguity_triggers_clarify(tmp_path):
    class StageBNever:
        def route(self, *_a, **_k):  # pragma: no cover
            raise AssertionError("Should clarify before LLM fallback")

    jarvis = _make_app(tmp_path, stage_b=StageBNever())
    resp = jarvis.process_message("what is it today", client={"id": "t"})
    assert resp.intent_id == "system.clarify"
    assert resp.requires_followup is True


def test_fuzzy_never_calls_llm(tmp_path):
    calls = {"n": 0}

    class StageBSpy:
        def route(self, *_a, **_k):
            calls["n"] += 1
            return None

    jarvis = _make_app(tmp_path, stage_b=StageBSpy())
    _ = jarvis.process_message("tell me the current time right now please", client={"id": "t"})
    assert calls["n"] == 0


def test_fuzzy_limits_phrase_candidates(tmp_path):
    # Create 201 phrases where the ONLY good match is after the limit.
    phrases = [f"noise phrase {i}" for i in range(200)] + ["special unique match tokens"]
    reg = CoreIntentRegistry(
        intents=[CoreIntent(id="core.time.now", label="time", phrases=phrases, is_fact=True)],
        fuzzy_cfg={
            "enabled": True,
            "min_score": 0.72,
            "min_score_if_contains": 0.62,
            "ambiguity_margin": 0.05,
            "max_phrases_considered_per_intent": 300,
            "max_total_phrase_candidates": 200,
        },
    )
    out = reg.fuzzy_match_fact_intent("special unique match tokens")
    assert out is None

