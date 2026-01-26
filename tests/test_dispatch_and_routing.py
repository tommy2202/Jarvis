from __future__ import annotations

from jarvis.core.dispatcher import Dispatcher
from jarvis.core.events import EventLogger
from jarvis.core.intent_router import StageAIntent, StageAIntentRouter
from jarvis.core.jarvis_app import JarvisApp
from jarvis.core.llm_router import LLMConfig, StageBLLMRouter
from jarvis.core.module_registry import ModuleRegistry
from jarvis.core.security import AdminSession, PermissionPolicy, SecurityManager
from jarvis.core.secure_store import SecureStore
from jarvis.core.crypto import generate_usb_master_key_bytes, write_usb_key
from jarvis.core.capabilities.audit import CapabilityAuditLogger
from jarvis.core.capabilities.engine import CapabilityEngine
from jarvis.core.capabilities.loader import default_config_dict, validate_and_normalize


class DummyLogger:
    def info(self, *_a, **_k): ...
    def warning(self, *_a, **_k): ...
    def error(self, *_a, **_k): ...


def _make_security(tmp_path):
    usb = tmp_path / "usb.bin"
    write_usb_key(str(usb), generate_usb_master_key_bytes())
    store = SecureStore(usb_key_path=str(usb), store_path=str(tmp_path / "store.enc"))
    sec = SecurityManager(secure_store=store, admin_session=AdminSession(timeout_seconds=9999))
    return sec


def test_stage_a_match_and_confirmation(tmp_path):
    sec = _make_security(tmp_path)
    registry = ModuleRegistry()
    registry.register("jarvis.modules.music")

    intents = [StageAIntent(id="music.play", module_id="music", keywords=["play"], required_args=["song", "service"])]
    stage_a = StageAIntentRouter(intents, threshold=0.55)
    stage_b = StageBLLMRouter(LLMConfig(mock_mode=True))
    policy = PermissionPolicy(intents={"music.play": {"requires_admin": False, "resource_intensive": False}})
    caps_cfg = validate_and_normalize(default_config_dict())
    eng = CapabilityEngine(cfg=caps_cfg, audit=CapabilityAuditLogger(path=str(tmp_path / "security.jsonl")), logger=None)
    dispatcher = Dispatcher(
        registry=registry,
        policy=policy,
        security=sec,
        event_logger=EventLogger(str(tmp_path / "e.jsonl")),
        logger=DummyLogger(),
        capability_engine=eng,
        secure_store=sec.secure_store,
        inline_intent_allowlist=["music.play"],
    )

    jarvis = JarvisApp(
        stage_a=stage_a,
        stage_b=stage_b,
        dispatcher=dispatcher,
        intent_config_by_id={"music.play": {"id": "music.play", "module_id": "music", "required_args": ["song", "service"]}},
        confirmation_templates={"music.play": "Playing {song} on {service}."},
        event_logger=EventLogger(str(tmp_path / "events.jsonl")),
        logger=DummyLogger(),
        threshold=0.55,
    )

    resp = jarvis.process_message("play Coldplay on spotify", client={"name": "test"})
    assert resp.intent_id == "music.play"
    assert "Playing Coldplay on Spotify." in resp.reply


def test_admin_gating_denies_without_admin(tmp_path):
    sec = _make_security(tmp_path)
    registry = ModuleRegistry()
    registry.register("jarvis.modules.anime_dubbing")

    intents = [StageAIntent(id="anime_dubbing.run", module_id="anime_dubbing", keywords=["anime", "dubbing"], required_args=[])]
    stage_a = StageAIntentRouter(intents, threshold=0.55)
    stage_b = StageBLLMRouter(LLMConfig(mock_mode=True))
    policy = PermissionPolicy(intents={"anime_dubbing.run": {"requires_admin": True, "resource_intensive": True}})
    caps_cfg = validate_and_normalize(default_config_dict())
    eng = CapabilityEngine(cfg=caps_cfg, audit=CapabilityAuditLogger(path=str(tmp_path / "security.jsonl")), logger=None)
    dispatcher = Dispatcher(
        registry=registry,
        policy=policy,
        security=sec,
        event_logger=EventLogger(str(tmp_path / "e.jsonl")),
        logger=DummyLogger(),
        capability_engine=eng,
        secure_store=sec.secure_store,
        inline_intent_allowlist=["anime_dubbing.run"],
    )

    jarvis = JarvisApp(
        stage_a=stage_a,
        stage_b=stage_b,
        dispatcher=dispatcher,
        intent_config_by_id={"anime_dubbing.run": {"id": "anime_dubbing.run", "module_id": "anime_dubbing", "required_args": []}},
        confirmation_templates={"anime_dubbing.run": "Okay — starting the dubbing pipeline."},
        event_logger=EventLogger(str(tmp_path / "events.jsonl")),
        logger=DummyLogger(),
        threshold=0.55,
    )

    resp = jarvis.process_message("anime dubbing", client={"name": "test"})
    assert "Admin required" in resp.reply


def test_llm_unknown_intent_refused(tmp_path):
    sec = _make_security(tmp_path)
    registry = ModuleRegistry()
    registry.register("jarvis.modules.music")

    stage_a = StageAIntentRouter([], threshold=0.55)
    stage_b = StageBLLMRouter(LLMConfig(mock_mode=True))
    policy = PermissionPolicy(intents={"music.play": {"requires_admin": False, "resource_intensive": False}})
    caps_cfg = validate_and_normalize(default_config_dict())
    eng = CapabilityEngine(cfg=caps_cfg, audit=CapabilityAuditLogger(path=str(tmp_path / "security.jsonl")), logger=None)
    dispatcher = Dispatcher(
        registry=registry,
        policy=policy,
        security=sec,
        event_logger=EventLogger(str(tmp_path / "e.jsonl")),
        logger=DummyLogger(),
        capability_engine=eng,
        secure_store=sec.secure_store,
        inline_intent_allowlist=["music.play"],
    )

    jarvis = JarvisApp(
        stage_a=stage_a,
        stage_b=stage_b,
        dispatcher=dispatcher,
        intent_config_by_id={"music.play": {"id": "music.play", "module_id": "music", "required_args": ["song", "service"]}},
        confirmation_templates={"music.play": "Playing {song} on {service}."},
        event_logger=EventLogger(str(tmp_path / "events.jsonl")),
        logger=DummyLogger(),
        threshold=0.55,
    )

    resp = jarvis.process_message("do something unsafe", client={"name": "test"})
    assert resp.intent_id == "unknown"
    assert "couldn’t map" in resp.reply.lower()

