from __future__ import annotations

from jarvis.core.capabilities.audit import CapabilityAuditLogger
from jarvis.core.capabilities.engine import CapabilityEngine
from jarvis.core.capabilities.loader import default_config_dict, validate_and_normalize
from jarvis.core.capabilities.models import RequestContext, RequestSource
from jarvis.core.capabilities.models import DefaultPolicy
from jarvis.core.dispatcher import Dispatcher
from jarvis.core.events import EventLogger
from jarvis.core.module_registry import LoadedModule, ModuleRegistry
from jarvis.core.security import AdminSession, PermissionPolicy, SecurityManager
from jarvis.core.secure_store import SecureStore
from jarvis.core.crypto import generate_usb_master_key_bytes, write_usb_key


class DummyLogger:
    def error(self, *_a, **_k): ...


def _make_security(tmp_path) -> tuple[SecurityManager, SecureStore]:
    usb = tmp_path / "usb.bin"
    write_usb_key(str(usb), generate_usb_master_key_bytes())
    store = SecureStore(usb_key_path=str(usb), store_path=str(tmp_path / "store.enc"))
    sec = SecurityManager(secure_store=store, admin_session=AdminSession(timeout_seconds=9999))
    return sec, store


def _make_cap_engine(tmp_path, *, intent_requirements: dict[str, list[str]]):
    raw = default_config_dict()
    raw["intent_requirements"] = dict(intent_requirements)
    cfg = validate_and_normalize(raw)
    audit = CapabilityAuditLogger(path=str(tmp_path / "security.jsonl"))
    return CapabilityEngine(cfg=cfg, audit=audit, logger=None)


def _make_dispatcher(tmp_path, *, cap_engine: CapabilityEngine, module_meta: dict, handler):
    sec, store = _make_security(tmp_path)
    reg = ModuleRegistry()
    reg._modules_by_id["mod"] = LoadedModule(module_path="jarvis.modules.music", module_id="mod", meta=module_meta, handler=handler)  # noqa: SLF001
    disp = Dispatcher(
        registry=reg,
        policy=PermissionPolicy(intents={}),
        security=sec,
        event_logger=EventLogger(str(tmp_path / "events.jsonl")),
        logger=DummyLogger(),
        capability_engine=cap_engine,
        secure_store=store,
    )
    return disp, sec


def test_unknown_intent_denied_by_default_and_handler_not_called(tmp_path):
    called = {"n": 0}

    def handler(intent_id, args, context):  # noqa: ANN001
        called["n"] += 1
        return {"ok": True}

    cap_engine = _make_cap_engine(tmp_path, intent_requirements={"known.intent": []})
    meta = {
        "id": "mod",
        "resource_class": "local",
        "execution_mode": "inline",
        "capabilities_by_intent": {"known.intent": []},
    }
    disp, _sec = _make_dispatcher(tmp_path, cap_engine=cap_engine, module_meta=meta, handler=handler)

    r = disp.dispatch("t1", "unknown.intent", "mod", {}, {"client": {"id": "c"}, "source": "cli"})
    assert r.ok is False
    assert called["n"] == 0
    assert "Intent is not registered in capabilities policy" in r.reply
    assert "config/capabilities.json" in r.reply


def test_unmapped_intent_denied_even_if_module_exists(tmp_path):
    called = {"n": 0}

    def handler(intent_id, args, context):  # noqa: ANN001
        called["n"] += 1
        return {"ok": True}

    # Module "supports" intent, but capabilities mapping does not -> deny.
    cap_engine = _make_cap_engine(tmp_path, intent_requirements={"other.intent": []})
    meta = {
        "id": "mod",
        "resource_class": "local",
        "execution_mode": "inline",
        "capabilities_by_intent": {"x.run": []},
    }
    disp, _sec = _make_dispatcher(tmp_path, cap_engine=cap_engine, module_meta=meta, handler=handler)
    r = disp.dispatch("t2", "x.run", "mod", {}, {"client": {"id": "c"}, "source": "cli"})
    assert r.ok is False
    assert called["n"] == 0
    assert "Intent is not registered in capabilities policy" in r.reply


def test_dispatcher_denies_when_module_contract_incomplete(tmp_path):
    called = {"n": 0}

    def handler(intent_id, args, context):  # noqa: ANN001
        called["n"] += 1
        return {"ok": True}

    cap_engine = _make_cap_engine(tmp_path, intent_requirements={"music.play": ["CAP_AUDIO_OUTPUT"]})
    # Missing execution_mode/resource_class/capabilities_by_intent => deny
    meta = {"id": "mod"}
    disp, _sec = _make_dispatcher(tmp_path, cap_engine=cap_engine, module_meta=meta, handler=handler)
    r = disp.dispatch("t3", "music.play", "mod", {"song": "x"}, {"client": {"id": "c"}, "source": "cli"})
    assert r.ok is False
    assert called["n"] == 0
    assert "Module contract incomplete" in r.reply


def test_cap_admin_action_hard_rule_requires_admin_even_if_config_relaxed(tmp_path):
    cap_engine = _make_cap_engine(tmp_path, intent_requirements={"do.admin": ["CAP_ADMIN_ACTION"]})
    # Attempt to "relax" via config: hard rule must still deny.
    cap_engine.cfg.capabilities["CAP_ADMIN_ACTION"].requires_admin = False
    cap_engine.cfg.capabilities["CAP_ADMIN_ACTION"].default_policy = DefaultPolicy.allow

    ctx = RequestContext(trace_id="t", source=RequestSource.cli, is_admin=False, safe_mode=False, shutting_down=False, subsystem_health={}, intent_id="do.admin", secure_store_mode="READY")
    dec = cap_engine.evaluate(ctx)
    assert dec.allowed is False
    assert "CAP_ADMIN_ACTION" in (dec.denied_capabilities or [])


def test_web_source_cannot_perform_admin_actions_even_if_admin_unlocked(tmp_path):
    cap_engine = _make_cap_engine(tmp_path, intent_requirements={"do.admin": ["CAP_ADMIN_ACTION"]})
    ctx = RequestContext(trace_id="t", source=RequestSource.web, is_admin=True, safe_mode=False, shutting_down=False, subsystem_health={}, intent_id="do.admin", secure_store_mode="READY")
    dec = cap_engine.evaluate(ctx)
    assert dec.allowed is False


def test_shutting_down_restricts_to_safe_caps(tmp_path):
    cap_engine = _make_cap_engine(
        tmp_path,
        intent_requirements={
            "run.proc": ["CAP_RUN_SUBPROCESS"],
            "say.ok": ["CAP_AUDIO_OUTPUT"],
        },
    )
    denied_ctx = RequestContext(trace_id="t1", source=RequestSource.cli, is_admin=True, safe_mode=False, shutting_down=True, subsystem_health={}, intent_id="run.proc", secure_store_mode="READY")
    assert cap_engine.evaluate(denied_ctx).allowed is False
    allowed_ctx = RequestContext(trace_id="t2", source=RequestSource.cli, is_admin=False, safe_mode=False, shutting_down=True, subsystem_health={}, intent_id="say.ok", secure_store_mode="READY")
    assert cap_engine.evaluate(allowed_ctx).allowed is True


def test_secure_store_key_missing_denies_requires_secrets_caps(tmp_path):
    cap_engine = _make_cap_engine(tmp_path, intent_requirements={"do.admin": ["CAP_ADMIN_ACTION"]})
    ctx = RequestContext(trace_id="t", source=RequestSource.cli, is_admin=True, safe_mode=False, shutting_down=False, subsystem_health={}, intent_id="do.admin", secure_store_mode="KEY_MISSING")
    dec = cap_engine.evaluate(ctx)
    assert dec.allowed is False
    assert "USB key missing" in " ".join(dec.reasons or [])

