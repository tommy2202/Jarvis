from __future__ import annotations

"""
Enforcement invariants (lock-in tests).

WHY THIS FILE EXISTS:
These tests protect the security model: execution must be deny-by-default and
must flow through the dispatcher + capability enforcement path. If any of these
regress, web/UI bypasses or config drift could reintroduce enforcement leaks.
"""

from pathlib import Path

from jarvis.core.capabilities.audit import CapabilityAuditLogger
from jarvis.core.capabilities.engine import CapabilityEngine
from jarvis.core.capabilities.loader import default_config_dict, validate_and_normalize
from jarvis.core.capabilities.models import RequestContext, RequestSource
from jarvis.core.dispatcher import Dispatcher
from jarvis.core.events import EventLogger
from jarvis.core.module_registry import LoadedModule, ModuleRegistry
from jarvis.core.security import AdminSession, PermissionPolicy, SecurityManager
from jarvis.core.secure_store import SecureStore


def _security(tmp_path) -> tuple[SecurityManager, SecureStore]:
    # No physical USB key required: point to a missing path to simulate KEY_MISSING.
    usb = tmp_path / "usb_missing.bin"
    store = SecureStore(usb_key_path=str(usb), store_path=str(tmp_path / "store.enc"))
    sec = SecurityManager(secure_store=store, admin_session=AdminSession(timeout_seconds=9999))
    return sec, store


def _dispatcher(tmp_path, *, cap_cfg) -> tuple[Dispatcher, dict]:
    sec, store = _security(tmp_path)
    policy = PermissionPolicy(intents={})
    reg = ModuleRegistry()
    called = {"n": 0}

    def handler(intent_id, args, context):  # noqa: ANN001
        called["n"] += 1
        return {"ok": True}

    reg._modules_by_id["mod"] = LoadedModule(  # noqa: SLF001
        module_path="test.mod",
        module_id="mod",
        meta={"resource_class": "default", "execution_mode": "inline", "required_capabilities": []},
        _unsafe_handler=handler,
    )

    eng = CapabilityEngine(cfg=cap_cfg, audit=CapabilityAuditLogger(path=str(tmp_path / "security.jsonl")), logger=None)
    disp = Dispatcher(
        registry=reg,
        policy=policy,
        security=sec,
        event_logger=EventLogger(str(tmp_path / "events.jsonl")),
        logger=type("L", (), {"error": lambda *_a, **_k: None})(),
        capability_engine=eng,
        secure_store=store,
    )
    return disp, called


def test_unknown_intent_denied(tmp_path):
    # Invariant: unknown/unregistered intents are denied-by-default.
    cfg = validate_and_normalize(default_config_dict())
    disp, called = _dispatcher(tmp_path, cap_cfg=cfg)

    # Capability decision must deny unknown intent deterministically.
    eng = disp.capability_engine
    dec = eng.evaluate(RequestContext(trace_id="t", source=RequestSource.cli, intent_id="unknown.intent", secure_store_mode="KEY_MISSING"))
    assert dec.allowed is False

    r = disp.dispatch("t", "unknown.intent", "mod", {}, {"source": "cli"})
    assert r.ok is False
    assert called["n"] == 0
    assert "not registered" in (r.reply or "").lower()
    assert "config/capabilities.json" in (r.reply or "")


def test_unmapped_intent_denied_even_if_module_exists(tmp_path):
    # Invariant: dispatcher must deny any intent not mapped in capabilities.json intent_requirements.
    cfg = validate_and_normalize(default_config_dict())
    disp, called = _dispatcher(tmp_path, cap_cfg=cfg)

    r = disp.dispatch("t", "x.run", "mod", {}, {"source": "cli"})
    assert r.ok is False
    assert called["n"] == 0
    assert "intent is not registered" in (r.reply or "").lower()


def test_cap_admin_action_hard_rule_denies_without_admin_even_if_config_allows(tmp_path):
    # Invariant: CAP_ADMIN_ACTION is hard-admin-only (code-level rule); config cannot relax it.
    raw = default_config_dict()
    # Attempt to "allow" CAP_ADMIN_ACTION in config (should not matter)
    raw["capabilities"]["CAP_ADMIN_ACTION"]["requires_admin"] = False
    raw["capabilities"]["CAP_ADMIN_ACTION"]["default_policy"] = "allow"
    raw["capabilities"]["CAP_ADMIN_ACTION"]["sensitivity"] = "normal"
    raw["intent_requirements"]["x.admin"] = ["CAP_ADMIN_ACTION"]
    cfg = validate_and_normalize(raw)

    eng = CapabilityEngine(cfg=cfg, audit=CapabilityAuditLogger(path=str(tmp_path / "sec.jsonl")), logger=None)
    ctx = RequestContext(trace_id="t", source=RequestSource.cli, intent_id="x.admin", is_admin=False)
    dec = eng.evaluate(ctx)
    assert dec.allowed is False
    assert "CAP_ADMIN_ACTION" in (dec.denied_capabilities or [])


def test_web_source_cannot_perform_admin_actions_even_if_admin(tmp_path):
    # Invariant: web is never allowed to perform CAP_ADMIN_ACTION (hard source rule).
    raw = default_config_dict()
    raw["intent_requirements"]["x.admin"] = ["CAP_ADMIN_ACTION"]
    cfg = validate_and_normalize(raw)

    eng = CapabilityEngine(cfg=cfg, audit=CapabilityAuditLogger(path=str(tmp_path / "sec2.jsonl")), logger=None)
    ctx = RequestContext(trace_id="t", source=RequestSource.web, intent_id="x.admin", is_admin=True)
    dec = eng.evaluate(ctx)
    assert dec.allowed is False
    assert "CAP_ADMIN_ACTION" in (dec.denied_capabilities or [])


def test_shutting_down_restricts_to_safe_caps(tmp_path):
    # Invariant: shutdown mode restricts execution to a minimal allowlist of safe capabilities.
    raw = default_config_dict()
    raw["intent_requirements"]["x.subproc"] = ["CAP_RUN_SUBPROCESS"]
    raw["intent_requirements"]["x.audio"] = ["CAP_AUDIO_OUTPUT"]
    cfg = validate_and_normalize(raw)

    eng = CapabilityEngine(cfg=cfg, audit=CapabilityAuditLogger(path=str(tmp_path / "sec3.jsonl")), logger=None)
    denied = eng.evaluate(RequestContext(trace_id="t", source=RequestSource.cli, intent_id="x.subproc", shutting_down=True))
    assert denied.allowed is False

    allowed = eng.evaluate(RequestContext(trace_id="t", source=RequestSource.cli, intent_id="x.audio", shutting_down=True))
    assert allowed.allowed is True


def test_dispatcher_blocks_execution_when_denied(tmp_path):
    # Invariant: when denied, dispatcher must not call handlers (no partial execution).
    cfg = validate_and_normalize(default_config_dict())
    disp, called = _dispatcher(tmp_path, cap_cfg=cfg)

    r = disp.dispatch("t", "x.run", "mod", {}, {"source": "cli"})
    assert r.ok is False
    assert called["n"] == 0


def test_secure_store_key_missing_denies_requires_secrets_caps(tmp_path):
    # Invariant: requires_secrets capabilities are denied when secure store key is missing.
    raw = default_config_dict()
    raw["intent_requirements"]["x.admin"] = ["CAP_ADMIN_ACTION"]
    cfg = validate_and_normalize(raw)

    eng = CapabilityEngine(cfg=cfg, audit=CapabilityAuditLogger(path=str(tmp_path / "sec4.jsonl")), logger=None)
    ctx = RequestContext(trace_id="t", source=RequestSource.cli, intent_id="x.admin", secure_store_mode="KEY_MISSING", is_admin=True)
    dec = eng.evaluate(ctx)
    assert dec.allowed is False
    assert "CAP_ADMIN_ACTION" in (dec.denied_capabilities or [])


def test_module_contract_incomplete_denied(tmp_path):
    # Invariant: non-core intents must include contract metadata or dispatcher denies.
    sec, store = _security(tmp_path)
    raw = default_config_dict()
    raw["intent_requirements"]["x.ok"] = []
    cfg = validate_and_normalize(raw)
    eng = CapabilityEngine(cfg=cfg, audit=CapabilityAuditLogger(path=str(tmp_path / "sec5.jsonl")), logger=None)

    called = {"n": 0}

    def handler(intent_id, args, context):  # noqa: ANN001
        called["n"] += 1
        return {"ok": True}

    reg = ModuleRegistry()
    reg._modules_by_id["m"] = LoadedModule(  # noqa: SLF001
        module_path="test.m",
        module_id="m",
        meta={"execution_mode": "inline", "required_capabilities": []},  # missing resource_class
        _unsafe_handler=handler,
    )

    disp = Dispatcher(
        registry=reg,
        policy=PermissionPolicy(intents={}),
        security=sec,
        event_logger=EventLogger(str(tmp_path / "events2.jsonl")),
        logger=type("L", (), {"error": lambda *_a, **_k: None})(),
        capability_engine=eng,
        secure_store=store,
    )
    r = disp.dispatch("t", "x.ok", "m", {}, {"source": "cli"})
    assert r.ok is False
    assert called["n"] == 0
    assert "module contract incomplete" in (r.reply or "").lower()


def test_audit_log_appends_on_denies(tmp_path):
    # Invariant: audit logging can append without error (privacy-safe, local).
    cfg = validate_and_normalize(default_config_dict())
    audit_path = Path(tmp_path) / "audit.jsonl"
    eng = CapabilityEngine(cfg=cfg, audit=CapabilityAuditLogger(path=str(audit_path)), logger=None)

    _ = eng.evaluate(RequestContext(trace_id="t", source=RequestSource.cli, intent_id="unknown.intent", secure_store_mode="KEY_MISSING"))
    assert audit_path.exists()
    assert audit_path.stat().st_size > 0

