from __future__ import annotations

import json
import os

import pytest


def _mk_engine(tmp_path):
    from jarvis.core.capabilities.audit import CapabilityAuditLogger
    from jarvis.core.capabilities.engine import CapabilityEngine
    from jarvis.core.capabilities.loader import default_config_dict, validate_and_normalize

    cfg = validate_and_normalize(default_config_dict())
    audit = CapabilityAuditLogger(path=str(tmp_path / "security.jsonl"), keep_last=50)
    eng = CapabilityEngine(cfg=cfg, audit=audit, logger=None)
    return eng


def test_deny_unknown_intent_by_default(tmp_path):
    from jarvis.core.capabilities.models import RequestContext, RequestSource

    eng = _mk_engine(tmp_path)
    ctx = RequestContext(trace_id="t1", source=RequestSource.cli, intent_id="unknown.intent")
    dec = eng.evaluate(ctx)
    assert dec.allowed is False


def test_cap_admin_action_requires_admin_even_if_config_allows(tmp_path):
    from jarvis.core.capabilities.audit import CapabilityAuditLogger
    from jarvis.core.capabilities.engine import CapabilityEngine
    from jarvis.core.capabilities.loader import default_config_dict, validate_and_normalize
    from jarvis.core.capabilities.models import RequestContext, RequestSource

    raw = default_config_dict()
    # Try to "allow" admin actions by default in config (should still require admin due to hard rules).
    raw["capabilities"]["CAP_ADMIN_ACTION"]["default_policy"] = "allow"
    cfg = validate_and_normalize(raw)
    eng = CapabilityEngine(cfg=cfg, audit=CapabilityAuditLogger(path=str(tmp_path / "security.jsonl")), logger=None)
    ctx = RequestContext(trace_id="t2", source=RequestSource.cli, intent_id="music.play")
    # Force requirement via intent requirements (override)
    cfg.intent_requirements["music.play"] = ["CAP_ADMIN_ACTION"]
    dec = eng.evaluate(ctx)
    assert dec.allowed is False
    assert "CAP_ADMIN_ACTION" in dec.denied_capabilities


def test_image_generation_requires_admin_always(tmp_path):
    from jarvis.core.capabilities.models import RequestContext, RequestSource

    eng = _mk_engine(tmp_path)
    # Inject an intent that requires image generation
    eng.cfg.intent_requirements["system.image_generate"] = ["CAP_IMAGE_GENERATION"]
    ctx = RequestContext(trace_id="t3", source=RequestSource.cli, intent_id="system.image_generate", is_admin=False)
    dec = eng.evaluate(ctx)
    assert dec.allowed is False
    assert "CAP_IMAGE_GENERATION" in dec.denied_capabilities


def test_web_source_denies_admin_action(tmp_path):
    from jarvis.core.capabilities.models import RequestContext, RequestSource

    eng = _mk_engine(tmp_path)
    eng.cfg.intent_requirements["system.admin"] = ["CAP_ADMIN_ACTION"]
    ctx = RequestContext(trace_id="t4", source=RequestSource.web, intent_id="system.admin", is_admin=True)
    dec = eng.evaluate(ctx)
    assert dec.allowed is False


def test_safe_mode_denies_heavy_compute_network_subprocess(tmp_path):
    from jarvis.core.capabilities.models import RequestContext, RequestSource

    eng = _mk_engine(tmp_path)
    ctx = RequestContext(trace_id="t5", source=RequestSource.cli, intent_id="anime_dubbing.run", safe_mode=True, is_admin=True)
    dec = eng.evaluate(ctx)
    assert dec.allowed is False
    assert any(c in dec.denied_capabilities for c in ["CAP_HEAVY_COMPUTE", "CAP_RUN_SUBPROCESS"])


def test_shutting_down_denies_most_capabilities(tmp_path):
    from jarvis.core.capabilities.models import RequestContext, RequestSource

    eng = _mk_engine(tmp_path)
    ctx = RequestContext(trace_id="t6", source=RequestSource.cli, intent_id="anime_dubbing.run", shutting_down=True, is_admin=True)
    dec = eng.evaluate(ctx)
    assert dec.allowed is False


def test_audit_log_written_on_denial(tmp_path):
    from jarvis.core.capabilities.models import RequestContext, RequestSource

    eng = _mk_engine(tmp_path)
    ctx = RequestContext(trace_id="t7", source=RequestSource.cli, intent_id="anime_dubbing.run", is_admin=False)
    dec = eng.evaluate(ctx)
    assert dec.allowed is False
    data = open(tmp_path / "security.jsonl", "r", encoding="utf-8").read()
    assert "t7" in data
    assert "capability.decision" in data
    assert "denied" in data

