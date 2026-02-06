"""
Test: Image generation capability enforcement.

Verifies that system.image_generate requires:
- CAP_IMAGE_GENERATION + CAP_HEAVY_COMPUTE
- Admin session (via ADMIN_ONLY_CAPS)
- Denied in safe_mode

These are enforced by the capability engine, NOT by the handler itself.
"""
from __future__ import annotations

import pytest

from jarvis.core.capabilities.defaults import default_capabilities, ADMIN_ONLY_CAPS
from jarvis.core.capabilities.loader import default_config_dict, validate_and_normalize
from jarvis.core.capabilities.models import RequestContext, RequestSource


def test_image_generate_requires_image_and_heavy_compute():
    """system.image_generate must require CAP_IMAGE_GENERATION + CAP_HEAVY_COMPUTE."""
    cfg = validate_and_normalize(default_config_dict())
    reqs = cfg.intent_requirements.get("system.image_generate")
    assert reqs is not None, "system.image_generate must be in intent_requirements"
    assert "CAP_IMAGE_GENERATION" in reqs
    assert "CAP_HEAVY_COMPUTE" in reqs


def test_image_generation_is_admin_only():
    """CAP_IMAGE_GENERATION is in ADMIN_ONLY_CAPS (non-negotiable admin requirement)."""
    assert "CAP_IMAGE_GENERATION" in ADMIN_ONLY_CAPS


def test_image_generation_denied_by_default():
    """CAP_IMAGE_GENERATION has default_policy=deny."""
    caps = default_capabilities()
    cap = caps.get("CAP_IMAGE_GENERATION")
    assert cap is not None
    assert cap.default_policy.value == "deny"


def test_image_generation_requires_admin_flag():
    """CAP_IMAGE_GENERATION has requires_admin=True."""
    caps = default_capabilities()
    cap = caps["CAP_IMAGE_GENERATION"]
    assert cap.requires_admin is True


def test_image_generation_high_sensitivity():
    """CAP_IMAGE_GENERATION has high sensitivity."""
    caps = default_capabilities()
    cap = caps["CAP_IMAGE_GENERATION"]
    assert cap.sensitivity.value == "high"


def test_capability_engine_denies_without_admin():
    """CapabilityEngine denies image generation without admin."""
    from jarvis.core.capabilities.engine import CapabilityEngine
    from jarvis.core.capabilities.audit import CapabilityAuditLogger
    import tempfile, os

    cfg = validate_and_normalize(default_config_dict())
    with tempfile.TemporaryDirectory() as td:
        audit = CapabilityAuditLogger(path=os.path.join(td, "cap.jsonl"))
        engine = CapabilityEngine(cfg=cfg, audit=audit, logger=None)

        ctx = RequestContext(
            trace_id="t1",
            intent_id="system.image_generate",
            source=RequestSource.cli,
            is_admin=False,  # NOT admin
            safe_mode=False,
            shutting_down=False,
        )
        decision = engine.evaluate(ctx)
        assert decision.allowed is False, "Should deny without admin"
        assert len(decision.denied_capabilities) > 0


def test_capability_engine_denies_in_safe_mode():
    """CapabilityEngine denies heavy compute (and thus image gen) in safe mode."""
    from jarvis.core.capabilities.engine import CapabilityEngine
    from jarvis.core.capabilities.audit import CapabilityAuditLogger
    import tempfile, os

    cfg = validate_and_normalize(default_config_dict())
    with tempfile.TemporaryDirectory() as td:
        audit = CapabilityAuditLogger(path=os.path.join(td, "cap.jsonl"))
        engine = CapabilityEngine(cfg=cfg, audit=audit, logger=None)

        ctx = RequestContext(
            trace_id="t2",
            intent_id="system.image_generate",
            source=RequestSource.cli,
            is_admin=True,
            safe_mode=True,  # SAFE MODE
            shutting_down=False,
        )
        decision = engine.evaluate(ctx)
        assert decision.allowed is False, "Should deny in safe mode"
