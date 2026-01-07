from __future__ import annotations

import datetime as dt

from jarvis.core.policy.engine import PolicyEngine
from jarvis.core.policy.matcher import PolicyMatcher
from jarvis.core.policy.models import PolicyConfigFile, PolicyContext


def test_deny_network_when_admin_locked():
    cfg = PolicyConfigFile.model_validate(
        {
            "enabled": True,
            "default": {"deny_unknown_intents": True, "deny_high_sensitivity_without_admin": True},
            "rules": [
                {
                    "id": "deny_network_when_locked",
                    "priority": 10,
                    "effect": "DENY",
                    "match": {"capabilities_any": ["CAP_NETWORK_ACCESS"], "is_admin": False},
                    "reason": "Network access requires admin unlock.",
                }
            ],
        }
    )
    pe = PolicyEngine(cfg=cfg, failsafe=False)
    dec = pe.evaluate(PolicyContext(trace_id="t", intent_id="x", required_capabilities=["CAP_NETWORK_ACCESS"], source="cli", is_admin=False))
    assert dec.allowed is False
    assert "Network access" in dec.final_reason


def test_quiet_hours_modifies_tts_disabled():
    fixed = dt.datetime(2026, 1, 1, 23, 30, tzinfo=dt.timezone.utc)
    matcher = PolicyMatcher(now=lambda: fixed)
    cfg = PolicyConfigFile.model_validate(
        {
            "enabled": True,
            "default": {"deny_unknown_intents": True, "deny_high_sensitivity_without_admin": True},
            "rules": [
                {
                    "id": "quiet_hours_no_tts",
                    "priority": 20,
                    "effect": "MODIFY",
                    "match": {"time_window": {"start": "23:00", "end": "07:00", "timezone": "UTC"}, "source_in": ["voice", "ui"]},
                    "modify": {"flags": {"tts_enabled": False}},
                    "reason": "Quiet hours",
                }
            ],
        }
    )
    pe = PolicyEngine(cfg=cfg, failsafe=False, matcher=matcher)
    dec = pe.evaluate(PolicyContext(trace_id="t", intent_id="x", required_capabilities=["CAP_AUDIO_OUTPUT"], source="voice", is_admin=False))
    assert dec.allowed is True
    assert dec.modifications.get("flags", {}).get("tts_enabled") is False


def test_priority_deny_overrides_allow():
    cfg = PolicyConfigFile.model_validate(
        {
            "enabled": True,
            "default": {"deny_unknown_intents": True, "deny_high_sensitivity_without_admin": True},
            "rules": [
                {"id": "deny_first", "priority": 1, "effect": "DENY", "match": {"intent_id_in": ["a"]}, "reason": "no"},
                {"id": "allow_later", "priority": 10, "effect": "ALLOW", "match": {"intent_id_in": ["a"]}, "reason": "yes"},
            ],
        }
    )
    pe = PolicyEngine(cfg=cfg, failsafe=False)
    dec = pe.evaluate(PolicyContext(trace_id="t", intent_id="a", required_capabilities=[], source="cli"))
    assert dec.allowed is False
    assert dec.matched_rules[0].id == "deny_first"


def test_modifications_never_increase_privilege():
    cfg = PolicyConfigFile.model_validate(
        {
            "enabled": True,
            "default": {"deny_unknown_intents": True, "deny_high_sensitivity_without_admin": True},
            "rules": [
                {"id": "try_enable_network", "priority": 1, "effect": "MODIFY", "match": {"intent_id_in": ["a"]}, "modify": {"flags": {"allow_network": True}}, "reason": "x"},
                {"id": "disable_network", "priority": 2, "effect": "MODIFY", "match": {"intent_id_in": ["a"]}, "modify": {"flags": {"allow_network": False}}, "reason": "y"},
            ],
        }
    )
    pe = PolicyEngine(cfg=cfg, failsafe=False)
    dec = pe.evaluate(PolicyContext(trace_id="t", intent_id="a", required_capabilities=["CAP_NETWORK_ACCESS"], source="cli"))
    # allow_network=true should be ignored; only false is allowed
    assert dec.modifications.get("flags", {}).get("allow_network") is False


def test_failsafe_denies_risky_without_admin():
    cfg = PolicyConfigFile(enabled=False)  # ignored when failsafe=True
    pe = PolicyEngine(cfg=cfg, failsafe=True, fail_message="invalid")
    dec = pe.evaluate(PolicyContext(trace_id="t", intent_id="x", required_capabilities=["CAP_HEAVY_COMPUTE"], source="cli", is_admin=False))
    assert dec.allowed is False
    assert dec.failsafe is True

