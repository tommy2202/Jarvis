from __future__ import annotations

from jarvis.core.errors import LLMUnavailableError
from jarvis.core.recovery import RecoveryAction, RecoveryPolicy, RecoveryConfig


def test_recovery_policy_fallback_for_llm_unavailable():
    p = RecoveryPolicy(RecoveryConfig())
    d = p.decide(LLMUnavailableError(), subsystem="llm")
    assert d.action == RecoveryAction.FALLBACK
    assert d.disable_subsystem == "llm"

