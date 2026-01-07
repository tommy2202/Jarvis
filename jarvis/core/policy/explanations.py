from __future__ import annotations

from jarvis.core.policy.models import PolicyDecision


def best_reason(dec: PolicyDecision) -> str:
    if dec.final_reason:
        return dec.final_reason
    if dec.matched_rules:
        # first matched is highest priority (engine keeps ordering)
        r = dec.matched_rules[0]
        return r.reason or f"Policy {r.id} applied."
    return "Policy decision applied."

