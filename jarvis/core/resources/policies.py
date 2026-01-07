from __future__ import annotations

from jarvis.core.resources.models import AdmissionAction, AdmissionDecision, OverBudgetPolicy, ResourceGovernorConfig, ResourceSnapshot


def decide_over_budget(cfg: ResourceGovernorConfig, *, snapshot: ResourceSnapshot, reasons: list[str]) -> AdmissionDecision:
    policy = cfg.policies.on_over_budget
    if policy == OverBudgetPolicy.DENY:
        return AdmissionDecision(
            allowed=False,
            action=AdmissionAction.DENY,
            delay_seconds=0.0,
            reasons=reasons,
            remediation="System is under resource pressure. Try again later or reduce load.",
            snapshot=snapshot.public_dict(),
        )
    if policy == OverBudgetPolicy.DELAY:
        delay = min(float(cfg.policies.max_delay_seconds), 1.0)
        return AdmissionDecision(
            allowed=False,
            action=AdmissionAction.DELAY,
            delay_seconds=delay,
            reasons=reasons,
            remediation=f"System is busy. Retrying soon (delay {delay:.0f}s).",
            snapshot=snapshot.public_dict(),
        )
    if policy == OverBudgetPolicy.SAFE_MODE:
        return AdmissionDecision(
            allowed=False,
            action=AdmissionAction.DENY,
            delay_seconds=0.0,
            reasons=reasons + ["Entering safe mode due to sustained pressure."],
            remediation="Safe mode activated. Reduce load and try again later.",
            snapshot=snapshot.public_dict(),
        )
    # THROTTLE default
    return AdmissionDecision(
        allowed=False,
        action=AdmissionAction.THROTTLE,
        delay_seconds=min(float(cfg.policies.max_delay_seconds), 1.0),
        reasons=reasons + ["Throttling under pressure."],
        remediation="System is busy. Try again shortly.",
        snapshot=snapshot.public_dict(),
    )

