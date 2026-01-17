from __future__ import annotations

from dataclasses import dataclass
from typing import List

from jarvis.core.startup.models import CheckStatus, OverallStatus, PhaseResult, StartupCheckResult


@dataclass(frozen=True)
class StartupDecision:
    status: OverallStatus
    safe_mode: bool
    force_start_used: bool


def decide(
    *,
    phases: List[PhaseResult],
    force_start: bool,
    safe_mode_flag: bool,
) -> StartupDecision:
    # any FAILED check => BLOCKED (fail-closed)
    blocked = False
    degraded_count = 0
    for ph in phases:
        if ph.status == CheckStatus.FAILED:
            blocked = True
        if ph.status == CheckStatus.DEGRADED:
            degraded_count += 1

    safe_mode = bool(safe_mode_flag)
    if degraded_count >= 2:
        safe_mode = True

    if blocked and force_start:
        # force-start downgrades to DEGRADED + safe mode
        return StartupDecision(status=OverallStatus.DEGRADED, safe_mode=True, force_start_used=True)

    if blocked:
        return StartupDecision(status=OverallStatus.BLOCKED, safe_mode=safe_mode, force_start_used=False)

    # if any degraded => DEGRADED
    any_degraded = any(ph.status == CheckStatus.DEGRADED for ph in phases)
    if any_degraded or safe_mode:
        return StartupDecision(status=OverallStatus.DEGRADED, safe_mode=safe_mode, force_start_used=False)
    return StartupDecision(status=OverallStatus.OK, safe_mode=False, force_start_used=False)

