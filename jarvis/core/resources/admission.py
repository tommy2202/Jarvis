from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Callable, Optional

from jarvis.core.resources.models import AdmissionAction, AdmissionDecision, ResourceSnapshot


@dataclass(frozen=True)
class DelayConfig:
    max_delay_seconds: float = 15.0


class AdmissionGate:
    """
    Implements DELAY behavior deterministically:
    - sleep in small chunks (or injected sleep)
    - re-check snapshot
    - stop after max_delay_seconds
    """

    def __init__(self, *, now: Callable[[], float] = time.time, sleep: Callable[[float], None] = time.sleep):
        self._now = now
        self._sleep = sleep

    def maybe_delay(
        self,
        *,
        decision: AdmissionDecision,
        cfg: DelayConfig,
        recheck: Callable[[], tuple[AdmissionDecision, ResourceSnapshot]],
    ) -> AdmissionDecision:
        if decision.action != AdmissionAction.DELAY:
            return decision
        deadline = self._now() + float(cfg.max_delay_seconds)
        delay = max(0.0, float(decision.delay_seconds))
        while self._now() < deadline:
            if delay > 0:
                self._sleep(min(delay, 0.25))
            new_dec, _snap = recheck()
            if new_dec.allowed:
                return new_dec
            # keep waiting only if still DELAY and we haven't exceeded deadline
            if new_dec.action != AdmissionAction.DELAY:
                return new_dec
            delay = max(0.0, float(new_dec.delay_seconds))
        # deadline reached: return the latest decision (usually deny/throttle)
        new_dec, _ = recheck()
        if new_dec.action == AdmissionAction.DELAY:
            # force deny after deadline
            return AdmissionDecision(
                allowed=False,
                action=AdmissionAction.DENY,
                delay_seconds=0.0,
                reasons=list(new_dec.reasons) + ["Delay limit reached."],
                remediation="System remained over budget. Try again later.",
                snapshot=dict(new_dec.snapshot),
            )
        return new_dec

