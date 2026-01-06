from __future__ import annotations

import time

from jarvis.core.circuit_breaker import BreakerConfig, CircuitBreaker


def test_circuit_breaker_opens_after_threshold():
    b = CircuitBreaker(BreakerConfig(failures=2, window_seconds=60, cooldown_seconds=60))
    assert b.allow() is True
    b.record_failure()
    assert b.allow() is True
    b.record_failure()
    assert b.allow() is False

