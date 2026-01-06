from __future__ import annotations

import time
import threading
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional


class BreakerState(str, Enum):
    CLOSED = "CLOSED"
    OPEN = "OPEN"
    HALF_OPEN = "HALF_OPEN"


@dataclass
class BreakerConfig:
    failures: int
    window_seconds: int
    cooldown_seconds: int


class CircuitBreaker:
    def __init__(self, cfg: BreakerConfig):
        self.cfg = cfg
        self._lock = threading.Lock()
        self._fail_times: List[float] = []
        self._state = BreakerState.CLOSED
        self._opened_at: Optional[float] = None
        self._half_open_tested: bool = False

    def state(self) -> BreakerState:
        with self._lock:
            self._update_state_locked()
            return self._state

    def allow(self) -> bool:
        with self._lock:
            self._update_state_locked()
            if self._state == BreakerState.CLOSED:
                return True
            if self._state == BreakerState.OPEN:
                return False
            # HALF_OPEN: allow exactly one test call
            if not self._half_open_tested:
                self._half_open_tested = True
                return True
            return False

    def record_success(self) -> None:
        with self._lock:
            self._fail_times.clear()
            self._state = BreakerState.CLOSED
            self._opened_at = None
            self._half_open_tested = False

    def record_failure(self) -> None:
        with self._lock:
            now = time.time()
            self._fail_times.append(now)
            cutoff = now - float(self.cfg.window_seconds)
            self._fail_times = [t for t in self._fail_times if t >= cutoff]
            if len(self._fail_times) >= int(self.cfg.failures):
                self._state = BreakerState.OPEN
                self._opened_at = now
                self._half_open_tested = False

    def _update_state_locked(self) -> None:
        if self._state == BreakerState.OPEN and self._opened_at is not None:
            if (time.time() - self._opened_at) >= float(self.cfg.cooldown_seconds):
                self._state = BreakerState.HALF_OPEN
                self._half_open_tested = False


class BreakerRegistry:
    def __init__(self, breakers: Dict[str, CircuitBreaker]):
        self.breakers = breakers

    def status(self) -> Dict[str, str]:
        return {k: v.state().value for k, v in self.breakers.items()}

