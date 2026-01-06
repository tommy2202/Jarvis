from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Dict, Optional


@dataclass
class TokenBucket:
    """
    Token bucket rate limiter:
    - capacity = max tokens in bucket
    - refill_rate = tokens per second
    Each request consumes 1 token.
    """

    capacity: float
    refill_rate: float
    tokens: float
    last_refill: float


class RateLimiter:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._buckets: Dict[str, TokenBucket] = {}

    def allow(self, key: str, *, per_minute: int) -> bool:
        now = time.time()
        cap = float(max(1, int(per_minute)))
        rate = cap / 60.0
        with self._lock:
            b = self._buckets.get(key)
            if b is None:
                b = TokenBucket(capacity=cap, refill_rate=rate, tokens=cap, last_refill=now)
                self._buckets[key] = b
            # refill
            elapsed = max(0.0, now - b.last_refill)
            b.tokens = min(b.capacity, b.tokens + elapsed * b.refill_rate)
            b.last_refill = now
            if b.tokens >= 1.0:
                b.tokens -= 1.0
                return True
            return False

