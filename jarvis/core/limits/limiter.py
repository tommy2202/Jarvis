from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional

from pydantic import BaseModel, ConfigDict, Field


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


class RateLimitRule(BaseModel):
    model_config = ConfigDict(extra="forbid")

    per_minute: int = Field(default=60, ge=1, le=1_000_000)
    cooldown_seconds: int = Field(default=0, ge=0, le=3600)


class LimitsConfigFile(BaseModel):
    """
    config/limits.json schema.
    """

    model_config = ConfigDict(extra="forbid")

    schema_version: int = Field(default=1, ge=1, le=10)
    default: RateLimitRule = Field(default_factory=RateLimitRule)
    sources: Dict[str, RateLimitRule] = Field(default_factory=dict)
    intents: Dict[str, RateLimitRule] = Field(default_factory=dict)


def default_limits_config_dict() -> Dict[str, Any]:
    # Conservative defaults; tune via config/limits.json.
    cfg = LimitsConfigFile(
        default=RateLimitRule(per_minute=120, cooldown_seconds=1),
        sources={
            "cli": RateLimitRule(per_minute=240, cooldown_seconds=0),
            "ui": RateLimitRule(per_minute=240, cooldown_seconds=0),
            "voice": RateLimitRule(per_minute=120, cooldown_seconds=1),
            "web": RateLimitRule(per_minute=120, cooldown_seconds=1),
            "system": RateLimitRule(per_minute=600, cooldown_seconds=0),
        },
        intents={},
    )
    return cfg.model_dump()


@dataclass(frozen=True)
class LimitDecision:
    allowed: bool
    reason: str = ""
    retry_after_seconds: float = 0.0
    scope: str = ""


class Limiter:
    """
    Core limiter for dispatcher intent execution (per-source + per-intent).
    This is separate from web middleware request limiting; this guards *execution*.
    """

    def __init__(self, *, config_manager: Any = None, time_fn=time.time):
        self._cfg_mgr = config_manager
        self._time = time_fn
        self._lock = threading.Lock()
        self._buckets: Dict[str, TokenBucket] = {}
        self._cooldowns_until: Dict[str, float] = {}

    def _load_cfg(self) -> LimitsConfigFile:
        raw = {}
        if self._cfg_mgr is not None:
            try:
                raw = self._cfg_mgr.read_non_sensitive("limits.json") or {}
            except Exception:
                raw = {}
        if not isinstance(raw, dict):
            raw = {}
        try:
            return LimitsConfigFile.model_validate(raw)
        except Exception:
            # Fail-safe: defaults
            return LimitsConfigFile.model_validate(default_limits_config_dict())

    def _rule_for_source(self, cfg: LimitsConfigFile, source: str) -> RateLimitRule:
        s = str(source or "").lower()
        return cfg.sources.get(s) or cfg.default

    def _rule_for_intent(self, cfg: LimitsConfigFile, intent_id: str) -> RateLimitRule:
        iid = str(intent_id or "")
        return cfg.intents.get(iid) or cfg.default

    def _allow_bucket(self, key: str, *, per_minute: int) -> tuple[bool, float]:
        """
        Returns (allowed, retry_after_seconds).
        """
        now = float(self._time())
        cap = float(max(1, int(per_minute)))
        rate = cap / 60.0
        with self._lock:
            cd_until = float(self._cooldowns_until.get(key, 0.0) or 0.0)
            if now < cd_until:
                return False, max(0.0, cd_until - now)

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
                return True, 0.0

            # retry: time until next token
            retry = (1.0 - b.tokens) / b.refill_rate if b.refill_rate > 0 else 60.0
            return False, max(0.0, float(retry))

    def allow(
        self,
        *,
        source: str,
        intent_id: str,
        user_id: str = "default",
        client_id: Optional[str] = None,
        is_admin: bool = False,
        diagnostics_override: bool = False,
    ) -> LimitDecision:
        """
        Global intent-execution limiter.

        diagnostics_override: if True and is_admin, bypasses limits.
        """
        if bool(is_admin) and bool(diagnostics_override):
            return LimitDecision(allowed=True, reason="admin_override", scope="override")

        cfg = self._load_cfg()

        src = str(source or "cli").lower()
        iid = str(intent_id or "")
        uid = str(user_id or "default")
        cid = str(client_id or "")

        src_rule = self._rule_for_source(cfg, src)
        intent_rule = self._rule_for_intent(cfg, iid)

        # Per-source limit is per (source, client_id if present else user_id) to avoid one client DoS-ing others.
        src_actor = cid or uid
        k_source = f"source:{src}:{src_actor}"
        ok, retry = self._allow_bucket(k_source, per_minute=int(src_rule.per_minute))
        if not ok:
            if int(src_rule.cooldown_seconds) > 0:
                with self._lock:
                    self._cooldowns_until[k_source] = float(self._time()) + float(src_rule.cooldown_seconds)
                retry = max(retry, float(src_rule.cooldown_seconds))
            return LimitDecision(allowed=False, reason="rate_limited_source", retry_after_seconds=retry, scope="source")

        # Per-intent limit is per (intent, source, client_id if present else user_id)
        k_intent = f"intent:{iid}:{src}:{src_actor}"
        ok2, retry2 = self._allow_bucket(k_intent, per_minute=int(intent_rule.per_minute))
        if not ok2:
            if int(intent_rule.cooldown_seconds) > 0:
                with self._lock:
                    self._cooldowns_until[k_intent] = float(self._time()) + float(intent_rule.cooldown_seconds)
                retry2 = max(retry2, float(intent_rule.cooldown_seconds))
            return LimitDecision(allowed=False, reason="rate_limited_intent", retry_after_seconds=retry2, scope="intent")

        return LimitDecision(allowed=True, reason="ok", scope="ok")

