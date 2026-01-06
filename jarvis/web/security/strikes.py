from __future__ import annotations

import time
from typing import Any, Dict, Optional

from pydantic import BaseModel, Field

from jarvis.core.secure_store import SecureStore, SecretUnavailable


class LockoutConfig(BaseModel):
    strike_threshold: int = Field(default=5, ge=1, le=1000)
    lockout_minutes: int = Field(default=15, ge=1, le=24 * 60)
    permanent_after: int = Field(default=3, ge=1, le=100)


class StrikeEntry(BaseModel):
    strikes: int = 0
    lockout_until: Optional[float] = None
    lockouts: int = 0


class SecurityState(BaseModel):
    ips: Dict[str, StrikeEntry] = Field(default_factory=dict)
    keys: Dict[str, StrikeEntry] = Field(default_factory=dict)


class StrikeManager:
    """
    Persistent strike/lockout system stored in encrypted secure store.

    Secure store key:
    - web.security_state: SecurityState
    """

    def __init__(self, secure_store: SecureStore, cfg: LockoutConfig):
        self.secure_store = secure_store
        self.cfg = cfg

    def _load(self) -> SecurityState:
        try:
            raw = self.secure_store.get("web.security_state") or {}
        except SecretUnavailable:
            raw = {}
        try:
            return SecurityState.model_validate(raw)
        except Exception:
            return SecurityState()

    def _save(self, st: SecurityState) -> None:
        self.secure_store.set("web.security_state", st.model_dump())

    def is_ip_locked(self, ip: str) -> bool:
        st = self._load()
        e = st.ips.get(ip)
        if not e or not e.lockout_until:
            return False
        return time.time() < float(e.lockout_until)

    def is_key_locked(self, key_id: str) -> bool:
        st = self._load()
        e = st.keys.get(key_id)
        if not e or not e.lockout_until:
            return False
        return time.time() < float(e.lockout_until)

    def record_strike(self, *, ip: Optional[str], key_id: Optional[str]) -> Dict[str, Any]:
        st = self._load()
        now = time.time()
        lockout_seconds = int(self.cfg.lockout_minutes) * 60
        out: Dict[str, Any] = {"ip_locked": False, "key_locked": False}

        if ip:
            e = st.ips.get(ip) or StrikeEntry()
            e.strikes += 1
            if e.strikes >= int(self.cfg.strike_threshold):
                e.lockouts += 1
                e.strikes = 0
                e.lockout_until = now + lockout_seconds
                out["ip_locked"] = True
            st.ips[ip] = e

        if key_id:
            e2 = st.keys.get(key_id) or StrikeEntry()
            e2.strikes += 1
            if e2.strikes >= int(self.cfg.strike_threshold):
                e2.lockouts += 1
                e2.strikes = 0
                e2.lockout_until = now + lockout_seconds
                out["key_locked"] = True
            st.keys[key_id] = e2

        self._save(st)
        return out

    def get_lockouts(self) -> Dict[str, Any]:
        st = self._load()
        now = time.time()
        ips = {k: v.model_dump() for k, v in st.ips.items() if v.lockout_until and now < float(v.lockout_until)}
        keys = {k: v.model_dump() for k, v in st.keys.items() if v.lockout_until and now < float(v.lockout_until)}
        return {"ips": ips, "keys": keys}

    def unlock_ip(self, ip: str) -> bool:
        st = self._load()
        if ip not in st.ips:
            return False
        st.ips[ip].lockout_until = None
        st.ips[ip].strikes = 0
        self._save(st)
        return True

    def key_lockouts_count(self, key_id: str) -> int:
        st = self._load()
        e = st.keys.get(key_id)
        return int(e.lockouts) if e else 0

