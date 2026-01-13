from __future__ import annotations

import secrets
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from jarvis.core.secure_store import SecureStore, SecretUnavailable


def _scrypt_hash(passphrase: str, salt: bytes, n: int = 2**14, r: int = 8, p: int = 1) -> bytes:
    kdf = Scrypt(salt=salt, length=32, n=n, r=r, p=p)
    return kdf.derive(passphrase.encode("utf-8"))


@dataclass
class AdminSession:
    timeout_seconds: int
    _unlocked: bool = False
    _last_activity: float = 0.0

    def is_admin(self) -> bool:
        if not self._unlocked:
            return False
        if (time.time() - self._last_activity) > self.timeout_seconds:
            self._unlocked = False
            return False
        return True

    def touch(self) -> None:
        if self._unlocked:
            self._last_activity = time.time()

    def lock(self) -> None:
        self._unlocked = False
        self._last_activity = 0.0

    def unlock(self) -> None:
        self._unlocked = True
        self._last_activity = time.time()


@dataclass
class PermissionPolicy:
    # permissions.json: {"intents": {"music.play": {...}}}
    intents: Dict[str, Dict[str, Any]]

    def for_intent(self, intent_id: str) -> Dict[str, Any]:
        return self.intents.get(intent_id, {})

    # ---- Legacy compatibility (DO NOT use for enforcement) ----
    def evaluate_via_enforcement(self, *, ctx, capability_engine, policy_engine=None) -> bool:  # noqa: ANN001
        """
        Deprecated adapter: compute allow/deny using the authoritative capability+policy path.

        This must never return True if capability or policy would deny.
        """
        try:
            cap_dec = capability_engine.evaluate(ctx)
            if not bool(getattr(cap_dec, "allowed", False)):
                return False
        except Exception:
            return False

        if policy_engine is None:
            return True

        try:
            from jarvis.core.policy.models import PolicyContext

            pctx = PolicyContext(
                trace_id=str(getattr(ctx, "trace_id", "legacy")),
                intent_id=str(getattr(ctx, "intent_id", "")),
                required_capabilities=list(getattr(cap_dec, "required_capabilities", []) or []),
                source=str(getattr(getattr(ctx, "source", None), "value", getattr(ctx, "source", "cli"))),
                client_id=getattr(ctx, "client_id", None),
                client_ip=None,
                is_admin=bool(getattr(ctx, "is_admin", False)),
                safe_mode=bool(getattr(ctx, "safe_mode", False)),
                shutting_down=bool(getattr(ctx, "shutting_down", False)),
                secure_store_mode=getattr(ctx, "secure_store_mode", None),
                tags=[],
                resource_over_budget=None,
                confirmed=bool(getattr(ctx, "confirmed", False)),
            )
            pdec = policy_engine.evaluate(pctx)
            # If policy requires confirmation, treat as not allowed for execution.
            if not bool(getattr(pdec, "allowed", False)):
                return False
            if bool(getattr(pdec, "require_confirmation", False)):
                return False
            return True
        except Exception:
            return False


@dataclass
class SecurityManager:
    secure_store: SecureStore
    admin_session: AdminSession

    def is_usb_present(self) -> bool:
        st = self.secure_store.status()
        return st.mode not in {"KEY_MISSING"}

    def has_admin_passphrase_set(self) -> bool:
        try:
            return self.secure_store.get("admin.passphrase_hash") is not None
        except SecretUnavailable:
            return False

    def set_admin_passphrase(self, passphrase: str) -> None:
        salt = secrets.token_bytes(16)
        digest = _scrypt_hash(passphrase, salt)
        payload = {"salt": salt.hex(), "digest": digest.hex(), "kdf": {"name": "scrypt", "n": 2**14, "r": 8, "p": 1}}
        self.secure_store.set("admin.passphrase_hash", payload)

    def verify_and_unlock_admin(self, passphrase: str) -> bool:
        try:
            payload = self.secure_store.get("admin.passphrase_hash")
        except SecretUnavailable:
            return False
        if not payload:
            return False
        salt = bytes.fromhex(payload["salt"])
        expected = bytes.fromhex(payload["digest"])
        kdf = payload.get("kdf") or {}
        digest = _scrypt_hash(passphrase, salt, n=int(kdf.get("n", 2**14)), r=int(kdf.get("r", 8)), p=int(kdf.get("p", 1)))
        ok = secrets.compare_digest(digest, expected)
        if ok:
            self.admin_session.unlock()
        return ok

    def lock_admin(self) -> None:
        self.admin_session.lock()

    def is_admin(self) -> bool:
        return self.admin_session.is_admin()

    def touch_admin(self) -> None:
        self.admin_session.touch()

