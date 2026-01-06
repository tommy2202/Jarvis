from __future__ import annotations

import secrets
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from jarvis.core.crypto import SecureStore, SecureStoreLockedError


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


@dataclass
class SecurityManager:
    secure_store: SecureStore
    admin_session: AdminSession

    def is_usb_present(self) -> bool:
        return self.secure_store.is_unlocked()

    def has_admin_passphrase_set(self) -> bool:
        try:
            return self.secure_store.secure_get("admin.passphrase_hash") is not None
        except SecureStoreLockedError:
            return False

    def set_admin_passphrase(self, passphrase: str) -> None:
        salt = secrets.token_bytes(16)
        digest = _scrypt_hash(passphrase, salt)
        payload = {"salt": salt.hex(), "digest": digest.hex(), "kdf": {"name": "scrypt", "n": 2**14, "r": 8, "p": 1}}
        self.secure_store.secure_set("admin.passphrase_hash", payload)

    def verify_and_unlock_admin(self, passphrase: str) -> bool:
        try:
            payload = self.secure_store.secure_get("admin.passphrase_hash")
        except SecureStoreLockedError:
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

