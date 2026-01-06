from __future__ import annotations

import hashlib
import secrets
import time
from typing import Any, Dict, List, Optional, Set

from pydantic import BaseModel, Field

from jarvis.core.crypto import SecureStore
from jarvis.core.events import redact


SCOPES: Set[str] = {"read", "message", "admin"}


class ApiKeyRecord(BaseModel):
    id: str
    key_hash: str
    created_at: float
    last_used_at: Optional[float] = None
    scopes: List[str] = Field(default_factory=list)
    allowed_ips: Optional[List[str]] = None
    revoked: bool = False
    revoked_at: Optional[float] = None
    revoked_reason: Optional[str] = None
    lockouts: int = 0


class ApiKeyStore:
    """
    Encrypted API key registry. Stores only SHA-256 hashes of keys (still encrypted at rest).

    Secure store keys:
    - web.api_keys: [ApiKeyRecord...]
    """

    def __init__(self, secure_store: SecureStore):
        self.secure_store = secure_store

    def _load(self) -> List[ApiKeyRecord]:
        raw = self.secure_store.secure_get("web.api_keys") or []
        out: List[ApiKeyRecord] = []
        if isinstance(raw, list):
            for r in raw:
                try:
                    out.append(ApiKeyRecord.model_validate(r))
                except Exception:
                    continue
        return out

    def _save(self, records: List[ApiKeyRecord]) -> None:
        self.secure_store.secure_set("web.api_keys", [r.model_dump() for r in records])

    @staticmethod
    def _hash_key(key: str) -> str:
        return hashlib.sha256(key.encode("utf-8")).hexdigest()

    def create_key(self, *, scopes: List[str], allowed_ips: Optional[List[str]] = None) -> Dict[str, str]:
        scopes_norm = sorted(set([s for s in scopes if s in SCOPES]))
        if not scopes_norm:
            raise ValueError("At least one valid scope required.")
        key = secrets.token_urlsafe(32)
        rec = ApiKeyRecord(
            id=secrets.token_hex(8),
            key_hash=self._hash_key(key),
            created_at=time.time(),
            scopes=scopes_norm,
            allowed_ips=allowed_ips,
        )
        records = self._load()
        records.append(rec)
        self._save(records)
        return {"id": rec.id, "key": key}

    def list_keys(self) -> List[ApiKeyRecord]:
        return self._load()

    def revoke_key(self, key_id: str, *, reason: str = "revoked") -> bool:
        records = self._load()
        changed = False
        for r in records:
            if r.id == key_id and not r.revoked:
                r.revoked = True
                r.revoked_at = time.time()
                r.revoked_reason = reason
                changed = True
        if changed:
            self._save(records)
        return changed

    def bump_lockout(self, key_id: str) -> None:
        records = self._load()
        changed = False
        for r in records:
            if r.id == key_id:
                r.lockouts += 1
                changed = True
        if changed:
            self._save(records)

    def validate(self, provided_key: str, *, ip: Optional[str], required_scope: str) -> Dict[str, Any]:
        if required_scope not in SCOPES:
            raise ValueError("Unknown required scope.")
        if not provided_key:
            return {"ok": False, "reason": "missing"}
        h = self._hash_key(provided_key)
        records = self._load()
        for r in records:
            if secrets.compare_digest(r.key_hash, h):
                if r.revoked:
                    return {"ok": False, "reason": "revoked", "key_id": r.id}
                if required_scope not in set(r.scopes):
                    return {"ok": False, "reason": "scope_denied", "key_id": r.id}
                if r.allowed_ips is not None and ip is not None and ip not in set(r.allowed_ips):
                    return {"ok": False, "reason": "ip_denied", "key_id": r.id}
                r.last_used_at = time.time()
                self._save(records)
                return {"ok": True, "key_id": r.id, "scopes": r.scopes}
        return {"ok": False, "reason": "invalid"}

