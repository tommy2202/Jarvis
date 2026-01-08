from __future__ import annotations

import json
import os
import shutil
import threading
import time
import uuid
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field

from jarvis.core.crypto import (
    UsbKeyMissingError,
    aesgcm_decrypt,
    aesgcm_encrypt,
    best_effort_restrict_permissions,
    key_id_from_key_bytes,
    read_usb_key,
)
from jarvis.core.security_events import SecurityAuditLogger


class SecureStoreMode(str, Enum):
    READY = "READY"
    KEY_MISSING = "KEY_MISSING"
    STORE_MISSING = "STORE_MISSING"
    STORE_CORRUPT = "STORE_CORRUPT"
    KEY_MISMATCH = "KEY_MISMATCH"
    READ_ONLY = "READ_ONLY"


class SecretUnavailable(RuntimeError):
    pass


class SecureStoreStatus(BaseModel):
    model_config = ConfigDict(extra="forbid")
    mode: SecureStoreMode
    status: str
    next_steps: str
    key_id: Optional[str] = None
    store_version: Optional[int] = None
    store_id: Optional[str] = None
    last_error: Optional[str] = None


class _EncryptedPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")
    store_version: int = Field(default=1, ge=1)
    store_id: str
    key_id: str
    created_at: float
    updated_at: float
    record_count: int
    secrets: Dict[str, Any] = Field(default_factory=dict)


@dataclass
class SecureStore:
    """
    Versioned, tamper-evident encrypted secure store.

    Files:
    - secure/secure_store.enc          (JSON with AES-GCM nonce+ciphertext)
    - secure/store.meta.json           (plaintext, non-sensitive: store_id + key_id + store_version)
    - secure/backups/secure_store.*.enc backups
    - secure/backups/last_known_good.enc
    """

    usb_key_path: str
    store_path: str
    meta_path: str = os.path.join("secure", "store.meta.json")
    backups_dir: str = os.path.join("secure", "backups")
    max_backups: int = 10
    max_bytes: int = 65536
    read_only: bool = False
    aad: bytes = b"jarvis.secure_store.container.v1"

    def __post_init__(self) -> None:
        self._lock = threading.Lock()
        self._audit = SecurityAuditLogger(path=os.path.join("logs", "security.jsonl"))
        self._shutdown_writes = False
        self._writes_paused = False
        self._pause_token: Optional[str] = None

    def begin_shutdown(self) -> None:
        """
        Prevent new writes during shutdown (safety).
        """
        with self._lock:
            self._shutdown_writes = True

    def pause_writes(self) -> str:
        """
        Temporarily pause writes (for backups). Returns a token required for resume.
        """
        with self._lock:
            tok = uuid.uuid4().hex
            self._writes_paused = True
            self._pause_token = tok
            return tok

    def resume_writes(self, token: str) -> None:
        with self._lock:
            if self._pause_token and token == self._pause_token:
                self._writes_paused = False
                self._pause_token = None

    # ---------- public API ----------
    def status(self) -> SecureStoreStatus:
        with self._lock:
            return self._status_locked()

    def export_public_status(self) -> Dict[str, Any]:
        st = self.status()
        return {
            "mode": st.mode.value,
            "status": st.status,
            "next_steps": st.next_steps,
            "key_id": st.key_id,
            "store_version": st.store_version,
            "store_id": st.store_id,
        }

    def list_keys(self, prefix: Optional[str] = None) -> List[str]:
        payload = self._load_payload_or_raise()
        keys = sorted(payload.secrets.keys())
        if prefix:
            keys = [k for k in keys if k.startswith(prefix)]
        return keys

    def get(self, key: str) -> Any:
        payload = self._load_payload_or_raise()
        return payload.secrets.get(key)

    def set(self, key: str, value: Any, *, trace_id: str = "secure") -> None:
        if self._shutdown_writes or self._writes_paused:
            raise SecretUnavailable("Secure store writes are blocked during shutdown.")
        if self.read_only:
            self._audit.log(trace_id=trace_id, severity="WARN", event="secure.write_blocked", ip=None, endpoint="secure_store", outcome="read_only", details={"key": key})
            raise SecretUnavailable("Secure store is read-only.")
        # ensure JSON-serializable and size bounded
        try:
            test = json.dumps(value, ensure_ascii=False)
        except Exception as e:  # noqa: BLE001
            raise ValueError("Secret value must be JSON-serializable.") from e
        if len(test.encode("utf-8")) > int(self.max_bytes):
            raise ValueError("Secret value too large.")

        with self._lock:
            payload = self._load_payload_locked(create_if_missing=True)
            payload.secrets[key] = value
            payload.updated_at = time.time()
            payload.record_count = len(payload.secrets)
            self._write_payload_locked(payload)
            self._audit.log(trace_id=trace_id, severity="INFO", event="secure.set", ip=None, endpoint="secure_store", outcome="ok", details={"key": key})

    def delete(self, key: str, *, trace_id: str = "secure") -> None:
        if self._shutdown_writes or self._writes_paused:
            raise SecretUnavailable("Secure store writes are blocked during shutdown.")
        if self.read_only:
            raise SecretUnavailable("Secure store is read-only.")
        with self._lock:
            payload = self._load_payload_locked(create_if_missing=False)
            if key in payload.secrets:
                del payload.secrets[key]
                payload.updated_at = time.time()
                payload.record_count = len(payload.secrets)
                self._write_payload_locked(payload)
            self._audit.log(trace_id=trace_id, severity="INFO", event="secure.delete", ip=None, endpoint="secure_store", outcome="ok", details={"key": key})

    def backup_now(self) -> Optional[str]:
        with self._lock:
            if not os.path.exists(self.store_path):
                return None
            os.makedirs(self.backups_dir, exist_ok=True)
            ts = time.strftime("%Y%m%d_%H%M%S", time.gmtime())
            dst = os.path.join(self.backups_dir, f"secure_store.{ts}.enc")
            shutil.copy2(self.store_path, dst)
            self._enforce_backup_retention()
            return dst

    def restore_backup(self, backup_path: str, *, trace_id: str = "secure") -> None:
        with self._lock:
            if not os.path.exists(backup_path):
                raise FileNotFoundError(backup_path)
            # do not overwrite without making a backup
            self.backup_now()
            os.makedirs(os.path.dirname(self.store_path), exist_ok=True)
            shutil.copy2(backup_path, self.store_path)
            self._audit.log(trace_id=trace_id, severity="HIGH", event="secure.restore", ip=None, endpoint="secure_store", outcome="ok", details={"backup": os.path.basename(backup_path)})
            # validate decrypt
            _ = self._load_payload_locked(create_if_missing=False)

    def rotate_key_prepare(self, *, new_key_path: str, new_store_path: str) -> Dict[str, Any]:
        """
        Safe rotation: decrypt with current key, re-encrypt with new key bytes, write .new files.
        Does not modify existing key/store.
        """
        with self._lock:
            payload = self._load_payload_locked(create_if_missing=False)
            old_key = self._read_key_locked()
            old_key_id = key_id_from_key_bytes(old_key)
            # new key bytes
            if os.path.exists(new_key_path):
                raise FileExistsError(new_key_path)
            import secrets

            new_key = secrets.token_bytes(32)
            os.makedirs(os.path.dirname(new_key_path) or ".", exist_ok=True)
            with open(new_key_path, "wb") as f:
                f.write(new_key)
            best_effort_restrict_permissions(new_key_path)
            new_key_id = key_id_from_key_bytes(new_key)

            payload.key_id = new_key_id
            payload.updated_at = time.time()
            blob = aesgcm_encrypt(new_key, json.dumps(payload.model_dump(), ensure_ascii=False, sort_keys=True).encode("utf-8"), aad=self.aad)
            os.makedirs(os.path.dirname(new_store_path) or ".", exist_ok=True)
            with open(new_store_path, "w", encoding="utf-8") as f:
                json.dump(blob, f, indent=2, ensure_ascii=False, sort_keys=True)
                f.write("\n")
            return {"old_key_id": old_key_id, "new_key_id": new_key_id, "new_key_path": new_key_path, "new_store_path": new_store_path}

    # ---------- internal ----------
    def _status_locked(self) -> SecureStoreStatus:
        # key check
        try:
            key = read_usb_key(self.usb_key_path)
        except UsbKeyMissingError:
            return SecureStoreStatus(
                mode=SecureStoreMode.KEY_MISSING,
                status="USB key not found.",
                next_steps=f"Insert USB key and ensure it exists at {self.usb_key_path}. Run scripts/create_usb_key.py if needed.",
                last_error="key_missing",
            )
        key_id = key_id_from_key_bytes(key)

        # store file check
        if not os.path.exists(self.store_path):
            return SecureStoreStatus(
                mode=SecureStoreMode.STORE_MISSING,
                status="Secure store file missing.",
                next_steps="Create it by setting a secret (e.g. scripts/set_secret.py) or restore from backups.",
                key_id=key_id,
                last_error="store_missing",
            )

        # meta check for quick mismatch detection
        meta = self._read_meta_locked()
        if meta and meta.get("key_id") and meta.get("key_id") != key_id:
            return SecureStoreStatus(
                mode=SecureStoreMode.KEY_MISMATCH,
                status="USB key does not match this secure store.",
                next_steps="Use the original USB key for this store, or restore the correct store/key pair from backups. Use scripts/check_usb_key.py to confirm key_id.",
                key_id=key_id,
                store_id=meta.get("store_id"),
                store_version=meta.get("store_version"),
                last_error="key_mismatch",
            )

        # decrypt check
        try:
            payload = self._load_payload_locked(create_if_missing=False)
        except Exception as e:  # noqa: BLE001
            return SecureStoreStatus(
                mode=SecureStoreMode.STORE_CORRUPT,
                status="Secure store is corrupt or cannot be decrypted.",
                next_steps="Do not overwrite. Restore from secure/backups or recreate store if you accept data loss. Use scripts/restore_secure_store.py to restore a backup.",
                key_id=key_id,
                last_error=str(e),
            )

        # compare decrypted meta with plaintext meta (tamper signal)
        if meta:
            if meta.get("store_id") and meta.get("store_id") != payload.store_id:
                self._audit.log(trace_id="secure", severity="HIGH", event="secure.meta_mismatch", ip=None, endpoint="secure_store", outcome="mismatch", details={"field": "store_id"})
            if meta.get("key_id") and meta.get("key_id") != payload.key_id:
                self._audit.log(trace_id="secure", severity="HIGH", event="secure.meta_mismatch", ip=None, endpoint="secure_store", outcome="mismatch", details={"field": "key_id"})

        if self.read_only:
            return SecureStoreStatus(
                mode=SecureStoreMode.READ_ONLY,
                status="Secure store is available (read-only mode).",
                next_steps="Disable read-only mode to write secrets.",
                key_id=key_id,
                store_id=payload.store_id,
                store_version=payload.store_version,
            )

        return SecureStoreStatus(
            mode=SecureStoreMode.READY,
            status="Secure store ready.",
            next_steps="No action needed.",
            key_id=key_id,
            store_id=payload.store_id,
            store_version=payload.store_version,
        )

    def _read_key_locked(self) -> bytes:
        try:
            return read_usb_key(self.usb_key_path)
        except UsbKeyMissingError as e:
            raise SecretUnavailable(str(e)) from e

    def _read_meta_locked(self) -> Optional[Dict[str, Any]]:
        try:
            if not os.path.exists(self.meta_path):
                return None
            with open(self.meta_path, "r", encoding="utf-8") as f:
                obj = json.load(f)
            return obj if isinstance(obj, dict) else None
        except Exception:
            return None

    def _write_meta_locked(self, payload: _EncryptedPayload) -> None:
        os.makedirs(os.path.dirname(self.meta_path), exist_ok=True)
        meta = {"store_version": payload.store_version, "store_id": payload.store_id, "key_id": payload.key_id, "updated_at": payload.updated_at}
        tmp = self.meta_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(meta, f, indent=2, ensure_ascii=False, sort_keys=True)
            f.write("\n")
        os.replace(tmp, self.meta_path)

    def _load_payload_or_raise(self) -> _EncryptedPayload:
        with self._lock:
            st = self._status_locked()
            if st.mode in {SecureStoreMode.KEY_MISSING, SecureStoreMode.KEY_MISMATCH, SecureStoreMode.STORE_CORRUPT}:
                self._audit.log(trace_id="secure", severity="WARN", event="secure.unavailable", ip=None, endpoint="secure_store", outcome=st.mode.value, details={"next": st.next_steps})
                raise SecretUnavailable(st.next_steps)
            return self._load_payload_locked(create_if_missing=(st.mode == SecureStoreMode.STORE_MISSING))

    def _load_payload_locked(self, *, create_if_missing: bool) -> _EncryptedPayload:
        key = self._read_key_locked()
        key_id = key_id_from_key_bytes(key)

        if not os.path.exists(self.store_path):
            if not create_if_missing:
                raise SecretUnavailable("Secure store missing.")
            payload = _EncryptedPayload(
                store_version=1,
                store_id=uuid.uuid4().hex,
                key_id=key_id,
                created_at=time.time(),
                updated_at=time.time(),
                record_count=0,
                secrets={},
            )
            self._write_payload_locked(payload, key_override=key)
            return payload

        with open(self.store_path, "r", encoding="utf-8") as f:
            blob = json.load(f)
        pt = aesgcm_decrypt(key, blob, aad=self.aad)
        obj = json.loads(pt.decode("utf-8"))
        payload = _EncryptedPayload.model_validate(obj)
        # key_id mismatch inside payload means we used wrong key or tampered store.
        if payload.key_id != key_id:
            raise SecretUnavailable("KEY_MISMATCH: decrypted payload key_id mismatch.")

        # update last known good
        self._write_last_known_good()
        # ensure meta file exists/updated
        self._write_meta_locked(payload)
        return payload

    def _write_payload_locked(self, payload: _EncryptedPayload, *, key_override: Optional[bytes] = None) -> None:
        key = key_override or self._read_key_locked()
        os.makedirs(os.path.dirname(self.store_path), exist_ok=True)
        self._backup_before_write()
        pt = json.dumps(payload.model_dump(), ensure_ascii=False, sort_keys=True).encode("utf-8")
        if len(pt) > int(self.max_bytes):
            raise ValueError("Secure store payload too large.")
        blob = aesgcm_encrypt(key, pt, aad=self.aad)
        tmp = self.store_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(blob, f, indent=2, ensure_ascii=False, sort_keys=True)
            f.write("\n")
        os.replace(tmp, self.store_path)
        self._write_meta_locked(payload)
        self._write_last_known_good()

    def _backup_before_write(self) -> None:
        if not os.path.exists(self.store_path):
            return
        os.makedirs(self.backups_dir, exist_ok=True)
        ts = time.strftime("%Y%m%d_%H%M%S", time.gmtime())
        dst = os.path.join(self.backups_dir, f"secure_store.{ts}.enc")
        shutil.copy2(self.store_path, dst)
        self._enforce_backup_retention()
        self._audit.log(trace_id="secure", severity="INFO", event="secure.backup", ip=None, endpoint="secure_store", outcome="ok", details={"file": os.path.basename(dst)})

    def _enforce_backup_retention(self) -> None:
        try:
            items = [os.path.join(self.backups_dir, f) for f in os.listdir(self.backups_dir) if f.startswith("secure_store.") and f.endswith(".enc")]
            items.sort(key=lambda p: os.path.getmtime(p), reverse=True)
            for p in items[int(self.max_backups) :]:
                try:
                    os.remove(p)
                except OSError:
                    pass
        except Exception:
            pass

    def _write_last_known_good(self) -> None:
        try:
            os.makedirs(self.backups_dir, exist_ok=True)
            if os.path.exists(self.store_path):
                shutil.copy2(self.store_path, os.path.join(self.backups_dir, "last_known_good.enc"))
        except Exception:
            pass

