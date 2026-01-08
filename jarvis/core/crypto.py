from __future__ import annotations

import base64
import json
import os
import secrets
from dataclasses import dataclass
from typing import Any, Dict, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class UsbKeyMissingError(RuntimeError):
    pass


class SecureStoreLockedError(RuntimeError):
    pass


def key_id_from_key_bytes(key: bytes) -> str:
    import hashlib

    h = hashlib.sha256(key).hexdigest()
    return h[:16]


def _b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("ascii")


def _b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s.encode("ascii"))


def generate_usb_master_key_bytes() -> bytes:
    # AES-256 key
    return secrets.token_bytes(32)


def write_usb_key(path: str, key_bytes: bytes) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(key_bytes)


def read_usb_key(path: str) -> bytes:
    if not os.path.exists(path):
        raise UsbKeyMissingError(f"USB key not found at {path!r}")
    with open(path, "rb") as f:
        b = f.read()
    if len(b) != 32:
        raise ValueError("USB master key must be 32 bytes (AES-256).")
    return b


def best_effort_restrict_permissions(path: str) -> None:
    """
    Best-effort permissions tightening.
    On Windows this is limited; on POSIX it sets 0o600.
    """
    try:
        if os.name != "nt":
            os.chmod(path, 0o600)
    except Exception:
        return


def aesgcm_encrypt(key: bytes, plaintext: bytes, aad: bytes = b"") -> Dict[str, str]:
    aes = AESGCM(key)
    nonce = secrets.token_bytes(12)
    ct = aes.encrypt(nonce, plaintext, aad or None)
    return {"v": 1, "nonce": _b64e(nonce), "ciphertext": _b64e(ct)}


def aesgcm_decrypt(key: bytes, blob: Dict[str, str], aad: bytes = b"") -> bytes:
    if blob.get("v") != 1:
        raise ValueError("Unsupported encrypted blob version.")
    aes = AESGCM(key)
    nonce = _b64d(blob["nonce"])
    ct = _b64d(blob["ciphertext"])
    return aes.decrypt(nonce, ct, aad or None)


@dataclass
class SecureStore:
    """
    Encrypted JSON key/value store backed by AES-GCM and a USB master key.

    - If USB key missing: store is locked (read/write prohibited).
    - File format: JSON with AES-GCM nonce+ciphertext.
    """

    usb_key_path: str
    store_path: str
    aad: bytes = b"jarvis.secure_store.v1"

    def _get_master_key(self) -> bytes:
        return read_usb_key(self.usb_key_path)

    def _load_plain(self) -> Dict[str, Any]:
        if not os.path.exists(self.store_path):
            return {}
        with open(self.store_path, "r", encoding="utf-8") as f:
            blob = json.load(f)
        key = self._get_master_key()
        pt = aesgcm_decrypt(key, blob, aad=self.aad)
        return json.loads(pt.decode("utf-8"))

    def _save_plain(self, data: Dict[str, Any]) -> None:
        os.makedirs(os.path.dirname(self.store_path), exist_ok=True)
        key = self._get_master_key()
        pt = json.dumps(data, ensure_ascii=False, sort_keys=True).encode("utf-8")
        blob = aesgcm_encrypt(key, pt, aad=self.aad)
        tmp = self.store_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(blob, f, indent=2, ensure_ascii=False, sort_keys=True)
            f.write("\n")
        os.replace(tmp, self.store_path)

    def is_unlocked(self) -> bool:
        try:
            _ = self._get_master_key()
            return True
        except UsbKeyMissingError:
            return False

    def secure_get(self, key: str) -> Optional[Any]:
        if not self.is_unlocked():
            raise SecureStoreLockedError("USB key required to read secure store.")
        data = self._load_plain()
        return data.get(key)

    def secure_set(self, key: str, value: Any) -> None:
        if not self.is_unlocked():
            raise SecureStoreLockedError("USB key required to write secure store.")
        data = self._load_plain()
        data[key] = value
        self._save_plain(data)

    def secure_delete(self, key: str) -> None:
        if not self.is_unlocked():
            raise SecureStoreLockedError("USB key required to write secure store.")
        data = self._load_plain()
        if key in data:
            del data[key]
            self._save_plain(data)

