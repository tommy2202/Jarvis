from __future__ import annotations

import json

import pytest

from jarvis.core.crypto import (
    SecureStore,
    SecureStoreLockedError,
    aesgcm_decrypt,
    aesgcm_encrypt,
    generate_usb_master_key_bytes,
    write_usb_key,
)


def test_aesgcm_round_trip():
    key = generate_usb_master_key_bytes()
    pt = b"hello jarvis"
    blob = aesgcm_encrypt(key, pt, aad=b"test")
    out = aesgcm_decrypt(key, blob, aad=b"test")
    assert out == pt


def test_secure_store_write_requires_usb_key(tmp_path):
    store = SecureStore(usb_key_path=str(tmp_path / "missing.bin"), store_path=str(tmp_path / "store.enc"))
    with pytest.raises(SecureStoreLockedError):
        store.secure_set("x", "y")


def test_secure_store_round_trip(tmp_path):
    usb = tmp_path / "usb.bin"
    write_usb_key(str(usb), generate_usb_master_key_bytes())
    store = SecureStore(usb_key_path=str(usb), store_path=str(tmp_path / "store.enc"))
    store.secure_set("web.api_key", "abc")
    assert store.secure_get("web.api_key") == "abc"

