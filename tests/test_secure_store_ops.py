from __future__ import annotations

import json
import os

import pytest

from jarvis.core.crypto import generate_usb_master_key_bytes, write_usb_key
from jarvis.core.secure_store import SecureStore, SecretUnavailable


def test_create_key_and_store_round_trip(tmp_path):
    usb = tmp_path / "usb.bin"
    write_usb_key(str(usb), generate_usb_master_key_bytes())
    store = SecureStore(usb_key_path=str(usb), store_path=str(tmp_path / "secure_store.enc"), meta_path=str(tmp_path / "store.meta.json"), backups_dir=str(tmp_path / "backups"))
    assert store.status().mode.value in {"STORE_MISSING", "READY"}
    store.set("web.api_keys", [{"id": "1"}])
    assert store.get("web.api_keys")[0]["id"] == "1"
    assert store.status().mode.value in {"READY", "READ_ONLY"}
    assert os.path.exists(store.meta_path)


def test_key_missing_mode(tmp_path):
    store = SecureStore(usb_key_path=str(tmp_path / "missing.bin"), store_path=str(tmp_path / "secure_store.enc"), meta_path=str(tmp_path / "store.meta.json"), backups_dir=str(tmp_path / "backups"))
    st = store.status()
    assert st.mode.value == "KEY_MISSING"
    with pytest.raises(SecretUnavailable):
        store.get("x")


def test_key_mismatch_mode(tmp_path):
    usb1 = tmp_path / "usb1.bin"
    usb2 = tmp_path / "usb2.bin"
    write_usb_key(str(usb1), generate_usb_master_key_bytes())
    write_usb_key(str(usb2), generate_usb_master_key_bytes())
    store1 = SecureStore(usb_key_path=str(usb1), store_path=str(tmp_path / "secure_store.enc"), meta_path=str(tmp_path / "store.meta.json"), backups_dir=str(tmp_path / "backups"))
    store1.set("a", "b")
    store2 = SecureStore(usb_key_path=str(usb2), store_path=str(tmp_path / "secure_store.enc"), meta_path=str(tmp_path / "store.meta.json"), backups_dir=str(tmp_path / "backups"))
    assert store2.status().mode.value == "KEY_MISMATCH"


def test_corrupt_store_mode(tmp_path):
    usb = tmp_path / "usb.bin"
    write_usb_key(str(usb), generate_usb_master_key_bytes())
    path = tmp_path / "secure_store.enc"
    path.write_text("{not json", encoding="utf-8")
    store = SecureStore(usb_key_path=str(usb), store_path=str(path), meta_path=str(tmp_path / "store.meta.json"), backups_dir=str(tmp_path / "backups"))
    st = store.status()
    assert st.mode.value == "STORE_CORRUPT"


def test_backup_created_on_set(tmp_path):
    usb = tmp_path / "usb.bin"
    write_usb_key(str(usb), generate_usb_master_key_bytes())
    store = SecureStore(usb_key_path=str(usb), store_path=str(tmp_path / "secure_store.enc"), meta_path=str(tmp_path / "store.meta.json"), backups_dir=str(tmp_path / "backups"), max_backups=10)
    store.set("k1", "v1")
    store.set("k2", "v2")
    assert os.path.isdir(store.backups_dir)
    files = [f for f in os.listdir(store.backups_dir) if f.startswith("secure_store.") and f.endswith(".enc")]
    assert len(files) >= 1


def test_rotation_flow_new_key_can_decrypt_old_key_cannot(tmp_path):
    usb = tmp_path / "usb.bin"
    write_usb_key(str(usb), generate_usb_master_key_bytes())
    store_path = tmp_path / "secure_store.enc"
    meta_path = tmp_path / "store.meta.json"
    backups = tmp_path / "backups"
    store = SecureStore(usb_key_path=str(usb), store_path=str(store_path), meta_path=str(meta_path), backups_dir=str(backups))
    store.set("x", "y")

    new_key_path = str(tmp_path / "usb_new.bin")
    new_store_path = str(tmp_path / "secure_store_new.enc")
    info = store.rotate_key_prepare(new_key_path=new_key_path, new_store_path=new_store_path)

    # Old key should not decrypt the new store (key_id mismatch after decrypt)
    store_old = SecureStore(usb_key_path=str(usb), store_path=new_store_path, meta_path=str(tmp_path / "meta2.json"), backups_dir=str(backups))
    assert store_old.status().mode.value in {"STORE_CORRUPT", "KEY_MISMATCH"}

    # New key should decrypt
    store_new = SecureStore(usb_key_path=new_key_path, store_path=new_store_path, meta_path=str(tmp_path / "meta3.json"), backups_dir=str(backups))
    assert store_new.get("x") == "y"


def test_list_keys(tmp_path):
    usb = tmp_path / "usb.bin"
    write_usb_key(str(usb), generate_usb_master_key_bytes())
    store = SecureStore(usb_key_path=str(usb), store_path=str(tmp_path / "secure_store.enc"), meta_path=str(tmp_path / "store.meta.json"), backups_dir=str(tmp_path / "backups"))
    store.set("a.one", 1)
    store.set("a.two", 2)
    store.set("b.three", 3)
    assert store.list_keys(prefix="a.") == ["a.one", "a.two"]

