from __future__ import annotations

import json
import os
import time

import pytest

from jarvis.core.config.manager import ConfigManager, SecretUnavailable, ConfigError
from jarvis.core.config.paths import ConfigFsPaths
from jarvis.core.crypto import generate_usb_master_key_bytes, write_usb_key
from .helpers.config_builders import build_web_config_v1


class DummyLogger:
    def info(self, *_a, **_k): ...
    def warning(self, *_a, **_k): ...
    def error(self, *_a, **_k): ...


def _mk_cm(tmp_path, *, with_usb: bool = True) -> ConfigManager:
    root = str(tmp_path)
    fs = ConfigFsPaths(root=root)
    os.makedirs(fs.config_dir, exist_ok=True)
    # minimal required files: create empty; manager will default them
    cm = ConfigManager(fs=fs, logger=DummyLogger(), read_only=False)
    cfg = cm.load_all()
    if with_usb:
        usb_path = os.path.join(root, "usb.bin")
        write_usb_key(usb_path, generate_usb_master_key_bytes())
        # override security config to use temp usb + secure store
        sec = cfg.security.model_dump()
        sec["usb_key_path"] = usb_path
        sec["secure_store_path"] = os.path.join(root, "secure", "store.enc")
        cm.save_non_sensitive("security.json", sec)
    return cm


def test_validation_rejects_unknown_fields(tmp_path):
    cm = _mk_cm(tmp_path)
    bad = cm.get().web.model_dump()
    bad["unknown_field"] = 1
    # write file then validation should fail on reload
    with pytest.raises(Exception):
        cm.save_non_sensitive("web.json", bad)


def test_corrupt_json_triggers_recovery_and_backup(tmp_path):
    cm = _mk_cm(tmp_path)
    fs = cm.fs
    # write corrupt web.json
    web_path = os.path.join(fs.config_dir, "web.json")
    with open(web_path, "w", encoding="utf-8") as f:
        f.write("{not json")
    # load_all should recover to defaults and move corrupt to backups
    cm.load_all()
    backups = os.listdir(fs.backups_dir)
    assert any("web.json" in b and "corrupt" in b for b in backups)


def test_atomic_write_preserves_integrity(tmp_path):
    cm = _mk_cm(tmp_path)
    web = cm.get().web.model_dump()
    web["port"] = 8123
    cm.save_non_sensitive("web.json", web)
    # file should be valid JSON and contain port
    with open(os.path.join(cm.fs.config_dir, "web.json"), "r", encoding="utf-8") as f:
        obj = json.load(f)
    assert obj["port"] == 8123


def test_migration_bumps_version(tmp_path):
    fs = ConfigFsPaths(root=str(tmp_path))
    os.makedirs(fs.config_dir, exist_ok=True)
    # simulate old version app.json
    with open(fs.app, "w", encoding="utf-8") as f:
        json.dump({"config_version": 1, "created_at": "x", "last_migrated_at": "x", "backups": {"max_backups_per_file": 10}, "hot_reload": {"enabled": False, "debounce_ms": 500, "poll_interval_ms": 500}}, f)
    # legacy web.json with host key
    with open(fs.web, "w", encoding="utf-8") as f:
        web = build_web_config_v1(
            overrides={
                "enabled": False,
                "host": "0.0.0.0",
                "port": 8000,
                "allowed_origins": [],
                "enable_web_ui": True,
            }
        )
        json.dump(web, f)
    cm = ConfigManager(fs=fs, logger=DummyLogger(), read_only=False)
    cfg = cm.load_all()
    assert cfg.app.config_version >= 2
    assert "bind_host" in cfg.web.model_dump()


def test_hot_reload_applies_valid_and_rejects_invalid(tmp_path):
    cm = _mk_cm(tmp_path)
    app = cm.get().app.model_dump()
    app["hot_reload"]["enabled"] = True
    cm.save_non_sensitive("app.json", app)
    cm.load_all()
    # valid change
    web = cm.get().web.model_dump()
    web["port"] = 9001
    with open(os.path.join(cm.fs.config_dir, "web.json"), "w", encoding="utf-8") as f:
        json.dump(web, f)
    assert cm.reload_if_changed() is True
    assert cm.get().web.port == 9001
    # invalid change (unknown field)
    web2 = cm.get().web.model_dump()
    web2["nope"] = 1
    with open(os.path.join(cm.fs.config_dir, "web.json"), "w", encoding="utf-8") as f:
        json.dump(web2, f)
    assert cm.reload_if_changed() is False
    assert cm.get().web.port == 9001


def test_secrets_require_usb_key(tmp_path):
    cm = _mk_cm(tmp_path, with_usb=False)
    # set_secret should fail because usb path points to default E:\ and doesn't exist in tests
    with pytest.raises(SecretUnavailable):
        cm.set_secret("x", "y")

