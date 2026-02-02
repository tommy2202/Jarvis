from __future__ import annotations

import json
import os
from types import SimpleNamespace

import pytest

from jarvis.core.capabilities.audit import CapabilityAuditLogger
from jarvis.core.capabilities.engine import CapabilityEngine
from jarvis.core.capabilities.loader import default_config_dict, validate_and_normalize
from jarvis.core.config.io import read_json_file, atomic_write_json
from jarvis.core.config.manager import ConfigError, ConfigManager
from jarvis.core.config.paths import ConfigFsPaths
from jarvis.core.ops_log import OpsLogger
from jarvis.core.policy.engine import PolicyEngine
from jarvis.core.policy.models import PolicyConfigFile
from jarvis.core.startup.runner import StartupFlags, StartupSelfCheckRunner
from .helpers.config_builders import build_capabilities_config_v1, build_policy_config_v1
from .helpers.fakes import FakeDispatcher


class _L:
    def info(self, *_a, **_k): ...
    def warning(self, *_a, **_k): ...
    def error(self, *_a, **_k): ...


def _write_json(path: str, obj: dict) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)
        f.write("\n")


def test_invalid_schema_version_fails_load(tmp_path):
    cfg_dir = tmp_path / "config"
    os.makedirs(cfg_dir, exist_ok=True)
    policy = build_policy_config_v1(schema_version=99)
    _write_json(
        str(cfg_dir / "policy.json"),
        policy,
    )
    cm = ConfigManager(fs=ConfigFsPaths(str(tmp_path)), logger=_L())
    with pytest.raises(ConfigError, match="schema_version"):
        cm.load_all()


def test_missing_required_field_fails_load(tmp_path):
    cfg_dir = tmp_path / "config"
    os.makedirs(cfg_dir, exist_ok=True)
    caps = build_capabilities_config_v1()
    caps.pop("capabilities", None)
    _write_json(str(cfg_dir / "capabilities.json"), caps)
    cm = ConfigManager(fs=ConfigFsPaths(str(tmp_path)), logger=_L())
    with pytest.raises(ConfigError, match="capabilities.json"):
        cm.load_all()


def test_successful_boot_writes_lkg_snapshot(tmp_path, monkeypatch):
    import jarvis.core.startup.checks as checks

    monkeypatch.setattr(checks.platform, "system", lambda: "Windows")

    cm = ConfigManager(fs=ConfigFsPaths(str(tmp_path)), logger=_L())
    cfg_obj = cm.load_all()

    modules_root = tmp_path / "jarvis" / "modules"
    os.makedirs(modules_root, exist_ok=True)

    class FakeSecureStatus:
        def __init__(self, mode: str):
            self.mode = SimpleNamespace(value=mode)
            self.next_steps = ""

    class FakeSecureStore:
        def status(self):
            return FakeSecureStatus("READY")

        def is_unlocked(self):
            return True

    class FakeRuntimeState:
        def load(self):
            return None

        def get_snapshot(self):
            return {"crash": {"dirty_shutdown_detected": False}, "security": {"admin_locked": True}}

    caps = validate_and_normalize(default_config_dict())
    cap_engine = CapabilityEngine(cfg=caps, audit=CapabilityAuditLogger(path=str(tmp_path / "security.jsonl")), logger=None)
    policy_engine = PolicyEngine(cfg=PolicyConfigFile())
    privacy_store = object()
    dispatcher = FakeDispatcher(capability_engine=cap_engine, policy_engine=policy_engine, privacy_store=privacy_store)

    ops = OpsLogger(path=str(tmp_path / "ops.jsonl"))
    runner = StartupSelfCheckRunner(ops=ops)
    res = runner.run(
        flags=StartupFlags(),
        root_dir=str(tmp_path),
        logs_dir=str(tmp_path / "logs"),
        config_manager=cm,
        secure_store=FakeSecureStore(),
        runtime_state=FakeRuntimeState(),
        cfg_obj=cfg_obj,
        capabilities_cfg_raw=default_config_dict(),
        core_ready={"capability_ok": True, "event_bus_ok": True, "telemetry_ok": True, "job_manager_ok": True, "error_policy_ok": True, "runtime_ok": True},
        dispatcher=dispatcher,
        capability_engine=cap_engine,
        policy_engine=policy_engine,
        privacy_store=privacy_store,
        modules_root=str(modules_root),
    )
    assert res.overall_status.value in {"OK", "DEGRADED"}

    lkg_dir = tmp_path / ".lkg"
    assert lkg_dir.is_dir()
    for name in ("capabilities.json", "policy.json", "execution.json", "privacy.json", "module_trust.json"):
        assert (lkg_dir / name).is_file()


def test_restore_lkg_requires_admin_and_is_audited(tmp_path):
    cm = ConfigManager(fs=ConfigFsPaths(str(tmp_path)), logger=_L())
    _ = cm.load_all()

    ops = OpsLogger(path=str(tmp_path / "ops.jsonl"))
    cm.snapshot_security_lkg(root_dir=str(tmp_path), ops=ops)

    policy_path = tmp_path / "config" / "policy.json"
    rr = read_json_file(str(policy_path))
    assert rr.ok
    modified = dict(rr.data)
    modified["enabled"] = False
    atomic_write_json(str(policy_path), modified, cm.fs.backups_dir, max_backups=3)

    class FakeSecurityManager:
        def __init__(self, admin: bool):
            self._admin = admin

        def is_admin(self) -> bool:
            return self._admin

    with pytest.raises(PermissionError):
        cm.restore_security_lkg(root_dir=str(tmp_path), security_manager=FakeSecurityManager(False), ops=ops)

    restored = cm.restore_security_lkg(root_dir=str(tmp_path), security_manager=FakeSecurityManager(True), ops=ops)
    assert "policy.json" in restored

    lkg_policy = read_json_file(str(tmp_path / ".lkg" / "policy.json")).data
    restored_policy = read_json_file(str(policy_path)).data
    assert restored_policy == lkg_policy

    with open(ops.path, "r", encoding="utf-8") as f:
        lines = [line.strip() for line in f.readlines() if line.strip()]
    assert any('"event": "config.lkg.restore"' in line for line in lines)
