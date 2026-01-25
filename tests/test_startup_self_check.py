from __future__ import annotations

import os
from types import SimpleNamespace

import pytest
from tests.helpers.fakes import FakeDispatcher


def test_secure_store_key_missing_allows_degraded(tmp_path, monkeypatch):
    # Force Windows for self-check.
    import jarvis.core.startup.checks as checks

    monkeypatch.setattr(checks.platform, "system", lambda: "Windows")

    from jarvis.core.ops_log import OpsLogger
    from jarvis.core.startup.runner import StartupFlags, StartupSelfCheckRunner
    from jarvis.core.capabilities.engine import CapabilityEngine
    from jarvis.core.capabilities.loader import default_config_dict, validate_and_normalize
    from jarvis.core.capabilities.audit import CapabilityAuditLogger

    class FakeConfig:
        def __init__(self):
            self.fs = SimpleNamespace(config_dir=str(tmp_path / "config"))

        def validate(self):
            return None

        def get(self):
            return SimpleNamespace(app=SimpleNamespace(config_version=999), voice=SimpleNamespace(enabled=False), state_machine=SimpleNamespace(enable_voice=False), llm=SimpleNamespace(enabled=False), web=SimpleNamespace(enabled=False, allow_remote=False), telemetry=SimpleNamespace(model_dump=lambda: {}), models=SimpleNamespace(vosk_model_path=""))

        def read_non_sensitive(self, _name: str):
            return {"capabilities": {}}

    class FakeSecureStatus:
        def __init__(self, mode: str):
            self.mode = SimpleNamespace(value=mode)
            self.next_steps = "insert usb"

    class FakeSecureStore:
        def status(self):
            return FakeSecureStatus("KEY_MISSING")

    class FakeRuntimeState:
        def load(self):
            return None

        def get_snapshot(self):
            return {"crash": {"dirty_shutdown_detected": False}, "security": {"admin_locked": True}}

    ops = OpsLogger(path=str(tmp_path / "ops.jsonl"))
    runner = StartupSelfCheckRunner(ops=ops)
    cfg = FakeConfig().get()
    caps = validate_and_normalize(default_config_dict())
    cap_engine = CapabilityEngine(cfg=caps, audit=CapabilityAuditLogger(path=str(tmp_path / "security.jsonl")), logger=None)
    privacy_store = object()
    dispatcher = FakeDispatcher(capability_engine=cap_engine, privacy_store=privacy_store)

    res = runner.run(
        flags=StartupFlags(),
        root_dir=str(tmp_path),
        logs_dir=str(tmp_path / "logs"),
        config_manager=FakeConfig(),
        secure_store=FakeSecureStore(),
        runtime_state=FakeRuntimeState(),
        cfg_obj=cfg,
        capabilities_cfg_raw={"capabilities": {}},
        core_ready={"capability_ok": True, "event_bus_ok": True, "telemetry_ok": True, "job_manager_ok": True, "error_policy_ok": True, "runtime_ok": True},
        dispatcher=dispatcher,
        capability_engine=cap_engine,
        policy_engine=None,
        privacy_store=privacy_store,
        modules_root=str(tmp_path / "jarvis" / "modules"),
    )
    assert res.overall_status.value in {"DEGRADED", "OK"}
    assert any(p.phase_id == 2 and p.status.value == "DEGRADED" for p in res.phases)


def test_secure_store_key_mismatch_blocks(tmp_path, monkeypatch):
    import jarvis.core.startup.checks as checks

    monkeypatch.setattr(checks.platform, "system", lambda: "Windows")

    from jarvis.core.ops_log import OpsLogger
    from jarvis.core.startup.runner import StartupFlags, StartupSelfCheckRunner
    from jarvis.core.capabilities.engine import CapabilityEngine
    from jarvis.core.capabilities.loader import default_config_dict, validate_and_normalize
    from jarvis.core.capabilities.audit import CapabilityAuditLogger

    class FakeConfig:
        def __init__(self):
            self.fs = SimpleNamespace(config_dir=str(tmp_path / "config"))

        def validate(self):
            return None

        def get(self):
            return SimpleNamespace(app=SimpleNamespace(config_version=999), voice=SimpleNamespace(enabled=False), state_machine=SimpleNamespace(enable_voice=False), llm=SimpleNamespace(enabled=False), web=SimpleNamespace(enabled=False, allow_remote=False), telemetry=SimpleNamespace(model_dump=lambda: {}), models=SimpleNamespace(vosk_model_path=""))

    class FakeSecureStatus:
        def __init__(self, mode: str):
            self.mode = SimpleNamespace(value=mode)
            self.next_steps = "restore backups"

    class FakeSecureStore:
        def status(self):
            return FakeSecureStatus("KEY_MISMATCH")

    class FakeRuntimeState:
        def load(self):
            return None

        def get_snapshot(self):
            return {"crash": {"dirty_shutdown_detected": False}, "security": {"admin_locked": True}}

    ops = OpsLogger(path=str(tmp_path / "ops.jsonl"))
    runner = StartupSelfCheckRunner(ops=ops)
    cfg = FakeConfig().get()
    caps = validate_and_normalize(default_config_dict())
    cap_engine = CapabilityEngine(cfg=caps, audit=CapabilityAuditLogger(path=str(tmp_path / "security.jsonl")), logger=None)
    privacy_store = object()
    dispatcher = FakeDispatcher(capability_engine=cap_engine, privacy_store=privacy_store)
    res = runner.run(
        flags=StartupFlags(),
        root_dir=str(tmp_path),
        logs_dir=str(tmp_path / "logs"),
        config_manager=FakeConfig(),
        secure_store=FakeSecureStore(),
        runtime_state=FakeRuntimeState(),
        cfg_obj=cfg,
        capabilities_cfg_raw={"capabilities": {}},
        core_ready={"capability_ok": True, "event_bus_ok": True, "telemetry_ok": True, "job_manager_ok": True, "error_policy_ok": True, "runtime_ok": True},
        dispatcher=dispatcher,
        capability_engine=cap_engine,
        policy_engine=None,
        privacy_store=privacy_store,
        modules_root=str(tmp_path / "jarvis" / "modules"),
    )
    assert res.overall_status.value == "BLOCKED"

