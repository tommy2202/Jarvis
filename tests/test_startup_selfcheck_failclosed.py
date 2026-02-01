from __future__ import annotations

from types import SimpleNamespace

from .helpers.fakes import FakeDispatcher


def test_startup_fails_when_capability_engine_missing(tmp_path, monkeypatch):
    import jarvis.core.startup.checks as checks

    monkeypatch.setattr(checks.platform, "system", lambda: "Windows")

    from jarvis.core.ops_log import OpsLogger
    from jarvis.core.startup.runner import StartupFlags, StartupSelfCheckRunner

    class FakeConfig:
        def __init__(self):
            self.fs = SimpleNamespace(config_dir=str(tmp_path / "config"))

        def validate(self):
            return None

        def get(self):
            return SimpleNamespace(
                app=SimpleNamespace(config_version=999),
                voice=SimpleNamespace(enabled=False),
                state_machine=SimpleNamespace(enable_voice=False),
                llm=SimpleNamespace(enabled=False),
                web=SimpleNamespace(enabled=False, allow_remote=False, bind_host="127.0.0.1"),
                telemetry=SimpleNamespace(model_dump=lambda: {}),
                models=SimpleNamespace(vosk_model_path=""),
                policy=SimpleNamespace(enabled=False),
            )

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

    ops = OpsLogger(path=str(tmp_path / "ops.jsonl"))
    runner = StartupSelfCheckRunner(ops=ops)
    cfg = FakeConfig().get()
    privacy_store = object()
    dispatcher = FakeDispatcher(capability_engine=None, privacy_store=privacy_store)
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
        capability_engine=None,
        policy_engine=None,
        privacy_store=privacy_store,
        modules_root=str(tmp_path / "jarvis" / "modules"),
    )
    assert res.overall_status.value == "BLOCKED"


def test_startup_fails_when_web_enabled_without_secure_store(tmp_path, monkeypatch):
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
            return SimpleNamespace(
                app=SimpleNamespace(config_version=999),
                voice=SimpleNamespace(enabled=False),
                state_machine=SimpleNamespace(enable_voice=False),
                llm=SimpleNamespace(enabled=False),
                web=SimpleNamespace(enabled=True, allow_remote=False, bind_host="0.0.0.0"),
                telemetry=SimpleNamespace(model_dump=lambda: {}),
                models=SimpleNamespace(vosk_model_path=""),
                policy=SimpleNamespace(enabled=False),
            )

    class FakeSecureStatus:
        def __init__(self, mode: str):
            self.mode = SimpleNamespace(value=mode)
            self.next_steps = "insert usb"

    class FakeSecureStore:
        def status(self):
            return FakeSecureStatus("KEY_MISSING")

        def is_unlocked(self):
            return False

    class FakeRuntimeState:
        def load(self):
            return None

        def get_snapshot(self):
            return {"crash": {"dirty_shutdown_detected": False}, "security": {"admin_locked": True}}

    caps = validate_and_normalize(default_config_dict())
    cap_engine = CapabilityEngine(cfg=caps, audit=CapabilityAuditLogger(path=str(tmp_path / "security.jsonl")), logger=None)
    privacy_store = object()
    dispatcher = FakeDispatcher(capability_engine=cap_engine, privacy_store=privacy_store)

    ops = OpsLogger(path=str(tmp_path / "ops.jsonl"))
    runner = StartupSelfCheckRunner(ops=ops)
    cfg = FakeConfig().get()
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
