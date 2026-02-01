from __future__ import annotations

import time
from types import SimpleNamespace

from jarvis.core.audit.timeline import AuditTimelineManager
from jarvis.core.capabilities.audit import CapabilityAuditLogger
from jarvis.core.capabilities.engine import CapabilityEngine
from jarvis.core.capabilities.loader import default_config_dict, validate_and_normalize
from jarvis.core.events.bus import EventBus, EventBusConfig, OverflowPolicy
from jarvis.core.ops_log import OpsLogger
from jarvis.core.startup.runner import StartupFlags, StartupSelfCheckRunner
from .helpers.fakes import FakeDispatcher


def _mk_audit_mgr(tmp_path, event_bus):
    cfg = {
        "enabled": True,
        "store": {"path_jsonl": str(tmp_path / "audit.jsonl"), "use_sqlite_index": True, "sqlite_path": str(tmp_path / "index.sqlite")},
        "integrity": {"enabled": True, "verify_on_startup": False, "verify_last_n": 2000},
        "retention": {"days": 7, "max_events": 50000},
        "export": {"max_rows": 20000},
        # Ensure deterministic tests (don't ingest workspace logs).
        "ingest_sources": {"security": str(tmp_path / "security.jsonl"), "ops": str(tmp_path / "ops.jsonl"), "errors": str(tmp_path / "errors.jsonl")},
    }
    m = AuditTimelineManager(cfg=cfg, logger=None, event_bus=event_bus, telemetry=None, ops_logger=None)
    m.start()
    return m


def _wait_for_audit_event(audit, *, action: str, trace_id: str, timeout: float = 3.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        rows = audit.list_events(limit=200)
        for r in rows:
            if r.action == action and r.trace_id == trace_id:
                return r
        time.sleep(0.05)
    return None


def test_startup_fails_when_capability_engine_missing_audited(tmp_path, monkeypatch):
    import jarvis.core.startup.checks as checks

    monkeypatch.setattr(checks.platform, "system", lambda: "Windows")

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

    eb = EventBus(cfg=EventBusConfig(enabled=True, max_queue_size=200, worker_threads=2, overflow_policy=OverflowPolicy.DROP_OLDEST), logger=None)
    audit = _mk_audit_mgr(tmp_path, eb)
    try:
        ops = OpsLogger(path=str(tmp_path / "ops.jsonl"))
        runner = StartupSelfCheckRunner(ops=ops, event_bus=eb)
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
            capabilities_cfg_raw=default_config_dict(),
            core_ready={"capability_ok": True, "event_bus_ok": True, "telemetry_ok": True, "job_manager_ok": True, "error_policy_ok": True, "runtime_ok": True},
            dispatcher=dispatcher,
            capability_engine=None,
            policy_engine=None,
            privacy_store=privacy_store,
            modules_root=str(tmp_path / "jarvis" / "modules"),
        )
        assert res.overall_status.value == "BLOCKED"

        ev = _wait_for_audit_event(audit, action="startup.failed", trace_id="startup")
        assert ev is not None
        reason_codes = (ev.details or {}).get("reason_codes") or []
        assert "dispatcher.capability_engine" in reason_codes or "capability_engine.ready" in reason_codes
    finally:
        eb.shutdown(0.5)


def test_startup_fails_on_remote_web_when_secure_store_locked(tmp_path, monkeypatch):
    import jarvis.core.startup.checks as checks

    monkeypatch.setattr(checks.platform, "system", lambda: "Windows")

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
                web=SimpleNamespace(enabled=True, allow_remote=True, bind_host="0.0.0.0"),
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
        capabilities_cfg_raw=default_config_dict(),
        core_ready={"capability_ok": True, "event_bus_ok": True, "telemetry_ok": True, "job_manager_ok": True, "error_policy_ok": True, "runtime_ok": True},
        dispatcher=dispatcher,
        capability_engine=cap_engine,
        policy_engine=None,
        privacy_store=privacy_store,
        modules_root=str(tmp_path / "jarvis" / "modules"),
    )
    assert res.overall_status.value == "BLOCKED"
