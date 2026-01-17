from __future__ import annotations

import time

from jarvis.core.audit.timeline import AuditTimelineManager
from jarvis.core.capabilities.audit import CapabilityAuditLogger
from jarvis.core.capabilities.engine import CapabilityEngine
from jarvis.core.capabilities.loader import default_config_dict, validate_and_normalize
from jarvis.core.crypto import generate_usb_master_key_bytes, write_usb_key
from jarvis.core.dispatcher import Dispatcher
from jarvis.core.events import EventLogger
from jarvis.core.events.bus import EventBus, EventBusConfig, OverflowPolicy
from jarvis.core.job_manager import JobManager, job_system_health_check
from jarvis.core.module_registry import ModuleRegistry
from jarvis.core.policy.engine import PolicyEngine
from jarvis.core.policy.models import PolicyConfigFile
from jarvis.core.security import AdminSession, PermissionPolicy, SecurityManager
from jarvis.core.secure_store import SecureStore


class DummyLogger:
    def info(self, *_a, **_k): ...
    def warning(self, *_a, **_k): ...
    def error(self, *_a, **_k): ...


def _security(tmp_path):
    usb = tmp_path / "usb.bin"
    write_usb_key(str(usb), generate_usb_master_key_bytes())
    store = SecureStore(usb_key_path=str(usb), store_path=str(tmp_path / "store.enc"))
    sec = SecurityManager(secure_store=store, admin_session=AdminSession(timeout_seconds=9999))
    return sec, store


def _mk_audit_mgr(tmp_path, event_bus):
    cfg = {
        "enabled": True,
        "store": {"path_jsonl": str(tmp_path / "audit.jsonl"), "use_sqlite_index": True, "sqlite_path": str(tmp_path / "index.sqlite")},
        "integrity": {"enabled": True, "verify_on_startup": False, "verify_last_n": 2000},
        "retention": {"days": 90, "max_events": 50000},
        "export": {"max_rows": 20000},
        "ingest_sources": {"security": str(tmp_path / "security.jsonl"), "ops": str(tmp_path / "ops.jsonl"), "errors": str(tmp_path / "errors.jsonl")},
    }
    m = AuditTimelineManager(cfg=cfg, logger=None, event_bus=event_bus, telemetry=None, ops_logger=None)
    m.start()
    return m


def _dispatch_ctx(source: str, *, safe_mode: bool = False, shutting_down: bool = False):
    return {
        "source": source,
        "client": {"name": source, "id": "test"},
        "safe_mode": bool(safe_mode),
        "shutting_down": bool(shutting_down),
    }


def _make_dispatcher(tmp_path, *, event_bus=None, is_admin: bool = False):
    sec, store = _security(tmp_path)
    if is_admin:
        sec.admin_session.unlock()
    ev_logger = EventLogger(str(tmp_path / "events.jsonl"))
    policy = PermissionPolicy(intents={})

    raw = default_config_dict()
    cap_cfg = validate_and_normalize(raw)
    cap_engine = CapabilityEngine(cfg=cap_cfg, audit=CapabilityAuditLogger(path=str(tmp_path / "security.jsonl")), logger=None, event_bus=event_bus)
    policy_engine = PolicyEngine(cfg=PolicyConfigFile(), event_bus=event_bus)

    jobs = JobManager(
        jobs_dir=str(tmp_path / "jobs"),
        max_concurrent_jobs=1,
        default_timeout_seconds=2,
        retention_max_jobs=10,
        retention_days=1,
        poll_interval_ms=50,
        event_logger=ev_logger,
        logger=DummyLogger(),
        event_bus=event_bus,
    )
    reg = ModuleRegistry()
    dispatcher = Dispatcher(
        registry=reg,
        policy=policy,
        security=sec,
        event_logger=ev_logger,
        logger=DummyLogger(),
        capability_engine=cap_engine,
        secure_store=store,
        event_bus=event_bus,
        policy_engine=policy_engine,
        job_manager=jobs,
    )
    return dispatcher, jobs, sec


def test_heavy_job_from_web_denied_without_admin(tmp_path, monkeypatch):
    dispatcher, jobs, _sec = _make_dispatcher(tmp_path, is_admin=False)
    try:
        jobs.register_job("system.heavy_demo", job_system_health_check, required_capabilities=["CAP_RUN_SUBPROCESS"], heavy=True)
        called = {"n": 0}

        def boom(*_a, **_k):
            called["n"] += 1
            raise AssertionError("submit_job should not be called on denial")

        monkeypatch.setattr(jobs, "submit_job", boom)
        res = dispatcher.submit_job("trace1", "system.heavy_demo", {}, _dispatch_ctx("web"))
        assert res.ok is False
        assert called["n"] == 0
    finally:
        jobs.stop()


def test_shutting_down_denies_job_submission(tmp_path):
    dispatcher, jobs, _sec = _make_dispatcher(tmp_path, is_admin=True)
    try:
        jobs.register_job("system.light_demo", job_system_health_check, required_capabilities=["CAP_RUN_SUBPROCESS"])
        res = dispatcher.submit_job("trace2", "system.light_demo", {}, _dispatch_ctx("cli", shutting_down=True))
        assert res.ok is False
    finally:
        jobs.stop()


def test_safe_mode_denies_subprocess_jobs(tmp_path, monkeypatch):
    dispatcher, jobs, _sec = _make_dispatcher(tmp_path, is_admin=True)
    try:
        jobs.register_job("system.safe_mode_demo", job_system_health_check, required_capabilities=["CAP_RUN_SUBPROCESS"])
        called = {"n": 0}

        def boom(*_a, **_k):
            called["n"] += 1
            raise AssertionError("submit_job should not be called on denial")

        monkeypatch.setattr(jobs, "submit_job", boom)
        res = dispatcher.submit_job("trace3", "system.safe_mode_demo", {}, _dispatch_ctx("cli", safe_mode=True))
        assert res.ok is False
        assert called["n"] == 0
    finally:
        jobs.stop()


def test_job_submit_denial_audited(tmp_path):
    eb = EventBus(cfg=EventBusConfig(enabled=True, max_queue_size=200, worker_threads=2, overflow_policy=OverflowPolicy.DROP_OLDEST), logger=None)
    audit = _mk_audit_mgr(tmp_path, eb)
    dispatcher, jobs, _sec = _make_dispatcher(tmp_path, event_bus=eb, is_admin=True)
    try:
        jobs.register_job("system.audit_demo", job_system_health_check, required_capabilities=["CAP_RUN_SUBPROCESS"])
        trace_id = "trace-denied"
        res = dispatcher.submit_job(trace_id, "system.audit_demo", {}, _dispatch_ctx("cli", safe_mode=True))
        assert res.ok is False

        deadline = time.time() + 3.0
        found = False
        while time.time() < deadline and not found:
            rows = audit.list_events(limit=200)
            found = any(r.action == "job.submit.denied" and r.trace_id == trace_id for r in rows)
            if not found:
                time.sleep(0.05)
        assert found is True
    finally:
        jobs.stop()
        eb.shutdown(0.5)
