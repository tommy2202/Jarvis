from __future__ import annotations

from jarvis.core.capabilities.audit import CapabilityAuditLogger
from jarvis.core.capabilities.engine import CapabilityEngine
from jarvis.core.capabilities.loader import default_config_dict, validate_and_normalize
from jarvis.core.crypto import generate_usb_master_key_bytes, write_usb_key
from jarvis.core.dispatcher import Dispatcher
from jarvis.core.events import EventLogger
from jarvis.core.job_manager import JobManager, job_system_health_check
from jarvis.core.runtime import _find_denial, _tail_denials
from jarvis.core.security import AdminSession, PermissionPolicy, SecurityManager
from jarvis.core.secure_store import SecureStore
from jarvis.core.module_registry import ModuleRegistry


class _L:
    def info(self, *_a, **_k): ...
    def warning(self, *_a, **_k): ...
    def error(self, *_a, **_k): ...


def _make_dispatcher(tmp_path):
    usb = tmp_path / "usb.bin"
    write_usb_key(str(usb), generate_usb_master_key_bytes())
    store = SecureStore(usb_key_path=str(usb), store_path=str(tmp_path / "store.enc"))
    sec = SecurityManager(secure_store=store, admin_session=AdminSession(timeout_seconds=9999))

    raw = default_config_dict()
    cap_cfg = validate_and_normalize(raw)
    cap_engine = CapabilityEngine(cfg=cap_cfg, audit=CapabilityAuditLogger(path=str(tmp_path / "security.jsonl")), logger=None)

    ev_logger = EventLogger(str(tmp_path / "events.jsonl"))
    jobs = JobManager(
        jobs_dir=str(tmp_path / "jobs"),
        max_concurrent_jobs=1,
        default_timeout_seconds=2,
        retention_max_jobs=10,
        retention_days=1,
        poll_interval_ms=50,
        event_logger=ev_logger,
        logger=_L(),
        event_bus=None,
    )
    dispatcher = Dispatcher(
        registry=ModuleRegistry(),
        policy=PermissionPolicy(intents={}),
        security=sec,
        event_logger=ev_logger,
        logger=_L(),
        capability_engine=cap_engine,
        secure_store=store,
        job_manager=jobs,
    )
    return dispatcher, jobs, ev_logger


def test_denial_breakdown_and_why_lookup(tmp_path):
    dispatcher, jobs, ev_logger = _make_dispatcher(tmp_path)
    try:
        jobs.register_job("system.admin_only", job_system_health_check, required_capabilities=["CAP_ADMIN_ACTION"])
        trace_id = "trace-denied"
        res = dispatcher.submit_job(trace_id, "system.admin_only", {}, {"source": "cli", "client": {"name": "cli", "id": "stdin"}})
        assert res.ok is False
        assert res.decision_breakdown is not None
        assert res.decision_breakdown.get("denied_by")
        assert res.decision_breakdown.get("remediation")
        assert res.decision_breakdown.get("trace_id") == trace_id

        rows = _tail_denials(ev_logger.path, n=10)
        assert rows
        row = [r for r in rows if r.get("trace_id") == trace_id][-1]
        assert row.get("denied_by")
        assert row.get("reason_code")
        assert row.get("remediation")
        assert row.get("trace_id") == trace_id

        found = _find_denial(ev_logger.path, trace_id=trace_id)
        assert found is not None
        assert found.get("denied_by") == row.get("denied_by")
        assert found.get("reason_code") == row.get("reason_code")
        assert found.get("trace_id") == trace_id
    finally:
        jobs.stop()
