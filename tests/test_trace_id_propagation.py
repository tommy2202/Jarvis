from __future__ import annotations

import time

from jarvis.core.capabilities.audit import CapabilityAuditLogger
from jarvis.core.capabilities.engine import CapabilityEngine
from jarvis.core.capabilities.loader import default_config_dict, validate_and_normalize
from jarvis.core.crypto import generate_usb_master_key_bytes, write_usb_key
from jarvis.core.dispatcher import Dispatcher
from jarvis.core.events import EventLogger
from jarvis.core.events.bus import EventBus, EventBusConfig
from jarvis.core.intent_router import StageAIntent, StageAIntentRouter
from jarvis.core.jarvis_app import JarvisApp
from jarvis.core.job_manager import JobManager, job_system_health_check
from jarvis.core.llm_router import LLMConfig, StageBLLMRouter
from jarvis.core.module_registry import ModuleRegistry
from jarvis.core.policy.engine import PolicyEngine
from jarvis.core.policy.models import PolicyConfigFile
from jarvis.core.security import AdminSession, PermissionPolicy, SecurityManager
from jarvis.core.secure_store import SecureStore
from jarvis.core.audit.ingestors import audit_from_core_event


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


def test_trace_id_propagation(tmp_path):
    bus = EventBus(cfg=EventBusConfig(enabled=True, max_queue_size=200, worker_threads=1), logger=None)
    events = []
    bus.subscribe("*", lambda ev: events.append(ev), priority=10)

    sec, store = _security(tmp_path)
    ev_logger = EventLogger(str(tmp_path / "events.jsonl"))
    policy = PermissionPolicy(intents={"demo.run": {"requires_admin": False, "resource_intensive": False}})

    raw = default_config_dict()
    raw["intent_requirements"]["demo.run"] = []
    cap_cfg = validate_and_normalize(raw)
    cap_engine = CapabilityEngine(cfg=cap_cfg, audit=CapabilityAuditLogger(path=str(tmp_path / "security.jsonl")), logger=None, event_bus=bus)

    policy_engine = PolicyEngine(cfg=PolicyConfigFile(), event_bus=bus)

    jobs = JobManager(
        jobs_dir=str(tmp_path / "jobs"),
        max_concurrent_jobs=1,
        default_timeout_seconds=2,
        retention_max_jobs=10,
        retention_days=1,
        poll_interval_ms=50,
        event_logger=ev_logger,
        logger=DummyLogger(),
        event_bus=bus,
    )
    jobs.register_job("system.health_check", job_system_health_check)

    def handler(intent_id, args, context):  # noqa: ANN001
        _ = intent_id, args, context
        jobs.submit_job("system.health_check", {}, {"source": "test"})
        return {"summary": "job queued"}

    reg = ModuleRegistry()
    reg.register_handler(
        module_id="demo",
        module_path="test.demo",
        meta={"resource_class": "default", "execution_mode": "inline", "required_capabilities": []},
        handler=handler,
    )

    dispatcher = Dispatcher(
        registry=reg,
        policy=policy,
        security=sec,
        event_logger=ev_logger,
        logger=DummyLogger(),
        capability_engine=cap_engine,
        secure_store=store,
        event_bus=bus,
        policy_engine=policy_engine,
    )

    stage_a = StageAIntentRouter([StageAIntent(id="demo.run", module_id="demo", keywords=["run"], required_args=[])], threshold=0.1)
    stage_b = StageBLLMRouter(LLMConfig(mock_mode=True))
    jarvis = JarvisApp(
        stage_a=stage_a,
        stage_b=stage_b,
        dispatcher=dispatcher,
        intent_config_by_id={"demo.run": {"id": "demo.run", "module_id": "demo", "required_args": []}},
        confirmation_templates={"demo.run": "Running demo."},
        event_logger=ev_logger,
        logger=DummyLogger(),
        threshold=0.1,
    )

    trace_id = "trace-123"
    try:
        resp = jarvis.process_message("run demo", client={"name": "test"}, source="cli", trace_id=trace_id)
        time.sleep(0.2)

        assert resp.trace_id == trace_id
        assert resp.ux_events
        assert all(ev.get("trace_id") == trace_id for ev in resp.ux_events or [])

        cap_event = next(ev for ev in events if ev.event_type == "capability.decision")
        policy_event = next(ev for ev in events if ev.event_type == "policy.decision")
        ux_event = next(ev for ev in events if ev.event_type == "ux.acknowledge")
        job_event = next(ev for ev in events if ev.event_type == "job.created")

        assert cap_event.trace_id == trace_id
        assert policy_event.trace_id == trace_id
        assert ux_event.trace_id == trace_id
        assert job_event.trace_id == trace_id

        audit = audit_from_core_event(cap_event)
        assert audit is not None
        assert audit.trace_id == trace_id

        job_list = jobs.list_jobs()
        assert job_list
        assert all(j.trace_id == trace_id for j in job_list)
    finally:
        jobs.stop()
        bus.shutdown(0.5)
