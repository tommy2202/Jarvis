from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from jarvis.core.capabilities.audit import CapabilityAuditLogger
from jarvis.core.capabilities.engine import CapabilityEngine
from jarvis.core.capabilities.loader import default_config_dict, validate_and_normalize
from jarvis.core.crypto import generate_usb_master_key_bytes, write_usb_key
from jarvis.core.dispatcher import Dispatcher
from jarvis.core.events import EventLogger
from jarvis.core.job_manager import JobManager, job_system_health_check
from jarvis.core.module_registry import ModuleRegistry
from jarvis.core.policy.engine import PolicyEngine
from jarvis.core.policy.models import PolicyConfigFile, PolicyEffect, PolicyMatch, PolicyRule
from jarvis.core.security import AdminSession, PermissionPolicy, SecurityManager
from jarvis.core.secure_store import SecureStore
from jarvis.web.api import create_app
from jarvis.web.security.auth import ApiKeyStore


class DummyLogger:
    def info(self, *_a, **_k): ...
    def warning(self, *_a, **_k): ...
    def error(self, *_a, **_k): ...


class DummySecurity:
    def verify_and_unlock_admin(self, _passphrase: str) -> bool:
        return False


class DummyJobs:
    def list_jobs(self):
        return []

    def get_job(self, _job_id: str):
        raise KeyError("missing")


def _security(tmp_path):
    usb = tmp_path / "usb.bin"
    write_usb_key(str(usb), generate_usb_master_key_bytes())
    store = SecureStore(usb_key_path=str(usb), store_path=str(tmp_path / "store.enc"), meta_path=str(tmp_path / "meta.json"), backups_dir=str(tmp_path / "b"))
    sec = SecurityManager(secure_store=store, admin_session=AdminSession(timeout_seconds=9999))
    return sec, store


def _make_dispatcher_with_policy(tmp_path, policy_engine):
    sec, store = _security(tmp_path)
    ev_logger = EventLogger(str(tmp_path / "events.jsonl"))
    policy = PermissionPolicy(intents={})

    raw = default_config_dict()
    raw["intent_requirements"]["system.job.submit"] = []
    raw["safe_mode"] = {"deny": []}
    raw["source_policies"] = {"cli": {"deny": [], "require_admin_for": [], "allow_all_non_sensitive": True}}
    cap_cfg = validate_and_normalize(raw)
    cap_engine = CapabilityEngine(cfg=cap_cfg, audit=CapabilityAuditLogger(path=str(tmp_path / "security.jsonl")), logger=None)

    jobs = JobManager(
        jobs_dir=str(tmp_path / "jobs"),
        max_concurrent_jobs=1,
        default_timeout_seconds=2,
        retention_max_jobs=10,
        retention_days=1,
        poll_interval_ms=50,
        event_logger=ev_logger,
        logger=DummyLogger(),
    )
    dispatcher = Dispatcher(
        registry=ModuleRegistry(),
        policy=policy,
        security=sec,
        event_logger=ev_logger,
        logger=DummyLogger(),
        capability_engine=cap_engine,
        secure_store=store,
        policy_engine=policy_engine,
        job_manager=jobs,
    )
    return dispatcher, jobs


def test_web_jobs_route_uses_dispatcher(tmp_path):
    usb = tmp_path / "usb.bin"
    write_usb_key(str(usb), generate_usb_master_key_bytes())
    store = SecureStore(usb_key_path=str(usb), store_path=str(tmp_path / "store.enc"), meta_path=str(tmp_path / "meta.json"), backups_dir=str(tmp_path / "b"))
    key = ApiKeyStore(store).create_key(scopes=["read", "message", "admin"])["key"]

    called = {}

    def submit_job(trace_id, kind, args, ctx, *, priority=50, max_runtime_seconds=None):  # noqa: ANN001
        called["trace_id"] = trace_id
        called["kind"] = kind
        called["args"] = dict(args)
        called["source"] = str((ctx or {}).get("source"))
        called["priority"] = priority
        called["max_runtime_seconds"] = max_runtime_seconds
        return SimpleNamespace(ok=True, job_id="job123")

    dispatcher = SimpleNamespace(submit_job=submit_job)
    jarvis = SimpleNamespace(dispatcher=dispatcher)

    web_cfg = {
        "max_request_bytes": 32768,
        "rate_limits": {"per_ip_per_minute": 100, "per_key_per_minute": 100, "admin_per_minute": 100},
        "lockout": {"strike_threshold": 10, "lockout_minutes": 15, "permanent_after": 3},
        "admin": {"allow_remote_unlock": False, "allowed_admin_ips": ["127.0.0.1"]},
    }
    app = create_app(
        jarvis_app=jarvis,
        security_manager=DummySecurity(),
        event_logger=EventLogger(str(tmp_path / "events.jsonl")),
        logger=DummyLogger(),
        auth_dep=None,
        job_manager=DummyJobs(),
        runtime=SimpleNamespace(safe_mode=False),
        secure_store=store,
        web_cfg=web_cfg,
        allowed_origins=[],
        enable_web_ui=False,
        remote_control_enabled=True,
    )
    c = TestClient(app)
    r = c.post(
        "/v1/jobs",
        headers={"X-API-Key": key, "Content-Type": "application/json"},
        json={"kind": "system.health_check", "args": {"x": 1}, "priority": 5, "max_runtime_seconds": 10},
    )
    assert r.status_code == 200
    assert called["kind"] == "system.health_check"
    assert called["source"] == "web"


def test_policy_denied_job_does_not_call_job_manager(tmp_path, monkeypatch):
    rule = PolicyRule(id="deny.jobs", effect=PolicyEffect.DENY, match=PolicyMatch(intent_id_in=["system.job.submit"]), reason="deny jobs")
    policy_engine = PolicyEngine(cfg=PolicyConfigFile(enabled=True, rules=[rule]))
    dispatcher, jobs = _make_dispatcher_with_policy(tmp_path, policy_engine)
    try:
        jobs.register_job("system.policy_demo", job_system_health_check, required_capabilities=[])
        called = {"n": 0}

        def boom(*_a, **_k):
            called["n"] += 1
            raise AssertionError("submit_job should not be called on denial")

        monkeypatch.setattr(jobs, "submit_job", boom)
        res = dispatcher.submit_job("trace", "system.policy_demo", {}, {"source": "cli", "client": {"name": "cli", "id": "test"}})
        assert res.ok is False
        assert called["n"] == 0
    finally:
        jobs.stop()


def test_internal_primitives_require_explicit_flags(tmp_path):
    sec, store = _security(tmp_path)
    reg = ModuleRegistry()

    def handler(intent_id, args, context):  # noqa: ANN001
        return {"ok": True}

    loaded = reg.register_handler(
        module_id="demo",
        module_path="test.demo",
        meta={"resource_class": "default", "execution_mode": "inline", "required_capabilities": []},
        handler=handler,
    )

    dispatcher = Dispatcher(
        registry=reg,
        policy=PermissionPolicy(intents={}),
        security=sec,
        event_logger=EventLogger(str(tmp_path / "events.jsonl")),
        logger=DummyLogger(),
        capability_engine=None,
        secure_store=store,
    )

    with pytest.raises(RuntimeError, match="internal"):
        dispatcher.execute_loaded_module(loaded, intent_id="demo.run", args={}, context={}, persist_allowed=True)

    with pytest.raises(RuntimeError, match="internal"):
        loaded._call_unsafe(intent_id="demo.run", args={}, context={})

    with pytest.raises(RuntimeError, match="internal"):
        Dispatcher._run_in_subprocess("test.demo", "demo.run", {}, {"_dispatcher_execute": True})
