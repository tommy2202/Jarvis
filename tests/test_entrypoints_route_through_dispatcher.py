from __future__ import annotations

from types import SimpleNamespace

from fastapi.testclient import TestClient

from jarvis.core.crypto import generate_usb_master_key_bytes, write_usb_key
from jarvis.core.events import EventLogger
from jarvis.core.secure_store import SecureStore
from jarvis.web.api import create_app
from jarvis.web.security.auth import ApiKeyStore
from app import handle_cli_jobs_command, handle_cli_modules_command


class DummyLogger:
    def info(self, *_a, **_k): ...
    def warning(self, *_a, **_k): ...
    def error(self, *_a, **_k): ...


class DummySecurity:
    def verify_and_unlock_admin(self, _passphrase: str) -> bool:
        return False


class DummyJobs:
    def list_jobs(self, status=None):  # noqa: ANN001
        return []

    def get_job(self, _job_id: str):
        raise KeyError("missing")


def _secure_store(tmp_path) -> SecureStore:
    usb = tmp_path / "usb.bin"
    write_usb_key(str(usb), generate_usb_master_key_bytes())
    return SecureStore(usb_key_path=str(usb), store_path=str(tmp_path / "store.enc"), meta_path=str(tmp_path / "meta.json"), backups_dir=str(tmp_path / "b"))


def test_web_jobs_route_calls_dispatcher(tmp_path):
    store = _secure_store(tmp_path)
    key = ApiKeyStore(store).create_key(scopes=["read", "message", "admin"])["key"]

    called = {}

    def submit_job(trace_id, kind, args, ctx, *, priority=50, max_runtime_seconds=None):  # noqa: ANN001
        called["trace_id"] = trace_id
        called["kind"] = kind
        called["args"] = dict(args or {})
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
    assert called.get("kind") == "system.health_check"
    assert called.get("source") == "web"


def test_cli_jobs_run_routes_to_dispatcher():
    called = {}

    def submit_job(trace_id, kind, args, ctx, *, priority=50, max_runtime_seconds=None):  # noqa: ANN001
        called["trace_id"] = trace_id
        called["kind"] = kind
        called["args"] = dict(args or {})
        called["source"] = str((ctx or {}).get("source"))
        return SimpleNamespace(ok=True, job_id="job456")

    dispatcher = SimpleNamespace(submit_job=submit_job, cancel_job=lambda *_a, **_k: True, resume_job=lambda *_a, **_k: True)
    handled = handle_cli_jobs_command(
        "/jobs run health_check",
        dispatcher=dispatcher,
        job_manager=None,
        safe_mode=False,
        shutting_down=False,
    )
    assert handled is True
    assert called.get("kind") == "system.health_check"
    assert called.get("source") == "cli"


def test_cli_modules_enable_routes_to_dispatcher():
    called = {}

    def modules_enable(_trace_id, module_id):  # noqa: ANN001
        called["module_id"] = module_id
        return True

    dispatcher = SimpleNamespace(modules_enable=modules_enable, modules_disable=lambda *_a, **_k: True, modules_scan=lambda *_a, **_k: {}, modules_repair=lambda *_a, **_k: {})
    module_manager = SimpleNamespace(export=lambda _p: True)
    handled = handle_cli_modules_command("/modules enable demo.module", dispatcher=dispatcher, module_manager=module_manager)
    assert handled is True
    assert called.get("module_id") == "demo.module"
