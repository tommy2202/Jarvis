from __future__ import annotations

from types import SimpleNamespace

from fastapi.testclient import TestClient

from jarvis.core.crypto import generate_usb_master_key_bytes, write_usb_key
from jarvis.core.events import EventLogger
from jarvis.core.secure_store import SecureStore
from jarvis.ui.ui_events import UiController
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

    def submit_job(self, *_a, **_k):  # noqa: ANN001
        raise AssertionError("job_manager.submit_job should not be called by entrypoints")


def _secure_store(tmp_path) -> SecureStore:
    usb = tmp_path / "usb.bin"
    write_usb_key(str(usb), generate_usb_master_key_bytes())
    return SecureStore(usb_key_path=str(usb), store_path=str(tmp_path / "store.enc"), meta_path=str(tmp_path / "meta.json"), backups_dir=str(tmp_path / "b"))


def _web_cfg() -> dict:
    return {
        "max_request_bytes": 32768,
        "rate_limits": {"per_ip_per_minute": 100, "per_key_per_minute": 100, "admin_per_minute": 100},
        "lockout": {"strike_threshold": 10, "lockout_minutes": 15, "permanent_after": 3},
        "admin": {"allow_remote_unlock": False, "allowed_admin_ips": ["127.0.0.1"]},
    }


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
        job_manager=DummyJobs(),
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


def test_ui_send_text_uses_core_client_submit():
    called = {}

    class DummyCore:
        def submit_text(self, source, text, client_meta=None, trace_id=None):  # noqa: ANN001
            called["source"] = source
            called["text"] = text
            called["client_meta"] = dict(client_meta or {})
            return "trace123"

        def get_result(self, _trace_id):  # noqa: ANN001
            return None

    controller = UiController(core=DummyCore())
    trace_id = controller.send_text(text="hi", client_meta={"client": "desktop"})
    assert trace_id == "trace123"
    assert called.get("source") == "ui"
    assert called.get("text") == "hi"


def test_web_message_routes_through_dispatcher(tmp_path):
    store = _secure_store(tmp_path)
    key = ApiKeyStore(store).create_key(scopes=["message"])["key"]
    called = {}

    class RecordingDispatcher:
        def dispatch(self, trace_id, intent_id, module_id, args, context):  # noqa: ANN001
            called["trace_id"] = trace_id
            called["intent_id"] = intent_id
            called["module_id"] = module_id
            called["source"] = (context or {}).get("source")
            return SimpleNamespace(ok=True, reply="ok", denied_reason=None, remediation=None, modifications={}, ux_events=None, module_output={})

    class DummyJarvis:
        def __init__(self, dispatcher):
            self.dispatcher = dispatcher

        def process_message(self, message, client=None, source="cli", safe_mode=False, shutting_down=False, trace_id=None):  # noqa: ANN001
            self.dispatcher.dispatch(trace_id or "web-trace", "demo.intent", "demo", {"message": message}, {"source": source, "client": client or {}})
            return SimpleNamespace(
                trace_id=trace_id or "web-trace",
                reply="ok",
                intent_id="demo.intent",
                intent_source="stage_a",
                confidence=1.0,
                requires_followup=False,
                followup_question=None,
            )

    dispatcher = RecordingDispatcher()
    jarvis = DummyJarvis(dispatcher)
    app = create_app(
        jarvis_app=jarvis,
        security_manager=DummySecurity(),
        event_logger=EventLogger(str(tmp_path / "events.jsonl")),
        logger=DummyLogger(),
        auth_dep=None,
        job_manager=DummyJobs(),
        runtime=None,
        secure_store=store,
        web_cfg=_web_cfg(),
        allowed_origins=[],
        enable_web_ui=False,
        remote_control_enabled=True,
    )
    c = TestClient(app)
    r = c.post(
        "/v1/message",
        headers={"X-API-Key": key, "Content-Type": "application/json"},
        json={"message": "hello", "client": {"name": "web"}},
    )
    assert r.status_code == 200
    assert called.get("intent_id") == "demo.intent"
    assert called.get("source") == "web"


def test_web_jobs_submit_routes_through_dispatcher(tmp_path):
    store = _secure_store(tmp_path)
    key = ApiKeyStore(store).create_key(scopes=["message"])["key"]
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
    app = create_app(
        jarvis_app=jarvis,
        security_manager=DummySecurity(),
        event_logger=EventLogger(str(tmp_path / "events.jsonl")),
        logger=DummyLogger(),
        auth_dep=None,
        job_manager=DummyJobs(),
        runtime=SimpleNamespace(safe_mode=False),
        secure_store=store,
        web_cfg=_web_cfg(),
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
