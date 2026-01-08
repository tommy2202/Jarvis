from __future__ import annotations

from fastapi.testclient import TestClient

from jarvis.core.crypto import generate_usb_master_key_bytes, write_usb_key
from jarvis.core.events import EventLogger
from jarvis.core.secure_store import SecureStore
from jarvis.web.api import create_app
from jarvis.web.security.auth import ApiKeyStore


class DummySecurity:
    def verify_and_unlock_admin(self, _passphrase: str) -> bool:
        return False


class DummyJarvis:
    def process_message(self, message: str, client=None):
        return type(
            "R",
            (),
            {"trace_id": "t", "reply": "ok", "intent_id": "music.play", "intent_source": "stage_a", "confidence": 1.0, "requires_followup": False, "followup_question": None},
        )()


class DummyRuntime:
    def submit_text(self, *_a, **_k):
        return "tid"

    def wait_for_result(self, *_a, **_k):
        return {"reply": "ok", "intent": {"id": "music.play", "source": "stage_a", "confidence": 1.0}}

    def get_status(self):
        return {"state": "SLEEPING"}


def test_permission_denied_returns_403(tmp_path):
    usb = tmp_path / "usb.bin"
    write_usb_key(str(usb), generate_usb_master_key_bytes())
    store = SecureStore(usb_key_path=str(usb), store_path=str(tmp_path / "store.enc"), meta_path=str(tmp_path / "meta.json"), backups_dir=str(tmp_path / "b"))
    key = ApiKeyStore(store).create_key(scopes=["read", "message", "admin"])["key"]
    web_cfg = {"max_request_bytes": 32768, "rate_limits": {"per_ip_per_minute": 100, "per_key_per_minute": 100, "admin_per_minute": 100}, "lockout": {"strike_threshold": 10, "lockout_minutes": 15, "permanent_after": 3}, "admin": {"allow_remote_unlock": False, "allowed_admin_ips": ["127.0.0.1"]}}
    app = create_app(
        jarvis_app=DummyJarvis(),
        security_manager=DummySecurity(),
        event_logger=EventLogger(str(tmp_path / "events.jsonl")),
        logger=type("L", (), {"error": lambda *_a, **_k: None})(),
        auth_dep=None,
        job_manager=None,
        runtime=DummyRuntime(),
        secure_store=store,
        web_cfg=web_cfg,
        allowed_origins=[],
        enable_web_ui=False,
        remote_control_enabled=True,
    )
    c = TestClient(app)
    r = c.post("/v1/admin/unlock", headers={"X-API-Key": key, "Content-Type": "application/json"}, json={"passphrase": "x"})
    assert r.status_code == 403

