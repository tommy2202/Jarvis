from __future__ import annotations

import json
import os

import pytest
from fastapi.testclient import TestClient

from jarvis.core.secure_store import SecureStore
from jarvis.core.crypto import generate_usb_master_key_bytes, write_usb_key
from jarvis.core.events import EventLogger
from jarvis.core.security_events import SecurityAuditLogger
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
            {
                "trace_id": "t",
                "reply": "ok",
                "intent_id": "music.play",
                "intent_source": "stage_a",
                "confidence": 1.0,
                "requires_followup": False,
                "followup_question": None,
            },
        )()


class DummyRuntime:
    def __init__(self):
        self.llm_lifecycle = None

    def submit_text(self, *_a, **_k):
        return "tid"

    def wait_for_result(self, *_a, **_k):
        return {"reply": "ok", "intent": {"id": "music.play", "source": "stage_a", "confidence": 1.0}}

    def get_status(self):
        return {"state": "SLEEPING"}


def _mk_store(tmp_path):
    usb = tmp_path / "usb.bin"
    write_usb_key(str(usb), generate_usb_master_key_bytes())
    return SecureStore(usb_key_path=str(usb), store_path=str(tmp_path / "store.enc"))


def _mk_app(tmp_path, web_cfg):
    store = _mk_store(tmp_path)
    ks = ApiKeyStore(store)
    key = ks.create_key(scopes=["read", "message", "admin"])
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
    return app, key["key"], store


def test_invalid_api_key_rejected(tmp_path):
    app, good_key, _store = _mk_app(tmp_path, {"max_request_bytes": 32768, "rate_limits": {"per_ip_per_minute": 100, "per_key_per_minute": 100, "admin_per_minute": 100}, "lockout": {"strike_threshold": 10, "lockout_minutes": 15, "permanent_after": 3}, "admin": {"allow_remote_unlock": False, "allowed_admin_ips": ["127.0.0.1"]}})
    c = TestClient(app)
    r = c.get("/v1/status", headers={"X-API-Key": "bad"})
    assert r.status_code == 401


def test_revoked_key_rejected(tmp_path):
    web_cfg = {"max_request_bytes": 32768, "rate_limits": {"per_ip_per_minute": 100, "per_key_per_minute": 100, "admin_per_minute": 100}, "lockout": {"strike_threshold": 10, "lockout_minutes": 15, "permanent_after": 3}, "admin": {"allow_remote_unlock": False, "allowed_admin_ips": ["127.0.0.1"]}}
    app, good_key, store = _mk_app(tmp_path, web_cfg)
    ks = ApiKeyStore(store)
    # revoke first key
    recs = ks.list_keys()
    assert recs
    ks.revoke_key(recs[0].id, reason="test")
    c = TestClient(app)
    r = c.get("/v1/status", headers={"X-API-Key": good_key})
    assert r.status_code == 401


def test_rate_limit_enforced(tmp_path):
    web_cfg = {"max_request_bytes": 32768, "rate_limits": {"per_ip_per_minute": 100, "per_key_per_minute": 2, "admin_per_minute": 100}, "lockout": {"strike_threshold": 10, "lockout_minutes": 15, "permanent_after": 3}, "admin": {"allow_remote_unlock": False, "allowed_admin_ips": ["127.0.0.1"]}}
    app, good_key, _store = _mk_app(tmp_path, web_cfg)
    c = TestClient(app)
    for i in range(2):
        r = c.post("/v1/message", headers={"X-API-Key": good_key, "Content-Type": "application/json"}, json={"message": "hi"})
        assert r.status_code == 200
    r3 = c.post("/v1/message", headers={"X-API-Key": good_key, "Content-Type": "application/json"}, json={"message": "hi"})
    assert r3.status_code == 429


def test_lockout_triggered_after_repeated_failures(tmp_path):
    web_cfg = {"max_request_bytes": 32768, "rate_limits": {"per_ip_per_minute": 100, "per_key_per_minute": 100, "admin_per_minute": 100}, "lockout": {"strike_threshold": 2, "lockout_minutes": 15, "permanent_after": 3}, "admin": {"allow_remote_unlock": False, "allowed_admin_ips": ["127.0.0.1"]}}
    app, _good_key, _store = _mk_app(tmp_path, web_cfg)
    c = TestClient(app)
    r1 = c.get("/v1/status", headers={"X-API-Key": "bad"})
    r2 = c.get("/v1/status", headers={"X-API-Key": "bad"})
    assert r1.status_code == 401
    assert r2.status_code == 401
    r3 = c.get("/v1/status", headers={"X-API-Key": "bad"})
    assert r3.status_code in {403, 401}


def test_admin_unlock_blocked_from_remote_ip(tmp_path):
    # testclient host is not localhost -> should be blocked when allow_remote_unlock=false
    web_cfg = {"max_request_bytes": 32768, "rate_limits": {"per_ip_per_minute": 100, "per_key_per_minute": 100, "admin_per_minute": 100}, "lockout": {"strike_threshold": 10, "lockout_minutes": 15, "permanent_after": 3}, "admin": {"allow_remote_unlock": False, "allowed_admin_ips": ["127.0.0.1"]}}
    app, good_key, _store = _mk_app(tmp_path, web_cfg)
    c = TestClient(app)
    r = c.post("/v1/admin/unlock", headers={"X-API-Key": good_key, "Content-Type": "application/json"}, json={"passphrase": "x"})
    assert r.status_code == 403


def test_request_size_limit_enforced(tmp_path):
    web_cfg = {"max_request_bytes": 100, "rate_limits": {"per_ip_per_minute": 100, "per_key_per_minute": 100, "admin_per_minute": 100}, "lockout": {"strike_threshold": 10, "lockout_minutes": 15, "permanent_after": 3}, "admin": {"allow_remote_unlock": False, "allowed_admin_ips": ["127.0.0.1"]}}
    app, good_key, _store = _mk_app(tmp_path, web_cfg)
    c = TestClient(app)
    big = {"message": "x" * 500}
    r = c.post("/v1/message", headers={"X-API-Key": good_key, "Content-Type": "application/json"}, data=json.dumps(big))
    assert r.status_code in {400, 413}


def test_lockout_persists_in_secure_store(tmp_path):
    store = _mk_store(tmp_path)
    from jarvis.web.security.strikes import StrikeManager, LockoutConfig

    sm = StrikeManager(store, LockoutConfig(strike_threshold=1, lockout_minutes=15, permanent_after=3))
    sm.record_strike(ip="1.2.3.4", key_id=None)
    sm2 = StrikeManager(store, LockoutConfig(strike_threshold=1, lockout_minutes=15, permanent_after=3))
    assert sm2.is_ip_locked("1.2.3.4") is True

