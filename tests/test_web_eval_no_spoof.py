from __future__ import annotations

from fastapi.testclient import TestClient

from jarvis.core.capabilities.audit import CapabilityAuditLogger
from jarvis.core.capabilities.engine import CapabilityEngine
from jarvis.core.capabilities.loader import default_config_dict, validate_and_normalize
from jarvis.core.crypto import generate_usb_master_key_bytes, write_usb_key
from jarvis.core.events import EventLogger
from jarvis.core.policy.engine import PolicyEngine
from jarvis.core.policy.models import PolicyConfigFile, PolicyEffect, PolicyMatch, PolicyRule
from jarvis.core.security import AdminSession, SecurityManager
from jarvis.core.secure_store import SecureStore
from jarvis.web.api import create_app
from jarvis.web.security.auth import ApiKeyStore


class DummyLogger:
    def info(self, *_a, **_k): ...
    def warning(self, *_a, **_k): ...
    def error(self, *_a, **_k): ...


class DummyBreakers:
    def status(self):  # noqa: ANN001
        return {}


class DummyRuntime:
    def __init__(self, *, safe_mode: bool, shutting_down: bool):
        self.safe_mode = bool(safe_mode)
        self._shutdown_in_progress = bool(shutting_down)
        self.breakers = DummyBreakers()


def _security(tmp_path):
    usb = tmp_path / "usb.bin"
    write_usb_key(str(usb), generate_usb_master_key_bytes())
    store = SecureStore(usb_key_path=str(usb), store_path=str(tmp_path / "store.enc"))
    sec = SecurityManager(secure_store=store, admin_session=AdminSession(timeout_seconds=9999))
    return sec, store


def _make_app(tmp_path, *, admin_unlocked: bool, policy_engine=None, extra_intents=None):
    sec, store = _security(tmp_path)
    if admin_unlocked:
        sec.admin_session.unlock()

    raw = default_config_dict()
    for k, v in (extra_intents or {}).items():
        raw["intent_requirements"][k] = list(v)
    cap_cfg = validate_and_normalize(raw)
    cap_engine = CapabilityEngine(cfg=cap_cfg, audit=CapabilityAuditLogger(path=str(tmp_path / "security.jsonl")), logger=None, event_bus=None)
    cap_engine.policy_engine = policy_engine

    class FakeDispatcher:
        def __init__(self, capability_engine):
            self.capability_engine = capability_engine

    class FakeJarvis:
        def __init__(self, dispatcher):
            self.dispatcher = dispatcher

    runtime = DummyRuntime(safe_mode=False, shutting_down=False)
    web_cfg = {
        "max_request_bytes": 32768,
        "rate_limits": {"per_ip_per_minute": 100, "per_key_per_minute": 100, "admin_per_minute": 100},
        "lockout": {"strike_threshold": 10, "lockout_minutes": 15, "permanent_after": 3},
        "admin": {"allow_remote_unlock": False, "allowed_admin_ips": ["127.0.0.1"]},
    }
    app = create_app(
        jarvis_app=FakeJarvis(FakeDispatcher(cap_engine)),
        security_manager=sec,
        event_logger=EventLogger(str(tmp_path / "events.jsonl")),
        logger=DummyLogger(),
        auth_dep=None,
        job_manager=None,
        runtime=runtime,
        secure_store=store,
        web_cfg=web_cfg,
        telemetry=None,
        draining_event=None,
        allowed_origins=[],
        enable_web_ui=False,
        allow_remote_admin_unlock=False,
        remote_control_enabled=True,
        lockdown_manager=None,
    )
    key = ApiKeyStore(store).create_key(scopes=["read"])["key"]
    return TestClient(app), key


def test_web_capabilities_eval_rejects_is_admin_spoof(tmp_path):
    client, key = _make_app(tmp_path, admin_unlocked=False)
    res = client.post(
        "/v1/capabilities/eval",
        headers={"X-API-Key": key},
        json={"intent_id": "anime_dubbing.run", "is_admin": True, "safe_mode": False, "shutting_down": False},
    )
    assert res.status_code == 200
    data = res.json()
    assert data.get("allowed") is False
    assert data.get("simulated") is False


def test_web_policy_eval_simulate_requires_admin_and_marks_simulated(tmp_path):
    cfg = PolicyConfigFile(
        enabled=True,
        rules=[
            PolicyRule(
                id="require_admin_for_demo",
                description="Require admin for demo intent",
                priority=1,
                effect=PolicyEffect.REQUIRE_ADMIN,
                match=PolicyMatch(intent_id_in=["demo.intent"]),
                reason="Admin required.",
                remediation="Unlock admin to proceed.",
            )
        ],
    )
    pe = PolicyEngine(cfg=cfg, event_bus=None)
    client, key = _make_app(tmp_path, admin_unlocked=True, policy_engine=pe, extra_intents={"demo.intent": []})
    res = client.post(
        "/v1/policy/eval",
        headers={"X-API-Key": key},
        json={"intent_id": "demo.intent", "simulate": True, "is_admin": False},
    )
    assert res.status_code == 200
    data = res.json()
    assert data.get("allowed") is False
    assert data.get("simulated") is True
