from __future__ import annotations

import os
import time

import pytest


def test_telemetry_records_metrics_and_snapshot(tmp_path, monkeypatch):
    from jarvis.core.telemetry.manager import TelemetryConfig, TelemetryManager

    monkeypatch.chdir(tmp_path)
    tm = TelemetryManager(cfg=TelemetryConfig(enabled=True, poll_interval_seconds=9999, sample_interval_seconds=9999), logger=None, root_path=".")
    try:
        tm.increment_counter("requests_total", 1, tags={"source": "cli"})
        tm.set_gauge("jobs_queued", 3)
        tm.record_latency("routing_latency_ms", 12.5, tags={"source": "stage_a"})
        snap = tm.get_snapshot()
        assert "metrics" in snap
        assert "resources" in snap
        ms = tm.get_metrics_summary()
        assert any(k.startswith("requests_total") for k in ms.get("counters", {}).keys())
        assert any(k.startswith("routing_latency_ms") for k in ms.get("histograms", {}).keys())
    finally:
        tm.stop()


def test_redaction_removes_secrets():
    from jarvis.core.telemetry.redaction import telemetry_redact

    obj = {
        "api_key": "abc123",
        "nested": {"token": "t0k3n", "note": "Authorization: Bearer SECRETSECRET"},
        "msg": "password=supersecret",
    }
    out = telemetry_redact(obj)
    assert "abc123" not in str(out)
    assert "t0k3n" not in str(out)
    assert "SECRETSECRET" not in str(out)
    assert "supersecret" not in str(out)


def test_health_change_emits_event(tmp_path, monkeypatch):
    from jarvis.core.telemetry.manager import TelemetryConfig, TelemetryManager

    monkeypatch.chdir(tmp_path)

    class DummyStore:
        def __init__(self):
            self.mode = "READY"

        def status(self):
            class S:
                def __init__(self, mode):
                    self.mode = type("M", (), {"value": mode})()

            return S(self.mode)

    store = DummyStore()
    tm = TelemetryManager(cfg=TelemetryConfig(enabled=True, poll_interval_seconds=0.2, sample_interval_seconds=9999), logger=None, root_path=".")
    try:
        tm.attach(secure_store=store)
        # allow first check to populate baseline
        time.sleep(0.5)
        store.mode = "KEY_MISSING"
        time.sleep(0.6)
        snap = tm.get_snapshot()
        evs = snap.get("recent_events") or []
        assert any(e.get("event_type") == "health_change" and e.get("subsystem") == "secure_store" for e in evs)
    finally:
        tm.stop()


def test_retention_cleanup_removes_old_telemetry_logs(tmp_path, monkeypatch):
    from jarvis.core.telemetry.manager import TelemetryConfig, TelemetryManager

    monkeypatch.chdir(tmp_path)
    os.makedirs(os.path.join("logs", "telemetry"), exist_ok=True)
    p = os.path.join("logs", "telemetry", "metrics.jsonl")
    with open(p, "w", encoding="utf-8") as f:
        f.write("x\n")
    old = time.time() - (10 * 86400)
    os.utime(p, (old, old))
    tm = TelemetryManager(cfg=TelemetryConfig(enabled=False, retention_days=1), logger=None, root_path=".")
    try:
        assert not os.path.exists(p)
    finally:
        tm.stop()


def test_web_endpoints_return_telemetry_snapshot(tmp_path, monkeypatch):
    # Skip if fastapi test client not present (should be in dev deps).
    try:
        from fastapi.testclient import TestClient
    except Exception:
        pytest.skip("fastapi TestClient unavailable")

    from jarvis.core.events import EventLogger
    from jarvis.core.secure_store import SecureStore
    from jarvis.core.crypto import generate_usb_master_key_bytes, write_usb_key
    from jarvis.web.api import create_app
    from jarvis.web.security.auth import ApiKeyStore
    from jarvis.core.telemetry.manager import TelemetryConfig, TelemetryManager

    monkeypatch.chdir(tmp_path)
    usb = tmp_path / "usb.bin"
    write_usb_key(str(usb), generate_usb_master_key_bytes())
    store = SecureStore(usb_key_path=str(usb), store_path=str(tmp_path / "store.enc"))
    key = ApiKeyStore(store).create_key(scopes=["read", "message", "admin"])["key"]

    class DummyRuntime:
        def __init__(self, telemetry):
            self.telemetry = telemetry
            self.llm_lifecycle = None

        def submit_text(self, *_a, **_k):
            return "tid"

        def wait_for_result(self, *_a, **_k):
            return {"reply": "ok", "intent": {"id": "music.play", "source": "stage_a", "confidence": 1.0}}

        def get_status(self):
            return {"state": "SLEEPING"}

    tm = TelemetryManager(cfg=TelemetryConfig(enabled=False), logger=None, root_path=".")
    app = create_app(
        jarvis_app=type("J", (), {"process_message": lambda *_a, **_k: None})(),
        security_manager=type("S", (), {"verify_and_unlock_admin": lambda *_a, **_k: False})(),
        event_logger=EventLogger(str(tmp_path / "events.jsonl")),
        logger=type("L", (), {"error": lambda *_a, **_k: None})(),
        auth_dep=None,
        job_manager=None,
        runtime=DummyRuntime(tm),
        secure_store=store,
        web_cfg={"max_request_bytes": 32768, "rate_limits": {"per_ip_per_minute": 1000, "per_key_per_minute": 1000, "admin_per_minute": 1000}, "lockout": {"strike_threshold": 100, "lockout_minutes": 15, "permanent_after": 3}, "admin": {"allow_remote_unlock": False, "allowed_admin_ips": ["127.0.0.1"]}},
        allowed_origins=[],
        enable_web_ui=False,
        remote_control_enabled=True,
        telemetry=tm,
    )
    c = TestClient(app)
    r = c.get("/v1/telemetry/snapshot", headers={"X-API-Key": key})
    assert r.status_code == 200
    assert "health" in r.json()
    tm.stop()

