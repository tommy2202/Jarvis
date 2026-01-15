from __future__ import annotations

import time

import pytest

from jarvis.core.audit.timeline import AuditTimelineManager
from jarvis.core.config.manager import ConfigManager
from jarvis.core.config.paths import ConfigFsPaths
from jarvis.core.events.bus import EventBus, EventBusConfig, OverflowPolicy
from jarvis.core.privacy.store import PrivacyStore


class _L:
    def info(self, *_a, **_k): ...
    def warning(self, *_a, **_k): ...
    def error(self, *_a, **_k): ...


def _make_cfg(tmp_path) -> ConfigManager:
    cm = ConfigManager(fs=ConfigFsPaths(str(tmp_path)), logger=_L(), read_only=False)
    cm.load_all()
    return cm


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


def test_consent_grant_revoke(tmp_path):
    cm = _make_cfg(tmp_path)
    ps = PrivacyStore(db_path=str(tmp_path / "runtime" / "privacy.sqlite"), config_manager=cm, event_bus=None, logger=_L())

    assert ps.set_consent(user_id="default", scope="telemetry", granted=True, trace_id="t", actor_is_admin=False) is True
    c = ps.get_consent(user_id="default", scope="telemetry")
    assert c is not None and c.granted is True

    assert ps.set_consent(user_id="default", scope="telemetry", granted=False, trace_id="t", actor_is_admin=False) is True
    c2 = ps.get_consent(user_id="default", scope="telemetry")
    assert c2 is not None and c2.granted is False

    # Sensitive scopes require admin
    assert ps.set_consent(user_id="default", scope="memory", granted=True, trace_id="t", actor_is_admin=False) is False
    assert ps.set_consent(user_id="default", scope="memory", granted=True, trace_id="t", actor_is_admin=True) is True


def test_consent_audited(tmp_path):
    cm = _make_cfg(tmp_path)
    eb = EventBus(cfg=EventBusConfig(enabled=True, max_queue_size=1000, worker_threads=2, overflow_policy=OverflowPolicy.DROP_OLDEST))
    audit = _mk_audit_mgr(tmp_path, eb)

    ps = PrivacyStore(db_path=str(tmp_path / "runtime" / "privacy.sqlite"), config_manager=cm, event_bus=eb, logger=_L())
    assert ps.set_consent(user_id="default", scope="telemetry", granted=True, trace_id="trace123", actor_is_admin=False) is True

    # event bus + audit ingestion is async; poll for a short window
    deadline = time.time() + 3.0
    found = False
    while time.time() < deadline and not found:
        rows = audit.list_events(limit=200)
        found = any(r.action == "privacy.consent_changed" for r in rows)
        if not found:
            time.sleep(0.05)
    assert found is True


def test_retention_change_requires_admin(tmp_path):
    cm = _make_cfg(tmp_path)
    ps = PrivacyStore(db_path=str(tmp_path / "runtime" / "privacy.sqlite"), config_manager=cm, event_bus=None, logger=_L())

    raw_before = cm.read_non_sensitive("privacy.json")
    with pytest.raises(PermissionError):
        ps.set_retention_ttl_days(policy_id="AUDIT:LOW", ttl_days=7, trace_id="t", actor_is_admin=False)
    raw_after = cm.read_non_sensitive("privacy.json")
    assert raw_after == raw_before

