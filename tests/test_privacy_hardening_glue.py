from __future__ import annotations

import os

from jarvis.core.capabilities.audit import CapabilityAuditLogger
from jarvis.core.capabilities.engine import CapabilityEngine
from jarvis.core.capabilities.loader import default_config_dict, validate_and_normalize
from jarvis.core.config.manager import ConfigManager
from jarvis.core.config.paths import ConfigFsPaths
from jarvis.core.crypto import generate_usb_master_key_bytes, write_usb_key
from jarvis.core.dispatcher import Dispatcher
from jarvis.core.events import EventLogger
from jarvis.core.module_registry import ModuleRegistry
from jarvis.core.privacy.models import DataCategory
from jarvis.core.privacy.store import PrivacyStore
from jarvis.core.runtime import JarvisRuntime, RuntimeConfig, RuntimeEvent, EventType
from jarvis.core.security import AdminSession, PermissionPolicy, SecurityManager
from jarvis.core.secure_store import SecureStore


class _L:
    def info(self, *_a, **_k): ...
    def warning(self, *_a, **_k): ...
    def error(self, *_a, **_k): ...


def _make_cfg(tmp_path) -> ConfigManager:
    cm = ConfigManager(fs=ConfigFsPaths(str(tmp_path)), logger=_L(), read_only=False)
    cm.load_all()
    return cm


def _make_secure_store(tmp_path) -> SecureStore:
    usb = tmp_path / "usb.bin"
    write_usb_key(str(usb), generate_usb_master_key_bytes())
    return SecureStore(usb_key_path=str(usb), store_path=str(tmp_path / "store.enc"))


def test_no_transcript_stored_by_default(tmp_path):
    # State machine persistence must not contain raw text.
    persist = tmp_path / "sm.jsonl"
    rt = JarvisRuntime(
        cfg=RuntimeConfig(),
        jarvis_app=object(),
        event_logger=EventLogger(str(tmp_path / "events.jsonl")),
        logger=_L(),
        persist_path=str(persist),
    )
    _ = rt.submit_text("cli", "my secret transcript text", client_meta={"id": "c"})
    data = persist.read_text(encoding="utf-8", errors="ignore")
    assert "my secret transcript text" not in data
    assert "text_len" in data


def test_transcript_storage_requires_consent(tmp_path):
    cm = _make_cfg(tmp_path)
    # enable persistent transcript storage in privacy.json
    raw = cm.read_non_sensitive("privacy.json")
    raw.setdefault("data_minimization", {})
    raw["data_minimization"]["disable_persistent_transcripts"] = False
    cm.save_non_sensitive("privacy.json", raw)

    store = _make_secure_store(tmp_path)
    sec = SecurityManager(secure_store=store, admin_session=AdminSession(timeout_seconds=9999))
    ps = PrivacyStore(db_path=str(tmp_path / "runtime" / "privacy.sqlite"), config_manager=cm, event_bus=None, logger=_L())
    ps.attach_secure_store(store)

    rt = JarvisRuntime(
        cfg=RuntimeConfig(),
        jarvis_app=object(),
        event_logger=EventLogger(str(tmp_path / "events.jsonl")),
        logger=_L(),
        security_manager=sec,
        secure_store=store,
        persist_path=str(tmp_path / "sm.jsonl"),
        privacy_store=ps,
    )

    # No consent -> should not store
    rt._enqueue(RuntimeEvent(trace_id="t1", source="voice", type=EventType.TranscriptionReady, payload={"text": "hello"}))
    try:
        _ = store.get("transcript:t1")
        assert False, "transcript stored without consent"
    except Exception:
        pass

    # Grant consent -> should store encrypted blob + create DataRecord with expires_at
    ps.set_consent(user_id="default", scope="transcripts", granted=True, trace_id="t", actor_is_admin=True)
    rt._enqueue(RuntimeEvent(trace_id="t2", source="voice", type=EventType.TranscriptionReady, payload={"text": "hello2"}))
    assert str(store.get("transcript:t2")) == "hello2"
    recs = ps.list_records(user_id="default", limit=200)
    hits = [r for r in recs if r.data_category == DataCategory.TRANSCRIPT and "transcript:t2" in r.storage_ref]
    assert hits and hits[0].expires_at is not None


def test_ephemeral_mode_executes_action(tmp_path):
    cm = _make_cfg(tmp_path)
    ps = PrivacyStore(db_path=str(tmp_path / "runtime" / "privacy.sqlite"), config_manager=cm, event_bus=None, logger=_L())

    # Capability engine must allow the intent (empty caps)
    raw_caps = default_config_dict()
    raw_caps.setdefault("intent_requirements", {})
    raw_caps["intent_requirements"]["core.privacy.test"] = []
    cap_cfg = validate_and_normalize(raw_caps)
    eng = CapabilityEngine(cfg=cap_cfg, audit=CapabilityAuditLogger(path=str(tmp_path / "security.jsonl")), logger=None)

    store = _make_secure_store(tmp_path)
    sec = SecurityManager(secure_store=store, admin_session=AdminSession(timeout_seconds=9999))
    reg = ModuleRegistry()

    def handler(intent_id, args, context):  # noqa: ANN001
        # Attempt to persist an artifact reference; should be blocked in ephemeral mode.
        from jarvis.core.privacy.models import DataRecord, LawfulBasis, Sensitivity, StorageKind

        ps.register_record(
            DataRecord(
                user_id="default",
                data_category=DataCategory.JOB_ARTIFACT,
                sensitivity=Sensitivity.MEDIUM,
                lawful_basis=LawfulBasis.LEGITIMATE_INTERESTS,
                created_at="2026-01-01T00:00:00Z",
                storage_kind=StorageKind.FILE,
                storage_ref=str(tmp_path / "runtime" / "should_not_exist.bin"),
                storage_ref_hash="x",
                producer="test",
            )
        )
        return {"ephemeral": bool((context or {}).get("ephemeral", False)), "ok": True}

    reg.register_handler(module_id="core.mod", module_path="test.core.mod", meta={}, handler=handler)
    disp = Dispatcher(
        registry=reg,
        policy=PermissionPolicy(intents={}),
        security=sec,
        event_logger=EventLogger(str(tmp_path / "e.jsonl")),
        logger=_L(),
        capability_engine=eng,
        secure_store=store,
        privacy_store=ps,
    )

    r0 = disp.dispatch("t", "core.privacy.test", "core.mod", {}, {"source": "cli", "user_id": "default", "privacy_scopes": ["memory"]})
    assert r0.ok is True
    assert (r0.module_output or {}).get("ephemeral") is True
    assert (r0.module_output or {}).get("ok") is True
    # No artifact DataRecord should be persisted.
    recs = ps.list_records(user_id="default", limit=200)
    assert not any(r.data_category == DataCategory.JOB_ARTIFACT for r in recs)


def test_consent_allows_persistence(tmp_path):
    cm = _make_cfg(tmp_path)
    store = _make_secure_store(tmp_path)
    sec = SecurityManager(secure_store=store, admin_session=AdminSession(timeout_seconds=9999))
    ps = PrivacyStore(db_path=str(tmp_path / "runtime" / "privacy.sqlite"), config_manager=cm, event_bus=None, logger=_L())

    # Grant consent for memory scope so persistence is allowed.
    ps.set_consent(user_id="default", scope="memory", granted=True, trace_id="t", actor_is_admin=True)

    raw_caps = default_config_dict()
    raw_caps.setdefault("intent_requirements", {})
    raw_caps["intent_requirements"]["core.privacy.test2"] = []
    cap_cfg = validate_and_normalize(raw_caps)
    eng = CapabilityEngine(cfg=cap_cfg, audit=CapabilityAuditLogger(path=str(tmp_path / "security.jsonl")), logger=None)

    reg = ModuleRegistry()

    def handler2(intent_id, args, context):  # noqa: ANN001
        from jarvis.core.privacy.models import DataRecord, LawfulBasis, Sensitivity, StorageKind

        rid = ps.register_record(
            DataRecord(
                user_id="default",
                data_category=DataCategory.JOB_ARTIFACT,
                sensitivity=Sensitivity.MEDIUM,
                lawful_basis=LawfulBasis.LEGITIMATE_INTERESTS,
                created_at="2026-01-01T00:00:00Z",
                storage_kind=StorageKind.FILE,
                storage_ref=str(tmp_path / "runtime" / "ok.bin"),
                storage_ref_hash="y",
                producer="test",
            )
        )
        return {"ephemeral": bool((context or {}).get("ephemeral", False)), "record_id": rid}

    reg.register_handler(module_id="core.mod2", module_path="test.core.mod2", meta={}, handler=handler2)
    disp = Dispatcher(
        registry=reg,
        policy=PermissionPolicy(intents={}),
        security=sec,
        event_logger=EventLogger(str(tmp_path / "e2.jsonl")),
        logger=_L(),
        capability_engine=eng,
        secure_store=store,
        privacy_store=ps,
    )

    r1 = disp.dispatch("t", "core.privacy.test2", "core.mod2", {}, {"source": "cli", "user_id": "default", "privacy_scopes": ["memory"]})
    assert r1.ok is True
    assert (r1.module_output or {}).get("ephemeral") is False
    recs = ps.list_records(user_id="default", limit=200)
    assert any(r.data_category == DataCategory.JOB_ARTIFACT for r in recs)

