from __future__ import annotations

from jarvis.core.dispatcher import Dispatcher
from jarvis.core.events import EventLogger
from jarvis.core.module_registry import ModuleRegistry
from jarvis.core.security import PermissionPolicy, SecurityManager, AdminSession
from jarvis.core.secure_store import SecureStore
from jarvis.core.crypto import generate_usb_master_key_bytes, write_usb_key
from jarvis.core.capabilities.engine import CapabilityEngine
from jarvis.core.capabilities.loader import validate_and_normalize, default_config_dict
from jarvis.core.capabilities.audit import CapabilityAuditLogger
from jarvis.core.policy.engine import PolicyEngine
from jarvis.core.policy.models import PolicyConfigFile
from jarvis.core.jarvis_app import JarvisApp
from jarvis.core.intent_router import StageAIntentRouter, StageAIntent
from jarvis.core.llm_router import StageBLLMRouter, LLMConfig


def test_require_confirmation_blocks_until_confirm(tmp_path):
    # Minimal wiring: registry + dispatcher + jarvis_app
    usb = tmp_path / "usb.bin"
    write_usb_key(str(usb), generate_usb_master_key_bytes())
    store = SecureStore(usb_key_path=str(usb), store_path=str(tmp_path / "store.enc"))
    security = SecurityManager(secure_store=store, admin_session=AdminSession(timeout_seconds=60))

    reg = ModuleRegistry()
    called = {"n": 0}

    def handler(intent_id, args, context):  # noqa: ANN001
        called["n"] += 1
        return {"ok": True}

    from jarvis.core.module_registry import LoadedModule

    reg._modules_by_id["mod"] = LoadedModule(module_path="test.mod", module_id="mod", handler=handler, meta={"id": "mod", "resource_intensive": False})  # type: ignore[attr-defined]

    policy = PermissionPolicy(intents={"intent.x": {"requires_admin": False}})
    # Use default capability definitions, override intent requirements for our intent.
    raw_caps = default_config_dict()
    raw_caps["intent_requirements"] = {"intent.x": []}
    raw_caps["source_policies"] = {}
    raw_caps["safe_mode"] = {"deny": []}
    caps_cfg = validate_and_normalize(raw_caps)
    cap_engine = CapabilityEngine(cfg=caps_cfg, audit=CapabilityAuditLogger(path=str(tmp_path / "sec.jsonl")), logger=None, event_bus=None)
    pol_cfg = PolicyConfigFile.model_validate({"enabled": True, "rules": [{"id": "confirm", "priority": 1, "effect": "REQUIRE_CONFIRMATION", "match": {"intent_id_in": ["intent.x"]}, "reason": "Confirm needed"}]})
    cap_engine.policy_engine = PolicyEngine(cfg=pol_cfg)

    disp = Dispatcher(registry=reg, policy=policy, security=security, event_logger=EventLogger(str(tmp_path / "events.jsonl")), logger=type("L", (), {"error": lambda *_a, **_k: None})(), capability_engine=cap_engine, secure_store=store)

    # Jarvis app
    stage_a = StageAIntentRouter([StageAIntent(id="intent.x", module_id="mod", keywords=["do"], required_args=[])], threshold=0.0)
    stage_b = StageBLLMRouter(LLMConfig(mock_mode=True))
    ja = JarvisApp(stage_a=stage_a, stage_b=stage_b, dispatcher=disp, intent_config_by_id={"intent.x": {"module_id": "mod", "required_args": []}}, confirmation_templates={"intent.x": "Doing X."}, event_logger=EventLogger(str(tmp_path / "events2.jsonl")), logger=type("L2", (), {})(), threshold=0.0)

    r1 = ja.process_message("do", client={"id": "c"}, source="cli")
    assert called["n"] == 0
    assert r1.requires_followup is True

    r2 = ja.process_message("confirm", client={"id": "c"}, source="cli")
    assert called["n"] == 1
    assert "Doing X" in r2.reply

