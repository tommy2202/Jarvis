from __future__ import annotations

import json
import os
import socket
import time

from jarvis.core.broker.registry import ToolRegistry
from jarvis.core.broker.server import BrokerServer
from jarvis.core.broker.write_broker import WriteBroker
from jarvis.core.capabilities.audit import CapabilityAuditLogger
from jarvis.core.capabilities.engine import CapabilityEngine
from jarvis.core.capabilities.loader import default_config_dict, validate_and_normalize
from jarvis.core.config.manager import ConfigManager
from jarvis.core.config.paths import ConfigFsPaths
from jarvis.core.crypto import generate_usb_master_key_bytes, write_usb_key
from jarvis.core.events import EventLogger
from jarvis.core.policy.engine import PolicyEngine
from jarvis.core.policy.models import PolicyConfigFile
from jarvis.core.privacy.store import PrivacyStore
from jarvis.core.secure_store import SecureStore
from jarvis.core.security_events import SecurityAuditLogger
from .helpers.config_builders import build_policy_config_v1


class _L:
    def info(self, *_a, **_k): ...
    def warning(self, *_a, **_k): ...
    def error(self, *_a, **_k): ...


def _make_cfg(tmp_path) -> ConfigManager:
    fs = ConfigFsPaths(str(tmp_path))
    os.makedirs(fs.config_dir, exist_ok=True)
    policy_path = os.path.join(fs.config_dir, "policy.json")
    if not os.path.exists(policy_path):
        with open(policy_path, "w", encoding="utf-8") as f:
            json.dump(build_policy_config_v1(), f)
            f.write("\n")
    cm = ConfigManager(fs=fs, logger=_L(), read_only=False)
    cm.load_all()
    return cm


def _make_capability_engine(tmp_path) -> CapabilityEngine:
    raw = default_config_dict()
    raw["intent_requirements"]["system.tool.call"] = []
    cfg = validate_and_normalize(raw)
    return CapabilityEngine(cfg=cfg, audit=CapabilityAuditLogger(path=str(tmp_path / "security.jsonl")), logger=None)


def _call_broker(host: str, port: int, payload: dict) -> dict:
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8") + b"\n"
    with socket.create_connection((host, int(port)), timeout=2) as s:
        s.sendall(data)
        res = s.recv(65536).decode("utf-8")
    return json.loads(res.strip() or "{}")


def test_unknown_tool_denied(tmp_path):
    cap_engine = _make_capability_engine(tmp_path)
    policy_engine = PolicyEngine(cfg=PolicyConfigFile())
    registry = ToolRegistry()
    server = BrokerServer(
        tool_broker=registry,
        capability_engine=cap_engine,
        policy_engine=policy_engine,
        event_logger=EventLogger(str(tmp_path / "events.jsonl")),
        logger=_L(),
    )
    info = server.start()
    try:
        res = _call_broker(
            info["host"],
            info["port"],
            {
                "token": info["token"],
                "trace_id": "t1",
                "tool_name": "unknown.tool",
                "tool_args": {},
                "requested_caps": [],
                "context": {"trace_id": "t1"},
            },
        )
        assert res.get("allowed") is False
        assert res.get("reason_code") == "TOOL_UNKNOWN"
    finally:
        server.stop()


def test_token_required_and_expires(tmp_path):
    cap_engine = _make_capability_engine(tmp_path)
    policy_engine = PolicyEngine(cfg=PolicyConfigFile())
    registry = ToolRegistry()
    server = BrokerServer(
        tool_broker=registry,
        capability_engine=cap_engine,
        policy_engine=policy_engine,
        event_logger=EventLogger(str(tmp_path / "events.jsonl")),
        logger=_L(),
        token_ttl_seconds=0.05,
    )
    info = server.start()
    try:
        res = _call_broker(
            info["host"],
            info["port"],
            {
                "trace_id": "t2",
                "tool_name": "unknown.tool",
                "tool_args": {},
                "requested_caps": [],
                "context": {"trace_id": "t2"},
            },
        )
        assert res.get("allowed") is False
        assert res.get("reason_code") == "TOKEN_INVALID"

        time.sleep(0.1)
        res2 = _call_broker(
            info["host"],
            info["port"],
            {
                "token": info["token"],
                "trace_id": "t3",
                "tool_name": "unknown.tool",
                "tool_args": {},
                "requested_caps": [],
                "context": {"trace_id": "t3"},
            },
        )
        assert res2.get("allowed") is False
        assert res2.get("reason_code") == "TOKEN_EXPIRED"
    finally:
        server.stop()


def test_write_tool_respects_ephemeral_mode(tmp_path):
    cm = _make_cfg(tmp_path)
    ps = PrivacyStore(db_path=str(tmp_path / "runtime" / "privacy.sqlite"), config_manager=cm, event_bus=None, logger=_L())
    usb = tmp_path / "usb.bin"
    write_usb_key(str(usb), generate_usb_master_key_bytes())
    store = SecureStore(usb_key_path=str(usb), store_path=str(tmp_path / "store.enc"))
    broker = WriteBroker(privacy_store=ps, secure_store=store, audit_logger=SecurityAuditLogger(path=str(tmp_path / "security.jsonl")))
    cap_engine = _make_capability_engine(tmp_path)
    policy_engine = PolicyEngine(cfg=PolicyConfigFile())
    server = BrokerServer(
        tool_broker=broker,
        capability_engine=cap_engine,
        policy_engine=policy_engine,
        event_logger=EventLogger(str(tmp_path / "events.jsonl")),
        logger=_L(),
    )
    info = server.start()
    try:
        res = _call_broker(
            info["host"],
            info["port"],
            {
                "token": info["token"],
                "trace_id": "t4",
                "tool_name": "write.memory",
                "tool_args": {"content": "hello", "user_id": "default"},
                "requested_caps": [],
                "context": {"trace_id": "t4", "ephemeral": True},
            },
        )
        assert res.get("allowed") is False
        assert res.get("reason_code") == "ephemeral_mode"
    finally:
        server.stop()
