from __future__ import annotations

import json
import socket

import pytest

from jarvis.core.broker.interface import ToolResult
from jarvis.core.broker.registry import ToolRegistry
from jarvis.core.broker.server import BrokerServer
from jarvis.core.capabilities.audit import CapabilityAuditLogger
from jarvis.core.capabilities.engine import CapabilityEngine
from jarvis.core.capabilities.loader import default_config_dict, validate_and_normalize
from jarvis.core.events import EventLogger
from jarvis.core.policy.engine import PolicyEngine
from jarvis.core.policy.models import PolicyConfigFile


class _L:
    def info(self, *_a, **_k): ...
    def warning(self, *_a, **_k): ...
    def error(self, *_a, **_k): ...


def _make_capability_engine(tmp_path) -> CapabilityEngine:
    raw = default_config_dict()
    raw["intent_requirements"]["system.tool.call"] = []
    cfg = validate_and_normalize(raw)
    return CapabilityEngine(cfg=cfg, audit=CapabilityAuditLogger(path=str(tmp_path / "security.jsonl")), logger=None)


def _call_broker(host: str, port: int, payload: dict) -> dict:
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8") + b"\n"
    with socket.create_connection((host, int(port)), timeout=2) as sock:
        sock.sendall(data)
        res = sock.recv(65536).decode("utf-8")
    return json.loads(res.strip() or "{}")


def test_loopback_allowed_with_token(tmp_path):
    cap_engine = _make_capability_engine(tmp_path)
    policy_engine = PolicyEngine(cfg=PolicyConfigFile())
    registry = ToolRegistry()

    def _echo(args, context):  # noqa: ANN001
        trace_id = str((context or {}).get("trace_id") or "tool")
        return ToolResult(allowed=True, reason_code="ALLOWED", trace_id=trace_id, output={"echo": dict(args or {})})

    registry.register("core.echo", _echo)
    server = BrokerServer(
        tool_broker=registry,
        capability_engine=cap_engine,
        policy_engine=policy_engine,
        event_logger=EventLogger(str(tmp_path / "events.jsonl")),
        logger=_L(),
        allowed_client_cidrs=["127.0.0.1/32"],
    )
    info = server.start()
    try:
        res = _call_broker(
            info["host"],
            info["port"],
            {
                "token": info["token"],
                "trace_id": "t-allow",
                "tool_name": "core.echo",
                "tool_args": {"msg": "hi"},
                "requested_caps": [],
                "context": {"trace_id": "t-allow"},
            },
        )
        assert res.get("allowed") is True
        assert res.get("reason_code") == "ALLOWED"
    finally:
        server.stop()


def test_private_lan_denied_reason_code():
    server = BrokerServer(tool_broker=ToolRegistry())
    allowed, reason = server._check_client_allowed("192.168.1.10")
    assert allowed is False
    assert reason == "CLIENT_NOT_ALLOWED"


def test_docker_nat_allowed_only_when_configured():
    server = BrokerServer(tool_broker=ToolRegistry(), allowed_client_cidrs=["127.0.0.1/32", "::1/128", "172.16.0.0/12"])
    allowed_nat, reason_nat = server._check_client_allowed("172.18.0.2")
    assert allowed_nat is True
    assert reason_nat == "ALLOWED"

    allowed_private, reason_private = server._check_client_allowed("10.0.0.5")
    assert allowed_private is False
    assert reason_private == "CLIENT_NOT_ALLOWED"


def test_invalid_cidr_fails_start(tmp_path):
    cap_engine = _make_capability_engine(tmp_path)
    policy_engine = PolicyEngine(cfg=PolicyConfigFile())
    server = BrokerServer(
        tool_broker=ToolRegistry(),
        capability_engine=cap_engine,
        policy_engine=policy_engine,
        event_logger=EventLogger(str(tmp_path / "events.jsonl")),
        logger=_L(),
        allowed_client_cidrs=["127.0.0.1/32", "bad-cidr"],
    )
    with pytest.raises(ValueError, match="Invalid CIDR"):
        server.start()
