from __future__ import annotations

import json
import socket
import subprocess

from jarvis.core.broker.interface import ToolResult
from jarvis.core.broker.registry import ToolRegistry
from jarvis.core.broker.server import BrokerServer
from jarvis.core.capabilities.audit import CapabilityAuditLogger
from jarvis.core.capabilities.engine import CapabilityEngine
from jarvis.core.capabilities.loader import default_config_dict, validate_and_normalize
from jarvis.core.events import EventLogger
from jarvis.core.execution.models import ExecutionBackend, ExecutionPlan, ExecutionRequest, ToolCall
from jarvis.core.execution.sandbox_runner import SandboxExecutionRunner
from jarvis.core.policy.engine import PolicyEngine
from jarvis.core.policy.models import PolicyConfigFile
from jarvis.core.security_events import SecurityAuditLogger


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


def test_broker_unknown_tool_denied_direct(tmp_path):
    cap_engine = _make_capability_engine(tmp_path)
    policy_engine = PolicyEngine(cfg=PolicyConfigFile())
    registry = ToolRegistry()
    server = BrokerServer(
        tool_broker=registry,
        capability_engine=cap_engine,
        policy_engine=policy_engine,
        event_logger=EventLogger(str(tmp_path / "events.jsonl")),
        audit_logger=SecurityAuditLogger(path=str(tmp_path / "security.jsonl")),
        logger=_L(),
    )
    info = server.start()
    try:
        res = server.handle_call(
            {
                "token": info["token"],
                "trace_id": "t1",
                "tool_name": "unknown.tool",
                "tool_args": {},
                "requested_caps": [],
                "context": {"trace_id": "t1"},
            },
            client_host="127.0.0.1",
        )
        assert res.ok is False
        assert res.reason_code == "TOOL_UNKNOWN"
    finally:
        server.stop()


def test_broker_token_enforcement(tmp_path):
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
        audit_logger=SecurityAuditLogger(path=str(tmp_path / "security.jsonl")),
        logger=_L(),
    )
    info = server.start()
    try:
        res = _call_broker(
            info["host"],
            info["port"],
            {
                "trace_id": "t2",
                "tool_name": "core.echo",
                "tool_args": {"msg": "hi"},
                "requested_caps": [],
                "context": {"trace_id": "t2"},
            },
        )
        assert res.get("allowed") is False
        assert res.get("reason_code") == "TOKEN_INVALID"

        res2 = _call_broker(
            info["host"],
            info["port"],
            {
                "token": "bad-token",
                "trace_id": "t3",
                "tool_name": "core.echo",
                "tool_args": {"msg": "hi"},
                "requested_caps": [],
                "context": {"trace_id": "t3"},
            },
        )
        assert res2.get("allowed") is False
        assert res2.get("reason_code") == "TOKEN_INVALID"

        res3 = _call_broker(
            info["host"],
            info["port"],
            {
                "token": info["token"],
                "trace_id": "t4",
                "tool_name": "core.echo",
                "tool_args": {"msg": "hi"},
                "requested_caps": [],
                "context": {"trace_id": "t4"},
            },
        )
        assert res3.get("allowed") is True
        assert res3.get("reason_code") == "ALLOWED"
    finally:
        server.stop()


def test_sandbox_runner_broker_env_and_stop(monkeypatch, tmp_path):
    runner = SandboxExecutionRunner(config={"sandbox": {"image": "jarvis-sandbox:latest", "work_root": str(tmp_path)}}, logger=_L())
    monkeypatch.setattr(SandboxExecutionRunner, "is_available", lambda _self: True)

    broker_state = {}

    class FakeBrokerServer:
        def __init__(self, *args, **kwargs):  # noqa: ANN001
            broker_state["instance"] = self
            self.started = False
            self.stopped = False

        def start(self):  # noqa: D401
            self.started = True
            return {"host": "127.0.0.1", "port": 8123, "token": "tok"}

        def stop(self) -> None:
            self.stopped = True

    monkeypatch.setattr("jarvis.core.execution.sandbox_runner.BrokerServer", FakeBrokerServer)

    cmds: list[list[str]] = []

    def fake_run(cmd, *args, **kwargs):  # noqa: ANN001
        if cmd[:2] == ["docker", "rm"]:
            return subprocess.CompletedProcess(cmd, 0, "", "")
        cmds.append(cmd)
        raise subprocess.TimeoutExpired(cmd, timeout=1)

    monkeypatch.setattr("jarvis.core.execution.sandbox_runner.subprocess.run", fake_run)

    req = ExecutionRequest(
        trace_id="t5",
        intent_id="system.plan",
        module_id="plan",
        args={},
        context={"source": "cli", "is_admin": False, "user_id": "default"},
        required_capabilities=[],
        execution_mode="process",
        is_core=True,
        allow_inline_intents=[],
        default_backend=ExecutionBackend.sandbox,
        fallback_backend=ExecutionBackend.local_process,
        sandbox_require_available=True,
        sandbox_available=True,
        module_path="",
        persist_allowed=True,
        execution_plan=ExecutionPlan(
            backend=ExecutionBackend.sandbox,
            mode="sandbox",
            reason="plan",
            fallback_used=False,
            tool_calls=[ToolCall(tool_name="core.echo", tool_args={"msg": "hello"})],
        ),
    )

    res = runner.run(request=req, plan=req.execution_plan)
    assert res.ok is False
    assert res.error == "sandbox_timeout"
    assert broker_state["instance"].started is True
    assert broker_state["instance"].stopped is True
    assert cmds
    env_vars = {cmd[i + 1] for i, val in enumerate(cmds[0]) if val == "-e"}
    assert any(val.startswith("BROKER_URL=") for val in env_vars)
    assert any(val.startswith("BROKER_TOKEN=") for val in env_vars)


def test_broker_audit_redacts_sensitive_args(tmp_path):
    cap_engine = _make_capability_engine(tmp_path)
    policy_engine = PolicyEngine(cfg=PolicyConfigFile())
    registry = ToolRegistry()

    def _echo(args, context):  # noqa: ANN001
        trace_id = str((context or {}).get("trace_id") or "tool")
        return ToolResult(allowed=True, reason_code="ALLOWED", trace_id=trace_id, output={"ok": True})

    registry.register("core.echo", _echo)
    events_path = tmp_path / "events.jsonl"
    audit_path = tmp_path / "security.jsonl"
    server = BrokerServer(
        tool_broker=registry,
        capability_engine=cap_engine,
        policy_engine=policy_engine,
        event_logger=EventLogger(str(events_path)),
        audit_logger=SecurityAuditLogger(path=str(audit_path)),
        logger=_L(),
    )
    info = server.start()
    try:
        server.handle_call(
            {
                "token": info["token"],
                "trace_id": "t6",
                "tool_name": "core.echo",
                "tool_args": {"password": "supersecret", "token": "abc123", "key": "def456"},
                "requested_caps": [],
                "context": {"trace_id": "t6"},
            },
            client_host="127.0.0.1",
        )
    finally:
        server.stop()
    event_data = events_path.read_text(encoding="utf-8")
    assert "supersecret" not in event_data
    assert "abc123" not in event_data
    assert "def456" not in event_data
