from __future__ import annotations

import subprocess

from jarvis.core.broker.registry import ToolRegistry
from jarvis.core.execution.models import ExecutionBackend, ExecutionPlan, ExecutionRequest, ToolCall
from jarvis.core.execution.sandbox_runner import SandboxExecutionRunner


class _L:
    def info(self, *_a, **_k): ...
    def warning(self, *_a, **_k): ...
    def error(self, *_a, **_k): ...


class _EventLogger:
    def __init__(self) -> None:
        self.events: list[dict] = []

    def log(self, trace_id: str, event_type: str, details: dict | None = None) -> None:
        self.events.append({"trace_id": trace_id, "event": event_type, "details": dict(details or {})})


def _make_request(*, trace_id: str, execution_plan: ExecutionPlan | None, tool_broker=None) -> ExecutionRequest:
    return ExecutionRequest(
        trace_id=trace_id,
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
        execution_plan=execution_plan,
        tool_broker=tool_broker,
    )


def test_non_plan_network_none(monkeypatch, tmp_path):
    runner = SandboxExecutionRunner(config={"sandbox": {"image": "jarvis-sandbox:latest", "work_root": str(tmp_path)}}, logger=_L())
    monkeypatch.setattr(SandboxExecutionRunner, "is_available", lambda _self: True)

    cmds: list[list[str]] = []

    def fake_run(cmd, *args, **kwargs):  # noqa: ANN001
        if cmd[:2] == ["docker", "rm"]:
            return subprocess.CompletedProcess(cmd, 0, "", "")
        cmds.append(cmd)
        raise subprocess.TimeoutExpired(cmd, timeout=1)

    monkeypatch.setattr("jarvis.core.execution.sandbox_runner.subprocess.run", fake_run)

    plan = ExecutionPlan(backend=ExecutionBackend.sandbox, mode="sandbox", reason="test", fallback_used=False)
    req = _make_request(trace_id="t-net-none", execution_plan=None, tool_broker=ToolRegistry())
    res = runner.run(request=req, plan=plan)
    assert res.ok is False
    assert cmds
    idx = cmds[0].index("--network")
    assert cmds[0][idx + 1] == "none"


def test_plan_network_exception_audited(monkeypatch, tmp_path):
    event_logger = _EventLogger()
    runner = SandboxExecutionRunner(
        config={"sandbox": {"image": "jarvis-sandbox:latest", "work_root": str(tmp_path)}},
        logger=_L(),
        event_logger=event_logger,
    )
    monkeypatch.setattr(SandboxExecutionRunner, "is_available", lambda _self: True)

    class FakeBrokerServer:
        def __init__(self, *args, **kwargs):  # noqa: ANN001
            return None

        def start(self):  # noqa: D401
            return {"host": "127.0.0.1", "port": 8123, "token": "tok"}

        def stop(self) -> None:
            return None

    monkeypatch.setattr("jarvis.core.execution.sandbox_runner.BrokerServer", FakeBrokerServer)

    cmds: list[list[str]] = []

    def fake_run(cmd, *args, **kwargs):  # noqa: ANN001
        if cmd[:2] == ["docker", "rm"]:
            return subprocess.CompletedProcess(cmd, 0, "", "")
        cmds.append(cmd)
        raise subprocess.TimeoutExpired(cmd, timeout=1)

    monkeypatch.setattr("jarvis.core.execution.sandbox_runner.subprocess.run", fake_run)

    plan = ExecutionPlan(
        backend=ExecutionBackend.sandbox,
        mode="sandbox",
        reason="plan",
        fallback_used=False,
        tool_calls=[ToolCall(tool_name="core.echo", tool_args={"msg": "hello"})],
    )
    req = _make_request(trace_id="t-net-plan", execution_plan=plan)
    res = runner.run(request=req, plan=plan)
    assert res.ok is False
    assert cmds
    idx = cmds[0].index("--network")
    assert cmds[0][idx + 1] != "none"
    assert res.warning is not None
    assert res.warning.get("reason_code") == "BROKER_REQUIRED"
    assert res.warning.get("network_mode")
    assert any(
        e.get("event") == "sandbox.network_exception"
        and e.get("trace_id") == "t-net-plan"
        and e.get("details", {}).get("reason_code") == "BROKER_REQUIRED"
        and e.get("details", {}).get("network_mode")
        for e in event_logger.events
    )


def test_plan_missing_broker_token_fails_closed(monkeypatch, tmp_path):
    runner = SandboxExecutionRunner(config={"sandbox": {"image": "jarvis-sandbox:latest", "work_root": str(tmp_path)}}, logger=_L())
    monkeypatch.setattr(SandboxExecutionRunner, "is_available", lambda _self: True)

    class FakeBrokerServer:
        def __init__(self, *args, **kwargs):  # noqa: ANN001
            return None

        def start(self):  # noqa: D401
            return {"host": "127.0.0.1", "port": 8123, "token": ""}

        def stop(self) -> None:
            return None

    monkeypatch.setattr("jarvis.core.execution.sandbox_runner.BrokerServer", FakeBrokerServer)

    called = {"docker": False}

    def fake_run(cmd, *args, **kwargs):  # noqa: ANN001
        called["docker"] = True
        raise AssertionError("docker should not be invoked when broker is unavailable")

    monkeypatch.setattr("jarvis.core.execution.sandbox_runner.subprocess.run", fake_run)

    plan = ExecutionPlan(
        backend=ExecutionBackend.sandbox,
        mode="sandbox",
        reason="plan",
        fallback_used=False,
        tool_calls=[ToolCall(tool_name="core.echo", tool_args={"msg": "hello"})],
    )
    req = _make_request(trace_id="t-net-fail", execution_plan=plan)
    res = runner.run(request=req, plan=plan)
    assert res.ok is False
    assert res.error == "broker_unavailable"
    assert called["docker"] is False
