from __future__ import annotations

import shutil
import subprocess

import pytest

from jarvis.core.capabilities.audit import CapabilityAuditLogger
from jarvis.core.capabilities.engine import CapabilityEngine
from jarvis.core.capabilities.loader import default_config_dict, validate_and_normalize
from jarvis.core.events import EventLogger
from jarvis.core.execution.models import ExecutionBackend, ExecutionPlan, ExecutionRequest, ToolCall
from jarvis.core.execution.sandbox_runner import SandboxExecutionRunner
from jarvis.core.policy.engine import PolicyEngine
from jarvis.core.policy.models import PolicyConfigFile


def _docker_image_available(image: str) -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        res = subprocess.run(["docker", "image", "inspect", image], capture_output=True, text=True, timeout=4)
        return res.returncode == 0
    except Exception:
        return False


def _make_capability_engine(tmp_path) -> CapabilityEngine:
    raw = default_config_dict()
    raw["intent_requirements"]["system.tool.call"] = []
    cfg = validate_and_normalize(raw)
    return CapabilityEngine(cfg=cfg, audit=CapabilityAuditLogger(path=str(tmp_path / "security.jsonl")), logger=None)


@pytest.mark.skipif(not _docker_image_available("jarvis-sandbox:latest"), reason="sandbox image not available")
def test_sandbox_plan_integration_echo(tmp_path):
    cap_engine = _make_capability_engine(tmp_path)
    policy_engine = PolicyEngine(cfg=PolicyConfigFile())
    runner = SandboxExecutionRunner(
        config={"sandbox": {"image": "jarvis-sandbox:latest", "work_root": str(tmp_path)}},
        capability_engine=cap_engine,
        policy_engine=policy_engine,
        event_logger=EventLogger(str(tmp_path / "events.jsonl")),
        logger=None,
    )
    plan = ExecutionPlan(
        backend=ExecutionBackend.sandbox,
        mode="sandbox",
        reason="plan",
        fallback_used=False,
        tool_calls=[ToolCall(tool_name="core.echo", tool_args={"msg": "hello"})],
    )
    req = ExecutionRequest(
        trace_id="t-plan-1",
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
        execution_plan=plan,
    )
    res = runner.run(request=req, plan=plan)
    assert res.ok is True
    assert isinstance(res.output, dict)
    assert res.output.get("tool_results")
    assert res.output["tool_results"][0]["tool_name"] == "core.echo"


@pytest.mark.skipif(not _docker_image_available("jarvis-sandbox:latest"), reason="sandbox image not available")
def test_sandbox_plan_integration_unknown_tool_denied(tmp_path):
    cap_engine = _make_capability_engine(tmp_path)
    policy_engine = PolicyEngine(cfg=PolicyConfigFile())
    runner = SandboxExecutionRunner(
        config={"sandbox": {"image": "jarvis-sandbox:latest", "work_root": str(tmp_path)}},
        capability_engine=cap_engine,
        policy_engine=policy_engine,
        event_logger=EventLogger(str(tmp_path / "events.jsonl")),
        logger=None,
    )
    plan = ExecutionPlan(
        backend=ExecutionBackend.sandbox,
        mode="sandbox",
        reason="plan",
        fallback_used=False,
        tool_calls=[ToolCall(tool_name="unknown.tool", tool_args={"msg": "nope"})],
    )
    req = ExecutionRequest(
        trace_id="t-plan-2",
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
        execution_plan=plan,
    )
    res = runner.run(request=req, plan=plan)
    assert res.ok is False
    assert "TOOL_UNKNOWN" in (res.error or "")
