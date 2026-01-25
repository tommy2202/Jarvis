from __future__ import annotations

from jarvis.core.execution.models import ExecutionBackend, ExecutionRequest
from jarvis.core.execution.router import select_backend


def _base_request(**overrides):
    req = ExecutionRequest(
        trace_id="t1",
        intent_id="core.time.now",
        module_id="core",
        args={},
        context={},
        required_capabilities=[],
        execution_mode="inline",
        is_core=True,
        allow_inline_intents=["core.time.now"],
        default_backend=ExecutionBackend.local_process,
        fallback_backend=ExecutionBackend.local_process,
        sandbox_require_available=True,
        sandbox_available=True,
    )
    return req.model_copy(update=overrides)


def test_risky_caps_selects_sandbox():
    req = _base_request(
        intent_id="demo.run",
        module_id="demo",
        execution_mode="process",
        is_core=False,
        required_capabilities=["CAP_RUN_SUBPROCESS"],
        allow_inline_intents=[],
        default_backend=ExecutionBackend.local_process,
    )
    plan = select_backend(req)
    assert plan.backend == ExecutionBackend.sandbox


def test_allowlisted_core_intent_selects_inline():
    req = _base_request(
        intent_id="core.time.now",
        module_id="core",
        execution_mode="inline",
        is_core=True,
        required_capabilities=[],
        allow_inline_intents=["core.time.now"],
        default_backend=ExecutionBackend.sandbox,
    )
    plan = select_backend(req)
    assert plan.backend == ExecutionBackend.inline
