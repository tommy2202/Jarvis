from __future__ import annotations

from typing import Iterable, Set

from jarvis.core.execution.models import ExecutionBackend, ExecutionPlan, ExecutionRequest


RISKY_CAPS: Set[str] = {
    "CAP_RUN_SUBPROCESS",
    "CAP_NETWORK_ACCESS",
    "CAP_HEAVY_COMPUTE",
    "CAP_IMAGE_GENERATION",
    "CAP_CODE_GENERATION",
}


def _normalize_backend(value: object) -> ExecutionBackend:
    if isinstance(value, ExecutionBackend):
        return value
    v = str(value or "").strip().lower()
    if v in {"inline"}:
        return ExecutionBackend.inline
    if v in {"local_thread", "thread"}:
        return ExecutionBackend.local_thread
    if v in {"local_process", "process", "local"}:
        return ExecutionBackend.local_process
    if v in {"sandbox", "sandboxed"}:
        return ExecutionBackend.sandbox
    return ExecutionBackend.local_process


def _inline_allowlist(values: Iterable[str]) -> Set[str]:
    return {str(v).strip() for v in values if str(v or "").strip()}


def select_backend(request: ExecutionRequest) -> ExecutionPlan:
    required = set([str(c) for c in (request.required_capabilities or []) if str(c or "").strip()])
    allow_inline = _inline_allowlist(request.allow_inline_intents or [])
    requested_mode = str(request.execution_mode or "process").strip().lower()
    if requested_mode not in {"inline", "thread", "process"}:
        requested_mode = "process"

    reason = "default_backend"
    fallback_used = False

    if required & RISKY_CAPS:
        backend = ExecutionBackend.sandbox
        reason = "risky_capability"
    elif requested_mode == "inline" and request.is_core and request.intent_id in allow_inline:
        backend = ExecutionBackend.inline
        reason = "allowlisted_inline"
    else:
        backend = _normalize_backend(request.default_backend)

    if backend in {ExecutionBackend.local_process, ExecutionBackend.local_thread}:
        if requested_mode == "thread":
            backend = ExecutionBackend.local_thread
        else:
            backend = ExecutionBackend.local_process

    if backend == ExecutionBackend.sandbox and not request.sandbox_available:
        if request.sandbox_require_available:
            reason = "sandbox_unavailable"
        else:
            backend = _normalize_backend(request.fallback_backend)
            if backend in {ExecutionBackend.local_process, ExecutionBackend.local_thread}:
                if requested_mode == "thread":
                    backend = ExecutionBackend.local_thread
                else:
                    backend = ExecutionBackend.local_process
            reason = "sandbox_unavailable_fallback"
            fallback_used = True

    mode = "sandbox"
    if backend == ExecutionBackend.inline:
        mode = "inline"
    elif backend == ExecutionBackend.local_thread:
        mode = "thread"
    elif backend == ExecutionBackend.local_process:
        mode = "process"

    return ExecutionPlan(backend=backend, mode=mode, reason=reason, fallback_used=fallback_used)
