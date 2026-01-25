from __future__ import annotations

import contextvars
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Dict

from jarvis.core.execution.models import ExecutionBackend, ExecutionPlan, ExecutionRequest, ExecutionResult


class LocalExecutionRunner:
    def run(self, *, request: ExecutionRequest, plan: ExecutionPlan, dispatcher: Any) -> ExecutionResult:
        backend = plan.backend
        exec_context: Dict[str, Any] = dict(request.context or {})
        if request.tool_broker is not None and backend in {ExecutionBackend.inline, ExecutionBackend.local_thread}:
            exec_context.setdefault("tool_broker", request.tool_broker)
        try:
            if backend == ExecutionBackend.inline:
                out = dispatcher.execute_loaded_module(
                    request.loaded_module,
                    intent_id=request.intent_id,
                    args=request.args,
                    context=exec_context,
                    persist_allowed=request.persist_allowed,
                    internal_call=True,
                )
                return ExecutionResult(ok=True, backend=backend, exec_mode=plan.mode, trace_id=request.trace_id, output=out)

            if backend == ExecutionBackend.local_thread:
                with ThreadPoolExecutor(max_workers=1) as ex:
                    cv = contextvars.copy_context()

                    def _run():  # noqa: ANN001
                        return dispatcher.execute_loaded_module(
                            request.loaded_module,
                            intent_id=request.intent_id,
                            args=request.args,
                            context=exec_context,
                            persist_allowed=request.persist_allowed,
                            internal_call=True,
                        )

                    fut = ex.submit(cv.run, _run)
                    out = fut.result(timeout=30.0)
                return ExecutionResult(ok=True, backend=backend, exec_mode=plan.mode, trace_id=request.trace_id, output=out)

            if backend == ExecutionBackend.local_process:
                ctx = dict(exec_context or {})
                ctx["_dispatcher_execute"] = True
                out = dispatcher._run_in_subprocess(  # noqa: SLF001
                    request.module_path,
                    request.intent_id,
                    request.args or {},
                    ctx,
                    internal_call=True,
                )
                return ExecutionResult(ok=True, backend=backend, exec_mode=plan.mode, trace_id=request.trace_id, output=out)

            return ExecutionResult(ok=False, backend=backend, exec_mode=plan.mode, trace_id=request.trace_id, error="sandbox_backend_unavailable")
        except Exception as e:  # noqa: BLE001
            return ExecutionResult(ok=False, backend=backend, exec_mode=plan.mode, trace_id=request.trace_id, error=str(e)[:300])
