from __future__ import annotations

import importlib
import os
import time
import traceback
from dataclasses import dataclass
from typing import Any, Callable, Dict


@dataclass
class WorkerContext:
    job_id: str
    trace_id: str
    emit: Callable[[str, Dict[str, Any]], None]

    def progress(self, pct: int, message: str = "") -> None:
        pct = max(0, min(100, int(pct)))
        self.emit("progress", {"progress": pct, "message": message})

    def log(self, message: str, **fields: Any) -> None:
        self.emit("log", {"message": str(message), **fields})


def _load_handler(handler_ref: str) -> Callable[[Dict[str, Any], WorkerContext], Dict[str, Any]]:
    # handler_ref must be "jarvis.something:func"
    if ":" not in handler_ref:
        raise ValueError("Invalid handler_ref.")
    mod_name, func_name = handler_ref.split(":", 1)
    if not mod_name.startswith("jarvis."):
        raise ValueError("Handler module must be under 'jarvis.'")
    if not func_name or func_name.startswith("_"):
        raise ValueError("Invalid handler function name.")
    mod = importlib.import_module(mod_name)
    fn = getattr(mod, func_name, None)
    if not callable(fn):
        raise ValueError("Handler is not callable.")
    return fn


def worker_main(job_id: str, trace_id: str, spec: Dict[str, Any], handler_ref: str, q) -> None:  # noqa: ANN001
    """
    Process entrypoint (spawn-safe).
    Emits events back to main via q:
      {"event_type": "...", "payload": {...}, "ts": <epoch>}
    """

    def emit(event_type: str, payload: Dict[str, Any]) -> None:
        q.put({"event_type": event_type, "payload": payload, "ts": time.time()})

    emit("started", {"pid": os.getpid()})

    try:
        handler = _load_handler(handler_ref)
        ctx = WorkerContext(job_id=job_id, trace_id=trace_id, emit=emit)
        args = spec.get("args") or {}
        result = handler(args=args, ctx=ctx)
        if result is not None and not isinstance(result, dict):
            raise TypeError("Job handler must return a dict (or None).")
        emit("finished", {"status": "SUCCEEDED", "result": result or {}})
    except Exception as e:  # noqa: BLE001
        include_tb = bool(spec.get("debug_tracebacks", False))
        tb = traceback.format_exc(limit=50) if include_tb else None
        emit(
            "error",
            {
                "type": e.__class__.__name__,
                "message": str(e),
                "traceback": tb,
            },
        )
        emit("finished", {"status": "FAILED", "result": {}})

