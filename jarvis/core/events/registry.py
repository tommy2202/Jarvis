from __future__ import annotations


CORE_EVENT_TYPES: set[str] = {
    "state.transition",
    "state.timeout",
    "intent.routed",
    "intent.denied",
    "capability.decision",
    "job.created",
    "job.started",
    "job.progress",
    "job.completed",
    "job.failed",
    "llm.loaded",
    "llm.unloaded",
    "llm.error",
    "error.raised",
    "recovery.action",
    "shutdown.begin",
    "shutdown.phase",
    "shutdown.complete",
    "telemetry.health_change",
}


def is_core_event_type(event_type: str) -> bool:
    return str(event_type) in CORE_EVENT_TYPES

