"""
Core internal event bus + legacy event logger.

This package intentionally keeps backwards-compatible exports:
- `EventLogger`, `redact` (previously `jarvis.core.events` module)
"""

from jarvis.core.events.legacy import EventLogger, redact
from jarvis.core.events.models import BaseEvent, EventSeverity, SourceSubsystem
from jarvis.core.events.bus import EventBus, OverflowPolicy, EventBusConfig

__all__ = [
    "EventLogger",
    "redact",
    "BaseEvent",
    "EventSeverity",
    "SourceSubsystem",
    "EventBus",
    "OverflowPolicy",
    "EventBusConfig",
]

