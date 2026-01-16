from __future__ import annotations

import contextlib
import contextvars
import uuid
from typing import Iterator, Optional

_TRACE_ID: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar("jarvis.trace_id", default=None)


def new_trace_id() -> str:
    return uuid.uuid4().hex


def current_trace_id(default: Optional[str] = None) -> Optional[str]:
    trace_id = _TRACE_ID.get()
    return trace_id if trace_id else default


def set_trace_id(trace_id: Optional[str]) -> contextvars.Token:
    return _TRACE_ID.set(str(trace_id) if trace_id else None)


def reset_trace_id(token: contextvars.Token) -> None:
    try:
        _TRACE_ID.reset(token)
    except Exception:
        pass


def resolve_trace_id(trace_id: Optional[str] = None) -> str:
    if trace_id:
        return str(trace_id)
    existing = current_trace_id()
    if existing:
        return existing
    return new_trace_id()


@contextlib.contextmanager
def trace_context(trace_id: Optional[str]) -> Iterator[Optional[str]]:
    if not trace_id:
        yield current_trace_id()
        return
    token = set_trace_id(trace_id)
    try:
        yield str(trace_id)
    finally:
        reset_trace_id(token)
