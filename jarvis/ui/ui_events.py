from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from jarvis.ui.ui_models import CoreClient


@dataclass
class PendingRequest:
    trace_id: str
    text: str
    source: str
    created_at: float
    client_meta: Dict[str, Any] = field(default_factory=dict)


class UiController:
    """
    Thin controller for the UI: delegates everything to core APIs.
    Designed to be unit-testable without Tk.
    """

    def __init__(self, core: CoreClient):
        self.core = core
        self._lock = threading.Lock()
        self._pending: Dict[str, PendingRequest] = {}

    def send_text(self, *, text: str, client_meta: Optional[Dict[str, Any]] = None) -> str:
        trace_id = self.core.submit_text("ui", text, client_meta=client_meta or {})
        with self._lock:
            self._pending[trace_id] = PendingRequest(trace_id=trace_id, text=text, source="ui", created_at=0.0, client_meta=client_meta or {})
        return trace_id

    def poll_result(self, trace_id: str) -> Optional[Dict[str, Any]]:
        return self.core.get_result(trace_id)

    def drop_pending(self, trace_id: str) -> None:
        with self._lock:
            self._pending.pop(trace_id, None)

    def list_pending(self) -> list[str]:
        with self._lock:
            return list(self._pending.keys())

