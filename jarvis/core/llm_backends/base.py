from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional


@dataclass
class BackendHealth:
    ok: bool
    detail: str = ""


class LLMBackend:
    """
    Backend interface. Must be safe and non-interactive.
    """

    name: str

    def health(self) -> BackendHealth: ...

    def chat(self, *, model: str, messages: list[dict], options: Dict[str, Any], timeout_seconds: float) -> str: ...

    def is_server_running(self) -> bool: ...

    def start_server(self) -> bool: ...

    def stop_server(self) -> bool: ...

