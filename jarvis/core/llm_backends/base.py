from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict


@dataclass
class BackendHealth:
    ok: bool
    detail: str = ""


class LLMBackend:
    """
    Backend interface.  Must be safe, non-interactive, and backend-neutral.

    Readiness semantics (no "server" assumptions):
    - ensure_ready()  -> prepare the backend (load model / validate HTTP)
    - is_ready()      -> non-blocking readiness probe
    - release()       -> unload / free resources
    - health()        -> detailed health probe
    - chat()          -> perform an LLM request
    """

    name: str = "base"

    def health(self) -> BackendHealth:
        """Return detailed health information."""
        ...

    def chat(
        self,
        *,
        model: str,
        messages: list[dict],
        options: Dict[str, Any],
        timeout_seconds: float,
        trace_id: str = "",
    ) -> str:
        """Send a chat request and return the raw text response."""
        ...

    # ── neutral readiness API ──────────────────────────────────────
    def ensure_ready(self) -> None:
        """Prepare the backend (load model / verify connectivity)."""
        ...

    def is_ready(self) -> bool:
        """Non-blocking readiness check."""
        return self.health().ok

    def release(self) -> None:
        """Release resources (unload model / drop connections)."""
        ...

    # ── backward-compat shims (deprecated) ─────────────────────────
    def is_server_running(self) -> bool:
        """Deprecated: use is_ready()."""
        return self.is_ready()

    def start_server(self) -> bool:
        """Deprecated: use ensure_ready()."""
        try:
            self.ensure_ready()
            return self.is_ready()
        except Exception:
            return False

    def stop_server(self) -> bool:
        """Deprecated: use release()."""
        try:
            self.release()
            return True
        except Exception:
            return False
