from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional


@dataclass
class BackendHealth:
    ok: bool
    detail: str = ""


@dataclass
class ImageResult:
    """Result of an image generation request.

    NEVER stores prompt text — only safe metadata.
    """

    output_path: str
    preset: str = "default"
    seed: Optional[int] = None
    width: int = 0
    height: int = 0
    steps: int = 0
    workflow_hash: str = ""
    engine_version: str = ""


class ImageBackend:
    """
    Image generation backend interface.

    Readiness semantics mirror the LLM backend layer:
    - ensure_ready()  -> validate backend availability
    - is_ready()      -> non-blocking readiness probe
    - release()       -> release any held resources
    - health()        -> detailed health check
    - generate()      -> submit a generation job and return the result
    """

    name: str = "base"

    def health(self) -> BackendHealth:
        """Return detailed health information."""
        ...

    def ensure_ready(self) -> None:
        """Validate backend availability (e.g. HTTP reachable)."""
        ...

    def is_ready(self) -> bool:
        """Non-blocking readiness check."""
        return self.health().ok

    def release(self) -> None:
        """Release resources."""
        ...

    def generate(
        self,
        *,
        prompt: str,
        preset: str,
        width: int,
        height: int,
        steps: int,
        seed: Optional[int] = None,
        negative_prompt: Optional[str] = None,
        trace_id: str,
        timeout_seconds: float,
    ) -> ImageResult:
        """Generate an image and save it to disk.  Returns ImageResult with output_path."""
        ...
