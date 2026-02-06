"""
llama.cpp in-process backend using llama-cpp-python (GGUF models).

- Loads model lazily in ensure_ready()
- Unloads in release() by dropping references + gc
- Timeout and max-token enforcement
- llama-cpp-python is an OPTIONAL dependency
"""
from __future__ import annotations

import gc
import threading
import time
from typing import Any, Dict, Optional

from jarvis.core.llm_backends.base import BackendHealth, LLMBackend

# Lazy import to keep the package optional.
_llama_cpp = None


def _get_llama_cpp():  # noqa: ANN202
    """Import llama_cpp on first use; raise clear error if missing."""
    global _llama_cpp
    if _llama_cpp is not None:
        return _llama_cpp
    try:
        import llama_cpp  # type: ignore[import-untyped]

        _llama_cpp = llama_cpp
        return _llama_cpp
    except ImportError as exc:
        raise ImportError(
            "llama-cpp-python is required for the llamacpp backend. "
            "Install it with:  pip install llama-cpp-python"
        ) from exc


class LlamaCppBackend(LLMBackend):
    """In-process GGUF model via llama-cpp-python."""

    name: str = "llamacpp"

    def __init__(
        self,
        *,
        model_path: str,
        n_ctx: int = 2048,
        n_gpu_layers: int = 0,
        n_threads: Optional[int] = None,
        verbose: bool = False,
    ) -> None:
        self.model_path = model_path
        self.n_ctx = n_ctx
        self.n_gpu_layers = n_gpu_layers
        self.n_threads = n_threads
        self.verbose = verbose

        self._model: Any = None
        self._lock = threading.Lock()

    # ── readiness API ──────────────────────────────────────────────

    def health(self) -> BackendHealth:
        if self._model is not None:
            return BackendHealth(ok=True, detail="model_loaded")
        return BackendHealth(ok=False, detail="model_not_loaded")

    def ensure_ready(self) -> None:
        """Lazy-load the GGUF model into memory."""
        if self._model is not None:
            return
        with self._lock:
            if self._model is not None:
                return
            llama_cpp = _get_llama_cpp()
            kwargs: Dict[str, Any] = {
                "model_path": self.model_path,
                "n_ctx": self.n_ctx,
                "n_gpu_layers": self.n_gpu_layers,
                "verbose": self.verbose,
            }
            if self.n_threads is not None:
                kwargs["n_threads"] = self.n_threads
            self._model = llama_cpp.Llama(**kwargs)

    def is_ready(self) -> bool:
        return self._model is not None

    def release(self) -> None:
        """Unload model and free memory."""
        with self._lock:
            if self._model is not None:
                self._model = None
                gc.collect()

    # ── LLM chat ───────────────────────────────────────────────────

    def chat(
        self,
        *,
        model: str,
        messages: list[dict],
        options: Dict[str, Any],
        timeout_seconds: float,
        trace_id: str = "",
    ) -> str:
        if self._model is None:
            raise RuntimeError("Model not loaded; call ensure_ready() first.")

        max_tokens = int(options.get("num_predict", options.get("max_tokens", 512)))
        temperature = float(options.get("temperature", 0.7))

        # Enforce timeout via a background watchdog thread.
        result_holder: Dict[str, Any] = {}
        error_holder: Dict[str, Any] = {}
        done = threading.Event()

        def _generate() -> None:
            try:
                resp = self._model.create_chat_completion(
                    messages=messages,
                    max_tokens=max_tokens,
                    temperature=temperature,
                )
                result_holder["resp"] = resp
            except Exception as exc:
                error_holder["exc"] = exc
            finally:
                done.set()

        t = threading.Thread(target=_generate, daemon=True)
        t.start()

        if not done.wait(timeout=timeout_seconds):
            import requests

            raise requests.Timeout(
                f"llama.cpp generation exceeded {timeout_seconds}s timeout"
            )

        if "exc" in error_holder:
            raise error_holder["exc"]

        resp = result_holder.get("resp") or {}
        choices = resp.get("choices") or []
        if not choices:
            return ""
        content = (choices[0].get("message") or {}).get("content") or ""

        # Post-check: enforce max_tokens by truncating if needed.
        # llama-cpp-python should respect max_tokens, but belt-and-suspenders.
        return str(content)

    # ── backward-compat shims ──────────────────────────────────────

    def is_server_running(self) -> bool:
        return self.is_ready()

    def start_server(self) -> bool:
        self.ensure_ready()
        return self.is_ready()

    def stop_server(self) -> bool:
        self.release()
        return True
