from __future__ import annotations

import os
import shutil
import subprocess
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional

import requests

from jarvis.core.llm_backends.base import BackendHealth, LLMBackend


@dataclass
class OllamaBackend(LLMBackend):
    base_url: str = "http://127.0.0.1:11434"
    managed: bool = False
    _proc: Optional[subprocess.Popen] = None
    name: str = "ollama"

    def _url(self, path: str) -> str:
        return f"{self.base_url.rstrip('/')}{path}"

    def health(self) -> BackendHealth:
        try:
            r = requests.get(self._url("/api/tags"), timeout=2.0)
            if r.status_code == 200:
                return BackendHealth(ok=True, detail="ok")
            return BackendHealth(ok=False, detail=f"HTTP {r.status_code}")
        except Exception as e:  # noqa: BLE001
            return BackendHealth(ok=False, detail=str(e))

    # ── neutral readiness API ──────────────────────────────────────

    def ensure_ready(self) -> None:
        """Validate Ollama HTTP availability; optionally start in managed mode."""
        if self.health().ok:
            return
        if not self.managed:
            return
        exe = shutil.which("ollama")
        if not exe:
            return
        try:
            self._proc = subprocess.Popen(
                [exe, "serve"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )  # noqa: S603,S607
        except Exception:
            self._proc = None
            return
        for _ in range(10):
            if self.health().ok:
                return
            time.sleep(0.2)

    def is_ready(self) -> bool:
        return self.health().ok

    def release(self) -> None:
        """Terminate managed Ollama process if we started it."""
        if self._proc is None:
            return
        try:
            self._proc.terminate()
            self._proc.wait(timeout=2.0)
        except Exception:
            pass
        finally:
            self._proc = None

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
        payload = {
            "model": model,
            "messages": messages,
            "stream": False,
            "options": options,
        }
        r = requests.post(self._url("/api/chat"), json=payload, timeout=timeout_seconds)
        r.raise_for_status()
        data = r.json()
        return str(((data.get("message") or {}).get("content")) or "")

    # ── backward-compat shims (used by legacy code / tests) ───────

    def is_server_running(self) -> bool:
        return self.is_ready()

    def start_server(self) -> bool:
        self.ensure_ready()
        return self.is_ready()

    def stop_server(self) -> bool:
        self.release()
        return True
