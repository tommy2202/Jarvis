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
    base_url: str
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

    def is_server_running(self) -> bool:
        return self.health().ok

    def start_server(self) -> bool:
        # Best-effort; safest behavior is to not hang and not kill user processes.
        if self.is_server_running():
            return True
        if not self.managed:
            return False
        exe = shutil.which("ollama")
        if not exe:
            return False
        try:
            # On Windows: 'ollama serve' typically starts a background service.
            # On Linux/macOS: it runs in foreground. We keep the process handle only if started here.
            self._proc = subprocess.Popen([exe, "serve"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)  # noqa: S603,S607
        except Exception:
            self._proc = None
            return False
        # Wait briefly for server to come up.
        for _ in range(10):
            if self.is_server_running():
                return True
            time.sleep(0.2)
        return False

    def stop_server(self) -> bool:
        if self._proc is None:
            return False
        try:
            self._proc.terminate()
            self._proc.wait(timeout=2.0)
            return True
        except Exception:
            return False
        finally:
            self._proc = None

    def chat(self, *, model: str, messages: list[dict], options: Dict[str, Any], timeout_seconds: float) -> str:
        payload = {
            "model": model,
            "messages": messages,
            "stream": False,
            "options": options,
        }
        r = requests.post(self._url("/api/chat"), json=payload, timeout=timeout_seconds)
        r.raise_for_status()
        data = r.json()
        # Ollama chat response: {"message":{"role":"assistant","content":"..."}, ...}
        return str(((data.get("message") or {}).get("content")) or "")

