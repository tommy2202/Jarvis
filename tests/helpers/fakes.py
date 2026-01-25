from __future__ import annotations

import json
import time as _time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


class FakeClock:
    def __init__(self, start: float = 1_700_000_000.0):
        self._t = float(start)

    def time(self) -> float:
        return self._t

    def advance(self, seconds: float) -> None:
        self._t += float(seconds)


@dataclass
class FakeTTS:
    spoken: List[str] = field(default_factory=list)
    fail: bool = False

    def speak(self, trace_id: str, text: str) -> None:
        if self.fail:
            raise RuntimeError("tts failed")
        self.spoken.append(text)


@dataclass
class FakeVoice:
    wav_path: str = "x.wav"
    transcript: str = "hello"
    fail_capture: bool = False
    fail_transcribe: bool = False

    listen_seconds: float = 0.1

    def start(self, on_wake):  # noqa: ANN001
        self._on_wake = on_wake

    def stop(self) -> None:
        return

    def capture_audio(self, trace_id: str) -> str:
        if self.fail_capture:
            raise RuntimeError("capture failed")
        return self.wav_path

    def transcribe(self, wav_path: str) -> str:
        if self.fail_transcribe:
            raise RuntimeError("stt failed")
        return self.transcript


class FakeLLMBackend:
    """
    Implements the LLMLifecycleController backend interface used in tests.
    """

    def __init__(self):
        self.running = True
        self.calls = 0
        self.responses: List[str] = []
        self.raise_timeout = False
        self.raise_error = False

    name = "fake"

    def health(self):
        return type("H", (), {"ok": self.running, "detail": "ok" if self.running else "down"})()

    def is_server_running(self):
        return self.running

    def start_server(self):
        self.running = True
        return True

    def stop_server(self):
        self.running = False
        return True

    def chat(self, *, model: str, messages: list[dict], options: Dict[str, Any], timeout_seconds: float) -> str:
        import requests

        self.calls += 1
        if self.raise_timeout:
            raise requests.Timeout()
        if self.raise_error:
            raise RuntimeError("backend error")
        if self.responses:
            return self.responses.pop(0)
        return '{"reply":"ok"}'


class FakeJarvisApp:
    """
    Minimal JarvisApp shim for runtime tests: returns a deterministic reply.
    """

    def __init__(self, reply_prefix: str = "echo: "):
        self.reply_prefix = reply_prefix
        self.calls: List[str] = []

        class _SB:
            def warmup(self): ...
            def unload(self): ...

        self.stage_b = _SB()

    def process_message(self, message: str, client=None):  # noqa: ANN001
        self.calls.append(message)
        return type(
            "R",
            (),
            {
                "trace_id": "x",
                "reply": f"{self.reply_prefix}{message}",
                "intent_id": "system.echo",
                "intent_source": "stage_a",
                "confidence": 1.0,
                "requires_followup": False,
                "followup_question": None,
            },
        )()


class FakeDispatcher:
    """
    Minimal dispatcher shim for startup checks.
    """

    def __init__(self, *, capability_engine=None, policy_engine=None, privacy_store=None):
        from jarvis.core.privacy.gates import PrivacyGate

        self.capability_engine = capability_engine
        self.policy_engine = policy_engine
        self._privacy_gate = PrivacyGate(privacy_store=privacy_store) if privacy_store is not None else None

    def execute_loaded_module(self, _loaded, *, intent_id, args, context, persist_allowed):  # noqa: ANN001
        from jarvis.core.privacy.gates import persistence_context

        with persistence_context(persist_allowed=bool(persist_allowed)):
            return {}

