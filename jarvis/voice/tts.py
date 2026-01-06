from __future__ import annotations

import os
import queue
import threading
from dataclasses import dataclass
from typing import Optional

from jarvis.voice.errors import DependencyMissing, TTSError


def _is_windows() -> bool:
    return os.name == "nt"


class TTSEngine:
    name: str

    def is_available(self) -> bool: ...
    def status(self) -> str: ...
    def speak(self, text: str) -> None: ...


@dataclass
class SapiTTSEngine(TTSEngine):
    name: str = "sapi"
    dry_run: bool = False

    def __post_init__(self) -> None:
        self._voice = None

    def is_available(self) -> bool:
        return _is_windows()

    def status(self) -> str:
        return f"tts=sapi available={self.is_available()} dry_run={self.dry_run}"

    def _get_voice(self):
        if self.dry_run:
            return None
        if self._voice is not None:
            return self._voice
        if not _is_windows():
            raise DependencyMissing("SAPI TTS requires Windows.")
        try:
            import win32com.client  # type: ignore
        except Exception as e:
            raise DependencyMissing(f"pywin32 not available: {e}") from e
        self._voice = win32com.client.Dispatch("SAPI.SpVoice")
        return self._voice

    def speak(self, text: str) -> None:
        if not text:
            return
        if self.dry_run:
            return
        try:
            v = self._get_voice()
            assert v is not None
            # Speak is synchronous by default.
            v.Speak(text)
        except Exception as e:
            raise TTSError(f"SAPI TTS failed: {e}") from e


@dataclass
class Pyttsx3TTSEngine(TTSEngine):
    name: str = "pyttsx3"
    dry_run: bool = False

    def __post_init__(self) -> None:
        self._engine = None

    def is_available(self) -> bool:
        try:
            import pyttsx3  # type: ignore  # noqa: F401

            return True
        except Exception:
            return False

    def status(self) -> str:
        return f"tts=pyttsx3 available={self.is_available()} dry_run={self.dry_run}"

    def _get_engine(self):
        if self.dry_run:
            return None
        if self._engine is not None:
            return self._engine
        try:
            import pyttsx3  # type: ignore
        except Exception as e:
            raise DependencyMissing(f"pyttsx3 not available: {e}") from e
        self._engine = pyttsx3.init()
        return self._engine

    def speak(self, text: str) -> None:
        if not text:
            return
        if self.dry_run:
            return
        try:
            eng = self._get_engine()
            assert eng is not None
            eng.say(text)
            eng.runAndWait()
        except Exception as e:
            raise TTSError(f"pyttsx3 TTS failed: {e}") from e


class TTSWorker:
    """
    Dedicated playback thread. speak_blocking() enqueues a job and waits for completion.
    """

    def __init__(self, primary: TTSEngine, fallback: Optional[TTSEngine], logger, event_logger):
        self.primary = primary
        self.fallback = fallback
        self.logger = logger
        self.event_logger = event_logger
        self._q: queue.Queue = queue.Queue()
        self._stop = threading.Event()
        self._t = threading.Thread(target=self._run, name="tts", daemon=True)
        self._t.start()

    def stop(self) -> None:
        self._stop.set()
        self._q.put(None)
        self._t.join(timeout=2.0)

    def speak_blocking(self, trace_id: str, text: str) -> None:
        done = threading.Event()
        self._q.put((trace_id, text, done))
        done.wait(timeout=30.0)

    def _run(self) -> None:
        while not self._stop.is_set():
            item = self._q.get()
            if item is None:
                return
            trace_id, text, done = item
            try:
                self.event_logger.log(trace_id, "voice.tts.start", {"backend": getattr(self.primary, "name", "primary")})
                try:
                    self.primary.speak(text)
                    self.event_logger.log(trace_id, "voice.tts.ok", {"backend": getattr(self.primary, "name", "primary")})
                except Exception as e:
                    self.event_logger.log(trace_id, "voice.tts.fail", {"backend": getattr(self.primary, "name", "primary"), "error": str(e)})
                    if self.fallback is None:
                        raise
                    self.fallback.speak(text)
                    self.event_logger.log(trace_id, "voice.tts.ok", {"backend": getattr(self.fallback, "name", "fallback")})
            except Exception as e:
                self.logger.error(f"[{trace_id}] TTS error: {e}")
            finally:
                done.set()

