from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Callable, Optional

from jarvis.voice.errors import DependencyMissing


WakeCallback = Callable[[], None]


class WakeWordEngine:
    def start(self) -> None: ...
    def stop(self) -> None: ...
    def is_ready(self) -> bool: ...
    def status(self) -> str: ...


class NoWakeWordEngine(WakeWordEngine):
    def start(self) -> None:
        return

    def stop(self) -> None:
        return

    def is_ready(self) -> bool:
        return True

    def status(self) -> str:
        return "wake_word_engine=none"


@dataclass
class PorcupineWakeWordEngine(WakeWordEngine):
    access_key: str
    keyword: str
    on_wake: WakeCallback
    device_index: Optional[int] = None

    def __post_init__(self) -> None:
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._ready = False

    def is_ready(self) -> bool:
        return self._ready

    def status(self) -> str:
        return f"wake_word_engine=porcupine ready={self._ready}"

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="wakeword", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=2.0)

    def _run(self) -> None:
        try:
            import pvporcupine  # type: ignore
            from pvrecorder import PvRecorder  # type: ignore
        except Exception as e:
            self._ready = False
            raise DependencyMissing(f"porcupine dependencies missing: {e}") from e

        porcupine = None
        recorder = None
        try:
            porcupine = pvporcupine.create(access_key=self.access_key, keywords=[self.keyword])
            recorder = PvRecorder(device_index=self.device_index if self.device_index is not None else -1, frame_length=porcupine.frame_length)
            recorder.start()
            self._ready = True
            while not self._stop.is_set():
                pcm = recorder.read()
                res = porcupine.process(pcm)
                if res >= 0:
                    # Signal wake without blocking porcupine loop.
                    try:
                        self.on_wake()
                    except Exception:
                        pass
        finally:
            self._ready = False
            try:
                if recorder is not None:
                    recorder.stop()
                    recorder.delete()
            except Exception:
                pass
            try:
                if porcupine is not None:
                    porcupine.delete()
            except Exception:
                pass

