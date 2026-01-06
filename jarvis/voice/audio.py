from __future__ import annotations

import os
import time
import wave
from dataclasses import dataclass
from typing import Any, List, Optional

from jarvis.voice.errors import AudioError, DependencyMissing


def _is_windows() -> bool:
    return os.name == "nt"


def _try_beep(freq: int = 880, ms: int = 120) -> None:
    if not _is_windows():
        return
    try:
        import winsound  # type: ignore

        winsound.Beep(freq, ms)
    except Exception:
        return


def ensure_audio_retention(dir_path: str, keep_last_n: int) -> None:
    try:
        os.makedirs(dir_path, exist_ok=True)
        files = [
            os.path.join(dir_path, f)
            for f in os.listdir(dir_path)
            if f.lower().endswith(".wav") and os.path.isfile(os.path.join(dir_path, f))
        ]
        files.sort(key=lambda p: os.path.getmtime(p), reverse=True)
        for p in files[keep_last_n:]:
            try:
                os.remove(p)
            except OSError:
                pass
    except Exception:
        return


def list_microphones() -> List[dict]:
    try:
        import sounddevice as sd  # type: ignore
    except Exception as e:
        raise DependencyMissing(f"sounddevice not available: {e}") from e

    devices = sd.query_devices()
    out: List[dict] = []
    for idx, d in enumerate(devices):
        if int(d.get("max_input_channels", 0)) <= 0:
            continue
        out.append({"index": idx, "name": d.get("name"), "hostapi": d.get("hostapi"), "max_input_channels": d.get("max_input_channels")})
    return out


@dataclass
class AudioRecorder:
    sample_rate: int = 16000
    device_index: Optional[int] = None
    audio_dir: str = os.path.join("logs", "audio")
    keep_last_n: int = 25

    def beep(self) -> None:
        _try_beep()

    def record_wav(self, trace_id: str, seconds: float, *, sensitive: bool = False) -> str:
        """
        Records mono 16-bit PCM WAV at sample_rate.
        Stores as logs/audio/<trace_id>_<ts>.wav unless sensitive=True (temp file that is deleted by caller).
        """
        try:
            import numpy as np  # type: ignore
            import sounddevice as sd  # type: ignore
        except Exception as e:
            raise DependencyMissing(f"audio dependencies missing: {e}") from e

        if seconds <= 0:
            raise AudioError("seconds must be > 0")

        if sensitive:
            out_path = os.path.join(self.audio_dir, f"{trace_id}_sensitive_{int(time.time())}.wav")
        else:
            out_path = os.path.join(self.audio_dir, f"{trace_id}_{int(time.time())}.wav")

        os.makedirs(self.audio_dir, exist_ok=True)
        ensure_audio_retention(self.audio_dir, self.keep_last_n)

        frames: list[np.ndarray] = []
        start = time.time()

        def callback(indata, _frames, _time_info, status):  # noqa: ANN001
            if status:
                # Non-fatal; capture continues.
                pass
            frames.append(indata.copy())
            if (time.time() - start) >= seconds:
                raise sd.CallbackStop()  # type: ignore[attr-defined]

        try:
            with sd.InputStream(
                samplerate=self.sample_rate,
                channels=1,
                dtype="int16",
                device=self.device_index,
                callback=callback,
            ):
                # Wait slightly longer than target duration.
                sd.sleep(int(seconds * 1000) + 250)
        except Exception as e:
            raise AudioError(f"recording failed: {e}") from e

        if not frames:
            raise AudioError("no audio captured")

        audio = np.concatenate(frames, axis=0).astype("int16")

        try:
            with wave.open(out_path, "wb") as wf:
                wf.setnchannels(1)
                wf.setsampwidth(2)
                wf.setframerate(self.sample_rate)
                wf.writeframes(audio.tobytes())
        except Exception as e:
            raise AudioError(f"failed to write wav: {e}") from e

        return out_path

