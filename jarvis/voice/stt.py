from __future__ import annotations

import os
import wave
from dataclasses import dataclass
from typing import Optional

from jarvis.voice.errors import DependencyMissing, ModelNotConfigured, STTError


class STTEngine:
    name: str

    def is_available(self) -> bool: ...
    def status(self) -> str: ...
    def transcribe(self, wav_path: str) -> str: ...


@dataclass
class VoskSTT(STTEngine):
    model_path: str
    name: str = "vosk"

    def __post_init__(self) -> None:
        self._model = None

    def is_available(self) -> bool:
        return bool(self.model_path) and os.path.isdir(self.model_path)

    def status(self) -> str:
        return f"stt=vosk configured={self.is_available()}"

    def _get_model(self):
        if self._model is not None:
            return self._model
        try:
            from vosk import Model  # type: ignore
        except Exception as e:
            raise DependencyMissing(f"vosk not available: {e}") from e
        if not self.is_available():
            raise ModelNotConfigured("Vosk model path not configured.")
        self._model = Model(self.model_path)
        return self._model

    def transcribe(self, wav_path: str) -> str:
        try:
            from vosk import KaldiRecognizer  # type: ignore
        except Exception as e:
            raise DependencyMissing(f"vosk not available: {e}") from e

        model = self._get_model()
        try:
            with wave.open(wav_path, "rb") as wf:
                if wf.getnchannels() != 1 or wf.getframerate() != 16000:
                    # We only record 16k mono; if something else, fail clearly.
                    raise STTError("WAV must be 16kHz mono for Vosk.")
                rec = KaldiRecognizer(model, wf.getframerate())
                rec.SetWords(False)
                while True:
                    data = wf.readframes(4000)
                    if len(data) == 0:
                        break
                    rec.AcceptWaveform(data)
                res = rec.FinalResult()
            # Vosk returns JSON string like {"text":"..."}
            import json

            obj = json.loads(res)
            return (obj.get("text") or "").strip()
        except Exception as e:
            raise STTError(f"vosk transcription failed: {e}") from e


@dataclass
class FasterWhisperSTT(STTEngine):
    model_path: str
    name: str = "faster_whisper"
    device_preference: str = "auto"  # "auto"|"cpu"|"cuda"

    def __post_init__(self) -> None:
        self._model = None

    def is_available(self) -> bool:
        return bool(self.model_path) and (os.path.isdir(self.model_path) or os.path.isfile(self.model_path))

    def status(self) -> str:
        return f"stt=faster_whisper configured={self.is_available()} device={self.device_preference}"

    def _get_model(self):
        if self._model is not None:
            return self._model
        try:
            from faster_whisper import WhisperModel  # type: ignore
        except Exception as e:
            raise DependencyMissing(f"faster-whisper not available: {e}") from e
        if not self.is_available():
            raise ModelNotConfigured("faster-whisper model path not configured.")
        # Do not download: require local path.
        device = "cpu"
        if self.device_preference == "cuda":
            device = "cuda"
        elif self.device_preference == "auto":
            # Try CUDA if available, but never crash if not.
            try:
                device = "cuda"
                self._model = WhisperModel(self.model_path, device=device, compute_type="float16")
                return self._model
            except Exception:
                device = "cpu"
        self._model = WhisperModel(self.model_path, device=device, compute_type="int8")
        return self._model

    def transcribe(self, wav_path: str) -> str:
        model = self._get_model()
        try:
            segments, info = model.transcribe(wav_path, beam_size=1, vad_filter=True)
            text = "".join(seg.text for seg in segments).strip()
            return text
        except Exception as e:
            raise STTError(f"faster-whisper transcription failed: {e}") from e

