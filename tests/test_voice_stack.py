from __future__ import annotations

import math
import os
import wave

import pytest

from jarvis.voice.stt import FasterWhisperSTT, VoskSTT
from jarvis.voice.tts import Pyttsx3TTSEngine, SapiTTSEngine
from jarvis.voice.state_machine import VoiceConfig, VoiceController, VoiceState


def _gen_sine_wav(path: str, seconds: float = 0.5, sr: int = 16000) -> None:
    n = int(seconds * sr)
    amp = 2000
    with wave.open(path, "wb") as wf:
        wf.setnchannels(1)
        wf.setsampwidth(2)
        wf.setframerate(sr)
        for i in range(n):
            v = int(amp * math.sin(2 * math.pi * 440.0 * (i / sr)))
            wf.writeframesraw(int(v).to_bytes(2, byteorder="little", signed=True))


def test_stt_adapters_skip_gracefully_without_models(tmp_path):
    wav_path = str(tmp_path / "tone.wav")
    _gen_sine_wav(wav_path)

    vosk = VoskSTT(model_path="")
    fw = FasterWhisperSTT(model_path="")
    assert vosk.is_available() is False
    assert fw.is_available() is False

    # Transcribe should raise ModelNotConfigured; we only assert "doesn't crash process".
    with pytest.raises(Exception):
        _ = vosk.transcribe(wav_path)
    with pytest.raises(Exception):
        _ = fw.transcribe(wav_path)


def test_tts_engines_dry_run_init():
    sapi = SapiTTSEngine(dry_run=True)
    pytt = Pyttsx3TTSEngine(dry_run=True)
    # Dry run should not throw and should "speak" no-op.
    sapi.speak("hello")
    pytt.speak("hello")


def test_state_machine_timeout_transitions(tmp_path):
    # This test avoids microphone + STT by using a controller with voice disabled.
    # We only verify state container behavior (no thread start).
    cfg = VoiceConfig(
        enabled=False,
        wake_word_engine="none",
        wake_word="jarvis",
        mic_device_index=None,
        stt_backend_primary="vosk",
        stt_backend_fallback="faster_whisper",
        tts_backend_primary="pyttsx3",
        tts_backend_fallback="pyttsx3",
        listen_seconds=0.1,
        sample_rate=16000,
        idle_sleep_seconds=0.1,
        confirm_beep=False,
        audio_retention_files=1,
        allow_voice_admin_unlock=False,
        thinking_timeout_seconds=0.1,
    )

    class DummyStore:
        def secure_get(self, _k): return None

    class DummyJarvis:
        class DummyStageB:
            def warmup(self): ...
            def unload(self): ...

        stage_b = DummyStageB()

        def process_message(self, *_a, **_k):
            return type("R", (), {"reply": "ok"})()

    class DummySecurity:
        def verify_and_unlock_admin(self, _p): return False

    class DummyLogger:
        def info(self, *_a, **_k): ...
        def warning(self, *_a, **_k): ...
        def error(self, *_a, **_k): ...

    class DummyEvent:
        def log(self, *_a, **_k): ...

    vc = VoiceController(
        cfg=cfg,
        models_cfg={"vosk_model_path": "", "faster_whisper_model_path": ""},
        secure_store=DummyStore(),
        jarvis_app=DummyJarvis(),
        security_manager=DummySecurity(),
        logger=DummyLogger(),
        event_logger=DummyEvent(),
    )
    assert vc.get_state() == VoiceState.SLEEPING.value

