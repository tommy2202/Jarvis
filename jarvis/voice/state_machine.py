from __future__ import annotations

import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, Optional

from jarvis.voice.audio import AudioRecorder
from jarvis.voice.errors import AudioError, DependencyMissing, ModelNotConfigured, STTError, TTSError, VoiceTimeout
from jarvis.voice.stt import FasterWhisperSTT, STTEngine, VoskSTT
from jarvis.voice.tts import Pyttsx3TTSEngine, SapiTTSEngine, TTSWorker, TTSEngine
from jarvis.voice.wakeword import NoWakeWordEngine, PorcupineWakeWordEngine, WakeWordEngine


class VoiceState(str, Enum):
    SLEEPING = "SLEEPING"
    WAKE_DETECTED = "WAKE_DETECTED"
    LISTENING = "LISTENING"
    TRANSCRIBING = "TRANSCRIBING"
    THINKING = "THINKING"
    SPEAKING = "SPEAKING"
    ERROR = "ERROR"


@dataclass
class VoiceConfig:
    enabled: bool
    wake_word_engine: str
    wake_word: str
    mic_device_index: Optional[int]
    stt_backend_primary: str
    stt_backend_fallback: str
    tts_backend_primary: str
    tts_backend_fallback: str
    listen_seconds: float
    sample_rate: int
    idle_sleep_seconds: float
    confirm_beep: bool
    audio_retention_files: int
    allow_voice_admin_unlock: bool
    thinking_timeout_seconds: float


class VoiceController:
    """
    Owns voice threads and is the integration point for app.py commands.
    """

    def __init__(self, cfg: VoiceConfig, models_cfg: Dict[str, Any], secure_store, jarvis_app, security_manager, logger, event_logger):
        self.cfg = cfg
        self.models_cfg = models_cfg
        self.secure_store = secure_store
        self.jarvis_app = jarvis_app
        self.security_manager = security_manager
        self.logger = logger
        self.event_logger = event_logger

        self._state = VoiceState.SLEEPING
        self._state_lock = threading.Lock()
        self._stop = threading.Event()
        self._wake_event = threading.Event()
        self._interaction_lock = threading.Lock()

        self._audio = AudioRecorder(
            sample_rate=int(cfg.sample_rate),
            device_index=cfg.mic_device_index,
            keep_last_n=int(cfg.audio_retention_files),
        )

        self._stt_primary, self._stt_fallback = self._build_stt()
        self._tts_worker = TTSWorker(primary=self._build_tts(cfg.tts_backend_primary), fallback=self._build_tts(cfg.tts_backend_fallback), logger=logger, event_logger=event_logger)

        self._wake_engine = self._build_wake_engine()
        self._thread = threading.Thread(target=self._run, name="voice-main", daemon=True)
        self._executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="voice-worker")

        self._last_interaction = 0.0

    def start(self) -> None:
        if self._thread.is_alive():
            return
        self._stop.clear()
        self._wake_engine.start()
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._wake_event.set()
        try:
            self._wake_engine.stop()
        except Exception:
            pass
        try:
            self._tts_worker.stop()
        except Exception:
            pass
        try:
            self._executor.shutdown(wait=False, cancel_futures=True)
        except Exception:
            pass
        self._thread.join(timeout=2.0)

    def status(self) -> Dict[str, Any]:
        return {
            "enabled": self.cfg.enabled,
            "state": self.get_state(),
            "wake": self._wake_engine.status(),
            "stt_primary": self._stt_primary.status(),
            "stt_fallback": self._stt_fallback.status() if self._stt_fallback else "none",
            "tts_primary": self._tts_worker.primary.status(),
            "tts_fallback": self._tts_worker.fallback.status() if self._tts_worker.fallback else "none",
        }

    def get_state(self) -> str:
        with self._state_lock:
            return str(self._state.value)

    def trigger_listen_once(self) -> None:
        # Manual push-to-talk.
        self._wake_event.set()

    def force_sleep(self) -> None:
        # Unload conversation model lifecycle, then return to sleeping.
        try:
            self.jarvis_app.stage_b.unload()
        except Exception:
            pass
        self._set_state("manual", VoiceState.SLEEPING)

    def on_wake(self) -> None:
        self._wake_event.set()

    def _build_wake_engine(self) -> WakeWordEngine:
        engine = (self.cfg.wake_word_engine or "none").lower()
        if engine == "none":
            return NoWakeWordEngine()
        if engine != "porcupine":
            return NoWakeWordEngine()

        # AccessKey in secure store.
        access_key = None
        try:
            access_key = self.secure_store.secure_get("porcupine.access_key")
        except Exception:
            access_key = None
        if not access_key:
            # Missing key: keep running but wake word disabled; /listen still works.
            return NoWakeWordEngine()
        return PorcupineWakeWordEngine(
            access_key=str(access_key),
            keyword=str(self.cfg.wake_word or "jarvis").lower(),
            on_wake=self.on_wake,
            device_index=self.cfg.mic_device_index,
        )

    def _build_stt(self) -> tuple[STTEngine, Optional[STTEngine]]:
        vosk_path = str(self.models_cfg.get("vosk_model_path") or "")
        fw_path = str(self.models_cfg.get("faster_whisper_model_path") or "")
        primary = (self.cfg.stt_backend_primary or "vosk").lower()
        fallback = (self.cfg.stt_backend_fallback or "faster_whisper").lower()

        primary_engine: STTEngine
        fallback_engine: Optional[STTEngine] = None

        if primary == "vosk":
            primary_engine = VoskSTT(model_path=vosk_path)
        elif primary in {"faster_whisper", "faster-whisper"}:
            primary_engine = FasterWhisperSTT(model_path=fw_path)
        else:
            primary_engine = VoskSTT(model_path=vosk_path)

        if fallback in {"faster_whisper", "faster-whisper"}:
            fallback_engine = FasterWhisperSTT(model_path=fw_path)
        elif fallback == "vosk":
            fallback_engine = VoskSTT(model_path=vosk_path)
        else:
            fallback_engine = None

        return primary_engine, fallback_engine

    def _build_tts(self, name: str) -> Optional[TTSEngine]:
        n = (name or "").lower()
        if n == "sapi":
            return SapiTTSEngine()
        if n == "pyttsx3":
            return Pyttsx3TTSEngine()
        return None

    def _set_state(self, trace_id: str, new_state: VoiceState, details: Optional[Dict[str, Any]] = None) -> None:
        with self._state_lock:
            old = self._state
            self._state = new_state
        self.event_logger.log(trace_id, "voice.state", {"from": old.value, "to": new_state.value, **(details or {})})

    def _speak(self, trace_id: str, text: str) -> None:
        self._set_state(trace_id, VoiceState.SPEAKING)
        self._tts_worker.speak_blocking(trace_id, text)

    def _run(self) -> None:
        self._set_state("voice", VoiceState.SLEEPING, {"wake_ready": self._wake_engine.is_ready()})
        while not self._stop.is_set():
            # Idle rule: unload LLM after inactivity.
            if self._last_interaction and (time.time() - self._last_interaction) > float(self.cfg.idle_sleep_seconds):
                try:
                    self.jarvis_app.stage_b.unload()
                except Exception:
                    pass
                self._last_interaction = 0.0

            # Wait for wake (porcupine) or manual /listen.
            self._wake_event.wait(timeout=0.25)
            if self._stop.is_set():
                break
            if not self._wake_event.is_set():
                continue
            self._wake_event.clear()

            # Only one interaction at a time.
            if not self._interaction_lock.acquire(blocking=False):
                continue
            try:
                self._voice_interaction()
            finally:
                self._interaction_lock.release()

    def _voice_interaction(self) -> None:
        trace_id = uuid.uuid4().hex
        self._set_state(trace_id, VoiceState.WAKE_DETECTED)

        if self.cfg.confirm_beep:
            try:
                self._audio.beep()
            except Exception:
                pass

        # LLM lifecycle: warm on wake.
        try:
            self.jarvis_app.stage_b.warmup()
        except Exception:
            pass

        # LISTENING: capture wav in worker to avoid blocking.
        self._set_state(trace_id, VoiceState.LISTENING, {"listen_seconds": self.cfg.listen_seconds})
        if self.cfg.confirm_beep:
            try:
                self._audio.beep()
            except Exception:
                pass

        try:
            fut = self._executor.submit(self._audio.record_wav, trace_id, float(self.cfg.listen_seconds))
            wav_path = fut.result(timeout=float(self.cfg.listen_seconds) + 2.0)
            self.event_logger.log(trace_id, "voice.audio.captured", {"path": wav_path})
        except FutureTimeout:
            self._set_state(trace_id, VoiceState.ERROR, {"error": "listening timeout"})
            self._speak(trace_id, "I didn’t catch that.")
            self._set_state(trace_id, VoiceState.SLEEPING)
            return
        except Exception as e:
            self._set_state(trace_id, VoiceState.ERROR, {"error": str(e)})
            self._speak(trace_id, "Microphone error.")
            self._set_state(trace_id, VoiceState.SLEEPING)
            return

        # TRANSCRIBING
        self._set_state(trace_id, VoiceState.TRANSCRIBING, {"primary": getattr(self._stt_primary, "name", "primary")})
        text = ""
        try:
            text = self._stt_primary.transcribe(wav_path)
            self.event_logger.log(trace_id, "voice.stt.ok", {"backend": self._stt_primary.name, "text_len": len(text)})
        except Exception as e:
            self.event_logger.log(trace_id, "voice.stt.fail", {"backend": self._stt_primary.name, "error": str(e)})
            if self._stt_fallback is None:
                self._speak(trace_id, "I couldn’t transcribe that.")
                self._set_state(trace_id, VoiceState.SLEEPING)
                return
            try:
                text = self._stt_fallback.transcribe(wav_path)
                self.event_logger.log(trace_id, "voice.stt.ok", {"backend": self._stt_fallback.name, "text_len": len(text)})
            except Exception as e2:
                self.event_logger.log(trace_id, "voice.stt.fail", {"backend": self._stt_fallback.name, "error": str(e2)})
                self._speak(trace_id, "I couldn’t transcribe that.")
                self._set_state(trace_id, VoiceState.SLEEPING)
                return

        if not text.strip():
            self._speak(trace_id, "I didn’t catch that.")
            self._set_state(trace_id, VoiceState.SLEEPING)
            return

        # Voice admin unlock: default disabled.
        if text.strip().lower() == "admin unlock" and bool(self.cfg.allow_voice_admin_unlock):
            self._handle_voice_admin_unlock(trace_id)
            self._set_state(trace_id, VoiceState.SLEEPING)
            return

        # THINKING: route/dispatch via existing JarvisApp (with timeout).
        self._set_state(trace_id, VoiceState.THINKING, {"thinking_timeout_seconds": self.cfg.thinking_timeout_seconds})
        try:
            fut2 = self._executor.submit(self.jarvis_app.process_message, text, {"name": "voice", "id": "mic"})
            resp = fut2.result(timeout=float(self.cfg.thinking_timeout_seconds))
        except FutureTimeout:
            self._speak(trace_id, "That’s taking too long.")
            self._set_state(trace_id, VoiceState.SLEEPING)
            return
        except Exception as e:
            self.event_logger.log(trace_id, "voice.thinking.error", {"error": str(e)})
            self._speak(trace_id, "Something went wrong.")
            self._set_state(trace_id, VoiceState.SLEEPING)
            return

        # Speak reply
        self._speak(trace_id, resp.reply)
        self._last_interaction = time.time()
        self._set_state(trace_id, VoiceState.SLEEPING)

    def _handle_voice_admin_unlock(self, trace_id: str) -> None:
        # Safer behavior: do not persist audio, do not log passphrase content.
        self._speak(trace_id, "Say your passphrase.")
        try:
            wav = self._audio.record_wav(trace_id, seconds=min(4.0, float(self.cfg.listen_seconds)), sensitive=True)
        except Exception:
            self._speak(trace_id, "Microphone error.")
            return
        try:
            # STT still needed; if fails, deny.
            pw = ""
            try:
                pw = self._stt_primary.transcribe(wav)
            except Exception:
                if self._stt_fallback:
                    try:
                        pw = self._stt_fallback.transcribe(wav)
                    except Exception:
                        pw = ""
            ok = self.security_manager.verify_and_unlock_admin(pw.strip())
            self._speak(trace_id, "Admin unlocked." if ok else "Admin unlock failed.")
        finally:
            try:
                import os

                os.remove(wav)
            except Exception:
                pass

