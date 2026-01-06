from __future__ import annotations

import argparse
import getpass
import os
import threading
import time
from typing import Any, Dict, Optional

import uvicorn

from jarvis.core.config_loader import ConfigLoader, ConfigPaths
from jarvis.core.crypto import SecureStore
from jarvis.core.dispatcher import Dispatcher
from jarvis.core.events import EventLogger
from jarvis.core.intent_router import StageAIntent, StageAIntentRouter
from jarvis.core.jarvis_app import JarvisApp
from jarvis.core.llm_router import LLMConfig, StageBLLMRouter
from jarvis.core.logger import setup_logging
from jarvis.core.module_registry import ModuleRegistry
from jarvis.core.security import AdminSession, PermissionPolicy, SecurityManager
from jarvis.core.setup_wizard import SetupWizard
from jarvis.core.job_manager import (
    JobManager,
    SleepArgs,
    WriteTestFileArgs,
    job_system_cleanup_jobs,
    job_system_health_check,
    job_system_sleep,
    job_system_sleep_llm,
    job_system_write_test_file,
)
from jarvis.core.runtime import JarvisRuntime, RuntimeConfig, TTSAdapter, VoiceAdapter
from jarvis.web.api import create_app
from jarvis.web.auth import build_api_key_auth


def _load_json(cfg: ConfigLoader, path: str, default: Dict[str, Any]) -> Dict[str, Any]:
    data = cfg.load(path)
    return data if isinstance(data, dict) and data else dict(default)


def _ensure_admin_passphrase(security: SecurityManager, logger) -> None:
    if not security.is_usb_present():
        logger.info("USB key missing: admin features locked.")
        return
    if security.has_admin_passphrase_set():
        return
    try:
        p1 = getpass.getpass("Set admin passphrase (will be stored encrypted): ")
        p2 = getpass.getpass("Confirm admin passphrase: ")
    except (EOFError, KeyboardInterrupt):
        logger.warning("Admin passphrase not set (interactive input unavailable).")
        return
    if not p1 or p1 != p2:
        logger.warning("Admin passphrase not set (mismatch/empty).")
        return
    security.set_admin_passphrase(p1)
    logger.info("Admin passphrase set.")


def _start_web_thread(
    jarvis: JarvisApp,
    security: SecurityManager,
    secure_store: SecureStore,
    cfg: ConfigLoader,
    paths: ConfigPaths,
    event_logger: EventLogger,
    logger,
    job_manager: JobManager | None,
    runtime: JarvisRuntime | None,
) -> None:
    web_cfg = _load_json(
        cfg,
        paths.web,
        default={"enabled": False, "host": "0.0.0.0", "port": 8787, "allowed_origins": [], "enable_web_ui": True, "allow_remote_admin_unlock": False},
    )
    if not web_cfg.get("enabled", False):
        return

    enable_web_ui = bool(web_cfg.get("enable_web_ui", True))
    allow_remote_admin_unlock = bool(web_cfg.get("allow_remote_admin_unlock", False))
    allowed_origins = web_cfg.get("allowed_origins") or []

    remote_control_enabled = True
    auth = None

    if not secure_store.is_unlocked():
        # Safest: do not expose remote control without USB key.
        remote_control_enabled = False
        host = "127.0.0.1"
        port = int(web_cfg.get("port", 8787))
        logger.warning("USB key missing: starting web server on localhost only with remote control disabled.")
    else:
        host = str(web_cfg.get("host") or "0.0.0.0")
        port = int(web_cfg.get("port") or 8787)
        api_key = secure_store.secure_get("web.api_key")
        if not api_key:
            logger.error("Web enabled but API key not found. Run: python scripts/rotate_api_key.py")
            return
        auth = build_api_key_auth(api_key=str(api_key), event_logger=event_logger)

    fastapi_app = create_app(
        jarvis_app=jarvis,
        security_manager=security,
        event_logger=event_logger,
        logger=logger,
        auth_dep=auth,
        job_manager=job_manager,
        runtime=runtime,
        allowed_origins=list(allowed_origins),
        enable_web_ui=enable_web_ui,
        allow_remote_admin_unlock=allow_remote_admin_unlock,
        remote_control_enabled=remote_control_enabled,
    )

    def run() -> None:
        uvicorn.run(fastapi_app, host=host, port=port, log_level="info")

    t = threading.Thread(target=run, name="jarvis-web", daemon=True)
    t.start()
    logger.info(f"Web server started on http://{host}:{port}")


def main() -> None:
    ap = argparse.ArgumentParser(description="Jarvis (offline-first) CLI/voice/web")
    ap.add_argument("--mode", choices=["text", "voice", "hybrid"], default="hybrid", help="Run mode.")
    args = ap.parse_args()

    logger = setup_logging("logs")
    event_logger = EventLogger("logs/events.jsonl")

    paths = ConfigPaths()
    cfg = ConfigLoader(paths)

    security_cfg = _load_json(
        cfg,
        paths.security,
        default={
            "usb_key_path": r"E:\JARVIS_KEY.bin",
            "secure_store_path": "secure/secure_store.enc",
            "admin_session_timeout_seconds": 900,
            "router_confidence_threshold": 0.55,
            "llm": {"base_url": "http://localhost:11434", "timeout_seconds": 5.0, "model": "qwen:14b-chat", "mock_mode": True},
        },
    )

    secure_store = SecureStore(
        usb_key_path=str(security_cfg.get("usb_key_path")),
        store_path=str(security_cfg.get("secure_store_path")),
    )
    security = SecurityManager(secure_store=secure_store, admin_session=AdminSession(timeout_seconds=int(security_cfg.get("admin_session_timeout_seconds", 900))))

    _ensure_admin_passphrase(security, logger)

    # Setup wizard (startup)
    wiz = SetupWizard(cfg=cfg, paths=paths, secure_store=secure_store, logger=logger)
    wiz.run_interactive()

    modules_registry_cfg = _load_json(cfg, paths.modules_registry, default={"modules": []})
    modules_cfg = _load_json(cfg, paths.modules, default={"intents": []})
    perms_cfg = _load_json(cfg, paths.permissions, default={"intents": {}})
    resp_cfg = _load_json(cfg, paths.responses, default={"confirmations": {}})

    # Module registry
    registry = ModuleRegistry()
    for entry in modules_registry_cfg.get("modules") or []:
        if not isinstance(entry, dict) or not entry.get("enabled", False):
            continue
        registry.register(str(entry.get("module")))

    # Stage-A intents
    stage_a_intents = []
    intent_config_by_id: Dict[str, Dict[str, Any]] = {}
    for i in modules_cfg.get("intents") or []:
        if not isinstance(i, dict) or not i.get("id"):
            continue
        intent_id = str(i["id"])
        intent_config_by_id[intent_id] = dict(i)
        stage_a_intents.append(
            StageAIntent(
                id=intent_id,
                module_id=str(i.get("module_id") or ""),
                keywords=list(i.get("keywords") or []),
                required_args=list(i.get("required_args") or []),
            )
        )

    threshold = float(security_cfg.get("router_confidence_threshold", 0.55))
    stage_a = StageAIntentRouter(stage_a_intents, threshold=threshold)

    llm_cfg_raw = security_cfg.get("llm") or {}
    stage_b = StageBLLMRouter(
        LLMConfig(
            base_url=str(llm_cfg_raw.get("base_url", "http://localhost:11434")),
            timeout_seconds=float(llm_cfg_raw.get("timeout_seconds", 5.0)),
            model=str(llm_cfg_raw.get("model", "qwen:14b-chat")),
            mock_mode=bool(llm_cfg_raw.get("mock_mode", True)),
        )
    )

    policy = PermissionPolicy(intents=dict(perms_cfg.get("intents") or {}))
    dispatcher = Dispatcher(registry=registry, policy=policy, security=security, event_logger=event_logger, logger=logger)

    jarvis = JarvisApp(
        stage_a=stage_a,
        stage_b=stage_b,
        dispatcher=dispatcher,
        intent_config_by_id=intent_config_by_id,
        confirmation_templates=dict(resp_cfg.get("confirmations") or {}),
        event_logger=event_logger,
        logger=logger,
        threshold=threshold,
    )

    # Job manager (core subsystem)
    jobs_cfg = _load_json(
        cfg,
        paths.jobs,
        default={
            "max_concurrent_jobs": 1,
            "default_timeout_seconds": 600,
            "retention_max_jobs": 200,
            "retention_days": 30,
            "poll_interval_ms": 200,
        },
    )

    job_manager: JobManager | None = JobManager(
        jobs_dir="logs/jobs",
        max_concurrent_jobs=int(jobs_cfg.get("max_concurrent_jobs", 1)),
        default_timeout_seconds=int(jobs_cfg.get("default_timeout_seconds", 600)),
        retention_max_jobs=int(jobs_cfg.get("retention_max_jobs", 200)),
        retention_days=int(jobs_cfg.get("retention_days", 30)),
        poll_interval_ms=int(jobs_cfg.get("poll_interval_ms", 200)),
        event_logger=event_logger,
        logger=logger,
    )

    # Register allowlisted job kinds (no shell, no arbitrary code).
    job_manager.register_job("system.sleep", job_system_sleep, schema_model=SleepArgs)
    job_manager.register_job("system.health_check", job_system_health_check)
    job_manager.register_job("system.write_test_file", job_system_write_test_file, schema_model=WriteTestFileArgs)
    job_manager.register_job("system.cleanup_jobs", job_system_cleanup_jobs)
    job_manager.register_job("system.sleep_llm", job_system_sleep_llm)

    # Post-complete hooks that must run in main process (stateful operations / retention).
    def _hook_cleanup(_st):
        job_manager.enforce_retention()

    def _hook_sleep_llm(_st):
        try:
            jarvis.stage_b.unload()
        except Exception:
            pass

    def _hook_health_check(st):
        # Augment result with a safe snapshot from the main process.
        try:
            snap = {
                "allowed_job_kinds": job_manager.allowed_kinds(),
                "admin": security.is_admin(),
                "usb_present": security.is_usb_present(),
            }
            job_manager.patch_job_result(st.id, {"snapshot": snap})
        except Exception:
            pass

    job_manager.post_complete_hooks.update(
        {
            "system.cleanup_jobs": _hook_cleanup,
            "system.sleep_llm": _hook_sleep_llm,
            "system.health_check": _hook_health_check,
        }
    )

    # Core Runtime State Machine
    sm_cfg_raw = _load_json(
        cfg,
        paths.state_machine,
        default={
            "idle_sleep_seconds": 45,
            "timeouts": {"LISTENING": 8, "TRANSCRIBING": 15, "UNDERSTANDING": 10, "EXECUTING": 20, "SPEAKING": 20},
            "enable_voice": False,
            "enable_tts": True,
            "enable_wake_word": True,
            "max_concurrent_interactions": 1,
            "busy_policy": "queue",
            "result_ttl_seconds": 120,
        },
    )
    sm_cfg = RuntimeConfig.model_validate(sm_cfg_raw)

    # Build optional voice adapters (reuse existing voice package components)
    voice_adapter = None
    tts_adapter = None
    if sm_cfg.enable_tts:
        try:
            from jarvis.voice.tts import Pyttsx3TTSEngine, SapiTTSEngine, TTSWorker

            primary = SapiTTSEngine() if os.name == "nt" else Pyttsx3TTSEngine()
            fallback = Pyttsx3TTSEngine()
            tts_worker = TTSWorker(primary=primary, fallback=fallback, logger=logger, event_logger=event_logger)
            tts_adapter = TTSAdapter(worker=tts_worker)
        except Exception as e:
            logger.warning(f"TTS disabled (init failed): {e}")
            tts_adapter = None

    if sm_cfg.enable_voice and args.mode in {"voice", "hybrid"}:
        voice_cfg = _load_json(cfg, paths.voice, default={"enabled": False})
        models_cfg = _load_json(cfg, paths.models, default={"vosk_model_path": "", "faster_whisper_model_path": ""})
        if bool(voice_cfg.get("enabled", False)):
            try:
                from jarvis.voice.audio import AudioRecorder
                from jarvis.voice.stt import FasterWhisperSTT, VoskSTT
                from jarvis.voice.wakeword import NoWakeWordEngine, PorcupineWakeWordEngine

                recorder = AudioRecorder(
                    sample_rate=int(voice_cfg.get("sample_rate", 16000)),
                    device_index=voice_cfg.get("mic_device_index", None),
                    keep_last_n=int(voice_cfg.get("audio_retention_files", 25)),
                )
                stt_primary = VoskSTT(model_path=str(models_cfg.get("vosk_model_path") or ""))
                stt_fallback = FasterWhisperSTT(model_path=str(models_cfg.get("faster_whisper_model_path") or ""))

                wake_engine = None
                if sm_cfg.enable_wake_word and str(voice_cfg.get("wake_word_engine", "porcupine")).lower() == "porcupine":
                    access_key = None
                    try:
                        access_key = secure_store.secure_get("porcupine.access_key")
                    except Exception:
                        access_key = None
                    if access_key:
                        wake_engine = PorcupineWakeWordEngine(
                            access_key=str(access_key),
                            keyword=str(voice_cfg.get("wake_word", "jarvis")).lower(),
                            on_wake=lambda: None,  # runtime will overwrite
                            device_index=voice_cfg.get("mic_device_index", None),
                        )
                    else:
                        wake_engine = NoWakeWordEngine()

                voice_adapter = VoiceAdapter(
                    recorder=recorder,
                    stt_primary=stt_primary,
                    stt_fallback=stt_fallback,
                    wake_engine=wake_engine,
                    listen_seconds=float(voice_cfg.get("listen_seconds", 8)),
                )
            except Exception as e:
                logger.warning(f"Voice disabled (init failed): {e}")
                voice_adapter = None

    runtime = JarvisRuntime(cfg=sm_cfg, jarvis_app=jarvis, event_logger=event_logger, logger=logger, job_manager=job_manager, voice_adapter=voice_adapter, tts_adapter=tts_adapter)
    runtime.start()

    _start_web_thread(jarvis, security, secure_store, cfg, paths, event_logger, logger, job_manager, runtime)

    logger.info("Jarvis CLI ready. Type /exit to quit. (/status, /wake, /sleep, /shutdown, /jobs ...)")

    while True:
        try:
            text = input("> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not text:
            continue
        if text == "/exit":
            break
        if text == "/sleep":
            runtime.request_sleep()
            print("Sleeping.")
            continue
        if text == "/status":
            print(runtime.get_status())
            continue
        if text == "/wake":
            runtime.wake()
            print("Wake requested.")
            continue
        if text == "/shutdown":
            runtime.request_shutdown()
            print("Shutdown requested.")
            break
        if text.startswith("/say "):
            runtime.say(text.split(" ", 1)[1].strip(), source="cli")
            print("Speaking...")
            continue
        if text == "/mics":
            try:
                from jarvis.voice.audio import list_microphones

                mics = list_microphones()
                for m in mics:
                    print(f"{m['index']}: {m['name']}")
            except Exception as e:
                print(f"Unable to list microphones: {e}")
            continue
        if text.startswith("/jobs"):
            parts = text.split()
            if len(parts) == 1 or (len(parts) >= 2 and parts[1] == "list"):
                status = parts[2] if len(parts) >= 3 else None
                jobs = job_manager.list_jobs(status=status)
                for j in jobs[:50]:
                    print(f"{j.id} | {j.status.value:10s} | {j.kind} | {j.progress:3d}% | {j.message}")
                continue
            if len(parts) >= 3 and parts[1] == "show":
                jid = parts[2]
                try:
                    j = job_manager.get_job(jid)
                except KeyError:
                    print("Job not found.")
                else:
                    print(j.model_dump())
                continue
            if len(parts) >= 3 and parts[1] == "cancel":
                jid = parts[2]
                ok = job_manager.cancel_job(jid)
                print("Canceled." if ok else "Unable to cancel.")
                continue
            if len(parts) >= 3 and parts[1] == "tail":
                jid = parts[2]
                n = int(parts[3]) if len(parts) >= 4 else 20
                evs = job_manager.tail_job_events(jid, last_n=n)
                for e in evs:
                    print(e)
                continue
            if len(parts) >= 3 and parts[1] == "run":
                name = parts[2]
                if name == "health_check":
                    jid = job_manager.submit_job("system.health_check", {}, {"source": "cli", "client_id": "stdin"})
                    print(f"Submitted: {jid}")
                    continue
                if name == "cleanup":
                    jid = job_manager.submit_job("system.cleanup_jobs", {}, {"source": "cli", "client_id": "stdin"})
                    print(f"Submitted: {jid}")
                    continue
                print("Unknown run target. Use: health_check | cleanup")
                continue
            print("Usage: /jobs list [STATUS] | /jobs show <id> | /jobs cancel <id> | /jobs tail <id> [n] | /jobs run health_check|cleanup")
            continue
        if text.startswith("/admin unlock"):
            if not security.is_usb_present():
                print("USB key required for admin unlock.")
                continue
            try:
                pw = getpass.getpass("Passphrase: ")
            except (EOFError, KeyboardInterrupt):
                print()
                continue
            ok = security.verify_and_unlock_admin(pw)
            print("Admin unlocked." if ok else "Invalid passphrase.")
            continue
        if text.startswith("/admin lock"):
            security.lock_admin()
            print("Admin locked.")
            continue

        if args.mode == "voice":
            print("Voice-only mode: use /wake or /exit.")
        else:
            trace_id = runtime.submit_text("cli", text, client_meta={"id": "stdin"})
            res = runtime.wait_for_result(trace_id, timeout_seconds=20.0)
            print(res["reply"] if res else "…")
        time.sleep(0.01)

    try:
        runtime.stop()
    except Exception:
        pass
    try:
        if job_manager is not None:
            job_manager.stop()
    except Exception:
        pass


if __name__ == "__main__":
    main()

