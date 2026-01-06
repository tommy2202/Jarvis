from __future__ import annotations

import argparse
import getpass
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


def _start_web_thread(jarvis: JarvisApp, security: SecurityManager, secure_store: SecureStore, cfg: ConfigLoader, paths: ConfigPaths, event_logger: EventLogger, logger) -> None:
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

    _start_web_thread(jarvis, security, secure_store, cfg, paths, event_logger, logger)

    # Voice stack (optional; safe if deps/models missing)
    voice_controller: Optional[object] = None
    voice_cfg = _load_json(cfg, "config/voice.json", default={"enabled": False})
    models_cfg = _load_json(cfg, "config/models.json", default={"vosk_model_path": "", "faster_whisper_model_path": ""})
    if args.mode in {"voice", "hybrid"} and bool(voice_cfg.get("enabled", False)):
        try:
            from jarvis.voice.state_machine import VoiceConfig, VoiceController
        except Exception as e:
            logger.warning(f"Voice stack not available: {e}")
            voice_controller = None
        else:
            vc = VoiceConfig(
                enabled=bool(voice_cfg.get("enabled", False)),
                wake_word_engine=str(voice_cfg.get("wake_word_engine", "porcupine")),
                wake_word=str(voice_cfg.get("wake_word", "jarvis")),
                mic_device_index=voice_cfg.get("mic_device_index", None),
                stt_backend_primary=str(voice_cfg.get("stt_backend_primary", "vosk")),
                stt_backend_fallback=str(voice_cfg.get("stt_backend_fallback", "faster_whisper")),
                tts_backend_primary=str(voice_cfg.get("tts_backend_primary", "sapi")),
                tts_backend_fallback=str(voice_cfg.get("tts_backend_fallback", "pyttsx3")),
                listen_seconds=float(voice_cfg.get("listen_seconds", 8)),
                sample_rate=int(voice_cfg.get("sample_rate", 16000)),
                idle_sleep_seconds=float(voice_cfg.get("idle_sleep_seconds", 45)),
                confirm_beep=bool(voice_cfg.get("confirm_beep", True)),
                audio_retention_files=int(voice_cfg.get("audio_retention_files", 25)),
                allow_voice_admin_unlock=bool(voice_cfg.get("allow_voice_admin_unlock", False)),
                thinking_timeout_seconds=float(voice_cfg.get("thinking_timeout_seconds", 15)),
            )
            voice_controller = VoiceController(
                cfg=vc,
                models_cfg=models_cfg,
                secure_store=secure_store,
                jarvis_app=jarvis,
                security_manager=security,
                logger=logger,
                event_logger=event_logger,
            )
            try:
                voice_controller.start()
                logger.info("Voice stack enabled.")
            except Exception as e:
                logger.warning(f"Voice failed to start; continuing text-only: {e}")
                voice_controller = None

    logger.info("Jarvis CLI ready. Type /exit to quit. (/mics, /listen, /voice status)")

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
            try:
                if voice_controller is not None:
                    voice_controller.force_sleep()
            except Exception:
                pass
            try:
                jarvis.stage_b.unload()
            except Exception:
                pass
            print("Sleeping.")
            continue
        if text.startswith("/voice "):
            cmd = text.split(" ", 1)[1].strip().lower()
            if cmd == "status":
                if voice_controller is None:
                    print("Voice: off/unavailable.")
                else:
                    st = voice_controller.status()
                    print(st)
                continue
            if cmd == "off":
                if voice_controller is not None:
                    voice_controller.stop()
                    voice_controller = None
                print("Voice disabled.")
                continue
            if cmd == "on":
                print("Voice enable requires config/voice.json enabled:true and restart.")
                continue
        if text == "/listen":
            if voice_controller is None:
                print("Voice not running. Enable in config/voice.json and restart.")
            else:
                voice_controller.trigger_listen_once()
                print("Listening once...")
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
            print("Voice-only mode: use /listen or /exit.")
        else:
            resp = jarvis.process_message(text, client={"name": "cli", "id": "stdin"})
            print(resp.reply)
        time.sleep(0.01)

    try:
        if voice_controller is not None:
            voice_controller.stop()
    except Exception:
        pass


if __name__ == "__main__":
    main()

