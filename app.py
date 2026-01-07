from __future__ import annotations

import argparse
import getpass
import os
import sys
import threading
import time
import uuid
from typing import Any, Dict, Optional

import uvicorn

from jarvis.core.config import get_config
from jarvis.core.secure_store import SecureStore, SecretUnavailable
from jarvis.core.dispatcher import Dispatcher
from jarvis.core.events import EventLogger
from jarvis.core.intent_router import StageAIntent, StageAIntentRouter
from jarvis.core.jarvis_app import JarvisApp
from jarvis.core.llm_router import LLMConfig  # legacy name kept
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
from jarvis.core.error_reporter import ErrorReporter, ErrorReporterConfig
from jarvis.core.recovery import RecoveryPolicy, RecoveryConfig
from jarvis.core.circuit_breaker import CircuitBreaker, BreakerConfig, BreakerRegistry
from jarvis.core.llm_lifecycle import LLMPolicy, LLMLifecycleController
from jarvis.core.llm_router import LLMConfig as StageBLegacyConfig, StageBLLMRouter
from jarvis.core.telemetry.manager import TelemetryManager, TelemetryConfig
from jarvis.core.ops_log import OpsLogger
from jarvis.core.runtime_control import RuntimeController, check_startup_recovery
from jarvis.core.shutdown_orchestrator import ShutdownConfig, ShutdownOrchestrator
from jarvis.core.persistence.runtime_state import write_dirty_flag
from jarvis.web.api import create_app
from jarvis.web.auth import build_api_key_auth  # legacy
from jarvis.web.security.auth import ApiKeyStore
from jarvis.web.security.strikes import StrikeManager, LockoutConfig


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


class WebServerHandle:
    def __init__(self, *, app, host: str, port: int, logger, telemetry: TelemetryManager | None, allow_remote: bool, draining_event: threading.Event):  # noqa: ANN001
        self.app = app
        self.host = host
        self.port = port
        self.logger = logger
        self.telemetry = telemetry
        self.allow_remote = allow_remote
        self.draining_event = draining_event
        self._server: Optional[uvicorn.Server] = None
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        cfg = uvicorn.Config(self.app, host=self.host, port=self.port, log_level="info")
        self._server = uvicorn.Server(cfg)

        def run() -> None:
            assert self._server is not None
            self._server.run()

        self._thread = threading.Thread(target=run, name="jarvis-web", daemon=True)
        self._thread.start()
        if self.telemetry is not None:
            try:
                self.telemetry.set_web_server_info(enabled=True, bind_host=self.host, port=self.port, allow_remote=self.allow_remote, thread_alive=True)
            except Exception:
                pass
        self.logger.info(f"Web server started on http://{self.host}:{self.port}")

    def set_draining(self, draining: bool) -> None:
        if draining:
            self.draining_event.set()
        else:
            self.draining_event.clear()

    def stop(self) -> None:
        self.set_draining(True)
        if self._server is not None:
            self._server.should_exit = True
        if self._thread is not None and self._thread.is_alive():
            self._thread.join(timeout=3.0)
        if self.telemetry is not None:
            try:
                self.telemetry.set_web_server_info(enabled=True, bind_host=self.host, port=self.port, allow_remote=self.allow_remote, thread_alive=False)
            except Exception:
                pass


def _start_web_thread(
    jarvis: JarvisApp,
    security: SecurityManager,
    secure_store: SecureStore,
    config_manager,
    event_logger: EventLogger,
    logger,
    job_manager: JobManager | None,
    runtime: JarvisRuntime | None,
    telemetry: TelemetryManager | None,
) -> Optional[WebServerHandle]:
    web_cfg = config_manager.get().web.model_dump()
    if not web_cfg.get("enabled", False):
        return None

    enable_web_ui = bool(web_cfg.get("enable_web_ui", True))
    allowed_origins = web_cfg.get("allowed_origins") or []

    allow_remote = bool(web_cfg.get("allow_remote", False))
    bind_host = str(web_cfg.get("bind_host") or "127.0.0.1")
    port = int(web_cfg.get("port") or 8000)

    # Secure Binding & Exposure Rules:
    # - Default bind: localhost only
    # - Remote requires explicit allow_remote + USB key present
    if not allow_remote:
        if bind_host != "127.0.0.1":
            logger.warning("Web allow_remote=false: forcing bind_host=127.0.0.1")
        bind_host = "127.0.0.1"
    else:
        if not secure_store.is_unlocked():
            logger.error("Refusing to start web server: allow_remote=true requires USB key present.")
            return None
        from jarvis.core.security_events import SecurityAuditLogger

        SecurityAuditLogger().log(
            trace_id="web",
            severity="HIGH",
            event="web.remote_enabled",
            ip=None,
            endpoint="startup",
            outcome="enabled",
            details={"bind_host": bind_host, "port": port},
        )

    draining_event = threading.Event()
    fastapi_app = create_app(
        jarvis_app=jarvis,
        security_manager=security,
        event_logger=event_logger,
        logger=logger,
        auth_dep=None,
        job_manager=job_manager,
        runtime=runtime,
        secure_store=secure_store,
        web_cfg=web_cfg,
        telemetry=telemetry,
        draining_event=draining_event,
        allowed_origins=list(allowed_origins),
        enable_web_ui=enable_web_ui,
        allow_remote_admin_unlock=False,
        remote_control_enabled=secure_store.is_unlocked(),
    )
    h = WebServerHandle(app=fastapi_app, host=bind_host, port=port, logger=logger, telemetry=telemetry, allow_remote=allow_remote, draining_event=draining_event)
    h.start()
    return h


def main() -> None:
    ap = argparse.ArgumentParser(description="Jarvis (offline-first) CLI/voice/web")
    ap.add_argument("--mode", choices=["text", "voice", "hybrid"], default="hybrid", help="Run mode.")
    ap.add_argument("--ui", action="store_true", help="Launch desktop UI (Tkinter) instead of CLI.")
    args = ap.parse_args()

    logger = setup_logging("logs")
    event_logger = EventLogger("logs/events.jsonl")
    ops = OpsLogger()
    recovery_info = check_startup_recovery(ops=ops, root_path=".")
    # Mark this run as "dirty" until we complete a graceful shutdown.
    try:
        write_dirty_flag(".", trace_id=uuid.uuid4().hex)
    except Exception:
        pass

    config = get_config(logger=logger)
    cfg_obj = config.get()
    # Safe-mode restart override (local, non-persistent).
    if recovery_info.get("restart") and bool((recovery_info["restart"] or {}).get("safe_mode", False)):
        defaults = (cfg_obj.runtime.startup or {}).get("safe_mode_defaults") or {"web_enabled": True, "voice_enabled": True, "llm_enabled": True}
        try:
            cfg_obj = cfg_obj.model_copy(deep=True)
            cfg_obj.web.enabled = bool(defaults.get("web_enabled", False))
            cfg_obj.voice.enabled = bool(defaults.get("voice_enabled", False))
            cfg_obj.state_machine.enable_voice = bool(defaults.get("voice_enabled", False))
            cfg_obj.llm.enabled = bool(defaults.get("llm_enabled", False))
            ops.log(trace_id=str((recovery_info["restart"] or {}).get("trace_id") or "startup"), event="startup_safe_mode", outcome="applied", details=defaults)
        except Exception:
            pass

    telemetry_cfg = TelemetryConfig.model_validate(cfg_obj.telemetry.model_dump())
    telemetry = TelemetryManager(cfg=telemetry_cfg, logger=logger, root_path=".")
    telemetry.attach(config_manager=config)

    # Error handling + recovery subsystem
    recovery_cfg = RecoveryConfig.model_validate(cfg_obj.recovery.model_dump())
    error_reporter = ErrorReporter(cfg=ErrorReporterConfig(include_tracebacks=bool(recovery_cfg.debug.get("include_tracebacks", False))), telemetry=telemetry)
    recovery_policy = RecoveryPolicy(recovery_cfg)
    breakers_map = {}
    for name, bc in (recovery_cfg.circuit_breakers or {}).items():
        try:
            breakers_map[name] = CircuitBreaker(
                BreakerConfig(
                    failures=int(bc.get("failures", 3)),
                    window_seconds=int(bc.get("window_seconds", 30)),
                    cooldown_seconds=int(bc.get("cooldown_seconds", 30)),
                )
            )
        except Exception:
            continue
    breaker_registry = BreakerRegistry(breakers_map)

    secure_store = SecureStore(
        usb_key_path=cfg_obj.security.usb_key_path,
        store_path=cfg_obj.security.secure_store_path,
        meta_path=os.path.join("secure", "store.meta.json"),
        backups_dir=os.path.join("secure", "backups"),
        max_backups=int(cfg_obj.security.secure_store_backup_keep),
        max_bytes=int(cfg_obj.security.secure_store_max_bytes),
        read_only=bool(cfg_obj.security.secure_store_read_only),
    )
    security = SecurityManager(secure_store=secure_store, admin_session=AdminSession(timeout_seconds=int(cfg_obj.security.admin_session_timeout_seconds)))
    telemetry.attach(secure_store=secure_store, security_manager=security)

    _ensure_admin_passphrase(security, logger)

    # Setup wizard currently uses config files; keep behavior but avoid ad-hoc loads elsewhere.
    wiz = SetupWizard(cfg=None, paths=None, secure_store=secure_store, logger=logger)  # type: ignore[arg-type]
    try:
        wiz.run_interactive()
        config.load_all()
        cfg_obj = config.get()
    except Exception:
        # wizard is optional; continue with validated config
        pass

    # Use unified validated config everywhere below
    modules_registry_cfg = cfg_obj.modules_registry.model_dump()
    modules_cfg = cfg_obj.modules.model_dump()
    perms_cfg = cfg_obj.permissions.model_dump()
    resp_cfg = cfg_obj.responses.model_dump()

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

    threshold = float(cfg_obj.security.router_confidence_threshold)
    stage_a = StageAIntentRouter(stage_a_intents, threshold=threshold)

    # LLM lifecycle policy (new)
    llm_policy = LLMPolicy.model_validate(cfg_obj.llm.model_dump())
    llm_lifecycle = LLMLifecycleController(policy=llm_policy, event_logger=event_logger, logger=logger, telemetry=telemetry) if (llm_policy.roles and llm_policy.enabled) else None
    telemetry.attach(llm_lifecycle=llm_lifecycle)

    # Stage-B router uses lifecycle if available; otherwise stays in safe mock mode.
    stage_b = StageBLLMRouter(StageBLegacyConfig(mock_mode=True), lifecycle=llm_lifecycle)

    policy = PermissionPolicy(intents=dict(perms_cfg.get("intents") or {}))
    dispatcher = Dispatcher(registry=registry, policy=policy, security=security, event_logger=event_logger, logger=logger, error_reporter=error_reporter, telemetry=telemetry)

    jarvis = JarvisApp(
        stage_a=stage_a,
        stage_b=stage_b,
        dispatcher=dispatcher,
        intent_config_by_id=intent_config_by_id,
        confirmation_templates=dict(resp_cfg.get("confirmations") or {}),
        event_logger=event_logger,
        logger=logger,
        threshold=threshold,
        telemetry=telemetry,
    )
    telemetry.attach(jarvis_app=jarvis, dispatcher=dispatcher)

    # Job manager (core subsystem)
    jobs_cfg = cfg_obj.jobs
    job_manager: JobManager | None = JobManager(
        jobs_dir="logs/jobs",
        max_concurrent_jobs=int(jobs_cfg.max_concurrent_jobs),
        default_timeout_seconds=int(jobs_cfg.default_timeout_seconds),
        retention_max_jobs=int(jobs_cfg.retention_max_jobs),
        retention_days=int(jobs_cfg.retention_days),
        poll_interval_ms=int(jobs_cfg.poll_interval_ms),
        event_logger=event_logger,
        logger=logger,
        debug_tracebacks=bool(recovery_cfg.debug.get("include_tracebacks", False)),
        telemetry=telemetry,
    )
    telemetry.attach(job_manager=job_manager)

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
    sm_cfg = RuntimeConfig.model_validate(cfg_obj.state_machine.model_dump())

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

    if sm_cfg.enable_voice and args.mode in {"voice", "hybrid"} and cfg_obj.voice.enabled:
        voice_cfg = cfg_obj.voice.model_dump()
        models_cfg = cfg_obj.models.model_dump()
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
                        access_key = secure_store.get("porcupine.access_key")
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

    runtime = JarvisRuntime(
        cfg=sm_cfg,
        jarvis_app=jarvis,
        event_logger=event_logger,
        logger=logger,
        job_manager=job_manager,
        llm_lifecycle=llm_lifecycle,
        voice_adapter=voice_adapter,
        tts_adapter=tts_adapter,
        security_manager=security,
        secure_store=secure_store,
        telemetry=telemetry,
        error_reporter=error_reporter,
        recovery_policy=recovery_policy,
        breakers=breaker_registry,
    )
    runtime.start()
    telemetry.attach(runtime=runtime, voice_adapter=voice_adapter, tts_adapter=tts_adapter)

    web_handle = _start_web_thread(jarvis, security, secure_store, config, event_logger, logger, job_manager, runtime, telemetry)

    # Runtime control (shutdown/restart orchestration)
    shutdown_block = cfg_obj.runtime.shutdown or {}
    shutdown_cfg = ShutdownConfig(
        phase_timeouts_seconds=dict(shutdown_block.get("phase_timeouts_seconds") or {}),
        job_grace_seconds=float(shutdown_block.get("job_grace_seconds", 15)),
        force_kill_after_seconds=float(shutdown_block.get("force_kill_after_seconds", 30)),
    )
    orchestrator = ShutdownOrchestrator(
        cfg=shutdown_cfg,
        ops=ops,
        logger=logger,
        runtime=runtime,
        job_manager=job_manager,
        llm_lifecycle=llm_lifecycle,
        telemetry=telemetry,
        secure_store=secure_store,
        config_manager=config,
        web_handle=web_handle,
        ui_handle=None,
        root_path=".",
    )
    controller = RuntimeController(runtime_cfg=cfg_obj.runtime.model_dump(), ops=ops, logger=logger, orchestrator=orchestrator, security_manager=security)

    if args.ui:
        from jarvis.ui.app import run_desktop_ui

        ui_cfg = config.get().ui
        try:
            run_desktop_ui(runtime=runtime, config=ui_cfg, logger=logger, on_shutdown=lambda: controller.request_shutdown(reason="ui_close", restart=False, argv=sys.argv))
        finally:
            # If UI exits without invoking callback, shut down gracefully.
            if not controller.get_shutdown_status().get("in_progress"):
                controller.request_shutdown(reason="ui_exit", restart=False, argv=sys.argv)
        return

    logger.info("Jarvis CLI ready. Type /exit to quit. (/status, /wake, /sleep, /shutdown, /jobs ...)")

    while True:
        try:
            text = input("> ").strip()
        except EOFError:
            print()
            break
        except KeyboardInterrupt:
            print()
            controller.request_shutdown(reason="ctrl_c", restart=False, argv=sys.argv)
            return
        if not text:
            continue
        if text == "/exit":
            break
        if text == "/sleep":
            runtime.request_sleep()
            print("Sleeping.")
            continue
        if text == "/status":
            st = runtime.get_status()
            st["shutdown_status"] = controller.get_shutdown_status()
            print(st)
            continue
        if text == "/wake":
            runtime.wake()
            print("Wake requested.")
            continue
        if text.startswith("/shutdown"):
            requires_confirm = bool((cfg_obj.runtime.shutdown or {}).get("shutdown_requires_confirm", True))
            if requires_confirm:
                ans = input("Confirm shutdown? (y/N) ").strip().lower()
                if ans != "y":
                    print("Canceled.")
                    continue
            controller.request_shutdown(reason="cli_shutdown", restart=False, argv=sys.argv)
            return
        if text.startswith("/restart"):
            parts = text.split()
            if len(parts) >= 2 and parts[1] in {"llm", "web", "voice", "jobs"}:
                ok = controller.restart_subsystem(parts[1])
                print("OK" if ok else "Failed")
                continue
            try:
                controller.request_restart(reason="cli_restart", safe_mode=False, argv=sys.argv)
            except Exception as e:
                print(str(e))
            return
        if text.startswith("/safe_mode restart"):
            try:
                controller.request_restart(reason="cli_safe_mode_restart", safe_mode=True, argv=sys.argv)
            except Exception as e:
                print(str(e))
            return
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
        if text.startswith("/web"):
            parts = text.split()
            if len(parts) == 1 or (len(parts) >= 2 and parts[1] == "status"):
                web_cfg = config.get().web.model_dump()
                st = {"config": web_cfg}
                if secure_store.is_unlocked():
                    try:
                        ks = ApiKeyStore(secure_store).list_keys()
                        st["keys"] = [{"id": k.id, "scopes": k.scopes, "revoked": k.revoked, "last_used_at": k.last_used_at, "lockouts": k.lockouts} for k in ks]
                        st["lockouts"] = StrikeManager(secure_store, LockoutConfig.model_validate((web_cfg.get("lockout") or {}))).get_lockouts()
                    except Exception as e:
                        st["error"] = str(e)
                else:
                    st["error"] = "USB key missing (secure store locked)."
                print(st)
                continue
            # admin required for mutating operations
            if not security.is_admin():
                print("Admin required.")
                continue
            if not secure_store.is_unlocked():
                print("USB key required.")
                continue
            web_cfg = config.get().web.model_dump()
            key_store = ApiKeyStore(secure_store)
            strikes = StrikeManager(secure_store, LockoutConfig.model_validate((web_cfg.get("lockout") or {})))
            from jarvis.core.security_events import SecurityAuditLogger

            audit = SecurityAuditLogger()

            if len(parts) >= 2 and parts[1] == "enable":
                web_cfg["enabled"] = True
                web_cfg["bind_host"] = "127.0.0.1"
                web_cfg["allow_remote"] = False
                config.save_non_sensitive("web.json", web_cfg)
                audit.log(trace_id="cli", severity="INFO", event="web.config", ip=None, endpoint="cli", outcome="enabled", details={"enabled": True})
                print("Web enabled (localhost only). Restart app.py.")
                continue
            if len(parts) >= 2 and parts[1] == "disable":
                web_cfg["enabled"] = False
                config.save_non_sensitive("web.json", web_cfg)
                audit.log(trace_id="cli", severity="INFO", event="web.config", ip=None, endpoint="cli", outcome="disabled", details={"enabled": False})
                print("Web disabled. Restart app.py.")
                continue
            if len(parts) >= 2 and parts[1] == "rotate-key":
                rec = key_store.create_key(scopes=["read", "message", "admin"])
                audit.log(trace_id="cli", severity="HIGH", event="web.key.created", ip=None, endpoint="cli", outcome="ok", details={"key_id": rec["id"]})
                print("New API key created (store this safely; it will not be shown again):")
                print(rec["key"])
                continue
            if len(parts) >= 2 and parts[1] == "list-keys":
                ks = key_store.list_keys()
                for k in ks:
                    print({"id": k.id, "scopes": k.scopes, "revoked": k.revoked, "created_at": k.created_at, "last_used_at": k.last_used_at, "allowed_ips": k.allowed_ips, "lockouts": k.lockouts})
                continue
            if len(parts) >= 3 and parts[1] == "revoke-key":
                kid = parts[2]
                ok = key_store.revoke_key(kid, reason="revoked_by_admin")
                audit.log(trace_id="cli", severity="HIGH", event="web.key.revoked", ip=None, endpoint="cli", outcome="ok" if ok else "not_found", details={"key_id": kid})
                print("Revoked." if ok else "Key not found/already revoked.")
                continue
            if len(parts) >= 3 and parts[1] == "unlock-ip":
                ip = parts[2]
                ok = strikes.unlock_ip(ip)
                audit.log(trace_id="cli", severity="HIGH", event="web.lockout.cleared", ip=ip, endpoint="cli", outcome="ok" if ok else "not_found", details={})
                print("Unlocked." if ok else "No lockout for IP.")
                continue
            if len(parts) >= 2 and parts[1] == "locks":
                print(strikes.get_lockouts())
                continue
            print("Usage: /web status | /web enable | /web disable | /web rotate-key | /web list-keys | /web revoke-key <id> | /web unlock-ip <ip> | /web locks")
            continue
        if text.startswith("/config"):
            parts = text.split()
            if len(parts) == 1 or parts[1] == "status":
                print({"paths": config.open_paths(), "hot_reload": config.get().app.hot_reload})
                continue
            if parts[1] == "open":
                print(config.open_paths())
                continue
            if parts[1] == "validate":
                try:
                    config.validate()
                    print("OK")
                except Exception as e:
                    print(str(e))
                continue
            if parts[1] == "reload":
                ok = config.reload_if_changed()
                print("reloaded" if ok else "no change / rejected")
                continue
            if parts[1] == "diff":
                d = config.diff_since_last_load()
                print(d.changed_files)
                continue
            print("Usage: /config status|open|validate|reload|diff")
            continue
        if text.startswith("/secure"):
            parts = text.split()
            cmd = parts[1] if len(parts) >= 2 else "status"
            if cmd == "status":
                st = secure_store.status()
                print(st.model_dump())
                continue
            if cmd == "keys":
                try:
                    print(secure_store.list_keys())
                except Exception as e:
                    print(str(e))
                continue

            # admin-only operations below
            if not security.is_admin():
                print("Admin required.")
                continue

            if cmd == "get" and len(parts) >= 3:
                key = parts[2]
                show = "--show" in parts
                v = secure_store.get(key)
                if v is None:
                    print("(null)")
                else:
                    print(v if show else "***REDACTED***")
                continue
            if cmd == "set" and len(parts) >= 3:
                key = parts[2]
                val = getpass.getpass(f"Value for {key}: ")
                secure_store.set(key, val, trace_id="cli")
                print("OK")
                continue
            if cmd == "delete" and len(parts) >= 3:
                key = parts[2]
                secure_store.delete(key, trace_id="cli")
                print("OK")
                continue
            if cmd == "backup":
                p = secure_store.backup_now()
                print(p or "no store to backup")
                continue
            if cmd == "restore" and len(parts) >= 3 and parts[2] == "list":
                if os.path.isdir(secure_store.backups_dir):
                    files = [f for f in os.listdir(secure_store.backups_dir) if f.startswith("secure_store.") and f.endswith(".enc")]
                    files.sort(reverse=True)
                    for f in files:
                        print(f)
                else:
                    print("No backups.")
                continue
            if cmd == "restore" and len(parts) >= 3:
                b = parts[2]
                path = b if os.path.isabs(b) else os.path.join(secure_store.backups_dir, b)
                secure_store.restore_backup(path, trace_id="cli")
                print("Restored.")
                continue
            if cmd == "rotate":
                print("Run: python scripts/rotate_usb_key.py (use --apply to swap automatically)")
                continue
            print("Usage: /secure status|keys|get <k> [--show]|set <k>|delete <k>|backup|restore list|restore <backup>|rotate")
            continue
        if text.startswith("/errors"):
            parts = text.split()
            if len(parts) == 1 or (len(parts) >= 2 and parts[1] == "last"):
                n = int(parts[2]) if len(parts) >= 3 else 20
                for e in error_reporter.tail(n):
                    print(e)
                continue
            if len(parts) >= 3 and parts[1] == "show":
                tid = parts[2]
                for e in error_reporter.by_trace_id(tid):
                    print(e)
                continue
            if len(parts) >= 3 and parts[1] == "export":
                path = parts[2]
                import json, os

                os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(error_reporter.tail(1000), f, indent=2, ensure_ascii=False)
                print(f"Exported to {path}")
                continue
            print("Usage: /errors last [n] | /errors show <trace_id> | /errors export <path>")
            continue
        if text.startswith("/health"):
            parts = text.split()
            sub = parts[1] if len(parts) >= 2 else None
            if sub:
                print({"health": telemetry.get_health(subsystem=sub)})
            else:
                snap = telemetry.get_snapshot()
                print(
                    {
                        "uptime_seconds": snap.get("uptime_seconds"),
                        "resources": snap.get("resources"),
                        "health": snap.get("health"),
                    }
                )
            continue
        if text.startswith("/metrics"):
            parts = text.split()
            if len(parts) >= 3 and parts[1] == "export":
                path = parts[2]
                print({"exported": telemetry.export_snapshot(path)})
                continue
            print(telemetry.get_metrics_summary())
            continue
        if text.startswith("/telemetry"):
            parts = text.split()
            if len(parts) == 1 or parts[1] == "status":
                print({"enabled": telemetry.cfg.enabled, "retention_days": telemetry.cfg.retention_days})
                continue
            if parts[1] == "reset":
                if not security.is_admin():
                    print("Admin required.")
                    continue
                telemetry.reset()
                print("Telemetry reset.")
                continue
            print("Usage: /telemetry status | /telemetry reset")
            continue
        if text.startswith("/debug"):
            parts = text.split()
            if len(parts) >= 2 and parts[1] == "enable":
                if not security.is_admin():
                    print("Admin required.")
                    continue
                error_reporter.set_debug_override(True)
                print("Debug enabled (tracebacks may be logged).")
                continue
            if len(parts) >= 2 and parts[1] == "disable":
                if not security.is_admin():
                    print("Admin required.")
                    continue
                error_reporter.set_debug_override(False)
                print("Debug disabled.")
                continue
            print("Usage: /debug enable|disable")
            continue
        if text.startswith("/llm"):
            parts = text.split()
            if len(parts) == 1 or (len(parts) >= 2 and parts[1] == "status"):
                print(llm_lifecycle.get_status() if llm_lifecycle else {"enabled": False})
                continue
            if len(parts) >= 3 and parts[1] == "unload":
                target = parts[2].lower()
                if not llm_lifecycle:
                    print("LLM lifecycle not configured.")
                    continue
                if target == "all":
                    llm_lifecycle.unload_all("manual")
                    print("Unloaded all.")
                    continue
                llm_lifecycle.unload_role(target, reason="manual", trace_id="cli")
                print(f"Unloaded {target}.")
                continue
            if len(parts) >= 4 and parts[1] == "test":
                if not llm_lifecycle:
                    print("LLM lifecycle not configured.")
                    continue
                role = parts[2].lower()
                prompt = text.split(" ", 3)[3]
                from jarvis.core.llm_contracts import LLMRequest, LLMRole, Message, OutputSchema

                schema = OutputSchema.chat_reply
                req = LLMRequest(
                    trace_id="cli",
                    role=LLMRole(role),
                    messages=[Message(role="user", content=prompt)],
                    output_schema=schema,
                    safety={"allowed_intents": [], "denylist_phrases": ["reveal secrets", "system prompt"]},
                    max_tokens=1024 if role == "coder" else 512,
                    temperature=0.2 if role == "coder" else 0.7,
                )
                llm_lifecycle.ensure_role_ready(role, trace_id="cli")
                resp = llm_lifecycle.call(role, req)
                print(resp.model_dump())
                if role == "coder":
                    llm_lifecycle.unload_role("coder", reason="on_demand_complete", trace_id="cli")
                continue
            print("Usage: /llm status | /llm unload chat|coder|all | /llm test chat|coder \"...\"")
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
        controller.request_shutdown(reason="cli_exit", restart=False, argv=sys.argv)
    except Exception:
        pass
    return


if __name__ == "__main__":
    main()

