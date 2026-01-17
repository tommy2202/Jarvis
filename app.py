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
from jarvis.core.modules import ModuleManager
from jarvis.core.limits.limiter import Limiter
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
from jarvis.core.runtime_control import RuntimeController
from jarvis.core.shutdown_orchestrator import ShutdownConfig, ShutdownOrchestrator
from jarvis.core.runtime_state.manager import RuntimeStateManager, RuntimeStateManagerConfig
from jarvis.core.runtime_state.io import dirty_exists
from jarvis.core.flags import FeatureFlagManager
from jarvis.core.lockdown import LockdownManager
from jarvis.core.migrations import VersionRegistry
from jarvis.core.capabilities.loader import validate_and_normalize
from jarvis.core.capabilities.audit import CapabilityAuditLogger
from jarvis.core.capabilities.engine import CapabilityEngine
from jarvis.core.events.bus import EventBus, EventBusConfig, OverflowPolicy
from jarvis.core.events.subscribers import CoreEventJsonlSubscriber
from jarvis.core.ux.primitives import render_events
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
    lockdown_manager: Any | None,
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
        lockdown_manager=lockdown_manager,
    )
    h = WebServerHandle(app=fastapi_app, host=bind_host, port=port, logger=logger, telemetry=telemetry, allow_remote=allow_remote, draining_event=draining_event)
    h.start()
    return h


def main() -> None:
    ap = argparse.ArgumentParser(description="Jarvis (offline-first) CLI/voice/web")
    ap.add_argument("--mode", choices=["text", "voice", "hybrid"], default="hybrid", help="Run mode.")
    ap.add_argument("--ui", action="store_true", help="Launch desktop UI (Tkinter) instead of CLI.")
    ap.add_argument("--force-start", action="store_true", help="Force start even if self-check would block (requires confirmation).")
    ap.add_argument("--safe-mode", action="store_true", help="Start in safe mode (restrictions enabled).")
    ap.add_argument("--diagnostics-only", action="store_true", help="Run startup self-check and exit.")
    args = ap.parse_args()

    logger = setup_logging("logs")
    event_logger = EventLogger("logs/events.jsonl")
    version_registry = VersionRegistry(logger=logger)
    ops = OpsLogger()

    config = get_config(logger=logger, version_registry=version_registry, event_logger=event_logger)
    cfg_obj = config.get()

    # Internal Event Bus (initialized early; in-process only)
    e_cfg = cfg_obj.events.model_dump()
    eb_cfg = EventBusConfig(
        enabled=bool(e_cfg.get("enabled", True)),
        max_queue_size=int(e_cfg.get("max_queue_size", 1000)),
        worker_threads=int(e_cfg.get("worker_threads", 4)),
        overflow_policy=OverflowPolicy(str(e_cfg.get("overflow_policy", "DROP_OLDEST"))),
        shutdown_grace_seconds=float(e_cfg.get("shutdown_grace_seconds", 5)),
        log_dropped_events=bool(e_cfg.get("log_dropped_events", True)),
    )
    event_bus = EventBus(cfg=eb_cfg, logger=logger)
    event_bus.subscribe("*", CoreEventJsonlSubscriber(), priority=100)

    # Persistent runtime state (operational state; no secrets)
    rs_cfg = RuntimeStateManagerConfig.model_validate(cfg_obj.runtime_state.model_dump())
    runtime_state = RuntimeStateManager(cfg=rs_cfg, ops=ops, logger=logger)
    runtime_state.attach(config_manager=config)
    runtime_state.load()
    # Crash markers + restart marker
    try:
        was_dirty = dirty_exists(runtime_state.paths)
    except Exception:
        was_dirty = False
    if was_dirty:
        ops.log(trace_id="startup", event="recovered_from_crash", outcome="dirty_flag_present", details={"runtime_dir": runtime_state.paths.runtime_dir})
    marker = runtime_state.consume_restart_marker()
    if marker:
        runtime_state.set_restart_marker_info(marker)
        ops.log(trace_id=str(marker.get("trace_id") or "startup"), event="restart_complete", outcome="ok", details={"safe_mode": bool(marker.get("safe_mode"))})
        # Safe-mode restart override (local, non-persistent).
        if bool(marker.get("safe_mode", False)):
            defaults = (cfg_obj.runtime.startup or {}).get("safe_mode_defaults") or {"web_enabled": True, "voice_enabled": True, "llm_enabled": True}
            try:
                cfg_obj = cfg_obj.model_copy(deep=True)
                cfg_obj.web.enabled = bool(defaults.get("web_enabled", False))
                cfg_obj.voice.enabled = bool(defaults.get("voice_enabled", False))
                cfg_obj.state_machine.enable_voice = bool(defaults.get("voice_enabled", False))
                cfg_obj.llm.enabled = bool(defaults.get("llm_enabled", False))
                ops.log(trace_id=str(marker.get("trace_id") or "startup"), event="startup_safe_mode", outcome="applied", details=defaults)
            except Exception:
                pass
    runtime_state.mark_dirty_startup()

    # Privacy / GDPR core (data inventory + classification)
    from jarvis.core.privacy.store import PrivacyStore

    privacy_store = PrivacyStore(
        db_path=os.path.join(runtime_state.paths.runtime_dir, "privacy.sqlite"),
        config_manager=config,
        event_bus=event_bus,
        logger=logger,
        version_registry=version_registry,
        event_logger=event_logger,
    )
    from jarvis.core.privacy.dsar import DsarEngine, ModuleHooksRegistry

    dsar_engine = DsarEngine(store=privacy_store, root_path=".", hooks=ModuleHooksRegistry(), logger=logger)

    # Audit Timeline (hash-chained, privacy-safe)
    from jarvis.core.audit.timeline import AuditTimelineManager

    audit = AuditTimelineManager(cfg=cfg_obj.audit.model_dump(), logger=logger, event_bus=event_bus, telemetry=None, ops_logger=ops, privacy_store=privacy_store)
    audit.start()

    # Re-create loggers with privacy inventory wiring for the rest of the process lifetime.
    event_logger = EventLogger("logs/events.jsonl", privacy_store=privacy_store)
    ops = OpsLogger(privacy_store=privacy_store)

    # Capability bus (validated config/capabilities.json)
    cap_raw = config.read_non_sensitive("capabilities.json")
    cap_cfg = validate_and_normalize(cap_raw)
    cap_audit = CapabilityAuditLogger(path=os.path.join("logs", "security.jsonl"), privacy_store=privacy_store)
    cap_engine = CapabilityEngine(cfg=cap_cfg, audit=cap_audit, logger=logger, event_bus=event_bus)

    # Policy engine (config-driven constraints)
    from jarvis.core.policy.engine import PolicyEngine
    from jarvis.core.policy.loader import load_policy_config

    pol_cfg, pol_failsafe, pol_err = load_policy_config(config)
    policy_engine = PolicyEngine(cfg=pol_cfg, failsafe=pol_failsafe, fail_message=pol_err, event_bus=event_bus)
    cap_engine.policy_engine = policy_engine

    telemetry_cfg = TelemetryConfig.model_validate(cfg_obj.telemetry.model_dump())
    telemetry = TelemetryManager(cfg=telemetry_cfg, logger=logger, root_path=".", privacy_store=privacy_store)
    telemetry.attach(config_manager=config)
    runtime_state.attach(telemetry=telemetry)
    event_bus.telemetry = telemetry
    telemetry.attach(event_bus=event_bus)
    # Attach telemetry to audit timeline (optional counters)
    audit.telemetry = telemetry

    # Resource Governor (local-only admission control for heavy operations)
    from jarvis.core.resources.governor import ResourceGovernor
    from jarvis.core.resources.models import ResourceGovernorConfig

    rg_cfg = ResourceGovernorConfig.model_validate(cfg_obj.resources.model_dump())
    resource_governor = ResourceGovernor(cfg=rg_cfg, telemetry=telemetry, event_bus=event_bus, runtime_state=runtime_state, logger=logger)
    telemetry.attach(resource_governor=resource_governor)
    # Make capability engine consult it (single enforcement still in dispatcher via cap engine)
    cap_engine.resource_governor = resource_governor

    # Error handling + recovery subsystem
    recovery_cfg = RecoveryConfig.model_validate(cfg_obj.recovery.model_dump())
    error_reporter = ErrorReporter(
        cfg=ErrorReporterConfig(include_tracebacks=bool(recovery_cfg.debug.get("include_tracebacks", False))),
        telemetry=telemetry,
        runtime_state=runtime_state,
        event_bus=event_bus,
        privacy_store=privacy_store,
    )
    recovery_policy = RecoveryPolicy(recovery_cfg)
    breakers_map = {}
    for name, bc in (recovery_cfg.circuit_breakers or {}).items():
        try:
            def _on_breaker_change(_st, br, _name=name):  # noqa: ANN001
                try:
                    from jarvis.core.runtime_state.models import BreakerSnapshot

                    s = br.snapshot()
                    runtime_state.record_breaker_state(
                        _name,
                        BreakerSnapshot(
                            state=str(s.get("state") or "UNKNOWN"),
                            opened_at=s.get("opened_at"),
                            cooldown_until=s.get("cooldown_until"),
                            failure_count_window=int(s.get("failure_count_window") or 0),
                        ),
                    )
                except Exception:
                    pass

            breakers_map[name] = CircuitBreaker(
                BreakerConfig(
                    failures=int(bc.get("failures", 3)),
                    window_seconds=int(bc.get("window_seconds", 30)),
                    cooldown_seconds=int(bc.get("cooldown_seconds", 30)),
                ),
                on_state_change=_on_breaker_change,
            )
        except Exception:
            continue
    breaker_registry = BreakerRegistry(breakers_map)
    # Restore breaker states from persistent runtime state (best effort)
    try:
        snaps = runtime_state.get_snapshot().get("breakers") or {}
        breaker_registry.restore(snaps)
    except Exception:
        pass

    secure_store = SecureStore(
        usb_key_path=cfg_obj.security.usb_key_path,
        store_path=cfg_obj.security.secure_store_path,
        meta_path=os.path.join("secure", "store.meta.json"),
        backups_dir=os.path.join("secure", "backups"),
        max_backups=int(cfg_obj.security.secure_store_backup_keep),
        max_bytes=int(cfg_obj.security.secure_store_max_bytes),
        read_only=bool(cfg_obj.security.secure_store_read_only),
    )
    try:
        privacy_store.attach_secure_store(secure_store)
    except Exception:
        pass
    security = SecurityManager(secure_store=secure_store, admin_session=AdminSession(timeout_seconds=int(cfg_obj.security.admin_session_timeout_seconds)))
    telemetry.attach(secure_store=secure_store, security_manager=security)
    runtime_state.attach(security_manager=security, secure_store=secure_store)

    # Feature flags (admin-only, auditable)
    from jarvis.core.security_events import SecurityAuditLogger

    feature_flags = FeatureFlagManager(security_manager=security, audit_logger=SecurityAuditLogger(), event_bus=event_bus, logger=logger)
    lockdown_manager = LockdownManager(security_manager=security, audit_logger=SecurityAuditLogger(), event_bus=event_bus, logger=logger)

    # Identity manager (user attribution + active user/session)
    from jarvis.core.identity.manager import IdentityManager

    identity_manager = IdentityManager(privacy_store=privacy_store, security_manager=security, logger=logger)
    _ = identity_manager.load_or_create_default_user()

    # Backup manager (zip exports + manifests)
    from jarvis.core.backup.api import BackupManager

    backup_mgr = BackupManager(
        cfg=cfg_obj.backup.model_dump(),
        root_dir=".",
        config_manager=config,
        secure_store=secure_store,
        runtime_state=runtime_state,
        audit_timeline=audit,
        telemetry=telemetry,
    )

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

    # Module discovery + install/enable registry (no-import scanning).
    # This runs before any module code is imported and is audit-logged via event bus.
    module_manager = ModuleManager(
        config_manager=config,
        modules_root=os.path.join("jarvis", "modules"),
        runtime_dir=str((cfg_obj.runtime_state.paths or {}).get("runtime_dir") or "runtime"),
        event_bus=event_bus,
        logger=logger,
        security_manager=security,
    )
    try:
        module_manager.scan(trace_id="startup")
    except Exception as e:
        logger.warning(f"Module scan failed (continuing): {e}")

    # Module registry
    registry = ModuleRegistry()
    for entry in modules_registry_cfg.get("modules") or []:
        if not isinstance(entry, dict) or not entry.get("enabled", False):
            continue
        # Hard gate: only load legacy modules if installed+enabled in modules.json registry.
        # (This preserves legacy config/modules_registry.json while preventing bypass.)
        try:
            module_path = str(entry.get("module") or "")
            legacy_id = module_path.split(".")[-1] if module_path else ""
            if legacy_id and not module_manager.is_module_enabled(legacy_id):
                continue
        except Exception:
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
    llm_lifecycle = LLMLifecycleController(policy=llm_policy, event_logger=event_logger, logger=logger, telemetry=telemetry, event_bus=event_bus, resource_governor=resource_governor) if (llm_policy.roles and llm_policy.enabled) else None
    telemetry.attach(llm_lifecycle=llm_lifecycle)
    runtime_state.attach(llm_lifecycle=llm_lifecycle)
    # Allow governor to reclaim LLM under pressure
    resource_governor.llm_lifecycle = llm_lifecycle

    # Stage-B router uses lifecycle if available; otherwise stays in safe mock mode.
    stage_b = StageBLLMRouter(StageBLegacyConfig(mock_mode=True), lifecycle=llm_lifecycle)

    policy = PermissionPolicy(intents=dict(perms_cfg.get("intents") or {}))
    limiter = Limiter(config_manager=config)
    dispatcher = Dispatcher(
        registry=registry,
        policy=policy,
        security=security,
        event_logger=event_logger,
        logger=logger,
        error_reporter=error_reporter,
        telemetry=telemetry,
        capability_engine=cap_engine,
        breaker_registry=breaker_registry,
        secure_store=secure_store,
        event_bus=event_bus,
        policy_engine=policy_engine,
        module_manager=module_manager,
        privacy_store=privacy_store,
        identity_manager=identity_manager,
        limiter=limiter,
        feature_flags=feature_flags,
        lockdown_manager=lockdown_manager,
    )

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
        core_fact_fuzzy_cfg=dict(getattr(cfg_obj.ui, "core_fact_fuzzy", {}) or {}),
        lockdown_manager=lockdown_manager,
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
        event_bus=event_bus,
        resource_governor=resource_governor,
    )
    dispatcher.job_manager = job_manager
    telemetry.attach(job_manager=job_manager)
    runtime_state.attach(job_manager=job_manager)

    # Register allowlisted job kinds (no shell, no arbitrary code).
    job_manager.register_job("system.sleep", job_system_sleep, schema_model=SleepArgs, required_capabilities=["CAP_RUN_SUBPROCESS"])
    job_manager.register_job("system.health_check", job_system_health_check, required_capabilities=["CAP_RUN_SUBPROCESS"])
    job_manager.register_job(
        "system.write_test_file",
        job_system_write_test_file,
        schema_model=WriteTestFileArgs,
        required_capabilities=["CAP_RUN_SUBPROCESS", "CAP_WRITE_FILES"],
    )
    job_manager.register_job("system.cleanup_jobs", job_system_cleanup_jobs, required_capabilities=["CAP_RUN_SUBPROCESS"])
    job_manager.register_job("system.sleep_llm", job_system_sleep_llm, required_capabilities=["CAP_RUN_SUBPROCESS"])
    # Prove governor gating end-to-end (heavy core job kind; not a feature module).
    job_manager.register_job("system.test_heavy", job_system_sleep, schema_model=SleepArgs, required_capabilities=["CAP_RUN_SUBPROCESS"], heavy=True)

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

    # --- Startup self-check (deterministic, before starting web/voice/UI) ---
    from jarvis.core.startup.runner import StartupSelfCheckRunner, StartupFlags
    from jarvis.core.startup.reporting import to_human

    runner = StartupSelfCheckRunner(ops=ops, logger=logger, event_bus=event_bus, telemetry=telemetry)
    # Secure store mode from phase 2 is derived from secure_store.status(); safe_mode uses args + dirty shutdown.
    core_ready = {
        "capability_ok": True,
        "event_bus_ok": True,
        "telemetry_ok": True,
        "job_manager_ok": job_manager is not None,
        "error_policy_ok": True,
        "runtime_ok": True,
    }
    result = runner.run(
        flags=StartupFlags(force_start=bool(args.force_start), safe_mode=bool(args.safe_mode), diagnostics_only=bool(args.diagnostics_only)),
        root_dir=".",
        logs_dir="logs",
        config_manager=config,
        secure_store=secure_store,
        runtime_state=runtime_state,
        cfg_obj=cfg_obj,
        capabilities_cfg_raw=cap_raw,
        core_ready=core_ready,
        dispatcher=dispatcher,
        capability_engine=cap_engine,
        policy_engine=policy_engine,
        privacy_store=privacy_store,
        modules_root=os.path.join("jarvis", "modules"),
    )
    try:
        runtime_state.record_startup_self_check(
            overall_status=result.overall_status.value,
            safe_mode=bool(result.started_in_safe_mode),
            runtime_fingerprint=result.runtime_fingerprint,
            warnings=result.warnings,
            blocking_reasons=result.blocking_reasons,
        )
    except Exception:
        pass
    if bool(args.diagnostics_only):
        print(to_human(result))
        return
    if result.overall_status.value == "BLOCKED":
        print(to_human(result))
        raise SystemExit(2)

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

    # Safe mode currently only applied via restart marker (stored in runtime_state)
    safe_mode_active = bool((runtime_state.get_snapshot().get("crash") or {}).get("restart_marker", {}).get("safe_mode", False)) if runtime_state else False
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
        runtime_state=runtime_state,
        error_reporter=error_reporter,
        recovery_policy=recovery_policy,
        breakers=breaker_registry,
        safe_mode=safe_mode_active,
        event_bus=event_bus,
        audit_timeline=audit,
        module_manager=module_manager,
        privacy_store=privacy_store,
        dsar_engine=dsar_engine,
        lockdown_manager=lockdown_manager,
    )
    runtime.start()
    telemetry.attach(runtime=runtime, voice_adapter=voice_adapter, tts_adapter=tts_adapter)
    runtime_state.attach(runtime=runtime)

    web_handle = _start_web_thread(jarvis, security, secure_store, config, event_logger, logger, job_manager, runtime, telemetry, lockdown_manager)

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
    orchestrator.event_bus = event_bus
    controller = RuntimeController(runtime_cfg=cfg_obj.runtime.model_dump(), ops=ops, logger=logger, orchestrator=orchestrator, runtime_state=runtime_state, security_manager=security)

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
        if text.startswith("/lockdown"):
            parts = text.split()
            if len(parts) == 1 or parts[1] == "status":
                print(runtime.get_status().get("lockdown") or {})
                continue
            if parts[1] in {"exit", "off", "disable"}:
                if not security.is_admin():
                    print("Admin required.")
                    continue
                ok = runtime.exit_lockdown(trace_id="cli")
                print("Lockdown exited." if ok else "Lockdown not active.")
                continue
            print("Usage: /lockdown status|exit")
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
            if len(parts) >= 3 and parts[1] == "resume":
                if not security.is_admin():
                    print("Admin required.")
                    continue
                jid = parts[2]
                ok = job_manager.resume_job(jid, is_admin=True, trace_id="cli")
                print("Resumed." if ok else "Unable to resume.")
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
                    dispatch_ctx = {
                        "source": "cli",
                        "client": {"name": "cli", "id": "stdin"},
                        "safe_mode": bool(getattr(runtime, "safe_mode", False)),
                        "shutting_down": bool(controller.get_shutdown_status().get("in_progress")) if controller else False,
                    }
                    res = dispatcher.submit_job("cli", "system.health_check", {}, dispatch_ctx)
                    print(f"Submitted: {res.job_id}" if res.ok else res.reply)
                    continue
                if name == "cleanup":
                    dispatch_ctx = {
                        "source": "cli",
                        "client": {"name": "cli", "id": "stdin"},
                        "safe_mode": bool(getattr(runtime, "safe_mode", False)),
                        "shutting_down": bool(controller.get_shutdown_status().get("in_progress")) if controller else False,
                    }
                    res = dispatcher.submit_job("cli", "system.cleanup_jobs", {}, dispatch_ctx)
                    print(f"Submitted: {res.job_id}" if res.ok else res.reply)
                    continue
                print("Unknown run target. Use: health_check | cleanup")
                continue
            print("Usage: /jobs list [STATUS] | /jobs show <id> | /jobs cancel <id> | /jobs resume <id> | /jobs tail <id> [n] | /jobs run health_check|cleanup")
            continue
        if text.startswith("/resources"):
            parts = text.split()
            if len(parts) == 1 or parts[1] == "status":
                print(resource_governor.get_status())
                continue
            if len(parts) >= 2 and parts[1] == "snapshot":
                print(resource_governor.get_snapshot())
                continue
            if len(parts) >= 2 and parts[1] == "policy":
                st = resource_governor.get_status()
                print({"budgets": st.get("budgets"), "policy": st.get("policy"), "throttles": st.get("throttles"), "safe_mode": st.get("safe_mode")})
                continue
            if len(parts) >= 3 and parts[1] == "safe_mode":
                if not security.is_admin():
                    print("Admin required.")
                    continue
                val = parts[2].lower()
                if val == "on":
                    resource_governor.set_forced_safe_mode(True, reason="cli_forced")
                    print("Safe mode forced ON.")
                    continue
                if val == "off":
                    resource_governor.set_forced_safe_mode(False, reason="cli_forced")
                    print("Safe mode forced OFF.")
                    continue
                print("Usage: /resources safe_mode on|off")
                continue
            if len(parts) >= 2 and parts[1] == "test_heavy":
                dispatch_ctx = {
                    "source": "cli",
                    "client": {"name": "cli", "id": "stdin"},
                    "safe_mode": bool(getattr(runtime, "safe_mode", False)),
                    "shutting_down": bool(controller.get_shutdown_status().get("in_progress")) if controller else False,
                }
                res = dispatcher.submit_job("cli", "system.test_heavy", {"seconds": 2.0}, dispatch_ctx)
                print(f"Submitted heavy job: {res.job_id}" if res.ok else res.reply)
                continue
            print("Usage: /resources status|snapshot|policy|safe_mode on|off|test_heavy")
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
        if text.startswith("/policy"):
            parts = text.split()
            if len(parts) == 1 or parts[1] == "status":
                print(policy_engine.status())
                continue
            if len(parts) >= 2 and parts[1] == "list":
                for r in policy_engine.rules():
                    print(f"{r.get('priority'):3d} | {r.get('id')} | {r.get('effect')} | {r.get('description')}")
                continue
            if len(parts) >= 3 and parts[1] == "show":
                rid = parts[2]
                print(policy_engine.get_rule(rid) or {"error": "not found"})
                continue
            if len(parts) >= 3 and parts[1] == "eval":
                iid = parts[2]
                src = "cli"
                is_admin = False
                # time is controlled by engine matcher in tests; here we use real time
                for p in parts[3:]:
                    if p.startswith("--source="):
                        src = p.split("=", 1)[1]
                    if p.startswith("--admin="):
                        is_admin = p.split("=", 1)[1].lower() == "true"
                from jarvis.core.policy.models import PolicyContext

                ctx = PolicyContext(trace_id="policy", intent_id=iid, source=src, is_admin=is_admin, required_capabilities=cap_engine.get_intent_requirements().get(iid) or [])
                dec = policy_engine.evaluate(ctx)
                print(dec.model_dump())
                continue
            if len(parts) >= 2 and parts[1] == "reload":
                pol_cfg, pol_failsafe, pol_err = load_policy_config(config)
                policy_engine.cfg = pol_cfg
                policy_engine._failsafe = bool(pol_failsafe)  # noqa: SLF001
                policy_engine._fail_message = str(pol_err or "")  # noqa: SLF001
                print(policy_engine.status())
                continue
            if len(parts) >= 2 and parts[1] == "enable":
                if not security.is_admin():
                    print("Admin required.")
                    continue
                raw = config.read_non_sensitive("policy.json")
                raw["enabled"] = True
                config.save_non_sensitive("policy.json", raw)
                pol_cfg, pol_failsafe, pol_err = load_policy_config(config)
                policy_engine.cfg = pol_cfg
                policy_engine._failsafe = bool(pol_failsafe)  # noqa: SLF001
                policy_engine._fail_message = str(pol_err or "")  # noqa: SLF001
                print("Enabled.")
                continue
            if len(parts) >= 2 and parts[1] == "disable":
                if not security.is_admin():
                    print("Admin required.")
                    continue
                raw = config.read_non_sensitive("policy.json")
                raw["enabled"] = False
                config.save_non_sensitive("policy.json", raw)
                pol_cfg, pol_failsafe, pol_err = load_policy_config(config)
                policy_engine.cfg = pol_cfg
                policy_engine._failsafe = bool(pol_failsafe)  # noqa: SLF001
                policy_engine._fail_message = str(pol_err or "")  # noqa: SLF001
                print("Disabled.")
                continue
            print("Usage: /policy status|list|show <id>|eval <intent_id> --source=.. --admin=true|false|reload|enable|disable")
            continue
        if text.startswith("/caps"):
            parts = text.split()
            if len(parts) == 1 or parts[1] == "list":
                caps = cap_engine.get_capabilities()
                for cid in sorted(caps.keys()):
                    c = caps[cid]
                    print(f"{cid} | default={c['default_policy']} | sensitivity={c['sensitivity']} | requires_admin={c['requires_admin']}")
                continue
            if len(parts) >= 3 and parts[1] == "show":
                cid = parts[2]
                caps = cap_engine.get_capabilities()
                print(caps.get(cid) or {"error": "not found"})
                continue
            if len(parts) >= 3 and parts[1] == "intent":
                iid = parts[2]
                reqs = cap_engine.get_intent_requirements().get(iid)
                print({"intent_id": iid, "required_caps": reqs})
                continue
            if len(parts) >= 3 and parts[1] == "eval":
                iid = parts[2]
                src = "cli"
                is_admin = False
                safe_mode = False
                shutting_down = False
                for p in parts[3:]:
                    if p.startswith("--source="):
                        src = p.split("=", 1)[1]
                    if p.startswith("--admin="):
                        is_admin = p.split("=", 1)[1].lower() == "true"
                    if p.startswith("--safe_mode="):
                        safe_mode = p.split("=", 1)[1].lower() == "true"
                    if p.startswith("--shutting_down="):
                        shutting_down = p.split("=", 1)[1].lower() == "true"
                from jarvis.core.capabilities.models import RequestContext, RequestSource

                ctx = RequestContext(
                    trace_id="caps",
                    source=RequestSource(src),
                    is_admin=is_admin,
                    safe_mode=safe_mode,
                    shutting_down=shutting_down,
                    subsystem_health={"breakers": breaker_registry.status()},
                    intent_id=iid,
                    secure_store_mode=(secure_store.status().mode.value if secure_store else None),
                )
                dec = cap_engine.evaluate(ctx)
                print(dec.model_dump())
                continue
            if len(parts) >= 3 and parts[1] == "export":
                path = parts[2]
                import json, os

                os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
                payload = {"capabilities": cap_engine.get_capabilities(), "intent_requirements": cap_engine.get_intent_requirements(), "recent_decisions": cap_engine.audit.recent(50)}
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(payload, f, indent=2, ensure_ascii=False)
                print(f"Exported to {path}")
                continue
            print("Usage: /caps list | /caps show <cap_id> | /caps intent <intent_id> | /caps eval <intent_id> --source=cli|web|voice|ui --admin=true|false --safe_mode=true|false --shutting_down=true|false | /caps export <path>")
            continue
        if text.startswith("/modules"):
            parts = text.split()
            cmd = parts[1] if len(parts) >= 2 else "list"
            if cmd == "list":
                from jarvis.core.modules.cli import modules_list_lines

                for line in modules_list_lines(module_manager=module_manager, trace_id="cli"):
                    print(line)
                continue
            if cmd == "scan":
                print(module_manager.scan(trace_id="cli"))
                continue
            if cmd == "show" and len(parts) >= 3:
                mid = parts[2]
                from jarvis.core.modules.cli import modules_show_payload

                print(modules_show_payload(module_manager=module_manager, module_id=mid, trace_id="cli"))
                continue
            if cmd in {"enable", "disable"} and len(parts) >= 3:
                mid = parts[2]
                if not security.is_admin():
                    print("Admin required.")
                    continue
                ok = module_manager.enable(mid, trace_id="cli") if cmd == "enable" else module_manager.disable(mid, trace_id="cli")
                print("OK" if ok else "Failed")
                continue
            if cmd == "export" and len(parts) >= 3:
                out_path = parts[2]
                print({"exported": module_manager.export(out_path)})
                continue
            print("Usage: /modules list | /modules scan | /modules show <id> | /modules enable <id> | /modules disable <id> | /modules export <path>")
            continue
        if text.startswith("/privacy"):
            parts = text.split()
            cmd = parts[1] if len(parts) >= 2 else "status"
            if cmd == "status":
                prefs = privacy_store.get_preferences(user_id="default")
                cons = {}
                for scope in sorted((privacy_store._privacy_cfg_raw().get("default_consent_scopes") or {}).keys()):  # noqa: SLF001
                    c = privacy_store.get_consent(user_id="default", scope=scope)
                    cons[scope] = bool(c.granted) if c else False
                print(
                    {
                        "db": os.path.join(runtime_state.paths.runtime_dir, "privacy.sqlite").replace("\\", "/"),
                        "user_id": "default",
                        "preferences": prefs.model_dump(),
                        "consent": cons,
                    }
                )
                continue
            if cmd == "dsar":
                sub = parts[2] if len(parts) >= 3 else "help"
                if sub == "request" and len(parts) >= 4:
                    kind = parts[3]
                    rid = dsar_engine.request(user_id="default", request_type=kind, payload={}, trace_id="cli")
                    print({"request_id": rid, "type": kind})
                    continue
                if sub == "status" and len(parts) >= 4:
                    rid = parts[3]
                    req = dsar_engine.get(rid)
                    print(req.model_dump() if req else {"error": "not found"})
                    continue
                if sub == "run" and len(parts) >= 4:
                    if not security.is_admin():
                        print("Admin required (CAP_ADMIN_ACTION).")
                        continue
                    rid = parts[3]
                    try:
                        req = dsar_engine.run(request_id=rid, actor_is_admin=True, trace_id="cli")
                        print(req.model_dump())
                    except Exception as e:
                        print({"error": str(e)})
                    continue
                if sub == "export-open" and len(parts) >= 4:
                    rid = parts[3]
                    req = dsar_engine.get(rid)
                    if not req or not req.export_path:
                        print({"error": "no export available"})
                        continue
                    print({"export_path": req.export_path})
                    continue
                print("Usage: /privacy dsar request export|delete|restrict|correct | /privacy dsar status <id> | /privacy dsar run <id> | /privacy dsar export-open <id>")
                continue
            if cmd == "consent" and len(parts) >= 4 and parts[2] in {"grant", "revoke"}:
                action = parts[2]
                scope = parts[3]
                is_admin = bool(security.is_admin())
                if scope.strip().lower() in getattr(privacy_store, "SENSITIVE_SCOPES", set()) and not is_admin:
                    print("Admin required.")
                    continue
                ok = privacy_store.set_consent(user_id="default", scope=scope, granted=(action == "grant"), trace_id="cli", actor_is_admin=is_admin)
                print("OK" if ok else "Failed")
                continue
            if cmd == "retention" and len(parts) >= 3 and parts[2] == "list":
                rows = privacy_store.list_retention_policies()
                out = []
                for p in rows:
                    if not isinstance(p, dict):
                        continue
                    pid = f"{str(p.get('data_category') or '').upper()}:{str(p.get('sensitivity') or '').upper()}"
                    out.append({"policy_id": pid, "ttl_days": p.get("ttl_days"), "keep_forever": bool(p.get("keep_forever", False))})
                print({"policies": out})
                continue
            if cmd == "retention" and len(parts) >= 3 and parts[2] == "run":
                res = privacy_store.retention_run(trace_id="cli")
                print(res)
                continue
            if cmd == "retention" and len(parts) >= 3 and parts[2] == "pending":
                rows = privacy_store.retention_pending(limit=200)
                print({"pending": rows})
                continue
            if cmd == "retention" and len(parts) >= 4 and parts[2] in {"approve", "deny"}:
                if not security.is_admin():
                    print("Admin required (CAP_ADMIN_ACTION).")
                    continue
                aid = parts[3]
                try:
                    ok = privacy_store.retention_approve(action_id=aid, trace_id="cli", actor_is_admin=True) if parts[2] == "approve" else privacy_store.retention_deny(action_id=aid, trace_id="cli", actor_is_admin=True)
                except Exception:
                    ok = False
                print("OK" if ok else "Failed")
                continue
            if cmd == "retention" and len(parts) >= 5 and parts[2] == "set":
                if not security.is_admin():
                    print("Admin required (CAP_ADMIN_ACTION).")
                    continue
                pid = parts[3]
                ttl = int(parts[4])
                try:
                    ok = privacy_store.set_retention_ttl_days(policy_id=pid, ttl_days=ttl, trace_id="cli", actor_is_admin=True)
                except Exception:
                    ok = False
                print("OK" if ok else "Failed")
                continue
            print("Usage: /privacy status | /privacy consent grant <scope> | /privacy consent revoke <scope> | /privacy retention list | /privacy retention run | /privacy retention pending | /privacy retention approve <id> | /privacy retention deny <id> | /privacy retention set <policy_id> <ttl_days>")
            continue
        if text.startswith("/user"):
            parts = text.split()
            cmd = parts[1] if len(parts) >= 2 else "status"
            if cmd in {"status", "whoami"}:
                u = identity_manager.get_active_user()
                sess = identity_manager.active_session()
                print({"user": u.model_dump(), "admin": bool(security.is_admin()), "session": (sess.model_dump() if sess else None)})
                continue
            if cmd == "switch" and len(parts) >= 3:
                if not security.is_admin():
                    print("Admin required.")
                    continue
                uid = parts[2]
                try:
                    u2 = identity_manager.switch_active_user(uid)
                    print({"switched_to": u2.model_dump()})
                except Exception as e:
                    print({"error": str(e)})
                continue
            print("Usage: /user status | /user whoami | /user switch <user_id>")
            continue
        if text.startswith("/audit"):
            from jarvis.core.audit.formatter import format_line

            parts = text.split()
            if len(parts) == 1 or parts[1] == "tail":
                n = int(parts[2]) if len(parts) >= 3 else 20
                for line in audit.tail_formatted(n=n):
                    print(line)
                continue
            if len(parts) >= 2 and parts[1] == "integrity":
                rep = audit.verify_integrity(limit_last_n=int((cfg_obj.audit.integrity or {}).get("verify_last_n", 2000)))
                print(rep.model_dump())
                continue
            if len(parts) >= 3 and parts[1] == "show":
                ev = audit.get_event(parts[2])
                print(ev.model_dump() if ev else {"error": "not found"})
                continue
            if len(parts) >= 2 and parts[1] == "query":
                # minimal flag parser: --since= --until= --category= --outcome= --source= --limit=
                filters: dict = {"limit": 50}
                for p in parts[2:]:
                    if p.startswith("--since="):
                        filters["since"] = float(p.split("=", 1)[1])
                    if p.startswith("--until="):
                        filters["until"] = float(p.split("=", 1)[1])
                    if p.startswith("--category="):
                        filters["category"] = p.split("=", 1)[1]
                    if p.startswith("--outcome="):
                        filters["outcome"] = p.split("=", 1)[1]
                    if p.startswith("--source="):
                        filters["actor_source"] = p.split("=", 1)[1]
                    if p.startswith("--limit="):
                        filters["limit"] = int(p.split("=", 1)[1])
                rows = audit.list_events(**filters)
                for ev in reversed(rows):
                    print(format_line(ev))
                continue
            if len(parts) >= 4 and parts[1] == "export":
                fmt = parts[2]
                out_path = parts[3]
                filters: dict = {"limit": int((cfg_obj.audit.export or {}).get("max_rows", 20000))}
                if fmt == "json":
                    print(audit.export_json(out_path, filters=filters))
                    continue
                if fmt == "csv":
                    print(audit.export_csv(out_path, filters=filters))
                    continue
                print("Usage: /audit export json|csv <path>")
                continue
            if len(parts) >= 2 and parts[1] == "purge":
                if not security.is_admin():
                    print("Admin required.")
                    continue
                res = audit.purge_and_compact()
                print(res)
                continue
            print("Usage: /audit tail [n] | /audit query [--since=.. --category=.. --outcome=.. --source=.. --limit=N] | /audit show <id> | /audit export json|csv <path> | /audit integrity | /audit purge")
            continue
        if text.startswith("/backup"):
            parts = text.split()
            if len(parts) == 1 or parts[1] == "list":
                print(backup_mgr.list_backups())
                continue
            if len(parts) >= 2 and parts[1] == "create":
                profile = parts[2] if len(parts) >= 3 and not parts[2].startswith("--") else "standard"
                out_dir = None
                for p in parts[2:]:
                    if p.startswith("--path"):
                        # allow "--path dir" pattern
                        pass
                # simple parse: --path=<dir>
                for p in parts[2:]:
                    if p.startswith("--path="):
                        out_dir = p.split("=", 1)[1]
                path = backup_mgr.create_backup(profile=profile, out_dir=out_dir)
                print(path)
                continue
            if len(parts) >= 3 and parts[1] == "verify":
                print(backup_mgr.verify_backup(parts[2]))
                continue
            if len(parts) >= 3 and parts[1] == "export" and parts[2] == "support":
                days = int((cfg_obj.backup.support_bundle or {}).get("default_days", 7))
                out_dir = None
                for p in parts[3:]:
                    if p.startswith("--days="):
                        days = int(p.split("=", 1)[1])
                    if p.startswith("--path="):
                        out_dir = p.split("=", 1)[1]
                print(backup_mgr.export_support_bundle(days=days, out_dir=out_dir))
                continue
            if len(parts) >= 3 and parts[1] == "restore":
                if not security.is_admin():
                    print("Admin required.")
                    continue
                zip_path = parts[2]
                mode = "all"
                apply = False
                dry = True
                for p in parts[3:]:
                    if p.startswith("--mode="):
                        mode = p.split("=", 1)[1]
                    if p == "--apply":
                        apply = True
                        dry = False
                    if p == "--dry-run":
                        dry = True
                        apply = False
                if apply:
                    ans = input("Apply restore? This will overwrite files. (y/N) ").strip().lower()
                    if ans != "y":
                        print("Canceled.")
                        continue
                print(backup_mgr.restore(zip_path, mode=mode, dry_run=dry, apply=apply))
                continue
            print("Usage: /backup create [minimal|standard|full] [--path=<dir>] | /backup verify <zip> | /backup list | /backup export support [--days=N] [--path=<dir>] | /backup restore <zip> [--dry-run|--apply] [--mode=config|runtime|secure|all]")
            continue
        if text.startswith("/events"):
            parts = text.split()
            if len(parts) == 1 or parts[1] == "status":
                print({"enabled": event_bus.cfg.enabled, "accepting": True, "queue_depth": event_bus.get_stats().get("queue_depth")})
                continue
            if parts[1] == "stats":
                print(event_bus.get_stats())
                continue
            if parts[1] == "list-subscribers":
                print(event_bus.list_subscribers())
                continue
            if parts[1] == "enable":
                event_bus.set_enabled(True)
                print("enabled")
                continue
            if parts[1] == "disable":
                event_bus.set_enabled(False)
                print("disabled")
                continue
            if parts[1] == "dump" and len(parts) >= 3:
                if not security.is_admin():
                    print("Admin required.")
                    continue
                path = parts[2]
                import json, os

                os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(event_bus.dump_recent(500), f, indent=2, ensure_ascii=False)
                print(f"Exported to {path}")
                continue
            print("Usage: /events status|stats|list-subscribers|enable|disable|dump <path>")
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
            ok = runtime.admin_unlock(pw)
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
            if res:
                messages = render_events(res.get("ux_events"))
                if not messages:
                    messages = [str(res.get("reply") or "")]
                for msg in messages:
                    if msg:
                        print(msg)
            else:
                print("...")
        time.sleep(0.01)

    try:
        controller.request_shutdown(reason="cli_exit", restart=False, argv=sys.argv)
    except Exception:
        pass
    return


if __name__ == "__main__":
    main()

