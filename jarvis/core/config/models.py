from __future__ import annotations

import ipaddress
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator


class AppFileConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    config_version: int = Field(default=2, ge=1)
    created_at: str = "1970-01-01T00:00:00Z"
    last_migrated_at: str = "1970-01-01T00:00:00Z"
    backups: Dict[str, Any] = Field(default_factory=lambda: {"max_backups_per_file": 10})
    hot_reload: Dict[str, Any] = Field(default_factory=lambda: {"enabled": False, "debounce_ms": 500, "poll_interval_ms": 500})


class SecurityConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    usb_key_path: str = r"E:\JARVIS_KEY.bin"
    secure_store_path: str = "secure/secure_store.enc"
    secure_store_read_only: bool = False
    secure_store_max_bytes: int = 65536
    secure_store_backup_keep: int = 10
    admin_session_timeout_seconds: int = 900
    router_confidence_threshold: float = 0.55
    llm: Dict[str, Any] = Field(default_factory=dict)  # legacy block (not used for lifecycle)


class VoiceConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool = False
    wake_word_engine: str = "porcupine"
    wake_word: str = "jarvis"
    mic_device_index: Optional[int] = None
    stt_backend_primary: str = "vosk"
    stt_backend_fallback: str = "faster_whisper"
    tts_backend_primary: str = "sapi"
    tts_backend_fallback: str = "pyttsx3"
    listen_seconds: int = 8
    sample_rate: int = 16000
    idle_sleep_seconds: int = 45
    confirm_beep: bool = True
    audio_retention_files: int = 25
    allow_voice_admin_unlock: bool = False
    thinking_timeout_seconds: int = 15


class ModelsConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    vosk_model_path: str = ""
    faster_whisper_model_path: str = ""


class JobsConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    max_concurrent_jobs: int = 1
    default_timeout_seconds: int = 600
    retention_max_jobs: int = 200
    retention_days: int = 30
    poll_interval_ms: int = 200


class WebConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: int = Field(default=1, ge=1, le=10)
    enabled: bool = False
    bind_host: str = "127.0.0.1"
    port: int = 8000
    allow_remote: bool = False
    allowed_origins: List[str] = Field(default_factory=list)
    max_request_bytes: int = 32768
    rate_limits: Dict[str, int] = Field(default_factory=lambda: {"per_ip_per_minute": 60, "per_key_per_minute": 30, "admin_per_minute": 5})
    lockout: Dict[str, int] = Field(default_factory=lambda: {"strike_threshold": 5, "lockout_minutes": 15, "permanent_after": 3})
    admin: Dict[str, Any] = Field(default_factory=lambda: {"allow_remote_unlock": False, "allowed_admin_ips": ["127.0.0.1"]})
    enable_web_ui: bool = True


class TelemetryConfigFile(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool = True
    poll_interval_seconds: float = 5.0
    sample_interval_seconds: float = 5.0
    max_samples_per_histogram: int = 200
    retention_days: int = 14
    thresholds: Dict[str, float] = Field(
        default_factory=lambda: {
            "cpu_warn_percent": 85,
            "ram_warn_percent": 85,
            "disk_warn_percent_used": 90,
            "gpu_vram_warn_percent": 90,
        }
    )
    gpu: Dict[str, Any] = Field(default_factory=lambda: {"enable_nvml": True})


class ResourcesConfigFile(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool = True
    sample_interval_seconds: float = 2.0
    budgets: Dict[str, Any] = Field(
        default_factory=lambda: {
            "cpu_max_percent": 85,
            "ram_max_percent": 85,
            "process_ram_max_mb": 8000,
            "disk_min_free_gb": 5,
            "gpu_vram_max_percent": 90,
        }
    )
    policies: Dict[str, Any] = Field(default_factory=lambda: {"on_over_budget": "THROTTLE", "cooldown_seconds": 30, "max_delay_seconds": 15})
    gating: Dict[str, str] = Field(
        default_factory=lambda: {
            "heavy_compute_capability": "CAP_HEAVY_COMPUTE",
            "subprocess_capability": "CAP_RUN_SUBPROCESS",
            "network_capability": "CAP_NETWORK_ACCESS",
            "llm_capability": "CAP_HEAVY_COMPUTE",
        }
    )
    throttles: Dict[str, Any] = Field(default_factory=lambda: {"max_concurrent_heavy_jobs": 1, "max_concurrent_llm_requests": 1, "max_total_jobs": 2})
    safe_mode: Dict[str, Any] = Field(
        default_factory=lambda: {
            "enter_after_consecutive_violations": 5,
            "exit_after_seconds_stable": 120,
            "deny_caps": ["CAP_NETWORK_ACCESS", "CAP_RUN_SUBPROCESS", "CAP_HEAVY_COMPUTE"],
        }
    )


class AuditConfigFile(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool = True
    store: Dict[str, Any] = Field(
        default_factory=lambda: {
            "path_jsonl": "logs/audit/audit_events.jsonl",
            "use_sqlite_index": True,
            "sqlite_path": "logs/audit/index.sqlite",
        }
    )
    integrity: Dict[str, Any] = Field(default_factory=lambda: {"enabled": True, "verify_on_startup": True, "verify_last_n": 2000})
    retention: Dict[str, Any] = Field(default_factory=lambda: {"days": 90, "max_events": 50000})
    export: Dict[str, Any] = Field(default_factory=lambda: {"max_rows": 20000})


class PolicyConfigFile(BaseModel):
    model_config = ConfigDict(extra="forbid")
    schema_version: int = Field(default=1, ge=1, le=10)
    enabled: bool = True
    default: Dict[str, Any] = Field(default_factory=lambda: {"deny_unknown_intents": True, "deny_high_sensitivity_without_admin": True})
    rules: List[Dict[str, Any]] = Field(default_factory=list)


class BackupConfigFile(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool = True
    default_dir: str = "backups"
    profiles: Dict[str, Any] = Field(
        default_factory=lambda: {
            "minimal": {"include_logs": False},
            "standard": {"include_logs": True, "log_days": 7, "include_telemetry": True},
            "full": {"include_logs": True, "log_days": 3650, "include_telemetry": True},
        }
    )
    support_bundle: Dict[str, Any] = Field(default_factory=lambda: {"default_days": 7, "redact": True, "max_total_mb": 200})
class EventsBusConfigFile(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool = True
    max_queue_size: int = 1000
    worker_threads: int = 4
    overflow_policy: str = "DROP_OLDEST"  # DROP_OLDEST|DROP_NEWEST
    shutdown_grace_seconds: int = 5
    log_dropped_events: bool = True


class RuntimeControlConfigFile(BaseModel):
    model_config = ConfigDict(extra="forbid")
    shutdown: Dict[str, Any] = Field(
        default_factory=lambda: {
            "enable_restart": True,
            "restart_requires_admin": True,
            "shutdown_requires_confirm": True,
            "phase_timeouts_seconds": {
                "quiesce_inputs": 5,
                "drain_jobs": 20,
                "persist_flush": 10,
                "unload_resources": 10,
                "stop_services": 10,
            },
            "job_grace_seconds": 15,
            "force_kill_after_seconds": 30,
        }
    )
    startup: Dict[str, Any] = Field(default_factory=lambda: {"safe_mode_defaults": {"web_enabled": True, "voice_enabled": True, "llm_enabled": True}})


class RuntimeStateConfigFile(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool = True
    state_version: int = Field(default=1, ge=1)
    backup_keep: int = Field(default=20, ge=1, le=200)
    write_interval_seconds: int = Field(default=10, ge=1, le=3600)
    write_on_events: List[str] = Field(default_factory=lambda: ["shutdown", "error", "breaker_change"])
    paths: Dict[str, Any] = Field(default_factory=lambda: {"runtime_dir": "runtime"})


class UiConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    refresh_interval_ms: int = 350
    max_log_entries_displayed: int = 200
    theme: str = "light"  # light|dark
    confirm_on_exit: bool = True
    core_fact_fuzzy: Dict[str, Any] = Field(
        default_factory=lambda: {
            "enabled": True,
            "min_score": 0.72,
            "min_score_if_contains": 0.62,
            "ambiguity_margin": 0.05,
            "max_phrases_considered_per_intent": 30,
            "max_total_phrase_candidates": 200,
        }
    )


class LLMConfigFile(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool = True
    mode: str = "external"
    debug_log_prompts: bool = False
    managed_kill_server_on_idle: bool = False
    roles: Dict[str, Any] = Field(default_factory=dict)
    watchdog: Dict[str, Any] = Field(default_factory=dict)


class StateMachineConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    idle_sleep_seconds: int = 45
    timeouts: Dict[str, int] = Field(default_factory=lambda: {"LISTENING": 8, "TRANSCRIBING": 15, "UNDERSTANDING": 10, "EXECUTING": 20, "SPEAKING": 20})
    enable_voice: bool = False
    enable_tts: bool = True
    enable_wake_word: bool = True
    max_concurrent_interactions: int = 1
    busy_policy: str = "queue"
    result_ttl_seconds: int = 120


class ModulesRegistryConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    modules: List[Dict[str, Any]] = Field(default_factory=list)


def _default_inline_intent_allowlist() -> List[str]:
    try:
        from jarvis.core.core_intents import CoreIntentRegistry

        return CoreIntentRegistry().get_fact_intents()
    except Exception:
        return [
            "core.time.now",
            "core.date.today",
            "core.status.listening",
            "core.status.admin",
            "core.status.busy",
            "core.status.health",
            "core.identity.version",
        ]


class ModulesConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    # NOTE:
    # This file historically stored only Stage-A routing intent config.
    # We now also store the installed/enabled module registry here (schema_version=1),
    # while keeping backwards compatibility with existing `intents` consumers.
    schema_version: int = 1
    intents: List[Dict[str, Any]] = Field(default_factory=list)
    inline_intent_allowlist: List[str] = Field(default_factory=lambda: _default_inline_intent_allowlist())
    # Installed registry: module_id -> record (see jarvis.core.modules.models)
    modules: Dict[str, Dict[str, Any]] = Field(default_factory=dict)

    @field_validator("modules", mode="before")
    @classmethod
    def _coerce_modules_registry(cls, v: Any) -> Dict[str, Dict[str, Any]]:
        """
        Backwards compatibility:
        - allow missing/None
        - allow legacy list-of-dicts shape (best-effort)
        """
        if v is None:
            return {}
        if isinstance(v, dict):
            # ensure values are dict-like
            out: Dict[str, Dict[str, Any]] = {}
            for k, vv in v.items():
                if isinstance(vv, dict):
                    out[str(k)] = dict(vv)
            return out
        if isinstance(v, list):
            out2: Dict[str, Dict[str, Any]] = {}
            for item in v:
                if not isinstance(item, dict):
                    continue
                mid = item.get("module_id") or item.get("id") or item.get("module")
                if not mid:
                    continue
                out2[str(mid)] = dict(item)
            return out2
        return {}

    @field_validator("inline_intent_allowlist", mode="before")
    @classmethod
    def _coerce_inline_allowlist(cls, v: Any) -> List[str]:
        if v is None:
            return _default_inline_intent_allowlist()
        if isinstance(v, str):
            v = [v]
        if isinstance(v, list):
            out: List[str] = []
            for item in v:
                s = str(item or "").strip()
                if not s:
                    continue
                out.append(s)
            return sorted(set(out))
        return _default_inline_intent_allowlist()


class ExecutionConfigFile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: int = Field(default=1, ge=1, le=10)
    enabled: bool = True
    default_backend: str = "sandbox"
    fallback_backend: str = "local_process"
    sandbox: Dict[str, Any] = Field(
        default_factory=lambda: {
            "require_available": True,
            "image": "jarvis-sandbox:latest",
            "cpus": 1,
            "memory_mb": 512,
            "pids_limit": 256,
            "timeout_seconds": 30,
            "work_root": "runtime/sandbox",
        }
    )
    allow_inline_intents: List[str] = Field(default_factory=lambda: _default_inline_intent_allowlist())

    @field_validator("sandbox", mode="before")
    @classmethod
    def _validate_sandbox_broker(cls, v: Any) -> Dict[str, Any]:
        if v is None:
            return {}
        if not isinstance(v, dict):
            return {}
        broker_cfg = v.get("broker")
        if broker_cfg is None:
            return v
        if not isinstance(broker_cfg, dict):
            raise ValueError("execution.sandbox.broker must be an object")
        if "allowed_client_cidrs" not in broker_cfg:
            return v
        raw = broker_cfg.get("allowed_client_cidrs")
        if raw is None:
            cidrs: List[str] = []
        elif isinstance(raw, str):
            cidrs = [raw]
        elif isinstance(raw, list):
            cidrs = [str(item) for item in raw]
        else:
            raise ValueError("execution.sandbox.broker.allowed_client_cidrs must be a list of CIDR strings")
        cleaned: List[str] = []
        for item in cidrs:
            cidr = str(item or "").strip()
            if not cidr:
                raise ValueError("execution.sandbox.broker.allowed_client_cidrs contains an empty CIDR")
            try:
                ipaddress.ip_network(cidr, strict=False)
            except ValueError as exc:
                raise ValueError(f"Invalid CIDR in execution.sandbox.broker.allowed_client_cidrs: {cidr}") from exc
            cleaned.append(cidr)
        broker_cfg = dict(broker_cfg)
        broker_cfg["allowed_client_cidrs"] = cleaned
        out = dict(v)
        out["broker"] = broker_cfg
        return out

    @field_validator("allow_inline_intents", mode="before")
    @classmethod
    def _coerce_inline_allowlist(cls, v: Any) -> List[str]:
        if v is None:
            return _default_inline_intent_allowlist()
        if isinstance(v, str):
            v = [v]
        if isinstance(v, list):
            out: List[str] = []
            for item in v:
                s = str(item or "").strip()
                if not s:
                    continue
                out.append(s)
            return sorted(set(out))
        return _default_inline_intent_allowlist()


class PermissionsConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    intents: Dict[str, Dict[str, Any]] = Field(default_factory=dict)


class ResponsesConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    confirmations: Dict[str, str] = Field(default_factory=dict)


class AppConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    app: AppFileConfig
    security: SecurityConfig
    voice: VoiceConfig
    models: ModelsConfig
    web: WebConfig
    jobs: JobsConfig
    llm: LLMConfigFile
    state_machine: StateMachineConfig
    modules_registry: ModulesRegistryConfig
    modules: ModulesConfig
    permissions: PermissionsConfig
    responses: ResponsesConfig


class RecoveryConfigFile(BaseModel):
    model_config = ConfigDict(extra="forbid")
    debug: Dict[str, bool] = Field(default_factory=lambda: {"include_tracebacks": False, "log_prompts": False})
    retry: Dict[str, int] = Field(default_factory=lambda: {"llm_timeout_max_retries": 1, "llm_timeout_backoff_ms": 200})
    circuit_breakers: Dict[str, Dict[str, int]] = Field(default_factory=dict)


class AppConfigV2(BaseModel):
    model_config = ConfigDict(extra="forbid")
    app: AppFileConfig
    security: SecurityConfig
    voice: VoiceConfig
    models: ModelsConfig
    web: WebConfig
    ui: UiConfig
    telemetry: TelemetryConfigFile
    resources: ResourcesConfigFile
    execution: ExecutionConfigFile
    audit: AuditConfigFile
    policy: PolicyConfigFile
    backup: BackupConfigFile
    events: EventsBusConfigFile
    runtime: RuntimeControlConfigFile
    runtime_state: RuntimeStateConfigFile
    jobs: JobsConfig
    llm: LLMConfigFile
    recovery: RecoveryConfigFile
    state_machine: StateMachineConfig
    modules_registry: ModulesRegistryConfig
    modules: ModulesConfig
    permissions: PermissionsConfig
    responses: ResponsesConfig

