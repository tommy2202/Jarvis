from __future__ import annotations

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field


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


class ModulesConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    intents: List[Dict[str, Any]] = Field(default_factory=list)


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

