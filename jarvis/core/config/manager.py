from __future__ import annotations

import json
import os
import shutil
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional

from pydantic import ValidationError

from jarvis.core.config.io import (
    ReadResult,
    atomic_write_json,
    read_json_file,
    recover_from_corrupt,
    snapshot_last_known_good,
)
from jarvis.core.config.models import (
    AppConfigV2,
    AppFileConfig,
    EventsBusConfigFile,
    ExecutionConfigFile,
    ImageConfigFile,
    JobsConfig,
    LLMConfigFile,
    ModelsConfig,
    ModulesConfig,
    ModulesRegistryConfig,
    PermissionsConfig,
    RecoveryConfigFile,
    ResponsesConfig,
    SecurityConfig,
    StateMachineConfig,
    TelemetryConfigFile,
    ResourcesConfigFile,
    AuditConfigFile,
    PolicyConfigFile,
    BackupConfigFile,
    RuntimeControlConfigFile,
    RuntimeStateConfigFile,
    UiConfig,
    VoiceConfig,
    WebConfig,
)
from jarvis.core.config.paths import ConfigFsPaths
from jarvis.core.secure_store import SecureStore, SecretUnavailable as _SecureStoreSecretUnavailable
from jarvis.core.events import redact
from jarvis.core.config.watcher import ConfigWatcher, WatcherConfig


class ConfigError(RuntimeError):
    pass


class SecretUnavailable(ConfigError, _SecureStoreSecretUnavailable):
    pass


SECURITY_CRITICAL_CONFIGS: Dict[str, int] = {
    "capabilities.json": 1,
    "policy.json": 1,
    "execution.json": 1,
    "privacy.json": 1,
    "module_trust.json": 1,
}


@dataclass
class DiffResult:
    changed_files: Dict[str, Dict[str, Any]]


class ConfigManager:
    def __init__(
        self,
        *,
        fs: Optional[ConfigFsPaths] = None,
        logger=None,
        read_only: bool = False,
        version_registry: Any = None,
        event_logger: Any = None,
    ):
        self.fs = fs or ConfigFsPaths(".")
        self.logger = logger
        self.read_only = read_only
        self._version_registry = version_registry
        self._event_logger = event_logger
        self._cfg: Optional[AppConfigV2] = None
        self._raw_last: Dict[str, Dict[str, Any]] = {}
        self._secure_store: Optional[SecureStore] = None
        self._watcher: Optional[ConfigWatcher] = None

    # ---------- public API ----------
    def load_all(self) -> AppConfigV2:
        os.makedirs(self.fs.config_dir, exist_ok=True)
        os.makedirs(self.fs.backups_dir, exist_ok=True)
        os.makedirs(self.fs.last_known_good_dir, exist_ok=True)
        os.makedirs(self.fs.schema_dir, exist_ok=True)
        os.makedirs(self.fs.secure_dir, exist_ok=True)

        # read raw files with recovery
        files = self._load_raw_files()

        # migrations driven by app.json version
        app_raw = files.get("app.json") or {}
        cur_ver = int(app_raw.get("config_version") or 0)
        max_backups = int((app_raw.get("backups") or {}).get("max_backups_per_file", 10))
        from jarvis.core.migrations.runner import run_config_migrations, run_module_registry_migrations

        migrated, new_ver, mig_logs = run_config_migrations(
            fs=self.fs,
            files=files,
            current_version=cur_ver,
            backups_dir=self.fs.backups_dir,
            max_backups=max_backups,
            write_back=not self.read_only,
            registry=self._version_registry,
            event_logger=self._event_logger,
            trace_id="config",
        )
        if mig_logs and self.logger:
            self.logger.info("Config migrations: " + "; ".join(mig_logs))

        # ensure defaults exist (create missing)
        ensured = self._ensure_defaults(migrated, max_backups=max_backups)
        ensured, _mod_ver, mod_logs = run_module_registry_migrations(
            fs=self.fs,
            files=ensured,
            backups_dir=self.fs.backups_dir,
            max_backups=max_backups,
            write_back=not self.read_only,
            registry=self._version_registry,
            event_logger=self._event_logger,
            trace_id="modules",
        )
        if mod_logs and self.logger:
            self.logger.info("Module registry migrations: " + "; ".join(mod_logs))

        # validate
        cfg = self._validate_all(ensured)
        self._cfg = cfg
        self._raw_last = {k: dict(v) for k, v in ensured.items()}

        # create secure store handle (can be locked)
        self._secure_store = SecureStore(
            usb_key_path=cfg.security.usb_key_path,
            store_path=cfg.security.secure_store_path,
            meta_path=os.path.join(self.fs.secure_dir, "store.meta.json"),
            backups_dir=os.path.join(self.fs.secure_dir, "backups"),
            max_backups=int(cfg.security.secure_store_backup_keep),
            max_bytes=int(cfg.security.secure_store_max_bytes),
            read_only=bool(cfg.security.secure_store_read_only),
        )

        # snapshot last known good
        if not self.read_only:
            snapshot_last_known_good(self.fs.config_dir, self.fs.last_known_good_dir)

        # watcher
        self._setup_watcher()
        return cfg

    def validate(self) -> None:
        if self._cfg is None:
            raise ConfigError("Config not loaded.")
        _ = self._validate_all(self._load_raw_files())

    def get(self) -> AppConfigV2:
        if self._cfg is None:
            raise ConfigError("Config not loaded.")
        return self._cfg

    def read_non_sensitive(self, filename: str) -> Dict[str, Any]:
        """
        Read a single non-sensitive config file from config/ (safe recovery applied).
        """
        path = os.path.join(self.fs.config_dir, filename)
        rr = read_json_file(path)
        if rr.ok:
            return rr.data
        if rr.error and rr.error.startswith("corrupt_json"):
            data, _ = recover_from_corrupt(path, self.fs.backups_dir, self.fs.last_known_good_dir, max_backups=10)
            return data
        return {}

    def save_non_sensitive(self, filename: str, data: Dict[str, Any]) -> None:
        """
        Atomic write + backups, then validate whole config set.
        If validation fails, raise (backup remains available).
        """
        if self.read_only:
            raise ConfigError("Config manager is read-only.")
        if getattr(self, "_writes_paused", False):
            raise ConfigError("Config writes are paused (backup in progress).")
        if not isinstance(data, dict):
            raise ConfigError("Config data must be an object.")
        max_backups = int((self.get().app.backups or {}).get("max_backups_per_file", 10))
        path = os.path.join(self.fs.config_dir, filename)
        atomic_write_json(path, data, self.fs.backups_dir, max_backups=max_backups)
        # validate after write; if invalid keep previous in memory but don't auto-rollback silently
        self.load_all()

    def pause_writes(self) -> str:
        import uuid

        tok = uuid.uuid4().hex
        self._writes_paused = True
        self._pause_token = tok
        return tok

    def resume_writes(self, token: str) -> None:
        if getattr(self, "_pause_token", None) == token:
            self._writes_paused = False
            self._pause_token = None

    def diff_since_last_load(self) -> DiffResult:
        now = self._load_raw_files()
        changed: Dict[str, Dict[str, Any]] = {}
        for k, v in now.items():
            if k not in self._raw_last or self._raw_last[k] != v:
                changed[k] = {"before": self._raw_last.get(k), "after": v}
        return DiffResult(changed_files=changed)

    def reload_if_changed(self) -> bool:
        """
        Hot reload (non-sensitive only). If invalid, keep previous config.
        """
        if self._cfg is None:
            return False
        diff = self.diff_since_last_load()
        if not diff.changed_files:
            return False
        try:
            # validate full set; only apply if ok
            raw = self._load_raw_files()
            cfg = self._validate_all(raw)
            self._cfg = cfg
            self._raw_last = {k: dict(v) for k, v in raw.items()}
            if self.logger:
                self.logger.info(f"Config reloaded: {list(diff.changed_files.keys())}")
            return True
        except Exception as e:
            if self.logger:
                self.logger.warning(f"Config reload rejected (keeping previous): {e}")
            return False

    def open_paths(self) -> Dict[str, str]:
        return {
            "config_dir": self.fs.config_dir,
            "secure_dir": self.fs.secure_dir,
            "backups_dir": self.fs.backups_dir,
            "last_known_good_dir": self.fs.last_known_good_dir,
            "schema_dir": self.fs.schema_dir,
        }

    # ---- security-critical config controls ----
    def _security_config_versions(self) -> Dict[str, int]:
        return dict(SECURITY_CRITICAL_CONFIGS)

    def _security_config_names(self) -> list[str]:
        return list(self._security_config_versions().keys())

    def _validate_security_schema_version(self, name: str, raw: Dict[str, Any]) -> None:
        expected = self._security_config_versions().get(name)
        if expected is None:
            return
        if not isinstance(raw, dict):
            raise ConfigError(f"{name} invalid (not an object).")
        if raw.get("_invalid_config"):
            raise ConfigError(f"{name} invalid: {raw.get('_invalid_config')}")
        if "schema_version" not in raw:
            raise ConfigError(f"{name} missing schema_version (expected {expected}).")
        try:
            schema_version = int(raw.get("schema_version"))
        except Exception as e:  # noqa: BLE001
            raise ConfigError(f"{name} schema_version must be an integer (expected {expected}).") from e
        if schema_version != expected:
            raise ConfigError(
                f"{name} schema_version mismatch (expected {expected}). Run the config migration tool before starting."
            )

    def _validate_security_schema_versions(self, files: Dict[str, Dict[str, Any]]) -> None:
        for name in self._security_config_names():
            raw = files.get(name) or {}
            self._validate_security_schema_version(name, raw)

    def snapshot_security_lkg(self, *, root_dir: Optional[str] = None, ops: Any = None) -> list[str]:
        root = str(root_dir or self.fs.root or ".")
        lkg_dir = os.path.join(root, ".lkg")
        os.makedirs(lkg_dir, exist_ok=True)
        copied: list[str] = []
        for name in self._security_config_names():
            src = os.path.join(self.fs.config_dir, name)
            if not os.path.isfile(src):
                continue
            dst = os.path.join(lkg_dir, name)
            try:
                shutil.copy2(src, dst)
                copied.append(name)
            except Exception as e:  # noqa: BLE001
                if self.logger:
                    self.logger.warning(f"Unable to snapshot {name} to .lkg: {e}")
        if ops is not None:
            try:
                ops.log(trace_id="startup", event="config.lkg.snapshot", outcome="ok", details={"files": copied})
            except Exception:
                pass
        return copied

    def restore_security_lkg(self, *, root_dir: Optional[str] = None, security_manager: Any = None, ops: Any = None) -> list[str]:
        if security_manager is None or not bool(getattr(security_manager, "is_admin", lambda: False)()):
            raise PermissionError("Admin required to restore security configs from LKG.")
        root = str(root_dir or self.fs.root or ".")
        lkg_dir = os.path.join(root, ".lkg")
        if not os.path.isdir(lkg_dir):
            raise FileNotFoundError("No LKG directory found.")
        restored: list[str] = []
        max_backups = 10
        try:
            if self._cfg is not None:
                max_backups = int((self._cfg.app.backups or {}).get("max_backups_per_file", 10))
        except Exception:
            max_backups = 10
        for name in self._security_config_names():
            src = os.path.join(lkg_dir, name)
            if not os.path.isfile(src):
                continue
            rr = read_json_file(src)
            if not rr.ok:
                raise ConfigError(f"LKG file invalid: {name} ({rr.error})")
            self._validate_security_schema_version(name, rr.data)
            dst = os.path.join(self.fs.config_dir, name)
            atomic_write_json(dst, rr.data, self.fs.backups_dir, max_backups=max_backups)
            restored.append(name)
        if ops is not None:
            try:
                ops.log(trace_id="config", event="config.lkg.restore", outcome="ok", details={"files": restored})
            except Exception:
                pass
        return restored

    # Secrets unified API
    def get_secret(self, key: str) -> Any:
        if self._secure_store is None:
            raise SecretUnavailable("Secure store not initialized.")
        try:
            return self._secure_store.get(key)
        except _SecureStoreSecretUnavailable as e:
            raise SecretUnavailable(str(e)) from e

    def set_secret(self, key: str, value: Any) -> None:
        if self._secure_store is None:
            raise SecretUnavailable("Secure store not initialized.")
        try:
            self._secure_store.set(key, value)
        except _SecureStoreSecretUnavailable as e:
            raise SecretUnavailable(str(e)) from e

    # ---------- internals ----------
    def _load_raw_files(self) -> Dict[str, Dict[str, Any]]:
        names = [
            "app.json",
            "security.json",
            "voice.json",
            "models.json",
            "web.json",
            "ui.json",
            "telemetry.json",
            "resources.json",
            "execution.json",
            "audit.json",
            "privacy.json",
            "module_trust.json",
            "limits.json",
            "policy.json",
            "backup.json",
            "events.json",
            "runtime.json",
            "runtime_state.json",
            "capabilities.json",
            "jobs.json",
            "llm.json",
            "image.json",
            "recovery.json",
            "state_machine.json",
            "modules_registry.json",
            "modules.json",
            "permissions.json",
            "responses.json",
        ]
        out: Dict[str, Dict[str, Any]] = {}
        for name in names:
            path = os.path.join(self.fs.config_dir, name)
            rr: ReadResult = read_json_file(path)
            if rr.ok:
                out[name] = rr.data
                continue
            if name in SECURITY_CRITICAL_CONFIGS and rr.error:
                if rr.error == "missing":
                    out[name] = {}
                else:
                    if self.logger:
                        self.logger.warning(f"Invalid security config {name}: {rr.error}")
                    out[name] = {"_invalid_config": rr.error}
                continue
            if rr.error and rr.error.startswith("corrupt_json"):
                data, recovered = recover_from_corrupt(path, self.fs.backups_dir, self.fs.last_known_good_dir, max_backups=10)
                if self.logger:
                    self.logger.warning(f"Corrupt config {name} -> recovered={recovered}")
                out[name] = data
                continue
            # missing or other error: treat as missing -> defaults later
            out[name] = {}
        return out

    def _ensure_defaults(self, files: Dict[str, Dict[str, Any]], *, max_backups: int) -> Dict[str, Dict[str, Any]]:
        from jarvis.core.privacy.models import default_privacy_config_dict
        from jarvis.core.modules.models import default_module_trust_config_dict
        from jarvis.core.limits.limiter import default_limits_config_dict

        defaults: Dict[str, Dict[str, Any]] = {
            "app.json": AppFileConfig().model_dump(),
            "security.json": SecurityConfig().model_dump(),
            "voice.json": VoiceConfig().model_dump(),
            "models.json": ModelsConfig().model_dump(),
            "web.json": WebConfig().model_dump(),
            "ui.json": UiConfig().model_dump(),
            "telemetry.json": TelemetryConfigFile().model_dump(),
            "resources.json": ResourcesConfigFile().model_dump(),
            "execution.json": ExecutionConfigFile().model_dump(),
            "audit.json": AuditConfigFile().model_dump(),
            "privacy.json": default_privacy_config_dict(),
            "module_trust.json": default_module_trust_config_dict(),
            "limits.json": default_limits_config_dict(),
            "policy.json": PolicyConfigFile().model_dump(),
            "backup.json": BackupConfigFile().model_dump(),
            "events.json": EventsBusConfigFile().model_dump(),
            "runtime.json": RuntimeControlConfigFile().model_dump(),
            "runtime_state.json": RuntimeStateConfigFile().model_dump(),
            "capabilities.json": __import__("jarvis.core.capabilities.loader", fromlist=["default_config_dict"]).default_config_dict(),
            "jobs.json": JobsConfig().model_dump(),
            "llm.json": LLMConfigFile().model_dump(),
            "image.json": ImageConfigFile().model_dump(),
            "recovery.json": RecoveryConfigFile().model_dump(),
            "state_machine.json": StateMachineConfig().model_dump(),
            "modules_registry.json": ModulesRegistryConfig().model_dump(),
            "modules.json": ModulesConfig().model_dump(),
            "permissions.json": PermissionsConfig().model_dump(),
            "responses.json": ResponsesConfig().model_dump(),
        }
        out = dict(files)
        for name, dflt in defaults.items():
            if not out.get(name):
                out[name] = dflt
                if self.logger:
                    self.logger.warning(f"Missing config {name}; creating defaults.")
                if not self.read_only:
                    atomic_write_json(os.path.join(self.fs.config_dir, name), dflt, self.fs.backups_dir, max_backups=max_backups)
        return out

    def _validate_all(self, files: Dict[str, Dict[str, Any]]) -> AppConfigV2:
        try:
            self._validate_security_schema_versions(files)
            # Capabilities config is validated separately (outside AppConfigV2) to avoid bloating the core config schema.
            # Still strict schema validated at load time via capabilities.models.
            try:
                from jarvis.core.capabilities.loader import validate_and_normalize

                _ = validate_and_normalize(files.get("capabilities.json") or {})
            except Exception as e:
                raise ConfigError(f"capabilities.json invalid: {e}") from e

            # Privacy config is validated separately (outside AppConfigV2).
            try:
                from jarvis.core.privacy.models import PrivacyConfigFile

                _ = PrivacyConfigFile.model_validate(files.get("privacy.json") or {})
            except Exception as e:
                raise ConfigError(f"privacy.json invalid: {e}") from e

            # Module trust config is validated separately (outside AppConfigV2).
            try:
                from jarvis.core.modules.models import ModuleTrustConfigFile

                _ = ModuleTrustConfigFile.model_validate(files.get("module_trust.json") or {})
            except Exception as e:
                raise ConfigError(f"module_trust.json invalid: {e}") from e

            # Limits config is validated separately (outside AppConfigV2).
            try:
                from jarvis.core.limits.limiter import LimitsConfigFile

                _ = LimitsConfigFile.model_validate(files.get("limits.json") or {})
            except Exception as e:
                raise ConfigError(f"limits.json invalid: {e}") from e

            cfg = AppConfigV2(
                app=AppFileConfig.model_validate(files.get("app.json") or {}),
                security=SecurityConfig.model_validate(files.get("security.json") or {}),
                voice=VoiceConfig.model_validate(files.get("voice.json") or {}),
                models=ModelsConfig.model_validate(files.get("models.json") or {}),
                web=WebConfig.model_validate(files.get("web.json") or {}),
                ui=UiConfig.model_validate(files.get("ui.json") or {}),
                telemetry=TelemetryConfigFile.model_validate(files.get("telemetry.json") or {}),
                resources=ResourcesConfigFile.model_validate(files.get("resources.json") or {}),
                execution=ExecutionConfigFile.model_validate(files.get("execution.json") or {}),
                audit=AuditConfigFile.model_validate(files.get("audit.json") or {}),
                policy=PolicyConfigFile.model_validate(files.get("policy.json") or {}),
                backup=BackupConfigFile.model_validate(files.get("backup.json") or {}),
                events=EventsBusConfigFile.model_validate(files.get("events.json") or {}),
                runtime=RuntimeControlConfigFile.model_validate(files.get("runtime.json") or {}),
                runtime_state=RuntimeStateConfigFile.model_validate(files.get("runtime_state.json") or {}),
                jobs=JobsConfig.model_validate(files.get("jobs.json") or {}),
                llm=LLMConfigFile.model_validate(files.get("llm.json") or {}),
                image=ImageConfigFile.model_validate(files.get("image.json") or {}),
                recovery=RecoveryConfigFile.model_validate(files.get("recovery.json") or {}),
                state_machine=StateMachineConfig.model_validate(files.get("state_machine.json") or {}),
                modules_registry=ModulesRegistryConfig.model_validate(files.get("modules_registry.json") or {}),
                modules=ModulesConfig.model_validate(files.get("modules.json") or {}),
                permissions=PermissionsConfig.model_validate(files.get("permissions.json") or {}),
                responses=ResponsesConfig.model_validate(files.get("responses.json") or {}),
            )
            return cfg
        except ValidationError as e:
            # user-friendly error
            raise ConfigError(str(e)) from e

    def _setup_watcher(self) -> None:
        if self._cfg is None:
            return
        hr = self._cfg.app.hot_reload or {}
        wcfg = WatcherConfig(
            enabled=bool(hr.get("enabled", False)),
            debounce_ms=int(hr.get("debounce_ms", 500)),
            poll_interval_ms=int(hr.get("poll_interval_ms", 500)),
        )
        if self._watcher is None:
            self._watcher = ConfigWatcher(config_dir=self.fs.config_dir, cfg=wcfg, on_change=self.reload_if_changed, logger=self.logger)
        else:
            self._watcher.stop()
            self._watcher = ConfigWatcher(config_dir=self.fs.config_dir, cfg=wcfg, on_change=self.reload_if_changed, logger=self.logger)
        self._watcher.start()


_singleton: Optional[ConfigManager] = None


def get_config(*, logger=None, read_only: bool = False, version_registry: Any = None, event_logger: Any = None) -> ConfigManager:
    global _singleton  # noqa: PLW0603
    if _singleton is None:
        _singleton = ConfigManager(logger=logger, read_only=read_only, version_registry=version_registry, event_logger=event_logger)
        _singleton.load_all()
    return _singleton

