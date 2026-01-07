from __future__ import annotations

import json
import os
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
from jarvis.core.config.migrations.runner import latest_version, run_migrations
from jarvis.core.config.models import (
    AppConfigV2,
    AppFileConfig,
    EventsBusConfigFile,
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


@dataclass
class DiffResult:
    changed_files: Dict[str, Dict[str, Any]]


class ConfigManager:
    def __init__(self, *, fs: Optional[ConfigFsPaths] = None, logger=None, read_only: bool = False):
        self.fs = fs or ConfigFsPaths(".")
        self.logger = logger
        self.read_only = read_only
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
        migrated, new_ver, mig_logs = run_migrations(
            fs=self.fs,
            files=files,
            current_version=cur_ver,
            backups_dir=self.fs.backups_dir,
            max_backups=max_backups,
            write_back=not self.read_only,
        )
        if mig_logs and self.logger:
            self.logger.info("Config migrations: " + "; ".join(mig_logs))

        # ensure defaults exist (create missing)
        ensured = self._ensure_defaults(migrated, max_backups=max_backups)

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
        if not isinstance(data, dict):
            raise ConfigError("Config data must be an object.")
        max_backups = int((self.get().app.backups or {}).get("max_backups_per_file", 10))
        path = os.path.join(self.fs.config_dir, filename)
        atomic_write_json(path, data, self.fs.backups_dir, max_backups=max_backups)
        # validate after write; if invalid keep previous in memory but don't auto-rollback silently
        self.load_all()

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
            "audit.json",
            "events.json",
            "runtime.json",
            "runtime_state.json",
            "capabilities.json",
            "jobs.json",
            "llm.json",
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
        defaults: Dict[str, Dict[str, Any]] = {
            "app.json": AppFileConfig().model_dump(),
            "security.json": SecurityConfig().model_dump(),
            "voice.json": VoiceConfig().model_dump(),
            "models.json": ModelsConfig().model_dump(),
            "web.json": WebConfig().model_dump(),
            "ui.json": UiConfig().model_dump(),
            "telemetry.json": TelemetryConfigFile().model_dump(),
            "resources.json": ResourcesConfigFile().model_dump(),
            "audit.json": AuditConfigFile().model_dump(),
            "events.json": EventsBusConfigFile().model_dump(),
            "runtime.json": RuntimeControlConfigFile().model_dump(),
            "runtime_state.json": RuntimeStateConfigFile().model_dump(),
            "capabilities.json": __import__("jarvis.core.capabilities.loader", fromlist=["default_config_dict"]).default_config_dict(),
            "jobs.json": JobsConfig().model_dump(),
            "llm.json": LLMConfigFile().model_dump(),
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
            # Capabilities config is validated separately (outside AppConfigV2) to avoid bloating the core config schema.
            # Still strict schema validated at load time via capabilities.models.
            try:
                from jarvis.core.capabilities.loader import validate_and_normalize

                _ = validate_and_normalize(files.get("capabilities.json") or {})
            except Exception as e:
                raise ConfigError(f"capabilities.json invalid: {e}") from e

            cfg = AppConfigV2(
                app=AppFileConfig.model_validate(files.get("app.json") or {}),
                security=SecurityConfig.model_validate(files.get("security.json") or {}),
                voice=VoiceConfig.model_validate(files.get("voice.json") or {}),
                models=ModelsConfig.model_validate(files.get("models.json") or {}),
                web=WebConfig.model_validate(files.get("web.json") or {}),
                ui=UiConfig.model_validate(files.get("ui.json") or {}),
                telemetry=TelemetryConfigFile.model_validate(files.get("telemetry.json") or {}),
                resources=ResourcesConfigFile.model_validate(files.get("resources.json") or {}),
                audit=AuditConfigFile.model_validate(files.get("audit.json") or {}),
                events=EventsBusConfigFile.model_validate(files.get("events.json") or {}),
                runtime=RuntimeControlConfigFile.model_validate(files.get("runtime.json") or {}),
                runtime_state=RuntimeStateConfigFile.model_validate(files.get("runtime_state.json") or {}),
                jobs=JobsConfig.model_validate(files.get("jobs.json") or {}),
                llm=LLMConfigFile.model_validate(files.get("llm.json") or {}),
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


def get_config(*, logger=None, read_only: bool = False) -> ConfigManager:
    global _singleton  # noqa: PLW0603
    if _singleton is None:
        _singleton = ConfigManager(logger=logger, read_only=read_only)
        _singleton.load_all()
    return _singleton

