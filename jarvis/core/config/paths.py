from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class ConfigFsPaths:
    root: str = "."

    @property
    def config_dir(self) -> str:
        return os.path.join(self.root, "config")

    @property
    def secure_dir(self) -> str:
        return os.path.join(self.root, "secure")

    @property
    def schema_dir(self) -> str:
        return os.path.join(self.config_dir, "schema")

    @property
    def backups_dir(self) -> str:
        return os.path.join(self.config_dir, "backups")

    @property
    def last_known_good_dir(self) -> str:
        return os.path.join(self.backups_dir, "last_known_good")

    # Files
    @property
    def app(self) -> str:
        return os.path.join(self.config_dir, "app.json")

    @property
    def security(self) -> str:
        return os.path.join(self.config_dir, "security.json")

    @property
    def voice(self) -> str:
        return os.path.join(self.config_dir, "voice.json")

    @property
    def models(self) -> str:
        return os.path.join(self.config_dir, "models.json")

    @property
    def web(self) -> str:
        return os.path.join(self.config_dir, "web.json")

    @property
    def ui(self) -> str:
        return os.path.join(self.config_dir, "ui.json")

    @property
    def telemetry(self) -> str:
        return os.path.join(self.config_dir, "telemetry.json")

    @property
    def runtime(self) -> str:
        return os.path.join(self.config_dir, "runtime.json")

    @property
    def runtime_state(self) -> str:
        return os.path.join(self.config_dir, "runtime_state.json")

    @property
    def capabilities(self) -> str:
        return os.path.join(self.config_dir, "capabilities.json")

    @property
    def jobs(self) -> str:
        return os.path.join(self.config_dir, "jobs.json")

    @property
    def llm(self) -> str:
        return os.path.join(self.config_dir, "llm.json")

    @property
    def modules(self) -> str:
        return os.path.join(self.config_dir, "modules.json")

    @property
    def permissions(self) -> str:
        return os.path.join(self.config_dir, "permissions.json")

    @property
    def responses(self) -> str:
        return os.path.join(self.config_dir, "responses.json")

    @property
    def modules_registry(self) -> str:
        return os.path.join(self.config_dir, "modules_registry.json")

    @property
    def state_machine(self) -> str:
        return os.path.join(self.config_dir, "state_machine.json")

