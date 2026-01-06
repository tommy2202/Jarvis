from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass
from typing import Any, Dict


def _read_json(path: str) -> Dict[str, Any]:
    if not os.path.exists(path):
        return {}
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _atomic_write_json(path: str, data: Dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(prefix=".tmp_", suffix=".json", dir=os.path.dirname(path))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False, sort_keys=True)
            f.write("\n")
        os.replace(tmp_path, path)
    finally:
        try:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
        except OSError:
            pass


@dataclass(frozen=True)
class ConfigPaths:
    config_dir: str = "config"

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
    def security(self) -> str:
        return os.path.join(self.config_dir, "security.json")

    @property
    def web(self) -> str:
        return os.path.join(self.config_dir, "web.json")

    @property
    def modules_registry(self) -> str:
        return os.path.join(self.config_dir, "modules_registry.json")

    @property
    def voice(self) -> str:
        return os.path.join(self.config_dir, "voice.json")

    @property
    def models(self) -> str:
        return os.path.join(self.config_dir, "models.json")


class ConfigLoader:
    def __init__(self, paths: ConfigPaths):
        self.paths = paths

    def load(self, path: str) -> Dict[str, Any]:
        return _read_json(path)

    def save(self, path: str, data: Dict[str, Any]) -> None:
        _atomic_write_json(path, data)

