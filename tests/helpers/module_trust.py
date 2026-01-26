from __future__ import annotations

import json
import os

from jarvis.core.config.manager import ConfigManager
from jarvis.core.config.paths import ConfigFsPaths


class DummyLogger:
    def info(self, *_a, **_k): ...
    def warning(self, *_a, **_k): ...
    def error(self, *_a, **_k): ...


class EventBusCapture:
    def __init__(self) -> None:
        self.events: list[object] = []

    def publish_nowait(self, ev) -> None:  # noqa: ANN001
        self.events.append(ev)


def make_cfg(tmp_path) -> ConfigManager:
    cm = ConfigManager(fs=ConfigFsPaths(str(tmp_path)), logger=DummyLogger(), read_only=False)
    cm.load_all()
    return cm


def write_module_json(mod_dir: str, obj: dict) -> None:
    os.makedirs(mod_dir, exist_ok=True)
    path = os.path.join(mod_dir, "module.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)
        f.write("\n")
