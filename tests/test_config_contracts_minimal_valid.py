from __future__ import annotations

import json
import os

import pytest

from jarvis.core.config.manager import ConfigManager
from jarvis.core.config.paths import ConfigFsPaths
from .helpers.config_builders import (
    build_capabilities_config_v1,
    build_execution_config_v1,
    build_policy_config_v1,
    build_privacy_config_v1,
    build_web_config_v1,
)


class _L:
    def info(self, *_a, **_k): ...
    def warning(self, *_a, **_k): ...
    def error(self, *_a, **_k): ...


def _write_json(path: str, obj: dict) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)
        f.write("\n")


@pytest.mark.parametrize(
    "name,builder",
    [
        ("policy.json", build_policy_config_v1),
        ("privacy.json", build_privacy_config_v1),
        ("capabilities.json", build_capabilities_config_v1),
        ("execution.json", build_execution_config_v1),
        ("web.json", build_web_config_v1),
    ],
)
def test_minimal_config_contracts_validate(tmp_path, name, builder):
    cfg_dir = tmp_path / "config"
    _write_json(str(cfg_dir / name), builder())
    cm = ConfigManager(fs=ConfigFsPaths(str(tmp_path)), logger=_L(), read_only=False)
    cm.load_all()
