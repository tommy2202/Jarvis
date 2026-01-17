from __future__ import annotations

import json
import os

from jarvis.core.config.manager import ConfigManager
from jarvis.core.config.paths import ConfigFsPaths
from jarvis.core.modules.manager import ModuleManager


class _L:
    def info(self, *_a, **_k): ...
    def warning(self, *_a, **_k): ...
    def error(self, *_a, **_k): ...


class _Bus:
    def __init__(self) -> None:
        self.events = []

    def publish_nowait(self, evt) -> None:  # noqa: ANN001
        self.events.append(evt)


def _make_cfg(tmp_path) -> ConfigManager:
    cm = ConfigManager(fs=ConfigFsPaths(str(tmp_path)), logger=_L(), read_only=False)
    cm.load_all()
    return cm


def _write_module_json(mod_dir: str, obj: dict) -> None:
    os.makedirs(mod_dir, exist_ok=True)
    path = os.path.join(mod_dir, "module.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)
        f.write("\n")


def test_repeated_scan_without_changes_does_not_retrigger_wizard(tmp_path):
    cm = _make_cfg(tmp_path)
    modules_root = tmp_path / "jarvis" / "modules"
    mod_dir = modules_root / "demo.wizard"
    os.makedirs(mod_dir, exist_ok=True)

    bus = _Bus()
    mm = ModuleManager(config_manager=cm, modules_root=str(modules_root), runtime_dir=str(tmp_path / "runtime"), event_bus=bus, logger=_L(), security_manager=None)

    mm.scan(trace_id="t1", trigger="manual")
    created = [e for e in bus.events if getattr(e, "event_type", "") == "module.manifest_created"]
    assert len(created) == 1

    mm.scan(trace_id="t2", trigger="manual")
    created_after = [e for e in bus.events if getattr(e, "event_type", "") == "module.manifest_created"]
    assert len(created_after) == 1


def test_scan_change_marks_once_per_fingerprint(tmp_path):
    cm = _make_cfg(tmp_path)
    modules_root = tmp_path / "jarvis" / "modules"
    mod_dir = modules_root / "demo.change"
    os.makedirs(mod_dir, exist_ok=True)

    _write_module_json(
        str(mod_dir),
        {
            "schema_version": 1,
            "module_id": "demo.change",
            "version": "0.1.0",
            "display_name": "Demo Change",
            "description": "",
            "entrypoint": "demo_change:register",
            "intents": [
                {
                    "intent_id": "demo.change.ping",
                    "description": "",
                    "args_schema": {},
                    "required_capabilities": ["CAP_AUDIO_OUTPUT"],
                    "resource_class": "light",
                    "execution_mode": "inline",
                }
            ],
            "module_defaults": {"enabled_by_default": False, "admin_required_to_enable": False},
        },
    )

    bus = _Bus()
    mm = ModuleManager(config_manager=cm, modules_root=str(modules_root), runtime_dir=str(tmp_path / "runtime"), event_bus=bus, logger=_L(), security_manager=None)

    mm.scan(trace_id="t1", trigger="manual")

    _write_module_json(
        str(mod_dir),
        {
            "schema_version": 1,
            "module_id": "demo.change",
            "version": "0.1.1",
            "display_name": "Demo Change",
            "description": "updated",
            "entrypoint": "demo_change:register",
            "intents": [
                {
                    "intent_id": "demo.change.ping",
                    "description": "",
                    "args_schema": {},
                    "required_capabilities": ["CAP_AUDIO_OUTPUT"],
                    "resource_class": "light",
                    "execution_mode": "inline",
                }
            ],
            "module_defaults": {"enabled_by_default": False, "admin_required_to_enable": False},
        },
    )

    mm.scan(trace_id="t2", trigger="manual")
    changed = [e for e in bus.events if getattr(e, "event_type", "") == "module.changed_requires_review"]
    assert len(changed) == 1
    reg = mm.list_registry().get("modules") or {}
    rec = reg.get("demo.change") or {}
    fp = str(rec.get("changed_requires_review_fingerprint") or "")
    assert rec.get("changed_requires_review") is True
    assert fp

    mm.scan(trace_id="t3", trigger="manual")
    changed_after = [e for e in bus.events if getattr(e, "event_type", "") == "module.changed_requires_review"]
    assert len(changed_after) == 1
    reg2 = mm.list_registry().get("modules") or {}
    rec2 = reg2.get("demo.change") or {}
    assert rec2.get("changed_requires_review_fingerprint") == fp
