from __future__ import annotations

import json
import os
import sys
import importlib.abc
import importlib.machinery

from jarvis.core.modules.discovery import ModuleDiscovery


def _origin_in_root(origin: str | None, root: str) -> bool:
    if not origin:
        return False
    origin_abs = os.path.abspath(str(origin))
    root_abs = os.path.abspath(str(root))
    return origin_abs == root_abs or origin_abs.startswith(root_abs + os.sep)


class _RecordingFinder(importlib.abc.MetaPathFinder):
    def __init__(self, root: str) -> None:
        self.root = os.path.abspath(root)
        self.attempts: list[dict] = []

    def find_spec(self, fullname, path=None, target=None):  # noqa: ANN001
        if str(fullname).startswith("jarvis.modules."):
            self.attempts.append({"module": str(fullname), "origin": None})
        spec = importlib.machinery.PathFinder.find_spec(fullname, path, target)
        if spec is None:
            return None
        origin = getattr(spec, "origin", None)
        if _origin_in_root(origin, self.root):
            self.attempts.append({"module": str(fullname), "origin": str(origin)})
        locations = getattr(spec, "submodule_search_locations", None)
        if locations:
            for loc in locations:
                if _origin_in_root(str(loc), self.root):
                    self.attempts.append({"module": str(fullname), "origin": str(loc)})
        return None


def test_discovery_no_imports(monkeypatch, tmp_path):
    modules_root = tmp_path / "modules"
    mod_dir = modules_root / "demo"
    os.makedirs(mod_dir, exist_ok=True)
    (mod_dir / "impl.py").write_text("raise RuntimeError('imported')\n", encoding="utf-8")
    (mod_dir / "module.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "module_id": "demo",
                "version": "0.1.0",
                "display_name": "Demo",
                "description": "",
                "entrypoint": "demo:register",
                "intents": [],
                "module_defaults": {"enabled_by_default": False, "admin_required_to_enable": False},
            }
        )
        + "\n",
        encoding="utf-8",
    )

    finder = _RecordingFinder(str(modules_root))
    monkeypatch.setattr(sys, "meta_path", [finder] + list(sys.meta_path))
    monkeypatch.setattr(sys, "path", [str(modules_root)] + list(sys.path))

    disc = ModuleDiscovery(modules_root=str(modules_root))
    disc.scan()

    assert finder.attempts == []
    loaded = []
    for name, mod in sys.modules.items():
        origin = getattr(mod, "__file__", None)
        if _origin_in_root(origin, str(modules_root)):
            loaded.append((name, origin))
    assert loaded == []
