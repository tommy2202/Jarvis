from __future__ import annotations

from jarvis.core.config_loader import ConfigLoader, ConfigPaths
from jarvis.core.setup_wizard import SetupWizard


class DummyLogger:
    def info(self, *_a, **_k): ...
    def warning(self, *_a, **_k): ...
    def error(self, *_a, **_k): ...


def test_setup_wizard_detect_does_not_import(tmp_path, monkeypatch):
    modules_root = tmp_path / "jarvis" / "modules"
    modules_root.mkdir(parents=True)
    marker = tmp_path / "marker.txt"
    (modules_root / "evil.py").write_text(
        "from pathlib import Path\n"
        "Path('marker.txt').write_text('imported')\n"
        "MODULE_META = dict(id='evil', default_intent='evil.run')\n",
        encoding="utf-8",
    )

    cfg_dir = tmp_path / "config"
    cfg_dir.mkdir()
    paths = ConfigPaths(config_dir=str(cfg_dir))
    cfg = ConfigLoader(paths)
    cfg.save(paths.modules_registry, {"modules": []})
    cfg.save(paths.modules, {"intents": []})
    cfg.save(paths.permissions, {"intents": {}})
    cfg.save(paths.responses, {"confirmations": {}})

    monkeypatch.chdir(tmp_path)

    wiz = SetupWizard(cfg=cfg, paths=paths, secure_store=None, logger=DummyLogger())
    detection = wiz.detect()

    assert marker.exists() is False
    assert "jarvis.modules.evil" in detection["missing_in_registry"]
    missing = detection.get("missing_modules") or []
    entry = next((m for m in missing if m.get("module") == "jarvis.modules.evil"), None)
    assert entry is not None
    assert entry.get("pending_review") is True
    assert entry.get("meta_status") == "unknown"
