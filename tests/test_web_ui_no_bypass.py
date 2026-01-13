from __future__ import annotations

from pathlib import Path


def _read_text(path: str) -> str:
    return Path(path).read_text(encoding="utf-8")


def test_web_api_does_not_import_module_handlers_directly():
    txt = _read_text("jarvis/web/api.py")
    assert "jarvis.modules" not in txt
    assert "from jarvis.modules" not in txt


def test_ui_app_does_not_import_module_handlers_directly():
    txt = _read_text("jarvis/ui/app.py")
    assert "jarvis.modules" not in txt
    assert "from jarvis.modules" not in txt

