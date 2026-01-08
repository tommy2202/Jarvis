from __future__ import annotations

from pathlib import Path


def _read(path: str) -> str:
    return Path(path).read_text(encoding="utf-8")


def test_web_api_does_not_import_or_call_module_handlers_directly():
    txt = _read("jarvis/web/api.py")
    # Static guard: web API must not reach into modules directly (dispatcher is the single gate).
    assert "jarvis.modules" not in txt
    assert "ModuleRegistry" not in txt
    assert ".handler(" not in txt


def test_ui_app_does_not_import_or_call_module_handlers_directly():
    txt = _read("jarvis/ui/app.py")
    # Static guard: UI must be a thin client over runtime/dispatcher path.
    assert "jarvis.modules" not in txt
    assert "ModuleRegistry" not in txt
    assert ".handler(" not in txt

