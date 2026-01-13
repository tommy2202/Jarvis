from __future__ import annotations

"""
Static "no bypass" assertions for web/UI frontends.

WHY THIS FILE EXISTS:
Web/UI code must never directly import or call module handlers. Those pathways
would bypass dispatcher enforcement. TYPE_CHECKING-only imports are allowed.
"""

from pathlib import Path


def _read_text(path: str) -> str:
    return Path(path).read_text(encoding="utf-8")

def _strip_type_checking_blocks(txt: str) -> str:
    """
    Remove `if TYPE_CHECKING:` blocks so type-only imports don't fail the guard.
    """
    lines = txt.splitlines(True)
    out: list[str] = []
    skip_indent: int | None = None
    for line in lines:
        # Detect: if TYPE_CHECKING:
        if skip_indent is None and line.lstrip().startswith("if TYPE_CHECKING"):
            skip_indent = len(line) - len(line.lstrip())
            continue
        if skip_indent is not None:
            # Continue skipping while indentation is deeper than the if-line
            if line.strip() and (len(line) - len(line.lstrip())) > skip_indent:
                continue
            # End of block
            skip_indent = None
        out.append(line)
    return "".join(out)


def test_web_api_does_not_import_module_handlers_directly():
    # Invariant: web API must not import module handlers directly (dispatcher-only execution).
    txt = _read_text("jarvis/web/api.py")
    txt = _strip_type_checking_blocks(txt)
    assert "from jarvis.modules" not in txt
    assert "import jarvis.modules" not in txt


def test_ui_app_does_not_import_module_handlers_directly():
    # Invariant: UI must not import module handlers directly (dispatcher-only execution).
    txt = _read_text("jarvis/ui/app.py")
    txt = _strip_type_checking_blocks(txt)
    assert "from jarvis.modules" not in txt
    assert "import jarvis.modules" not in txt

