from __future__ import annotations

from pathlib import Path


def test_dependency_lock_present():
    root = Path(__file__).resolve().parents[1]
    req_in = root / "requirements.in"
    req_lock = root / "requirements.txt"
    readme = root / "README.md"

    assert req_in.exists()
    assert req_lock.exists()
    assert readme.exists()

    text = readme.read_text(encoding="utf-8")
    assert "requirements.txt" in text
    assert "scripts\\lock_deps.ps1" in text or "scripts/lock_deps.ps1" in text
    assert "scripts\\verify_deps.ps1" in text or "scripts/verify_deps.ps1" in text
