from __future__ import annotations

import os
from pathlib import Path


def test_repo_has_no_bytecode_artifacts():
    root = Path(__file__).resolve().parents[1]
    offenders: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        path = Path(dirpath)
        if "__pycache__" in path.parts:
            rel = str(path.relative_to(root))
            offenders.append(rel)
            for name in filenames:
                if name.endswith((".pyc", ".pyo")):
                    offenders.append(str((path / name).relative_to(root)))
            dirnames[:] = []
            continue
        for name in filenames:
            if name.endswith((".pyc", ".pyo")):
                offenders.append(str((path / name).relative_to(root)))
    assert not offenders, "Bytecode artifacts found:\n" + "\n".join(sorted(set(offenders)))
