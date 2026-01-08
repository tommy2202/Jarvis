from __future__ import annotations

import json
import os
import shutil
import time
import zipfile
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from jarvis.core.backup.verifier import verify_zip


@dataclass(frozen=True)
class RestorePlan:
    backup_id: str
    profile: str
    restore_mode: str
    files: List[str]
    warnings: List[str]


def plan_restore(zip_path: str, *, mode: str) -> RestorePlan:
    vr = verify_zip(zip_path)
    if not vr.ok:
        raise ValueError("Backup verification failed: " + "; ".join(vr.errors[:10]))
    with zipfile.ZipFile(zip_path, "r") as z:
        man = json.loads(z.read("manifest.json").decode("utf-8"))
        bid = str(man.get("backup_id") or "")
        profile = str(man.get("profile") or "")
        contents = [str(x.get("relative_path")) for x in (man.get("contents") or []) if isinstance(x, dict)]
    allowed_roots = {
        "config": ["config/"],
        "runtime": ["runtime/"],
        "secure": ["secure/"],
        "all": ["config/", "runtime/", "secure/"],
    }
    mode = str(mode)
    roots = allowed_roots.get(mode)
    if roots is None:
        raise ValueError("Invalid restore mode.")
    files = [p for p in contents if any(p.startswith(r) for r in roots)]
    return RestorePlan(backup_id=bid, profile=profile, restore_mode=mode, files=files, warnings=[])


def restore_to_staging(zip_path: str, *, staging_dir: str, plan: RestorePlan) -> str:
    os.makedirs(staging_dir, exist_ok=True)
    out = os.path.join(staging_dir, plan.backup_id or "backup")
    if os.path.exists(out):
        shutil.rmtree(out, ignore_errors=True)
    os.makedirs(out, exist_ok=True)
    with zipfile.ZipFile(zip_path, "r") as z:
        for rel in plan.files:
            if rel in {"manifest.json", "manifest.sha256"}:
                continue
            try:
                z.extract(rel, path=out)
            except Exception:
                continue
    return out


def apply_restore(staged_root: str, *, target_root: str, plan: RestorePlan) -> Dict[str, Any]:
    """
    Apply restore with atomic replaces where possible.
    Always preserves existing by copying to a timestamped pre_restore/ folder.
    """
    ts = time.strftime("%Y%m%d_%H%M%S", time.gmtime())
    pre = os.path.join(target_root, "restore_staging", "pre_restore", ts)
    os.makedirs(pre, exist_ok=True)

    def _copy_existing(rel: str) -> None:
        src = os.path.join(target_root, rel)
        if os.path.exists(src):
            dst = os.path.join(pre, rel)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            if os.path.isdir(src):
                shutil.copytree(src, dst, dirs_exist_ok=True)
            else:
                shutil.copy2(src, dst)

    def _atomic_replace(rel: str) -> None:
        src = os.path.join(staged_root, rel)
        dst = os.path.join(target_root, rel)
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        if os.path.isdir(src):
            # directory replace: move aside then move new in
            tmp_old = dst + f".old.{ts}"
            if os.path.exists(dst):
                os.replace(dst, tmp_old)
            os.replace(src, dst)
        else:
            tmp = dst + f".tmp.{ts}"
            shutil.copy2(src, tmp)
            os.replace(tmp, dst)

    touched = set()
    for rel in plan.files:
        root = rel.split("/", 1)[0] + "/"
        if root in {"config/", "runtime/", "secure/"}:
            touched.add(root[:-1])

    for r in sorted(touched):
        _copy_existing(r)
        _atomic_replace(r)

    # Post-restore: create a crash marker so next boot starts safe.
    try:
        cm = os.path.join(target_root, "runtime", "crash_markers")
        os.makedirs(cm, exist_ok=True)
        with open(os.path.join(cm, "dirty_shutdown.flag"), "w", encoding="utf-8") as f:
            f.write(f"restore:{ts}\n")
    except Exception:
        pass

    return {"applied": True, "pre_restore_backup": pre, "touched": sorted(touched)}

