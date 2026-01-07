from __future__ import annotations

import os
import time
from dataclasses import dataclass
from typing import Iterable, List, Optional, Tuple


@dataclass(frozen=True)
class BackupProfile:
    name: str
    include_logs: bool
    log_days: int
    include_telemetry: bool


def profile_from_config(cfg: dict, name: str) -> BackupProfile:
    profs = (cfg.get("profiles") or {})
    p = (profs.get(name) or {})
    return BackupProfile(
        name=name,
        include_logs=bool(p.get("include_logs", False)),
        log_days=int(p.get("log_days", 0) or 0),
        include_telemetry=bool(p.get("include_telemetry", False)),
    )


def collect_paths(root: str, *, profile: BackupProfile) -> Tuple[List[str], List[str]]:
    """
    Returns (files, warnings) as absolute paths.
    """
    warnings: List[str] = []
    files: List[str] = []

    def add_dir(rel: str) -> None:
        base = os.path.join(root, rel)
        if not os.path.exists(base):
            warnings.append(f"Missing: {rel}")
            return
        for dirpath, dirnames, filenames in os.walk(base):
            # exclude volatile/cache
            dirnames[:] = [d for d in dirnames if d not in {"__pycache__", "tmp", "cache", "models"}]
            for fn in filenames:
                if fn.endswith(".pyc"):
                    continue
                if rel.startswith("logs") and ("/audio" in dirpath.replace("\\", "/") or "\\audio" in dirpath):
                    # exclude raw audio by default
                    continue
                files.append(os.path.join(dirpath, fn))

    # Always include core state
    add_dir("config")
    add_dir(os.path.join("config", "backups", "last_known_good"))
    add_dir("secure")  # encrypted store only; we don't decrypt
    add_dir("runtime")

    # Audit head always (timeline integrity signal)
    audit_head = os.path.join(root, "logs", "audit", "head.json")
    if os.path.exists(audit_head):
        files.append(audit_head)
    else:
        warnings.append("Missing: logs/audit/head.json")

    # Logs per profile
    if profile.include_logs:
        logs_dir = os.path.join(root, "logs")
        cutoff = time.time() - float(max(0, profile.log_days) * 86400) if profile.log_days else 0.0
        if os.path.isdir(logs_dir):
            for dirpath, dirnames, filenames in os.walk(logs_dir):
                dirnames[:] = [d for d in dirnames if d not in {"audio", "__pycache__"}]
                for fn in filenames:
                    p = os.path.join(dirpath, fn)
                    if fn.endswith(".pyc"):
                        continue
                    try:
                        if cutoff and os.path.getmtime(p) < cutoff:
                            continue
                    except Exception:
                        continue
                    files.append(p)
        else:
            warnings.append("Missing: logs/")

    # Telemetry snapshots (optional)
    if profile.include_telemetry:
        add_dir(os.path.join("logs", "telemetry", "snapshots"))

    # docs optional
    if os.path.isdir(os.path.join(root, "docs")):
        add_dir("docs")

    # de-dup + only files
    uniq = []
    seen = set()
    for p in files:
        if p in seen:
            continue
        seen.add(p)
        if os.path.isfile(p):
            uniq.append(p)
    return uniq, warnings

