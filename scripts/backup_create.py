from __future__ import annotations

import argparse
import sys

from jarvis.core.backup.api import BackupManager
from jarvis.core.config.manager import get_config


def main() -> int:
    ap = argparse.ArgumentParser(description="Jarvis backup create")
    ap.add_argument("profile", nargs="?", default="standard", choices=["minimal", "standard", "full"])
    ap.add_argument("--path", default=None, help="Output directory (defaults to config/backup.json default_dir)")
    args = ap.parse_args()

    cm = get_config(logger=None)
    cfg = cm.get()
    mgr = BackupManager(cfg=cfg.backup.model_dump(), root_dir=".", config_manager=cm, secure_store=None, runtime_state=None, audit_timeline=None, telemetry=None)
    zip_path = mgr.create_backup(profile=args.profile, out_dir=args.path)
    print(zip_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

