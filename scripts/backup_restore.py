from __future__ import annotations

import argparse

from jarvis.core.backup.api import BackupManager
from jarvis.core.config.manager import get_config


def main() -> int:
    ap = argparse.ArgumentParser(description="Jarvis backup restore (dry-run by default)")
    ap.add_argument("zip_path")
    ap.add_argument("--mode", default="all", choices=["config", "runtime", "secure", "all"])
    ap.add_argument("--apply", action="store_true", help="Apply restore (overwrites files).")
    args = ap.parse_args()

    cm = get_config(logger=None)
    cfg = cm.get()
    mgr = BackupManager(cfg=cfg.backup.model_dump(), root_dir=".", config_manager=cm)
    res = mgr.restore(args.zip_path, mode=args.mode, dry_run=not args.apply, apply=bool(args.apply))
    print(res)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

