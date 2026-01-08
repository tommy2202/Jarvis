from __future__ import annotations

import argparse

from jarvis.core.backup.api import BackupManager
from jarvis.core.config.manager import get_config


def main() -> int:
    ap = argparse.ArgumentParser(description="Jarvis backup verify")
    ap.add_argument("zip_path")
    args = ap.parse_args()
    cm = get_config(logger=None)
    cfg = cm.get()
    mgr = BackupManager(cfg=cfg.backup.model_dump(), root_dir=".", config_manager=cm)
    res = mgr.verify_backup(args.zip_path)
    print(res)
    return 0 if res.get("ok") else 2


if __name__ == "__main__":
    raise SystemExit(main())

