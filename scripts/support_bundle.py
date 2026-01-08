from __future__ import annotations

import argparse

from jarvis.core.backup.api import BackupManager
from jarvis.core.config.manager import get_config


def main() -> int:
    ap = argparse.ArgumentParser(description="Jarvis support bundle exporter (redacted)")
    ap.add_argument("--days", type=int, default=None)
    ap.add_argument("--path", default=None)
    args = ap.parse_args()

    cm = get_config(logger=None)
    cfg = cm.get()
    mgr = BackupManager(cfg=cfg.backup.model_dump(), root_dir=".", config_manager=cm)
    days = int(args.days) if args.days is not None else int((cfg.backup.support_bundle or {}).get("default_days", 7))
    zip_path = mgr.export_support_bundle(days=days, out_dir=args.path)
    print(zip_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

