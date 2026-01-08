from __future__ import annotations

import argparse
import os

from jarvis.core.config import ConfigManager
from jarvis.core.config.paths import ConfigFsPaths
from jarvis.core.secure_store import SecureStore


def main() -> None:
    ap = argparse.ArgumentParser(description="Restore secure store from backups (requires USB key).")
    ap.add_argument("backup", nargs="?", default=None, help="Backup filename to restore (from secure/backups/)")
    ap.add_argument("--list", action="store_true", help="List available backups.")
    args = ap.parse_args()

    cm = ConfigManager(fs=ConfigFsPaths("."), logger=None)
    cfg = cm.load_all()
    sec = cfg.security

    store = SecureStore(
        usb_key_path=sec.usb_key_path,
        store_path=sec.secure_store_path,
        meta_path=os.path.join("secure", "store.meta.json"),
        backups_dir=os.path.join("secure", "backups"),
        max_backups=int(sec.secure_store_backup_keep),
        max_bytes=int(sec.secure_store_max_bytes),
        read_only=False,
    )

    if args.list or not args.backup:
        if not os.path.isdir(store.backups_dir):
            print("No backups directory found.")
            return
        files = [f for f in os.listdir(store.backups_dir) if f.startswith("secure_store.") and f.endswith(".enc")]
        files.sort(reverse=True)
        for f in files:
            print(f)
        return

    backup_path = args.backup
    if not os.path.isabs(backup_path):
        backup_path = os.path.join(store.backups_dir, backup_path)
    store.restore_backup(backup_path)
    print("Restore complete.")


if __name__ == "__main__":
    main()

