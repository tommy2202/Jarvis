from __future__ import annotations

import argparse
import os
import shutil

from jarvis.core.config import ConfigManager
from jarvis.core.config.paths import ConfigFsPaths
from jarvis.core.secure_store import SecureStore


def main() -> None:
    ap = argparse.ArgumentParser(description="Rotate USB key without bricking data.")
    ap.add_argument("--new-key-path", default=None, help="Path for new key file (default: <old>.new)")
    ap.add_argument("--new-store-path", default=None, help="Path for new store file (default: <store>.new)")
    ap.add_argument("--apply", action="store_true", help="Apply swap after preparing .new files.")
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

    st = store.status()
    if st.mode.value != "READY":
        raise SystemExit(f"Store not ready for rotation: {st.mode.value} ({st.next_steps})")

    old_key_path = sec.usb_key_path
    old_store_path = sec.secure_store_path
    new_key_path = args.new_key_path or (old_key_path + ".new")
    new_store_path = args.new_store_path or (old_store_path + ".new")

    info = store.rotate_key_prepare(new_key_path=new_key_path, new_store_path=new_store_path)
    print("Rotation prepared. Files created:")
    print(f"- new key:   {info['new_key_path']} (key_id={info['new_key_id']})")
    print(f"- new store: {info['new_store_path']}")
    print("")
    print("Checklist:")
    print("1) Verify the new key_id above matches your expectation.")
    print("2) Backup your old key and old store files.")
    print("3) Swap files (rename .new into place).")
    print("")

    if not args.apply:
        print("Run again with --apply to perform the swap automatically.")
        return

    # Back up old files before swapping
    os.makedirs(os.path.join("secure", "backups"), exist_ok=True)
    shutil.copy2(old_store_path, os.path.join("secure", "backups", os.path.basename(old_store_path) + ".pre_rotate"))
    shutil.copy2(old_key_path, os.path.join("secure", "backups", os.path.basename(old_key_path) + ".pre_rotate"))

    # Swap into place
    os.replace(new_key_path, old_key_path)
    os.replace(new_store_path, old_store_path)
    print("Swap completed.")


if __name__ == "__main__":
    main()

