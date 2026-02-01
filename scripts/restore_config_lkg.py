from __future__ import annotations

import argparse
import os
import sys

from jarvis.core.config import ConfigManager
from jarvis.core.config.paths import ConfigFsPaths
from jarvis.core.ops_log import OpsLogger
from jarvis.core.secure_store import SecureStore
from jarvis.core.security import AdminSession, SecurityManager


def main() -> None:
    ap = argparse.ArgumentParser(description="Restore security-critical configs from .lkg/ (admin required).")
    ap.add_argument("--root", default=".", help="Jarvis root directory (default: .)")
    ap.add_argument("--passphrase", default=None, help="Admin passphrase (or set env var).")
    ap.add_argument("--passphrase-env", default="JARVIS_ADMIN_PASSPHRASE", help="Env var to read passphrase from.")
    args = ap.parse_args()

    root_dir = str(args.root or ".")
    passphrase = args.passphrase or os.environ.get(str(args.passphrase_env or ""))
    if not passphrase:
        print("Admin passphrase required (--passphrase or env).", file=sys.stderr)
        raise SystemExit(2)

    cm = ConfigManager(fs=ConfigFsPaths(root_dir), logger=None)
    cfg = cm.load_all()
    store = SecureStore(
        usb_key_path=cfg.security.usb_key_path,
        store_path=cfg.security.secure_store_path,
        meta_path=os.path.join(root_dir, "secure", "store.meta.json"),
        backups_dir=os.path.join(root_dir, "secure", "backups"),
        max_backups=int(cfg.security.secure_store_backup_keep),
        max_bytes=int(cfg.security.secure_store_max_bytes),
        read_only=False,
    )
    sec = SecurityManager(secure_store=store, admin_session=AdminSession(timeout_seconds=int(cfg.security.admin_session_timeout_seconds)))
    if not sec.verify_and_unlock_admin(passphrase):
        print("Admin verification failed.", file=sys.stderr)
        raise SystemExit(1)

    ops = OpsLogger(path=os.path.join(root_dir, "logs", "ops.jsonl"))
    restored = cm.restore_security_lkg(root_dir=root_dir, security_manager=sec, ops=ops)
    if not restored:
        print("No LKG files restored.")
        return
    print("Restored: " + ", ".join(sorted(restored)))


if __name__ == "__main__":
    main()
