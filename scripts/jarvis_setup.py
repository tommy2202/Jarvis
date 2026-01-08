from __future__ import annotations

import logging

from jarvis.core.config import ConfigManager
from jarvis.core.config.paths import ConfigFsPaths
from jarvis.core.secure_store import SecureStore
from jarvis.core.logger import setup_logging
from jarvis.core.setup_wizard import SetupWizard


def main() -> None:
    logger = setup_logging("logs")
    cm = ConfigManager(fs=ConfigFsPaths("."), logger=logger)
    cfg_obj = cm.load_all()
    store = SecureStore(
        usb_key_path=cfg_obj.security.usb_key_path,
        store_path=cfg_obj.security.secure_store_path,
        meta_path="secure/store.meta.json",
        backups_dir="secure/backups",
        max_backups=int(cfg_obj.security.secure_store_backup_keep),
        max_bytes=int(cfg_obj.security.secure_store_max_bytes),
        read_only=bool(cfg_obj.security.secure_store_read_only),
    )

    wiz = SetupWizard(cfg=None, paths=None, secure_store=store, logger=logger)  # type: ignore[arg-type]
    wiz.run_interactive()


if __name__ == "__main__":
    main()

