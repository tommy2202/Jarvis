from __future__ import annotations

import logging

from jarvis.core.config_loader import ConfigLoader, ConfigPaths
from jarvis.core.crypto import SecureStore
from jarvis.core.logger import setup_logging
from jarvis.core.setup_wizard import SetupWizard


def main() -> None:
    logger = setup_logging("logs")
    paths = ConfigPaths()
    cfg = ConfigLoader(paths)
    sec = cfg.load(paths.security) or {}
    usb_path = str(sec.get("usb_key_path") or r"E:\JARVIS_KEY.bin")
    store_path = str(sec.get("secure_store_path") or "secure/secure_store.enc")
    store = SecureStore(usb_key_path=usb_path, store_path=store_path)

    wiz = SetupWizard(cfg=cfg, paths=paths, secure_store=store, logger=logger)
    wiz.run_interactive()


if __name__ == "__main__":
    main()

