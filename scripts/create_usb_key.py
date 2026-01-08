from __future__ import annotations

import os

from jarvis.core.config import ConfigManager
from jarvis.core.config.paths import ConfigFsPaths
from jarvis.core.crypto import generate_usb_master_key_bytes, key_id_from_key_bytes, write_usb_key, best_effort_restrict_permissions


def main() -> None:
    cm = ConfigManager(fs=ConfigFsPaths("."), logger=None)
    cfg = cm.load_all()
    usb_path = str(cfg.security.usb_key_path or r"E:\JARVIS_KEY.bin")

    if os.path.exists(usb_path):
        print(f"USB key already exists at: {usb_path}")
        return

    key = generate_usb_master_key_bytes()
    write_usb_key(usb_path, key)
    best_effort_restrict_permissions(usb_path)
    print(f"Created USB key at: {usb_path}")
    print(f"Key fingerprint (key_id): {key_id_from_key_bytes(key)}")


if __name__ == "__main__":
    main()

