from __future__ import annotations

import os

from jarvis.core.config_loader import ConfigLoader, ConfigPaths
from jarvis.core.crypto import generate_usb_master_key_bytes, write_usb_key


def main() -> None:
    paths = ConfigPaths()
    cfg = ConfigLoader(paths)
    sec = cfg.load(paths.security) or {}
    usb_path = str(sec.get("usb_key_path") or r"E:\JARVIS_KEY.bin")

    if os.path.exists(usb_path):
        print(f"USB key already exists at: {usb_path}")
        return

    key = generate_usb_master_key_bytes()
    write_usb_key(usb_path, key)
    print(f"Created USB key at: {usb_path}")


if __name__ == "__main__":
    main()

