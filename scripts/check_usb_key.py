from __future__ import annotations

import os

from jarvis.core.config import ConfigManager
from jarvis.core.config.paths import ConfigFsPaths
from jarvis.core.crypto import key_id_from_key_bytes, read_usb_key


def main() -> None:
    cm = ConfigManager(fs=ConfigFsPaths("."), logger=None)
    cfg = cm.load_all()
    path = str(cfg.security.usb_key_path or r"E:\JARVIS_KEY.bin")
    if not os.path.exists(path):
        raise SystemExit(f"USB key missing at: {path}")
    b = read_usb_key(path)
    print(f"USB key path: {path}")
    print(f"key_id: {key_id_from_key_bytes(b)}")


if __name__ == "__main__":
    main()

