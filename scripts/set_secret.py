from __future__ import annotations

import getpass
import sys

from jarvis.core.config_loader import ConfigLoader, ConfigPaths
from jarvis.core.crypto import SecureStore


def main() -> None:
    if len(sys.argv) < 2:
        raise SystemExit("Usage: python scripts/set_secret.py <key> [value]")

    key = sys.argv[1].strip()
    if not key:
        raise SystemExit("Key cannot be empty.")

    value = sys.argv[2] if len(sys.argv) >= 3 else None
    if value is None:
        value = getpass.getpass(f"Value for {key}: ")

    paths = ConfigPaths()
    cfg = ConfigLoader(paths)
    sec = cfg.load(paths.security) or {}
    usb_path = str(sec.get("usb_key_path") or r"E:\JARVIS_KEY.bin")
    store_path = str(sec.get("secure_store_path") or "secure/secure_store.enc")

    store = SecureStore(usb_key_path=usb_path, store_path=store_path)
    if not store.is_unlocked():
        raise SystemExit("USB key missing: cannot set encrypted secrets.")

    store.secure_set(key, value)
    print(f"Saved secret: {key}")


if __name__ == "__main__":
    main()

