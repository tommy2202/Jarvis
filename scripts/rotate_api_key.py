from __future__ import annotations

import secrets

from jarvis.core.config_loader import ConfigLoader, ConfigPaths
from jarvis.core.crypto import SecureStore


def main() -> None:
    paths = ConfigPaths()
    cfg = ConfigLoader(paths)
    sec = cfg.load(paths.security) or {}
    usb_path = str(sec.get("usb_key_path") or r"E:\JARVIS_KEY.bin")
    store_path = str(sec.get("secure_store_path") or "secure/secure_store.enc")

    store = SecureStore(usb_key_path=usb_path, store_path=store_path)
    if not store.is_unlocked():
        raise SystemExit("USB key missing: cannot create/rotate API key.")

    api_key = secrets.token_urlsafe(32)
    store.secure_set("web.api_key", api_key)
    print("Rotated web API key (stored encrypted). New key:")
    print(api_key)


if __name__ == "__main__":
    main()

