from __future__ import annotations

import secrets

from jarvis.core.config_loader import ConfigLoader, ConfigPaths
from jarvis.core.secure_store import SecureStore
from jarvis.web.security.auth import ApiKeyStore


def main() -> None:
    paths = ConfigPaths()
    cfg = ConfigLoader(paths)
    sec = cfg.load(paths.security) or {}
    usb_path = str(sec.get("usb_key_path") or r"E:\JARVIS_KEY.bin")
    store_path = str(sec.get("secure_store_path") or "secure/secure_store.enc")

    store = SecureStore(usb_key_path=usb_path, store_path=store_path)
    if store.status().mode.value == "KEY_MISSING":
        raise SystemExit("USB key missing: cannot create/rotate API key.")

    ks = ApiKeyStore(store)
    rec = ks.create_key(scopes=["read", "message", "admin"])
    print("Created new web API key (stored encrypted). New key (shown once):")
    print(rec["key"])
    print(f"Key id: {rec['id']}")


if __name__ == "__main__":
    main()

