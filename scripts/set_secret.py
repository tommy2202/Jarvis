from __future__ import annotations

import getpass
import sys

from jarvis.core.config import ConfigManager
from jarvis.core.config.paths import ConfigFsPaths


def main() -> None:
    if len(sys.argv) < 2:
        raise SystemExit("Usage: python scripts/set_secret.py <key> [value]")

    key = sys.argv[1].strip()
    if not key:
        raise SystemExit("Key cannot be empty.")

    value = sys.argv[2] if len(sys.argv) >= 3 else None
    if value is None:
        value = getpass.getpass(f"Value for {key}: ")

    cm = ConfigManager(fs=ConfigFsPaths("."), logger=None)
    cm.load_all()
    try:
        cm.set_secret(key, value)
    except Exception as e:
        raise SystemExit(str(e)) from e
    print(f"Saved secret: {key}")


if __name__ == "__main__":
    main()

