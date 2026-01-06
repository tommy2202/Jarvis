from __future__ import annotations

import json

from jarvis.core.config import ConfigManager
from jarvis.core.config.paths import ConfigFsPaths


def main() -> None:
    cm = ConfigManager(fs=ConfigFsPaths("."), logger=None)
    cfg = cm.load_all()
    print(json.dumps(cfg.model_dump(), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

