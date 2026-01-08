from __future__ import annotations

import logging
import os
from logging.handlers import RotatingFileHandler


def setup_logging(log_dir: str = "logs") -> logging.Logger:
    os.makedirs(log_dir, exist_ok=True)

    logger = logging.getLogger("jarvis")
    logger.setLevel(logging.INFO)
    logger.propagate = False

    if not any(isinstance(h, RotatingFileHandler) for h in logger.handlers):
        text_path = os.path.join(log_dir, "jarvis.log")
        h = RotatingFileHandler(text_path, maxBytes=1_000_000, backupCount=5, encoding="utf-8")
        fmt = logging.Formatter("%(asctime)s | %(levelname)s | %(message)s")
        h.setFormatter(fmt)
        logger.addHandler(h)

    if not any(isinstance(h, logging.StreamHandler) and not isinstance(h, RotatingFileHandler) for h in logger.handlers):
        sh = logging.StreamHandler()
        sh.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(sh)

    return logger

