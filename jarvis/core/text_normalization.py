from __future__ import annotations

import re
import string
from typing import List


_PUNCT_TABLE = str.maketrans({c: " " for c in string.punctuation})


def normalize_for_matching(text: str) -> str:
    """
    Deterministic, local normalization for intent matching:
    - lowercase
    - strip punctuation (→ spaces)
    - collapse whitespace
    """
    s = str(text or "").lower()
    s = s.translate(_PUNCT_TABLE)
    s = " ".join(s.split())
    return s


def tokenize(text: str) -> List[str]:
    """
    Tokenization used by routing/matching. Keep stable across routers.
    """
    return re.findall(r"[a-z0-9']+", normalize_for_matching(text))

