from __future__ import annotations

"""
Privacy redaction helpers (content minimization).

This layer is stricter than secret redaction:
- removes raw user text/transcripts/prompts by default
- keeps small metadata only (lengths, keys, counts)
"""

import hashlib
from typing import Any, Dict

from jarvis.core.events import redact as secret_redact


_DROP_KEYS = {"text", "message", "messages", "prompt", "transcript", "audio", "utterance", "raw"}


def _hash8(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8", errors="ignore")).hexdigest()[:8]


def privacy_redact(obj: Any) -> Any:
    """
    Redact secrets + remove raw content fields.
    """
    safe = secret_redact(obj)
    if isinstance(safe, dict):
        out: Dict[str, Any] = {}
        for k, v in list(safe.items())[:200]:
            kk = str(k or "")
            if kk.lower() in _DROP_KEYS:
                # preserve minimal metadata
                if isinstance(v, str):
                    out[f"{kk}_len"] = len(v)
                    out[f"{kk}_hash8"] = _hash8(v)
                else:
                    out[f"{kk}_present"] = True
                continue
            out[kk] = privacy_redact(v)
        return out
    if isinstance(safe, list):
        return [privacy_redact(x) for x in safe[:50]]
    if isinstance(safe, str):
        # keep short strings only (avoid log injection of user content)
        return safe if len(safe) <= 200 else safe[:200] + "…"
    return safe

