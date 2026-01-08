from __future__ import annotations

import re


_BEARER_RE = re.compile(r"(authorization:\s*bearer\s+)([A-Za-z0-9\-\._~\+/]+=*)", re.IGNORECASE)
_KV_RE = re.compile(r"(?i)\b(password|passphrase|token|api[_-]?key|access[_-]?key)\s*=\s*([^\s,;]+)")


def redact_text(text: str) -> str:
    s = text
    s = _BEARER_RE.sub(r"\1<redacted>", s)
    s = _KV_RE.sub(r"\1=<redacted>", s)
    # Remove obvious raw message fields if present in JSONL lines (best-effort)
    s = re.sub(r'("message"\s*:\s*)"(.*?)"', r'\1"<redacted>"', s, flags=re.IGNORECASE)
    s = re.sub(r'("text"\s*:\s*)"(.*?)"', r'\1"<redacted>"', s, flags=re.IGNORECASE)
    # Trim very long lines
    if len(s) > 5000:
        s = s[:5000] + "…"
    return s

