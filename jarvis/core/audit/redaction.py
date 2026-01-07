from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, Optional


_SECRET_KEYS = {
    "password",
    "passphrase",
    "api_key",
    "apikey",
    "token",
    "access_key",
    "authorization",
    "secret",
    "bearer",
    "key",
}

_BEARER_RE = re.compile(r"(authorization:\s*bearer\s+)([A-Za-z0-9\-\._~\+/]+=*)", re.IGNORECASE)
_KV_RE = re.compile(r"(?i)\b(password|passphrase|token|api[_-]?key|access[_-]?key)\s*=\s*([^\s,;]+)")


def _mask_ip(ip: str) -> str:
    # Minimal privacy: keep /24 only for IPv4; otherwise return "ip".
    try:
        parts = ip.split(".")
        if len(parts) == 4:
            return ".".join(parts[:3] + ["x"])
    except Exception:
        pass
    return "ip"


def redact_value(v: Any) -> Any:
    if v is None:
        return None
    if isinstance(v, (int, float, bool)):
        return v
    if isinstance(v, (bytes, bytearray)):
        return "<bytes>"
    if isinstance(v, str):
        s = v
        s = _BEARER_RE.sub(r"\1<redacted>", s)
        s = _KV_RE.sub(r"\1=<redacted>", s)
        if len(s) > 300:
            s = s[:300] + "…"
        return s
    if isinstance(v, list):
        return [redact_value(x) for x in v[:50]]
    if isinstance(v, dict):
        out: Dict[str, Any] = {}
        for k, vv in list(v.items())[:100]:
            kk = str(k)
            if kk.lower() in _SECRET_KEYS:
                out[kk] = "<redacted>"
                continue
            if kk.lower() in {"message", "text", "prompt", "transcript"}:
                out[kk] = "<redacted>"
                continue
            if kk.lower() in {"ip", "client_ip", "remote_ip"} and isinstance(vv, str):
                out[kk] = _mask_ip(vv)
                continue
            out[kk] = redact_value(vv)
        return out
    return str(v)[:300]


def redact_details(category: str, action: str, details: Dict[str, Any]) -> Dict[str, Any]:
    """
    Privacy-safe, category-aware redaction.
    - Drops raw user content
    - Redacts obvious secret keys
    - For intents: keep args keys only
    """
    d = redact_value(details or {})
    if not isinstance(d, dict):
        return {}
    # Intent execution: keep only arg keys
    if action in {"intent.execute", "intent.denied", "intent.routed"}:
        args = d.get("args")
        if isinstance(args, dict):
            d["args"] = {"keys": sorted(list(args.keys()))[:50]}
    return d

