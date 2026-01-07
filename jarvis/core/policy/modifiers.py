from __future__ import annotations

from typing import Any, Dict


_SAFE_FLAGS = {"tts_enabled", "voice_enabled", "allow_network", "allow_subprocess"}


def merge_modifications(base: Dict[str, Any], new: Dict[str, Any]) -> Dict[str, Any]:
    """
    Merge policy modifications, never relaxing privileges:
    - flags may only disable (set false), never enable.
    - llm_params caps may only decrease.
    """
    out = dict(base or {})
    for k, v in (new or {}).items():
        if k == "flags" and isinstance(v, dict):
            flags = dict(out.get("flags") or {})
            for fk, fv in v.items():
                if fk not in _SAFE_FLAGS:
                    continue
                # Only allow setting to False (or leaving unset). Never True.
                if fv is False:
                    flags[fk] = False
                elif fk not in flags:
                    # if someone tries to set True, ignore
                    continue
            out["flags"] = flags
            continue

        if k == "llm_params" and isinstance(v, dict):
            lp = dict(out.get("llm_params") or {})
            # max_tokens cap: choose min
            if "max_tokens" in v:
                try:
                    nv = int(v["max_tokens"])
                    ov = int(lp.get("max_tokens")) if lp.get("max_tokens") is not None else None
                    lp["max_tokens"] = nv if ov is None else min(ov, nv)
                except Exception:
                    pass
            # temperature cap: choose min
            if "temperature" in v:
                try:
                    nv = float(v["temperature"])
                    ov = float(lp.get("temperature")) if lp.get("temperature") is not None else None
                    lp["temperature"] = nv if ov is None else min(ov, nv)
                except Exception:
                    pass
            # role override: only allow forcing "chat" (never coder escalation)
            if "role" in v:
                if str(v["role"]) == "chat":
                    lp["role"] = "chat"
            out["llm_params"] = lp
            continue

        if k == "execution" and isinstance(v, dict):
            ex = dict(out.get("execution") or {})
            if "max_runtime_seconds" in v:
                try:
                    nv = int(v["max_runtime_seconds"])
                    ov = int(ex.get("max_runtime_seconds")) if ex.get("max_runtime_seconds") is not None else None
                    ex["max_runtime_seconds"] = nv if ov is None else min(ov, nv)
                except Exception:
                    pass
            if "force_profile" in v:
                # only allow forcing "low"
                if str(v["force_profile"]) == "low":
                    ex["force_profile"] = "low"
            out["execution"] = ex
            continue
    return out

