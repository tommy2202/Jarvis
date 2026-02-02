from __future__ import annotations

from typing import Any, Dict, Optional


def _with_overrides(base: Dict[str, Any], overrides: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    out = dict(base)
    if overrides:
        out.update(overrides)
    return out


def build_policy_config_v1(*, overrides: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    return _with_overrides({"schema_version": 1}, overrides)


def build_privacy_config_v1(*, overrides: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    return _with_overrides({"schema_version": 1}, overrides)


def build_capabilities_config_v1(
    *, capabilities: Optional[Dict[str, Any]] = None, overrides: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    base = {"schema_version": 1, "capabilities": capabilities or {}}
    return _with_overrides(base, overrides)


def build_execution_config_v1(*, overrides: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    return _with_overrides({"schema_version": 1}, overrides)


def build_web_config_v1(*, overrides: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    return _with_overrides({"schema_version": 1}, overrides)


def build_module_trust_config_v1(*, overrides: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    return _with_overrides({"schema_version": 1}, overrides)
