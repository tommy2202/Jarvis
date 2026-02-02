from __future__ import annotations

from typing import Any, Dict, Optional


def _with_overrides(
    base: Dict[str, Any],
    overrides: Optional[Dict[str, Any]] = None,
    **kwargs: Any,
) -> Dict[str, Any]:
    out = dict(base)
    if overrides:
        out.update(overrides)
    if kwargs:
        out.update(kwargs)
    return out


def build_policy_config_v1(*, overrides: Optional[Dict[str, Any]] = None, **kwargs: Any) -> Dict[str, Any]:
    return _with_overrides({"schema_version": 1}, overrides, **kwargs)


def build_privacy_config_v1(*, overrides: Optional[Dict[str, Any]] = None, **kwargs: Any) -> Dict[str, Any]:
    return _with_overrides({"schema_version": 1}, overrides, **kwargs)


def build_capabilities_config_v1(
    *,
    capabilities: Optional[Dict[str, Any]] = None,
    overrides: Optional[Dict[str, Any]] = None,
    **kwargs: Any,
) -> Dict[str, Any]:
    base = {"schema_version": 1, "capabilities": capabilities or {}}
    return _with_overrides(base, overrides, **kwargs)


def build_execution_config_v1(*, overrides: Optional[Dict[str, Any]] = None, **kwargs: Any) -> Dict[str, Any]:
    return _with_overrides({"schema_version": 1}, overrides, **kwargs)


def build_web_config_v1(*, overrides: Optional[Dict[str, Any]] = None, **kwargs: Any) -> Dict[str, Any]:
    return _with_overrides({"schema_version": 1}, overrides, **kwargs)


def build_module_trust_config_v1(*, overrides: Optional[Dict[str, Any]] = None, **kwargs: Any) -> Dict[str, Any]:
    return _with_overrides({"schema_version": 1}, overrides, **kwargs)


def build_modules_config_v1(*, overrides: Optional[Dict[str, Any]] = None, **kwargs: Any) -> Dict[str, Any]:
    return _with_overrides({"schema_version": 1}, overrides, **kwargs)
