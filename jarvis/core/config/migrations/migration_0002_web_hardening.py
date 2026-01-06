from __future__ import annotations

from typing import Any, Dict, Tuple


def migrate(all_files: Dict[str, Dict[str, Any]]) -> Tuple[Dict[str, Dict[str, Any]], int]:
    """
    Migration 0002: normalize legacy web.json keys -> hardened schema.
    - host -> bind_host
    - allow_remote_admin_unlock -> admin.allow_remote_unlock
    - ensure allow_remote default false
    """
    out = dict(all_files)
    web = dict(out.get("web.json") or {})
    if "host" in web and "bind_host" not in web:
        web["bind_host"] = web.pop("host")
    if "allow_remote_admin_unlock" in web:
        admin = dict(web.get("admin") or {})
        admin["allow_remote_unlock"] = bool(web.pop("allow_remote_admin_unlock"))
        if "allowed_admin_ips" not in admin:
            admin["allowed_admin_ips"] = ["127.0.0.1"]
        web["admin"] = admin
    if "allow_remote" not in web:
        web["allow_remote"] = False
    out["web.json"] = web
    return out, 2

