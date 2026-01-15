from __future__ import annotations

"""
Core identity + active session.

IMPORTANT:
This package does not replace the existing admin unlock system. Admin privilege
and expiry remain authoritative in `SecurityManager` / `AdminSession`.
IdentityManager only provides user attribution + an active user concept.
"""

