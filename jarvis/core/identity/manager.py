from __future__ import annotations

"""
IdentityManager: user attribution + active session.

No duplicate admin session system:
- Admin privilege and expiry remain in `SecurityManager.admin_session`.
"""

import time
import uuid
from typing import Any, Optional

from jarvis.core.identity.models import ActiveSession, UserIdentity, UserRole


def _iso_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


class IdentityManager:
    def __init__(self, *, privacy_store: Any, security_manager: Any, logger: Any = None):
        self.privacy_store = privacy_store
        self.security = security_manager
        self.logger = logger
        self._active_user_id: Optional[str] = None
        self._active_session: Optional[ActiveSession] = None

    def load_or_create_default_user(self) -> UserIdentity:
        """
        Uses the existing privacy store user table as the durable identity store.
        """
        u = self.privacy_store.get_or_create_default_user()
        # privacy store returns its own model; normalize into identity model shape
        out = UserIdentity(user_id=str(u.user_id), display_name=str(getattr(u, "display_name", "") or ""))
        self._active_user_id = out.user_id
        return out

    def get_active_user(self) -> UserIdentity:
        if not self._active_user_id:
            return self.load_or_create_default_user()
        # best-effort fetch from privacy store (source of truth)
        try:
            u = self.privacy_store.get_or_create_user(user_id=self._active_user_id, display_name="", is_default=False)
            return UserIdentity(user_id=str(u.user_id), display_name=str(getattr(u, "display_name", "") or ""), role=(UserRole.admin if bool(self.security.is_admin()) else UserRole.user))
        except Exception:
            return UserIdentity(user_id=str(self._active_user_id), display_name="", role=(UserRole.admin if bool(self.security.is_admin()) else UserRole.user))

    def start_session(self, *, is_admin: bool) -> ActiveSession:
        """
        Start a new active session for the current active user.

        Admin sessions require the existing admin unlock to be active.
        """
        u = self.get_active_user()
        if is_admin and not bool(self.security.is_admin()):
            raise PermissionError("Admin required.")
        expires_at = None
        if is_admin:
            try:
                sess = getattr(self.security, "admin_session", None)
                timeout = float(getattr(sess, "timeout_seconds", 0.0) or 0.0)
                expires_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + timeout)) if timeout > 0 else None
            except Exception:
                expires_at = None
        s = ActiveSession(session_id=uuid.uuid4().hex, user_id=u.user_id, is_admin=bool(is_admin), started_at=_iso_now(), expires_at=expires_at)
        self._active_session = s
        self._active_user_id = u.user_id
        return s

    def end_session(self) -> None:
        self._active_session = None
        try:
            self.security.lock_admin()
        except Exception:
            pass

    def switch_active_user(self, user_id: str) -> UserIdentity:
        """
        Switch active user (admin only).
        """
        if not bool(self.security.is_admin()):
            raise PermissionError("Admin required.")
        uid = str(user_id or "").strip()
        if not uid:
            raise ValueError("user_id required")
        # Ensure user exists
        u = self.privacy_store.get_or_create_user(user_id=uid, display_name="", is_default=False)
        self._active_user_id = str(u.user_id)
        # switching user ends current session (safety)
        self._active_session = None
        return UserIdentity(user_id=str(u.user_id), display_name=str(getattr(u, "display_name", "") or ""), role=UserRole.user)

    def active_session(self) -> Optional[ActiveSession]:
        """
        Return current active session view (admin flag is live).
        """
        if self._active_session is None:
            return None
        # reflect current admin expiry behavior
        is_admin_live = bool(self.security.is_admin())
        return self._active_session.model_copy(update={"is_admin": is_admin_live})

