from __future__ import annotations

import pytest

from jarvis.web.api import create_app


def test_cors_wildcard_rejected(tmp_path):
    # create_app should reject wildcard origins
    from jarvis.core.crypto import generate_usb_master_key_bytes, write_usb_key
    from jarvis.core.events import EventLogger
    from jarvis.core.secure_store import SecureStore

    usb = tmp_path / "usb.bin"
    write_usb_key(str(usb), generate_usb_master_key_bytes())
    store = SecureStore(usb_key_path=str(usb), store_path=str(tmp_path / "store.enc"), meta_path=str(tmp_path / "meta.json"), backups_dir=str(tmp_path / "b"))
    with pytest.raises(ValueError):
        create_app(
            jarvis_app=object(),
            security_manager=object(),
            event_logger=EventLogger(str(tmp_path / "events.jsonl")),
            logger=object(),
            auth_dep=None,
            job_manager=None,
            runtime=None,
            secure_store=store,
            web_cfg={"max_request_bytes": 32768, "rate_limits": {"per_ip_per_minute": 60, "per_key_per_minute": 30, "admin_per_minute": 5}, "lockout": {"strike_threshold": 5, "lockout_minutes": 15, "permanent_after": 3}, "admin": {"allow_remote_unlock": False, "allowed_admin_ips": ["127.0.0.1"]}},
            allowed_origins=["*"],
            enable_web_ui=False,
            remote_control_enabled=True,
        )

