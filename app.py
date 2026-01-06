from __future__ import annotations

import getpass
import threading
import time
from typing import Any, Dict

import uvicorn

from jarvis.core.config_loader import ConfigLoader, ConfigPaths
from jarvis.core.crypto import SecureStore
from jarvis.core.dispatcher import Dispatcher
from jarvis.core.events import EventLogger
from jarvis.core.intent_router import StageAIntent, StageAIntentRouter
from jarvis.core.jarvis_app import JarvisApp
from jarvis.core.llm_router import LLMConfig, StageBLLMRouter
from jarvis.core.logger import setup_logging
from jarvis.core.module_registry import ModuleRegistry
from jarvis.core.security import AdminSession, PermissionPolicy, SecurityManager
from jarvis.core.setup_wizard import SetupWizard
from jarvis.web.api import create_app
from jarvis.web.auth import build_api_key_auth


def _load_json(cfg: ConfigLoader, path: str, default: Dict[str, Any]) -> Dict[str, Any]:
    data = cfg.load(path)
    return data if isinstance(data, dict) and data else dict(default)


def _ensure_admin_passphrase(security: SecurityManager, logger) -> None:
    if not security.is_usb_present():
        logger.info("USB key missing: admin features locked.")
        return
    if security.has_admin_passphrase_set():
        return
    try:
        p1 = getpass.getpass("Set admin passphrase (will be stored encrypted): ")
        p2 = getpass.getpass("Confirm admin passphrase: ")
    except (EOFError, KeyboardInterrupt):
        logger.warning("Admin passphrase not set (interactive input unavailable).")
        return
    if not p1 or p1 != p2:
        logger.warning("Admin passphrase not set (mismatch/empty).")
        return
    security.set_admin_passphrase(p1)
    logger.info("Admin passphrase set.")


def _start_web_thread(jarvis: JarvisApp, security: SecurityManager, secure_store: SecureStore, cfg: ConfigLoader, paths: ConfigPaths, event_logger: EventLogger, logger) -> None:
    web_cfg = _load_json(
        cfg,
        paths.web,
        default={"enabled": False, "host": "0.0.0.0", "port": 8787, "allowed_origins": [], "enable_web_ui": True, "allow_remote_admin_unlock": False},
    )
    if not web_cfg.get("enabled", False):
        return

    enable_web_ui = bool(web_cfg.get("enable_web_ui", True))
    allow_remote_admin_unlock = bool(web_cfg.get("allow_remote_admin_unlock", False))
    allowed_origins = web_cfg.get("allowed_origins") or []

    remote_control_enabled = True
    auth = None

    if not secure_store.is_unlocked():
        # Safest: do not expose remote control without USB key.
        remote_control_enabled = False
        host = "127.0.0.1"
        port = int(web_cfg.get("port", 8787))
        logger.warning("USB key missing: starting web server on localhost only with remote control disabled.")
    else:
        host = str(web_cfg.get("host") or "0.0.0.0")
        port = int(web_cfg.get("port") or 8787)
        api_key = secure_store.secure_get("web.api_key")
        if not api_key:
            logger.error("Web enabled but API key not found. Run: python scripts/rotate_api_key.py")
            return
        auth = build_api_key_auth(api_key=str(api_key), event_logger=event_logger)

    fastapi_app = create_app(
        jarvis_app=jarvis,
        security_manager=security,
        event_logger=event_logger,
        logger=logger,
        auth_dep=auth,
        allowed_origins=list(allowed_origins),
        enable_web_ui=enable_web_ui,
        allow_remote_admin_unlock=allow_remote_admin_unlock,
        remote_control_enabled=remote_control_enabled,
    )

    def run() -> None:
        uvicorn.run(fastapi_app, host=host, port=port, log_level="info")

    t = threading.Thread(target=run, name="jarvis-web", daemon=True)
    t.start()
    logger.info(f"Web server started on http://{host}:{port}")


def main() -> None:
    logger = setup_logging("logs")
    event_logger = EventLogger("logs/events.jsonl")

    paths = ConfigPaths()
    cfg = ConfigLoader(paths)

    security_cfg = _load_json(
        cfg,
        paths.security,
        default={
            "usb_key_path": r"E:\JARVIS_KEY.bin",
            "secure_store_path": "secure/secure_store.enc",
            "admin_session_timeout_seconds": 900,
            "router_confidence_threshold": 0.55,
            "llm": {"base_url": "http://localhost:11434", "timeout_seconds": 5.0, "model": "qwen:14b-chat", "mock_mode": True},
        },
    )

    secure_store = SecureStore(
        usb_key_path=str(security_cfg.get("usb_key_path")),
        store_path=str(security_cfg.get("secure_store_path")),
    )
    security = SecurityManager(secure_store=secure_store, admin_session=AdminSession(timeout_seconds=int(security_cfg.get("admin_session_timeout_seconds", 900))))

    _ensure_admin_passphrase(security, logger)

    # Setup wizard (startup)
    wiz = SetupWizard(cfg=cfg, paths=paths, secure_store=secure_store, logger=logger)
    wiz.run_interactive()

    modules_registry_cfg = _load_json(cfg, paths.modules_registry, default={"modules": []})
    modules_cfg = _load_json(cfg, paths.modules, default={"intents": []})
    perms_cfg = _load_json(cfg, paths.permissions, default={"intents": {}})
    resp_cfg = _load_json(cfg, paths.responses, default={"confirmations": {}})

    # Module registry
    registry = ModuleRegistry()
    for entry in modules_registry_cfg.get("modules") or []:
        if not isinstance(entry, dict) or not entry.get("enabled", False):
            continue
        registry.register(str(entry.get("module")))

    # Stage-A intents
    stage_a_intents = []
    intent_config_by_id: Dict[str, Dict[str, Any]] = {}
    for i in modules_cfg.get("intents") or []:
        if not isinstance(i, dict) or not i.get("id"):
            continue
        intent_id = str(i["id"])
        intent_config_by_id[intent_id] = dict(i)
        stage_a_intents.append(
            StageAIntent(
                id=intent_id,
                module_id=str(i.get("module_id") or ""),
                keywords=list(i.get("keywords") or []),
                required_args=list(i.get("required_args") or []),
            )
        )

    threshold = float(security_cfg.get("router_confidence_threshold", 0.55))
    stage_a = StageAIntentRouter(stage_a_intents, threshold=threshold)

    llm_cfg_raw = security_cfg.get("llm") or {}
    stage_b = StageBLLMRouter(
        LLMConfig(
            base_url=str(llm_cfg_raw.get("base_url", "http://localhost:11434")),
            timeout_seconds=float(llm_cfg_raw.get("timeout_seconds", 5.0)),
            model=str(llm_cfg_raw.get("model", "qwen:14b-chat")),
            mock_mode=bool(llm_cfg_raw.get("mock_mode", True)),
        )
    )

    policy = PermissionPolicy(intents=dict(perms_cfg.get("intents") or {}))
    dispatcher = Dispatcher(registry=registry, policy=policy, security=security, event_logger=event_logger, logger=logger)

    jarvis = JarvisApp(
        stage_a=stage_a,
        stage_b=stage_b,
        dispatcher=dispatcher,
        intent_config_by_id=intent_config_by_id,
        confirmation_templates=dict(resp_cfg.get("confirmations") or {}),
        event_logger=event_logger,
        logger=logger,
        threshold=threshold,
    )

    _start_web_thread(jarvis, security, secure_store, cfg, paths, event_logger, logger)

    logger.info("Jarvis CLI ready. Type /exit to quit.")

    while True:
        try:
            text = input("> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            break
        if not text:
            continue
        if text == "/exit":
            break
        if text.startswith("/admin unlock"):
            if not security.is_usb_present():
                print("USB key required for admin unlock.")
                continue
            try:
                pw = getpass.getpass("Passphrase: ")
            except (EOFError, KeyboardInterrupt):
                print()
                continue
            ok = security.verify_and_unlock_admin(pw)
            print("Admin unlocked." if ok else "Invalid passphrase.")
            continue
        if text.startswith("/admin lock"):
            security.lock_admin()
            print("Admin locked.")
            continue

        resp = jarvis.process_message(text, client={"name": "cli", "id": "stdin"})
        print(resp.reply)
        time.sleep(0.01)


if __name__ == "__main__":
    main()

