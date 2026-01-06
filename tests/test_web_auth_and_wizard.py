from __future__ import annotations

import json

from fastapi.testclient import TestClient

from jarvis.core.config_loader import ConfigLoader, ConfigPaths
from jarvis.core.crypto import SecureStore, generate_usb_master_key_bytes, write_usb_key
from jarvis.core.setup_wizard import SetupWizard
from jarvis.web.api import create_app
from jarvis.web.auth import build_api_key_auth
from jarvis.core.jarvis_app import MessageResponse as CoreMessageResponse


class DummyLogger:
    def info(self, *_a, **_k): ...
    def warning(self, *_a, **_k): ...
    def error(self, *_a, **_k): ...


class FakeJarvis:
    def process_message(self, message: str, client=None):
        return CoreMessageResponse(
            trace_id="t1",
            reply="ok",
            intent_id="music.play",
            intent_source="stage_a",
            confidence=0.9,
            requires_followup=False,
            followup_question=None,
        )


class FakeSecurity:
    def verify_and_unlock_admin(self, _passphrase: str) -> bool:
        return True


class FakeEventLogger:
    def log(self, *_a, **_k): ...


def test_web_auth_rejects_missing_or_invalid_key():
    auth = build_api_key_auth(api_key="abc", event_logger=FakeEventLogger())
    app = create_app(
        jarvis_app=FakeJarvis(),
        security_manager=FakeSecurity(),
        event_logger=FakeEventLogger(),
        logger=DummyLogger(),
        auth_dep=auth,
        allowed_origins=[],
        enable_web_ui=False,
        allow_remote_admin_unlock=False,
        remote_control_enabled=True,
    )
    c = TestClient(app)
    r1 = c.post("/v1/message", json={"message": "hi"})
    assert r1.status_code == 401
    r2 = c.post("/v1/message", headers={"X-API-Key": "nope"}, json={"message": "hi"})
    assert r2.status_code == 401
    r3 = c.post("/v1/message", headers={"X-API-Key": "abc"}, json={"message": "hi"})
    assert r3.status_code == 200


def test_setup_wizard_writes_non_sensitive_configs(tmp_path):
    cfg_dir = tmp_path / "config"
    cfg_dir.mkdir()
    paths = ConfigPaths(config_dir=str(cfg_dir))
    cfg = ConfigLoader(paths)

    # enabled module missing config blocks -> needs setup
    # Include all built-in modules to avoid "missing in registry" prompts consuming inputs.
    cfg.save(
        paths.modules_registry,
        {
            "modules": [
                {"module": "jarvis.modules.music", "enabled": True},
                {"module": "jarvis.modules.anime_dubbing", "enabled": False},
            ]
        },
    )
    cfg.save(paths.modules, {"intents": []})
    cfg.save(paths.permissions, {"intents": {}})
    cfg.save(paths.responses, {"confirmations": {}})

    usb = tmp_path / "usb.bin"
    write_usb_key(str(usb), generate_usb_master_key_bytes())
    store = SecureStore(usb_key_path=str(usb), store_path=str(tmp_path / "store.enc"))

    wiz = SetupWizard(cfg=cfg, paths=paths, secure_store=store, logger=DummyLogger())

    answers = iter(
        [
            # "Module needs setup... Run setup now?" -> yes
            "y",
            # admin-only? -> n
            "n",
            # resource-intensive? -> n
            "n",
            # network? -> n
            "n",
            # keywords csv
            "play,music",
            # template
            "Playing {song} on {service}.",
        ]
    )

    wiz._run(lambda prompt: next(answers))  # noqa: SLF001

    modules = cfg.load(paths.modules)
    assert any(i["id"] == "music.play" for i in modules["intents"])
    perms = cfg.load(paths.permissions)
    assert perms["intents"]["music.play"]["requires_admin"] is False
    resp = cfg.load(paths.responses)
    assert resp["confirmations"]["music.play"].startswith("Playing")


def test_setup_wizard_new_modules_added_disabled_by_default(tmp_path):
    cfg_dir = tmp_path / "config"
    cfg_dir.mkdir()
    paths = ConfigPaths(config_dir=str(cfg_dir))
    cfg = ConfigLoader(paths)
    cfg.save(paths.modules_registry, {"modules": []})
    cfg.save(paths.modules, {"intents": []})
    cfg.save(paths.permissions, {"intents": {}})
    cfg.save(paths.responses, {"confirmations": {}})

    usb = tmp_path / "usb.bin"
    write_usb_key(str(usb), generate_usb_master_key_bytes())
    store = SecureStore(usb_key_path=str(usb), store_path=str(tmp_path / "store.enc"))

    wiz = SetupWizard(cfg=cfg, paths=paths, secure_store=store, logger=DummyLogger())

    # For each detected module, answer "yes" to add; wizard always writes enabled:false.
    wiz._run(lambda prompt: "y")  # noqa: SLF001
    reg = cfg.load(paths.modules_registry)
    assert reg["modules"], "expected modules to be proposed and added"
    assert all(m["enabled"] is False for m in reg["modules"])

