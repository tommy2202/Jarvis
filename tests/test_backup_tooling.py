from __future__ import annotations

import json
import os
import zipfile

import pytest

from jarvis.core.backup.api import BackupManager
from jarvis.core.backup.verifier import verify_zip


def _mk_tree(root: str) -> None:
    os.makedirs(os.path.join(root, "config"), exist_ok=True)
    os.makedirs(os.path.join(root, "secure"), exist_ok=True)
    os.makedirs(os.path.join(root, "runtime"), exist_ok=True)
    os.makedirs(os.path.join(root, "logs", "audit"), exist_ok=True)
    with open(os.path.join(root, "config", "app.json"), "w", encoding="utf-8") as f:
        json.dump({"config_version": 2}, f)
    with open(os.path.join(root, "secure", "secure_store.enc"), "w", encoding="utf-8") as f:
        f.write('{"nonce":"x","ciphertext":"y"}\n')
    with open(os.path.join(root, "secure", "store.meta.json"), "w", encoding="utf-8") as f:
        json.dump({"store_id": "s", "key_id": "k", "store_version": 1}, f)
    with open(os.path.join(root, "runtime", "state.json"), "w", encoding="utf-8") as f:
        json.dump({"state_version": 1}, f)
    with open(os.path.join(root, "logs", "audit", "head.json"), "w", encoding="utf-8") as f:
        json.dump({"head_hash": "0" * 64}, f)


def test_create_minimal_backup_and_verify(tmp_path):
    root = str(tmp_path)
    _mk_tree(root)
    cfg = {
        "enabled": True,
        "default_dir": "backups",
        "profiles": {"minimal": {"include_logs": False}},
        "support_bundle": {"default_days": 7, "redact": True, "max_total_mb": 200},
    }
    mgr = BackupManager(cfg=cfg, root_dir=root)
    out = mgr.create_backup(profile="minimal", out_dir=os.path.join(root, "backups"))
    assert os.path.exists(out)
    vr = verify_zip(out)
    assert vr.ok is True


def test_tamper_detection_fails_verify(tmp_path):
    root = str(tmp_path)
    _mk_tree(root)
    cfg = {"enabled": True, "default_dir": "backups", "profiles": {"minimal": {"include_logs": False}}, "support_bundle": {"default_days": 7, "redact": True, "max_total_mb": 200}}
    mgr = BackupManager(cfg=cfg, root_dir=root)
    out = mgr.create_backup(profile="minimal", out_dir=os.path.join(root, "backups"))

    # Tamper a file inside zip by rewriting one member
    tampered = os.path.join(root, "backups", "tampered.zip")
    with zipfile.ZipFile(out, "r") as zin, zipfile.ZipFile(tampered, "w", compression=zipfile.ZIP_DEFLATED) as zout:
        for name in zin.namelist():
            data = zin.read(name)
            if name == "config/app.json":
                data = b'{"config_version": 999}\n'
            zout.writestr(name, data)
    vr = verify_zip(tampered)
    assert vr.ok is False


def test_restore_dry_run_does_not_overwrite(tmp_path):
    root = str(tmp_path)
    _mk_tree(root)
    cfg = {"enabled": True, "default_dir": "backups", "profiles": {"minimal": {"include_logs": False}}, "support_bundle": {"default_days": 7, "redact": True, "max_total_mb": 200}}
    mgr = BackupManager(cfg=cfg, root_dir=root)
    out = mgr.create_backup(profile="minimal", out_dir=os.path.join(root, "backups"))

    # change config/app.json
    with open(os.path.join(root, "config", "app.json"), "w", encoding="utf-8") as f:
        json.dump({"config_version": 123}, f)
    res = mgr.restore(out, mode="config", dry_run=True, apply=False)
    assert res["dry_run"] is True
    with open(os.path.join(root, "config", "app.json"), "r", encoding="utf-8") as f:
        assert json.load(f)["config_version"] == 123


def test_support_bundle_redacts(tmp_path):
    root = str(tmp_path)
    _mk_tree(root)
    os.makedirs(os.path.join(root, "logs"), exist_ok=True)
    with open(os.path.join(root, "logs", "jarvis.log"), "w", encoding="utf-8") as f:
        f.write("Authorization: Bearer SECRETSECRET\npassword=supersecret\n")
    cfg = {"enabled": True, "default_dir": "backups", "profiles": {"minimal": {"include_logs": False}}, "support_bundle": {"default_days": 7, "redact": True, "max_total_mb": 200}}
    mgr = BackupManager(cfg=cfg, root_dir=root)
    zip_path = mgr.export_support_bundle(days=7, out_dir=os.path.join(root, "backups"))
    with zipfile.ZipFile(zip_path, "r") as z:
        data = z.read("logs/jarvis.log").decode("utf-8", errors="ignore")
    assert "SECRETSECRET" not in data
    assert "supersecret" not in data


def test_support_bundle_max_total_mb_enforced(tmp_path):
    root = str(tmp_path)
    _mk_tree(root)
    os.makedirs(os.path.join(root, "logs"), exist_ok=True)
    # Create many medium files so even after redaction/truncation we exceed max_total_mb.
    line = "x" * 5000  # not truncated (threshold > 5000)
    for i in range(300):
        with open(os.path.join(root, "logs", f"big_{i}.log"), "w", encoding="utf-8") as f:
            f.write(line + "\n")
    cfg = {"enabled": True, "default_dir": "backups", "profiles": {"minimal": {"include_logs": False}}, "support_bundle": {"default_days": 7, "redact": True, "max_total_mb": 1}}
    mgr = BackupManager(cfg=cfg, root_dir=root)
    with pytest.raises(ValueError):
        _ = mgr.export_support_bundle(days=7, out_dir=os.path.join(root, "backups"))

