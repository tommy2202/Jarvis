from __future__ import annotations

import os

import pytest

from jarvis.core.config.manager import ConfigManager
from jarvis.core.config.paths import ConfigFsPaths
from jarvis.core.crypto import generate_usb_master_key_bytes, write_usb_key


@pytest.fixture
def tmp_config_root(tmp_path):
    """
    Provides an isolated repo root with config/ and secure/ under tmp_path.
    """
    fs = ConfigFsPaths(root=str(tmp_path))
    os.makedirs(fs.config_dir, exist_ok=True)
    os.makedirs(fs.secure_dir, exist_ok=True)
    return fs


@pytest.fixture
def config_manager(tmp_config_root):
    cm = ConfigManager(fs=tmp_config_root, logger=None, read_only=False)
    cm.load_all()
    return cm


@pytest.fixture
def fake_usb_key_path(tmp_config_root):
    path = os.path.join(tmp_config_root.root, "usb.bin")
    write_usb_key(path, generate_usb_master_key_bytes())
    return path

