from __future__ import annotations

import json
import os

from jarvis.core.config.io import read_json_file
from jarvis.core.config.paths import ConfigFsPaths
from jarvis.core.events import EventLogger
from jarvis.core.migrations import VersionRegistry, run_module_registry_migrations
from .helpers.config_builders import build_modules_config_v1


def _read_events(path: str) -> list[dict]:
    if not os.path.exists(path):
        return []
    return [json.loads(line) for line in open(path, encoding="utf-8").read().splitlines() if line.strip()]


def test_migration_runs_once(tmp_path):
    fs = ConfigFsPaths(str(tmp_path))
    os.makedirs(fs.config_dir, exist_ok=True)
    events_path = os.path.join(str(tmp_path), "events.jsonl")
    registry = VersionRegistry(path=os.path.join(fs.config_dir, "schema_registry.json"), backups_dir=fs.backups_dir)
    event_logger = EventLogger(events_path)

    files = {
        "modules.json": build_modules_config_v1(
            schema_version=0,
            modules=[{"module_id": "demo", "enabled": True}],
            intents=[],
        ),
        "modules_registry.json": {"modules": "invalid"},
    }

    run_module_registry_migrations(
        fs=fs,
        files=files,
        backups_dir=fs.backups_dir,
        max_backups=3,
        write_back=True,
        registry=registry,
        event_logger=event_logger,
        trace_id="t1",
    )

    first_events = _read_events(events_path)
    assert any(e.get("event") == "migration.applied" for e in first_events)

    modules_path = os.path.join(fs.config_dir, "modules.json")
    rr = read_json_file(modules_path)
    assert rr.ok
    assert isinstance(rr.data.get("modules"), dict)
    assert int(rr.data.get("schema_version") or 0) == 1

    updated_files = {
        "modules.json": rr.data,
        "modules_registry.json": read_json_file(os.path.join(fs.config_dir, "modules_registry.json")).data,
    }

    run_module_registry_migrations(
        fs=fs,
        files=updated_files,
        backups_dir=fs.backups_dir,
        max_backups=3,
        write_back=True,
        registry=registry,
        event_logger=event_logger,
        trace_id="t2",
    )

    second_events = _read_events(events_path)
    assert len(second_events) == len(first_events)


def test_migration_logged(tmp_path):
    fs = ConfigFsPaths(str(tmp_path))
    os.makedirs(fs.config_dir, exist_ok=True)
    events_path = os.path.join(str(tmp_path), "events.jsonl")
    registry = VersionRegistry(path=os.path.join(fs.config_dir, "schema_registry.json"), backups_dir=fs.backups_dir)
    event_logger = EventLogger(events_path)

    files = {
        "modules.json": build_modules_config_v1(schema_version=0, modules=[], intents=[]),
        "modules_registry.json": {},
    }
    run_module_registry_migrations(
        fs=fs,
        files=files,
        backups_dir=fs.backups_dir,
        max_backups=3,
        write_back=True,
        registry=registry,
        event_logger=event_logger,
        trace_id="t-log",
    )

    events = _read_events(events_path)
    assert any(e.get("event") == "migration.applied" for e in events)
