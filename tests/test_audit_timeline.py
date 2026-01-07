from __future__ import annotations

import json
import os
import time

from jarvis.core.audit.formatter import format_line
from jarvis.core.audit.models import Actor, ActorSource, ActorUser, AuditCategory, AuditEvent, AuditOutcome, AuditSeverity
from jarvis.core.audit.redaction import redact_details
from jarvis.core.audit.timeline import AuditTimelineManager


def _mk_mgr(tmp_path):
    cfg = {
        "enabled": True,
        "store": {"path_jsonl": str(tmp_path / "audit.jsonl"), "use_sqlite_index": True, "sqlite_path": str(tmp_path / "index.sqlite")},
        "integrity": {"enabled": True, "verify_on_startup": False, "verify_last_n": 2000},
        "retention": {"days": 1, "max_events": 50000},
        "export": {"max_rows": 20000},
    }
    m = AuditTimelineManager(cfg=cfg, logger=None, event_bus=None, telemetry=None, ops_logger=None)
    return m


def test_hash_chain_and_integrity_ok(tmp_path):
    m = _mk_mgr(tmp_path)
    e1 = AuditEvent(category=AuditCategory.lifecycle, action="startup", outcome=AuditOutcome.success, summary="Startup", details={}, severity=AuditSeverity.INFO, actor=Actor(source=ActorSource.system, user=ActorUser.unknown))
    e2 = AuditEvent(category=AuditCategory.security, action="admin.unlock", outcome=AuditOutcome.denied, summary="Admin unlock", details={}, severity=AuditSeverity.WARN, actor=Actor(source=ActorSource.cli, user=ActorUser.user))
    m._append_event(e1)
    m._append_event(e2)
    rep = m.verify_integrity(limit_last_n=1000)
    assert rep.ok is True
    assert rep.checked >= 1


def test_tamper_breaks_integrity(tmp_path):
    m = _mk_mgr(tmp_path)
    e1 = AuditEvent(category=AuditCategory.lifecycle, action="startup", outcome=AuditOutcome.success, summary="Startup", details={}, severity=AuditSeverity.INFO, actor=Actor(source=ActorSource.system, user=ActorUser.unknown))
    e2 = AuditEvent(category=AuditCategory.lifecycle, action="shutdown", outcome=AuditOutcome.success, summary="Shutdown", details={}, severity=AuditSeverity.INFO, actor=Actor(source=ActorSource.system, user=ActorUser.unknown))
    m._append_event(e1)
    m._append_event(e2)

    # Tamper the second line summary (without fixing hash)
    path = str(tmp_path / "audit.jsonl")
    with open(path, "r", encoding="utf-8") as f:
        lines = f.readlines()
    obj = json.loads(lines[1])
    obj["summary"] = "TAMPERED"
    lines[1] = json.dumps(obj, ensure_ascii=False) + "\n"
    with open(path, "w", encoding="utf-8") as f:
        f.writelines(lines)

    rep = m.verify_integrity(limit_last_n=1000)
    assert rep.ok is False


def test_redaction_removes_secrets_and_user_text():
    d = {
        "message": "my password=supersecret",
        "Authorization": "Bearer SECRETSECRET",
        "token": "tok",
        "args": {"q": "user raw text should not appear"},
    }
    out = redact_details("execution", "intent.execute", d)
    s = str(out)
    assert "supersecret" not in s
    assert "SECRETSECRET" not in s
    assert "'token': 'tok'" not in s
    # args values not kept
    assert "user raw text" not in s


def test_retention_purge_compacts(tmp_path):
    m = _mk_mgr(tmp_path)
    # create old + new events
    old_ts = time.time() - (10 * 86400)
    new_ts = time.time()
    old = AuditEvent(timestamp=old_ts, category=AuditCategory.lifecycle, action="old", outcome=AuditOutcome.success, summary="old", details={}, severity=AuditSeverity.INFO, actor=Actor(source=ActorSource.system, user=ActorUser.unknown))
    new = AuditEvent(timestamp=new_ts, category=AuditCategory.lifecycle, action="new", outcome=AuditOutcome.success, summary="new", details={}, severity=AuditSeverity.INFO, actor=Actor(source=ActorSource.system, user=ActorUser.unknown))
    m._append_event(old)
    m._append_event(new)
    # set retention to 1 day and purge
    m.cfg["retention"] = {"days": 1, "max_events": 50000}
    res = m.purge_and_compact()
    assert res["written"] == 1
    rows = m.list_events(limit=10)
    assert len(rows) == 1
    assert rows[0].action == "new"


def test_sqlite_query_filters(tmp_path):
    m = _mk_mgr(tmp_path)
    m._append_event(AuditEvent(category=AuditCategory.job, action="job.started", outcome=AuditOutcome.success, summary="Job started", details={}, severity=AuditSeverity.INFO, actor=Actor(source=ActorSource.system, user=ActorUser.unknown)))
    m._append_event(AuditEvent(category=AuditCategory.security, action="web.auth_failed", outcome=AuditOutcome.denied, summary="Auth failed", details={}, severity=AuditSeverity.WARN, actor=Actor(source=ActorSource.web, user=ActorUser.unknown)))
    out = m.list_events(category="security", limit=10)
    assert len(out) == 1
    assert out[0].category.value == "security"


def test_formatter_stable(tmp_path):
    ev = AuditEvent(timestamp=0.0, category=AuditCategory.lifecycle, action="startup", outcome=AuditOutcome.success, summary="Startup", details={}, severity=AuditSeverity.INFO, actor=Actor(source=ActorSource.system, user=ActorUser.unknown))
    line = format_line(ev)
    assert "Startup" in line
    assert "success" in line

