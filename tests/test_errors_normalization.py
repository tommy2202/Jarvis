from __future__ import annotations

import json

from jarvis.core.error_reporter import ErrorReporter


def test_unknown_exception_normalized_and_redacted(tmp_path):
    p = tmp_path / "errors.jsonl"
    r = ErrorReporter(path=str(p))
    try:
        raise RuntimeError("boom")
    except Exception as e:  # noqa: BLE001
        je = r.report_exception(e, trace_id="t1", subsystem="router", context={"api_key": "SECRET", "x": 1})
        assert je.user_message
    lines = p.read_text(encoding="utf-8").splitlines()
    obj = json.loads(lines[-1])
    assert obj["trace_id"] == "t1"
    assert obj["subsystem"] == "router"
    assert "SECRET" not in json.dumps(obj)
    assert "***REDACTED***" in json.dumps(obj)

