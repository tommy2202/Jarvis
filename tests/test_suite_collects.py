from __future__ import annotations

import importlib

import pytest


CRITICAL_MODULES = [
    "jarvis.core.dispatcher",
    "jarvis.core.capabilities.engine",
    "jarvis.core.policy.engine",
    "jarvis.core.broker.server",
]


def test_suite_collects_imports():
    failures = []
    for module in CRITICAL_MODULES:
        try:
            importlib.import_module(module)
        except Exception as exc:
            failures.append(f"{module}: {exc.__class__.__name__}: {exc}")
    if failures:
        pytest.fail("Critical module import failures:\n" + "\n".join(failures))
