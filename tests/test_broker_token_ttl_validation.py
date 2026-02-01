from __future__ import annotations

import pytest

from jarvis.core.broker.registry import ToolRegistry
from jarvis.core.broker.server import BrokerServer


def test_token_ttl_zero_rejected():
    server = BrokerServer(tool_broker=ToolRegistry(), token_ttl_seconds=0)
    with pytest.raises(ValueError):
        server.start()


def test_token_ttl_negative_rejected():
    server = BrokerServer(tool_broker=ToolRegistry(), token_ttl_seconds=-1)
    with pytest.raises(ValueError):
        server.start()
