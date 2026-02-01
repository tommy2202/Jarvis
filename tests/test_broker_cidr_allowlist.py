from __future__ import annotations

import pytest

from jarvis.core.broker.registry import ToolRegistry
from jarvis.core.broker.server import BrokerServer


def test_loopback_allowed_when_allowlist_loopback():
    server = BrokerServer(tool_broker=ToolRegistry(), allowed_client_cidrs=["127.0.0.1/32", "::1/128"])
    allowed, reason = server._check_client_allowed("127.0.0.1")
    assert allowed is True
    assert reason == "ALLOWED"


def test_private_lan_denied_by_default():
    server = BrokerServer(tool_broker=ToolRegistry())
    allowed_a, reason_a = server._check_client_allowed("192.168.1.10")
    assert allowed_a is False
    assert reason_a == "CLIENT_NOT_ALLOWED"

    allowed_b, reason_b = server._check_client_allowed("10.0.0.5")
    assert allowed_b is False
    assert reason_b == "CLIENT_NOT_ALLOWED"


def test_docker_nat_allowed_only_when_allowlisted():
    server_default = BrokerServer(tool_broker=ToolRegistry())
    allowed_default, reason_default = server_default._check_client_allowed("172.18.0.2")
    assert allowed_default is False
    assert reason_default == "CLIENT_NOT_ALLOWED"

    server_allow = BrokerServer(tool_broker=ToolRegistry(), allowed_client_cidrs=["127.0.0.1/32", "::1/128", "172.16.0.0/12"])
    allowed_allow, reason_allow = server_allow._check_client_allowed("172.18.0.2")
    assert allowed_allow is True
    assert reason_allow == "ALLOWED"


def test_invalid_cidr_fails_broker_start():
    server = BrokerServer(tool_broker=ToolRegistry(), allowed_client_cidrs=["127.0.0.1/32", "bad-cidr"])
    with pytest.raises(ValueError, match="Invalid CIDR"):
        server.start()
