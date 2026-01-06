from __future__ import annotations

import pytest

from jarvis.core.llm_contracts import (
    LLMRequest,
    LLMRole,
    LLMResponse,
    LLMStatus,
    Message,
    OutputSchema,
    parse_strict_json,
    validate_schema,
)


def test_parse_and_validate_chat_reply():
    obj = parse_strict_json('{"reply":"hi"}')
    out = validate_schema(OutputSchema.chat_reply, obj)
    assert out["reply"] == "hi"


def test_parse_and_validate_intent_fallback():
    obj = parse_strict_json('{"intent_id":"music.play","confidence":0.5,"args":{},"confirmation_text":"x","requires_admin":false}')
    out = validate_schema(OutputSchema.intent_fallback, obj)
    assert out["intent_id"] == "music.play"


def test_llm_request_model():
    req = LLMRequest(
        trace_id="t",
        role=LLMRole.chat,
        messages=[Message(role="user", content="hello")],
        output_schema=OutputSchema.chat_reply,
        safety={"allowed_intents": ["a"], "denylist_phrases": ["b"]},
        max_tokens=10,
        temperature=0.1,
    )
    assert req.role == LLMRole.chat


def test_parse_strict_json_rejects_non_object():
    with pytest.raises(Exception):
        _ = parse_strict_json('["x"]')

