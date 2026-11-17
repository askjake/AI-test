"""Phase 1 tests for orchestrator.bedrock_client (P1-1..P1-6)."""

from __future__ import annotations

import io
import json

import pytest
from botocore.exceptions import ClientError

from orchestrator.bedrock_client import (
    BedrockClient,
    BedrockError,
    BetaRejectedError,
    computer_tool,
    custom_computer_tool,
)


def test_model_id_has_no_account_specific_fallback(monkeypatch):
    monkeypatch.setattr("orchestrator.bedrock_client.settings.bedrock_model_id", None)
    with pytest.raises(ValueError, match="BEDROCK_MODEL_ID"):
        BedrockClient(client=FakeClient())


def _canned_response(content: list[dict], stop_reason="tool_use", usage=None) -> dict:
    body = {
        "content": content,
        "stop_reason": stop_reason,
        "usage": usage or {"input_tokens": 10, "output_tokens": 5},
    }
    return {"body": io.BytesIO(json.dumps(body).encode("utf-8"))}


class FakeClient:
    """Minimal stand-in for a boto3 bedrock-runtime client."""

    def __init__(self, responses=None, errors=None):
        self._responses = list(responses or [])
        self._errors = list(errors or [])
        self.calls = []

    def invoke_model(self, **kwargs):
        self.calls.append(kwargs)
        if self._errors:
            err = self._errors.pop(0)
            if err is not None:
                raise err
        return self._responses.pop(0)


def _client_error(code: str, message: str = "") -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": message}}, "InvokeModel")


def test_client_constructs_without_anthropic(monkeypatch):
    """P1-1: wraps bedrock-runtime; never creates an Anthropic Cloud client."""
    created = {}

    import orchestrator.bedrock_client as mod

    class FakeSession:
        def client(self, service, **kwargs):
            created["service"] = service
            created["region"] = kwargs.get("region_name")
            return FakeClient()

    monkeypatch.setattr(mod.boto3, "Session", FakeSession)
    client = BedrockClient(region="us-west-2", model_id="m")
    assert created["service"] == "bedrock-runtime"
    assert created["region"] == "us-west-2"
    assert client.model_id == "m"


def test_request_body_well_formed(monkeypatch):
    """P1-2: body has required fields + computer tool + beta flag."""
    import orchestrator.bedrock_client as mod
    monkeypatch.setattr(mod.settings, "enable_prompt_caching", False, raising=False)
    client = BedrockClient(client=FakeClient(), model_id="m")
    tools = [computer_tool(1280, 800)]
    body = client.build_body(
        messages=[{"role": "user", "content": "hi"}],
        tools=tools,
        system="sys",
        max_tokens=256,
        betas=["computer-use-2025-11-24"],
    )
    assert body["anthropic_version"]
    assert body["max_tokens"] == 256
    assert body["system"] == "sys"
    assert body["messages"]
    assert body["anthropic_beta"] == ["computer-use-2025-11-24"]
    tool = body["tools"][0]
    assert tool["type"] == "computer_20251124"
    assert tool["display_width_px"] == 1280
    assert tool["display_height_px"] == 800


def test_computer_tool_retains_reviewed_legacy_contract():
    tool = computer_tool(1280, 800, tool_type="computer_20250124")
    assert tool["type"] == "computer_20250124"


def test_computer_tool_rejects_unreviewed_contract():
    with pytest.raises(ValueError, match="unsupported native computer-use tool type"):
        computer_tool(1280, 800, tool_type="computer_unreviewed")


def test_prompt_caching_marks_system_and_tools(monkeypatch):
    """Caching on: system becomes a cached text block and the last tool carries cache_control."""
    import orchestrator.bedrock_client as mod
    monkeypatch.setattr(mod.settings, "enable_prompt_caching", True, raising=False)
    client = BedrockClient(client=FakeClient(), model_id="m")
    body = client.build_body(
        messages=[{"role": "user", "content": "x"}],
        tools=[computer_tool(1280, 800)],
        system="sys",
    )
    assert body["system"] == [
        {"type": "text", "text": "sys", "cache_control": {"type": "ephemeral"}}
    ]
    assert body["tools"][-1]["cache_control"] == {"type": "ephemeral"}
    # The tool schema itself is otherwise preserved.
    assert body["tools"][-1]["type"] == "computer_20251124"


def test_prompt_caching_off_leaves_body_plain(monkeypatch):
    """Caching off: bare system string, no cache_control anywhere."""
    import orchestrator.bedrock_client as mod
    monkeypatch.setattr(mod.settings, "enable_prompt_caching", False, raising=False)
    client = BedrockClient(client=FakeClient(), model_id="m")
    body = client.build_body(
        messages=[{"role": "user", "content": "x"}],
        tools=[computer_tool(1280, 800)],
        system="sys",
    )
    assert body["system"] == "sys"
    assert "cache_control" not in body["tools"][-1]


def test_build_body_preserves_message_cache_control(monkeypatch):
    """Caching on: a message-level breakpoint placed upstream survives build_body."""
    import orchestrator.bedrock_client as mod
    monkeypatch.setattr(mod.settings, "enable_prompt_caching", True, raising=False)
    client = BedrockClient(client=FakeClient(), model_id="m")
    messages = [{"role": "user", "content": [
        {"type": "text", "text": "x", "cache_control": {"type": "ephemeral"}},
    ]}]
    body = client.build_body(messages=messages, tools=[computer_tool(1280, 800)], system="sys")
    assert body["messages"][0]["content"][0]["cache_control"] == {"type": "ephemeral"}


def test_build_body_strips_message_cache_control_when_disabled(monkeypatch):
    """Caching off: any leaked message-level breakpoint is removed."""
    import orchestrator.bedrock_client as mod
    monkeypatch.setattr(mod.settings, "enable_prompt_caching", False, raising=False)
    client = BedrockClient(client=FakeClient(), model_id="m")
    messages = [{"role": "user", "content": [
        {"type": "text", "text": "x", "cache_control": {"type": "ephemeral"}},
    ]}]
    body = client.build_body(messages=messages, tools=[computer_tool(1280, 800)], system="sys")
    assert "cache_control" not in body["messages"][0]["content"][0]


def test_response_parsing():
    """P1-3: text + tool_use blocks normalized."""
    fake = FakeClient(
        responses=[
            _canned_response(
                [
                    {"type": "text", "text": "let me look"},
                    {"type": "tool_use", "id": "t1", "name": "computer",
                     "input": {"action": "screenshot"}},
                ]
            )
        ]
    )
    client = BedrockClient(client=fake, model_id="m")
    result = client.invoke(messages=[{"role": "user", "content": "x"}],
                           tools=[computer_tool(800, 600)])
    assert len(result.content) == 2
    assert result.content[0].type == "text"
    assert result.content[0].text == "let me look"
    tu = result.first_tool_use()
    assert tu is not None
    assert tu.name == "computer"
    assert tu.input == {"action": "screenshot"}
    assert tu.id == "t1"


def test_throttling_retry_then_success():
    """P1-4: retries on throttling, eventually returns."""
    fake = FakeClient(
        errors=[_client_error("ThrottlingException"), None],
        responses=[_canned_response([{"type": "tool_use", "id": "t", "name": "computer",
                                      "input": {"action": "screenshot"}}])],
    )
    client = BedrockClient(client=fake, model_id="m", base_backoff=0.0)
    result = client.invoke(messages=[{"role": "user", "content": "x"}],
                           tools=[computer_tool(800, 600)])
    assert result.first_tool_use() is not None
    assert len(fake.calls) == 2


def test_throttling_exhausts_retries():
    fake = FakeClient(errors=[_client_error("ThrottlingException")] * 10)
    client = BedrockClient(client=fake, model_id="m", base_backoff=0.0, max_retries=2)
    with pytest.raises(BedrockError):
        client.invoke(messages=[{"role": "user", "content": "x"}],
                      tools=[computer_tool(800, 600)])
    assert len(fake.calls) == 3  # initial + 2 retries


def test_expired_token_rebuilds_session_and_retries():
    expired = FakeClient(errors=[_client_error("ExpiredTokenException")])
    fresh = FakeClient(responses=[_screenshot_response()])
    clients = iter((expired, fresh))
    created = []

    def factory():
        client = next(clients)
        created.append(client)
        return client

    client = BedrockClient(
        client_factory=factory,
        model_id="m",
        base_backoff=0.0,
    )
    result = client.invoke(
        messages=[{"role": "user", "content": "x"}],
        tools=[computer_tool(800, 600)],
    )

    assert result.first_tool_use() is not None
    assert created == [expired, fresh]
    assert len(expired.calls) == 1
    assert len(fresh.calls) == 1


def test_beta_rejection_is_explicit():
    """P1-5: beta/tool rejection raises a clear, identifiable error."""
    fake = FakeClient(
        errors=[_client_error("ValidationException",
                              "The model does not support anthropic_beta computer-use-2025-11-24")]
    )
    client = BedrockClient(client=fake, model_id="m")
    with pytest.raises(BetaRejectedError):
        client.invoke(messages=[{"role": "user", "content": "x"}],
                      tools=[computer_tool(800, 600)])


def test_generic_validation_error_is_bedrock_error():
    fake = FakeClient(errors=[_client_error("ValidationException", "max_tokens too large")])
    client = BedrockClient(client=fake, model_id="m")
    with pytest.raises(BedrockError) as exc:
        client.invoke(messages=[{"role": "user", "content": "x"}],
                      tools=[computer_tool(800, 600)])
    assert not isinstance(exc.value, BetaRejectedError)


# --- custom-tool fallback (P1-2b, P1-5b, P1-5c) ----------------------------


def _screenshot_response():
    return _canned_response(
        [{"type": "tool_use", "id": "t", "name": "computer", "input": {"action": "screenshot"}}]
    )


def test_custom_tool_schema():
    """P1-2b: custom tool is a plain 'computer' tool with an input_schema, no beta type."""
    tool = custom_computer_tool(1280, 800)
    assert tool["name"] == "computer"
    assert "type" not in tool  # not a native computer-use type
    props = tool["input_schema"]["properties"]
    assert {"action", "coordinate", "text"} <= set(props)
    assert "screenshot" in props["action"]["enum"]


def test_custom_body_has_no_beta():
    """P1-2b: custom-mode body omits anthropic_beta entirely."""
    client = BedrockClient(client=FakeClient(), model_id="m")
    body = client.build_body(
        messages=[{"role": "user", "content": "x"}],
        tools=[custom_computer_tool(1280, 800)],
    )
    assert "anthropic_beta" not in body


def test_build_body_includes_tool_choice():
    client = BedrockClient(client=FakeClient(), model_id="m")
    body = client.build_body(
        messages=[{"role": "user", "content": "x"}],
        tools=[computer_tool(1280, 800)],
        betas=["computer-use-2025-11-24"],
        tool_choice={"type": "any"},
    )
    assert body["tool_choice"] == {"type": "any"}
    assert body["anthropic_beta"] == ["computer-use-2025-11-24"]


def test_beta_mode_sends_beta(monkeypatch):
    import orchestrator.bedrock_client as mod
    monkeypatch.setattr(mod.settings, "computer_tool_mode", "beta", raising=False)
    fake = FakeClient(responses=[_screenshot_response()])
    client = BedrockClient(client=fake, model_id="m")
    result, mode = client.invoke_computer_use(messages=[{"role": "user", "content": "x"}])
    assert mode == "beta"
    assert result.first_tool_use().input == {"action": "screenshot"}
    sent = json.loads(fake.calls[0]["body"])
    assert sent["anthropic_beta"] == [client.computer_use_beta]
    assert sent["tools"][0]["type"] == "computer_20251124"


def test_custom_mode_sends_custom(monkeypatch):
    import orchestrator.bedrock_client as mod
    monkeypatch.setattr(mod.settings, "computer_tool_mode", "custom", raising=False)
    fake = FakeClient(responses=[_screenshot_response()])
    client = BedrockClient(client=fake, model_id="m")
    result, mode = client.invoke_computer_use(messages=[{"role": "user", "content": "x"}])
    assert mode == "custom"
    sent = json.loads(fake.calls[0]["body"])
    assert "anthropic_beta" not in sent
    assert sent["tools"][0]["name"] == "computer"
    assert "input_schema" in sent["tools"][0]


def test_auto_fallback_beta_to_custom(monkeypatch):
    """P1-5b: auto mode retries as custom on beta rejection and caches the result."""
    import orchestrator.bedrock_client as mod
    monkeypatch.setattr(mod.settings, "computer_tool_mode", "auto", raising=False)
    fake = FakeClient(
        errors=[_client_error("ValidationException",
                              "does not support tool types: computer_20251124"), None, None],
        responses=[_screenshot_response(), _screenshot_response()],
    )
    client = BedrockClient(client=fake, model_id="m")
    result, mode = client.invoke_computer_use(messages=[{"role": "user", "content": "x"}])
    assert mode == "custom"
    assert result.first_tool_use() is not None
    # First call was beta (rejected), second was custom (success).
    assert len(fake.calls) == 2
    assert "anthropic_beta" not in json.loads(fake.calls[1]["body"])
    # Resolved mode is cached: next call goes straight to custom (1 more call).
    result2, mode2 = client.invoke_computer_use(messages=[{"role": "user", "content": "y"}])
    assert mode2 == "custom"
    assert len(fake.calls) == 3
    assert "anthropic_beta" not in json.loads(fake.calls[2]["body"])


def test_custom_mode_does_not_fallback(monkeypatch):
    """P1-5c: errors in custom mode propagate (no further fallback)."""
    import orchestrator.bedrock_client as mod
    monkeypatch.setattr(mod.settings, "computer_tool_mode", "custom", raising=False)
    fake = FakeClient(errors=[_client_error("ValidationException", "max_tokens too large")])
    client = BedrockClient(client=fake, model_id="m")
    with pytest.raises(BedrockError):
        client.invoke_computer_use(messages=[{"role": "user", "content": "x"}])
    assert len(fake.calls) == 1
