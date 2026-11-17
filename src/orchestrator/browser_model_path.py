"""Model-client integration for the page classifier (CP43, b4r12-dev): the request the CP42-C diagnostic EVALUATED, built from the runner's
production model client (the same ``client.invoke`` + one forced non-acting tool pattern as chain_hooks._ask_model_from_client).

Bound to the executed evidence: the prompt, schema description, tool and transmitted text hashes below are the ones recorded in the CP42-C frozen
inputs (63fabddc...749d).  Tests compare them; a change here is a CHANGE OF THE REQUEST CONTRACT and the model pass must not be reused for it.
"""
from __future__ import annotations

import base64
import hashlib
import json
import re
from typing import Any, Callable

from orchestrator import browser_page_classifier as pc

PAGE_TOOL_NAME = "report_page_observation"
PAGE_PROMPT_SUFFIX = " Answer by calling " + PAGE_TOOL_NAME + "."
PAGE_MAX_TOKENS = 1400
EVALUATED = {
    "evidence": "CP42-C executed 12/12 diagnostic, frozen input sha256 63fabddcb10cf81bd0d30fa010a6220367ab1e7698bd7409c4132f236da9749d",
    "prompt_sha256": "c542049d2c610def524f08491e14116784d17b8bf5faac54c0a5f9037f5112de",
    "schema_description_sha256": "0dd8c89e21d651d6d2a76a3596abc9d4824a50d990bc0a2c54d658df09844af3",
    "tool_sha256": "d25c4e01008c5ca305289a92a6954ceb6430db6ba638e89cc8bb46b43b0f46bb",
    "transmitted_text_sha256": "85b0b163163a8cfd350f872f1d49bf01ff44502c33ff0b116169a707fe178e70",
    "profile_id": "l8qvcd4stnca", "region": "us-west-2", "max_tokens": PAGE_MAX_TOKENS, "temperature": "not set",
    # sha256 of the FULL evaluated model identifier (the account segment stays out of source); recorded in the CP42-C frozen inputs
    "model_id_sha256": "86b0091ec5603c67a5e9df204ab765a1b24f6d9627da7f9a456a9cc921f1efcd",
    "request_contract_sha256": "f075ea57a509d1206ae59499702fc950d740169f5c75c1a2f38ff4aff8ee790b",
}
COVERAGE = "SYNTHETIC_DIAGNOSTIC_ONLY"      # what a matching binding means: the CP42-C pass was 12 drawn frames, one sample each


def page_tool() -> dict:
    """Forced non-acting tool; its input_schema is derived from the parser's own vocabulary (identical to the evaluated tool)."""
    region = {"type": "object", "properties": {"id": {"type": "string"}, "label": {"type": "string"}, "x": {"type": "integer"}, "y": {"type": "integer"},
                                               "w": {"type": "integer"}, "h": {"type": "integer"}, "visual": {"type": "string", "enum": list(pc.REGION_VISUALS)}},
              "required": sorted(pc.REGION_KEYS)}
    props = {"schema": {"type": "string", "enum": [pc.SCHEMA_VERSION]}, "coordinate_system": {"type": "string", "enum": [pc.COORDINATE_SYSTEM]},
             "frame_width": {"type": "integer"}, "frame_height": {"type": "integer"}, "state": {"type": "string", "enum": list(pc.PAGE_STATES)},
             "confidence": {"type": "number", "minimum": 0, "maximum": 1}, "address_text": {"type": "string"}, "address_readable": {"type": "boolean"},
             "security_indicator": {"type": "string", "enum": list(pc.SECURITY_INDICATORS)}, "obstructed": {"type": "boolean"},
             "prompt_kind": {"type": "string", "enum": list(pc.PROMPT_KINDS)}, "regions": {"type": "array", "maxItems": pc.MAX_REGIONS, "items": region}}
    assert set(props) == set(pc.RESPONSE_KEYS)
    return {"name": PAGE_TOOL_NAME, "description": "Report the structured description of the screenshot.",
            "input_schema": {"type": "object", "properties": props, "required": sorted(pc.RESPONSE_KEYS)}}


def ask_model_from_client(client: Any) -> Callable[[bytes, str], str] | None:
    """(png, prompt) -> JSON text, via ``client.invoke`` with the forced tool.  The tool input is returned as JSON text for the strict parser; no other
    channel exists.  ``ask.tokens`` accumulates measured token usage for the run record."""
    invoke = getattr(client, "invoke", None)
    if invoke is None:
        return None
    tool = page_tool()
    tokens = {"input_tokens": 0, "output_tokens": 0}

    def ask(png: bytes, prompt: str) -> str:
        messages = [{"role": "user", "content": [
            {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": base64.b64encode(png).decode("ascii")}},
            {"type": "text", "text": prompt + PAGE_PROMPT_SUFFIX}]}]
        result = invoke(messages=messages, tools=[tool], max_tokens=PAGE_MAX_TOKENS, tool_choice={"type": "tool", "name": PAGE_TOOL_NAME})
        usage = getattr(result, "usage", None)
        if isinstance(usage, dict):
            for key in tokens:
                value = usage.get(key)
                if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
                    tokens[key] += value
        use = result.first_tool_use() if hasattr(result, "first_tool_use") else None
        if use is not None and isinstance(getattr(use, "input", None), dict):
            return json.dumps(use.input)
        for block in getattr(result, "content", []) or []:
            text = getattr(block, "text", None)
            if text:
                return text
        return ""
    ask.tokens = tokens                                   # type: ignore[attr-defined]
    return ask


def request_contract_sha256(client: Any) -> str:
    """Digest of the request the integrated path would send (image bytes replaced by a placeholder): version, token cap, tool + cache marking, tool
    choice, prompt text and every other body key.  Built through the client's OWN build_body, so runtime configuration (prompt caching, API version) counts."""
    body = client.build_body(messages=[{"role": "user", "content": [{"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "<png>"}},
                                                                   {"type": "text", "text": pc.build_prompt() + PAGE_PROMPT_SUFFIX}]}],
                             tools=[page_tool()], max_tokens=PAGE_MAX_TOKENS, tool_choice={"type": "tool", "name": PAGE_TOOL_NAME})
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def verify_evaluated_binding(client: Any) -> tuple[bool, str]:
    """(True, "") only when the configured model/profile, region and request contract equal the CP42-C evaluated binding.  Pure attribute reads and a
    local body build: NO network, NO model call.  Run BEFORE any session is launched."""
    try:
        model_id, region = getattr(client, "model_id", None), getattr(client, "region", None)
        if not isinstance(model_id, str) or hashlib.sha256(model_id.encode("utf-8")).hexdigest() != EVALUATED["model_id_sha256"]:
            return False, "MODEL_ID_MISMATCH"
        m = re.fullmatch(r"arn:aws:bedrock:([a-z0-9-]+):[0-9]{12}:application-inference-profile/([A-Za-z0-9]+)", model_id)
        if not m or m.group(2) != EVALUATED["profile_id"]:
            return False, "MODEL_PROFILE_MISMATCH"
        if region != EVALUATED["region"] or m.group(1) != EVALUATED["region"]:
            return False, "REGION_MISMATCH"
        if request_contract_sha256(client) != EVALUATED["request_contract_sha256"]:
            return False, "REQUEST_CONTRACT_MISMATCH"
    except Exception:
        return False, "BINDING_UNVERIFIABLE"
    return True, ""


def evaluation_binding(client: Any) -> dict:
    """What the report says about the relation between this run's model request and the evaluated one.  Informational (never authorises anything)."""
    model_id = str(getattr(client, "model_id", "") or "")
    region = str(getattr(client, "region", "") or "")
    m = re.fullmatch(r"arn:aws:[a-z-]+:([a-z0-9-]+):[0-9]{12}:application-inference-profile/([A-Za-z0-9]+)", model_id)
    return {"coverage": COVERAGE, "evaluated": dict(EVALUATED), "prompt_sha256_now": pc.prompt_sha256(), "schema_description_sha256_now": pc.schema_sha256(),
            "request_contract_unchanged": pc.prompt_sha256() == EVALUATED["prompt_sha256"] and pc.schema_sha256() == EVALUATED["schema_description_sha256"],
            "runtime_model_matches_evaluated_profile": bool(m and m.group(2) == EVALUATED["profile_id"] and m.group(1) == EVALUATED["region"] and region == EVALUATED["region"]),
            "note": "The model pass applies only to the evaluated profile, region, prompt, schema, tool and settings; a mismatch means the pass does not cover this run."}
