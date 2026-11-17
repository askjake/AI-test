"""Bedrock-runtime wrapper for Claude Computer Use (Phase 1).

Claude is reached **exclusively** through ``boto3.client("bedrock-runtime")`` —
there is no Anthropic Cloud SDK and no ``api.anthropic.com`` call anywhere. This module
builds the computer-use ``invoke_model`` body (with the configured reviewed native tool and
matching beta), parses the response into normalized content blocks, and
retries on throttling.

AWS credentials come from the standard credential chain. In the hardened runner, the shared
credentials file is a private, continuously refreshed tmpfs copy; an expired-token response
rebuilds a brand-new boto3 Session and retries against the newest on-disk token.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Any, Callable

import boto3
from botocore.config import Config as BotoConfig
from botocore.exceptions import ClientError

from .config import settings


class BedrockError(Exception):
    """Base error for Bedrock invocation problems."""


def _safe_error_summary(exc: BaseException) -> str:
    """Error CODE, HTTP status and request id only - never the service's message text (it can echo request content) and never credential values."""
    response = getattr(exc, "response", None)
    if isinstance(response, dict):
        code = str(response.get("Error", {}).get("Code", "") or exc.__class__.__name__)[:80]
        meta = response.get("ResponseMetadata", {}) if isinstance(response.get("ResponseMetadata"), dict) else {}
        parts = [f"code={code}"]
        if meta.get("HTTPStatusCode"):
            parts.append(f"http={meta['HTTPStatusCode']}")
        if meta.get("RequestId"):
            parts.append(f"request_id={str(meta['RequestId'])[:64]}")
        return ", ".join(parts)
    return f"type={exc.__class__.__name__}"


class BedrockCredentialError(BedrockError):
    """Credentials are expired and the configured source has not been renewed (safe text; no credential values)."""

    def __init__(self, message: str, category: str = "expired_token") -> None:
        super().__init__(message)
        self.category = category


class BetaRejectedError(BedrockError):
    """Raised when Bedrock rejects the computer-use beta or tool.

    This is the highest-risk Phase 1 failure: it means computer use is not enabled on the
    inference profile. It is surfaced as a distinct, identifiable error (never a generic
    exception) so provisioning can be resolved before any further build work.
    """


@dataclass
class ContentBlock:
    """A normalized piece of model output.

    ``type`` is ``"text"`` or ``"tool_use"``. For text blocks, ``text`` is set. For
    tool_use blocks, ``name``/``input``/``id`` are set.
    """

    type: str
    text: str | None = None
    name: str | None = None
    input: dict[str, Any] | None = None
    id: str | None = None


@dataclass
class InvokeResult:
    """Normalized result of a single ``invoke``."""

    content: list[ContentBlock]
    stop_reason: str | None
    usage: dict[str, Any]
    raw: dict[str, Any]

    def tool_uses(self) -> list[ContentBlock]:
        return [b for b in self.content if b.type == "tool_use"]

    def first_tool_use(self) -> ContentBlock | None:
        uses = self.tool_uses()
        return uses[0] if uses else None


# Substrings that identify a beta/tool-rejection validation error from Bedrock.
_BETA_REJECTION_MARKERS = (
    "anthropic_beta",
    "computer-use",
    "computer_20250124",
    "computer_20251124",
    "beta",
    "is not supported",
    "not enabled",
)


def _strip_message_cache_control(messages: list[dict[str, Any]]) -> None:
    """Remove any block-level ``cache_control`` from ``messages`` in place."""
    for message in messages:
        content = message.get("content")
        if not isinstance(content, list):
            continue
        for block in content:
            if isinstance(block, dict):
                block.pop("cache_control", None)


_COMPUTER_TOOL_TYPES = {"computer_20250124", "computer_20251124"}


def computer_tool(
    screen_w: int,
    screen_h: int,
    display_number: int = 1,
    *,
    tool_type: str = "computer_20251124",
) -> dict[str, Any]:
    """Build one reviewed native computer tool definition (beta mode)."""
    if tool_type not in _COMPUTER_TOOL_TYPES:
        raise ValueError("unsupported native computer-use tool type")
    return {
        "type": tool_type,
        "name": "computer",
        "display_width_px": screen_w,
        "display_height_px": screen_h,
        "display_number": display_number,
    }


def custom_computer_tool(screen_w: int, screen_h: int) -> dict[str, Any]:
    """Build a plain custom ``computer`` tool with an equivalent input schema.

    Used when the model rejects the configured native computer type. The executor in
    ``computer.py`` dispatches on the same ``{action, coordinate, text}`` shape, so only
    this declaration differs from the beta tool. No ``anthropic_beta`` header is needed.
    """
    return {
        "name": "computer",
        "description": (
            f"Control a {screen_w}x{screen_h} computer screen by vision. Take a screenshot "
            "to see the current state, then perform mouse and keyboard actions. Coordinates "
            "are [x, y] pixels from the top-left of the screen."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": [
                        "screenshot",
                        "left_click",
                        "right_click",
                        "double_click",
                        "mouse_move",
                        "type",
                        "key",
                        "scroll",
                        "cursor_position",
                    ],
                    "description": "The action to perform.",
                },
                "coordinate": {
                    "type": "array",
                    "items": {"type": "integer"},
                    "description": "[x, y] target for click/move/scroll actions.",
                },
                "text": {
                    "type": "string",
                    "description": "Text to type, or key combo (e.g. 'Return', 'ctrl+c').",
                },
                "scroll_direction": {
                    "type": "string",
                    "enum": ["up", "down", "left", "right"],
                },
                "scroll_amount": {"type": "integer"},
            },
            "required": ["action"],
        },
    }


class BedrockClient:
    """Thin wrapper around ``bedrock-runtime`` for Claude computer use."""

    def __init__(
        self,
        *,
        region: str | None = None,
        model_id: str | None = None,
        anthropic_version: str | None = None,
        computer_use_beta: str | None = None,
        computer_use_tool_type: str | None = None,
        max_retries: int = 4,
        base_backoff: float = 0.5,
        client: Any | None = None,
        client_factory: Callable[[], Any] | None = None,
    ) -> None:
        self.region = region or settings.aws_region
        self.model_id = model_id or settings.bedrock_model_id
        if not self.model_id:
            raise ValueError(
                "BEDROCK_MODEL_ID must explicitly name an approved model or inference profile."
            )
        self.anthropic_version = anthropic_version or settings.anthropic_version
        self.computer_use_beta = computer_use_beta or settings.computer_use_beta
        self.computer_use_tool_type = (
            computer_use_tool_type or settings.computer_use_tool_type
        )
        self.computer_tool_mode = settings.computer_tool_mode
        self.max_retries = max_retries
        self.base_backoff = base_backoff
        # Cached resolved mode after the first auto-fallback decision ("beta" | "custom").
        self._resolved_mode: str | None = None
        if client is not None and client_factory is not None:
            raise ValueError("pass either client or client_factory, not both")

        self._coordinator = (self._shared_coordinator() if client is None and client_factory is None
                             else getattr(client_factory, "coordinator", None))      # a factory may carry the refresh coordinator (native Windows)

        def default_factory() -> Any:
            # The refresh-aware coordinator (aws_refresh) re-validates the staged credential file on every signing call, so a
            # rotation reaches the NEXT model call of a running job without rebuilding anything.  Without it (no staged file),
            # a brand-new Session is still built: the module-level boto3 default session would cache an expired STS token.
            if self._coordinator is not None:
                return self._coordinator.client("bedrock-runtime", config=BotoConfig(retries={"max_attempts": 0}))
            return boto3.Session().client(
                "bedrock-runtime",
                region_name=self.region,
                config=BotoConfig(retries={"max_attempts": 0}),
            )

        # Injected fixed clients retain the old deterministic test behavior. Production and
        # explicit factories can be rebuilt once after an ExpiredToken response.
        self._client_factory = client_factory or (None if client is not None else default_factory)
        self._client = client or self._client_factory()

    @staticmethod
    def _shared_coordinator():
        """Coordinator for the runtime-staged credential file, or None when this process has no staged file."""
        import os as _os
        path = _os.environ.get("AWS_SHARED_CREDENTIALS_FILE")
        if not path or not _os.path.isfile(path):
            return None
        try:
            from aws_refresh import get_coordinator
        except ImportError:
            return None
        return get_coordinator(path, _os.environ.get("AWS_PROFILE") or "default", region=settings.aws_region,
                               config_file=_os.environ.get("AWS_CONFIG_FILE") or None)

    def build_body(
        self,
        *,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        system: str | None = None,
        max_tokens: int | None = None,
        betas: list[str] | None = None,
        tool_choice: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Assemble the ``invoke_model`` request body.

        ``betas`` is included as ``anthropic_beta`` only when it is a non-empty list, so
        custom-tool (non-beta) requests omit the header entirely.
        """
        caching = settings.enable_prompt_caching
        if caching and tools:
            # Mark the last tool so the whole tool block (identical for the run) is cached.
            tools = [*tools[:-1], {**tools[-1], "cache_control": {"type": "ephemeral"}}]
        # Message-level breakpoints are placed upstream by the agent loop. When caching is
        # off, strip any that leaked through so the body is plain.
        if not caching:
            _strip_message_cache_control(messages)
        body: dict[str, Any] = {
            "anthropic_version": self.anthropic_version,
            "max_tokens": max_tokens or settings.max_tokens,
            "messages": messages,
            "tools": tools,
        }
        if betas:
            body["anthropic_beta"] = betas
        if system is not None:
            if caching:
                body["system"] = [
                    {"type": "text", "text": system, "cache_control": {"type": "ephemeral"}}
                ]
            else:
                body["system"] = system
        if tool_choice is not None:
            body["tool_choice"] = tool_choice
        return body

    def invoke(
        self,
        *,
        messages: list[dict[str, Any]],
        tools: list[dict[str, Any]],
        system: str | None = None,
        max_tokens: int | None = None,
        betas: list[str] | None = None,
        tool_choice: dict[str, Any] | None = None,
    ) -> InvokeResult:
        """Call ``invoke_model`` and return a normalized result.

        Retries with exponential backoff on throttling. Raises :class:`BetaRejectedError`
        if Bedrock rejects the computer-use beta/tool, and :class:`BedrockError` for other
        client errors.
        """
        body = self.build_body(
            messages=messages,
            tools=tools,
            system=system,
            max_tokens=max_tokens,
            betas=betas,
            tool_choice=tool_choice,
        )
        payload = json.dumps(body)

        attempt = 0
        credential_refreshes = 0
        used_generation = self._coordinator.generation if self._coordinator is not None else 0
        while True:
            try:
                response = self._client.invoke_model(
                    modelId=self.model_id,
                    body=payload,
                    contentType="application/json",
                    accept="application/json",
                )
                return self._parse_response(response)
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code", "")
                if (
                    self._is_expired_credentials(code)
                    and self._client_factory is not None
                    and credential_refreshes < 1
                ):
                    # ONE bounded recovery for a CONFIRMED expired-token rejection (the request was refused before processing, so
                    # nothing is replayed that had an effect).  With the coordinator: one coordinated reload of the staged file and, only
                    # if newer credentials exist, one retry through the same client.  Without it: allow the credential bridge's poll to see
                    # an atomic refresh and rebuild the client once.
                    credential_refreshes += 1
                    if self._coordinator is not None:
                        outcome = self._coordinator.reload("expired-token", saw_generation=used_generation)
                        if outcome.reason != "chain" and (not outcome.usable or not (outcome.changed or outcome.coalesced)):
                            raise BedrockCredentialError(self._coordinator.renewal_message(), "upstream_renewal_failed") from None
                        if outcome.reason == "chain":
                            self._client = self._client_factory()
                    else:
                        time.sleep(max(self.base_backoff, 1.0))
                        self._client = self._client_factory()
                    continue
                if self._is_throttling(code) and attempt < self.max_retries:
                    time.sleep(self.base_backoff * (2 ** attempt))
                    attempt += 1
                    continue
                if self._is_beta_rejection(exc):
                    raise BetaRejectedError(
                        "Bedrock rejected the computer-use beta/tool — computer use is "
                        f"likely not enabled on model '{self.model_id}'. ({_safe_error_summary(exc)})"
                    ) from exc
                raise BedrockError(f"Bedrock invoke_model failed. ({_safe_error_summary(exc)})") from exc

    def invoke_computer_use(
        self,
        *,
        messages: list[dict[str, Any]],
        system: str | None = None,
        max_tokens: int | None = None,
        mode: str | None = None,
        tool_choice: dict[str, Any] | None = None,
        extra_tools: list[dict[str, Any]] | None = None,
    ) -> tuple[InvokeResult, str]:
        """Invoke with a computer tool, selecting the tool declaration by mode.

        ``mode`` is ``beta``, ``custom``, or ``auto`` (defaults to the client's configured
        ``computer_tool_mode``). In ``auto`` mode, the first call tries ``beta`` and, on a
        :class:`BetaRejectedError`, transparently retries once as ``custom``; the resolved
        mode is cached so subsequent calls in the same run skip the rejected attempt.

        ``extra_tools`` (e.g. the agent's ``report_result`` tool) are appended to the
        computer tool in every mode so the model can choose between driving and finishing.

        Returns a ``(result, resolved_mode)`` tuple.
        """
        mode = mode or self._resolved_mode or self.computer_tool_mode

        if mode == "beta":
            return self._invoke_mode("beta", messages, system, max_tokens, tool_choice, extra_tools), "beta"
        if mode == "custom":
            return self._invoke_mode("custom", messages, system, max_tokens, tool_choice, extra_tools), "custom"

        # auto: try beta, fall back to custom on rejection.
        try:
            result = self._invoke_mode("beta", messages, system, max_tokens, tool_choice, extra_tools)
            self._resolved_mode = "beta"
            return result, "beta"
        except BetaRejectedError:
            result = self._invoke_mode("custom", messages, system, max_tokens, tool_choice, extra_tools)
            self._resolved_mode = "custom"
            return result, "custom"

    def _invoke_mode(
        self,
        mode: str,
        messages: list[dict[str, Any]],
        system: str | None,
        max_tokens: int | None,
        tool_choice: dict[str, Any] | None,
        extra_tools: list[dict[str, Any]] | None = None,
    ) -> InvokeResult:
        """Build the per-mode tool/beta set and invoke."""
        if mode == "beta":
            tools = [computer_tool(
                settings.model_w,
                settings.model_h,
                tool_type=self.computer_use_tool_type,
            )]
            betas: list[str] | None = [self.computer_use_beta]
        else:  # custom
            tools = [custom_computer_tool(settings.model_w, settings.model_h)]
            betas = None
        if extra_tools:
            tools = tools + extra_tools
        return self.invoke(
            messages=messages,
            tools=tools,
            system=system,
            max_tokens=max_tokens,
            betas=betas,
            tool_choice=tool_choice,
        )

    # --- internals ---------------------------------------------------------

    @staticmethod
    def _is_throttling(code: str) -> bool:
        return code in {"ThrottlingException", "TooManyRequestsException", "ServiceUnavailableException"}

    @staticmethod
    def _is_expired_credentials(code: str) -> bool:
        # Only a CONFIRMED expiry may trigger the single reload+retry.  InvalidClientTokenId / UnrecognizedClientException mean the
        # credentials are INVALID (wrong or revoked), which a reload cannot cure; the shared classifier keeps this rule in one place.
        return code in {"ExpiredToken", "ExpiredTokenException", "RequestExpired", "TokenRefreshRequired"}

    @staticmethod
    def _is_beta_rejection(exc: ClientError) -> bool:
        err = exc.response.get("Error", {})
        code = err.get("Code", "")
        if code not in {"ValidationException", "ValidationError"}:
            return False
        msg = (err.get("Message", "") or "").lower()
        return any(marker in msg for marker in _BETA_REJECTION_MARKERS)

    @staticmethod
    def _parse_response(response: dict[str, Any]) -> InvokeResult:
        """Normalize a raw Bedrock response into an :class:`InvokeResult`."""
        raw_body = response["body"]
        # boto3 returns a StreamingBody; tests may pass bytes/str/dict directly.
        if hasattr(raw_body, "read"):
            raw_body = raw_body.read()
        if isinstance(raw_body, (bytes, bytearray)):
            raw_body = raw_body.decode("utf-8")
        if isinstance(raw_body, str):
            data = json.loads(raw_body)
        else:
            data = raw_body

        blocks: list[ContentBlock] = []
        for item in data.get("content", []):
            btype = item.get("type")
            if btype == "text":
                blocks.append(ContentBlock(type="text", text=item.get("text")))
            elif btype == "tool_use":
                blocks.append(
                    ContentBlock(
                        type="tool_use",
                        name=item.get("name"),
                        input=item.get("input", {}),
                        id=item.get("id"),
                    )
                )
            else:
                # Preserve unknown block types as text for visibility.
                blocks.append(ContentBlock(type=btype or "unknown", text=json.dumps(item)))

        return InvokeResult(
            content=blocks,
            stop_reason=data.get("stop_reason"),
            usage=data.get("usage", {}),
            raw=data,
        )
