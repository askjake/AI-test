"""Field-specific text checks; descriptive prose grants no target authority."""
from __future__ import annotations

import re

# Planning prose is permissive: credential words, natural-language claims,
# questions, colon headings, and file references are not classified as values.
# Only explicit key=value assignments and recognizable secret formats block.
_ASSIGNMENT = re.compile(
    r"(?ix)\b(?:passwords?|passphrases?|secrets?|tokens?|credentials?|authorization|"
    r"api[_ -]?keys?|aws_access_key_id|aws_secret_access_key|aws_session_token)\b"
    r"\s*[\"']?\s*="
)
_PLACEHOLDER = re.compile(
    r"(?ix)\s*(?:<saved[ _-]credential>|<credential[ _-]reference>|"
    r"\$\{(?:PASSWORD|TOKEN|CREDENTIAL_REFERENCE)\})\s*(?=[.!?\n]|$)"
)

_KEY = re.compile(r"-----BEGIN(?: [A-Z]+)? PRIVATE KEY-----")
_AWS_KEY = re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")
_BEARER = re.compile(r"(?i)\bBearer\s+([A-Za-z0-9._~+/-]{8,}=*)")
_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
_URL_SECRET = re.compile(r"(?i)\b[a-z][a-z0-9+.-]*://[^\s/@:]+:[^\s/@]+@")


def sensitive_content_rule(text: str) -> str | None:
    """Return a safe rule identifier without retaining or echoing a match."""
    for rule, pattern in (
        ("private-key", _KEY), ("aws-access-key", _AWS_KEY),
        ("jwt-token", _JWT),
        ("credential-in-url", _URL_SECRET),
    ):
        if pattern.search(text):
            return rule
    for match in _BEARER.finditer(text):
        value = match.group(1)
        if len(value) >= 24 or re.search(r"[0-9._~+/-]", value):
            return "bearer-token"
    for match in _ASSIGNMENT.finditer(text):
        if not _PLACEHOLDER.match(text[match.end():]):
            return "credential-value"
    return None


class AuthoringTextViolation(ValueError):
    def __init__(self, field: str, rule: str):
        # Only caller-owned field paths and fixed rule IDs may reach the UI.
        self.field = field if re.fullmatch(r"[A-Za-z0-9_.\[\] -]{1,100}", field) else "text"
        self.rule = rule
        super().__init__(
            f"Authoring text rejected at {self.field} (rule: {rule}). "
            "Use separate credential controls for values; rejected text is not shown."
        )


def check_authoring_text(text: str, field: str) -> None:
    rule = sensitive_content_rule(text)
    if rule:
        raise AuthoringTextViolation(field, rule)
