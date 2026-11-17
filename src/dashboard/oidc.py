"""OIDC authorization-code + PKCE provider boundary with deterministic transports."""
from __future__ import annotations

from dataclasses import dataclass
import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import ssl
import stat
import subprocess
import threading
import time
from typing import Any, Mapping, Protocol
from urllib.parse import urlencode, urlsplit
from urllib.request import Request as UrlRequest, urlopen

import jwt

from .auth import Actor
from .config import DashboardSettings


_MAX_RESPONSE_BYTES = 1024 * 1024


class OidcError(RuntimeError):
    code = "oidc_denied"


class OidcUnavailable(OidcError):
    code = "sso_unavailable"


class OidcDenied(OidcError):
    code = "oidc_denied"


class OidcTransport(Protocol):
    def get_json(self, url: str) -> Mapping[str, Any]: ...
    def post_form(self, url: str, form: Mapping[str, str]) -> Mapping[str, Any]: ...


class UrlLibOidcTransport:
    """Small no-credential-retention HTTP adapter used only after sign-in starts."""

    def __init__(self, timeout: float = 10.0, *, ca_file: str | None = None) -> None:
        self.timeout = timeout
        try:
            self.ssl_context = ssl.create_default_context(cafile=ca_file)
        except (OSError, ssl.SSLError) as exc:
            raise OidcUnavailable("OIDC CA file is unavailable") from exc

    @staticmethod
    def _decode(response: Any) -> Mapping[str, Any]:
        payload = response.read(_MAX_RESPONSE_BYTES + 1)
        if len(payload) > _MAX_RESPONSE_BYTES:
            raise OidcUnavailable("OIDC provider response exceeded the safe limit")
        try:
            value = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise OidcUnavailable("OIDC provider returned an invalid response") from exc
        if not isinstance(value, dict):
            raise OidcUnavailable("OIDC provider returned an invalid response")
        return value

    def get_json(self, url: str) -> Mapping[str, Any]:
        request = UrlRequest(url, headers={"Accept": "application/json"})
        try:
            with urlopen(request, timeout=self.timeout, context=self.ssl_context) as response:
                return self._decode(response)
        except OidcError:
            raise
        except OSError as exc:
            raise OidcUnavailable("OIDC provider is unavailable") from exc

    def post_form(self, url: str, form: Mapping[str, str]) -> Mapping[str, Any]:
        payload = urlencode(form).encode("ascii")
        request = UrlRequest(
            url,
            data=payload,
            headers={
                "Accept": "application/json",
                "Content-Type": "application/x-www-form-urlencoded",
            },
            method="POST",
        )
        try:
            with urlopen(request, timeout=self.timeout, context=self.ssl_context) as response:
                return self._decode(response)
        except OidcError:
            raise
        except OSError as exc:
            raise OidcUnavailable("OIDC token endpoint is unavailable") from exc


@dataclass(frozen=True)
class OidcMetadata:
    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    jwks_uri: str


@dataclass(frozen=True)
class OidcFlow:
    flow_id: str
    state: str
    nonce: str
    code_verifier: str
    expires_at: float


class OidcFlowStore:
    def __init__(self, ttl_seconds: int = 600, *, maximum: int = 512) -> None:
        self.ttl_seconds = ttl_seconds
        self.maximum = maximum
        self._flows: dict[str, OidcFlow] = {}
        self._lock = threading.RLock()

    def create(self) -> OidcFlow:
        now = time.time()
        flow = OidcFlow(
            flow_id=secrets.token_urlsafe(24),
            state=secrets.token_urlsafe(32),
            nonce=secrets.token_urlsafe(32),
            code_verifier=secrets.token_urlsafe(48),
            expires_at=now + self.ttl_seconds,
        )
        with self._lock:
            for key, item in list(self._flows.items()):
                if item.expires_at <= now:
                    self._flows.pop(key, None)
            if len(self._flows) >= self.maximum:
                oldest = min(self._flows, key=lambda key: self._flows[key].expires_at)
                self._flows.pop(oldest, None)
            self._flows[flow.flow_id] = flow
        return flow

    def consume(self, flow_id: str | None, state: str | None) -> OidcFlow:
        if not flow_id or not state:
            raise OidcDenied("OIDC state is missing")
        with self._lock:
            flow = self._flows.pop(flow_id, None)
        if flow is None or flow.expires_at <= time.time():
            raise OidcDenied("OIDC state is expired")
        if not hmac.compare_digest(flow.state, state):
            raise OidcDenied("OIDC state is invalid")
        return flow


def _b64url_sha256(value: str) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(value.encode("ascii")).digest()).rstrip(b"=").decode("ascii")


def _https_endpoint(value: object, label: str) -> str:
    if not isinstance(value, str):
        raise OidcUnavailable(f"OIDC {label} metadata is missing")
    parsed = urlsplit(value)
    if parsed.scheme != "https" or not parsed.netloc or parsed.fragment:
        raise OidcUnavailable(f"OIDC {label} metadata is invalid")
    return value


def _claim(claims: Mapping[str, Any], path: str) -> Any:
    value: Any = claims
    for segment in path.split("."):
        if not isinstance(value, Mapping) or segment not in value:
            return None
        value = value[segment]
    return value


def _claim_values(value: Any) -> set[str]:
    if isinstance(value, str):
        return {value}
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return set(value)
    return set()


def read_private_client_secret(path_text: str) -> str:
    path = Path(path_text).expanduser()
    if (
        not path.is_absolute()
        or path.is_symlink()
        or not path.is_file()
        or any(char in path_text for char in "\r\n\0")
    ):
        raise OidcUnavailable("OIDC client secret file is unavailable")
    if os.name == "nt":
        username = os.environ.get("USERNAME")
        if not username or any(char in username for char in "\r\n\0"):
            raise OidcUnavailable("OIDC client secret file cannot be protected")
        domain = os.environ.get("USERDOMAIN")
        if domain:
            username = f"{domain}\\{username}"
        try:
            result = subprocess.run(
                [
                    "icacls",
                    str(path),
                    "/inheritance:r",
                    "/grant:r",
                    f"{username}:(F)",
                ],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=15,
                check=False,
                shell=False,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise OidcUnavailable("OIDC client secret file cannot be protected") from exc
        if result.returncode != 0:
            raise OidcUnavailable("OIDC client secret file cannot be protected")
    elif stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise OidcUnavailable("OIDC client secret file is not owner-only")
    try:
        value = path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise OidcUnavailable("OIDC client secret file is unavailable") from exc
    if not 16 <= len(value) <= 4096 or any(char.isspace() for char in value):
        raise OidcUnavailable("OIDC client secret file is invalid")
    return value


class OidcProvider:
    def __init__(
        self,
        settings: DashboardSettings,
        transport: OidcTransport | None = None,
        flows: OidcFlowStore | None = None,
    ) -> None:
        self.settings = settings
        self.transport = transport or UrlLibOidcTransport(ca_file=settings.oidc_ca_file)
        self.flows = flows or OidcFlowStore()
        self._metadata: OidcMetadata | None = None
        self._jwks: Mapping[str, Any] | None = None

    @property
    def configured(self) -> bool:
        return self.settings.oidc_configured

    def _discover(self) -> OidcMetadata:
        if not self.configured:
            raise OidcUnavailable("Organization sign in is not configured")
        if self._metadata is not None:
            return self._metadata
        issuer = self.settings.oidc_issuer or ""
        value = self.transport.get_json(f"{issuer.rstrip('/')}/.well-known/openid-configuration")
        discovered_issuer = value.get("issuer")
        if not isinstance(discovered_issuer, str) or not hmac.compare_digest(discovered_issuer, issuer):
            raise OidcUnavailable("OIDC discovery issuer did not match configured issuer")
        methods = value.get("code_challenge_methods_supported")
        if not isinstance(methods, list) or "S256" not in methods:
            raise OidcUnavailable("OIDC provider does not advertise PKCE S256")
        self._metadata = OidcMetadata(
            issuer=issuer,
            authorization_endpoint=_https_endpoint(value.get("authorization_endpoint"), "authorization endpoint"),
            token_endpoint=_https_endpoint(value.get("token_endpoint"), "token endpoint"),
            jwks_uri=_https_endpoint(value.get("jwks_uri"), "JWKS endpoint"),
        )
        return self._metadata

    def authorization_request(self) -> tuple[OidcFlow, str]:
        metadata = self._discover()
        flow = self.flows.create()
        query = urlencode({
            "response_type": "code",
            "client_id": self.settings.oidc_client_id or "",
            "redirect_uri": self.settings.oidc_redirect_uri or "",
            "scope": " ".join(self.settings.oidc_scopes),
            "state": flow.state,
            "nonce": flow.nonce,
            "code_challenge": _b64url_sha256(flow.code_verifier),
            "code_challenge_method": "S256",
        })
        return flow, f"{metadata.authorization_endpoint}?{query}"

    def _signing_key(self, token: str) -> Any:
        metadata = self._discover()
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError as exc:
            raise OidcDenied("OIDC ID token header is invalid") from exc
        algorithm = header.get("alg")
        key_id = header.get("kid")
        if algorithm not in self.settings.oidc_signing_algorithms or not isinstance(key_id, str):
            raise OidcDenied("OIDC ID token algorithm or key identifier is invalid")
        if self._jwks is None:
            self._jwks = self.transport.get_json(metadata.jwks_uri)
        keys = self._jwks.get("keys") if isinstance(self._jwks, Mapping) else None
        if not isinstance(keys, list):
            raise OidcUnavailable("OIDC JWKS response is invalid")
        candidate = next((item for item in keys if isinstance(item, dict) and item.get("kid") == key_id), None)
        if candidate is None:
            # One bounded refresh supports normal provider key rotation.
            self._jwks = self.transport.get_json(metadata.jwks_uri)
            keys = self._jwks.get("keys") if isinstance(self._jwks, Mapping) else None
            candidate = next((item for item in keys or [] if isinstance(item, dict) and item.get("kid") == key_id), None)
        if candidate is None:
            raise OidcDenied("OIDC signing key was not found")
        try:
            return jwt.PyJWK.from_dict(candidate, algorithm=algorithm).key
        except (jwt.PyJWTError, ValueError) as exc:
            raise OidcDenied("OIDC signing key is invalid") from exc

    def _validate_id_token(self, token: str, nonce: str) -> Mapping[str, Any]:
        metadata = self._discover()
        key = self._signing_key(token)
        try:
            claims = jwt.decode(
                token,
                key,
                algorithms=list(self.settings.oidc_signing_algorithms),
                audience=self.settings.oidc_client_id,
                issuer=metadata.issuer,
                options={"require": ["exp", "iat", "iss", "aud", "sub", "nonce"]},
            )
        except jwt.PyJWTError as exc:
            raise OidcDenied("OIDC ID token validation failed") from exc
        received_nonce = claims.get("nonce")
        if not isinstance(received_nonce, str) or not hmac.compare_digest(received_nonce, nonce):
            raise OidcDenied("OIDC nonce validation failed")
        audience = claims.get("aud")
        if isinstance(audience, list) and len(audience) > 1 and claims.get("azp") != self.settings.oidc_client_id:
            raise OidcDenied("OIDC authorized party validation failed")
        return claims

    def complete(
        self,
        *,
        flow_id: str | None,
        state: str | None,
        code: str | None,
        response_issuer: str | None = None,
    ) -> Actor:
        flow = self.flows.consume(flow_id, state)
        if not code or len(code) > 4096 or any(char.isspace() for char in code):
            raise OidcDenied("OIDC authorization code is invalid")
        metadata = self._discover()
        if response_issuer is not None and not hmac.compare_digest(response_issuer, metadata.issuer):
            raise OidcDenied("OIDC response issuer validation failed")
        form = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self.settings.oidc_redirect_uri or "",
            "client_id": self.settings.oidc_client_id or "",
            "code_verifier": flow.code_verifier,
        }
        if self.settings.oidc_client_secret_file:
            form["client_secret"] = read_private_client_secret(self.settings.oidc_client_secret_file)
        token_response = self.transport.post_form(metadata.token_endpoint, form)
        id_token = token_response.get("id_token")
        if not isinstance(id_token, str) or len(id_token) > 64_000:
            raise OidcDenied("OIDC provider did not return a valid ID token")
        claims = self._validate_id_token(id_token, flow.nonce)
        values = _claim_values(_claim(claims, self.settings.oidc_role_claim))
        if values & set(self.settings.oidc_operator_values):
            role = "operator"
        elif values & set(self.settings.oidc_viewer_values):
            role = "viewer"
        else:
            raise OidcDenied("OIDC account is not mapped to an application role")
        subject = claims.get("sub")
        if not isinstance(subject, str) or not subject or len(subject) > 512:
            raise OidcDenied("OIDC subject is invalid")
        display = _claim(claims, self.settings.oidc_identity_claim)
        if not isinstance(display, str) or not display:
            display = claims.get("name") if isinstance(claims.get("name"), str) else subject
        display = "".join(char for char in display if char >= " " and char != "\x7f")[:200]
        return Actor(
            subject=f"oidc:{subject}",
            role=role,  # type: ignore[arg-type]
            auth_method="oidc",
            display_name=display,
        )

    def reject_response(
        self,
        *,
        flow_id: str | None,
        state: str | None,
        response_issuer: str | None = None,
    ) -> None:
        """Validate and consume an authorization-error response exactly once."""
        self.flows.consume(flow_id, state)
        metadata = self._discover()
        if response_issuer is not None and not hmac.compare_digest(
            response_issuer, metadata.issuer
        ):
            raise OidcDenied("OIDC response issuer validation failed")
