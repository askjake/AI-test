"""Managed, explicitly test-only Keycloak identity provider for one clone.

The source tree contains no credentials, private keys, or generated realm data.
Provisioning creates those values below the ignored, owner-only runtime root and
uses digest-pinned container images.  Keycloak is reachable only through the
managed TLS proxy; its HTTP listener is never published on the host.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import platform as host_platform
import re
import secrets
import shutil
import socket
import ssl
import stat
import subprocess
import tempfile
import time
from typing import Any, Mapping, Sequence
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from .config import (
    ConfigurationError,
    OidcConfig,
    RuntimeConfig,
    atomic_write_json,
    load_config,
    restrict_private_path,
    runtime_root,
    save_config,
    validate_private_secret_file,
)
from .image import engine_reachable, resolve_engine, run_checked


SCHEMA_VERSION = 1
REALM = "orchestrator-cookie"
CLIENT_ID = "orchestrator-cookie-app"
VIEWER_GROUP = "viewers"
OPERATOR_GROUP = "operators"
VIEWER_USERNAME = "local-viewer"
OPERATOR_USERNAME = "local-operator"
# Verified image contract: /opt/keycloak is owned by this non-root UID.
KEYCLOAK_RUNTIME_UID = "1000"

# Recovered and verified from the working 3080 test deployment.  Tags are
# retained only as human context; every engine operation uses the digest.
KEYCLOAK_IMAGE = (
    "quay.io/keycloak/keycloak@"
    "sha256:82c5b7a110456dbd42b86ea572e728878549954cc8bd03cd65410d75328095d2"
)
NGINX_IMAGE = (
    "docker.io/library/nginx@"
    "sha256:72ba65eb42c10344912a84ff42408db7d34f2feb642204570ab8fc5ffd29f1d3"
)

CONFIG_RELATIVE = Path("config") / "local_oidc.json"
RUNTIME_BACKUP_RELATIVE = Path("config") / "runtime.before-local-oidc.json"
STATE_RELATIVE = Path("state") / "local_oidc"
SECRETS_RELATIVE = Path("secrets") / "local_oidc"
OWNER_LABEL = "orchestrator-cookie.local-oidc.owner"
PURPOSE_LABEL = "orchestrator-cookie.local-oidc.purpose"
_HOST_RE = re.compile(
    r"^(?=.{1,253}$)"
    r"(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)"
    r"(?:\.(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?))*$"
)


@dataclass(frozen=True)
class LocalOidcState:
    schema_version: int
    public_host: str
    dashboard_port: int
    app_https_port: int
    idp_https_port: int
    engine: str
    platform: str
    owner_id: str
    network_name: str
    network_subnet: str
    keycloak_ip: str
    proxy_ip: str
    keycloak_container: str
    proxy_container: str
    keycloak_image: str
    nginx_image: str
    realm_file: str
    nginx_config: str
    ca_certificate: str
    server_certificate: str
    server_private_key: str
    client_secret_file: str
    viewer_password_file: str
    operator_password_file: str
    admin_environment_file: str

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> "LocalOidcState":
        try:
            state = cls(**{name: value[name] for name in cls.__dataclass_fields__})
        except (KeyError, TypeError) as exc:
            raise ConfigurationError("local OIDC state is incomplete") from exc
        state.validate()
        return state

    def validate(self) -> None:
        if self.schema_version != SCHEMA_VERSION:
            raise ConfigurationError("unsupported local OIDC state schema")
        validate_public_host(self.public_host)
        ports = (self.dashboard_port, self.app_https_port, self.idp_https_port)
        if any(not isinstance(port, int) or not 1 <= port <= 65535 for port in ports):
            raise ConfigurationError("local OIDC ports are invalid")
        if len(set(ports)) != len(ports):
            raise ConfigurationError("local OIDC ports must be distinct")
        if self.platform not in {"linux/amd64", "linux/arm64"}:
            raise ConfigurationError("local OIDC platform is invalid")
        if self.keycloak_image != KEYCLOAK_IMAGE or self.nginx_image != NGINX_IMAGE:
            raise ConfigurationError("local OIDC image identity differs from the reviewed package")
        if not re.fullmatch(r"[a-f0-9]{12}", self.owner_id):
            raise ConfigurationError("local OIDC owner identity is invalid")
        for name in (self.network_name, self.keycloak_container, self.proxy_container):
            if not re.fullmatch(r"[a-z0-9][a-z0-9_.-]{0,127}", name):
                raise ConfigurationError("local OIDC engine resource name is invalid")
        try:
            network = ipaddress.ip_network(self.network_subnet, strict=True)
            keycloak_ip = ipaddress.ip_address(self.keycloak_ip)
            proxy_ip = ipaddress.ip_address(self.proxy_ip)
        except ValueError as exc:
            raise ConfigurationError("local OIDC network state is invalid") from exc
        if network.version != 4 or keycloak_ip not in network or proxy_ip not in network:
            raise ConfigurationError("local OIDC container addresses are outside their network")
        for field_name in (
            "realm_file",
            "nginx_config",
            "ca_certificate",
            "server_certificate",
            "server_private_key",
            "client_secret_file",
            "viewer_password_file",
            "operator_password_file",
            "admin_environment_file",
        ):
            path = Path(getattr(self, field_name))
            if not path.is_absolute() or any(character in str(path) for character in "\r\n\0"):
                raise ConfigurationError("local OIDC artifact path is invalid")

    def to_dict(self) -> dict[str, Any]:
        return {name: getattr(self, name) for name in self.__dataclass_fields__}

    @property
    def issuer(self) -> str:
        return f"https://{url_host(self.public_host)}:{self.idp_https_port}/realms/{REALM}"

    @property
    def redirect_uri(self) -> str:
        return (
            f"https://{url_host(self.public_host)}:{self.app_https_port}"
            "/api/v1/auth/oidc/callback"
        )


@dataclass(frozen=True)
class LocalOidcStatus:
    configured: bool
    ready: bool
    detail: str
    app_url: str | None = None
    issuer: str | None = None


def validate_public_host(value: str) -> str:
    if not isinstance(value, str) or not value or any(character in value for character in "\r\n\0/:"):
        raise ConfigurationError("local OIDC public host must be a literal IP address or DNS name")
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        if not _HOST_RE.fullmatch(value) or value.lower() == "localhost":
            raise ConfigurationError("local OIDC public host is invalid")
    else:
        if address.version != 4 or address.is_unspecified or address.is_multicast:
            raise ConfigurationError("local OIDC public host must be a usable IPv4 address or DNS name")
    return value


def url_host(value: str) -> str:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return value
    return f"[{value}]" if address.version == 6 else value


def _owner_id(repo_root: Path) -> str:
    return hashlib.sha256(str(repo_root.resolve()).encode("utf-8")).hexdigest()[:12]


def _private_directory(path: Path) -> None:
    if path.is_symlink():
        raise ConfigurationError("local OIDC directory may not be a symlink")
    path.mkdir(parents=True, exist_ok=True)
    restrict_private_path(path)


def _atomic_write(path: Path, payload: bytes, mode: int) -> None:
    _private_directory(path.parent)
    if path.is_symlink():
        raise ConfigurationError("refusing to replace a local OIDC symlink")
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        if os.name != "nt":
            os.chmod(path, mode)
    except BaseException:
        try:
            os.close(descriptor)
        except OSError:
            pass
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        raise


def _secret(path: Path, *, characters: int = 48) -> str:
    if path.exists():
        validated = validate_private_secret_file(str(path), path.name)
        value = validated.read_text(encoding="utf-8").strip()
        if len(value) < 24 or any(character.isspace() for character in value):
            raise ConfigurationError(f"{path.name} is invalid")
        return value
    value = secrets.token_urlsafe(characters)
    _atomic_write(path, (value + "\n").encode("utf-8"), 0o600)
    return value


def _generate_certificates(
    *,
    public_host: str,
    ca_key_path: Path,
    ca_certificate_path: Path,
    server_key_path: Path,
    server_certificate_path: Path,
) -> None:
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
    except ImportError as exc:
        raise ConfigurationError("local OIDC provisioning requires the initialized dashboard environment") from exc

    now = datetime.now(timezone.utc)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    ca_name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "Orchestrator Cookie local test CA"),
    ])
    ca_certificate = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                ca_key.public_key()
            ),
            critical=False,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )

    server_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    server_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, public_host)])
    names: list[Any] = [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
    try:
        names.append(x509.IPAddress(ipaddress.ip_address(public_host)))
    except ValueError:
        names.append(x509.DNSName(public_host))
    server_certificate = (
        x509.CertificateBuilder()
        .subject_name(server_name)
        .issuer_name(ca_certificate.subject)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=825))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName(names), critical=False)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(
                server_key.public_key()
            ),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(
                ca_key.public_key()
            ),
            critical=False,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )

    private_format = serialization.PrivateFormat.PKCS8
    no_encryption = serialization.NoEncryption()
    _atomic_write(
        ca_key_path,
        ca_key.private_bytes(serialization.Encoding.PEM, private_format, no_encryption),
        0o600,
    )
    _atomic_write(
        ca_certificate_path,
        ca_certificate.public_bytes(serialization.Encoding.PEM),
        0o644,
    )
    _atomic_write(
        server_key_path,
        server_key.private_bytes(serialization.Encoding.PEM, private_format, no_encryption),
        0o600,
    )
    _atomic_write(
        server_certificate_path,
        server_certificate.public_bytes(serialization.Encoding.PEM),
        0o644,
    )


def _realm_document(
    *,
    public_host: str,
    app_https_port: int,
    client_secret: str,
    viewer_password: str,
    operator_password: str,
) -> dict[str, Any]:
    app_origin = f"https://{url_host(public_host)}:{app_https_port}"
    return {
        "realm": REALM,
        "enabled": True,
        "displayName": "Orchestrator Cookie local test identity",
        "sslRequired": "external",
        "registrationAllowed": False,
        "resetPasswordAllowed": False,
        "loginWithEmailAllowed": True,
        "duplicateEmailsAllowed": False,
        "groups": [{"name": VIEWER_GROUP}, {"name": OPERATOR_GROUP}],
        "clients": [
            {
                "clientId": CLIENT_ID,
                "name": "Orchestrator Cookie local test client",
                "enabled": True,
                "protocol": "openid-connect",
                "publicClient": False,
                "secret": client_secret,
                "standardFlowEnabled": True,
                "directAccessGrantsEnabled": False,
                "implicitFlowEnabled": False,
                "serviceAccountsEnabled": False,
                "redirectUris": [f"{app_origin}/api/v1/auth/oidc/callback"],
                "webOrigins": [app_origin],
                "attributes": {
                    "pkce.code.challenge.method": "S256",
                    "post.logout.redirect.uris": f"{app_origin}/*",
                },
                "protocolMappers": [
                    {
                        "name": "groups",
                        "protocol": "openid-connect",
                        "protocolMapper": "oidc-group-membership-mapper",
                        "consentRequired": False,
                        "config": {
                            "full.path": "false",
                            "claim.name": "groups",
                            "id.token.claim": "true",
                            "access.token.claim": "true",
                            "userinfo.token.claim": "true",
                        },
                    }
                ],
            }
        ],
        "users": [
            {
                "username": VIEWER_USERNAME,
                "enabled": True,
                "emailVerified": True,
                "email": "local-viewer@example.invalid",
                "groups": [f"/{VIEWER_GROUP}"],
                "credentials": [
                    {"type": "password", "value": viewer_password, "temporary": False}
                ],
            },
            {
                "username": OPERATOR_USERNAME,
                "enabled": True,
                "emailVerified": True,
                "email": "local-operator@example.invalid",
                "groups": [f"/{OPERATOR_GROUP}"],
                "credentials": [
                    {"type": "password", "value": operator_password, "temporary": False}
                ],
            },
        ],
    }


def _nginx_document(state: LocalOidcState) -> str:
    return f"""pid /tmp/nginx.pid;
error_log /dev/stderr info;

events {{}}

http {{
  access_log /dev/stdout;
  client_body_temp_path /tmp/client_body;
  proxy_temp_path /tmp/proxy;
  fastcgi_temp_path /tmp/fastcgi;
  uwsgi_temp_path /tmp/uwsgi;
  scgi_temp_path /tmp/scgi;

  server {{
    listen {state.app_https_port} ssl;
    server_name {state.public_host};

    ssl_certificate /tls/server.crt;
    ssl_certificate_key /tls/server.key;
    ssl_protocols TLSv1.2 TLSv1.3;

    location / {{
      proxy_pass http://host.docker.internal:{state.dashboard_port};
      proxy_http_version 1.1;
      proxy_set_header Host $http_host;
      proxy_set_header Forwarded "";
      proxy_set_header X-Forwarded-For $remote_addr;
      proxy_set_header X-Forwarded-Proto https;
      proxy_set_header X-Forwarded-Host $host;
      proxy_set_header X-Forwarded-Port {state.app_https_port};
      proxy_set_header X-Real-IP $remote_addr;
      proxy_set_header X-Original-Forwarded-For "";
      proxy_set_header X-Original-URL "";
      proxy_set_header X-Original-Method "";
      proxy_set_header X-Forwarded-Access-Token "";
      proxy_set_header X-Original-Access-Token "";
      proxy_read_timeout 300;
      proxy_buffering off;
    }}
  }}

  server {{
    listen {state.idp_https_port} ssl;
    server_name {state.public_host};

    ssl_certificate /tls/server.crt;
    ssl_certificate_key /tls/server.key;
    ssl_protocols TLSv1.2 TLSv1.3;

    location ^~ /realms/{REALM}/ {{
      proxy_pass http://keycloak:8080;
      proxy_set_header Host $http_host;
      proxy_set_header Forwarded "";
      proxy_set_header X-Forwarded-For $remote_addr;
      proxy_set_header X-Forwarded-Proto https;
      proxy_set_header X-Forwarded-Host $host;
      proxy_set_header X-Forwarded-Port {state.idp_https_port};
      proxy_set_header X-Real-IP $remote_addr;
      proxy_set_header X-Original-Forwarded-For "";
      proxy_set_header X-Original-URL "";
      proxy_set_header X-Original-Method "";
      proxy_set_header X-Forwarded-Access-Token "";
      proxy_set_header X-Original-Access-Token "";
    }}

    location ^~ /resources/ {{
      proxy_pass http://keycloak:8080;
      proxy_set_header Host $http_host;
      proxy_set_header Forwarded "";
      proxy_set_header X-Forwarded-For $remote_addr;
      proxy_set_header X-Forwarded-Proto https;
      proxy_set_header X-Forwarded-Host $host;
      proxy_set_header X-Forwarded-Port {state.idp_https_port};
      proxy_set_header X-Real-IP $remote_addr;
      proxy_set_header X-Original-Forwarded-For "";
      proxy_set_header X-Original-URL "";
      proxy_set_header X-Original-Method "";
      proxy_set_header X-Forwarded-Access-Token "";
      proxy_set_header X-Original-Access-Token "";
    }}

    location / {{ return 404; }}
  }}
}}
"""


def _port_available(port: int) -> bool:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(("0.0.0.0", port))
    except OSError:
        return False
    finally:
        sock.close()
    return True


def _select_port(start: int, *, reserved: set[int]) -> int:
    if not 1 <= start <= 65535:
        raise ConfigurationError("local OIDC preferred port is invalid")
    for port in range(start, 65536):
        if port not in reserved and _port_available(port):
            return port
    raise ConfigurationError(f"no local OIDC port is available from {start} through 65535")


def _engine_json(engine: str, argv: Sequence[str], *, timeout: int = 30) -> Any:
    try:
        result = run_checked([engine, *argv], timeout=timeout)
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return None


def _image_ready(engine: str, reference: str) -> bool:
    value = _engine_json(engine, ["image", "inspect", reference], timeout=30)
    if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
        return False
    expected = reference.rsplit("@", 1)[-1].lower()
    return any(
        isinstance(item, str) and item.rsplit("@", 1)[-1].lower() == expected
        for item in value[0].get("RepoDigests") or []
    )


def acquire_images(engine: str, platform: str) -> None:
    for reference in (KEYCLOAK_IMAGE, NGINX_IMAGE):
        if _image_ready(engine, reference):
            continue
        result = run_checked(
            [engine, "pull", "--platform", platform, reference],
            timeout=900,
        )
        if result.returncode != 0 or not _image_ready(engine, reference):
            raise ConfigurationError("local OIDC image acquisition or digest verification failed")


def _network(engine: str, state: LocalOidcState | None, owner_id: str) -> tuple[str, str, str, str, bool]:
    name = state.network_name if state else f"orchestrator-cookie-oidc-{owner_id}"
    value = _engine_json(engine, ["network", "inspect", name])
    created = False
    if value is None:
        result = run_checked(
            [
                engine,
                "network",
                "create",
                "--label",
                f"{OWNER_LABEL}={owner_id}",
                "--label",
                f"{PURPOSE_LABEL}=test-only-identity",
                name,
            ],
            timeout=60,
        )
        if result.returncode != 0:
            raise ConfigurationError("could not create the private local OIDC network")
        created = True
        value = _engine_json(engine, ["network", "inspect", name])
    if not isinstance(value, list) or len(value) != 1:
        raise ConfigurationError("local OIDC network could not be inspected")
    inspected = value[0]
    labels = inspected.get("Labels") or {}
    if labels.get(OWNER_LABEL) != owner_id:
        raise ConfigurationError("local OIDC network name is owned by another deployment")
    ipam = ((inspected.get("IPAM") or {}).get("Config") or [])
    subnet_text = next(
        (item.get("Subnet") for item in ipam if isinstance(item, dict) and item.get("Subnet")),
        None,
    )
    try:
        subnet = ipaddress.ip_network(subnet_text or "", strict=True)
    except ValueError as exc:
        raise ConfigurationError("local OIDC network has no usable subnet") from exc
    if subnet.version != 4 or subnet.num_addresses < 8:
        raise ConfigurationError("local OIDC network requires an IPv4 subnet with free addresses")
    keycloak_ip = str(subnet.network_address + 2)
    proxy_ip = str(subnet.network_address + 3)
    return name, str(subnet), keycloak_ip, proxy_ip, created


def _container(engine: str, name: str) -> dict[str, Any] | None:
    value = _engine_json(engine, ["container", "inspect", name])
    if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
        return None
    return value[0]


def _start_existing_container(engine: str, name: str, owner_id: str) -> bool:
    value = _container(engine, name)
    if value is None:
        return False
    labels = ((value.get("Config") or {}).get("Labels") or {})
    if labels.get(OWNER_LABEL) != owner_id:
        raise ConfigurationError(f"container name {name} is owned by another deployment")
    if not (value.get("State") or {}).get("Running"):
        result = run_checked([engine, "container", "start", name], timeout=90)
        if result.returncode != 0:
            raise ConfigurationError(f"local OIDC container {name} could not be started")
    return True


def _run_container(engine: str, argv: Sequence[str], label: str) -> None:
    result = run_checked([engine, "run", "--detach", *argv], timeout=180)
    if result.returncode != 0:
        raise ConfigurationError(f"local OIDC {label} container failed to start")


def _start_containers(engine: str, state: LocalOidcState) -> list[str]:
    created: list[str] = []
    uid = str(os.getuid()) if hasattr(os, "getuid") else "1000"
    gid = str(os.getgid()) if hasattr(os, "getgid") else "1000"
    user = f"{uid}:{gid}"
    keycloak_user = f"{KEYCLOAK_RUNTIME_UID}:{gid}"

    try:
        if not _start_existing_container(engine, state.keycloak_container, state.owner_id):
            _run_container(
                engine,
                [
                    "--name", state.keycloak_container,
                    "--label", f"{OWNER_LABEL}={state.owner_id}",
                    "--label", f"{PURPOSE_LABEL}=test-only-keycloak",
                    "--network", state.network_name,
                    "--network-alias", "keycloak",
                    "--ip", state.keycloak_ip,
                    "--user", keycloak_user,
                    "--cap-drop", "ALL",
                    "--security-opt", "no-new-privileges",
                    "--memory", "1g",
                    "--pids-limit", "512",
                    "--env-file", state.admin_environment_file,
                    "--volume", f"{Path(state.realm_file).parent.parent}:/opt/keycloak/data:rw",
                    "--entrypoint", "/bin/sh",
                    state.keycloak_image,
                    "-c",
                    'umask 0007; exec /opt/keycloak/bin/kc.sh "$@"',
                    "orchestrator-cookie-keycloak",
                    "start-dev",
                    "--import-realm",
                    f"--hostname={state.issuer.rsplit('/realms/', 1)[0]}",
                    "--hostname-strict=true",
                    "--proxy-headers=xforwarded",
                    "--http-enabled=true",
                ],
                "Keycloak",
            )
            created.append(state.keycloak_container)

        if not _start_existing_container(engine, state.proxy_container, state.owner_id):
            _run_container(
                engine,
                [
                    "--name", state.proxy_container,
                    "--label", f"{OWNER_LABEL}={state.owner_id}",
                    "--label", f"{PURPOSE_LABEL}=test-only-tls-proxy",
                    "--network", state.network_name,
                    "--ip", state.proxy_ip,
                    "--add-host", "host.docker.internal:host-gateway",
                    "--user", user,
                    "--read-only",
                    "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=16m",
                    "--cap-drop", "ALL",
                    "--security-opt", "no-new-privileges",
                    "--pids-limit", "128",
                    "--publish", f"0.0.0.0:{state.app_https_port}:{state.app_https_port}",
                    "--publish", f"0.0.0.0:{state.idp_https_port}:{state.idp_https_port}",
                    "--volume", f"{state.nginx_config}:/etc/nginx/nginx.conf:ro",
                    "--volume", f"{state.server_certificate}:/tls/server.crt:ro",
                    "--volume", f"{state.server_private_key}:/tls/server.key:ro",
                    "--entrypoint", "/usr/sbin/nginx",
                    state.nginx_image,
                    "-g", "daemon off;",
                ],
                "TLS proxy",
            )
            created.append(state.proxy_container)
    except BaseException:
        for name in reversed(created):
            run_checked([engine, "container", "rm", "--force", name], timeout=60)
        raise
    return created


def _wait_ready(state: LocalOidcState, *, timeout: float = 90.0) -> None:
    context = ssl.create_default_context(cafile=state.ca_certificate)
    endpoint = (
        f"https://127.0.0.1:{state.idp_https_port}/realms/{REALM}"
        "/.well-known/openid-configuration"
    )
    deadline = time.monotonic() + timeout
    last_error = "unavailable"
    while time.monotonic() < deadline:
        try:
            request = Request(endpoint, headers={"Accept": "application/json"})
            with urlopen(request, context=context, timeout=2) as response:
                payload = response.read(1024 * 1024 + 1)
            value = json.loads(payload.decode("utf-8"))
            if value.get("issuer") == state.issuer and "S256" in value.get("code_challenge_methods_supported", []):
                return
            last_error = "discovery identity or PKCE contract did not match"
        except (OSError, HTTPError, URLError, ValueError, json.JSONDecodeError) as exc:
            last_error = type(exc).__name__
        time.sleep(0.25)
    raise ConfigurationError(f"local OIDC provider did not become ready ({last_error})")


def load_local_oidc_state(repo_root: Path, *, required: bool = False) -> LocalOidcState | None:
    path = runtime_root(repo_root) / CONFIG_RELATIVE
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        if required:
            raise ConfigurationError("local OIDC is not provisioned")
        return None
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigurationError("local OIDC state is unreadable") from exc
    if not isinstance(value, dict):
        raise ConfigurationError("local OIDC state must be an object")
    return LocalOidcState.from_mapping(value)


def _runtime_backup_path(repo_root: Path) -> Path:
    return runtime_root(repo_root) / RUNTIME_BACKUP_RELATIVE


def _load_runtime_backup(repo_root: Path) -> RuntimeConfig:
    path = _runtime_backup_path(repo_root)
    if path.is_symlink() or not path.is_file():
        raise ConfigurationError("pre-OIDC runtime configuration backup is unavailable")
    if os.name != "nt" and stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise ConfigurationError("pre-OIDC runtime configuration backup is not owner-only")
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigurationError("pre-OIDC runtime configuration backup is unreadable") from exc
    if not isinstance(value, dict):
        raise ConfigurationError("pre-OIDC runtime configuration backup is invalid")
    config = RuntimeConfig.from_mapping(value)
    config.validate()
    return config


def _preserve_runtime_backup(repo_root: Path, config: RuntimeConfig) -> None:
    path = _runtime_backup_path(repo_root)
    if path.exists() or path.is_symlink():
        _load_runtime_backup(repo_root)
        return
    atomic_write_json(path, config.to_dict())
    restrict_private_path(path)


def _activate_runtime_config(repo_root: Path, state: LocalOidcState) -> RuntimeConfig:
    config = load_config(repo_root)
    configured = replace(
        config,
        bind_host="0.0.0.0",
        port=state.dashboard_port,
        preferred_port=state.dashboard_port,
        port_fallback_enabled=False,
        lan_enabled=True,
        engine=state.engine,
        oidc=OidcConfig(
            enabled=True,
            issuer=state.issuer,
            client_id=CLIENT_ID,
            redirect_uri=state.redirect_uri,
            client_secret_file=state.client_secret_file,
            ca_file=state.ca_certificate,
            provider_label="local test identity",
            test_only=True,
            role_claim="groups",
            viewer_values=(VIEWER_GROUP,),
            operator_values=(OPERATOR_GROUP,),
            identity_claim="preferred_username",
            scopes=("openid", "profile", "email"),
            signing_algorithms=("RS256",),
            tls_terminated=True,
            trusted_proxy_cidrs=(f"{state.proxy_ip}/32",),
            session_ttl_seconds=28_800,
        ),
    )
    configured.validate()
    save_config(repo_root, configured)
    return config


def provision_local_oidc(
    repo_root: Path,
    *,
    public_host: str,
    dashboard_port: int = 8025,
    app_https_port: int | None = None,
    idp_https_port: int | None = None,
    platform: str = "linux/amd64",
) -> LocalOidcState:
    """Explicitly acquire and provision the clone-local test identity stack."""
    if host_platform.system() != "Linux":
        raise ConfigurationError("the packaged local OIDC profile is currently supported only on Linux")
    public_host = validate_public_host(public_host)
    existing = load_local_oidc_state(repo_root)
    if existing:
        requested = (
            public_host,
            dashboard_port,
            platform,
        )
        observed = (
            existing.public_host,
            existing.dashboard_port,
            existing.platform,
        )
        if requested != observed:
            raise ConfigurationError(
                "local OIDC is already provisioned with different immutable settings"
            )
        if app_https_port is not None and app_https_port != existing.app_https_port:
            raise ConfigurationError("local OIDC application HTTPS port is already persisted")
        if idp_https_port is not None and idp_https_port != existing.idp_https_port:
            raise ConfigurationError("local OIDC provider HTTPS port is already persisted")
        start_local_oidc(repo_root, existing)
        _activate_runtime_config(repo_root, existing)
        return existing

    config = load_config(repo_root)
    _preserve_runtime_backup(repo_root, config)
    engine = resolve_engine(config.engine)
    if not engine:
        raise ConfigurationError("Docker or Podman is required for local OIDC")
    if Path(engine).name != "docker":
        raise ConfigurationError("the packaged local OIDC profile currently requires Docker")
    reachable, detail = engine_reachable(engine)
    if not reachable:
        raise ConfigurationError(detail)
    if platform not in {"linux/amd64", "linux/arm64"}:
        raise ConfigurationError("local OIDC platform must be linux/amd64 or linux/arm64")
    if type(dashboard_port) is not int or not 1 <= dashboard_port <= 65535:
        raise ConfigurationError("local OIDC dashboard port must be an integer from 1 through 65535")
    if not _port_available(dashboard_port):
        raise ConfigurationError(f"required dashboard port 0.0.0.0:{dashboard_port} is unavailable")

    reserved = {dashboard_port}
    selected_app_port = _select_port(app_https_port or 8443, reserved=reserved)
    reserved.add(selected_app_port)
    selected_idp_port = _select_port(idp_https_port or 9443, reserved=reserved)

    acquire_images(engine, platform)
    owner_id = _owner_id(repo_root)
    network_name, subnet, keycloak_ip, proxy_ip, network_created = _network(
        engine, None, owner_id
    )
    prefix = f"orchestrator-cookie-oidc-{owner_id}"
    root = runtime_root(repo_root)
    state_root = root / STATE_RELATIVE
    secrets_root = root / SECRETS_RELATIVE
    keycloak_data = state_root / "keycloak-data"
    import_root = keycloak_data / "import"
    tls_root = state_root / "tls"
    _private_directory(keycloak_data)
    _private_directory(import_root)
    _private_directory(tls_root)
    _private_directory(secrets_root)
    if os.name != "nt":
        # The enclosing runtime/state directories remain owner-only. These two
        # bind-mounted directories additionally admit the reviewed Keycloak UID
        # through the host owner's primary group.
        os.chmod(keycloak_data, 0o770)
        os.chmod(import_root, 0o770)

    client_secret_path = secrets_root / "client-secret"
    viewer_password_path = secrets_root / "viewer-password"
    operator_password_path = secrets_root / "operator-password"
    admin_password_path = secrets_root / "admin-password"
    admin_environment_path = secrets_root / "keycloak-admin.env"
    client_secret = _secret(client_secret_path)
    viewer_password = _secret(viewer_password_path)
    operator_password = _secret(operator_password_path)
    admin_password = _secret(admin_password_path)

    ca_key_path = secrets_root / "ca.key"
    ca_certificate_path = tls_root / "ca.crt"
    server_key_path = secrets_root / "server.key"
    server_certificate_path = tls_root / "server.crt"
    _generate_certificates(
        public_host=public_host,
        ca_key_path=ca_key_path,
        ca_certificate_path=ca_certificate_path,
        server_key_path=server_key_path,
        server_certificate_path=server_certificate_path,
    )

    realm_path = import_root / f"{REALM}-realm.json"
    _atomic_write(
        realm_path,
        (json.dumps(
            _realm_document(
                public_host=public_host,
                app_https_port=selected_app_port,
                client_secret=client_secret,
                viewer_password=viewer_password,
                operator_password=operator_password,
            ),
            indent=2,
            sort_keys=True,
        ) + "\n").encode("utf-8"),
        0o640,
    )
    if os.name != "nt":
        # _atomic_write secures its parent to 0700; restore only the import
        # directory's bounded Keycloak group traversal/read permission.
        os.chmod(import_root, 0o770)
    _atomic_write(
        admin_environment_path,
        (
            "KEYCLOAK_ADMIN=local-admin\n"
            f"KEYCLOAK_ADMIN_PASSWORD={admin_password}\n"
        ).encode("utf-8"),
        0o600,
    )

    state = LocalOidcState(
        schema_version=SCHEMA_VERSION,
        public_host=public_host,
        dashboard_port=dashboard_port,
        app_https_port=selected_app_port,
        idp_https_port=selected_idp_port,
        engine=engine,
        platform=platform,
        owner_id=owner_id,
        network_name=network_name,
        network_subnet=subnet,
        keycloak_ip=keycloak_ip,
        proxy_ip=proxy_ip,
        keycloak_container=f"{prefix}-keycloak",
        proxy_container=f"{prefix}-proxy",
        keycloak_image=KEYCLOAK_IMAGE,
        nginx_image=NGINX_IMAGE,
        realm_file=str(realm_path.resolve()),
        nginx_config=str((tls_root / "nginx.conf").resolve()),
        ca_certificate=str(ca_certificate_path.resolve()),
        server_certificate=str(server_certificate_path.resolve()),
        server_private_key=str(server_key_path.resolve()),
        client_secret_file=str(client_secret_path.resolve()),
        viewer_password_file=str(viewer_password_path.resolve()),
        operator_password_file=str(operator_password_path.resolve()),
        admin_environment_file=str(admin_environment_path.resolve()),
    )
    state.validate()
    _atomic_write(Path(state.nginx_config), _nginx_document(state).encode("utf-8"), 0o600)

    created: list[str] = []
    config_saved = False
    state_saved = False
    try:
        atomic_write_json(root / CONFIG_RELATIVE, state.to_dict())
        restrict_private_path(root / CONFIG_RELATIVE)
        state_saved = True
        created = _start_containers(engine, state)
        _wait_ready(state)
        _activate_runtime_config(repo_root, state)
        config_saved = True
    except BaseException:
        if config_saved:
            try:
                save_config(repo_root, config)
            except Exception:
                pass
        for container in reversed(created):
            run_checked([engine, "container", "rm", "--force", container], timeout=60)
        if network_created:
            run_checked([engine, "network", "rm", network_name], timeout=60)
        if state_saved:
            try:
                (root / CONFIG_RELATIVE).unlink()
            except FileNotFoundError:
                pass
        for generated_root in (state_root, secrets_root):
            expected_parent = root.resolve() / generated_root.parent.relative_to(root)
            resolved = generated_root.resolve()
            if (
                not generated_root.is_symlink()
                and resolved.parent == expected_parent
                and resolved.name == "local_oidc"
            ):
                shutil.rmtree(resolved, ignore_errors=True)
        raise
    return state


def start_local_oidc(
    repo_root: Path,
    state: LocalOidcState | None = None,
) -> LocalOidcStatus:
    state = state or load_local_oidc_state(repo_root, required=True)
    assert state is not None
    engine = resolve_engine(state.engine)
    if not engine:
        raise ConfigurationError("configured local OIDC engine is unavailable")
    reachable, detail = engine_reachable(engine)
    if not reachable:
        raise ConfigurationError(detail)
    if not all(_image_ready(engine, ref) for ref in (state.keycloak_image, state.nginx_image)):
        raise ConfigurationError("a pinned local OIDC image is absent; rerun explicit provisioning")
    network = _engine_json(engine, ["network", "inspect", state.network_name])
    if network is None:
        raise ConfigurationError("local OIDC network is absent; rerun explicit provisioning")
    _start_containers(engine, state)
    _wait_ready(state)
    return LocalOidcStatus(
        True,
        True,
        "local test OIDC is ready",
        f"https://{url_host(state.public_host)}:{state.app_https_port}",
        state.issuer,
    )


def stop_local_oidc(repo_root: Path) -> LocalOidcStatus:
    state = load_local_oidc_state(repo_root)
    if state is None:
        return LocalOidcStatus(False, False, "local OIDC is not provisioned")
    engine = resolve_engine(state.engine)
    if not engine:
        raise ConfigurationError("configured local OIDC engine is unavailable")
    reachable, detail = engine_reachable(engine)
    if not reachable:
        raise ConfigurationError(detail)
    for name in (state.proxy_container, state.keycloak_container):
        container = _container(engine, name)
        if container is None:
            continue
        labels = ((container.get("Config") or {}).get("Labels") or {})
        if labels.get(OWNER_LABEL) != state.owner_id:
            raise ConfigurationError(f"refusing to stop unowned container {name}")
        if (container.get("State") or {}).get("Running"):
            result = run_checked([engine, "container", "stop", "--time", "20", name], timeout=40)
            if result.returncode != 0:
                raise ConfigurationError(f"local OIDC container {name} could not be stopped")
    return LocalOidcStatus(
        True,
        False,
        "local test OIDC is stopped",
        f"https://{url_host(state.public_host)}:{state.app_https_port}",
        state.issuer,
    )


def deactivate_local_oidc(repo_root: Path) -> LocalOidcStatus:
    state = load_local_oidc_state(repo_root, required=True)
    assert state is not None
    restored = _load_runtime_backup(repo_root)
    stop_local_oidc(repo_root)
    save_config(repo_root, restored)
    return LocalOidcStatus(
        True,
        False,
        "local test OIDC is stopped and the pre-OIDC runtime configuration was restored",
        f"https://{url_host(state.public_host)}:{state.app_https_port}",
        state.issuer,
    )


def local_oidc_status(repo_root: Path) -> LocalOidcStatus:
    state = load_local_oidc_state(repo_root)
    if state is None:
        return LocalOidcStatus(False, False, "local OIDC is not provisioned")
    engine = resolve_engine(state.engine)
    if not engine:
        return LocalOidcStatus(True, False, "local OIDC engine is unavailable")
    statuses: dict[str, bool] = {}
    for label, name in (("Keycloak", state.keycloak_container), ("TLS proxy", state.proxy_container)):
        container = _container(engine, name)
        if container:
            labels = ((container.get("Config") or {}).get("Labels") or {})
            if labels.get(OWNER_LABEL) != state.owner_id:
                return LocalOidcStatus(
                    True,
                    False,
                    f"local OIDC container {name} is not owned by this clone",
                    f"https://{url_host(state.public_host)}:{state.app_https_port}",
                    state.issuer,
                )
        statuses[label] = bool(container and (container.get("State") or {}).get("Running"))
    ready = all(statuses.values())
    detail = (
        "local test OIDC containers are running"
        if ready
        else "local test OIDC is not fully running ("
        + ", ".join(f"{label}={'up' if running else 'down'}" for label, running in statuses.items())
        + ")"
    )
    return LocalOidcStatus(
        True,
        ready,
        detail,
        f"https://{url_host(state.public_host)}:{state.app_https_port}",
        state.issuer,
    )


def local_oidc_password_path(repo_root: Path, role: str) -> Path:
    state = load_local_oidc_state(repo_root, required=True)
    assert state is not None
    if role == "viewer":
        path = Path(state.viewer_password_file)
    elif role == "operator":
        path = Path(state.operator_password_file)
    else:
        raise ConfigurationError("local OIDC role must be viewer or operator")
    return validate_private_secret_file(str(path), f"local OIDC {role} password")


def read_local_oidc_password(repo_root: Path, role: str) -> str:
    path = local_oidc_password_path(repo_root, role)
    value = path.read_text(encoding="utf-8").strip()
    if len(value) < 24 or any(character.isspace() for character in value):
        raise ConfigurationError("local OIDC password is invalid")
    return value
