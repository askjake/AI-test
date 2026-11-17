"""Operator-only target discovery and write-only password staging.

Host suggestions are derived from configured allowlists and existing typed
project files. Password values are accepted only by the save operation, are
never returned, and are persisted as an owner-only file in the established
host secret source directory. The runner continues to receive only a safe
reference filename through project.yaml.
"""
from __future__ import annotations

import os
import base64
import binascii
import re
import stat
import tempfile
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator

from .config import DashboardSettings
from .builder_policy import TARGET_CAPABILITIES, TargetCapability


class _StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


TargetConnectionType = Literal["ssh-terminal", "rdp", "vnc"]
PasswordKind = Literal["rdp", "vnc", "gateway", "application"]


class TargetHostOption(_StrictModel):
    host: str = Field(min_length=1, max_length=253)
    sources: list[Literal["configured", "past-project"]] = Field(min_length=1, max_length=2)


class TargetOptions(_StrictModel):
    hosts: dict[TargetConnectionType, list[TargetHostOption]]
    password_references: list[str] = Field(default_factory=list, max_length=500)
    capabilities: list[TargetCapability] = Field(default_factory=lambda: list(TARGET_CAPABILITIES))


class PasswordSaveRequest(_StrictModel):
    kind: PasswordKind
    reference_name: str = Field(
        min_length=1,
        max_length=127,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$",
    )
    password: SecretStr
    overwrite: bool = False

    @field_validator("password")
    @classmethod
    def _bounded_password(cls, value: SecretStr) -> SecretStr:
        secret = value.get_secret_value()
        if not secret or len(secret) > 1_024:
            raise ValueError("Password must contain between 1 and 1024 characters.")
        if any(ord(char) < 32 or ord(char) == 127 for char in secret):
            raise ValueError("Password must not contain control characters.")
        return value


class PasswordSaveResponse(_StrictModel):
    reference_name: str
    kind: PasswordKind
    status: Literal["created", "replaced"]


class KnownHostsSaveRequest(_StrictModel):
    expected_host: str = Field(min_length=1, max_length=253)
    reference_name: str = Field(
        min_length=1, max_length=127,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]*$",
    )
    known_hosts: SecretStr
    overwrite: bool = False

    @field_validator("known_hosts")
    @classmethod
    def _bounded_known_hosts(cls, value: SecretStr) -> SecretStr:
        text = value.get_secret_value()
        if not text or len(text.encode("utf-8")) > 16_384:
            raise ValueError("Known-hosts material must contain between 1 and 16384 UTF-8 bytes.")
        if "\0" in text or "\r" in text:
            raise ValueError("Known-hosts material contains invalid control characters.")
        return value


class KnownHostsSaveResponse(_StrictModel):
    reference_name: str
    status: Literal["created", "replaced"]


class TargetSetupError(ValueError):
    """A target helper operation failed without exposing sensitive material."""


class SecretAlreadyExistsError(TargetSetupError):
    """The requested reference exists and overwrite was not confirmed."""


_HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,252}$")
_REFERENCE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,126}$")


def _safe_host(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    candidate = value.strip()
    return candidate if _HOST_RE.fullmatch(candidate) else None


def _safe_reference(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    candidate = value.strip()
    if candidate in {".", ".."} or not _REFERENCE_RE.fullmatch(candidate):
        return None
    return candidate


class TargetSetupService:
    """Read known target metadata and stage new password material safely."""

    def __init__(self, settings: DashboardSettings, global_settings: object | None = None):
        self.settings = settings
        self.global_settings = global_settings

    def _specs_root(self) -> str:
        value = (
            os.environ.get("DASHBOARD_SPECS_DIR")
            or os.environ.get("TESTS_SPECS_DIR")
            or self.settings.specs_dir
        )
        return os.path.abspath(value)

    def _secrets_root(self) -> str:
        value = (
            os.environ.get("DASHBOARD_SECRETS_DIR")
            or os.environ.get("SECRETS_DIR")
            or self.settings.secrets_dir
        )
        return os.path.abspath(value)

    def _configured_allowlist(self, name: str) -> list[object]:
        if self.global_settings is not None:
            return list(getattr(self.global_settings, name, []) or [])
        raw = os.environ.get(name.upper(), "").strip()
        if not raw:
            return []
        if raw.startswith("["):
            try:
                parsed = yaml.safe_load(raw)
            except yaml.YAMLError:
                return []
            return parsed if isinstance(parsed, list) else []
        return [item.strip() for item in raw.split(",") if item.strip()]

    @staticmethod
    def _read_project_metadata(path: str) -> dict:
        try:
            info = os.lstat(path)
            if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_size > 256_000:
                return {}
            with open(path, encoding="utf-8") as handle:
                payload = yaml.safe_load(handle) or {}
        except (OSError, yaml.YAMLError):
            return {}
        return payload if isinstance(payload, dict) else {}

    def options(self) -> TargetOptions:
        found: dict[TargetConnectionType, dict[str, set[str]]] = {
            "ssh-terminal": {},
            "rdp": {},
            "vnc": {},
        }

        def add(kind: TargetConnectionType, raw: object, source: str) -> None:
            host = _safe_host(raw)
            if host:
                found[kind].setdefault(host, set()).add(source)

        global_names = {
            "ssh-terminal": "ssh_host_allowlist",
            "rdp": "rdp_host_allowlist",
            "vnc": "vnc_host_allowlist",
        }
        for kind, name in global_names.items():
            for host in self._configured_allowlist(name):
                add(kind, host, "configured")

        root = self._specs_root()
        candidates = [os.path.join(root, "project.yaml")]
        try:
            for entry in os.scandir(root):
                if entry.is_dir(follow_symlinks=False):
                    candidates.append(os.path.join(entry.path, "project.yaml"))
        except OSError:
            pass

        allowlist_names: dict[TargetConnectionType, str] = {
            "ssh-terminal": "ssh_host_allowlist",
            "rdp": "rdp_host_allowlist",
            "vnc": "vnc_host_allowlist",
        }
        for path in candidates:
            payload = self._read_project_metadata(path)
            for kind, name in allowlist_names.items():
                values = payload.get(name, [])
                if isinstance(values, list):
                    for host in values:
                        add(kind, host, "past-project")
            target = payload.get("target")
            if isinstance(target, dict):
                kind = target.get("type")
                if kind in found:
                    add(kind, target.get("host"), "past-project")
                route = target.get("route")
                if isinstance(route, dict) and route.get("type") == "ssh-jump":
                    add("ssh-terminal", route.get("host"), "past-project")
                if kind == "vnc" and isinstance(target.get("via"), str):
                    gateway = target["via"].rsplit("@", 1)[-1]
                    add("ssh-terminal", gateway, "past-project")

        hosts: dict[TargetConnectionType, list[TargetHostOption]] = {
            kind: [
                TargetHostOption(
                    host=host,
                    sources=[source for source in ("configured", "past-project") if source in sources],
                )
                for host, sources in sorted(values.items(), key=lambda item: item[0].lower())
            ]
            for kind, values in found.items()
        }
        references: list[str] = []
        secret_root = self._secrets_root()
        try:
            for entry in os.scandir(secret_root):
                if entry.is_file(follow_symlinks=False):
                    reference = _safe_reference(entry.name)
                    if reference:
                        references.append(reference)
        except OSError:
            pass
        return TargetOptions(
            hosts=hosts,
            password_references=sorted(set(references), key=str.lower)[:500],
        )

    def save_password(self, request: PasswordSaveRequest) -> PasswordSaveResponse:
        reference = _safe_reference(request.reference_name)
        if not reference:
            raise TargetSetupError("Password reference must be a safe filename, not a path.")
        secret = request.password.get_secret_value()
        if request.kind == "vnc":
            encoded = secret.encode("utf-8")
            if len(encoded) > 8:
                raise TargetSetupError("VNC passwords must be at most 8 UTF-8 bytes.")
            content = _vnc_password_file(encoded)
        else:
            content = secret.encode("utf-8") + b"\n"

        root = self._secrets_root()
        os.makedirs(root, mode=0o700, exist_ok=True)
        root_info = os.lstat(root)
        if not stat.S_ISDIR(root_info.st_mode) or stat.S_ISLNK(root_info.st_mode):
            raise TargetSetupError("Secret storage is not a real directory.")
        os.chmod(root, 0o700)
        destination = os.path.join(root, reference)
        if os.path.commonpath((root, os.path.abspath(destination))) != root:
            raise TargetSetupError("Password reference must stay inside secret storage.")

        exists = os.path.lexists(destination)
        if exists:
            info = os.lstat(destination)
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
                raise TargetSetupError("Existing password reference is not a regular file.")
            if not request.overwrite:
                raise SecretAlreadyExistsError("A saved password already uses this reference.")

        temporary: str | None = None
        try:
            fd, temporary = tempfile.mkstemp(prefix=".password_", dir=root)
            with os.fdopen(fd, "wb") as handle:
                os.fchmod(handle.fileno(), 0o600)
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            if request.overwrite:
                os.replace(temporary, destination)
                temporary = None
            else:
                try:
                    os.link(temporary, destination, follow_symlinks=False)
                except FileExistsError as exc:
                    raise SecretAlreadyExistsError(
                        "A saved password already uses this reference."
                    ) from exc
                os.unlink(temporary)
                temporary = None
            os.chmod(destination, 0o600)
        finally:
            if temporary and os.path.exists(temporary):
                os.unlink(temporary)
        return PasswordSaveResponse(
            reference_name=reference,
            kind=request.kind,
            status="replaced" if exists else "created",
        )

    def save_known_hosts(self, request: KnownHostsSaveRequest) -> KnownHostsSaveResponse:
        reference = _safe_reference(request.reference_name)
        if not reference:
            raise TargetSetupError("Known-hosts reference must be a safe filename, not a path.")
        expected = request.expected_host.strip()
        if not _HOST_RE.fullmatch(expected):
            raise TargetSetupError("Expected jump host is invalid.")
        text = request.known_hosts.get_secret_value()
        matched = False
        supported_key = re.compile(
            r"^(?:ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(?:256|384|521)|sk-ssh-ed25519@openssh\.com)$"
        )
        lines: list[str] = []
        for raw in text.splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            fields = line.split()
            if len(fields) not in {3, 4} or not supported_key.fullmatch(fields[1]):
                raise TargetSetupError("Known-hosts material must use a supported OpenSSH host-key line.")
            if len(fields) == 4 and any(ord(char) < 32 or ord(char) == 127 for char in fields[3]):
                raise TargetSetupError("Known-hosts comment contains invalid characters.")
            try:
                decoded = base64.b64decode(fields[2], validate=True)
            except (ValueError, binascii.Error) as exc:
                raise TargetSetupError("Known-hosts key data is not valid base64.") from exc
            if not 16 <= len(decoded) <= 8_192:
                raise TargetSetupError("Known-hosts key data has an invalid bounded length.")
            hosts = fields[0].split(",")
            if any(item.startswith("|") for item in hosts):
                raise TargetSetupError("Hashed hostnames are not accepted because the expected jump host must be reviewable.")
            matched = matched or expected in hosts or any(
                item.startswith(f"[{expected}]:") for item in hosts
            )
            lines.append(line)
        if not lines or not matched:
            raise TargetSetupError("Known-hosts material does not contain the exact expected jump host.")
        exists = self._save_secret_bytes(
            reference, ("\n".join(lines) + "\n").encode("utf-8"),
            label="Known-hosts", overwrite=request.overwrite,
        )
        return KnownHostsSaveResponse(
            reference_name=reference,
            status="replaced" if exists else "created",
        )

    def _save_secret_bytes(
        self, reference: str, content: bytes, *, label: str, overwrite: bool
    ) -> bool:
        root = self._secrets_root()
        os.makedirs(root, mode=0o700, exist_ok=True)
        root_info = os.lstat(root)
        if not stat.S_ISDIR(root_info.st_mode) or stat.S_ISLNK(root_info.st_mode):
            raise TargetSetupError("Secret storage is not a real directory.")
        os.chmod(root, 0o700)
        destination = os.path.join(root, reference)
        if os.path.commonpath((root, os.path.abspath(destination))) != root:
            raise TargetSetupError(f"{label} reference must stay inside secret storage.")
        exists = os.path.lexists(destination)
        if exists:
            info = os.lstat(destination)
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
                raise TargetSetupError(f"Existing {label.lower()} reference is not a regular file.")
            # Known-hosts replacement uses the same explicit overwrite contract
            # as password replacement.
            if not overwrite:
                raise SecretAlreadyExistsError(f"A saved {label.lower()} file already uses this reference.")
        temporary: str | None = None
        try:
            fd, temporary = tempfile.mkstemp(prefix=".known_hosts_", dir=root)
            with os.fdopen(fd, "wb") as handle:
                os.fchmod(handle.fileno(), 0o600)
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            if overwrite:
                os.replace(temporary, destination)
                temporary = None
            else:
                try:
                    os.link(temporary, destination, follow_symlinks=False)
                except FileExistsError as exc:
                    raise SecretAlreadyExistsError(
                        f"A saved {label.lower()} file already uses this reference."
                    ) from exc
                os.unlink(temporary)
                temporary = None
            os.chmod(destination, 0o600)
        finally:
            if temporary and os.path.exists(temporary):
                os.unlink(temporary)
        return exists


# VNC password files use the historical fixed-key DES representation required
# by TigerVNC's ``-passwd`` option. This is format compatibility, not encryption
# at rest; filesystem mode 0600 remains the actual access control.
_VNC_KEY = bytes((23, 82, 107, 6, 35, 78, 88, 7))
_IP = (58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7)
_FP = (40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27, 34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25)
_E = (32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1)
_P = (16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25)
_PC1 = (57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4)
_PC2 = (14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32)
_SHIFTS = (1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1)
_SBOX = (
    ((14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7),(0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8),(4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0),(15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13)),
    ((15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10),(3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5),(0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15),(13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9)),
    ((10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8),(13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1),(13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7),(1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12)),
    ((7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15),(13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9),(10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4),(3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14)),
    ((2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9),(14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6),(4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14),(11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3)),
    ((12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11),(10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8),(9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6),(4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13)),
    ((4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1),(13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6),(1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2),(6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12)),
    ((13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7),(1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2),(7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8),(2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11)),
)


def _permute(value: int, table: tuple[int, ...], width: int) -> int:
    result = 0
    for position in table:
        result = (result << 1) | ((value >> (width - position)) & 1)
    return result


def _des_subkeys(key: bytes) -> list[int]:
    combined = _permute(int.from_bytes(key, "big"), _PC1, 64)
    left, right = combined >> 28, combined & ((1 << 28) - 1)
    subkeys: list[int] = []
    for shift in _SHIFTS:
        left = ((left << shift) | (left >> (28 - shift))) & ((1 << 28) - 1)
        right = ((right << shift) | (right >> (28 - shift))) & ((1 << 28) - 1)
        subkeys.append(_permute((left << 28) | right, _PC2, 56))
    return subkeys


def _des_encrypt_block(block: bytes, key: bytes) -> bytes:
    state = _permute(int.from_bytes(block, "big"), _IP, 64)
    left, right = state >> 32, state & 0xFFFFFFFF
    for subkey in _des_subkeys(key):
        expanded = _permute(right, _E, 32) ^ subkey
        substituted = 0
        for index in range(8):
            chunk = (expanded >> (42 - 6 * index)) & 0x3F
            row = ((chunk & 0x20) >> 4) | (chunk & 1)
            column = (chunk >> 1) & 0x0F
            substituted = (substituted << 4) | _SBOX[index][row][column]
        left, right = right, left ^ _permute(substituted, _P, 32)
    encrypted = _permute((right << 32) | left, _FP, 64)
    return encrypted.to_bytes(8, "big")


def _vnc_password_file(password: bytes) -> bytes:
    return _des_encrypt_block(password.ljust(8, b"\0"), _VNC_KEY)
