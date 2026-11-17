"""Verified runner-image acquisition and validation.

No source is downloaded implicitly.  Every mutating engine call is reachable
only from the explicit ``acquire-image`` command.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import json
import os
from pathlib import Path
import shutil
import subprocess
from typing import Iterable, Sequence

from .config import (
    ConfigurationError,
    IMAGE_MARKER_RELATIVE,
    ImageSource,
    ImageSourceKind,
    RuntimeConfig,
    atomic_write_json,
    runtime_root,
    sha256_file,
    validate_engine,
)


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str


@dataclass(frozen=True)
class ImageValidation:
    ready: bool
    detail: str
    image_id: str | None = None


def validate_argv(argv: Sequence[str]) -> list[str]:
    if not argv or not all(isinstance(value, str) for value in argv):
        raise ConfigurationError("subprocess argv must be a non-empty string sequence")
    for value in argv:
        if not value or any(char in value for char in ("\0", "\r", "\n")):
            raise ConfigurationError("subprocess argument is empty or contains control data")
        if len(value) > 32768:
            raise ConfigurationError("subprocess argument is unreasonably long")
    return list(argv)


def run_checked(
    argv: Sequence[str],
    *,
    cwd: Path | None = None,
    timeout: int = 30,
    env: dict[str, str] | None = None,
) -> CommandResult:
    """Run one explicit argv array.  Shell interpretation is never enabled."""
    command = validate_argv(argv)
    result = subprocess.run(
        command,
        cwd=str(cwd) if cwd else None,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
        text=True,
        timeout=timeout,
        shell=False,
    )
    return CommandResult(result.returncode, result.stdout, result.stderr)


def resolve_engine(configured: str | None = None) -> str | None:
    candidates: Iterable[str] = (configured,) if configured else ("docker", "podman")
    for candidate in candidates:
        if not candidate:
            continue
        validate_engine(candidate)
        if os.path.isabs(candidate) or os.path.sep in candidate or (os.altsep and os.altsep in candidate):
            resolved = str(Path(candidate).expanduser().resolve(strict=False))
            if not (Path(resolved).is_file() and os.access(resolved, os.X_OK)):
                continue
        else:
            resolved = shutil.which(candidate) or ""
        if not resolved:
            continue
        if Path(resolved).name.lower() not in {"docker", "docker.exe", "podman", "podman.exe"}:
            raise ConfigurationError("configured engine must resolve to Docker or Podman")
        return resolved
    return None


def engine_reachable(engine: str) -> tuple[bool, str]:
    try:
        result = run_checked([engine, "version", "--format", "{{.Server.Version}}"], timeout=12)
    except (OSError, subprocess.SubprocessError) as exc:
        return False, f"container engine command failed: {type(exc).__name__}"
    if result.returncode != 0:
        return False, "container engine is installed but its service is unreachable"
    version = result.stdout.strip().splitlines()[0] if result.stdout.strip() else "unknown"
    return True, f"container engine service is reachable (server {version})"


def _image_inspect(engine: str, image_ref: str) -> dict | None:
    try:
        result = run_checked([engine, "image", "inspect", image_ref], timeout=20)
    except (OSError, subprocess.SubprocessError):
        return None
    if result.returncode != 0:
        return None
    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError:
        return None
    if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
        return None
    return value[0]


def source_fingerprint(source: ImageSource) -> str:
    import hashlib

    payload = json.dumps(asdict(source), sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def validate_image(repo_root: Path, config: RuntimeConfig, engine: str) -> ImageValidation:
    source = config.image
    if source.kind == ImageSourceKind.UNAVAILABLE.value:
        return ImageValidation(False, "no verified runner-image source is configured")
    inspected = _image_inspect(engine, source.image_ref)
    if inspected is None:
        return ImageValidation(False, "configured runner image is not present locally")
    image_id = inspected.get("Id")
    if not isinstance(image_id, str) or not image_id:
        return ImageValidation(False, "container engine returned no runner image identity")
    entrypoint = ((inspected.get("Config") or {}).get("Entrypoint") or [])
    if entrypoint != ["/app/entrypoint.sh"]:
        return ImageValidation(False, "runner image has an unexpected entrypoint")

    if source.kind == ImageSourceKind.REFERENCE.value:
        repo_digests = inspected.get("RepoDigests") or []
        expected_digest = source.image_ref.lower().rsplit("@", 1)[-1]
        if not any(
            isinstance(value, str) and value.lower().rsplit("@", 1)[-1] == expected_digest
            for value in repo_digests
        ):
            return ImageValidation(False, "local image does not match the configured pinned digest")
        return ImageValidation(True, "verified pinned runner image is present", image_id)

    marker_path = runtime_root(repo_root) / IMAGE_MARKER_RELATIVE
    try:
        marker = json.loads(marker_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return ImageValidation(False, "runner image has no verified local acquisition record")
    if marker.get("source_fingerprint") != source_fingerprint(source):
        return ImageValidation(False, "runner image acquisition record is stale")
    if marker.get("image_id") != image_id:
        return ImageValidation(False, "runner image identity changed after verified acquisition")
    return ImageValidation(True, "verified local runner image is present", image_id)


def _verify_source_file(path_text: str | None, expected: str | None, label: str) -> Path:
    if not path_text or not expected:
        raise ConfigurationError(f"{label} path and checksum are required")
    path = Path(path_text).expanduser()
    if path.is_symlink() or not path.is_file():
        raise ConfigurationError(f"{label} must be a regular non-symlink file")
    observed = sha256_file(path)
    if observed.lower() != expected.lower():
        raise ConfigurationError(f"{label} SHA-256 verification failed")
    return path


def _prepare_vendor_context(repo_root: Path, artifact: Path) -> Path:
    build_root = runtime_root(repo_root) / "state" / "image-build"
    if build_root.exists():
        resolved = build_root.resolve()
        expected_parent = (runtime_root(repo_root) / "state").resolve()
        if resolved.parent != expected_parent or resolved.name != "image-build":
            raise ConfigurationError("refusing to replace an unexpected build directory")
        shutil.rmtree(build_root)
    ignore = shutil.ignore_patterns(
        ".git", ".orchestrator-cookie", ".venv", "__pycache__", ".pytest_cache"
    )
    shutil.copytree(repo_root, build_root, symlinks=False, ignore=ignore)
    vendor_dir = build_root / "docker" / "vendor"
    vendor_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(
        artifact,
        vendor_dir / "sublime-text_build-4200_amd64.deb",
        follow_symlinks=False,
    )
    return build_root


def acquire_image(repo_root: Path, config: RuntimeConfig) -> ImageValidation:
    """Perform the configured, explicit, provenance-checked image acquisition."""
    source = config.image
    source.validate()
    if source.kind == ImageSourceKind.UNAVAILABLE.value:
        raise ConfigurationError("configure a verified runner-image source first")
    engine = resolve_engine(config.engine)
    if not engine:
        raise ConfigurationError("Docker or Podman is not installed")
    reachable, detail = engine_reachable(engine)
    if not reachable:
        raise ConfigurationError(detail)

    if source.kind == ImageSourceKind.REFERENCE.value:
        command = [engine, "pull", "--platform", source.platform, source.image_ref]
        result = run_checked(command, timeout=900)
    elif source.kind == ImageSourceKind.ARCHIVE.value:
        archive = _verify_source_file(
            source.archive_path, source.archive_sha256, "runner image archive"
        )
        result = run_checked([engine, "load", "--input", str(archive)], timeout=900)
    else:
        if os.name == "nt" or not sys_platform_linux():
            raise ConfigurationError("vendor-artifact image builds are supported only on Linux")
        artifact = _verify_source_file(
            source.vendor_artifact_path,
            source.vendor_artifact_sha256,
            "vendor artifact",
        )
        context = _prepare_vendor_context(repo_root, artifact)
        result = run_checked(
            [
                engine,
                "build",
                "--platform",
                source.platform,
                "--tag",
                source.image_ref,
                "--file",
                str(context / "docker" / "Dockerfile"),
                str(context),
            ],
            timeout=1800,
        )
    if result.returncode != 0:
        raise ConfigurationError("runner image acquisition failed; inspect the engine output")

    inspected = _image_inspect(engine, source.image_ref)
    if inspected is None or not isinstance(inspected.get("Id"), str):
        raise ConfigurationError("acquired runner image could not be inspected")
    image_id = inspected["Id"]
    if ((inspected.get("Config") or {}).get("Entrypoint") or []) != ["/app/entrypoint.sh"]:
        raise ConfigurationError("acquired image does not satisfy the runner entrypoint contract")
    atomic_write_json(
        runtime_root(repo_root) / IMAGE_MARKER_RELATIVE,
        {
            "schema_version": 1,
            "source_fingerprint": source_fingerprint(source),
            "image_id": image_id,
        },
    )
    return validate_image(repo_root, config, engine)


def sys_platform_linux() -> bool:
    import platform

    return platform.system() == "Linux"
