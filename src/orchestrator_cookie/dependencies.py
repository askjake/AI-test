"""Managed-environment profiles, integrity checks, and non-secret diagnostics."""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
from importlib import import_module, metadata
import os
from pathlib import Path
import re
import sys
from typing import Iterable


RUNTIME_PROFILE = "runtime"
TEST_PROFILE = "test"
ENVIRONMENT_RELATIVE = Path("state") / "environment.json"

_PROFILE_FILES = {
    RUNTIME_PROFILE: ("requirements.txt", "requirements-dashboard.txt", "constraints.txt"),
    TEST_PROFILE: ("requirements-test.txt", "requirements.txt", "requirements-dashboard.txt", "constraints.txt"),
}
_PROFILE_DISTRIBUTIONS = {
    RUNTIME_PROFILE: {
        "APScheduler": "3.11.3",
        "Jinja2": "3.1.6",
        "Pillow": "12.3.0",
        "PyJWT": "2.13.0",
        "PyYAML": "6.0.3",
        "boto3": "1.43.79",
        "cffi": "2.1.1",
        "cryptography": "50.0.1",
        "fastapi": "0.141.1",
        "pydantic": "2.13.4",
        "pydantic-settings": "2.15.0",
        "pycparser": "3.0",
        "sse-starlette": "3.4.8",
        "starlette": "1.6.0",
        "uvicorn": "0.52.4",
    },
    TEST_PROFILE: {
        "httpx2": "2.10.0",
        "pytest": "9.1.1",
    },
}
_RUNTIME_IMPORTS = (
    "apscheduler",
    "boto3",
    "fastapi",
    "jinja2",
    "PIL",
    "pydantic",
    "pydantic_settings",
    "jwt",
    "sse_starlette",
    "starlette",
    "uvicorn",
    "yaml",
)


@dataclass(frozen=True)
class EnvironmentReadiness:
    ready: bool
    profile: str
    detail: str


def managed_venv_root(repo_root: Path) -> Path:
    return repo_root / ".orchestrator-cookie" / "venv"


def managed_python(repo_root: Path) -> Path:
    root = managed_venv_root(repo_root)
    return root / ("Scripts/python.exe" if os.name == "nt" else "bin/python")


def requirements_digest(repo_root: Path, profile: str) -> str:
    try:
        filenames = _PROFILE_FILES[profile]
    except KeyError as exc:
        raise ValueError(f"unsupported environment profile: {profile}") from exc
    digest = hashlib.sha256()
    for filename in filenames:
        path = repo_root / filename
        digest.update(filename.encode("utf-8") + b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def expected_distributions(profile: str) -> dict[str, str]:
    if profile not in _PROFILE_FILES:
        raise ValueError(f"unsupported environment profile: {profile}")
    expected = dict(_PROFILE_DISTRIBUTIONS[RUNTIME_PROFILE])
    if profile == TEST_PROFILE:
        expected.update(_PROFILE_DISTRIBUTIONS[TEST_PROFILE])
    return expected


def _managed_interpreter_active(repo_root: Path) -> bool:
    root = managed_venv_root(repo_root)
    if not managed_python(repo_root).is_file():
        return False
    try:
        return Path(sys.prefix).resolve() == root.resolve()
    except OSError:
        return False


def _version_problems(expected: dict[str, str]) -> list[str]:
    problems: list[str] = []
    for distribution, wanted in expected.items():
        try:
            actual = metadata.version(distribution)
        except metadata.PackageNotFoundError:
            problems.append(f"{distribution} is missing")
            continue
        if actual != wanted:
            problems.append(f"{distribution} is {actual}; expected {wanted}")
    return problems


def _import_problems(modules: Iterable[str]) -> list[str]:
    problems: list[str] = []
    for module in modules:
        try:
            import_module(module)
        except Exception as exc:  # readiness must report broken binary/transitive imports too
            problems.append(f"{module} import failed ({type(exc).__name__})")
    return problems


def _testclient_smoke() -> str | None:
    try:
        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        app = FastAPI()

        @app.get("/__phase15_readiness__")
        def readiness() -> dict[str, bool]:
            return {"ready": True}

        with TestClient(app) as client:
            response = client.get("/__phase15_readiness__")
        if response.status_code != 200 or response.json() != {"ready": True}:
            return "TestClient request returned an unexpected response"
    except Exception as exc:
        return f"TestClient smoke failed ({type(exc).__name__}: {exc})"
    return None


def environment_readiness(repo_root: Path, profile: str) -> EnvironmentReadiness:
    if profile not in _PROFILE_FILES:
        return EnvironmentReadiness(False, profile, "unsupported environment profile")
    if not managed_python(repo_root).is_file():
        return EnvironmentReadiness(
            False,
            profile,
            "managed environment is missing; run install init"
            + (" --with-test" if profile == TEST_PROFILE else ""),
        )
    if not _managed_interpreter_active(repo_root):
        return EnvironmentReadiness(
            False,
            profile,
            "managed environment exists but this command is using another Python; use the install wrapper",
        )
    if not ((3, 11) <= sys.version_info[:2] < (3, 14)):
        return EnvironmentReadiness(False, profile, "Python 3.11, 3.12, or 3.13 is required")
    problems = _version_problems(expected_distributions(profile))
    problems.extend(_import_problems(_RUNTIME_IMPORTS))
    if profile == TEST_PROFILE:
        problem = _testclient_smoke()
        if problem:
            problems.append(problem)
    if problems:
        remediation = "install init" + (" --with-test" if profile == TEST_PROFILE else "")
        return EnvironmentReadiness(
            False,
            profile,
            "; ".join(problems) + f"; repair with {remediation}",
        )
    return EnvironmentReadiness(True, profile, f"managed {profile} environment is ready")


def safe_detail(value: str) -> str:
    """Collapse subprocess detail without ever echoing secret-shaped values."""
    value = re.sub(
        r"(?i)\b(token|secret|password|authorization)\b(\s*[=:]\s*)(\S+)",
        r"\1\2[redacted]",
        value,
    )
    return " ".join(value.split())[:1000]
