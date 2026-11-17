"""Deterministic, dependency-free Python interpreter selection policy.

The platform wrappers perform executable probes before they can import this
package. This module captures the same policy for diagnostics and deterministic
cross-platform acceptance tests.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable


SUPPORTED_MIN = (3, 11)
SUPPORTED_MAX_EXCLUSIVE = (3, 14)


@dataclass(frozen=True)
class PythonCandidate:
    label: str
    command: str
    prefix_args: tuple[str, ...] = ()


@dataclass(frozen=True)
class PythonDiscovery:
    candidate: PythonCandidate
    version: tuple[int, int, int] | None


@dataclass(frozen=True)
class PythonSelection:
    selected: PythonDiscovery | None
    discoveries: tuple[PythonDiscovery, ...]
    explicit: bool = False


def is_supported_python(version: tuple[int, ...]) -> bool:
    return SUPPORTED_MIN <= version[:2] < SUPPORTED_MAX_EXCLUSIVE


def version_text(version: tuple[int, ...] | None) -> str:
    return "unavailable" if version is None else ".".join(str(value) for value in version[:3])


def interpreter_candidates(system: str, override: str | None = None) -> tuple[PythonCandidate, ...]:
    """Return the exact candidate order implemented by the platform wrappers."""
    if override:
        return (PythonCandidate("ORCHESTRATOR_PYTHON", override),)
    versioned = tuple(
        PythonCandidate(name, name) for name in ("python3.13", "python3.12", "python3.11")
    )
    if system == "Windows":
        launchers = tuple(
            PythonCandidate(f"py -{minor}", "py", (f"-{minor}",))
            for minor in ("3.13", "3.12", "3.11")
        )
        return versioned + launchers + (
            PythonCandidate("python.exe", "python.exe"),
            PythonCandidate("python", "python"),
            PythonCandidate("python3", "python3"),
        )
    return versioned + (
        PythonCandidate("python3", "python3"),
        PythonCandidate("python", "python"),
    )


def select_interpreter(
    system: str,
    *,
    override: str | None = None,
    probe: Callable[[PythonCandidate], tuple[int, int, int] | None],
) -> PythonSelection:
    """Select the first supported candidate; an explicit override never falls back."""
    discoveries: list[PythonDiscovery] = []
    for candidate in interpreter_candidates(system, override):
        discovery = PythonDiscovery(candidate, probe(candidate))
        discoveries.append(discovery)
        if discovery.version is not None and is_supported_python(discovery.version):
            return PythonSelection(discovery, tuple(discoveries), explicit=bool(override))
        if override:
            break
    return PythonSelection(None, tuple(discoveries), explicit=bool(override))


def python_remediation(system: str) -> str:
    if system == "Darwin":
        return (
            "Install Python 3.13 through an approved package route. With Homebrew already "
            "installed: brew install python@3.13; then export "
            "ORCHESTRATOR_PYTHON=\"$(brew --prefix python@3.13)/bin/python3.13\" and rerun "
            "./install.sh init. Otherwise use the approved python.org macOS package and set "
            "ORCHESTRATOR_PYTHON to its absolute python3.13 path."
        )
    if system == "Windows":
        return (
            "Install an approved Python 3.13 package (for example: winget install -e --id "
            "Python.Python.3.13), then set ORCHESTRATOR_PYTHON to python.exe or use py -3.13 "
            "and rerun .\\install.ps1 init."
        )
    return (
        "Install Python 3.11, 3.12, or 3.13 through the approved OS package route, set "
        "ORCHESTRATOR_PYTHON to its absolute path if needed, and rerun ./install.sh init."
    )
