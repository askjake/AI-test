"""Discovers projects and resolves their effective config (Phase 5).

Each immediate sub-directory of ``tests_specs/`` is a project; specs are collected
recursively (``<project>/**/*.md``). Any ``*.md`` left directly in the ``tests_specs/``
root forms an implicit ``default`` project.

Effective config is layered: global :mod:`orchestrator.config` defaults <- root
``tests_specs/project.yaml`` <- per-project ``tests_specs/<project>/project.yaml``. Later
layers win. Allowlists **replace** (not merge with) the lists from earlier layers. No
secrets ever live in ``project.yaml``.

NRDP-1: ``target.type: rdp-chain`` projects (written by the procedure screen) carry an
ordered ``target.chain`` that is parsed into ``Target.hops``; ``procedure`` and
``chain_hosts`` are carried on the returned config. Every other target type parses exactly
as before.
"""

from __future__ import annotations

import os
import re
from typing import Any

import yaml
from pydantic import Field, ValidationError

from .chain import ChainConfigError, ChainHop, validate_chain
from .config import settings
from .models import EffectiveConfig, Project, Target

DEFAULT_PROJECT = "default"

# The reserved directory (under a project root) holding the User's Manual. Its ``*.md`` files
# are operating documentation, NOT test specs, so it is excluded from spec collection.
MANUAL_DIR = "manual"
# The master manual page, always injected into every spec's planner when present.
MASTER_MANUAL = "manual.md"
_NON_RUNNABLE_MARKDOWN = frozenset({"README.md", "TEMPLATE.md"})

RDP_CHAIN = "rdp-chain"
MAX_CHAIN_HOPS = 8
# Same rule as dashboard/authoring.py SECRET_REFERENCE_RE + "no '..'" (_safe_secret_reference).
_SECRET_REFERENCE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
_HOP_KEYS = frozenset(ChainHop.model_fields)


class ManualError(ValueError):
    """Raised when a spec references a manual page that is missing or escapes the manual/ dir."""


class ChainProjectError(ValueError):
    """An rdp-chain project.yaml is invalid. Messages never contain secret values."""


class ChainEffectiveConfig(EffectiveConfig):
    """EffectiveConfig plus the NRDP-1 fields (additive; returned for every project).

    Kept here rather than in models.py so models.py stays untouched; readers should use
    ``getattr(config, "procedure", None)`` / ``getattr(config, "chain_hosts", [])``.
    """

    procedure: dict | None = None
    chain_hosts: list[str] = Field(default_factory=list)


# project.yaml keys we recognize; anything else is ignored.
_RECOGNIZED_KEYS = {
    "name",
    "ssh_host_allowlist",
    "rdp_host_allowlist",
    "vnc_host_allowlist",
    "max_steps",
    "max_seconds",
    "max_tokens",
    "max_total_tokens",
    "step_max_tokens",
    "keep_last_n_screenshots",
    "action_delay_seconds",
    "max_planner_steps",
    "step_max_steps",
    "target",
    "schedule",
    "enabled",
    "redaction",
    "manual_dir",
    "chain_hosts",
    "procedure",
}


def _read_yaml(path: str) -> dict[str, Any]:
    """Read a ``project.yaml`` into a dict; missing file -> empty dict."""
    if not os.path.isfile(path):
        return {}
    with open(path, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh) or {}
    if not isinstance(data, dict):
        raise ValueError(f"{path!r} must contain a YAML mapping, got {type(data).__name__}")
    return {k: v for k, v in data.items() if k in _RECOGNIZED_KEYS}


def _global_layer() -> dict[str, Any]:
    """The global config.py defaults, expressed as a project.yaml-style layer."""
    return {
        "ssh_host_allowlist": list(settings.ssh_host_allowlist),
        "rdp_host_allowlist": list(settings.rdp_host_allowlist),
        "vnc_host_allowlist": list(settings.vnc_host_allowlist),
        "max_steps": settings.max_steps,
        "max_seconds": settings.max_seconds,
        "max_tokens": settings.max_tokens,
        "max_total_tokens": settings.max_total_tokens,
        "step_max_tokens": settings.step_max_tokens,
        "keep_last_n_screenshots": settings.keep_last_n_screenshots,
        "action_delay_seconds": settings.action_delay_seconds,
        "max_planner_steps": settings.max_planner_steps,
        "step_max_steps": settings.step_max_steps,
        "target": {"type": "local-app"},
        "schedule": settings.default_cron,
    }


def _merge(*layers: dict[str, Any]) -> dict[str, Any]:
    """Merge layers left-to-right; later non-None values override earlier ones."""
    merged: dict[str, Any] = {}
    for layer in layers:
        for key, value in layer.items():
            if value is not None:
                merged[key] = value
    return merged


def _safe_secret_reference(value: Any) -> bool:
    return isinstance(value, str) and bool(_SECRET_REFERENCE_RE.fullmatch(value)) and ".." not in value


def build_chain_hops(raw_chain: Any, rdp_host_allowlist: list[str]) -> list[ChainHop]:
    """Parse and validate ``target.chain`` for an ``rdp-chain`` project.

    Rules: a non-empty list of mappings, at most 8; unknown hop keys refused; every
    ``password_file`` is a safe reference filename; :func:`chain.validate_chain` passes
    (contiguous orders, hop-1 certificate, no cert on hop>=2); and ``rdp_host_allowlist``
    is EXACTLY ``[hop1.host]`` so the runner can never connect to hop 2.. directly.
    """
    if not isinstance(raw_chain, list) or not raw_chain:
        raise ChainProjectError("target.chain must be a non-empty list of connections")
    if len(raw_chain) > MAX_CHAIN_HOPS:
        raise ChainProjectError(f"target.chain supports at most {MAX_CHAIN_HOPS} hops")
    hops: list[ChainHop] = []
    for index, raw in enumerate(raw_chain, start=1):
        if not isinstance(raw, dict):
            raise ChainProjectError(f"target.chain[{index}] must be a mapping")
        unknown = sorted(str(k) for k in raw if k not in _HOP_KEYS)
        if unknown:
            raise ChainProjectError(f"target.chain[{index}] has unsupported keys: {', '.join(unknown)}")
        if not _safe_secret_reference(raw.get("password_file")):
            raise ChainProjectError(
                f"target.chain[{index}].password_file must be a safe secret reference filename, not a path"
            )
        try:
            hops.append(ChainHop(**raw))
        except ValidationError as exc:
            fields = sorted({".".join(str(p) for p in err.get("loc", ())) for err in exc.errors()})
            raise ChainProjectError(
                f"target.chain[{index}] has invalid fields: {', '.join(fields)}"
            ) from None
    try:
        validate_chain(hops)
    except ChainConfigError as exc:
        raise ChainProjectError(str(exc)) from None
    first = hops[0].host
    inner = [h.host for h in hops[1:]]
    leaked = [h for h in rdp_host_allowlist if h in inner and h != first]
    if leaked:
        raise ChainProjectError(
            "rdp_host_allowlist must not contain hosts of hop 2 or later (they are reached only "
            "from inside the previous desktop): " + ", ".join(leaked)
        )
    if list(rdp_host_allowlist) != [first]:
        raise ChainProjectError(
            f"rdp_host_allowlist for an rdp-chain project must be exactly [{first!r}] (hop 1 only)"
        )
    return hops


_OUTER_HOST_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,252}$")


def rdp_chain_outer_hop(target: Any) -> ChainHop:
    """Return the validated first hop of an ``rdp-chain`` target.

    Hop 1 is the ONLY endpoint the runner may reach directly.  Egress policy and the authenticated
    target relay both derive the OUTER transport from this one function so they cannot disagree.
    Hop 2.. are opened from inside the hop-1 desktop and never appear here.  The hop's host/port are
    the logical destination: the relay socket address is separate and never replaces the reviewed
    certificate name/fingerprint.  Messages never contain secret values.
    """
    if getattr(target, "type", None) != RDP_CHAIN:
        raise ChainProjectError("target is not an rdp-chain")
    hops = list(getattr(target, "hops", None) or [])
    if not hops:
        raise ChainProjectError("rdp-chain has no connections; hop 1 host and port are required")
    first = hops[0]
    if first.order != 1:
        raise ChainProjectError("rdp-chain hop 1 is missing (the first connection must have order 1)")
    host = first.host if isinstance(first.host, str) else ""
    if host != host.strip() or not _OUTER_HOST_RE.fullmatch(host):
        raise ChainProjectError("rdp-chain hop 1 host is missing or malformed")
    port = first.port
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise ChainProjectError("rdp-chain hop 1 port must be between 1 and 65535")
    return first


def explain_chain_project_error(project_dir: str, specs_root: str) -> str | None:
    """A specific message when ``project_dir`` is an rdp-chain project whose transport is invalid.

    ``discover_projects`` skips broken projects, which would otherwise surface as the generic
    "exact project could not be resolved".  Returns None for anything that is not that case.
    """
    try:
        raw = _read_yaml(os.path.join(project_dir, "project.yaml"))
    except Exception:
        return None
    target = raw.get("target") if isinstance(raw, dict) else None
    if not isinstance(target, dict) or target.get("type") != RDP_CHAIN:
        return None
    try:
        load_project_config(project_dir, specs_root=specs_root)
    except ChainProjectError as exc:
        return f"rdp-chain project transport is invalid: {exc}"
    except Exception:
        return None
    return None


def load_project_config(project_dir: str, *, specs_root: str | None = None) -> EffectiveConfig:
    """Resolve the effective config for ``project_dir``.

    Layers: global config.py defaults <- root ``tests_specs/project.yaml`` <- the project's
    own ``project.yaml``. ``specs_root`` defaults to :data:`settings.tests_specs_dir` (the
    location of the optional root ``project.yaml``).
    """
    root = specs_root if specs_root is not None else settings.tests_specs_dir
    root_yaml = _read_yaml(os.path.join(root, "project.yaml"))
    project_yaml = _read_yaml(os.path.join(project_dir, "project.yaml"))
    merged = _merge(_global_layer(), root_yaml, project_yaml)

    raw_target = dict(merged.get("target") or {})
    target_type = str(raw_target.pop("type", None) or "local-app")
    if target_type == RDP_CHAIN:
        extra = sorted(str(k) for k in raw_target if k != "chain")
        if extra:
            raise ChainProjectError(f"rdp-chain target has unsupported keys: {', '.join(extra)}")
        hops = build_chain_hops(raw_target.get("chain"), list(merged.get("rdp_host_allowlist") or []))
        target = Target(type=RDP_CHAIN, params={}, hops=hops)
    else:
        raw_route = raw_target.pop("route", None)
        params = {k: str(v) for k, v in raw_target.items()}
        if raw_route is not None:
            if not isinstance(raw_route, dict):
                raise ValueError("target.route must be a typed YAML mapping")
            route_type = str(raw_route.get("type") or "direct")
            params["route_type"] = route_type
            if route_type == "ssh-jump":
                for source, destination in (
                    ("host", "jump_host"),
                    ("user", "jump_user"),
                    ("port", "jump_port"),
                    ("known_hosts_file", "jump_known_hosts_file"),
                ):
                    value = raw_route.get(source)
                    if value is not None:
                        params[destination] = str(value)
            elif route_type != "direct":
                raise ValueError(f"unsupported target route type: {route_type!r}")
        target = Target(type=target_type, params=params)

    procedure = merged.get("procedure")
    if procedure is not None and not isinstance(procedure, dict):
        raise ValueError("procedure must be a mapping")
    chain_hosts = merged.get("chain_hosts") or []
    if not isinstance(chain_hosts, list):
        raise ValueError("chain_hosts must be a list")
    chain_hosts = [str(h) for h in chain_hosts]
    if target_type == RDP_CHAIN and chain_hosts and chain_hosts != [h.host for h in target.hops]:
        raise ChainProjectError("chain_hosts must list the hop hosts in order")

    # ``manual_dir`` is a required per-project field, resolved relative to the cwd (absolute paths
    # allowed). The implicit ``default`` project (a root ``project.yaml`` covering loose specs) has
    # no owning sub-directory and is exempt — detected by ``project_dir == root``.
    manual_dir = _resolve_manual_dir(merged.get("manual_dir"), project_dir, root)

    return ChainEffectiveConfig(
        max_steps=int(merged["max_steps"]),
        max_seconds=int(merged["max_seconds"]),
        max_tokens=int(merged["max_tokens"]),
        max_total_tokens=int(merged["max_total_tokens"]),
        step_max_tokens=int(merged["step_max_tokens"]),
        keep_last_n_screenshots=int(merged["keep_last_n_screenshots"]),
        action_delay_seconds=float(merged["action_delay_seconds"]),
        max_planner_steps=int(merged["max_planner_steps"]),
        step_max_steps=int(merged["step_max_steps"]),
        ssh_host_allowlist=list(merged.get("ssh_host_allowlist") or []),
        rdp_host_allowlist=list(merged.get("rdp_host_allowlist") or []),
        vnc_host_allowlist=list(merged.get("vnc_host_allowlist") or []),
        target=target,
        schedule=merged.get("schedule"),
        redaction=list(merged.get("redaction") or []),
        manual_dir=manual_dir,
        procedure=procedure,
        chain_hosts=chain_hosts,
    )


def _resolve_manual_dir(raw: Any, project_dir: str, root: str) -> str | None:
    """Resolve and validate a project's required ``manual_dir``.

    ``manual_dir`` is required for every real (sub-directory) project and is resolved relative to
    the current working directory (absolute paths pass through). The implicit ``default`` project
    — the root ``project.yaml`` layer that covers loose ``*.md`` in the specs root — has no owning
    sub-directory, so the requirement is skipped when ``project_dir`` is the specs ``root``.

    Raises :class:`ValueError` if a real project omits ``manual_dir`` or points it at a directory
    that has no master ``manual.md`` — fail fast at config load rather than let a run start
    without the operating manual it depends on.
    """
    if os.path.normpath(project_dir) == os.path.normpath(root):
        return None
    if not raw or not str(raw).strip():
        raise ValueError(
            f"project {project_dir!r} is missing the required 'manual_dir' in project.yaml"
        )
    raw_path = str(raw).strip()
    portable = raw_path.replace("\\", "/")
    portable_parts = portable.split("/")
    if raw_path == "./manual":
        manual_dir = os.path.abspath(os.path.join(project_dir, MANUAL_DIR))
    elif (
        portable_parts[0] == "tests_manuals"
        and all(part not in {"", ".", ".."} for part in portable_parts)
    ):
        manual_dir = os.path.abspath(os.path.join(os.path.dirname(root), *portable_parts))
    else:
        manual_dir = os.path.abspath(raw_path)
    master = os.path.join(manual_dir, MASTER_MANUAL)
    if not os.path.isfile(master):
        raise ValueError(
            f"project {project_dir!r} manual_dir {manual_dir!r} has no master manual {MASTER_MANUAL!r}"
        )
    return manual_dir


def load_manual(manual_dir: str | None, referenced: list[str] | None = None) -> str | None:
    """Resolve the project's manual text for a spec: master ``manual.md`` + referenced pages.

    Reads ``<manual_dir>/manual.md`` (always, when present) then each name in ``referenced`` from
    the same directory, in listed order, joined with a labeled separator per topic page. Returns
    ``None`` when ``manual_dir`` is unset or is not a directory (the single-spec / no-project
    path, which has no owning project and therefore no manual).

    Raises :class:`ManualError` if a referenced name escapes the manual dir (contains a path
    separator or ``..``) or points at a file that does not exist — fail fast rather than let the
    planner silently lose navigation knowledge.
    """
    if not manual_dir or not os.path.isdir(manual_dir):
        return None

    parts: list[str] = []

    master_path = os.path.join(manual_dir, MASTER_MANUAL)
    if os.path.isfile(master_path):
        with open(master_path, "r", encoding="utf-8") as fh:
            master = fh.read().strip()
        if master:
            parts.append(master)

    for name in referenced or []:
        if os.sep in name or "/" in name or ".." in name.split(os.sep):
            raise ManualError(
                f"manual reference {name!r} must be a bare filename inside the manual/ dir"
            )
        page_path = os.path.join(manual_dir, name)
        if not os.path.isfile(page_path):
            raise ManualError(f"referenced manual page not found: {name!r} (in {manual_dir!r})")
        with open(page_path, "r", encoding="utf-8") as fh:
            body = fh.read().strip()
        parts.append(f"## Manual page: {name}\n{body}")

    if not parts:
        return None
    return "\n\n".join(parts)


def load_manual_page(manual_dir: str, name: str) -> str:
    """Load one topic page from ``manual_dir`` on demand, by the path used in the manual's TOC.

    ``name`` is a path relative to ``manual_dir`` exactly as it appears in ``manual.md``'s
    table-of-contents links (subdirectories allowed, e.g. ``services/100-create-service.md``).
    Resolved with :func:`os.path.realpath` and required to stay inside ``manual_dir`` so a
    ``..`` or absolute path cannot read files outside the manual tree. Returns the file text
    (stripped). Raises :class:`ManualError` if the path escapes the dir or the file is missing.
    """
    root = os.path.realpath(manual_dir)
    full = os.path.realpath(os.path.join(root, name))
    if full != root and not full.startswith(root + os.sep):
        raise ManualError(f"manual page {name!r} escapes the manual/ dir")
    if not os.path.isfile(full):
        raise ManualError(f"manual page not found: {name!r} (in {manual_dir!r})")
    with open(full, "r", encoding="utf-8") as fh:
        return fh.read().strip()


def _collect_specs(directory: str, *, recursive: bool) -> list[str]:
    """Return sorted ``*.md`` paths in ``directory`` (recursively when asked)."""
    found: list[str] = []
    if recursive:
        for dirpath, dirs, files in os.walk(directory):
            dirs[:] = [d for d in dirs if d != MANUAL_DIR]  # never descend into manual/
            for name in files:
                if name.endswith(".md") and name not in _NON_RUNNABLE_MARKDOWN:
                    found.append(os.path.join(dirpath, name))
    else:
        for name in os.listdir(directory):
            path = os.path.join(directory, name)
            if (
                name.endswith(".md")
                and name not in _NON_RUNNABLE_MARKDOWN
                and os.path.isfile(path)
            ):
                found.append(path)
    return sorted(found)


def _project_name(project_dir: str, config: EffectiveConfig) -> str:
    # project.yaml `name` wins; otherwise the directory basename.
    root_yaml = _read_yaml(os.path.join(project_dir, "project.yaml"))
    return str(root_yaml.get("name") or os.path.basename(os.path.normpath(project_dir)))


def project_slug(project: Project) -> str:
    """Return the stable filesystem identity used by dashboard and reports."""
    if project.name == DEFAULT_PROJECT and project.config.manual_dir is None:
        return DEFAULT_PROJECT
    return os.path.basename(os.path.normpath(project.dir))


def discover_projects(specs_root: str | None = None, *, include_disabled: bool = False) -> list[Project]:
    """Discover every enabled project under ``specs_root``.

    Each immediate sub-directory is a project (specs collected recursively). Any ``*.md``
    directly under the root forms the implicit ``default`` project. Projects whose
    ``project.yaml`` sets ``enabled: false`` are skipped.
    """
    root = specs_root if specs_root is not None else settings.tests_specs_dir
    projects: list[Project] = []

    if not os.path.isdir(root):
        return projects

    # Implicit default project from any *.md directly in the root.
    root_specs = _collect_specs(root, recursive=False)
    if root_specs:
        config = load_project_config(root, specs_root=root)
        projects.append(
            Project(
                name=DEFAULT_PROJECT,
                dir=root,
                config=config,
                specs=root_specs,
                enabled=True,
            )
        )

    for entry in sorted(os.listdir(root)):
        project_dir = os.path.join(root, entry)
        if not os.path.isdir(project_dir):
            continue
        # Some source bundles historically contained a recursively duplicated
        # tests_specs/tests_specs tree. It is packaging residue, not a project.
        if entry == os.path.basename(os.path.normpath(root)):
            continue
        try:
            enabled = _read_yaml(os.path.join(project_dir, "project.yaml")).get("enabled", True)
        except (PermissionError, OSError) as _perm_exc:
            import logging as _log
            _log.getLogger(__name__).warning(
                "discover_projects: skipping %s — cannot read project.yaml: %s",
                project_dir, _perm_exc,
            )
            continue
        if not enabled and not include_disabled:
            continue
        try:
            config = load_project_config(project_dir, specs_root=root)
            projects.append(
                Project(
                    name=_project_name(project_dir, config),
                    dir=project_dir,
                    config=config,
                    specs=_collect_specs(project_dir, recursive=True),
                    enabled=bool(enabled),
                )
            )
        except Exception as _proj_err:
            import logging as _log
            _log.getLogger(__name__).warning(
                "discover_projects: skipping %r — %s", project_dir, _proj_err
            )
            continue

    return projects


def find_project(name: str, specs_root: str | None = None, *, include_disabled: bool = False) -> Project | None:
    """Return an enabled project by stable slug, with display-name compatibility."""
    projects = discover_projects(specs_root, include_disabled=True) if include_disabled else discover_projects(specs_root)
    for project in projects:
        if project_slug(project) == name:
            return project
    for project in projects:
        if project.name == name:
            return project
    return None


def project_for_spec(spec_path: str, specs_root: str | None = None) -> Project | None:
    """Return the project that owns ``spec_path`` (the one whose specs include it)."""
    target = os.path.abspath(spec_path)
    for project in discover_projects(specs_root):
        if any(os.path.abspath(s) == target for s in project.specs):
            return project
    return None
