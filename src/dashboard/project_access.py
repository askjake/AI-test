"""Filesystem modes required by the non-root runner container.

Dashboard write operations can inherit a restrictive process umask. The
runner image intentionally executes as uid 10001, so project YAML/Markdown
must be world-readable and their directories world-traversable. Report
project directories created by the dashboard must also be writable by that
container uid.
"""
from __future__ import annotations

import os
import re
import stat


SPEC_DIR_MODE = 0o755
SPEC_FILE_MODE = 0o644
REPORT_PROJECT_MODE = 0o755      # CP45-G: dashboard-owned, never shared; the runner gets only the paths precreate_run_dirs hands over
RUN_DIR_MODE = 0o755
RUNS_SUBDIR = ".nrdp-runs"
_TRIGGER_RE = re.compile(r"^trig_[A-Za-z0-9_-]+$")
_RUN_TS_RE = re.compile(r"^\d{8}T\d{6}Z$")
_PROJECT_SLUG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]*$")
_READABLE_SPEC_SUFFIXES = (".yaml", ".yml", ".md")


class ProjectAccessError(RuntimeError):
    """Raised when a project mount cannot be made usable by the runner."""


def _chmod_regular(path: str, mode: int) -> None:
    if os.path.islink(path):
        return
    try:
        os.chmod(path, mode)
    except OSError as exc:
        raise ProjectAccessError(f"cannot set mode {mode:04o} on {path}: {exc}") from exc


def ensure_spec_directory(path: str) -> None:
    """Create a spec directory and make it traversable by the container."""
    try:
        os.makedirs(path, mode=SPEC_DIR_MODE, exist_ok=True)
    except OSError as exc:
        raise ProjectAccessError(f"cannot create spec directory {path}: {exc}") from exc
    _chmod_regular(path, SPEC_DIR_MODE)


def ensure_spec_file(path: str) -> None:
    """Make one dashboard-managed YAML/Markdown file container-readable."""
    _chmod_regular(path, SPEC_FILE_MODE)


def ensure_manual_directory(path: str) -> None:
    """Create a dashboard-managed manual directory with runner-readable modes.

    Manuals are mounted read-only into the runner just like specs, but they may
    live outside ``tests_specs``.  Keeping this narrow helper separate avoids
    broadening ``normalize_spec_project`` to unrelated host directories.
    """
    ensure_spec_directory(path)


def ensure_manual_file(path: str) -> None:
    """Make one dashboard-managed manual Markdown file runner-readable."""
    ensure_spec_file(path)


def normalize_spec_project(project_dir: str) -> None:
    """Normalize only directories plus YAML/Markdown files in one project.

    Symlinks and unrelated files are deliberately left untouched.
    """
    project_root = os.path.realpath(project_dir)
    if not os.path.isdir(project_root):
        raise ProjectAccessError(f"spec project directory does not exist: {project_dir}")
    for current, dirs, files in os.walk(project_root, followlinks=False):
        _chmod_regular(current, SPEC_DIR_MODE)
        dirs[:] = [name for name in dirs if not os.path.islink(os.path.join(current, name))]
        for name in files:
            if name == "project.yaml" or name.endswith((".yaml", ".yml", ".md")):
                _chmod_regular(os.path.join(current, name), SPEC_FILE_MODE)


def _has_acl(path: str) -> bool:
    try:
        return any(name.startswith("system.posix_acl") for name in os.listxattr(path, follow_symlinks=False))
    except (OSError, AttributeError):
        return False


def layout_problems(path: str, *, owner_uid: int | None = None) -> list:
    """CP45-N, read-only: why an EXISTING directory cannot serve the 0755 report contract ([] = compatible)."""
    owner_uid = os.geteuid() if owner_uid is None else owner_uid
    try:
        info = os.lstat(path)
    except OSError as exc:
        return [f"cannot be inspected ({exc.strerror or exc})"]
    if stat.S_ISLNK(info.st_mode):
        return ["is a symbolic link"]
    if not stat.S_ISDIR(info.st_mode):
        return ["is not a directory"]
    problems = []
    mode = stat.S_IMODE(info.st_mode)
    if info.st_uid != owner_uid:
        problems.append(f"is owned by uid {info.st_uid}, not the dashboard user (uid {owner_uid})")
    if mode & 0o022:
        problems.append(f"is group- or world-writable (mode {mode:04o})")
    if mode & 0o7000:
        problems.append(f"has setuid/setgid/sticky bits (mode {mode:04o})")
    if not mode & 0o001:
        problems.append(f"is not traversable by other users (mode {mode:04o}); the runner uid could not reach it")
    if _has_acl(path):
        problems.append("carries a POSIX ACL")
    return problems


def _incompatible(role: str, path: str, problems: list) -> ProjectAccessError:
    return ProjectAccessError(
        f"existing {role} {path} {'; '.join(problems)}. This layout is incompatible with the 0755 report permission contract; nothing was changed. "
        "Existing report layouts are never modified automatically - a separately reviewed migration plan is required."
    )


def ensure_report_project(reports_root: str, project: str) -> str:
    """Create the dashboard-owned report project directory when it is MISSING (new data only: 0755, explicit chmod).

    CP45-N: an EXISTING directory is returned untouched - never chmod'ed or chown'ed.  ``precreate_run_dirs`` refuses an incompatible one.
    """
    path = os.path.join(os.path.abspath(reports_root), project)
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        try:
            os.mkdir(path, REPORT_PROJECT_MODE)
            created = True
        except FileExistsError:
            created = False
        if created:
            os.chmod(path, REPORT_PROJECT_MODE)
        status = os.stat(path, follow_symlinks=False)
    except OSError as exc:
        raise ProjectAccessError(f"cannot prepare report directory {path}: {exc}") from exc
    if not stat.S_ISDIR(status.st_mode):
        raise ProjectAccessError(f"report project path is not a directory: {path}")
    return path


def _own_dir(path: str, role: str = "report directory") -> None:
    """Create ``path`` (0755, explicit chmod - never umask alone) or accept an existing COMPATIBLE dashboard-owned directory.  Never modifies existing data."""
    try:
        os.mkdir(path, RUN_DIR_MODE)
    except FileExistsError:
        problems = layout_problems(path)
        if problems:
            raise _incompatible(role, path, problems) from None
        return
    except OSError as exc:
        raise ProjectAccessError(f"cannot create {path}: {exc}") from exc
    os.chmod(path, RUN_DIR_MODE)     # the directory is NEW and dashboard-owned


def precreate_run_dirs(reports_root: str, project: str, trigger_id: str, run_ts: str) -> dict:
    """CP45-G: precreate, as the dashboard user, the exact paths the runner will own for this run.

    Everything stays dashboard-owned 0755 here; docker/entrypoint.sh hands ONLY run folder, report folder and project index to the runner uid
    (orchestrator.report_handoff) before the privilege drop.  ``control/`` stays dashboard-owned.  Nothing is world- or group-writable.
    """
    if not _PROJECT_SLUG_RE.fullmatch(project or "") or not _TRIGGER_RE.fullmatch(trigger_id or "") or not _RUN_TS_RE.fullmatch(run_ts or ""):
        raise ProjectAccessError("invalid project, trigger or run timestamp")
    for _role, _path in (("reports root", os.path.abspath(reports_root)),):
        _problems = layout_problems(_path)
        if _problems:
            raise _incompatible(_role, _path, _problems)
    project_dir = ensure_report_project(reports_root, project)
    _problems = layout_problems(project_dir)
    if _problems:
        raise _incompatible("report project directory", project_dir, _problems)
    runs = os.path.join(project_dir, RUNS_SUBDIR)
    run_folder = os.path.join(runs, trigger_id)
    control = os.path.join(run_folder, "control")
    report_folder = os.path.join(project_dir, run_ts)
    for role, path in ((".nrdp-runs directory", runs), ("trigger run folder", run_folder), ("control directory", control), ("report folder", report_folder)):
        _own_dir(path, role)
    index = os.path.join(project_dir, "index.html")
    try:
        fd = os.open(index, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o644)
    except FileExistsError:
        info = os.lstat(index)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ProjectAccessError(f"{index} is not a plain single-link file") from None
    except OSError as exc:
        raise ProjectAccessError(f"cannot create {index}: {exc}") from exc
    else:
        try:
            os.fchmod(fd, 0o644)
        finally:
            os.close(fd)
    return {"project_dir": project_dir, "run_folder": run_folder, "control": control, "report_folder": report_folder, "index": index}


def prepare_project_mounts(specs_root: str, reports_root: str, project: str) -> None:
    """Prepare a project immediately before a dashboard-triggered container run."""
    specs_root = os.path.abspath(specs_root)
    project_dir = os.path.realpath(os.path.join(specs_root, project))
    if os.path.commonpath((specs_root, project_dir)) != specs_root:
        raise ProjectAccessError("project path escapes the specs root")
    normalize_spec_project(project_dir)
    ensure_report_project(reports_root, project)


def _open_directory_no_follow(path: str, *, dir_fd: int | None = None) -> int:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, dir_fd=dir_fd)
    if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
        os.close(descriptor)
        raise ProjectAccessError("project mount component is not a directory")
    return descriptor


def _same_file(first: os.stat_result, second: os.stat_result) -> bool:
    return first.st_dev == second.st_dev and first.st_ino == second.st_ino


def _prepare_selected_tree(directory_fd: int) -> None:
    """Normalize one already-open project tree without following symlinks."""
    os.fchmod(directory_fd, SPEC_DIR_MODE)
    with os.scandir(directory_fd) as entries:
        for entry in entries:
            before = entry.stat(follow_symlinks=False)
            if stat.S_ISLNK(before.st_mode):
                continue
            if stat.S_ISDIR(before.st_mode):
                child_fd = _open_directory_no_follow(entry.name, dir_fd=directory_fd)
                try:
                    if not _same_file(before, os.fstat(child_fd)):
                        raise ProjectAccessError("project directory changed during preparation")
                    _prepare_selected_tree(child_fd)
                finally:
                    os.close(child_fd)
                continue
            if not stat.S_ISREG(before.st_mode) or not entry.name.endswith(
                _READABLE_SPEC_SUFFIXES
            ):
                continue
            flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
            file_fd = os.open(entry.name, flags, dir_fd=directory_fd)
            try:
                after = os.fstat(file_fd)
                if not stat.S_ISREG(after.st_mode) or not _same_file(before, after):
                    raise ProjectAccessError("project file changed during preparation")
                os.fchmod(file_fd, SPEC_FILE_MODE)
            finally:
                os.close(file_fd)


def prepare_watch_learn_project_mount(specs_root: str, project: str) -> None:
    """Prepare only the selected read-only Watch & Learn project mount.

    The permanently non-root capture worker needs traversal of the mounted
    specs root and selected project directories, plus read access to project
    YAML and Markdown.  This boundary deliberately does not touch reports,
    runtime state, secrets, other projects, arbitrary files, or symlink targets.
    """
    if not _PROJECT_SLUG_RE.fullmatch(project):
        raise ProjectAccessError("selected project is not an immediate safe child")
    root = os.path.abspath(specs_root)
    try:
        root_before = os.lstat(root)
        if stat.S_ISLNK(root_before.st_mode) or not stat.S_ISDIR(root_before.st_mode):
            raise ProjectAccessError("configured specs root is not a real directory")
        root_fd = _open_directory_no_follow(root)
    except (OSError, ProjectAccessError) as exc:
        if isinstance(exc, ProjectAccessError):
            raise
        raise ProjectAccessError("configured specs root is unavailable") from exc
    try:
        if not _same_file(root_before, os.fstat(root_fd)):
            raise ProjectAccessError("configured specs root changed during preparation")
        project_before = os.stat(project, dir_fd=root_fd, follow_symlinks=False)
        if stat.S_ISLNK(project_before.st_mode) or not stat.S_ISDIR(project_before.st_mode):
            raise ProjectAccessError("selected project is not a real directory")
        project_fd = _open_directory_no_follow(project, dir_fd=root_fd)
        try:
            if not _same_file(project_before, os.fstat(project_fd)):
                raise ProjectAccessError("selected project changed during preparation")
            os.fchmod(root_fd, SPEC_DIR_MODE)
            _prepare_selected_tree(project_fd)
        finally:
            os.close(project_fd)
    except OSError as exc:
        raise ProjectAccessError("selected project mount is not safely readable") from exc
    finally:
        os.close(root_fd)
