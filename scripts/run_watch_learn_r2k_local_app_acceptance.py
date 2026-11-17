#!/usr/bin/env python3
"""Attended, synthetic-only R2K local-app controlled-canvas acceptance.

This script uses the production adapter and runner. It never builds, pulls, or
pushes an image and the adapter forces network=none for the local-app worker.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import secrets
import stat
import subprocess

from PIL import Image

from dashboard.authoring import LocalAppTarget, ProjectDocument
from dashboard.capture_adapter import CaptureLaunchError, RunnerControlledCaptureAdapter
from dashboard.config import DashboardSettings
from watch_learn_privacy import redaction_configuration_revision


IMAGE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/:~-]{0,240}@sha256:[a-f0-9]{64}$")
PROJECT = "r2k-synthetic-local-app"
TITLE = "AI-Test-Watch-Learn-R2K-Synthetic"


def real_directory(path: Path, mode: int) -> Path:
    path.mkdir(parents=True, exist_ok=True, mode=mode)
    path.chmod(mode)
    info = path.lstat()
    if path.is_symlink() or not stat.S_ISDIR(info.st_mode) or stat.S_IMODE(info.st_mode) != mode:
        raise RuntimeError(f"directory mode contract {mode:04o} was not established")
    return path.resolve()


def write_private(path: Path, content: str, mode: int) -> None:
    path.write_text(content, encoding="utf-8")
    path.chmod(mode)
    info = path.lstat()
    if path.is_symlink() or not stat.S_ISREG(info.st_mode) or stat.S_IMODE(info.st_mode) != mode:
        raise RuntimeError(f"file mode contract {mode:04o} was not established")


def write_project(specs: Path) -> None:
    project = real_directory(specs / PROJECT, 0o755)
    manual = real_directory(project / "manual", 0o755)
    write_private(
        manual / "manual.md",
        "# Synthetic R2K local-app\n\nInert xmessage acceptance target.\n",
        0o644,
    )
    write_private(
        project / "project.yaml",
        "name: R2K synthetic local app\n"
        f"manual_dir: /app/tests_specs/{PROJECT}/manual\n"
        "target:\n"
        "  type: local-app\n"
        f"  app: /usr/bin/xmessage -title {TITLE} -center R2K-synthetic-only\n"
        f"  window: {TITLE}\n"
        f"  watch_learn_ready_window: {TITLE}\n"
        "redaction:\n"
        "  - [0, 0, 32, 32]\n",
        0o644,
    )


def verify_precontact_modes(root: Path, specs: Path, secrets_dir: Path, state: Path) -> None:
    expected = {
        root: 0o700,
        specs: 0o755,
        specs / PROJECT: 0o755,
        specs / PROJECT / "manual": 0o755,
        specs / PROJECT / "project.yaml": 0o644,
        specs / PROJECT / "manual" / "manual.md": 0o644,
        secrets_dir: 0o700,
        state: 0o700,
    }
    for path, mode in expected.items():
        info = path.lstat()
        if path.is_symlink() or stat.S_IMODE(info.st_mode) != mode:
            raise RuntimeError("synthetic fixture mode contract failed before target contact")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--accept-synthetic-target", action="store_true")
    parser.add_argument("--engine", required=True)
    parser.add_argument("--image", required=True)
    parser.add_argument("--evidence-dir", required=True, type=Path)
    arguments = parser.parse_args()
    if not arguments.accept_synthetic_target:
        raise SystemExit("explicit --accept-synthetic-target is required")
    engine = Path(arguments.engine)
    if not engine.is_absolute() or engine.name not in {"docker", "podman"} or not os.access(engine, os.X_OK):
        raise SystemExit("--engine must be an absolute installed docker or podman executable")
    if not IMAGE_RE.fullmatch(arguments.image):
        raise SystemExit("--image must be one exact digest-pinned local image")

    root = real_directory(arguments.evidence_dir, 0o700)
    specs = real_directory(root / "specs", 0o755)
    secrets_dir = real_directory(root / "secrets", 0o700)
    state = real_directory(root / "state", 0o700)
    write_project(specs)
    verify_precontact_modes(root, specs, secrets_dir, state)
    os.environ["ENGINE"] = str(engine)
    settings = DashboardSettings(
        specs_dir=str(specs),
        secrets_dir=str(secrets_dir),
        watch_learn_state_root=str(state / "demonstrations"),
        watch_learn_runner_image=arguments.image,
        watch_learn_connect_timeout_seconds=45,
        watch_learn_action_timeout_seconds=15,
    )
    project = ProjectDocument(
        dir_name=PROJECT,
        display_name="R2K synthetic local app",
        schedule="0 0 * * *",
        target=LocalAppTarget(
            app=f"/usr/bin/xmessage -title {TITLE} -center R2K-synthetic-only",
            window=TITLE,
            watch_learn_ready_window=TITLE,
        ),
        redaction=[[0, 0, 32, 32]],
        max_steps=1,
        max_seconds=60,
    )
    privacy_revision = redaction_configuration_revision(project.redaction)
    session_id = secrets.token_hex(16)
    adapter = RunnerControlledCaptureAdapter(settings, repo_root=str(Path(__file__).resolve().parents[1]))
    result: dict[str, object]
    try:
        connection = adapter.connect(session_id, project, privacy_revision)
        image = Image.open(io.BytesIO(connection.initial_evidence_png)).convert("RGB")
        image.load()
        if image.size != (1280, 720):
            raise RuntimeError("initial frame dimensions do not match 1280x720")
        if any(image.getpixel((x, y)) != (0, 0, 0) for x, y in ((0, 0), (16, 16), (31, 31))):
            raise RuntimeError("fixed pre-relay redaction was not present")
        proof = adapter.prove_session(session_id, TITLE)
        if proof.outcome != "executed" or proof.evidence_png is None:
            raise RuntimeError("exact ready-window verification failed")
        result = {
            "classification": "R2K_SYNTHETIC_LOCAL_APP_PASS",
            "session_id": session_id,
            "initial_frame_sha256": hashlib.sha256(connection.initial_evidence_png).hexdigest(),
            "frame_dimensions": [image.width, image.height],
            "fixed_redaction_verified": True,
            "ready_window_verified": True,
            "network_mode": "none",
            "target": "synthetic-xmessage",
        }
    except CaptureLaunchError as exc:
        result = {"classification": "R2K_SYNTHETIC_LOCAL_APP_FAIL", **exc.safe_fields()}
        print(json.dumps(result, sort_keys=True))
        return 1
    finally:
        adapter.disconnect(session_id)

    residual = subprocess.run(
        [str(engine), "ps", "-a", "--filter", f"name=^/phase17-{session_id}$", "--format", "{{.ID}}"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        timeout=15,
        check=False,
    )
    if residual.returncode != 0 or residual.stdout.strip():
        raise RuntimeError("capture cleanup left a residual container or could not be verified")
    result["cleanup_verified"] = True
    evidence = root / "r2k-local-app-result.json"
    write_private(evidence, json.dumps(result, indent=2, sort_keys=True) + "\n", 0o600)
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
