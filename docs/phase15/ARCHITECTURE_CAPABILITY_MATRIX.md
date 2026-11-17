# Phase 15 architecture and capability matrix

Phase 15 adds one standard-library Python control plane beneath thin POSIX and
PowerShell wrappers. It owns per-clone initialization, typed configuration,
token storage, diagnostics, dashboard lifecycle, update, uninstall, verified
runner-image acquisition, and the cross-platform container launch path.

The existing dashboard, wizard, typed authoring, guarded refinement, target
preflight, reports, screenshots, live display, orchestrator, and Linux
host-application bridge remain the functional components. Dashboard-triggered
runs now enter through `src/orchestrator/runtime_trigger.py` and
`src/orchestrator/runtime_runner.py`, using explicit argument arrays.

Phase 15.1 adds two managed dependency profiles and separates the configured
`preferred_port` from the authenticated actual running port. The runtime profile
contains dashboard/orchestrator dependencies only; the test profile adds pytest
and HTTPX2 plus a real TestClient request smoke. Doctor reports both layers
without mutating either.

## Readiness layers

| Layer | Meaning | What it does not prove |
| --- | --- | --- |
| Dashboard access | FastAPI dependencies, private runtime, safe bind, and authentication are ready. | Runner image, target reachability, or model access. |
| Runner readiness | Docker/Podman is reachable and an acquired image matches its configured provenance. | That a private target is reachable from the container. |
| Target reachability | An explicit, bounded, revision-bound wizard preflight succeeded against an allowlisted target. | AWS or Bedrock authorization. |
| AWS/model readiness | An owner-only current credential file, region, profile, and model/profile ID are configured. | Doctor does not call AWS or a model; an authorized action is still required to validate service access. |
| Linux host-app capability | Linux, verified runner, explicit enablement, existing allow roots, and bridge policy all pass. | macOS or Windows native application control. |

## Host capability matrix

| Capability | Linux | macOS | Windows |
| --- | --- | --- | --- |
| Dashboard, wizard, authoring, reports, screenshots, live display | Supported | Supported | Supported |
| Background start/stop/status/logs | Supported | Supported | Supported |
| Docker/Podman runner | Docker or Podman | Docker Desktop | Docker Desktop |
| Container-local Linux GUI target | Supported with verified runner image | Supported in Docker Desktop Linux VM | Supported in Docker Desktop Linux VM |
| Remote SSH terminal | Supported when allowlisted/reachable | Supported when allowlisted/reachable | Supported when allowlisted/reachable |
| Remote RDP | Supported when allowlisted/reachable | Supported when allowlisted/reachable | Supported when allowlisted/reachable |
| Remote VNC | Supported when allowlisted/reachable | Supported when allowlisted/reachable | Supported when allowlisted/reachable |
| Native host application | Linux only, disabled by default, allowlisted | Unavailable | Unavailable |
| Native macOS/Windows desktop automation | Unavailable | Unavailable | Unavailable |

Docker Desktop remote-target use requires host networking support to be enabled
in Docker Desktop and the target route to be reachable from the Docker Linux VM.
The installer does not change that setting and never claims target reachability
from engine readiness alone.

## Security boundaries

- The preferred listener is `127.0.0.1:8080`. If that port is occupied, start
  scans upward on the same bind host and persists the actual port only after
  authenticated identity health succeeds.
- A non-loopback bind requires explicit LAN configuration and valid viewer and
  operator tokens. Application construction fails without authentication.
- Tokens exist only in the owner-protected per-clone configuration directory;
  they are passed through the dashboard environment, never argv, URLs, logs, or
  generated project content.
- Runner invocations use argv arrays with no shell interpretation. Project,
  image, host, path, port, checksum, and engine inputs are validated.
- The runner remains read-only, drops all capabilities, adds only the existing
  bootstrap/egress capabilities, uses `no-new-privileges`, and mounts only the
  isolated workspace, reports, secrets source, and configured AWS-file parent.
- AWS credential values are never read or printed by the manager. The
  credential parent is mounted read-only so atomic host refreshes remain visible;
  the existing private in-container synchronizer copies the current file to
  tmpfs before the workload permanently drops root.
- RDP retains `/gdi:sw`, `/network:auto`, and `/timeout:30000`. `/gfx-` and
  `/cert:ignore` are removed from project input and are not present in the base
  command.
- Host-app remains Linux-only, explicitly enabled, path-allowlisted, and uses no
  privileged container, `nsenter`, host PID/IPC namespace, or general shell.
