# Phase 15.1 stabilization change report

## Outcome

Phase 15.1 makes managed dependency repair reproducible, separates production
runtime from full-test readiness, and makes the configured dashboard port a
preferred starting point rather than a single hard requirement. It also ships
as a portable transactional overlay whose default preflight cannot install or
mutate source.

## Exact source changes

| File | Change and rationale |
| --- | --- |
| `constraints.txt` | Adds the tested cross-platform version constraint set. |
| `requirements.txt` | Pins core runtime dependencies and removes pytest. |
| `requirements-dashboard.txt` | Pins the tested FastAPI, Starlette, Uvicorn, and SSE family. |
| `requirements-test.txt` | Adds the developer/full-test profile, including the direct `httpx2` TestClient dependency. |
| `install.sh`, `install.ps1` | Reuse managed Python whenever viable and make broken-environment repair fallback explicit rather than silent. |
| `scripts/environment_smoke.py` | Runs profile-aware readiness checks under managed Python. |
| `src/orchestrator_cookie/dependencies.py` | Implements exact version/import checks and a real TestClient request smoke. |
| `src/orchestrator_cookie/config.py` | Separates `preferred_port` from the authenticated actual running `port`, while reading older Phase 15 config safely. |
| `src/orchestrator_cookie/cli.py` | Adds `init --with-test`, locked install/repair, `pip check`, readiness manifests, actual URL output, and configuration guards while managed state is active. |
| `src/orchestrator_cookie/doctor.py` | Reports runtime and test readiness separately and explains side-effect-free automatic port fallback. |
| `src/orchestrator_cookie/lifecycle.py` | Adds local sequential probing, conservative bind-race retry, authenticated post-health persistence, actual-port status/stop, and failure cleanup. |
| `tests/test_phase15_installer.py` | Expands dependency, wrapper, port, race, persistence, doctor, token, and failure-path coverage. |
| `docs/phase15/*` | Updates dependency, deployment, rollback, test, and operator guidance. |

## Lifecycle semantics

- `preferred_port` is the first candidate and remains stable until an explicit
  `configure --port N` resets it.
- Startup checks only local bindability on the configured bind host. It neither
  identifies nor changes an occupying process.
- A port selected after fallback is written to process metadata and config only
  after the viewer-token-authenticated runtime identity matches both the new
  instance ID and PID.
- Only a narrowly classified immediate bind collision advances to the next
  candidate. Import errors, configuration errors, timeouts, and other exits stop
  the attempt and point to the redacted dashboard log.
- Status and stop take the endpoint from authenticated process metadata. Tokens
  remain absent from metadata, argv, URLs, and printed output.
- Foreground mode probes once, runs attached, and intentionally does not create
  managed process state; its final message says so.

## Security and operational scope

The overlay does not restart a dashboard, call a model, probe a target, read
credential contents, change firewall state, acquire/build an image, or mutate a
container engine. Loopback remains the default and non-loopback binding still
requires explicit LAN policy plus authentication. Existing isolation,
allowlists, secret staging, cancellation, RDP, and model/refinement controls are
unchanged.

The apply workflow backs up and replaces only manifest-declared source files.
User configuration, tokens, projects, reports, manuals, logs, and secrets under
`.orchestrator-cookie/` are not payload targets.
