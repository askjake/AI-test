# Phase 15.1 test report

Date: 2026-08-25
Native environment: Linux, CPython 3.12.13

## Baseline reproduction

Command:

```text
./install.sh init
PYTHONPATH=src .orchestrator-cookie/venv/bin/python -m pytest --collect-only -q
```

Result: dependency installation selected FastAPI 0.141.1 and Starlette 1.6.0
without a TestClient transport. Collection stopped with 7 errors in the
TestClient-heavy modules; 278 other tests were collected. This reproduced the
reported `httpx2` RuntimeError.

## Compatibility proof

After explicitly installing `httpx2==2.10.0` into the reproduced baseline, a
minimal FastAPI app completed a request through TestClient and the unchanged
baseline source produced:

```text
393 passed, 31 warnings in 11.61s
```

## Refactor validation before packaging

Focused command/result:

```text
python -m pytest -q tests/test_phase15_installer.py
40 passed in 0.32s
```

Full command/result:

```text
python -m pytest -q
408 passed, 31 warnings in 11.78s
```

## Fresh managed-environment acceptance

Commands:

```text
./install.sh init --with-test
.orchestrator-cookie/venv/bin/python -m pip check
.orchestrator-cookie/venv/bin/python scripts/environment_smoke.py --profile test
PYTHONPATH=src .orchestrator-cookie/venv/bin/python -m pytest -q
./install.sh doctor --json
```

Results:

- fresh exact dependency installation succeeded;
- `pip check`: no broken requirements;
- managed TestClient request smoke: pass;
- final full suite in the fresh managed dependency environment: 408 passed,
  31 warnings in 11.78s;
- doctor: runtime dependencies PASS, developer/test dependencies PASS, binding
  PASS, preferred port PASS.

Warnings are pre-existing pytest collection warnings plus Pillow and naive-UTC
deprecations outside this stabilization scope.

## Coverage added

Focused tests cover preferred/next/multiple port selection, existing-instance
idempotence, probe-to-bind collision retry, unrelated failure non-retry,
post-health-only persistence, actual-port status/stop routing, exhaustion,
doctor read-only fallback guidance, exact dependency profiles, TestClient
readiness, tokens absent from metadata/argv/URLs/output, explicit port reset,
loopback/LAN policy, and POSIX/PowerShell wrapper source contracts.

## Package acceptance

- archive safety inventory: no absolute/traversal paths, links, or cached bytecode;
- sidecar validation from a separate transfer directory: pass;
- incompatible managed environment, default apply: `STOP:` before backup/source mutation;
- explicit `--repair-test-env`: exact test profile and TestClient preflight passed;
- successful transactional apply: focused and full suites passed, payload hashes matched;
- independent rollback: baseline hashes restored;
- injected pytest option failure: observed after mutation and automatically rolled back;
- private token/config/report sentinels and an unrelated source-tree note remained byte-identical.

## Platform claim boundary

Linux runtime validation was executed. PowerShell/CMD and macOS behavior was
checked statically and through platform-independent Python unit paths. No native
Windows or macOS smoke ran; none is claimed.
