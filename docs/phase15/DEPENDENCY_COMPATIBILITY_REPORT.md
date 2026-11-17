# Phase 15.1 dependency compatibility and remediation report

## Evidence-based diagnosis

The Phase 15 baseline installed all requirements with open lower bounds and put
`pytest` in the production runtime list. On 2026-08-25 a clean initialization
resolved FastAPI 0.141.1 and Starlette 1.6.0, but neither the baseline runtime nor
dashboard requirements declared a TestClient transport. Full collection then
failed in seven modules with:

```text
RuntimeError: The starlette.testclient module requires the httpx2 package to be installed.
```

This is not a misspelled package name in current Starlette. Starlette 1.x first
imports `httpx2`, retains deprecated legacy `httpx` fallback, and lists
`httpx2>=2.0.0` in its `full` extra. FastAPI exposes Starlette's TestClient but
does not make a client transport a mandatory base dependency. Primary sources:

- <https://github.com/Kludex/starlette/blob/1.3.1/starlette/testclient.py>
- <https://github.com/Kludex/starlette/blob/1.3.1/pyproject.toml>
- <https://github.com/fastapi/fastapi/blob/master/pyproject.toml>
- <https://fastapi.tiangolo.com/reference/testclient/>

Installing `httpx2==2.10.0` into the reproduced baseline made a minimal
FastAPI/TestClient request succeed and the unchanged baseline source pass all
393 tests. The dependency is therefore declared directly, exactly, and only in
`requirements-test.txt`.

## Compatibility model

The managed environment has two intentional profiles:

| Profile | Command | Purpose |
| --- | --- | --- |
| Runtime | `install init` | Dashboard and orchestrator production runtime; no pytest or TestClient transport. |
| Test | `install init --with-test` | Runtime plus exact pytest and HTTPX2; required for full collection and release apply. |

Direct requirements are exact pins. `constraints.txt` also pins the tested
transitive resolution, while upstream environment markers continue to decide
platform-only wheels such as Uvicorn's optional event-loop implementation. The
installer always invokes pip through the clone-local managed interpreter, runs
`pip check`, then validates exact distributions, imports, and—under the test
profile—a real in-process request through TestClient.

The successful profile and a SHA-256 over its requirement/constraint inputs are
recorded in non-secret managed state. Doctor recalculates readiness and does not
trust the record alone.

## Repair behavior

Run the platform wrapper from the clone:

```text
install init                 # repair/validate production runtime
install init --with-test     # repair/validate full-test environment
```

`init` may download/install because that is its explicit purpose. It preserves
configuration, private tokens, projects, reports, manuals, logs, and secrets.
Once a usable managed interpreter exists, the wrappers never fall through to
host Python. If the managed directory exists but its Python executable is
missing, only an explicit `init` is allowed to use system Python, and the wrapper
prints a `REPAIR:` notice first.

Package apply is different: by default it performs a read-only managed
TestClient preflight and prints `STOP:` before source mutation if incompatible.
Only `--repair-test-env` authorizes the package to install the locked test
profile, still before source backup or mutation.

## Validation scope

The exact family was installed fresh and tested on CPython 3.12/Linux. The
requirements and wrappers are platform-neutral, PowerShell/CMD behavior has
static coverage, and upstream packages publish the relevant supported Python
and platform artifacts. No native macOS or Windows runtime smoke was run, so
this report does not claim one.
