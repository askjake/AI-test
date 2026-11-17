# Author-mode Project Builder R1 source test report

Date: 2026-09-14 (UTC)

## Source identity and reconstruction scope

- R1 functional-recovery archive SHA-256:
  `7cccbcc0b939047967680b36a8b72b4fce845f85697878c2db565d564c304013`.
- The R1 archive reconstructed tree `187af30832058e4799f3d859ac5c99c80e9f6d8d`, but it predates the
  target-relay recovery work and was used for comparison only.
- R1 feature base tree: `7448534ab7550cc50a4d6cb88935199e1a9a2be0`.
- Isolated R1 synthetic base commit:
  `350da2d1d233ccbed3de31c65821a2794b5cac56`.
- The synthetic base identifies exact source content only. It does not claim the missing parent
  history or remote lineage of the original repository.
- Final local candidate commit and tree are recorded in the companion delivery evidence generated
  after the commit. A Git commit/tree cannot contain its own final identity without changing it.

## R1 baseline gate

From the isolated R1 feature base, before corrective edits:

```sh
PYTHONPATH=src /workspace/scratch/aa726fb19cfa/current-3ab67d4/.test-venv/bin/python -m pytest -q
```

Result: **657 passed, 1 skipped, 32 warnings in 52.45s**.

## Final focused and compatibility gate

```sh
PYTHONPATH=src /workspace/scratch/aa726fb19cfa/current-3ab67d4/.test-venv/bin/python -m pytest -q tests/test_author_builder.py tests/test_project_composition.py tests/test_project_import.py tests/test_p13b_forms.py tests/test_phase16_auth.py tests/test_phase16r_reconciliation.py tests/test_phase17_watch_learn.py tests/test_targets.py tests/test_target_relay.py tests/test_imported_target_startup.py tests/test_gui_reliability.py
```

Result: **251 passed, 1 skipped, 1 warning in 23.31s**.

After the final candidate/apply binding check, the directly affected gate was repeated:

```sh
PYTHONPATH=src /workspace/scratch/aa726fb19cfa/current-3ab67d4/.test-venv/bin/python -m pytest -q tests/test_author_builder.py tests/test_gui_reliability.py
```

Result: **53 passed, 1 warning in 13.70s**.

## Final authoritative source gate

```sh
PYTHONPATH=src /workspace/scratch/aa726fb19cfa/current-3ab67d4/.test-venv/bin/python -m pytest -q
```

Result: **671 passed, 1 skipped, 32 warnings in 50.27s**.

The skip is the existing platform/availability-conditioned test. Warnings are expected and non-fatal:
existing pytest collection warnings for Pydantic model classes, Starlette `BlockingPortal`
deprecation, Pillow `Image.getdata` deprecation, and the existing naive UTC datetime deprecation in
runner tests.

## Static and template gates

```sh
git --git-dir=/workspace/scratch/339d2fcbc9cc/ai-test-author-builder-r1-repo/.git --work-tree=/workspace/scratch/339d2fcbc9cc/ai-test-author-builder-r1 diff --check
PYTHONPATH=src /workspace/scratch/aa726fb19cfa/current-3ab67d4/.test-venv/bin/python -m compileall -q src
sed -n '/<script>/,/<\/script>/p' templates/dashboard/index.html | sed '1d;$d' | node --check -
bash -n scripts/run_container.sh docker/egress_firewall.sh
```

Result: all exited **0** with no diagnostics.

## Isolation statement

All evidence is source-local. No dashboard or target service was started or reconfigured; no target,
SSH endpoint, VNC/RDP endpoint, VPN, AWS service, model, or other non-local service was contacted; no
secret or known-host file content was inspected; no image was built, published, or repinned; and no
branch was pushed or deployed. Host-key and model boundaries were exercised only through injected
fakes. The live VNC regression gate remains an explicit post-build/post-repin operator action.
