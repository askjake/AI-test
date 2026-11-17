# R2C test report

## Authoritative base

- R2 base tree: `747b66c8fb12aa74e0aef4a8f685c4bcff84d260`.
- Prior R2 source gate: 724 passed, 1 skipped.
- Prior deterministic lifecycle gate: 6 passed.
- Host real-browser result: rejected with a `frameCoordinator` temporal-dead-zone
  error after CSP blocked the lifecycle asset.

## R2C results

- Focused CSP/initialization, direct-interaction, and imported-readiness suite:
  46 passed.
- Deterministic Node lifecycle suite: 6 passed.
- Complete Python suite: 727 passed, 1 skipped, 32 inherited warnings.
- External lifecycle and browser-harness JavaScript syntax: passed.
- Inline dashboard JavaScript syntax: passed.
- Python compilation, shell syntax, and patch whitespace: passed.
- Real Chromium execution: environmentally excluded. The harness returned the
  intentional code 78 because no installed Chromium executable was available;
  it did not download a browser.

The three additional Python cases lock the exact same-origin script policy,
fixed initialization marker/event ordering, operator-only no-store lifecycle
delivery, enforced frame-ancestor response policy, and fail-fast browser-gate
observers. The retained browser scenario asserts frame A click to fully loaded
focused frame B, a second B click without rearming, disposable cancellation,
meaningful no-replay/no-rebase behavior, single-dispatch stale/revision/uncertain
failure handling, and fail-closed focus, visibility, pointer-capture, image-load,
geometry, and dimension behavior.

The complete suite retains existing stale-frame-before-journal/dispatch,
authorization, CSRF, redaction, secret, relay, egress, firewall, imported
readiness, worker, and GUI coverage. The inherited warnings remain the existing
pytest collection, Starlette TestClient, Pillow, and naive-UTC deprecations.

## Claim boundary

```text
R2C_SOURCE_TESTS=PASS
R2C_DETERMINISTIC_JS=PASS
R2C_REAL_BROWSER_GATE=ENVIRONMENTALLY_EXCLUDED
LIVE_BROWSER_ACCEPTANCE_CLAIM=false
LIVE_ACCEPTANCE_CLAIM=false
TARGET_CONTACT=false
AWS_CONTACT=false
MODEL_CONTACT=false
SECRET_VALUE_CONTACT=false
DEPLOYMENT=false
IMAGE_BUILD_OR_PUSH=false
REMOTE_OR_PARENT_LINEAGE_CLAIM=false
REMOTE_PUSH=false
```
