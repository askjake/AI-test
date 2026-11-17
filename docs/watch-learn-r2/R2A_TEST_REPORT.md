# R2A test report

## Baseline

- R1 tree: `f5e9694d7782b2897b8b350d46728fa5ce34b0e9`
- Focused: 142 passed, 1 skipped.
- Complete: 711 passed, 1 skipped.

## R2A results

- Extracted JavaScript lifecycle: 6 passed under Node.js 24.19.0.
- Focused direct interaction, Phase 17, Computer, and GUI: 144 passed,
  1 skipped.
- Complete source suite: 713 passed, 1 skipped, 32 warnings.
- Browser harness JavaScript syntax: passed.
- Inline dashboard JavaScript syntax: passed.
- Real Chromium execution: environmentally excluded because no Chromium
  executable is installed. The gate returned the intentional code 78 and did
  not download a browser.

The existing server test still proves stale frame revision is rejected before
journaling or adapter dispatch. The complete suite warnings are the inherited
pytest collection, Starlette TestClient, Pillow, and naive-UTC warnings.

## Claim boundary

`R2A_SOURCE_TESTS=PASS`

`R2A_DETERMINISTIC_JS=PASS`

`R2A_REAL_BROWSER_GATE=ENVIRONMENTALLY_EXCLUDED`

`LIVE_BROWSER_ACCEPTANCE_CLAIM=false`

`REMOTE_PUSH=false`
