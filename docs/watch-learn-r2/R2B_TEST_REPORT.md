# R2B test report

## Source results

- Imported readiness plus importer, Phase 17, and R2A direct-interaction focus:
  154 passed, 1 skipped.
- Security/CSRF/redaction/secret/relay/egress/GUI focus: 271 passed,
  1 skipped.
- Complete source suite: 724 passed, 1 skipped, 32 warnings.
- R2A deterministic JavaScript lifecycle: 6 passed.
- Python compilation, inline/dashboard JavaScript syntax, browser harness syntax,
  shell syntax, and patch whitespace: passed.
- The R2A real Chromium gate remains environmentally excluded because no
  browser executable is installed. No browser was downloaded.

The inherited complete-suite warnings are pytest collection, Starlette
TestClient, Pillow, and naive-UTC deprecations. The one skip is the inherited
optional environment case.

## R2B assertions exercised

The new tests cover incomplete structured status, non-imported compatibility,
legacy and generated provenance, no-write preview, no-contact validation,
strict schemas, stale project revision, bounds/frame contract, adapter allowlist,
destination-field exclusion, secret-value exclusion, sanitized references,
owner/project isolation, private modes, save/check/activation separation,
receipt invalidation, target-revision binding, OIDC-only private state, every
mutation route's CSRF gate, and preflight rejection without activation.

The complete suite retains existing stale-frame-before-journal/dispatch,
authentication, authorization, redaction, secret staging, target relay, egress,
firewall, model boundary, worker, and GUI checks.

## Claim boundary

`R2B_SOURCE_TESTS=PASS`

`R2B_TARGET_FREE_VALIDATION=PASS`

`TARGET_CONTACT_DURING_DEVELOPMENT=false`

`LIVE_ACCEPTANCE_CLAIM=false`

`REMOTE_PUSH=false`
