# Watch & Learn Direct Interaction R1 — Source Verification Report

## Result

Source-level result: **PASS**.

Live target result: **NOT RUN / NOT AUTHORIZED**. This report does not claim a
successful `mul-autotest` gate, deployment readiness, or release readiness.

## Provenance

| Item | Value |
| --- | --- |
| Advertised remote tip | `d242f734f150192a840affac0ab532bf4dfafa95` |
| Verified source tree | `4977dedeee08f36a62dc24c4b3f926d69f3e68de` |
| Local history mode | New synthetic root over the exact verified tree |
| Remote/parent lineage claim | False |
| Network limitation | `gitlab.com` DNS was unavailable in the verification environment |

The candidate commit/tree and deliverable SHA-256 values are recorded in the
companion package manifest generated after this report was committed.

## Baseline

| Gate | Result |
| --- | --- |
| Focused Watch & Learn + GUI reliability | 91 passed, 1 skipped |
| Complete source suite | 675 passed, 1 skipped |

## Candidate verification

| Gate | Result |
| --- | --- |
| Direct interaction + Phase 17 + Computer + GUI reliability | 142 passed, 1 skipped |
| Complete source suite | 711 passed, 1 skipped |
| Inline Watch & Learn JavaScript parse (`node` `vm.Script`) | PASS |
| Python compile (`python -m compileall -q src tests`) | PASS |
| Shell syntax (`bash -n` over `scripts/*.sh`, `docker/*.sh`, `install.sh`) | PASS |
| Patch whitespace (`git diff --check`) | PASS |

The complete suite emitted 32 warnings: pre-existing pytest collection warnings,
one Starlette TestClient deprecation, Pillow `getdata` deprecations, and runner
`datetime.utcnow` deprecations. No test failed.

## Added coverage

- Left, middle, right, and double-click schemas and worker dispatch.
- Pointer down/up, bounded pointer movement, semantic drag path, and automatic
  release behavior.
- Vertical and horizontal wheel input.
- Safe keys, `Shift+Tab`, `Ctrl+A`, denied shortcuts, and repeat limits.
- Exact frame SHA-256/dimension binding and stale-frame rejection before journal
  or target dispatch.
- Same-key/different-action idempotency conflict rejection.
- Action rate limit, queue bounds, one-in-flight source contract, disposable
  move/wheel coalescing, and uncertain-outcome no-retry behavior.
- Pause release success/failure, pointer-capture loss, focus/visibility cleanup,
  and direct-input arming/focus isolation.
- No literal text, IME, clipboard, paste, or drop capture; no global input hooks,
  browser storage, WebSocket, raw VNC, or noVNC path.
- Deterministic exclusion of incidental pointer movement and low-level button
  lifecycle events.

## Unchanged security boundaries

The candidate does not modify target relay selection, firewall policy,
container network mode, OIDC/authentication code, CSRF enforcement, secret
staging, redaction implementation, model-client construction, or promotion/run
authority. The complete suite includes the existing relay, security, runtime,
entrypoint, firewall-mode, redaction, ownership, and secret-entry regressions.

## Environmental exclusions

- GitLab cloning/pull/push was blocked by DNS policy; an exact-tree local
  recovery copy was used instead.
- No real browser, container engine, digest-pinned runner image, X server, live
  target, AWS service, or model was contacted.
- A separately authorized live `mul-autotest` acceptance is still required.
