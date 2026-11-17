# R2C CSP and browser-initialization root cause

## Disposition

The host Chromium rejection is a production-page initialization failure. It is
not a Playwright timing defect and is not repaired by delaying the test.

## Exact failure sequence

1. The R2 page declares `script-src 'unsafe-inline'` in its CSP.
2. R2A introduced the authenticated external script
   `/watch-learn-assets/lifecycle.js` before the page's inline controller.
3. Because `script-src` omits `'self'`, Chromium blocks that same-origin asset.
4. The inline controller begins evaluating and reaches
   `new WatchLearnLifecycle.FrameCoordinator()` without the lifecycle namespace.
   Top-level initialization aborts at that point.
5. Function declarations such as `showSession()` are hoisted, but the lexical
   `frameCoordinator` binding has not completed initialization.
6. The R2 browser harness calls `showSession()` without an explicit page-ready
   contract and observes `ReferenceError: Cannot access 'frameCoordinator'
   before initialization`.

The temporal-dead-zone error is therefore downstream evidence of the CSP block,
not the primary defect.

## R2C correction

R2C changes the page script policy to exactly:

```text
script-src 'self' 'unsafe-inline'
```

The existing inline controller remains permitted, and only same-origin external
scripts are newly authorized. Wildcards, `data:`, `blob:`, remote origins, and
`'unsafe-eval'` remain absent. The lifecycle route remains operator-authenticated
and returns `Cache-Control: no-store`.

The existing `frame-ancestors 'none'` restriction is moved from the meta policy
to the Watch & Learn HTTP response header. Browsers ignore `frame-ancestors`
when it is delivered in a meta element; the response header both preserves and
enforces that boundary without producing an expected console diagnostic that
would weaken the fail-fast browser gate.

After the lifecycle namespace loads, `FrameCoordinator` is constructed, direct
input state is initialized, and the static direct-input/fail-closed event
handlers are installed, the controller publishes exactly two non-sensitive
signals:

- `data-watch-learn-initialization="ready"` on the document element;
- a payload-free `watch-learn:ready` DOM event.

No actor, session, project, target, credential reference, token, evidence, or
action state is exposed by the signal.

## Browser-gate consequence

The localhost-only Playwright gate now waits for the deliberate readiness
marker before calling `showSession()`. It concurrently fails on page exceptions,
unexpected console errors, lifecycle request failures or non-success responses,
CSP violations, and initialization timeout. A sleep cannot convert those
failures into a pass.

## Claim boundary

The repaired source, deterministic JavaScript, and source-contract tests pass.
No Chromium executable was available in the development environment, so the
real-browser gate remains environmentally excluded and no live-browser or live
acceptance claim is made.
