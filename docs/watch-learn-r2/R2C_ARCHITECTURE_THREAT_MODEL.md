# R2C architecture and threat-model update

## Scope

R2C changes only Watch & Learn browser resource policy, initialization signaling,
the localhost browser gate, and their source tests. It does not change readiness,
relay, runner, firewall, authoring, target policy, authentication semantics,
redaction, journaling, dispatch, or model behavior.

## Trust boundaries

| Boundary | R2C control |
|---|---|
| Browser to lifecycle asset | Exact relative same-origin path; page CSP permits `'self'`; route requires operator authentication and returns `no-store`. |
| Browser controller initialization | Payload-free marker/event emitted only after lifecycle construction, direct-input state initialization, and handler installation. |
| Embedding another origin | `frame-ancestors 'none'` is enforced as an HTTP response policy rather than an ignored meta directive. |
| Browser test to application behavior | Loopback HTTP server and synthetic evidence only; no dashboard startup, credentials, target, AWS, or model access. |
| Direct input to server | Existing frame revision/dimensions, serialization, idempotency, arming, and stale-frame controls are unchanged. |

## Threats and controls

### Lifecycle script is blocked or missing

The initialization signal cannot be emitted. The gate observes the failed
request, non-success response, CSP violation, page exception, or bounded timeout
and rejects immediately.

### CSP repair widens executable authority

The source test parses the actual page directive and requires its script source
list to be exactly `'self'` and `'unsafe-inline'`. Wildcards, executable data or
blob URLs, remote CDNs, and eval authority fail the test.

### Readiness signal leaks sensitive state

The signal is a fixed literal marker and a payload-free `Event`. It includes no
session or authorization data and does not wait on or encode API responses.

### A partial controller is mistaken for ready

Publication checks the loaded namespace, constructed coordinator, initial
disarmed queue state, and the handler-installed guard. Its only call site occurs
after the static control, focus, and visibility handlers are registered.

### Browser errors are hidden by timing

The gate races the complete scenario against fatal observers for `pageerror`,
console errors, lifecycle request failure/status, and CSP violation. The page
must publish readiness within five seconds; no initialization sleep is used.

### Old input crosses a frame transition

The R2A browser and deterministic cases remain in the gate. Disposable A-bound
input is discarded; meaningful unsent input requires repetition; dispatched
input is never retried or rebased; stale, revision, and uncertain outcomes
dispatch once and disarm.

## Preserved security invariants

R2C retains explicit arming, canvas-only capture, the keyboard allowlist,
text/clipboard/composition prohibition, unique idempotency keys, serialized
dispatch, owner/OIDC/CSRF enforcement, pre-relay redaction, imported-readiness
save/check/activation separation, and the prohibition on raw VNC/noVNC input.
