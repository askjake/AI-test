# Watch & Learn Direct Interaction — Architecture and Threat Model

## Provenance and scope

This R1 source candidate was developed from a locally available recovery copy
whose Git tree is exactly `4977dedeee08f36a62dc24c4b3f926d69f3e68de`.
The advertised remote tip `d242f734f150192a840affac0ab532bf4dfafa95` was
not present locally and GitLab name resolution was unavailable. The local base
is therefore a new synthetic root over the exact reviewed tree. No parent or
remote lineage is claimed.

This is source-only work. It does not prove a live `mul-autotest` acceptance,
deployment readiness, or successful target behavior.

## Selected architecture

The implementation extends the existing constrained action API. It does not
embed VNC/noVNC, add a browser-to-target connection, expose a proxy, change
target selection, or widen the runner network policy.

| Stage | Boundary and behavior |
| --- | --- |
| Browser collection | Pointer Events and allowlisted keyboard events exist only on the focused controlled-frame image after explicit arming. |
| Browser queue | One state-changing request is in flight. Pending moves and wheel bursts are bounded/coalesced; meaningful action order is retained. |
| Frame binding | Every coordinate action carries schema version 1, the sanitized frame SHA-256, and exact frame dimensions captured at event time. |
| Dashboard API | Existing OIDC ownership, CSRF, project/session state, expected version, strict schema, request-size, and action quota checks remain authoritative. |
| Durable boundary | A sanitized intent plus privacy-safe action fingerprint is persisted, then dispatch-start is persisted, before target input occurs. |
| Adapter transport | The existing per-session capability-authenticated private FIFO transports one bounded request to the isolated runner. |
| Target input | The worker revalidates the action shape and drives only allowlisted `xdotool` pointer, wheel, and key operations through `Computer`. |
| Evidence | Meaningful completed actions may return one already-redacted frame; moves and pointer lifecycle events do not create evidence. |
| Learning | Pointer movement and low-level button lifecycle records are excluded. Click, drag, wheel burst, and safe key controls remain deterministic semantic steps. |
| Model path | Unchanged. Deterministic analysis remains mandatory; optional model enrichment is separately authorized and sees only bounded sanitized evidence. |
| Relay/firewall | Unchanged. The project-scoped destination-locked relay, no-host-networking posture, bridge restrictions, and firewall re-derivation remain intact. |

## Alternatives considered

| Approach | Result | Reason |
| --- | --- | --- |
| Extend bounded action API | Selected | Preserves authentication, ownership, versioning, journaling, receipts, redaction, and destination locking. |
| Raw VNC/noVNC session | Rejected | Would create a second broad input and display channel outside the reviewed durable action boundary. |
| Semantic browser gestures over the existing API | Incorporated | Click/double-click, drag, wheel burst, hover, and keys are normalized before dispatch, minimizing event volume. |

## Security and privacy properties

- Direct input is disarmed by default and requires both a recording session and
  explicit focus on the target frame.
- No document/window mouse or keyboard hook is installed. Context-menu and
  browser-key suppression are scoped to the focused frame while armed.
- Clipboard, paste, drop, `beforeinput`, and IME composition contents are never
  read or relayed. Ordinary literal text remains impossible in the action
  schema; the existing semantic intent and protected secret-reference flows are
  unchanged.
- Only `Shift+Tab` and `Ctrl+A` modifier chords are added. Alt, Meta, function
  keys, multi-modifier chords, and arbitrary keys remain invalid.
- Browser queue depth is 32, drag paths are at most 32 samples, key repeat is at
  most 3, the server accepts at most 20 actions per session/owner per second by
  default, and the existing action/evidence/request bounds still apply.
- Same idempotency key plus a different protected action fingerprint is a 409
  conflict. A dispatch-start without a receipt remains outcome-unknown and is
  never automatically retried.
- Coordinate input is rejected before journaling or dispatch unless the latest
  server evidence is readable and its SHA-256 and dimensions exactly match the
  event-time browser frame.
- Pausing invokes an idempotent worker release. A failed release changes the
  durable session to `capture_failed`. Worker pointer/key down lifecycle input
  also has a two-second automatic safety release.
- All untrusted labels and results continue to render with `textContent`; no
  HTML insertion API or browser storage was added.

## Failure behavior

Revision conflict, stale frame, queue overflow, rate limit, invalid schema,
lost authorization, rejected/failed receipt, uncertain outcome, pointer-capture
loss, focus loss, hidden page, and worker/relay failure stop or disarm direct
input without replay. An in-flight request is allowed to return its one receipt;
queued operations are cancelled. An uncertain receipt transitions through the
existing `reconciliation_required` path.

## Residual limits

- The source checks do not exercise a real browser, X server, target, or runner
  image. Browser behavior is covered by strict source-contract tests and
  JavaScript parsing; target execution is covered by injected `Computer` and
  worker tests.
- Touch-specific multi-pointer gestures are deferred. Pointer Events and the
  versioned schema leave room for a separately reviewed extension.
- A separately authorized live `mul-autotest` gate is required before any live
  or release-readiness claim.
