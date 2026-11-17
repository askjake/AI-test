# R2A frame lifecycle root cause

## Disposition

The R1 source tests were correct about server frame enforcement but did not
execute the browser lifecycle. The live rejection is reproduced from source as
a deterministic DOM/queue sequence. It is not caused by weak or incorrect
server validation.

## Exact R1 event sequence

1. Frame A is loaded, focused, and explicitly armed. `canvasRecord` describes A.
2. A pointer event captures A's SHA-256 and dimensions. `pumpActions()` sends it
   with the current session version and a unique idempotency key.
3. The server journals, dispatches once, captures frame B, advances the session
   version, and returns a successful receipt plus B's evidence metadata.
4. R1 `pumpActions()` calls `showSession(result.session)`.
5. R1 `showSession()` unconditionally calls `renderCanvas()`, even if evidence
   identity is unchanged.
6. R1 `renderCanvas()` assigns `canvasRecord = B`, destroys the focused A image,
   creates a B image, appends it, and calls `focus()` without waiting for B's
   `load` event.
7. Removing A causes its `blur` handler to run while `directArmed` is true. That
   handler clears the queue and calls `disarmDirect()`.
8. The visible result is therefore the reported live failure: the frame changed
   and direct interaction is no longer armed. The premature B metadata binding
   also creates a pixel/metadata interval in which B is described but not loaded.
9. If a hover, wheel, pending click, drag, or queued coordinate event from A
   survives until dispatch, its immutable A binding is correctly rejected by
   the server after B becomes current. R1 treats that disposable stale event as
   fatal and disarms the session again.

The primary cause is unconditional focused-node replacement. Premature metadata
binding, focus-before-load, and unclassified obsolete input make the failure
repeatable and amplify it. Fixing only pointer-move timing would not repair the
system.

## R2A correction

R2A adds a browser-local monotonic canvas generation. Session responses are
accepted only in version order. Same-evidence responses retain the exact image
node. New evidence is loaded off-DOM, decoded, checked against the advertised
dimensions, and committed atomically with its SHA-256, size, session, evidence
ID, and generation. Only after commit is the old image retired and focus moved.

During a real frame transition, new direct input is temporarily blocked. Old
hover/move and wheel work is discarded nonfatally. Unsent meaningful input is
cancelled with a precise repeat-on-new-frame message. Dispatched input is never
retried or rebased. Blur from the deliberately retired node is distinguished
from real browser focus loss.

## Evidence boundary

The extracted lifecycle and queue state machine executed under Node.js. A
Playwright/Chromium localhost-only browser harness is included, but no browser
executable was installed in the development environment and none was
downloaded. R2A therefore makes no live-browser acceptance claim.
