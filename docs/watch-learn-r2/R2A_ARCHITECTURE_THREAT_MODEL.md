# R2A architecture and threat model

## Trust boundaries

- The browser records only events on the focused, explicitly armed controlled
  image. It has no document-wide pointer or keyboard capture.
- A coordinate event carries immutable server fields plus a browser-only canvas
  generation. The generation never crosses the strict API schema.
- The dashboard remains the authentication, CSRF, owner/session, version,
  journal, rate, redaction, and frame-binding enforcement boundary.
- The existing private FIFO runner adapter remains the only target-control path.
  R2A adds no VNC/noVNC/WebSocket input surface.

## Threats and controls

| Threat | R2A control |
|---|---|
| New metadata paired with old pixels | Off-DOM load and exact natural-dimension check precede atomic generation commit. |
| Old response overwrites new UI state | Lower same-session versions are ignored. |
| DOM replacement generates false focus loss | Same evidence retains the node; controlled retirement is explicitly marked. |
| Old hover/wheel crosses a frame boundary | Timers and queued disposable work are cancelled nonfatally. |
| Old meaningful click silently changes target | It is never rebased or replayed; the operator must repeat it. |
| Request uncertainty causes a duplicate | One request remains in flight and the same action is never automatically retried. |
| Hidden page or real focus loss keeps control armed | Existing window, visibility, image blur, and pointer-capture fail-closed paths remain. |
| Clipboard or literal text capture | Paste, drop, composition, and before-input remain blocked without reading content. |
| Server stale protection weakened | No server frame, ownership, evidence, coordinate, journal, or version check was relaxed. |

## Residual risk and required gate

Node execution proves deterministic transition and queue behavior, not browser
event ordering. The supplied Chromium gate must run on an approved host against
local mocks before management may proceed to a separately authorized live
target gate. Source success is not release readiness.
