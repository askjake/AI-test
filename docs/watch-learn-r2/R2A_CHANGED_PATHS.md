# R2A changed paths

| Path | Purpose |
|---|---|
| `static/watch_learn_lifecycle.js` | Extracted monotonic frame/generation and obsolete-queue state machine. |
| `templates/dashboard/watch_learn.html` | Stable canvas loading, response ordering, focus retention, generation-bound queueing, and user-visible transition states. |
| `src/dashboard/app.py` | Authenticated no-store delivery of the lifecycle module. |
| `scripts/run_watch_learn_r2_browser_gate.js` | Localhost-only Playwright lifecycle acceptance using mock API/evidence. |
| `tests/js/watch_learn_lifecycle.test.js` | Deterministic JavaScript execution of frame and queue invariants. |
| `tests/test_watch_learn_browser_lifecycle.py` | Runs the JavaScript suite and locks down the no-download browser gate. |
| `tests/test_watch_learn_direct_interaction.py` | Updates R1 structural checks for generation-based binding. |
| `docs/watch-learn-r2/R2A_*` | Root cause, threat model, changed paths, and test evidence. |

No relay, firewall, authentication, authorization, redaction, model, runner
worker, or target-control implementation was changed in R2A.
