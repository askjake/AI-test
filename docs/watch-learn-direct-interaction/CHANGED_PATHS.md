# Watch & Learn Direct Interaction — Changed Paths

| Path | Purpose |
| --- | --- |
| `templates/dashboard/watch_learn.html` | Explicit arming/focus UX, serialized queue, frame-safe coordinate mapping, pointer/drag/wheel/key capture, privacy blocks, and emergency pause. |
| `src/dashboard/demonstration_models.py` | Versioned discriminated pointer, drag, wheel, and key schemas plus privacy-safe idempotency fingerprints. |
| `src/dashboard/demonstrations.py` | Frame freshness, server rate limit, conflict detection, release-on-pause, evidence suppression, and deterministic aggregation. |
| `src/dashboard/capture_adapter.py` | Bounded worker release request and versioned self-test action. |
| `src/dashboard/config.py` | Bounded per-session action-rate setting. |
| `src/orchestrator/watch_learn_worker.py` | Independent worker validation and allowlisted pointer/drag/wheel/key execution with automatic release. |
| `src/orchestrator/computer.py` | Explicit middle/double click, button lifecycle, drag, wheel, key lifecycle, and release primitives. |
| `tests/test_watch_learn_direct_interaction.py` | Direct-interaction schema, frame, idempotency, rate, release, worker, isolation, and privacy acceptance. |
| `tests/test_phase17_watch_learn.py` | Existing Phase 17 fixtures adapted to the versioned frame-bound protocol. |
| `tests/test_computer.py` | Target-input argv and release-path coverage. |
