# R2B changed paths

| Path | Purpose |
|---|---|
| `src/dashboard/watch_learn_readiness.py` | Strict owner-scoped readiness contracts, atomic state, target-free validation/check, short activation, and effective overlay. |
| `src/dashboard/watch_learn_readiness_routes.py` | Inspect/preview/validate/save/check/activate routes and the separately activated target-preflight boundary. |
| `src/dashboard/app.py` | Constructs the readiness service and registers its routes. |
| `src/dashboard/config.py` | Private readiness root and bounded activation TTL settings. |
| `src/dashboard/demonstration_models.py` | Revision-bound imported readiness and frame-contract fields with backward-compatible defaults. |
| `src/dashboard/demonstration_routes.py` | Applies owner overlay only to imported projects and adds readiness to capability/create/Connect gates. |
| `src/dashboard/demonstrations.py` | Persists readiness/frame contracts and rejects dimension-mismatched evidence. |
| `src/dashboard/project_import.py` | Stops auto-defaulting VNC readiness and generates a non-source-controlled import manifest. |
| `templates/dashboard/watch_learn.html` | Structured imported-project onboarding with visibly separate target-free and target-contact actions. |
| `tests/test_watch_learn_imported_readiness.py` | Schema, ownership, revision, no-contact, CSRF, activation, UI, and frame-contract coverage. |
| `tests/test_project_import.py` | Safe-disabled import and generated-manifest expectations. |
| `tests/test_phase17_watch_learn.py` | Updated operator UI contract for the explicit bounded target preflight. |
| `docs/watch-learn-r2/R2B_*` | Design, threat model, paths, and test/claim boundaries. |

R2B does not change relay, firewall, OIDC, model, runner image, worker input,
or deployment implementation. The R2A canvas lifecycle remains intact.
