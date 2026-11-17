# Author-mode Project Builder changed paths

| Path | Purpose |
| --- | --- |
| `src/dashboard/author_builder.py` | OIDC owner grants, local inventory, structured intent/plan, governed history, optional model boundary, isolated candidate/offline-validation/apply, persisted-policy host-key authorization, action ledger, and atomic reviewed-key save |
| `src/dashboard/author_builder_routes.py` | Typed, explicit operator endpoints for every builder and host-key action |
| `src/dashboard/project_composition.py` | Deterministic, provenance-bearing multi-root preview and atomic new-project creation |
| `src/dashboard/project_composition_routes.py` | Explicit composition preview/create endpoints |
| `src/dashboard/app.py` | Service construction, ownership publish/rollback callbacks, and router registration |
| `src/dashboard/config.py` | Bounded private-state, history, candidate-copy, and host-key discovery settings |
| `src/dashboard/project_import.py` | Transactional OIDC ownership callback and exact rollback callback for existing import publish |
| `templates/dashboard/index.html` | Staged Author Builder workspace, honest offline-validation language, persisted-route host-key controls, and multi-root composition; no implicit model, runner, target, or discovery action |
| `scripts/run_container.sh` | Propagates the Bedrock exclusion signal only for no-AWS-forwarding plus an active typed target relay |
| `tests/test_author_builder.py` | Authorization/IDOR, validation bundle, intent/plan/model boundary, history/privacy, isolation/staleness, persisted host-key policy/SSRF, atomic save, relay identity, and UI evidence |
| `tests/test_gui_reliability.py` | Positive/negative relay exclusion environment-contract tests and in-container consumer assertion |
| `tests/test_project_composition.py` | Determinism/provenance, OIDC ownership, staleness, traversal/link/duplicate/manual/existing-slug, and rollback evidence |
| `tests/test_project_import.py` | Ownership callback rollback regression after a failed post-publish audit |
| `docs/author-builder/ARCHITECTURE_THREAT_MODEL.md` | Architecture, persistence tradeoffs, authority matrix, threat controls, and residual risks |
| `docs/author-builder/OPERATOR_RELEASE_HANDOFF.md` | Separate release configuration/gates and unresolved VNC relay status |
| `docs/author-builder/TEST_REPORT.md` | Exact offline commands and source-gate evidence |

No runner Python or target-relay implementation was changed. The only launcher change is the narrow
`ORCHESTRATOR_EGRESS_EXCLUDE_BEDROCK=1` propagation contract described above; default-deny, endpoint
pinning, target scope, and non-relay behavior remain unchanged.
