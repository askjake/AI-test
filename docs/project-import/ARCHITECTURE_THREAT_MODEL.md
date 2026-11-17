# Project-folder import: architecture and threat model

## Scope and invariants

Project-folder import is an operator-only authoring feature. It browses server-side
directories that the clone administrator explicitly allowlists, produces a non-publishing
validation preview, and atomically publishes a new project only after a second, explicit
confirmation. It does not invoke the runner, contact a target, construct a model client,
read AWS configuration, or import credential material.

The importer accepts a self-contained portable AI-Test folder:

```text
candidate/
├── project.yaml
├── 010-example.md
├── nested/020-example.md
└── manual/
    ├── manual.md
    └── topic.md
```

It also accepts the established split layout when the selected project contains a
normalized relative `manual_dir` whose directory remains inside the same configured root.
This supports selecting `tests_specs/<slug>` while safely copying
`tests_manuals/<slug>`. Absolute, parent-relative, cross-root, linked, and reparse manual
paths are denied.

Only the top-level `project.yaml`, runnable Markdown outside `manual/`, and Markdown plus
safe image assets inside the portable or root-contained legacy manual are eligible. The stored
`project.yaml` is rendered through the existing typed authoring validator with
`manual_dir: ./manual`. Specification and manual Markdown bytes are copied unchanged;
source files and metadata are never modified.

## File and dependency map

| File | Responsibility | Existing dependency preserved |
|---|---|---|
| `src/orchestrator_cookie/config.py` | Strict, canonical installer model for zero or more import roots | Existing private JSON config and atomic writer |
| `src/orchestrator_cookie/cli.py` | Repeated `--project-import-root` and explicit clear switch | Existing owner-only configure workflow |
| `src/orchestrator_cookie/lifecycle.py` | Exports validated roots and private audit path to the dashboard | Existing managed dashboard environment |
| `src/orchestrator_cookie/doctor.py` | Disabled/ready/unsafe finding and capability | Existing non-mutating doctor report |
| `src/dashboard/config.py` | Typed runtime limits and root environment parsing | Existing `DASHBOARD_` settings contract |
| `src/dashboard/project_import.py` | Browse, scan portable or root-contained split manuals, preview token, staging, validation, publish, audit | Existing authoring validators; no runner/model imports |
| `src/dashboard/project_import_routes.py` | Typed API and deterministic application errors | Existing operator and CSRF dependencies |
| `src/dashboard/app.py` | Constructs one service and mounts its router | Existing application factory and mutation audit |
| `src/dashboard/authoring.py` | Resolves exact portable `./manual` form for authoring validation | All legacy manual paths retain cwd-relative behavior |
| `src/orchestrator/projects.py` | Resolves exact portable `./manual` form at runtime | External `tests_manuals/...` paths remain unchanged |
| `src/dashboard/editor_routes.py` | Does not offer portable manual pages as runnable specs | Existing project/spec editor routes |
| `templates/dashboard/index.html` | Operator button, accessible browser, preview, confirmation, refresh/select | Existing single-page dashboard and project list |
| `tests/test_project_import.py` | Filesystem, API, installer, transaction, audit, and UI regression gates | Existing managed pytest profile |

## API map

All routes are below `/api/v1/authoring/project-import` and require the existing
`verify_operator` dependency. Cookie-authenticated POST requests also require the existing
CSRF header.

| Method and path | Input | Writes project store? | Result |
|---|---|---:|---|
| `GET /capabilities` | None | No | Enabled state and public bounds; no host paths |
| `GET /roots` | None | No | Root identifiers and friendly labels only |
| `POST /discover` | Root id | No | Logical portable/split projects and safe root-relative metadata |
| `POST /browse` | Root id + normalized relative directory | No | Advanced breadcrumbs and safe child directories only |
| `POST /preview` | Root id + relative directory + new slug | No | Counts, bounded bytes, warnings/errors, exclusions, opaque token |
| `POST /apply` | Opaque preview token + unchanged slug | Yes | Atomic new project or typed failure with no merge/overwrite |

Validation errors appear in preview diagnostics. Request failures use stable codes such
as `invalid_path`, `linked_path`, `project_import_disabled`, `project_exists`,
`stale_preview`, `preview_expired`, and `audit_unavailable`.

## Trust boundaries and controls

| Threat | Control | Failure posture |
|---|---|---|
| Arbitrary absolute path or traversal | Client supplies root id plus strict POSIX-relative path; Windows drives, backslashes, dot segments, hidden and unsafe selection components are rejected | Typed 400; no listing |
| Sibling-prefix escape | `Path.resolve(strict=True)` plus `commonpath` containment under the canonical root | Typed 400 |
| Symlink, broken link, junction, or reparse escape | `lstat`/no-follow checks on configured roots, every selected component, and every scanned entry; components are identity-checked again | Denied, including on platforms where reparse safety cannot be proven |
| Root replacement | Device/inode identity captured at service construction and rechecked for every operation | `root_changed` conflict |
| Legacy manual escape or substitution | `manual_dir` must be normalized and relative; resolution stays below the same configured root; its path digest, directory identities, and file digests join the preview manifest | Validation error or stale preview; no publish |
| Changing source file | Before/opened/after identity checks, `O_NOFOLLOW` where supported, content SHA-256, directory identity checks | `source_changed` or stale preview |
| Preview/apply race | One-time, actor/session-bound, short-lived opaque token contains server-side root, relative path, slug, and manifest digest; apply scans before and after staging | `stale_preview`; another preview required |
| Secret disclosure | Secret-like/hidden names are redacted, sensitive entries make preview invalid, no file contents or absolute root paths enter responses or audit | Import denied |
| Oversized input or resource exhaustion | Configured depth, file count, single-file bytes, total bytes, browse entries, excluded-entry response, token count, and TTL bounds | Validation error; no publish |
| FIFO, socket, device, or special node | Only regular files and ordinary directories are accepted | Validation error |
| Existing destination or concurrent collision | Slug validator plus OS-specific atomic no-replace rename (`renameat2`, `renamex_np`, Windows rename refusal) | 409 or fail-closed 503; never merge/overwrite |
| Partial copy/validation/publish | Private staging directory on the destination filesystem, existing authoring validation, file and directory fsync, atomic publish | Only the operation-owned staging inode is cleaned |
| Audit failure after publish | Published inode is moved out and removed before returning a typed error | No successful unaudited import |
| Cleanup substitution | Staging and published inode identities are retained and checked before cleanup/rollback | Refuses to delete an unowned replacement |
| Target/model/network side effect | Import module has no runner, target, subprocess, boto3, or model dependency; tests replace process/network entry points with failing sentinels | Preview remains filesystem-read/audit-only |

## Audit contract

Preview and apply events are JSON Lines with a UTC timestamp, bounded actor and auth
method, one-way session digest, configured root id, one-way source-relative-path digest,
manifest digest, destination slug, counts, bytes, action, and result. Events contain no
absolute import-root path, source-relative path text, file contents, token, credential, or
OIDC secret. The file is opened append-only and set to mode `0600` on POSIX.

## Compatibility and limitations

- The browser is intentionally app-native UI over a server directory API; a remote web
  page cannot open a native server filesystem picker.
- Import neither overwrites nor merges and imports exactly one selected project plus, when
  requested by that project's legacy metadata, one root-contained manual tree.
- Absolute, parent-relative, cross-root, linked, or reparse `manual_dir` values are never
  followed. A legacy manual outside the selected root must first be staged as a sanitized
  self-contained folder with `manual/manual.md`.
- Missing legacy schedules remain absent, and missing window titles are normalized only to
  the exact deterministic fallback already used by the runner. Legacy VNC `via` syntax is
  migrated to the typed SSH local-forward route; no shell-oriented route is retained.
- Preview tokens are memory-only, one use, and expire after five minutes by default;
  dashboard restart invalidates them.
- Windows reparse/junction entries are denied during browsing. Version 1 fails closed
  before preview file reads on Windows until a separately reviewed `CreateFileW`
  no-follow handle implementation is available. Linux and macOS publish use explicit
  no-replace primitives; unknown POSIX platforms fail closed.
