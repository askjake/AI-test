# Author-mode Project Builder architecture and threat model

## Recovery and lineage boundary

This source candidate was developed from a verified recovery snapshot whose tracked tree is
`b35e5060df21bf1bbbc7f7c65ad667f0aa74ee7b`, attested as the tree of the otherwise unreachable
commit `bc924ec7be89c074a938e7ae0c48d1dd9b9b4775`. The isolated repository has a synthetic recovery
root. It proves exact tree content, not parent history or remote lineage.

## Workflow and authority boundaries

The Author workspace exposes staged commands rather than an autonomous agent:

1. Understand a natural-language objective and save it as an editable structured intent.
2. Inspect a bounded local inventory containing paths, roles, sizes, and content hashes.
3. Optionally select same-author projects and preview a redacted history capsule.
4. Create a plan bound to exact intent, project, inventory, and history revisions.
5. Optionally request constrained model refinement with a separate literal confirmation.
6. Copy the reviewed project to a private candidate, apply only reviewed text-file changes, and
   explicitly run selected in-process offline validation categories.
7. Review the diff and evidence, then apply with exact project, plan, candidate, validation, and source
   revisions plus an exact project-slug confirmation.

Ordinary dashboard operator access is insufficient. Every builder operation requires a unique OIDC
operator identity and a server-side owner/editor grant for the project. Project-not-authorized is
reported as not found to reduce project enumeration. Newly created OIDC projects are claimed during
the atomic publish transaction; the exact claim is removed if publish is rolled back. Existing
projects can be granted to exact OIDC subjects through an administrator-owned configuration file.

The server, not the browser, enforces access, revisions, path containment, action order, limits,
and confirmations. Browser state is presentation state only and grants no capability.

## Local persistence choice

Private builder state is stored below a configured clone-local state root as atomic JSON and JSONL:
owner grants, structured intents, plans, action events, bounded history entries, retention settings,
and isolated candidates. Directories are private, state files are regular non-symlinks, replacement
is atomic, and owner directories use opaque hashes of OIDC principals.

This representation reuses the deployment's local ownership and backup boundary, has no external
index or vector-service dependency, and is easy to inspect and delete. Its tradeoffs are single-node
scope and process-level locking rather than multi-host transactions. It is therefore unsuitable as
a shared distributed authoring database without a future storage abstraction and concurrency model.

## History ledger and capsule

History is off by default. A request names each source project explicitly; the service verifies the
same principal can author every source before reading ledger entries. Stored entries use a fixed,
typed schema: structural/change categories, bounded summaries, plan decision, test identifiers,
outcome, evidence class, error class, revisions, timestamps, and provenance. Raw source, reports,
screenshots, manuals, prompts, target data, filesystem roots, secret references, and credentials are
not ledger fields. Summary filters reject credential patterns and redact host/endpoint and path-like
values.

A capsule states the selected projects, provenance, reason to use, item IDs, and its own fingerprint.
It cannot change file roots, host allowlists, secret authority, import roots, commands, test scope, or
model availability. Detach removes one project's retained items, delete removes selected/all owner
history, and retention applies an owner-selected age limit plus a configured item cap. These changes
produce action-ledger events without copying deleted content into the audit trail.

## Model boundary

Opening Author mode, inventory, history preview, and local planning construct no model client and
make no model call. The sole refinement endpoint requires the exact literal confirmation and current
plan revision. Its payload contains only structured intent, inventory metadata, the selected redacted
capsule, allowed files/validation categories, and a forced response schema. Source contents and secrets are excluded.
The returned proposal is validated against the plan's existing file/validation authority and cannot
weaken or replace the reviewed validation gate. Audit data holds
category fingerprints and proposal metadata, not the sensitive prompt body. Model output is advice;
it cannot apply files or invoke a target.

## Candidate isolation and application

Inventory and candidate copies reject traversal, symlinks, special files, oversized files, excessive
file counts, and source changes detected across no-follow open/read checks. Candidates live in the
private owner state root with private modes. Only safe text types named in the current plan can be
changed. Offline validation is typed, static, and in-process; it never starts a target, runner,
subprocess, model, network request, or credential flow. The deterministic project bundle validates
typed project configuration, every managed specification, the referenced master-manual structure,
JSON/YAML syntax, and exact optional import/composition content manifests when present. Reports list
the components actually run and explicitly state that no project executed.

Apply requires a passing offline-validation report for the exact candidate revision, the exact
ordered category selection bound into the reviewed plan, and an unchanged original
project revision. It copies to a sibling stage, verifies the candidate hash, assigns managed-project
read modes, swaps directories with rollback, and never merges into the existing directory.

## Multi-root composition

Composition reuses configured Project Import roots and their root-ID plus relative-path containment
checks. A preview maps explicit roles (`project-spec`, `specs`, `manual-root`, `assets`, or
`support-files`) into one deterministic manifest with per-file provenance. It rejects traversal,
links/reparse points, special or sensitive types, duplicate source mappings, duplicate destinations,
missing master manual, invalid typed project/spec files, capacity breaches, and an existing slug.
Create consumes the owner-bound preview token, rescans all sources, requires exact revision and slug
confirmation, and atomically publishes a new project only. It never merges or overwrites.

## SSH host-key trust flow

Host-key discovery is disabled by default at deployment configuration. Public requests contain only
expected revision tokens and literal confirmations; route documents, hosts, ports, and allowlists are
forbidden. The server safely reloads current persisted `project.yaml` and makes it the sole authority.
An unsaved browser draft cannot authorize network discovery. Eligibility requires a persisted typed
VNC-over-SSH-jump route, the exact persisted jump host in the persisted SSH allowlist, and matching
server-computed project/route revisions. The route revision includes target type/host/port, jump
host/user/port, and the normalized effective SSH allowlist. The explicit discover command invokes an injectable, one-host transport;
the production adapter uses argv-only `ssh-keyscan`, an exact host/port, fixed key algorithms, a short
timeout, no stdin, and a response-size bound. It does not open VNC, run a target, or use credentials.

Discovery returns an expiring in-memory candidate with algorithm, fingerprint, normalized
`known_hosts` line (`[host]:port` for non-22), and bound project/route revisions. It records metadata,
not key material, in the action ledger. A distinct save command requires the unchanged route,
unchanged project, a reviewed exact-host normalized key line, and a literal confirmation. Candidate
bindings and reviewed content are checked before the in-memory candidate is consumed; malformed,
stale, symlink, or duplicate-name rejection cannot consume an otherwise valid candidate. Save uses
an atomic new-only publish to create a regular reference under the managed secret root with `0600`,
rejects symlinks and existing names, and never overwrites. A successful save is single-use.

Discovery does not establish trust. Runtime SSH continues to use strict host-key checking against
the separately saved reviewed reference. When a destination-locked loopback relay carries TCP, SSH
still names and verifies the original declared jump host; the ProxyCommand does not substitute the
relay identity or put a credential in argv.

## Threats and controls

| Threat | Control |
| --- | --- |
| IDOR or shared-token access | Unique OIDC principal plus server-side project grant on every operation |
| Stale review / TOCTOU | Content-derived revisions, rescan, no-follow reads, and exact confirmation |
| Source mutation before approval | Private candidate copy; original write exists only in explicit apply |
| History privacy leakage | Fixed redacted fields, same-owner authorization, opt-in sources, bounded retention |
| Prompt-driven authority expansion | Metadata-only payload and immutable server-side allowed-file/validation gate |
| Client-selected host / SSRF | Persisted typed project is sole route and allowlist authority; public models forbid policy objects |
| Filesystem escape | Configured roots, normalized relative paths, containment and link/special-file rejection |
| Automatic network trust | Deployment flag plus explicit discover, expiring candidate, separate reviewed save |
| Host-key downgrade through relay | Strict checking against original host identity and saved reference |
| Secret overwrite/exposure | New-only regular file, no symlinks, private mode, no key material in audit |
| Denial through large trees/output | Per-file, total-byte, file-count, timeout, response, and history caps |

## Explicit non-capabilities and residual risks

The feature does not start targets, connect to VNC/RDP/SSH during inspection/planning/validation, run
arbitrary commands or a project, read secret contents, import history as source, or deploy code. Local JSON
state is not a distributed transaction system, administrator grant-file lifecycle remains an operator
responsibility, and host-key fingerprints still require human/out-of-band verification.

R1 includes the narrow source correction for the known VNC relay Bedrock firewall mismatch. When and
only when AWS forwarding is disabled and an active typed target relay was selected, the launcher now
passes `ORCHESTRATOR_EGRESS_EXCLUDE_BEDROCK=1` to match the private-hosts calculation; the existing
container firewall consumes that signal. This does not widen egress or forward credentials. Source
tests cover positive and negative branches, but cannot establish the separately authorized live VNC
gate, which remains unproven.
