# R2K local-app project-mount root cause

## Reproduced facts

The supplied R2J host evidence has SHA-256
`67f0540954623971ff538d7a97071ea12b3a17a27ee18db1cc4a6f95065dd8a9`.
Its typed launch record reached `worker_started`, with both FIFOs ready, before
failing as `project_config_invalid`. The private diagnostic traceback reported
that the selected project was missing `manual_dir`, although the mounted YAML
contained that key.

The selected project was owned by host UID/GID 1003:1004 with modes 0700 on
the specs, project, and manual directories and 0600 on `project.yaml` and
`manual.md`. The container worker permanently runs as UID/GID 10001 without
supplementary groups or DAC-bypass capabilities. It therefore could not read
the mounted YAML. The loader's missing-field report was a downstream symptom
of mount inaccessibility.

The corrected-fixture evidence has SHA-256
`00909648043e1f81eeca6b60a5e0f30ab912261287650fc27fdc665345ea01e0`.
Changing only mounted specs/project/manual directories to 0755 and the YAML
and Markdown files to 0644 produced a complete synthetic pass: exact window
match, 1280x720 initial frame, fixed redaction before return, network none,
and clean container/FIFO teardown.

## R2K correction

`DemonstrationService.connect` now prepares the exact selected project before
calling the capture adapter. Descriptor-based traversal rejects a symlinked
specs root or selected project, permits only an immediate validated project
slug, never follows directory or file symlinks, and verifies stable device and
inode identity after opening each selected object.

Only these modes may change:

- configured specs root: 0755;
- real directories below the selected project: 0755;
- regular YAML, YML, and Markdown files below the selected project: 0644.

Other projects, arbitrary file types, reports, secrets, runtime state,
readiness records, demonstration bundles, and symlink targets remain
untouched. Preparation failure occurs before adapter contact and is recorded
only as the allowlisted pair
`project_mount_preparation/project_mount_unreadable`; the API remains generic.

## Operational image-depth finding

The host also proved that a 128-layer overlay is rejected with `max depth
exceeded`. This is separate from the project-mount defect. R2K includes an
explicit validation-only shallow-overlay helper. It requires an already-local,
reviewed digest-pinned base with at most 114 layers, disables pull and build
network access, preserves and compares runtime configuration, and rejects a
candidate above 120 layers. It never pushes or deploys an image.

The supplied flattened host image is validation evidence only and is not an
approved release image.
