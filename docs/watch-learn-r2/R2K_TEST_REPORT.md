# R2K test report

## Input and host-evidence verification

- R2J review archive SHA-256: PASS —
  `1e85c77fe866512a1c8090530aa6d0399d01fa9147c43fa440df9e74777a82c0`.
- R2J archive structure: PASS — 16 safe members and all internal checksums.
- Exact R2J source reconstruction: PASS — tree
  `4a19386bb9326f17835a20bcda2a37b4d77d20d7`.
- Initial R2J host evidence SHA-256: PASS —
  `67f0540954623971ff538d7a97071ea12b3a17a27ee18db1cc4a6f95065dd8a9`.
- Corrected-fixture evidence SHA-256: PASS —
  `00909648043e1f81eeca6b60a5e0f30ab912261287650fc27fdc665345ea01e0`.

## Reproduced host facts

- Original R2J synthetic run: FAIL at `worker_started/project_config_invalid`;
  both FIFOs ready, no application launch, cleanup completed.
- Corrected readable R2J fixture: PASS — 1280x720, exact ready-window match,
  fixed redaction, network none, and cleanup verified.
- Validation overlay depth: 128 layers rejected; flattened validation image
  passed. The flattened image is not a release image.

## R2K source results

- Focused R2K suite: PASS — 13 passed.
- Phase 17, direct-interaction, readiness, R2J diagnostic, and R2K focused
  suites: PASS — 121 passed, 1 skipped.
- Complete Python suite: PASS — 755 passed, 1 skipped, 32 warnings.

The single skip is the inherited root/UID-separated entrypoint proof when the
development environment cannot provide the required identity mappings.

JavaScript, browser-support, syntax, whitespace, browser, runtime, and final
reconstruction results are recorded in the review package generated from this
source tree.

## Runtime disposition

- Real R2K container acceptance: ENVIRONMENTALLY EXCLUDED in the development
  environment; Docker/Podman is unavailable.
- Corrected R2K synthetic host acceptance: NOT PERFORMED here. The included
  attended wrapper is required on the validation host.
- Non-synthetic target acceptance: NOT PERFORMED.
- Functional source-repair claim: true for the proven mount-readability defect.
- Release-readiness claim: false until reviewed host R2K acceptance passes.
