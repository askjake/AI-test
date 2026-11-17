# Phase 16R security notes

Phase 16 authentication and OIDC controls in `docs/phase16/SECURITY.md` remain
in force. Phase 16R adds these invariants:

- Python 3.14 and unsupported explicit overrides are rejected before installer
  logic or managed-environment creation.
- The dashboard, runner image, target path, and AWS/model access remain separate
  gates; doctor is target/model/IdP free.
- Jump route fields are server-validated typed data and are part of the
  revision used by preflight TTL checks.
- SSH jump execution uses a literal argv, ProxyJump, strict host-key checking,
  an explicit clone-local known-hosts file, and exact target/jump allowlists.
- `StrictHostKeyChecking=no`, shell-composed ProxyCommand strings, credential
  URLs, generic RDP/VNC jumps, and direct-route fallback are prohibited.
- Known-hosts files, private keys, passwords, passphrases, tokens, cookies,
  OIDC secrets, and AWS credentials never belong in project YAML, browser
  storage, URLs, logs, reports, screenshots, Git, release archives, or model
  context.
- Target editing, validation, saving, and route-state rendering are local-only.
  Preflight is a separate explicit Operator mutation.

Native macOS and Windows wrapper execution remains a bounded acceptance item;
the selection policy and source paths are deterministically tested on Linux.
No real IdP, target, jumpbox, model, engine, firewall, proxy, certificate, DNS,
or tunnel was configured or contacted during implementation.
