# Hardened container run (Phase 8)

The image is built to run with least privilege. The intended launch is
`scripts/run_container.sh`, which applies the full Phase 8 isolation contract.

## Isolation contract (P8-1, P8-8)

`scripts/run_container.sh` runs the image with:

- `--read-only` — the root filesystem is read-only. Writable state lives only on tmpfs
  (`/tmp`, `/home/orchestrator`) and the `reports/` volume. `entrypoint.sh` creates Xvfb's socket
  dir and the WM's HOME under those tmpfs paths, so startup works unchanged.
- `--network=bridge` gives every runner its own network namespace. A per-run,
  non-sensitive hosts file is mounted read-only at `/etc/hosts` so the bounded
  firewall bootstrap can consume already-resolved allowlisted destinations before
  DNS is blocked. The trusted host launcher computes the same reviewed endpoint
  policy, resolves it through the host network, validates every IPv4/hostname pair,
  and seeds that private file. This supports hosts whose VPN DNS is unavailable in
  a Docker bridge. On Linux, Bedrock traffic additionally uses a short-lived HTTP CONNECT
  relay bound only to the bridge gateway. The relay requires an unguessable per-run
  credential, accepts only the exact regional Bedrock hostname on TCP 443, and
  connects through the host's pinned addresses or configured HTTPS proxy. TLS and
  SigV4 remain end-to-end between the non-root runner and AWS. The firewall permits
  the relay socket instead of direct Bedrock destinations, and the relay, credential,
  and private hosts file are removed immediately after the run. Docker Desktop hosts retain
  the direct pinned-address path because their bridge is owned by the desktop VM.
  `--cap-drop ALL` is followed by `NET_ADMIN` and four bounded bootstrap capabilities:
  `DAC_READ_SEARCH`, `CHOWN`, `SETUID`, and `SETGID`. They let the root entrypoint read the
  owner-only source files, assign the private copies, apply the network policy, and
  permanently become uid 10001.
  The workload starts only after that uid/gid transition, with those capabilities cleared.
- Watch & Learn capture and its target-free self-test retain `DAC_OVERRIDE` only for the
  bounded root bootstrap so it can create the `0600` FIFO endpoints inside the validated
  host-owned `0700` control directory. Those modes have `--network=none` and do not receive
  `NET_ADMIN`. Every bootstrap capability is cleared by the permanent uid/gid transition
  before the worker workload starts.
- `--security-opt no-new-privileges`.
- Starts in the bounded bootstrap as root and runs Xvfb, target clients, and all agent/model
  code as the non-root `orchestrator` user (uid 10001).

## Mount surface (P8-1)

Normal execution has four fixed application mounts:

| Host path         | Container path        | Mode |
|-------------------|-----------------------|------|
| `reports/`        | `/app/reports`        | rw   |
| `tests_specs/`    | `/app/tests_specs`    | ro   |
| `tests_manuals/`  | `/app/tests_manuals`  | ro   |
| `secrets/`        | `/app/secrets-source` | ro   |

The host secret tree remains owner-only (`0600` files). At startup, the bounded root bootstrap
copies regular non-symlink files into a private `/app/secrets` tmpfs (`0700` directories,
`0400` files), assigns them to uid 10001, and permanently drops privileges before Xvfb,
target clients, or agent code starts. The original host modes are never weakened.

Short-lived AWS credentials use a separate rotating-file bridge. The host launcher resolves
`ORCHESTRATOR_AWS_CREDENTIALS_FILE`, `~/aws/credentials[/credentials]`, the SDK's configured
file, or `~/.aws/credentials` (in that order), mounts only its containing directory read-only,
and never forwards frozen dashboard credential values when a file is available. A fixed
capability-limited helper mirrors only `credentials` and optional `config` into the private
AWS tmpfs as `0400`. Atomic host replacements are detected. If Bedrock reports an expired
token, the client creates a new boto3 Session and retries against the refreshed copy.

When configured, the credentials file's containing directory and optional AWS
config directory are additional read-only bootstrap mounts. Only their selected
files are copied into `/app/aws-runtime`; the workload receives the private
copies. Watch & Learn capture mounts specs, manuals, and the secret source
read-only, but deliberately omits reports and every AWS source/environment value. Local-app
capture uses no network. Typed VNC-over-SSH capture enables the private bridge and firewall
only for the selected project's SSH gateway and excludes Bedrock and the direct VNC endpoint.

`tests_manuals/` holds each project's operating manual (named by `manual_dir` in its
`project.yaml`), kept outside the spec tree; it is mounted read-only like the specs.

AWS credentials are staged from an explicitly resolved file when available,
with environment credentials retained only as a role-based fallback. They are
never baked into the image or written to `project.yaml`.

## Egress allowlist (P8-2)

Outbound traffic is default-DROP except authenticated bridge-gateway relays for the exact
regional Bedrock runtime endpoint and, on Linux, the selected VNC project's exact transport.
Other target types retain exact direct ports for their allowlisted hosts.
Approved names are resolved by the host launcher and target addresses are pinned in the
private container hosts file before startup; general DNS and IPv6 egress remain blocked.
This blocks exfiltration and, critically, any accidental call to
the banned Claude Cloud endpoint `api.anthropic.com`.

The entrypoint applies it inside the private container network namespace, as root, before
dropping privileges or starting the workload:

```sh
# allowed hostnames come from: python -m orchestrator.egress
docker/egress_firewall.sh
```

The allowlist is computed independently by `orchestrator.egress` in both launch layers
(Bedrock for the configured region + the selected project's effective route when a project
is named, otherwise the union of enabled projects). The host resolves and pins its results.
The container recomputes the hostname/port policy, verifies each relay against the selected
project, replaces the selected VNC transport's direct rule with only the target-relay socket,
and installs direct firewall rules only for remaining approved entries from the private file.
The target relay accepts a per-run credential and has no client-selected destination. For an
SSH-jump VNC route it terminates only the outer TCP reachability gap; strict OpenSSH
host-key verification and the loopback local forward remain inside the runner. Extra
host-file entries cannot widen the enforced network policy, and the Bedrock relay rejects
every non-Bedrock CONNECT authority.

## Verify the gate (P8-GATE)

Inside the running, hardened container:

```sh
python scripts/smoke_security.py          # full checklist incl. egress reachability
python scripts/smoke_security.py --no-net # skip live egress legs (keep allowlist checks)
```

It checks: non-root, read-only `tests_specs/`, `tests_manuals/` and the source-secret bind,
private runtime secrets, writable `reports/`, egress
allowlist (Bedrock reachable; `api.anthropic.com` + arbitrary host blocked), the screenshot
redaction hook, that no secret reaches the audit log, and that resource caps fire on a
deliberately looping spec.

## Example

```sh
podman build --tls-verify=false -f docker/Dockerfile -t orchestrator:latest .
AWS_REGION=us-west-2 BEDROCK_MODEL_ID=us.anthropic.claude-sonnet-4-6 \
  ENGINE=podman IMAGE=orchestrator:latest scripts/run_container.sh --once
```
