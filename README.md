# Orchestrator Cookie — AI Desktop Test Runner

> Current cross-platform installation, sign-in, and target-route guidance is in
> [`docs/phase16r/OPERATOR_GUIDE.md`](docs/phase16r/OPERATOR_GUIDE.md). For a
> normal installation run `./install.sh doctor && ./install.sh init` on
> macOS/Linux, or `.\\install.ps1 doctor` followed by `.\\install.ps1 init` on
> Windows. Developers add `--with-test` to `init` only when validating source.
> Operator setup and use of the optional project-folder importer is documented
> in [`docs/project-import/OPERATOR_GUIDE.md`](docs/project-import/OPERATOR_GUIDE.md).

A scheduled, sandboxed agent that runs **plain-English Markdown test specs** against
GUI / terminal / remote-desktop targets using **Claude Computer Use via AWS Bedrock**,
driving everything by vision (screenshots) + `xdotool`, and emitting **HTML reports** with
per-step screenshots and a reasoning log.

End users write **no scripts** — a test is a Markdown file describing a goal and a list of
assertions in English. Specs are grouped into **projects**, each with its own optional
config and cron schedule. The agent runs inside an isolated, hardened Docker container;
an explicitly enabled `host-app` bridge can launch an allowlisted GUI program as the host
user while still presenting its window on the container's isolated virtual display.

## How it works

Every target type is just **a window on the same Xvfb virtual display**, driven by one
vision loop:

```
screenshot → Claude returns a tool_use action → execute via xdotool → new screenshot → repeat
            until Claude calls report_result, or a resource cap is hit
```

The five target types differ *only* in which window is focused:

1. **`local-app`** — a Linux GUI app installed inside the runner image.
2. **`host-app`** — an explicitly allowlisted app such as `~/JAMboree/BOOM.sh`, executed
   as the host user and rendered into the run's Xvfb.
3. **`ssh-terminal`** — an `xterm` running `ssh` to a remote host (SSH happens *from inside* the container).
4. **`rdp`** — an `xfreerdp` window connected to an **existing** remote Windows machine.
5. **`vnc`** — an `xtigervncviewer` window connected to an **existing** remote VNC server.

## Critical constraint

Claude is called **exclusively** through `bedrock-runtime` (boto3 `invoke_model`). The
direct Anthropic API is banned — there is **no `anthropic` SDK import and no
`api.anthropic.com` call anywhere**. AWS credentials use the standard credential chain
(env / role / profile). Secrets (SSH keys, RDP passwords) live in a read-only `secrets/`
mount and are handed to client processes only — **never typed by Claude, never on-screen**.

---

## Supported local bootstrap

```bash
./install.sh doctor
./install.sh init
./install.sh access --role operator --copy
```

On Windows PowerShell:

```powershell
.\install.ps1 doctor
.\install.ps1 init
.\install.ps1 access --role operator --copy
```

The wrappers select Python 3.13, 3.12, or 3.11 deterministically and reject
Python 3.14. Set `ORCHESTRATOR_PYTHON` to an approved absolute interpreter path
when platform discovery needs an explicit choice. The dashboard remains local;
remote target connectivity is configured separately in the Project Builder.

### Packaged local OIDC test identity

Linux installations can provision a self-contained, explicitly test-only Keycloak login
for role and Watch & Learn testing. It uses generated per-clone credentials and TLS,
digest-pinned images, a declarative realm import, an exact dashboard backend port of 8025,
and sequential one-time selection for occupied HTTPS ports:

```bash
./install.sh stop
./install.sh local-oidc provision --public-host '<dashboard-host-or-ip>' --yes
./install.sh start
./install.sh local-oidc access --role operator --copy
```

Open the printed HTTPS `OIDC URL`. This local provider is not corporate SSO and must not
be internet-exposed. See
[`docs/local-oidc/OPERATOR_GUIDE.md`](docs/local-oidc/OPERATOR_GUIDE.md) for certificate
trust, lifecycle, safety, and corporate-provider separation.

Developer validation uses the same clone-local environment:

```bash
./install.sh init --with-test
PYTHONPATH=src .orchestrator-cookie/venv/bin/python -m pytest -q
```

Direct module checks are diagnostic only and do not replace initialization:

```bash
export PYTHONPATH=src

# Config smoke — prints the resolved settings
.orchestrator-cookie/venv/bin/python -c "from orchestrator.config import settings; print(settings)"

# Bedrock connectivity is an explicit separately authorized action
export BEDROCK_MODEL_ID="<your inference-profile ARN or model id>"
export AWS_REGION="us-west-2"
.orchestrator-cookie/venv/bin/python scripts/smoke_bedrock.py
```

Running a full test requires the virtual display and target tooling (`xvfb`, `xdotool`,
`xterm`, `ssh`, `xfreerdp`, `xtigervncviewer`). The supported way to run the agent end-to-end is **inside the
container** (see [Build & run the container](#build--run-the-container)).

---

## Organizing specs into projects

A **project** is an immediate sub-directory of `tests_specs/`. Specs are collected
recursively (`<project>/**/*.md`). Any `*.md` left directly in the `tests_specs/` root
belongs to an implicit `default` project.

```
tests_specs/
├─ project.yaml          # OPTIONAL root defaults shared by all projects
├─ checkout/             # the "checkout" project
│  ├─ project.yaml       # per-project config (REQUIRED: manual_dir)
│  ├─ example_local.md
│  └─ example_ssh.md
└─ backups/
   ├─ project.yaml
   └─ example_rdp.md

tests_manuals/           # established external-manual layout remains supported
└─ checkout/             # the "checkout" project's manual (path set in its project.yaml)
   ├─ manual.md          # master manual, always injected into the planner
   └─ services/          # topic pages, loaded on demand by the planner
      └─ 100-create.md
```

A project is **skipped** if its `project.yaml` sets `enabled: false`. Existing projects
continue to point `manual_dir` at an operating-manual directory outside the spec tree.
Imported portable project folders use the narrowly defined `manual_dir: ./manual` form;
the project loader resolves only that exact form relative to the owning project and never
walks the `manual/` subtree as specifications. See [Operating manual](#operating-manual)
and the [project-folder import guide](docs/project-import/OPERATOR_GUIDE.md).

The importer also recognizes the established split repository layout when a selected
`tests_specs/<project>` folder names a relative `tests_manuals/<project>` directory inside
the same configured import root. It applies the same no-link, containment, size, freshness,
and sensitive-file checks to that manual tree, then publishes a self-contained managed
copy with `manual_dir: ./manual`. Absolute and parent-relative legacy paths remain denied.

New projects created from the dashboard's guided builder atomically receive a project
document, starter specification, and managed `manual.md`. The retained Phase 12
compatibility API now uses that same transaction; when its local-app command is omitted,
it selects the runner-packaged `xmessage` smoke target instead of the unavailable legacy
`xterm` default. Watch & Learn still requires an explicit ready-window title and reviewed
fixed-region redaction in the guided form.

---

## Writing a spec

A spec is a Markdown file with three sections (`## Setup` is optional). It does **not** declare
a target — the project's single target lives in `project.yaml` (see below). Copy
[`tests_specs/TEMPLATE.md`](tests_specs/TEMPLATE.md) to start.

```markdown
# Test: Verify nightly backup ran on build01

## Goal
Connect to the build server over SSH and confirm today's backup completed and the backup
service is healthy. Drive the terminal entirely by what you see on screen.

## Setup
The SSH session opens at the home directory.

## Assertions
- A backup file dated today is present in /var/backups.
- `systemctl status backup.service` reports the service as "active".
```

A spec that still carries a `## Target` section is a **load error** — declare the target once
in `project.yaml` instead.

### Goal & Assertions

- **Goal** — plain English describing what the agent should accomplish in the focused window.
- **Assertions** — a bullet list; each is evaluated independently and reported pass/fail
  with screenshot evidence.

---

## Operating manual

A spec says **what** to verify; the project's **operating manual** carries **how** to drive the
app (buttons, fields, dialog flow, UI quirks). Keep it **outside** the spec tree and point the
project's `project.yaml` at it with a **required** `manual_dir` (a path relative to the repo
root, or absolute):

```
tests_specs/checkout/
├─ project.yaml                    # manual_dir: tests_manuals/checkout
└─ 00-login.md ...                 # the specs

tests_manuals/checkout/            # the manual dir named by manual_dir
├─ manual.md                       # master — always injected into the planner
├─ 001-launch-and-login.md         # topic pages, loaded on demand
├─ management/010-refresh.md
└─ services/100-create.md
```

How it works:

- **`manual_dir` is required** in every project's `project.yaml`, and the directory it names
  **must** contain a master `manual.md`. A missing `manual_dir`, or one pointing at a directory
  with no `manual.md`, aborts the project run at config load with a clear error.
- **`manual.md` is injected automatically** into every spec's planner prompt — you do **not**
  name it (or any manual file) in a spec. Keep it lean: the app's layout, global UI quirks, and
  a **table of contents** linking the topic pages by path.
- **Topic pages are loaded on demand.** The planner reads `manual.md`'s table of contents and
  calls a `read_manual_page` tool with a page's path (e.g. `services/100-create.md`) only when
  it needs that page's detailed procedure. So the manual can grow large (100+ files) without
  bloating context — only the pages actually needed for a run are ever loaded.
- **The manual directory is never run as specs** — it lives outside `tests_specs/`, and its
  `*.md` files are operating docs, not tests.
- Specs **do not** declare which manual pages they need; there is no `## Manual` section. (A
  stray `## Manual` section in a spec is simply ignored.)

Write `manual.md`'s table of contents as a Markdown link list — the link paths are exactly what
the planner passes to `read_manual_page`:

```markdown
## Manual
* [Launch and login](001-launch-and-login.md)
* Management
  * [Refresh the GUI](management/010-refresh.md)
* Services
  * [Create service](services/100-create.md)
```

A page path that escapes the manual directory (a `..` or absolute path) is refused, so the
planner can only read files inside the manual tree.

---

## Configuring hosts, secrets & per-project `project.yaml`

### Secrets

Place SSH keys and RDP/VNC password files under `secrets/` (mounted read-only). Reference them
by filename from the project's `target:` block (e.g. `key: build01_id_ed25519`,
`password_file: winbox01.pass`) — only the path is passed to the client process; the secret
value is never typed by Claude or shown on screen. **No secret value ever goes into
`project.yaml` or a spec.** The gateway SSH password for a tunnelled VNC target is fed to `ssh`
via `sshpass -f <path>` (a headless container has no TTY for ssh's interactive prompt);
`sshpass` ships in the container image. Project Builder saves the gateway password and a
trusted, out-of-band-reviewed OpenSSH host-key line through separate write-only controls;
the YAML contains only their owner-only reference filenames.

### Host allowlists

`ssh-terminal` / `rdp` / `vnc` targets are refused unless the host is in the effective
allowlist. Allowlists are set globally (env) or per project. Configure the global default via env:

```bash
export SSH_HOST_ALLOWLIST="build01,build02"   # comma-separated or JSON list
export RDP_HOST_ALLOWLIST='["winbox01"]'
```

### `project.yaml`

Effective config is merged in this order (later wins):

```
global config.py defaults  ←  tests_specs/project.yaml (root)  ←  tests_specs/<project>/project.yaml
```

Allowlists **replace** (not merge) the inherited list. Copy
[`tests_specs/project.yaml.template`](tests_specs/project.yaml.template) to start.
Recognized keys (**no secrets**; `manual_dir` is required, the rest optional):

| Key | Meaning |
|-----|---------|
| `name` | Display name (defaults to the directory name). |
| `manual_dir` | **Required.** Path (relative to the repo root, or absolute) to the project's operating-manual directory, which must contain a master `manual.md`. Kept outside the spec tree. See [Operating manual](#operating-manual). |
| `target` | The project's single target — a mapping of `type` (one of `local-app` / `host-app` / `ssh-terminal` / `rdp` / `vnc`) plus connection params (see the per-type table below). Opened once for the whole spec tree. |
| `ssh_host_allowlist` / `rdp_host_allowlist` / `vnc_host_allowlist` | **Replace** the inherited allowlists. |
| `max_steps` / `max_seconds` / `max_tokens` / `max_total_tokens` | Override resource caps. |
| `keep_last_n_screenshots` | How many recent screenshots stay as real images in the prompt; older ones become a text placeholder to bound input-token growth (default 3). |
| `schedule` | Cron expression for this project (falls back to `default_cron`). |
| `enabled` | `false` skips the project entirely. |

The `target:` block by type (params other than `type` are passed straight to the client):

| Type | Params | Notes |
|------|--------|-------|
| `local-app` | `app: <launch cmd>`, `window: <window name>` | Launches/focuses an app installed inside the runner image. |
| `host-app` | `app: <allowlisted host path>`, `cwd:`, `window:`, `startup_timeout:` | Launches an app as the host user and renders it into the run's isolated Xvfb. Requires `HOST_APP_ENABLED=1` and `HOST_APP_ALLOW_ROOTS`; supported by single-project dashboard/`run_specs.sh` runs. |
| `ssh-terminal` | `host:`, `user:`, `key: <file in secrets/>` | `host` **must** be in the effective `ssh_host_allowlist`. |
| `rdp` | `host:`, `user:`, `password_file: <file in secrets/>` | `host` **must** be in the effective `rdp_host_allowlist`. |
| `vnc` | `host:`, `port:` (optional), `password_file: <file in secrets/>` | `host` **must** be in the effective `vnc_host_allowlist`. `password_file` is a `vncpasswd`-format file. |
| `vnc` (tunnelled) | adds `via: user@gateway`, `gateway_password_file: <file in secrets/>` | The viewer SSHes into `via` and reaches `host` from there. The gateway host **must** be in `ssh_host_allowlist`; `gateway_password_file` is **required** with `via`. |

A target host not in its allowlist is refused **before any connection** is attempted.

All settings (model id, region, caps, display size, paths, `default_cron`) read from the
environment first — see `src/orchestrator/config.py` for the full list and defaults.

---

## Hierarchical sessions

Every project runs as a hierarchical session, so **a project is one target**: all of its specs
run against ONE target that is opened once and closed once. This suits targets where the
expensive part is **connecting / logging in / launching the app** and you want a suite of small
tests against the same live session. Concretely:

- The target is **opened once** before the spec tree is walked and **closed once** after — no
  spec re-connects or re-logs-in.
- Specs run **depth-first** over the directory tree (sorted): specs directly in a directory
  before descending into its subdirectories. Name them for order, e.g. `00-login.md`,
  `records/10-create.md`, `records/20-search.md`.
- Each spec still runs in its **own fresh agent context** with its own `max_total_tokens`
  budget — so a long suite never overflows a single context. The only thing carried across is
  a **compact digest** (a few lines per prior spec: title + pass/fail + an `ending_state` the
  agent reports), seeded into the next spec's system prompt so it knows the app's current
  state. Later siblings see earlier siblings' outcomes (accumulate).
- Reports: every spec emits its own `report.html` (linked from the run dashboard), and the
  run report grows a **"Session summary"** panel — the rolled-up digest — plus directory
  group sub-headings.

Works for **any** target type (`local-app` / `host-app` / `ssh-terminal` / `rdp` / `vnc`). The first
(mother) spec performs the connect/login/launch; children assume that state. Requirements and
conventions:

- Set the project's one target in `project.yaml`'s `target:` block. Specs carry no target; a
  spec containing a `## Target` section is errored on its own (siblings still run).
- For network targets, set the matching allowlist (`ssh_host_allowlist` / `rdp_host_allowlist`
  / `vnc_host_allowlist`); `local-app` needs none.
- For a `host-app`, explicitly enable the host bridge and allowlist one or more application
  roots in the dashboard environment. The bridge executes argv directly (never through a
  shell), rejects executable/cwd symlink escapes, and terminates the host process group with
  the container run:

  ```bash
  HOST_APP_ENABLED=1
  HOST_APP_ALLOW_ROOTS=/absolute/path/to/approved/application/root
  ```
- Each child's Goal should navigate back to a known starting screen (or known directory for
  `ssh-terminal`), so it is robust to where the previous spec left the session.
- The digest is model-authored prose about app **state** — author specs so credentials are
  never echoed into `ending_state`.

If the target fails to open, every remaining spec is recorded `errored` with the session
error rather than silently skipped.

Example `project.yaml` `target:` blocks per type:

```yaml
# local-app
target: {type: local-app, app: "myapp --no-sandbox", window: MyApp}
# host-app (the executable and cwd must resolve inside HOST_APP_ALLOW_ROOTS)
target: {type: host-app, app: "~/JAMboree/BOOM.sh", cwd: "~/JAMboree", window: JAMboree, startup_timeout: 90}
# ssh-terminal
target: {type: ssh-terminal, host: build01, user: ci, key: ci_id_ed25519}
# rdp
target: {type: rdp, host: win-test, user: tester, password_file: rdp_pw}
# vnc
target: {type: vnc, host: vnc-host, password_file: vnc_pw}
```

The full design rationale is in [`HIERARCHICAL-CONTEXT-DESIGN.md`](HIERARCHICAL-CONTEXT-DESIGN.md).

---

## Running tests

```bash
export PYTHONPATH=src

# Run one spec
python -m orchestrator.runner tests_specs/checkout/example_local.md

# Run a whole project (all its specs)
python -m orchestrator.runner --project checkout

# Scheduler one-shot: run every enabled project once and exit (for external cron/systemd)
python -m orchestrator.scheduler --once

# One-shot, single project
python -m orchestrator.scheduler --once --project checkout

# Long-running scheduled mode: one cron trigger per enabled project, runs in the foreground
python -m orchestrator.scheduler
```

Each project's `schedule` (or `default_cron`, e.g. `0 2 * * *`) drives the long-running
mode. Use `--project <name>` to narrow either mode to a single project.

The commands above run the agent directly on the host, which needs the full GUI stack
(`xvfb`, `xdotool`, `xterm`, `ssh`, `xfreerdp`, `xtigervncviewer`) installed locally. In practice you run specs
**inside the container** via [`scripts/run_specs.sh`](#run_specssh--the-convenient-way-to-run-specs),
which provides that stack and handles AWS creds + model selection for you.

---

## Reading reports

A run writes a self-contained static report tree under `reports/`:

```
reports/
├─ index.html                  # top-level: lists every project
└─ <project>/
   ├─ index.html               # this project's run history
   └─ <run_ts>/
      ├─ report.html           # per-run dashboard (pass/fail + step log)
      └─ <test_slug>/
         ├─ result.json        # structured result
         ├─ audit.jsonl        # full action + model-response log
         └─ *.png              # per-step screenshots
```

- Open `reports/index.html` for the project list.
- A per-run `report.html` shows, for each test: a pass/fail badge, per-assertion results,
  and an expandable **step log** — reasoning text + action + screenshot thumbnail for every
  step. Screenshots for click/mouse actions are annotated with a **red rounded-rectangle
  around the action point**, so a reader sees exactly where the agent acted (the marker is
  drawn only on the report copy — the image sent to Claude stays clean). Screenshots are
  referenced relatively, so the tree can be copied/served as-is.

---

## Build & run the container

The container provides the virtual display and all target tooling, and runs with the full
Phase 8 isolation contract. See [`docker/docker-run.md`](docker/docker-run.md) for details.

```bash
# Build (podman or docker)
podman build -f docker/Dockerfile -t orchestrator:latest .

# Run hardened (read-only root FS and least-privilege bootstrap capabilities).
# Pass any runner/scheduler args after the image name.
AWS_REGION=us-west-2 BEDROCK_MODEL_ID="<model id>" \
  ENGINE=podman IMAGE=orchestrator:latest scripts/run_container.sh --once
```

The fixed application mounts are `reports/` (rw), `tests_specs/` (ro),
`tests_manuals/` (ro), and `secrets/` (ro). When configured, the launcher also
mounts only the containing directories for the selected AWS credentials/config
files so the entrypoint can stage private rotating copies. Outbound traffic is
default-DROP except the exact approved TCP ports for Bedrock and allowlisted
SSH/RDP/VNC hosts. Names are resolved before the policy is installed and target
addresses are pinned in a private per-run `/etc/hosts` file. On Linux, Bedrock TLS and the
one selected VNC transport use separate authenticated, destination-locked host relays so
Docker can follow host VPN/proxy routes without host networking or a broader allowed
destination. Direct VNC locks the relay to the VNC socket. VNC-over-SSH locks it to the
jump-host SSH socket while OpenSSH still verifies the original jump-host identity and owns
the onward local forward. The container independently recomputes both approved contracts
before general DNS and IPv6 egress are blocked. Docker Desktop retains direct
pinned-address egress through its VM.

### `run_specs.sh` — the convenient way to run specs

`scripts/run_specs.sh` wraps `run_container.sh` for the common case of running specs. It
takes care of the two things a run needs from the host: it resolves AWS credentials from the
standard chain and sets `BEDROCK_MODEL_ID` (falling back to the explicitly configured
`$ANTHROPIC_DEFAULT_SONNET_MODEL`). There is no baked-in account-specific model fallback.
What runs depends on the argument:

```bash
# No argument: run every enabled project once (scheduler --once)
scripts/run_specs.sh

# A project name: run all specs in that project
scripts/run_specs.sh mul

# A spec file path: run that single spec
scripts/run_specs.sh tests_specs/mul/connection_test.md
```

The argument is treated as a **spec file** if it ends in `.md` or names an existing file,
otherwise as a **project name**. Override the model with `BEDROCK_MODEL_ID=…` or the engine
with `ENGINE=docker`. Prerequisites: a built `orchestrator:latest` image, valid AWS
credentials (run the `aws-login` skill or `aws sso login` first), and the container engine
running.

---

## Troubleshooting

### Bedrock auth / connectivity

- `python scripts/smoke_bedrock.py` is the fastest check that Claude is reachable. It sends
  a tiny message with the computer tool and asserts a `tool_use` comes back.
- **`UnrecognizedClientException` / expired token** — refresh AWS credentials (this repo's
  `aws-login` skill, `aws sso login`, or your usual mechanism). Creds come from the standard
  chain; confirm `AWS_REGION` matches the region your inference profile lives in.
- **`AccessDeniedException`** — the role/profile lacks `bedrock:InvokeModel` on the model
  ARN, or the inference profile isn't enabled in that account/region.
- **`ResourceNotFoundException`** — `BEDROCK_MODEL_ID` is wrong for the region. Use the
  inference-profile ARN, not a bare foundation-model id, when the company profile requires it.

### Computer-use beta rejected

- The default native contract is the Sonnet 4.6 pair `computer_20251124` and
  `computer-use-2025-11-24`. The legacy `computer_20250124` and
  `computer-use-2025-01-24` pair remains available only when both values are explicitly
  configured. Mismatched or unreviewed pairs fail before a model call.
- The project defaults to `computer_tool_mode=auto`, which tries `beta` first and
  transparently falls back to a plain **`custom`** computer tool when an inference profile
  rejects native computer use. If you see a beta/tool `ValidationException`, this fallback
  handles it — no action needed.
- To skip the failed beta attempt entirely, set `COMPUTER_TOOL_MODE=custom`.
- Custom mode lacks computer-use fine-tuning, so click accuracy is weaker — budget more
  steps (`MAX_STEPS`) for complex specs.

### `max_total_tokens (...) budget exceeded`

- Each step sends a screenshot, and the cumulative token budget (`MAX_TOTAL_TOKENS`) covers
  the **whole run**. To keep input from growing every step, only the most recent
  `keep_last_n_screenshots` (default 3) are kept as real images — older ones are replaced with
  a text placeholder. Lower this if runs still exhaust the budget, or raise `MAX_TOTAL_TOKENS`.
- Prompt caching (`ENABLE_PROMPT_CACHING`, default on) caches the static system+tools prefix
  **and** rolls a `cache_control` breakpoint over the frozen message-history prefix of the
  text-only planner, so its append-only conversation is re-read from cache instead of re-billed
  as fresh input each turn. This keeps the planner's `MAX_TOTAL_TOKENS` budget growing linearly
  (not quadratically) with session length. Set it `false` if an inference profile rejects
  `cache_control`.

### Display issues

- **`Can't open display :1`** — Xvfb isn't up. Inside the container, `entrypoint.sh` starts
  `Xvfb :1` and the window manager before the runner; check its logs. Locally, you need your
  own Xvfb (`Xvfb :1 &; export DISPLAY=:1`).
- **Blank or misaligned screenshots / clicks land off-target** — the native Xvfb resolution
  (`SCREEN_W`/`SCREEN_H`, default 1280×800) and the model-space resolution (`MODEL_W`/`MODEL_H`,
  default 1280×800) are independent: screenshots are downscaled to model space and clicks are
  scaled back up to native. Keep model space at/below ~1280×800 for click accuracy.
- **Window never focuses** — for `local-app`, the `window=` name must match what
  `xdotool search --name` finds. For `host-app`, also check `reports/host-app.log`, confirm
  `HOST_APP_ENABLED=1`, and ensure the real executable and `cwd` resolve beneath
  `HOST_APP_ALLOW_ROOTS`. A top-level `volumes:` block is not used for host apps because the
  program already executes directly on the host. For `ssh`/`rdp`/`vnc`, the connection may have failed (check the
  allowlist and that the secret file exists under `secrets/`).

### Tests don't run / project skipped

- A project with `enabled: false` is skipped silently — check its `project.yaml`.
- A non-allowlisted `ssh`/`rdp`/`vnc` host is **refused at spec load**; add it to the effective
  allowlist.

---

## Project layout

See `PROJECT-PLAN.md` for the full architecture and 10-phase build plan, `TEST-CASES.md`
for per-phase test cases, and `CHECK-LIST.md` for the per-phase exit-gate checklist.
