# Phase 16R operator guide

Run commands from the clone root. The installer does not install Python,
Homebrew, a package manager, Docker Desktop, Docker, or Podman.

## Normal user installation

Linux or macOS:

```sh
./install.sh doctor
./install.sh init
```

Windows PowerShell or Command Prompt:

```powershell
.\install.ps1 doctor
.\install.ps1 init
# Command Prompt may use: install.cmd doctor / install.cmd init
```

If discovery needs an explicit supported interpreter:

```sh
ORCHESTRATOR_PYTHON=/absolute/path/to/python3.13 ./install.sh init
```

```powershell
$env:ORCHESTRATOR_PYTHON = 'C:\Approved\Python313\python.exe'
.\install.ps1 init
```

On macOS with Homebrew already installed, the actionable path is:

```sh
brew install python@3.13
export ORCHESTRATOR_PYTHON="$(brew --prefix python@3.13)/bin/python3.13"
./install.sh init
```

Without Homebrew, install the approved Python 3.13 macOS package through the
organization's supported route, set `ORCHESTRATOR_PYTHON` to its absolute
`python3.13` path, and rerun `init`. Python 3.14 is not accepted.

## Developer validation

Developer and release validation is a separate profile:

```sh
./install.sh init --with-test
PYTHONPATH=src .orchestrator-cookie/venv/bin/python -m pytest -q
```

On Windows use `.orchestrator-cookie\venv\Scripts\python.exe` and set
`$env:PYTHONPATH = 'src'`.

## Sign in and local recovery

Normal users open the reported dashboard URL and choose **Sign in with
organization account** when OIDC is configured. The clone owner may use local
bootstrap recovery without displaying a credential:

```sh
./install.sh access --role viewer --copy
./install.sh access --role operator --copy
./install.sh access --show-path
```

Paste a copied value only into **Local bootstrap access** on `/sign-in`.
`--show-path` displays only the private file location. If clipboard support is
unavailable, the command stops without printing a credential.

## Connection path

The dashboard stays local. In Project Builder, choose **Direct** or **Via
approved jump host** under **Connection path**. Jump routing supports SSH terminal and
VNC targets. SSH terminal uses strict `ProxyJump`; VNC uses a loopback-only SSH local
forward. On Linux this remains valid when the jump host is reachable only through a host
VPN: the runner uses a destination-locked host relay for the outer SSH socket and still
checks the original jump-host key. For VNC, save the VNC password and gateway password separately, paste a trusted
known-hosts line obtained out of band into the write-only host-key control, retain the
gateway in the SSH allowlist and the VNC endpoint in the VNC allowlist, then validate the
draft and review the route state.

Route states mean:

- `unconfigured`: required typed route fields are missing or unsupported;
- `configured-but-unprobed`: local fields exist, but server static readiness has not run;
- `preflight-ready`: static policy passed; no target has been contacted;
- `verified-current`: explicit preflight verified transport for this exact revision and TTL.

Only an Operator selecting **Test target now** initiates bounded target
activity. Do not use it until the target/jump details and authorization are
approved.

## Layered doctor output

```sh
./install.sh doctor
```

Dashboard bootstrap can be ready while Docker/Podman, runner image, target, or
AWS/model gates remain blocked. Doctor never contacts a target, IdP, or model,
pulls an image, creates a tunnel, changes a firewall, or starts project work.
