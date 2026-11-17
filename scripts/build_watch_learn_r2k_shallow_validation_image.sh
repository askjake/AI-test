#!/usr/bin/env bash
# Build a local R2K validation overlay only from an already-present, reviewed,
# digest-pinned, sufficiently shallow runner base. This helper never pulls or
# pushes and is not an operational release or deployment command.
set -Eeuo pipefail
umask 077

usage() {
  echo "usage: $0 --build-reviewed-validation-image --engine /abs/docker --base name@sha256:<64hex> --tag local-name:tag --source /abs/repo --expected-tree <40hex>" >&2
  exit 64
}

approved=false
engine= base= tag= source_dir= expected_tree=
while (( $# )); do
  case "$1" in
    --build-reviewed-validation-image) approved=true; shift ;;
    --engine) engine=${2-}; shift 2 ;;
    --base) base=${2-}; shift 2 ;;
    --tag) tag=${2-}; shift 2 ;;
    --source) source_dir=${2-}; shift 2 ;;
    --expected-tree) expected_tree=${2-}; shift 2 ;;
    *) usage ;;
  esac
done

[[ "$approved" == true ]] || usage
[[ "$engine" == /* && -x "$engine" ]] || { echo 'BLOCKED: engine must be an absolute executable' >&2; exit 10; }
[[ "${engine##*/}" == docker || "${engine##*/}" == podman ]] || { echo 'BLOCKED: unsupported engine' >&2; exit 10; }
[[ "$base" =~ ^[A-Za-z0-9][A-Za-z0-9._/:~-]{0,240}@sha256:[a-f0-9]{64}$ ]] || { echo 'BLOCKED: base must be digest pinned' >&2; exit 11; }
[[ "$tag" =~ ^[A-Za-z0-9][A-Za-z0-9._/:~-]{0,240}$ ]] || { echo 'BLOCKED: invalid local tag' >&2; exit 12; }
[[ "$source_dir" == /* && -d "$source_dir/.git" ]] || { echo 'BLOCKED: source must be an absolute Git worktree' >&2; exit 13; }
[[ "$expected_tree" =~ ^[a-f0-9]{40}$ ]] || { echo 'BLOCKED: expected tree must be exact' >&2; exit 14; }
[[ "$(git -C "$source_dir" rev-parse HEAD^{tree})" == "$expected_tree" ]] || { echo 'BLOCKED: source tree identity mismatch' >&2; exit 15; }
git -C "$source_dir" diff --quiet
git -C "$source_dir" diff --cached --quiet
[[ -z "$(git -C "$source_dir" ls-files --others --exclude-standard)" ]] || { echo 'BLOCKED: source contains untracked files' >&2; exit 15; }

work=$(mktemp -d "${TMPDIR:-/tmp}/watch-learn-r2k-image.XXXXXX")
trap 'rm -rf -- "$work"' EXIT
base_json="$work/base.json"
candidate_json="$work/candidate.json"
"$engine" image inspect "$base" >"$base_json" || { echo 'BLOCKED: reviewed base is not present locally; no pull attempted' >&2; exit 16; }

base_user=$(python3 - "$base_json" <<'PY'
import json, sys
image=json.load(open(sys.argv[1], encoding='utf-8'))[0]
layers=image.get('RootFS', {}).get('Layers', [])
if image.get('Os') != 'linux' or image.get('Architecture') != 'amd64':
    raise SystemExit('BLOCKED: reviewed base must be linux/amd64')
if len(layers) > 114:
    raise SystemExit('BLOCKED: reviewed base exceeds 114 filesystem layers')
config=image.get('Config') or {}
user=config.get('User') or ''
if user not in {'orchestrator', '10001', '10001:10001'}:
    raise SystemExit('BLOCKED: reviewed base does not retain the non-root runtime user')
if config.get('Entrypoint') != ['/app/entrypoint.sh']:
    raise SystemExit('BLOCKED: reviewed base entrypoint is unexpected')
if config.get('WorkingDir') != '/app' or not config.get('Cmd'):
    raise SystemExit('BLOCKED: reviewed base command or working directory is unexpected')
env=dict(item.split('=', 1) for item in config.get('Env', []) if '=' in item)
for name in ('DISPLAY', 'HOME', 'XDG_RUNTIME_DIR', 'PYTHONPATH'):
    if not env.get(name):
        raise SystemExit(f'BLOCKED: reviewed base lacks required {name}')
print(user)
PY
)

cat >"$work/Dockerfile" <<EOF
ARG BASE_IMAGE
FROM \${BASE_IMAGE}
USER root
COPY --chown=10001:10001 src/ /app/src/
COPY --chown=10001:10001 templates/ /app/templates/
COPY --chown=10001:10001 scripts/ /app/scripts/
COPY --chown=10001:10001 docker/entrypoint.sh /app/entrypoint.sh
COPY --chown=10001:10001 docker/egress_firewall.sh /app/docker/egress_firewall.sh
RUN chmod -R a+rX /app/src /app/templates /app/scripts && chmod 0755 /app/entrypoint.sh /app/docker/egress_firewall.sh
USER ${base_user}
EOF

"$engine" build --pull=false --network=none --no-cache \
  --build-arg "BASE_IMAGE=$base" -f "$work/Dockerfile" -t "$tag" "$source_dir"
"$engine" image inspect "$tag" >"$candidate_json"
python3 - "$base_json" "$candidate_json" <<'PY'
import json, sys
base=json.load(open(sys.argv[1], encoding='utf-8'))[0]
candidate=json.load(open(sys.argv[2], encoding='utf-8'))[0]
for key in ('Os', 'Architecture'):
    if candidate.get(key) != base.get(key):
        raise SystemExit(f'FAIL: candidate changed {key}')
for key in ('Entrypoint', 'Cmd', 'WorkingDir', 'User', 'Env'):
    if (candidate.get('Config') or {}).get(key) != (base.get('Config') or {}).get(key):
        raise SystemExit(f'FAIL: candidate changed runtime Config.{key}')
layers=candidate.get('RootFS', {}).get('Layers', [])
if len(layers) > 120:
    raise SystemExit('FAIL: candidate exceeds the reviewed 120-layer ceiling')
print(f'R2K_VALIDATION_IMAGE_LAYERS={len(layers)}')
print(f'R2K_VALIDATION_IMAGE_ARCHITECTURE={candidate.get("Architecture")}')
print(f'R2K_VALIDATION_IMAGE_ID={candidate.get("Id")}')
PY
"$engine" run --rm --pull=never --network=none --user 0:0 --entrypoint /bin/sh "$tag" -c \
  'getent passwd 10001 >/dev/null && test -x /app/entrypoint.sh && test -x /app/docker/egress_firewall.sh && test -r /app/src/orchestrator/watch_learn_worker.py'
echo 'R2K_SHALLOW_VALIDATION_IMAGE=PASS'
echo 'NOTICE: local validation image only; no push, deployment, cutover, or release claim performed.'
