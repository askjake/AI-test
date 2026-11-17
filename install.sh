#!/usr/bin/env sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
VENV_DIR="$SCRIPT_DIR/.orchestrator-cookie/venv"
VENV_PYTHON="$VENV_DIR/bin/python"
PROBE_CODE='import sys; print("%d.%d.%d" % sys.version_info[:3])'

PYTHON_VERSION=

probe_python() {
    candidate=$1
    if PYTHON_VERSION=$("$candidate" -c "$PROBE_CODE" 2>/dev/null); then
        case "$PYTHON_VERSION" in
            3.11.*|3.12.*|3.13.*) return 0 ;;
            *) return 1 ;;
        esac
    fi
    PYTHON_VERSION=unavailable
    return 1
}

resolve_override() {
    override=${ORCHESTRATOR_PYTHON:-}
    case "$override" in
        /*) candidate=$override ;;
        */*)
            echo "BLOCKED: ORCHESTRATOR_PYTHON must be an absolute path or command name." >&2
            exit 3
            ;;
        *) candidate=$(command -v -- "$override" 2>/dev/null || true) ;;
    esac
    if [ -z "$candidate" ] || [ ! -x "$candidate" ]; then
        echo "BLOCKED: ORCHESTRATOR_PYTHON '$override' is unavailable or not executable." >&2
        exit 3
    fi
    if ! probe_python "$candidate"; then
        echo "BLOCKED: ORCHESTRATOR_PYTHON resolved to Python $PYTHON_VERSION; Python 3.11, 3.12, or 3.13 is required." >&2
        exit 3
    fi
    PYTHON=$candidate
}

resolve_system_python() {
    DISCOVERED=
    for name in python3.13 python3.12 python3.11 python3 python; do
        candidate=$(command -v -- "$name" 2>/dev/null || true)
        if [ -z "$candidate" ]; then
            continue
        fi
        if probe_python "$candidate"; then
            PYTHON=$candidate
            return 0
        fi
        DISCOVERED="${DISCOVERED}${DISCOVERED:+; }$name: Python $PYTHON_VERSION"
    done
    echo "BLOCKED: Python 3.11, 3.12, or 3.13 is required.${DISCOVERED:+ Discovered $DISCOVERED.}" >&2
    if [ "$(uname -s 2>/dev/null || true)" = "Darwin" ]; then
        if command -v brew >/dev/null 2>&1; then
            echo "REMEDIATION: brew install python@3.13" >&2
            echo 'Then: export ORCHESTRATOR_PYTHON="$(brew --prefix python@3.13)/bin/python3.13"' >&2
        else
            echo "REMEDIATION: install Python 3.13 from an approved python.org macOS package (or first install Homebrew through your approved route); this installer will not install it." >&2
            echo 'Then set ORCHESTRATOR_PYTHON to the absolute python3.13 path.' >&2
        fi
        echo "Rerun: ./install.sh init" >&2
    else
        echo "REMEDIATION: install Python 3.11, 3.12, or 3.13 through the approved OS package route, set ORCHESTRATOR_PYTHON if needed, and rerun ./install.sh init." >&2
    fi
    exit 3
}

EXPLICIT_PYTHON=
if [ -n "${ORCHESTRATOR_PYTHON:-}" ]; then
    resolve_override
    EXPLICIT_PYTHON=$PYTHON
fi

if [ -x "$VENV_PYTHON" ]; then
    if probe_python "$VENV_PYTHON"; then
        if [ -n "$EXPLICIT_PYTHON" ] && [ "${1:-}" = "init" ]; then
            PYTHON=$EXPLICIT_PYTHON
        else
            PYTHON=$VENV_PYTHON
        fi
    elif [ "${1:-}" != "init" ]; then
        echo "BLOCKED: the managed environment exists but its Python $PYTHON_VERSION is unusable; run install init to repair it." >&2
        exit 3
    else
        echo "REPAIR: managed Python $PYTHON_VERSION is unsupported; selecting a supported system Python for this clone-local repair." >&2
        if [ -n "$EXPLICIT_PYTHON" ]; then
            PYTHON=$EXPLICIT_PYTHON
        else
            resolve_system_python
        fi
    fi
elif [ -d "$VENV_DIR" ] && [ "${1:-}" != "init" ]; then
    echo "BLOCKED: the managed environment exists but its Python is unusable; run install init to repair it." >&2
    exit 3
elif [ -d "$VENV_DIR" ]; then
    echo "REPAIR: managed Python is unusable; using system Python only to repair this clone-local environment." >&2
    if [ -n "$EXPLICIT_PYTHON" ]; then
        PYTHON=$EXPLICIT_PYTHON
    else
        resolve_system_python
    fi
elif [ -n "$EXPLICIT_PYTHON" ]; then
    PYTHON=$EXPLICIT_PYTHON
else
    resolve_system_python
fi

export ORCHESTRATOR_RESOLVED_PYTHON="$PYTHON"
exec "$PYTHON" "$SCRIPT_DIR/scripts/installer.py" "$@"
