#!/bin/sh
# Provision the runtime baseline that airlock's sandbox binds read-only.
#
# airlock builds its root from the host's /usr, /bin, /lib, /sbin (see
# airlock/_nsinit.py HOST_RO_BINDS). corpus-003 measured what a thin image
# costs: `node` was absent, so every JavaScript package exited 127 before doing
# any real work, and a missing `pip` is what made corpus-001's supply-chain
# family undetectable.
#
# Two ways to fix that:
#
#   --bootstrap   Build a hermetic overlay in $AIRLOCK_RUNTIME_ROOT
#                 (default ~/.airlock/runtime). No root required. The sandbox
#                 mounts it read-only over /usr/local when AIRLOCK_RUNTIME_OVERLAY
#                 is set.
#   --apply       Install into the host image itself. Requires root.
#
#   --check       Report the current state; changes nothing.
#
# Versions are pinned in scripts/runtime-baseline.txt so any coverage number
# names the baseline it was measured against.
set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
BASELINE_FILE="$HERE/runtime-baseline.txt"
RUNTIME="${AIRLOCK_RUNTIME_ROOT:-$HOME/.airlock/runtime}"
NODE_VERSION=20.18.1
MODE="${1:---check}"

PY_VERSION=$(python3 -c 'import sys;print("%d.%d" % sys.version_info[:2])')
SITE="$RUNTIME/lib/python$PY_VERSION/site-packages"

# A --prefix install lands in $SITE, but /usr/bin/python3 computes sys.prefix
# from its own location, so it will not search there unless PYTHONPATH says so.
run_pip() {
    env PYTHONPATH="$SITE" python3 -m pip "$@"
}

report() {
    prefix="$1"
    printf '%-26s' 'node'
    if [ -n "$prefix" ] && [ -x "$prefix/bin/node" ]; then "$prefix/bin/node" --version
    elif command -v node >/dev/null 2>&1; then command -v node
    else echo MISSING; fi
    printf '%-26s' 'pip'
    if [ -n "$prefix" ] && [ -d "$prefix/lib/python$PY_VERSION/site-packages/pip" ]; then
        echo "present (prefix $prefix)"
    elif python3 -m pip --version >/dev/null 2>&1; then python3 -m pip --version
    else echo MISSING; fi
    printf '%-26s' 'python3'
    python3 -V
    for module in docx pptx openpyxl reportlab; do
        printf '%-26s' "python:$module"
        if [ -n "$prefix" ]; then
            PYTHONPATH="$prefix/lib/python$PY_VERSION/site-packages" \
                python3 -c "import $module" 2>/dev/null && echo present || echo MISSING
        else
            python3 -c "import $module" 2>/dev/null && echo present || echo MISSING
        fi
    done
}

bootstrap() {
    mkdir -p "$RUNTIME/bin" "$RUNTIME/lib"
    if [ ! -x "$RUNTIME/bin/node" ]; then
        echo "fetching node v$NODE_VERSION into $RUNTIME"
        curl -fsSL "https://nodejs.org/dist/v$NODE_VERSION/node-v$NODE_VERSION-linux-x64.tar.xz" \
            | tar -xJ -C "$RUNTIME" --strip-components=1
    fi
    if [ ! -d "$SITE/pip" ]; then
        echo "bootstrapping pip into $RUNTIME"
        curl -fsSL https://bootstrap.pypa.io/get-pip.py -o "$RUNTIME/get-pip.py"
        python3 "$RUNTIME/get-pip.py" --prefix "$RUNTIME" --no-warn-script-location
    fi
    run_pip install --prefix "$RUNTIME" --no-warn-script-location \
        -r "$BASELINE_FILE" || echo "WARN: some baseline packages did not install"
    mkdir -p "$RUNTIME/lib/python$PY_VERSION"
    # Debian/Ubuntu python searches dist-packages; pip writes site-packages.
    ln -sfn site-packages "$RUNTIME/lib/python$PY_VERSION/dist-packages"
    echo "overlay ready: $RUNTIME"
    echo "use it with: export AIRLOCK_RUNTIME_OVERLAY=$RUNTIME"
    report "$RUNTIME"
}

apply_root() {
    if [ "$(id -u)" -ne 0 ]; then
        echo "error: --apply needs root; use --bootstrap for a no-root overlay" >&2
        exit 3
    fi
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq nodejs npm python3-pip
    python3 -m pip install --break-system-packages -q -r "$BASELINE_FILE" \
        || python3 -m pip install -q -r "$BASELINE_FILE"
    report ""
}

case "$MODE" in
    --check) report "" ;;
    --bootstrap) bootstrap ;;
    --apply) apply_root ;;
    *) echo "usage: $0 [--check|--bootstrap|--apply]" >&2; exit 2 ;;
esac
