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
# Published checksum for node-v20.18.1-linux-x64.tar.xz, from
# https://nodejs.org/dist/v20.18.1/SHASUMS256.txt
NODE_SHA256=c6fa75c841cbffac851678a472f2a5bd612fff8308ef39236190e1f8dbb0e567
# bootstrap.pypa.io has no versioned get-pip path, so the digest is pinned as
# well; an upstream change fails closed and the pin must be reviewed, not
# silently trusted. Bump deliberately.
GET_PIP_SHA256=356e0d0de21cdc348c3394084d90939b85e4246c4d14c76aee6ca4f46646ea98
GET_PIP_URL=https://bootstrap.pypa.io/get-pip.py
MODE="${1:---check}"

PY_VERSION=$(python3 -c 'import sys;print("%d.%d" % sys.version_info[:2])')
SITE="$RUNTIME/lib/python$PY_VERSION/site-packages"

# Download to a destination and refuse to continue unless the bytes match the
# pinned digest. Checksums are not a formality: an unpinned bootstrap script is
# remote code execution with a trust assumption attached.
fetch_verified() {
    url="$1"
    destination="$2"
    expected="$3"
    curl -fsSL "$url" -o "$destination"
    actual=$(sha256sum "$destination" | cut -d' ' -f1)
    if [ "$actual" != "$expected" ]; then
        echo "error: checksum mismatch for $url" >&2
        echo "  expected $expected" >&2
        echo "  actual   $actual" >&2
        rm -f "$destination"
        exit 4
    fi
}

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
        archive="$RUNTIME/node-v$NODE_VERSION.tar.xz"
        fetch_verified "https://nodejs.org/dist/v$NODE_VERSION/node-v$NODE_VERSION-linux-x64.tar.xz" \
            "$archive" "$NODE_SHA256"
        tar -xJ -C "$RUNTIME" --strip-components=1 -f "$archive"
        rm -f "$archive"
    fi
    if [ ! -d "$SITE/pip" ]; then
        echo "bootstrapping pip into $RUNTIME"
        script="$RUNTIME/get-pip.py"
        fetch_verified "$GET_PIP_URL" "$script" "$GET_PIP_SHA256"
        python3 "$script" --prefix "$RUNTIME" --no-warn-script-location
        rm -f "$script"
    fi
    # A warning here is how a "measured" run silently acquires a different
    # runtime than the one it claims. Failure is fatal.
    if ! run_pip install --prefix "$RUNTIME" --no-warn-script-location \
            -r "$BASELINE_FILE"; then
        echo "error: baseline packages did not install; the overlay is not usable" >&2
        exit 5
    fi
    mkdir -p "$RUNTIME/lib/python$PY_VERSION"
    # Debian/Ubuntu python searches dist-packages; pip writes site-packages.
    ln -sfn site-packages "$RUNTIME/lib/python$PY_VERSION/dist-packages"
    verify_baseline
    echo "overlay ready: $RUNTIME"
    echo "use it with: export AIRLOCK_RUNTIME_OVERLAY=$RUNTIME"
    report "$RUNTIME"
}

verify_baseline() {
    missing=''
    for module in docx pptx openpyxl reportlab defusedxml numpy; do
        PYTHONPATH="$SITE" python3 -c "import $module" 2>/dev/null \
            || missing="$missing $module"
    done
    if [ -n "$missing" ]; then
        echo "error: baseline modules do not import:$missing" >&2
        exit 6
    fi
    echo "baseline verified: all pinned modules import"
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
