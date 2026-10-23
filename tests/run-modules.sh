#!/bin/sh
#
# run-modules.sh - behavioural round-trip test for multi-module projects.
#
# A "qjsc -c" byte code file holds one blob per module: the dependencies
# of the main module first, the main module last.  The decompiler prints
# every module with a "/* ===== Module: <name> ===== */" header; this
# script splits that output back into one file per module and compares the
# behaviour of the original project with the reconstructed one.
#
set -u

cd "$(dirname "$0")/.."
ROOT=tests/modules
BIN=./jarona-decompile
SPLIT=tests/split_modules.awk

PASS=0
FAIL=0
SKIP=0

if [ ! -x "$BIN" ]; then
    echo "FATAL: $BIN not built. Run 'make' first." >&2
    exit 1
fi

if [ ! -d "$ROOT" ]; then
    echo "FATAL: $ROOT not found" >&2
    exit 1
fi

# --------------------------------------------------------------- engine ---
ENGINE=${QJS_ENGINE:-}
if [ -z "$ENGINE" ]; then
    for cand in \
        "${QJS_DIR:-}/qjs" \
        /tmp/opencode/quickjs-2024-01-13/qjs \
        /usr/local/bin/qjs \
        "$(command -v qjs 2>/dev/null || true)" \
        "$(command -v node 2>/dev/null || true)"
    do
        if [ -n "$cand" ] && [ -x "$cand" ]; then ENGINE=$cand; break; fi
    done
fi

if [ -z "$ENGINE" ]; then
    echo "FATAL: no JavaScript engine found; set QJS_ENGINE or QJS_DIR" >&2
    exit 1
fi

echo "engine: $ENGINE"
echo

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

run_engine() {
    _f=$1
    _dir=$2
    ( cd "$_dir" && timeout 20 "$ENGINE" --module "$_f" 2>&1 )
    echo "exit=$?"
}

for dir in "$ROOT"/*/; do
    [ -d "$dir" ] || continue
    name=$(basename "$dir")
    bin="$dir/main.bin"
    [ -f "$bin" ] || { SKIP=$((SKIP + 1)); continue; }

    work="$TMP/$name"
    mkdir -p "$work/src"

    if ! "$BIN" -d "$bin" > "$work/decompiled.js" 2>"$work/err"; then
        echo "FAIL: $name - decompiler exited with an error"
        sed 's/^/      /' "$work/err" | head -3
        FAIL=$((FAIL + 1))
        continue
    fi

    # Split the decompiler output into one file per module.
    if ! awk -v outdir="$work/src" -f "$SPLIT" "$work/decompiled.js"; then
        echo "FAIL: $name - could not split the decompiled output"
        FAIL=$((FAIL + 1))
        continue
    fi

    if [ ! -f "$work/src/main.js" ]; then
        echo "FAIL: $name - no main.js in the reconstructed project"
        ls -l "$work/src" | sed 's/^/      /'
        FAIL=$((FAIL + 1))
        continue
    fi

    expected=$(run_engine main.js "$dir")
    actual=$(run_engine main.js "$work/src")

    if [ "$expected" = "$actual" ]; then
        echo "PASS: $name"
        PASS=$((PASS + 1))
    else
        echo "FAIL: $name - behaviour differs"
        echo "  --- original ---"
        printf '%s\n' "$expected" | sed 's/^/      /' | head -12
        echo "  --- decompiled ---"
        printf '%s\n' "$actual" | sed 's/^/      /' | head -12
        FAIL=$((FAIL + 1))
    fi
done

echo
echo "============================================"
echo "Modules: $PASS passed, $FAIL failed, $SKIP skipped"
echo "============================================"
[ "$FAIL" -eq 0 ]
