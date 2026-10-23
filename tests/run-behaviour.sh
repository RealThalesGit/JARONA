#!/bin/sh
#
# run-behaviour.sh - behavioural round-trip test.
#
# For every fixture the script
#   1. decompiles the byte code back to JavaScript,
#   2. runs the original source and the reconstructed source with the same
#      JavaScript engine,
#   3. compares the produced output.
#
# The reconstructed source must behave exactly like the original one.
#
# Requirements:
#   - qjs (or any QuickJS build) - set QJS_DIR to the build directory
#   - node can be used as a fallback engine
#
set -u

cd "$(dirname "$0")/.."
FIX=tests/fixtures
BIN=./jarona-decompile

PASS=0
FAIL=0
SKIP=0

if [ ! -x "$BIN" ]; then
    echo "FATAL: $BIN not built. Run 'make' first." >&2
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
    # run_engine <file> <is-module>
    _f=$1
    _mod=$2
    if [ "$_mod" = "1" ]; then
        timeout 20 "$ENGINE" --module "$_f" 2>&1
    else
        timeout 20 "$ENGINE" "$_f" 2>&1
    fi
    echo "exit=$?"
}

for js in "$FIX"/*.js; do
    name=$(basename "$js" .js)
    bin="$FIX/$name.bin"
    [ -f "$bin" ] || continue

    out_js="$TMP/$name.out.js"

    if ! "$BIN" -d "$bin" > "$out_js" 2>"$TMP/$name.err"; then
        echo "FAIL: $name - decompiler exited with an error"
        sed 's/^/      /' "$TMP/$name.err" | head -3
        FAIL=$((FAIL + 1))
        continue
    fi

    # ES modules need to be run as modules.
    is_module=0
    if grep -qE '^[[:space:]]*(export|import)[[:space:]]' "$js"; then
        is_module=1
    fi

    expected=$(run_engine "$js" "$is_module")
    actual=$(run_engine "$out_js" "$is_module")

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
echo "Behaviour: $PASS passed, $FAIL failed, $SKIP skipped"
echo "============================================"
[ "$FAIL" -eq 0 ]
