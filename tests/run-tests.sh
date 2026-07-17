#!/bin/sh
# run-tests.sh — regression test runner for jarona-decompile.
# Runs every .bin fixture in tests/fixtures through every output mode
# and verifies no crashes and non-trivial output.
set -e
cd "$(dirname "$0")/.."

BIN=./jarona-decompile
FIX=tests/fixtures
PASS=0
FAIL=0

if [ ! -x "$BIN" ]; then
    echo "FATAL: $BIN not built. Run 'make' first." >&2
    exit 1
fi

if [ ! -d "$FIX" ] || [ -z "$(ls "$FIX"/*.bin 2>/dev/null)" ]; then
    echo "FATAL: no .bin fixtures in $FIX. Run 'make fixtures' first." >&2
    exit 1
fi

for f in "$FIX"/*.bin; do
    name=$(basename "$f" .bin)
    for mode in "" "-d" "-j" "--hex" "-s -a" "--vanilla -d"; do
        out=$($BIN $mode "$f" 2>/dev/null) || {
            echo "FAIL: $name [$mode] — non-zero exit"
            FAIL=$((FAIL + 1)); continue
        }
        n=$(printf '%s' "$out" | wc -c)
        if [ "$n" -lt 10 ]; then
            echo "FAIL: $name [$mode] — suspiciously short output ($n bytes)"
            FAIL=$((FAIL + 1)); continue
        fi
        PASS=$((PASS + 1))
    done
done

echo "============================================"
echo "Tests: $PASS passed, $FAIL failed"
echo "============================================"
[ "$FAIL" -eq 0 ]
