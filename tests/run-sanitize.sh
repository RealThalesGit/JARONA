#!/bin/sh
#
# run-sanitize.sh - binding-name sanitization test.
#
# QuickJS stores binding names as plain byte strings.  A binary that was
# produced elsewhere (or hand-patched) may therefore carry a binding whose
# text is not a legal JavaScript identifier, e.g. "AIM-TEST".  The
# decompiler must rewrite such bindings into a valid identifier
# ("AIM_TEST"), *consistently* - the declaration and every reference have
# to agree - while leaving string literals and property keys untouched
# (their text is data, not a binding).
#
# Because invalid identifiers cannot be produced from valid JavaScript
# source, this script takes a normal fixture, patches one atom inside the
# byte code to contain a '-' and checks that
#   1. the decompiled source parses,
#   2. it behaves like the unpatched original, and
#   3. string/key atoms are left verbatim.
#
# Requirements: qjs (set QJS_DIR or QJS_ENGINE), python3.
#
set -u

cd "$(dirname "$0")/.."
FIX=tests/fixtures
BIN=./jarona-decompile

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
        "$(command -v qjs 2>/dev/null || true)"
    do
        if [ -n "$cand" ] && [ -x "$cand" ]; then ENGINE=$cand; break; fi
    done
fi
if [ -z "$ENGINE" ]; then
    echo "FATAL: no JavaScript engine found; set QJS_ENGINE or QJS_DIR" >&2
    exit 1
fi
if ! command -v python3 >/dev/null 2>&1; then
    echo "FATAL: python3 is required" >&2
    exit 1
fi

echo "engine: $ENGINE"
echo

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

PASS=0
FAIL=0

# patch_atom <src.bin> <dst.bin> <from> <to>
# Replace the atom `from` with `to` (both must have the same byte length so
# the atom table stays consistent).
patch_atom() {
    python3 - "$@" <<'PY'
import sys
src, dst, frm, to = sys.argv[1:5]
data = bytearray(open(src, 'rb').read())
fb, tb = frm.encode(), to.encode()
assert len(fb) == len(tb), "atom replacement must keep the same length"
n = 0
i = 0
while True:
    j = data.find(fb, i)
    if j < 0:
        break
    # only patch length-prefixed atom-table entries: the byte before the
    # text is (len << 1) | is_wide_char
    if data[j-1] == len(fb) << 1:
        data[j:j+len(fb)] = tb
        n += 1
    i = j + 1
assert n >= 1, "atom not found"
open(dst, 'wb').write(data)
PY
}

check() {
    name=$1; shift
    if [ "$1" = "1" ]; then
        echo "PASS: $name"; PASS=$((PASS + 1))
    else
        echo "FAIL: $name"; FAIL=$((FAIL + 1))
    fi
}

# --- 1. function name (21_bindings.bin) ------------------------------------
SRC=$FIX/21_bindings.bin
PATCHED=$TMP/21_fn.bin
patch_atom "$SRC" "$PATCHED" "compute" "compu-t"      # compute -> compu-t
if ! "$BIN" -d "$PATCHED" > "$TMP/21_fn.js" 2>"$TMP/21_fn.err"; then
    check "sanitize function name (decompile)" 0
    sed 's/^/      /' "$TMP/21_fn.err" | head -3
else
    if ! grep -q "function compu_t" "$TMP/21_fn.js"; then
        check "sanitize function name (output)" 0
        grep -n "compu" "$TMP/21_fn.js" | sed 's/^/      /' | head -3
    else
        a=$("$ENGINE" "$FIX/21_bindings.js" 2>&1)
        b=$("$ENGINE" "$TMP/21_fn.js" 2>&1)
        if [ "$a" = "$b" ]; then check "sanitize function name (behaviour)" 1
        else
            check "sanitize function name (behaviour)" 0
            echo "      orig: $a"
            echo "      dec : $b"
        fi
    fi
fi

# --- 2. local const binding (21_bindings.bin) ------------------------------
PATCHED=$TMP/21_var.bin
patch_atom "$SRC" "$PATCHED" "counter" "count-r"      # counter -> count-r
if ! "$BIN" -d "$PATCHED" > "$TMP/21_var.js" 2>"$TMP/21_var.err"; then
    check "sanitize const binding (decompile)" 0
    sed 's/^/      /' "$TMP/21_var.err" | head -3
else
    if ! grep -q "const count_r" "$TMP/21_var.js"; then
        check "sanitize const binding (output)" 0
        grep -n "count" "$TMP/21_var.js" | sed 's/^/      /' | head -3
    else
        a=$("$ENGINE" "$FIX/21_bindings.js" 2>&1)
        b=$("$ENGINE" "$TMP/21_var.js" 2>&1)
        if [ "$a" = "$b" ]; then check "sanitize const binding (behaviour)" 1
        else
            check "sanitize const binding (behaviour)" 0
            echo "      orig: $a"
            echo "      dec : $b"
        fi
    fi
fi

# --- 3. the 'this' pseudo-variable and class reconstruction survive --------
if ! "$BIN" -d "$FIX/04_classes.bin" > "$TMP/04.js" 2>/dev/null; then
    check "class reconstruction (decompile)" 0
else
    if grep -q "this\." "$TMP/04.js" && ! grep -q "this_" "$TMP/04.js"; then
        check "class reconstruction keeps 'this'" 1
    else
        check "class reconstruction keeps 'this'" 0
        grep -n "this" "$TMP/04.js" | sed 's/^/      /' | head -5
    fi
fi

echo
echo "============================================"
echo "Sanitize: $PASS passed, $FAIL failed"
echo "============================================"
[ "$FAIL" -eq 0 ]
