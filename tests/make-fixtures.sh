#!/bin/sh
#
# make-fixtures.sh - regenerate the byte code fixtures.
#
# For every tests/fixtures/*.js file the script produces:
#
#   <name>.qjsc   the compiled module produced by qjsc
#   <name>.bin    the raw byte code payload extracted from <name>.qjsc
#
# Requirements:
#   - qjsc and qjs from a stock QuickJS build (see QJS_DIR below)
#   - the extractor in tests/extract_bytecode.c
#
# Usage:
#   QJS_DIR=/path/to/quickjs tests/make-fixtures.sh
#
set -eu

cd "$(dirname "$0")/.."
FIX=tests/fixtures

QJS_DIR=${QJS_DIR:-}
if [ -z "$QJS_DIR" ]; then
    for cand in \
        "$PWD/third_party/quickjs" \
        /tmp/opencode/quickjs-2024-01-13 \
        /usr/local
    do
        if [ -x "$cand/qjsc" ]; then QJS_DIR=$cand; break; fi
    done
fi

if [ -z "$QJS_DIR" ] || [ ! -x "$QJS_DIR/qjsc" ]; then
    echo "make-fixtures.sh: qjsc not found; set QJS_DIR to a QuickJS build dir" >&2
    exit 1
fi

echo "using qjsc from $QJS_DIR"

# The extractor turns a .qjsc container into the bare byte code payload.
EXTRACT=tests/extract_bytecode
if [ ! -x "$EXTRACT" ]; then
    echo "building the byte code extractor..."
    ${CC:-cc} -O2 -o "$EXTRACT" tests/extract_bytecode.c
fi

for js in "$FIX"/*.js; do
    name=$(basename "$js" .js)
    qjsc="$FIX/$name.qjsc"
    bin="$FIX/$name.bin"

    echo "  compiling $name.js"
    # Compile from inside the fixture directory so that the file name that
    # is embedded in the debug info stays "<name>.js" - the decompiler
    # uses it as the source file name of the reconstructed script.
    # qjsc -c emits a C file holding the byte code as a hex array;
    # the extractor below turns that array into the raw payload.
    ( cd "$FIX" && "$QJS_DIR/qjsc" -c -o "$name.qjsc" "$name.js" )
    "$EXTRACT" "$qjsc" "$bin"
done

# --------------------------------------------------------------- modules ---
# Multi-module projects: the byte code file holds one blob per module.
MODDIR=tests/modules
if [ -d "$MODDIR" ]; then
    for dir in "$MODDIR"/*/; do
        [ -d "$dir" ] || continue
        name=$(basename "$dir")
        [ -f "$dir/main.js" ] || continue

        echo "  compiling module project $name"
        ( cd "$dir" && "$QJS_DIR/qjsc" -c -o "$name.qjsc" main.js )
        "$EXTRACT" "$dir/$name.qjsc" "$dir/main.bin"
    done
fi

echo "fixtures regenerated"
