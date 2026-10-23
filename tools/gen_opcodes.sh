#!/bin/sh
#
# gen_opcodes.sh - regenerate (and verify) the JARONA opcode tables.
#
# Usage:
#     tools/gen_opcodes.sh [options] [path/to/quickjs-opcode.h]
#
# Options:
#     --frida-header FILE   Opcode header of Frida's QuickJS fork.  The
#                           opcode table derived from it is compared with
#                           the committed tools/frida-opcodes.txt.  When
#                           they differ the script reports the difference
#                           and stops; --force updates the committed table.
#     --check               Do not write anything: verify that the
#                           committed tables still match their sources.
#     --force               Overwrite tools/frida-opcodes.txt with the
#                           table derived from --frida-header.
#
# Two QuickJS dialects are supported:
#
#   vanilla  stock QuickJS (verified against quickjs 2024-01-13).
#            The opcode space is: 0x00..0xB5 base opcodes, 0xB6..0xF7
#            short opcodes.  The "temporary" (phase 1) opcodes are not
#            part of the emitted bytecode and are therefore absent.
#
#   frida    Frida's QuickJS fork, whose opcode space additionally
#            contains the 19 temporary opcodes at 0xB6..0xC8, which
#            shifts every short opcode up by 19 (they start at 0xC9).
#            The numbering lives in tools/frida-opcodes.txt; the opcode
#            *definitions* are the ones of tools/frida-quickjs-opcode.h,
#            which is used to verify the table.
#
# Outputs (all under src/):
#     qjs_opcodes_enum.inc      opcode name enum, vanilla numbering
#     qjs_opcodes_vanilla.inc   vanilla opcode info table
#     qjs_opcodes_frida.inc     frida opcode info table
#
set -eu

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/.." && pwd)
src="$root/src"

stock=""
frida_header=""
check=0
force=0

while [ $# -gt 0 ]; do
    case $1 in
        --frida-header)
            shift
            frida_header=${1:-}
            [ -n "$frida_header" ] || { echo "gen_opcodes.sh: --frida-header needs a file" >&2; exit 1; }
            ;;
        --check)
            check=1
            ;;
        --force)
            force=1
            ;;
        -h|--help)
            sed -n '2,40p' "$0"
            exit 0
            ;;
        -*)
            echo "gen_opcodes.sh: unknown option '$1'" >&2
            exit 1
            ;;
        *)
            stock=$1
            ;;
    esac
    shift
done

if [ -z "$stock" ]; then
    for cand in \
        "$here/quickjs-opcode.h" \
        "$root/third_party/quickjs/quickjs-opcode.h" \
        /usr/include/quickjs/quickjs-opcode.h
    do
        if [ -f "$cand" ]; then stock=$cand; break; fi
    done
fi
if [ -z "$stock" ] || [ ! -f "$stock" ]; then
    echo "gen_opcodes.sh: cannot find quickjs-opcode.h; pass its path as \$1" >&2
    exit 1
fi

frida_txt="$here/frida-opcodes.txt"
if [ ! -f "$frida_txt" ]; then
    echo "gen_opcodes.sh: missing $frida_txt" >&2
    exit 1
fi

# The vendored header of Frida's fork is used to verify the table when no
# other header is given explicitly.
if [ -z "$frida_header" ] && [ -f "$here/frida-quickjs-opcode.h" ]; then
    frida_header="$here/frida-quickjs-opcode.h"
fi

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# A stable, machine independent name for a source file; it is written into
# the generated files so that they do not depend on where the project is
# checked out.
relpath() {
    case $1 in
        "$root"/*) printf '%s\n' "${1#"$root"/}" ;;
        *)         printf '%s\n' "$(basename "$1")" ;;
    esac
}

stock_label=$(relpath "$stock")

# --------------------------------------------------------------- helpers ---
# Portable hexadecimal to decimal conversion (mawk has no strtonum()).
HEX_DEC='
function hex2dec(s,   i, c, v, d) {
    v = 0
    for (i = 1; i <= length(s); i++) {
        c = tolower(substr(s, i, 1))
        d = index("0123456789abcdef", c) - 1
        if (d < 0) return -1
        v = v * 16 + d
    }
    return v
}
'

# Normalise a frida table to "<index> <name> <size> <n_pop> <n_push> <fmt>".
# The index may be given as hexadecimal ("0x0B6") or as a plain decimal
# number; the normalised form always uses a decimal index.
normalize_frida() {
    awk "$HEX_DEC"'
    /^[[:space:]]*#/ { next }
    /^[[:space:]]*$/ { next }
    {
        idx = $1
        if (idx ~ /^0[xX]/) {
            sub(/^0[xX]/, "", idx)
            idx = hex2dec(idx)
        }
        printf "%d %s %s %s %s %s\n", idx, $2, $3, $4, $5, $6
    }' "$1"
}

# ---------------------------------------------------------------- vanilla ---
# Only the upper case DEF() entries make it into the emitted bytecode; the
# lower case def() entries are the "temporary" opcodes that the compiler
# removes before writing the final byte code.
awk '
    /^[[:space:]]*\/\// { next }
    match($0, /DEF\([[:space:]]*[A-Za-z_][A-Za-z_0-9]*[[:space:]]*,[[:space:]]*[0-9]+[[:space:]]*,[[:space:]]*-?[0-9]+[[:space:]]*,[[:space:]]*-?[0-9]+[[:space:]]*,[[:space:]]*[A-Za-z_][A-Za-z_0-9]*/) {
        s = substr($0, RSTART, RLENGTH)
        sub(/^DEF\([[:space:]]*/, "", s)
        n = split(s, a, ",")
        id = a[1];  gsub(/[[:space:]]/, "", id)
        sz = a[2] + 0
        np = a[3] + 0
        nq = a[4] + 0
        fm = a[5]; gsub(/[[:space:]]/, "", fm)
        printf "%s %d %d %d %s\n", id, sz, np, nq, fm
    }
' "$stock" > "$tmp/vanilla.txt"

if [ ! -s "$tmp/vanilla.txt" ]; then
    echo "gen_opcodes.sh: no opcodes parsed from $stock" >&2
    exit 1
fi

# ------------------------------------------------------------------ frida ---
# Parses the committed Frida table into "$tmp/frida.txt" with a decimal
# opcode index.  It is called again after the table has been updated so
# that the generated tables use the new values.
parse_frida_table() {
    awk "$HEX_DEC"'
    /^[[:space:]]*#/ { next }
    /^[[:space:]]*$/ { next }
    {
        idx = $1; sub(/^0[xX]/, "", idx)
        printf "%d %s %s %s %s %s\n", hex2dec(idx), $2, $3, $4, $5, $6
    }
    ' "$frida_txt" > "$tmp/frida.txt"

    if [ ! -s "$tmp/frida.txt" ]; then
        echo "gen_opcodes.sh: no opcodes parsed from $frida_txt" >&2
        exit 1
    fi
}

parse_frida_table

# ------------------------------------------------- frida header cross check ---
# The opcode header of Frida's fork lists the opcodes in the order in which
# they are numbered: the base opcodes first, then the temporary (phase 1)
# opcodes and finally the short opcodes.  That is exactly the numbering of
# the Frida dialect, so the file order gives the opcode byte values.
if [ -n "$frida_header" ]; then
    if [ ! -f "$frida_header" ]; then
        echo "gen_opcodes.sh: no such frida header: $frida_header" >&2
        exit 1
    fi
    awk '
        /^[[:space:]]*\/\// { next }
        /^[[:space:]]*#[ \t]*if[ \t]+SHORT_OPCODES/ { in_short = 1; next }
        match($0, /(^|[^A-Za-z_0-9])(DEF|def)\([ \t]*[A-Za-z_][A-Za-z_0-9]*[ \t]*,[ \t]*[0-9]+[ \t]*,[ \t]*-?[0-9]+[ \t]*,[ \t]*-?[0-9]+[ \t]*,[ \t]*[A-Za-z_][A-Za-z_0-9]*/) {
            s = substr($0, RSTART, RLENGTH)
            sub(/^[^A-Za-z_0-9]*/, "", s)
            sub(/^(DEF|def)\(/, "", s)
            n = split(s, a, ",")
            id = a[1];  gsub(/[ \t\r]/, "", id)
            sz = a[2] + 0
            np = a[3] + 0
            nq = a[4] + 0
            fm = a[5]; gsub(/[ \t\r]/, "", fm)
            printf "0x%03X %s %d %d %d %s\n", idx, id, sz, np, nq, fm
            idx++
        }
        BEGIN { idx = 0 }
    ' "$frida_header" > "$tmp/frida_hdr.txt"

    if [ ! -s "$tmp/frida_hdr.txt" ]; then
        echo "gen_opcodes.sh: no opcodes parsed from $frida_header" >&2
        exit 1
    fi

    normalize_frida "$tmp/frida_hdr.txt" > "$tmp/frida_hdr.norm"
    normalize_frida "$tmp/frida.txt"     > "$tmp/frida.norm"

    if ! cmp -s "$tmp/frida_hdr.norm" "$tmp/frida.norm"; then
        echo "gen_opcodes.sh: $frida_header does not match $frida_txt" >&2
        diff -u "$tmp/frida.norm" "$tmp/frida_hdr.norm" >&2 || true
        if [ "$force" -eq 1 ]; then
            echo "gen_opcodes.sh: updating $frida_txt" >&2
            {
                echo "# Frida-QuickJS opcode table (Frida's fork of QuickJS)."
                echo "#"
                echo "# Frida's fork inserts 19 extra \"temporary (phase 1)\" opcodes at"
                echo "# 0xB6..0xC8 (scope handling, optional chaining, line numbers), which"
                echo "# shifts every short opcode up by 19 (they start at 0xC9)."
                echo "#"
                echo "# Format:  <index> <name> <size> <n_pop> <n_push> <fmt>"
                echo "#"
                echo "# This file is the single source of truth for the Frida dialect;"
                echo "# regenerate src/qjs_opcodes.{h,c} with tools/gen_opcodes.sh"
                echo "#"
                awk '{
                    printf "%s %-26s %2d %3d %3d %s\n", $1, $2, $3, $4, $5, $6
                }' "$tmp/frida_hdr.txt"
            } > "$frida_txt.new"
            mv "$frida_txt.new" "$frida_txt"
            parse_frida_table
            normalize_frida "$frida_txt" > "$tmp/frida.norm"
        else
            echo "gen_opcodes.sh: run with --force to update $frida_txt" >&2
            exit 1
        fi
    fi
    echo "gen_opcodes.sh: frida table matches $frida_header"
fi

# ------------------------------------------------------------------ enum ---
{
    echo "/*"
    echo " * qjs_opcodes_enum.inc - opcode name constants (vanilla numbering)"
    echo " *"
    echo " * GENERATED by tools/gen_opcodes.sh - do not edit by hand."
    echo " *"
    echo " * The values match the opcode byte values of the vanilla dialect."
    echo " */"
    echo "enum {"
    awk '{ printf "    qjs_op_%s = %d,\n", $1, NR - 1 }' "$tmp/vanilla.txt"
    echo "    qjs_op_count,             /* sentinel: number of vanilla opcodes */"
    echo "};"
} > "$tmp/qjs_opcodes_enum.inc"

# --------------------------------------------------------------- vanilla ---
{
    echo "/*"
    echo " * qjs_opcodes_vanilla.inc - stock QuickJS opcode table"
    echo " *"
    echo " * GENERATED by tools/gen_opcodes.sh - do not edit by hand."
    echo " * Source: $stock_label"
    echo " */"
    echo "const qjs_op_info_t qjs_op_info_vanilla[QJS_OP_TABLE_SIZE] = {"
    awk '{
        printf "    /* 0x%02X */ { \"%s\",%*s %d, %3d, %3d, QJS_FMT_%s },\n",
               NR - 1, $1, 18 - length($1), "", $2, $3, $4, $5
    }' "$tmp/vanilla.txt"
    echo "    /* out of range slots: size 0 marks them as invalid */"
    awk -v n="$(wc -l < "$tmp/vanilla.txt")" 'BEGIN {
        for (i = n; i < 256; i++)
            printf "    /* 0x%02X */ { \"invalid\",          0,  0,  0, QJS_FMT_none },\n", i
    }'
    echo "};"
} > "$tmp/qjs_opcodes_vanilla.inc"

# ----------------------------------------------------------------- frida ---
{
    echo "/*"
    echo " * qjs_opcodes_frida.inc - Frida QuickJS fork opcode table"
    echo " *"
    echo " * GENERATED by tools/gen_opcodes.sh - do not edit by hand."
    echo " * Source: tools/frida-opcodes.txt"
    echo " */"
    echo "const qjs_op_info_t qjs_op_info_frida[QJS_FRIDA_TABLE_SIZE] = {"
    awk '{
        printf "    [0x%02X] = { \"%s\",%*s %d, %3d, %3d, QJS_FMT_%s },\n",
               $1, $2, 18 - length($2), "", $3, $4, $5, $6
    }' "$tmp/frida.txt"
    echo "};"
} > "$tmp/qjs_opcodes_frida.inc"

# ----------------------------------------------------------------- write ---
if [ "$check" -eq 1 ]; then
    rc=0
    for f in qjs_opcodes_enum.inc qjs_opcodes_vanilla.inc qjs_opcodes_frida.inc; do
        if ! cmp -s "$tmp/$f" "$src/$f"; then
            echo "gen_opcodes.sh: $src/$f is out of date" >&2
            diff -u "$src/$f" "$tmp/$f" >&2 || true
            rc=1
        fi
    done
    [ "$rc" -eq 0 ] && echo "gen_opcodes.sh: opcode tables are up to date"
    exit $rc
fi

for f in qjs_opcodes_enum.inc qjs_opcodes_vanilla.inc qjs_opcodes_frida.inc; do
    cp "$tmp/$f" "$src/$f"
done

nvan=$(wc -l < "$tmp/vanilla.txt")
nfri=$(wc -l < "$tmp/frida.txt")
echo "gen_opcodes.sh: vanilla=$nvan frida=$nfri opcodes -> src/qjs_opcodes_{enum,vanilla,frida}.inc"
