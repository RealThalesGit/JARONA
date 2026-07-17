#!/bin/sh
# Regenerate src/qjs_builtin_atoms.h from a real QuickJS quickjs-atom.h.
# Usage: gen_atoms.sh /path/to/quickjs-atom.h > src/qjs_builtin_atoms.h
ATOM_H="$1"
[ -f "$ATOM_H" ] || { echo "error: $ATOM_H not found" >&2; exit 1; }
cat <<'HEADER'
/*
 * qjs_builtin_atoms.h - Built-in QuickJS atoms (vanilla QuickJS)
 *
 * Auto-generated from quickjs-atom.h by tools/gen_atoms.sh.
 * Do not edit by hand — regenerate with: make atoms QUICKJS_ATOM_H=...
 *
 * NOTE: Frida's QuickJS fork inserts one extra built-in atom,
 * "prepareStackTrace", between "stack" (idx 54) and "name" (idx 55),
 * pushing every subsequent built-in atom up by 1 and making
 * JS_ATOM_END = 228 instead of 227. The decompiler handles this
 * offset in qjs_atom_str() when a function is in Frida mode.
 */
#ifndef QJS_BUILTIN_ATOMS_H
#define QJS_BUILTIN_ATOMS_H

#include <stddef.h>   /* NULL */

#define QJS_BUILTIN_ATOM_COUNT 227 /* +1 for JS_ATOM_NULL at index 0 */
#define QJS_FRIDA_EXTRA_ATOM_INDEX 55   /* vanilla index where Frida inserts prepareStackTrace */
#define QJS_FRIDA_EXTRA_ATOM_NAME "prepareStackTrace"
#define QJS_FRIDA_BUILTIN_ATOM_COUNT 228

/* Defined in qjs_opcodes.c (single instance, shared across all TUs). */
extern const char *qjs_builtin_atoms[QJS_BUILTIN_ATOM_COUNT];

/* The actual table is below, included exactly once (in qjs_opcodes.c
 * via JARONA_DEFINE_ATOM_TABLE). Other translation units just see the
 * extern declaration above. */
#ifdef JARONA_DEFINE_ATOM_TABLE

const char *qjs_builtin_atoms[QJS_BUILTIN_ATOM_COUNT] = {
    NULL, /* index 0 = JS_ATOM_NULL */
HEADER
awk '
/^DEF\(/ {
    s = $0
    sub(/^DEF\([^,]*,[ \t]*"/, "", s)
    sub(/".*$/, "", s)
    printf "    \"%s\", /* index %d */\n", s, NR_DEF
    NR_DEF++
}
' "$ATOM_H"
cat <<'FOOTER'
};

#endif /* JARONA_DEFINE_ATOM_TABLE */

#endif /* QJS_BUILTIN_ATOMS_H */
FOOTER
