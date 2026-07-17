/*
 * value.h - JS value parser and printer (for constant pool entries)
 *
 * Reads the recursive BC_TAG_* structure into qjs_value_t.
 */
#ifndef JARONA_VALUE_H
#define JARONA_VALUE_H

#include "qjs_format.h"
#include "reader.h"

/* =========================================================
 * Resolve an atom index to a C string.
 *
 * Returns a static pointer (valid until next call) or "<atom:N>".
 * Handles:
 *   - tagged-int atoms (encoded as (val<<1)|1) -> returns the integer
 *   - atom-table indices -> returns the string from the table
 *   - special built-in atoms (idx < first_atom) -> returns "<builtin:N>"
 * ========================================================= */
const char *qjs_atom_str(qjs_reader_t *r, uint32_t atom_idx);

/* Like above, but returns a freshly malloc'd buffer (caller frees). */
char *qjs_atom_dup(qjs_reader_t *r, uint32_t atom_idx);

/* =========================================================
 * Top-level parse entry point.
 *
 * Reads the BC_VERSION + atom table, then a single top-level value
 * (which is usually a function or module).
 *
 * Returns the parsed value (caller frees with qjs_value_free), or
 * NULL on error.
 * ========================================================= */
qjs_value_t *qjs_parse_bytecode(const uint8_t *buf, size_t len,
                                 int allow_bytecode, int allow_reference);

/* =========================================================
 * Free a parsed value tree
 * ========================================================= */
void qjs_value_free(qjs_value_t *v);

/* =========================================================
 * Recursive value reader
 * ========================================================= */
qjs_value_t *qjs_read_value(qjs_reader_t *r, int allow_bytecode, int allow_reference);

/* =========================================================
 * Free helpers for sub-types
 * ========================================================= */
void qjs_function_free(qjs_function_t *fn);
void qjs_module_free(qjs_module_t *m);

/* =========================================================
 * Register an object reference (for BC_TAG_OBJECT_REFERENCE)
 * ========================================================= */
int qjs_add_obj_ref(qjs_reader_t *r, qjs_value_t *v);

#endif /* JARONA_VALUE_H */
