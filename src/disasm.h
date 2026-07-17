/*
 * disasm.h - QuickJS bytecode disassembler
 *
 * Walks the bytecode of a qjs_function_t and produces readable
 * assembly-style output. Reconstructs label targets, resolves
 * atoms, and shows constant-pool references.
 */
#ifndef JARONA_DISASM_H
#define JARONA_DISASM_H

#include "qjs_format.h"
#include "qjs_opcodes.h"
#include "reader.h"
#include <stdio.h>

/* =========================================================
 * Output modes
 * ========================================================= */
typedef enum {
    QJS_OUT_TEXT,        /* human-readable assembly */
    QJS_OUT_JSON,        /* structured JSON */
    QJS_OUT_PSEUDO_JS,   /* pseudo-JS decompilation */
} qjs_output_mode_t;

/* =========================================================
 * Disassemble a single function (and recurse into nested functions)
 *
 * Outputs to `out`. The cpool_base is the global offset added to
 * cpool indices when displaying them (so c[N] references are unique
 * across the whole program).
 * ========================================================= */
void qjs_disasm_function(FILE *out, qjs_reader_t *r, qjs_function_t *fn,
                          int cpool_base, qjs_output_mode_t mode, int indent);

/* =========================================================
 * Disassemble a top-level value (function, module, or constant)
 * ========================================================= */
void qjs_disasm_value(FILE *out, qjs_reader_t *r, qjs_value_t *v,
                       qjs_output_mode_t mode, int indent);

/* =========================================================
 * Compute the target PC of a label instruction.
 *
 * Returns 1 on success, 0 on failure. The target PC is stored in
 * *target_pc. The target is computed as: pc + op_size + offset.
 * ========================================================= */
int qjs_resolve_label(const uint8_t *bc, uint32_t bc_len, uint32_t pc,
                       int op_size, qjs_op_fmt_t fmt, int big_endian,
                       int32_t *target_pc);

/* =========================================================
 * Pretty-print a constant-pool value as a JS-like literal.
 * Returns a malloc'd string.
 * ========================================================= */
char *qjs_format_value(qjs_reader_t *r, qjs_value_t *v, int max_depth);

/* =========================================================
 * Print function header info (signature, args, locals)
 * ========================================================= */
void qjs_print_function_header(FILE *out, qjs_reader_t *r, qjs_function_t *fn,
                                int indent, qjs_output_mode_t mode);

/* =========================================================
 * Print constant pool of a function
 * ========================================================= */
void qjs_print_cpool(FILE *out, qjs_reader_t *r, qjs_function_t *fn,
                     int cpool_base, int indent, qjs_output_mode_t mode);

/* =========================================================
 * Reset the global cpool counter (call before each full dump)
 * ========================================================= */
void qjs_disasm_reset(void);

#endif /* JARONA_DISASM_H */
