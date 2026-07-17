/*
 * decompile.h - Pseudo-decompiler
 *
 * Attempts to reconstruct JS-like source from QuickJS bytecode.
 * This is a best-effort symbolic decompiler that tracks a virtual
 * stack and emits JS-like expressions for each operation.
 */
#ifndef JARONA_DECOMPILE_H
#define JARONA_DECOMPILE_H

#include "qjs_format.h"
#include "reader.h"
#include <stdio.h>

/* =========================================================
 * Decompile a function into pseudo-JS
 *
 * Outputs to `out`. The cpool_base is the global offset added to
 * cpool indices.
 * ========================================================= */
void qjs_decompile_function(FILE *out, qjs_reader_t *r, qjs_function_t *fn,
                             int cpool_base, int indent);

/* =========================================================
 * Decompile a top-level value
 * ========================================================= */
void qjs_decompile_value(FILE *out, qjs_reader_t *r, qjs_value_t *v, int indent);

#endif /* JARONA_DECOMPILE_H */
