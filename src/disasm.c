/*
 * disasm.c - Disassembler implementation
 *
 * Walks QuickJS bytecode and produces assembly-style output.
 */
#include "disasm.h"
#include "value.h"
#include "qjs_opcodes.h"
#include "util.h"
#include <math.h>
#include <float.h>
#include <stdarg.h>
#include <ctype.h>

/* =========================================================
 * Label resolution
 * ========================================================= */
int qjs_resolve_label(const uint8_t *bc, uint32_t bc_len, uint32_t pc,
                       int op_size, qjs_op_fmt_t fmt, int big_endian,
                       int32_t *target_pc) {
    int32_t rel = 0;
    switch (fmt) {
        case QJS_FMT_label8:
            if (pc + 2 > bc_len) return 0;
            rel = (int8_t)bc[pc + 1];
            break;
        case QJS_FMT_label16:
            if (pc + 3 > bc_len) return 0;
            rel = (int16_t)rd_u16(bc + pc + 1, big_endian);
            break;
        case QJS_FMT_label:
            if (pc + 5 > bc_len) return 0;
            rel = (int32_t)rd_u32(bc + pc + 1, big_endian);
            break;
        case QJS_FMT_label_u16:
            if (pc + 3 > bc_len) return 0;
            rel = (int16_t)rd_u16(bc + pc + 1, big_endian);
            break;
        case QJS_FMT_atom_label_u8:
            if (pc + 6 > bc_len) return 0;
            rel = (int8_t)bc[pc + 5];
            break;
        case QJS_FMT_atom_label_u16:
            if (pc + 7 > bc_len) return 0;
            rel = (int16_t)rd_u16(bc + pc + 5, big_endian);
            break;
        default:
            return 0;
    }
    /* QuickJS uses: target = pc + 1 + offset (NOT pc + size + offset).
     * The offset is relative to the byte after the opcode, not the next instruction. */
    int32_t tgt;
    switch (fmt) {
        case QJS_FMT_label8:
        case QJS_FMT_label16:
        case QJS_FMT_label:
        case QJS_FMT_label_u16:
            tgt = (int32_t)(pc + 1 + rel);
            break;
        case QJS_FMT_atom_label_u8:
        case QJS_FMT_atom_label_u16:
            /* offset is at pc+5, target = (pc+5) + 1 + rel = pc + 6 + rel */
            tgt = (int32_t)(pc + 5 + 1 + rel);
            break;
        default:
            return 0;
    }
    (void)op_size;
    if (tgt < 0 || (uint32_t)tgt > bc_len) return 0;
    *target_pc = tgt;
    return 1;
}

/* =========================================================
 * Format a value as a JS-like literal
 * ========================================================= */
static void format_value_into(char **pbuf, size_t *plen, size_t *pcap,
                              qjs_reader_t *r, qjs_value_t *v, int depth, int max_depth);

static void buf_append(char **pbuf, size_t *plen, size_t *pcap, const char *s, size_t n) {
    if (*plen + n + 1 > *pcap) {
        while (*plen + n + 1 > *pcap) *pcap = *pcap ? *pcap * 2 : 64;
        *pbuf = xrealloc(*pbuf, *pcap);
    }
    memcpy(*pbuf + *plen, s, n);
    *plen += n;
    (*pbuf)[*plen] = '\0';
}

static void buf_appendf(char **pbuf, size_t *plen, size_t *pcap, const char *fmt, ...) {
    char tmp[256];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(tmp, sizeof(tmp), fmt, ap);
    va_end(ap);
    if (n < 0) return;
    if ((size_t)n >= sizeof(tmp)) {
        /* truncated; allocate a bigger buffer */
        char *big = xmalloc(n + 1);
        va_start(ap, fmt);
        vsnprintf(big, n + 1, fmt, ap);
        va_end(ap);
        buf_append(pbuf, plen, pcap, big, n);
        free(big);
    } else {
        buf_append(pbuf, plen, pcap, tmp, n);
    }
}

static void format_string_into(char **pbuf, size_t *plen, size_t *pcap, const char *s, size_t len) {
    buf_append(pbuf, plen, pcap, "\"", 1);
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)s[i];
        switch (c) {
            case '"':  buf_append(pbuf, plen, pcap, "\\\"", 2); break;
            case '\\': buf_append(pbuf, plen, pcap, "\\\\", 2); break;
            case '\n': buf_append(pbuf, plen, pcap, "\\n", 2); break;
            case '\r': buf_append(pbuf, plen, pcap, "\\r", 2); break;
            case '\t': buf_append(pbuf, plen, pcap, "\\t", 2); break;
            case '\b': buf_append(pbuf, plen, pcap, "\\b", 2); break;
            case '\f': buf_append(pbuf, plen, pcap, "\\f", 2); break;
            default:
                if (c < 0x20) {
                    char tmp[8];
                    int n = snprintf(tmp, sizeof(tmp), "\\x%02x", c);
                    buf_append(pbuf, plen, pcap, tmp, n);
                } else {
                    buf_append(pbuf, plen, pcap, (const char *)&c, 1);
                }
                break;
        }
    }
    buf_append(pbuf, plen, pcap, "\"", 1);
}

static void format_value_into(char **pbuf, size_t *plen, size_t *pcap,
                              qjs_reader_t *r, qjs_value_t *v, int depth, int max_depth) {
    if (!v) {
        buf_append(pbuf, plen, pcap, "<null>", 6);
        return;
    }
    if (depth > max_depth) {
        buf_append(pbuf, plen, pcap, "...", 3);
        return;
    }
    switch (v->kind) {
        case QJS_VAL_NULL:
            buf_append(pbuf, plen, pcap, "null", 4);
            break;
        case QJS_VAL_UNDEFINED:
            buf_append(pbuf, plen, pcap, "undefined", 9);
            break;
        case QJS_VAL_BOOL:
            buf_append(pbuf, plen, pcap, v->u.b ? "true" : "false", v->u.b ? 4 : 5);
            break;
        case QJS_VAL_INT32:
            buf_appendf(pbuf, plen, pcap, "%d", v->u.i32);
            break;
        case QJS_VAL_FLOAT64: {
            double d = v->u.f64;
            if (isnan(d)) buf_append(pbuf, plen, pcap, "NaN", 3);
            else if (isinf(d)) buf_append(pbuf, plen, pcap, d < 0 ? "-Infinity" : "Infinity", d < 0 ? 9 : 8);
            else {
                /* Use %g-like formatting but always include a decimal */
                char tmp[64];
                int n = snprintf(tmp, sizeof(tmp), "%.17g", d);
                buf_append(pbuf, plen, pcap, tmp, n);
                if (!strchr(tmp, '.') && !strchr(tmp, 'e') && !strchr(tmp, 'n') && !strchr(tmp, 'i'))
                    buf_append(pbuf, plen, pcap, ".0", 2);
            }
            break;
        }
        case QJS_VAL_STRING:
            format_string_into(pbuf, plen, pcap, v->u.str.data, v->u.str.len);
            break;
        case QJS_VAL_OBJECT:
            buf_append(pbuf, plen, pcap, "{ ", 2);
            for (uint32_t i = 0; i < v->u.obj.count; i++) {
                if (i > 0) buf_append(pbuf, plen, pcap, ", ", 2);
                const char *key = qjs_atom_str(r, v->u.obj.props[i].key_atom);
                buf_append(pbuf, plen, pcap, key, strlen(key));
                buf_append(pbuf, plen, pcap, ": ", 2);
                format_value_into(pbuf, plen, pcap, r, v->u.obj.props[i].value, depth + 1, max_depth);
            }
            buf_append(pbuf, plen, pcap, " }", 2);
            break;
        case QJS_VAL_ARRAY:
        case QJS_VAL_TEMPLATE_OBJECT:
            buf_append(pbuf, plen, pcap, "[ ", 2);
            for (uint32_t i = 0; i < v->u.arr.count; i++) {
                if (i > 0) buf_append(pbuf, plen, pcap, ", ", 2);
                format_value_into(pbuf, plen, pcap, r, v->u.arr.items[i], depth + 1, max_depth);
            }
            buf_append(pbuf, plen, pcap, " ]", 2);
            break;
        case QJS_VAL_BIG_INT:
        case QJS_VAL_BIG_FLOAT:
        case QJS_VAL_BIG_DECIMAL: {
            const char *suffix = (v->kind == QJS_VAL_BIG_INT) ? "n" :
                                  (v->kind == QJS_VAL_BIG_FLOAT) ? "l" : "m";
            buf_append(pbuf, plen, pcap, v->u.bignum.digits, strlen(v->u.bignum.digits));
            buf_append(pbuf, plen, pcap, suffix, 1);
            break;
        }
        case QJS_VAL_FUNCTION:
            buf_appendf(pbuf, plen, pcap, "_function_%d", v->u.func.fn->func_idx);
            break;
        case QJS_VAL_MODULE:
            buf_append(pbuf, plen, pcap, "_module", 7);
            break;
        case QJS_VAL_TYPED_ARRAY:
            buf_append(pbuf, plen, pcap, "_typed_array", 12);
            break;
        case QJS_VAL_ARRAY_BUFFER:
            buf_appendf(pbuf, plen, pcap, "_ArrayBuffer_%u", v->u.str.len);
            break;
        case QJS_VAL_SHARED_ARRAY_BUFFER:
            buf_appendf(pbuf, plen, pcap, "_SharedArrayBuffer_%u", v->u.str.len);
            break;
        case QJS_VAL_DATE:
            buf_appendf(pbuf, plen, pcap, "new Date(%g)", v->u.f64);
            break;
        case QJS_VAL_OBJECT_VALUE:
            buf_append(pbuf, plen, pcap, "_object_value", 13);
            break;
        case QJS_VAL_OBJECT_REFERENCE:
            buf_appendf(pbuf, plen, pcap, "_obj_ref_%u", v->u.ref.ref_idx);
            break;
        case QJS_VAL_ERROR:
            buf_append(pbuf, plen, pcap, "_error", 6);
            break;
    }
}

char *qjs_format_value(qjs_reader_t *r, qjs_value_t *v, int max_depth) {
    char *buf = NULL;
    size_t len = 0, cap = 0;
    format_value_into(&buf, &len, &cap, r, v, 0, max_depth);
    if (!buf) buf = xstrdup("");
    return buf;
}

/* =========================================================
 * Function header printing
 * ========================================================= */
static const char *func_kind_str(uint8_t func_kind) {
    switch (func_kind) {
        case 0: return "function";
        case 1: return "function*";     /* generator */
        case 2: return "async function";
        case 3: return "async function*";
        default: return "function";
    }
}

void qjs_print_function_header(FILE *out, qjs_reader_t *r, qjs_function_t *fn,
                                int indent, qjs_output_mode_t mode) {
    const char *name = qjs_atom_str(r, fn->func_name_atom);
    const char *kind = func_kind_str(fn->flags.func_kind);

    if (mode == QJS_OUT_TEXT) {
        put_indent(out, indent);
        fprintf(out, "; ===== Function #%d: %s %s =====\n",
                fn->func_idx, kind, name[0] ? name : "<anonymous>");
        put_indent(out, indent);
        fprintf(out, ";   args=%u  vars=%u  defined_args=%u  stack_size=%u\n",
                fn->arg_count, fn->var_count, fn->defined_arg_count, fn->stack_size);
        put_indent(out, indent);
        fprintf(out, ";   closure_vars=%d  cpool=%d  bytecode_len=%d  locals=%d\n",
                fn->closure_var_count, fn->cpool_count, fn->byte_code_len, fn->local_count);
        put_indent(out, indent);
        fprintf(out, ";   js_mode=0x%02x  func_kind=%d  has_prototype=%d  has_debug=%d\n",
                fn->js_mode, fn->flags.func_kind, fn->flags.has_prototype, fn->flags.has_debug);
        put_indent(out, indent);
        fprintf(out, ";   need_home_object=%d  is_derived_ctor=%d  super_allowed=%d  arguments_allowed=%d\n",
                fn->flags.need_home_object, fn->flags.is_derived_class_constructor,
                fn->flags.super_allowed, fn->flags.arguments_allowed);
        if (fn->flags.has_debug) {
            put_indent(out, indent);
            fprintf(out, ";   filename=%s  line=%d  pc2line_len=%d\n",
                    qjs_atom_str(r, fn->debug_filename_atom),
                    fn->debug_line_num, fn->debug_pc2line_len);
        }
    } else if (mode == QJS_OUT_JSON) {
        put_indent(out, indent);
        fprintf(out, "\"function\": {\n");
        put_indent(out, indent + 1);
        fprintf(out, "\"index\": %d,\n", fn->func_idx);
        put_indent(out, indent + 1);
        fprintf(out, "\"name\": \"%s\",\n", name);
        put_indent(out, indent + 1);
        fprintf(out, "\"kind\": \"%s\",\n", kind);
        put_indent(out, indent + 1);
        fprintf(out, "\"arg_count\": %u,\n", fn->arg_count);
        put_indent(out, indent + 1);
        fprintf(out, "\"var_count\": %u,\n", fn->var_count);
        put_indent(out, indent + 1);
        fprintf(out, "\"defined_arg_count\": %u,\n", fn->defined_arg_count);
        put_indent(out, indent + 1);
        fprintf(out, "\"stack_size\": %u,\n", fn->stack_size);
        put_indent(out, indent + 1);
        fprintf(out, "\"closure_var_count\": %d,\n", fn->closure_var_count);
        put_indent(out, indent + 1);
        fprintf(out, "\"cpool_count\": %d,\n", fn->cpool_count);
        put_indent(out, indent + 1);
        fprintf(out, "\"bytecode_len\": %d,\n", fn->byte_code_len);
        put_indent(out, indent + 1);
        fprintf(out, "\"flags\": {\"has_prototype\": %d, \"has_debug\": %d, \"func_kind\": %d, \"need_home_object\": %d, \"is_derived_ctor\": %d}\n",
                fn->flags.has_prototype, fn->flags.has_debug, fn->flags.func_kind,
                fn->flags.need_home_object, fn->flags.is_derived_class_constructor);
    }
}

/* =========================================================
 * Variable definitions display
 * ========================================================= */
static void print_vardefs(FILE *out, qjs_reader_t *r, qjs_function_t *fn,
                           int indent, qjs_output_mode_t mode) {
    if (fn->vardefs_count <= 0) return;

    if (mode == QJS_OUT_TEXT) {
        put_indent(out, indent);
        fprintf(out, "; ----- Locals / Args (%d) -----\n", fn->vardefs_count);
        for (int i = 0; i < fn->vardefs_count; i++) {
            qjs_vardef_t *vd = &fn->vardefs[i];
            put_indent(out, indent);
            fprintf(out, ";   [%2d] %-20s scope=%d next=%d kind=%d %s%s%s\n",
                    i, qjs_atom_str(r, vd->var_name_atom),
                    vd->scope_level, vd->scope_next, vd->var_kind,
                    vd->is_const ? "const " : "",
                    vd->is_lexical ? "lexical " : "",
                    vd->is_captured ? "captured" : "");
        }
    } else if (mode == QJS_OUT_JSON) {
        put_indent(out, indent);
        fprintf(out, "\"vardefs\": [");
        for (int i = 0; i < fn->vardefs_count; i++) {
            qjs_vardef_t *vd = &fn->vardefs[i];
            fprintf(out, "%s\n", i > 0 ? "," : "");
            put_indent(out, indent + 1);
            fprintf(out, "{\"idx\": %d, \"name\": \"%s\", \"scope_level\": %d, \"scope_next\": %d, \"var_kind\": %d, \"is_const\": %d, \"is_lexical\": %d, \"is_captured\": %d}",
                    i, qjs_atom_str(r, vd->var_name_atom),
                    vd->scope_level, vd->scope_next, vd->var_kind,
                    vd->is_const, vd->is_lexical, vd->is_captured);
        }
        fprintf(out, "\n");
        put_indent(out, indent);
        fprintf(out, "],\n");
    }
}

/* =========================================================
 * Closure vars display
 * ========================================================= */
static void print_closure_vars(FILE *out, qjs_reader_t *r, qjs_function_t *fn,
                                int indent, qjs_output_mode_t mode) {
    if (fn->closure_var_count <= 0) return;

    if (mode == QJS_OUT_TEXT) {
        put_indent(out, indent);
        fprintf(out, "; ----- Closure Vars (%d) -----\n", fn->closure_var_count);
        for (int i = 0; i < fn->closure_var_count; i++) {
            qjs_closure_var_t *cv = &fn->closure_vars[i];
            put_indent(out, indent);
            fprintf(out, ";   [%2d] %-20s var_idx=%d kind=%d %s%s%s\n",
                    i, qjs_atom_str(r, cv->var_name_atom),
                    cv->var_idx, cv->var_kind,
                    cv->is_local ? "local " : "",
                    cv->is_arg ? "arg " : "",
                    cv->is_const ? "const" : "");
        }
    } else if (mode == QJS_OUT_JSON) {
        put_indent(out, indent);
        fprintf(out, "\"closure_vars\": [");
        for (int i = 0; i < fn->closure_var_count; i++) {
            qjs_closure_var_t *cv = &fn->closure_vars[i];
            fprintf(out, "%s\n", i > 0 ? "," : "");
            put_indent(out, indent + 1);
            fprintf(out, "{\"idx\": %d, \"name\": \"%s\", \"var_idx\": %d, \"var_kind\": %d, \"is_local\": %d, \"is_arg\": %d, \"is_const\": %d, \"is_lexical\": %d}",
                    i, qjs_atom_str(r, cv->var_name_atom),
                    cv->var_idx, cv->var_kind,
                    cv->is_local, cv->is_arg, cv->is_const, cv->is_lexical);
        }
        fprintf(out, "\n");
        put_indent(out, indent);
        fprintf(out, "],\n");
    }
}

/* =========================================================
 * Constant pool display
 * ========================================================= */
void qjs_print_cpool(FILE *out, qjs_reader_t *r, qjs_function_t *fn,
                     int cpool_base, int indent, qjs_output_mode_t mode) {
    if (fn->cpool_count <= 0) return;

    if (mode == QJS_OUT_TEXT) {
        put_indent(out, indent);
        fprintf(out, "; ----- Constant Pool (%d entries) -----\n", fn->cpool_count);
        for (int i = 0; i < fn->cpool_count; i++) {
            qjs_value_t *v = fn->cpool[i];
            char *s = qjs_format_value(r, v, 4);
            put_indent(out, indent);
            fprintf(out, ";   c[%d] %s\n", cpool_base + i, s);
            free(s);
        }
    } else if (mode == QJS_OUT_JSON) {
        put_indent(out, indent);
        fprintf(out, "\"cpool\": [");
        for (int i = 0; i < fn->cpool_count; i++) {
            qjs_value_t *v = fn->cpool[i];
            char *s = qjs_format_value(r, v, 4);
            fprintf(out, "%s\n", i > 0 ? "," : "");
            put_indent(out, indent + 1);
            fprintf(out, "{\"idx\": %d, \"value\": %s}", cpool_base + i, s);
            free(s);
        }
        fprintf(out, "\n");
        put_indent(out, indent);
        fprintf(out, "],\n");
    }
}

/* =========================================================
 * Resolve atom operand at a given offset in the bytecode
 *
 * The raw u32 in the bytecode is the encoded atom value:
 *   (idx << 1) | 1  -> tagged integer atom (idx is the int value)
 *   (table_idx << 1) -> atom table index (to be resolved)
 *
 * The QuickJS reader calls bc_idx_to_atom which converts table
 * indices into real atoms. We do the same: for non-tagged atoms,
 * we resolve through the atom table (adding first_atom offset).
 * ========================================================= */
static const char *resolve_atom_operand(qjs_reader_t *r, const uint8_t *bc, uint32_t off) {
    uint32_t raw = rd_u32(bc + off, r->big_endian);
    return qjs_atom_str(r, raw);
}

/* =========================================================
 * Disassemble bytecode body
 * ========================================================= */
static void disasm_bytecode(FILE *out, qjs_reader_t *r, qjs_function_t *fn,
                             int cpool_base, int indent, qjs_output_mode_t mode) {
    const uint8_t *bc = fn->byte_code;
    uint32_t len = (uint32_t)fn->byte_code_len;

    if (mode == QJS_OUT_TEXT) {
        put_indent(out, indent);
        fprintf(out, "; ----- Bytecode (%u bytes) -----\n", len);
    } else if (mode == QJS_OUT_JSON) {
        put_indent(out, indent);
        fprintf(out, "\"bytecode\": [");
    }

    int first_insn = 1;

    for (uint32_t pc = 0; pc < len;) {
        uint8_t op = bc[pc];
        if (op >= QJS_OP_INFO_COUNT) {
            if (mode == QJS_OUT_TEXT) {
                put_indent(out, indent);
                fprintf(out, "[0x%04X] <INVALID 0x%02X>\n", pc, op);
            } else if (mode == QJS_OUT_JSON) {
                if (!first_insn) fprintf(out, ",");
                fprintf(out, "\n");
                put_indent(out, indent + 1);
                fprintf(out, "{\"pc\": %u, \"op\": \"<invalid>\", \"opcode\": %u}", pc, op);
                first_insn = 0;
            }
            pc++;
            continue;
        }

        const qjs_op_info_t *info = &qjs_op_info[op];
        int sz = info->size;

        if (pc + sz > len) {
            if (mode == QJS_OUT_TEXT) {
                put_indent(out, indent);
                fprintf(out, "[0x%04X] <TRUNCATED %s>\n", pc, info->name);
            } else if (mode == QJS_OUT_JSON) {
                if (!first_insn) fprintf(out, ",");
                fprintf(out, "\n");
                put_indent(out, indent + 1);
                fprintf(out, "{\"pc\": %u, \"op\": \"<truncated>\", \"name\": \"%s\"}", pc, info->name);
                first_insn = 0;
            }
            break;
        }

        if (mode == QJS_OUT_TEXT) {
            put_indent(out, indent);
            fprintf(out, "[0x%04X] %-24s", pc, info->name);

            /* operand decoding */
            switch (info->fmt) {
                case QJS_FMT_none:
                case QJS_FMT_none_int:
                case QJS_FMT_none_loc:
                case QJS_FMT_none_arg:
                case QJS_FMT_none_var_ref:
                    break;
                case QJS_FMT_i8:
                    fprintf(out, " %d", (int8_t)bc[pc + 1]);
                    break;
                case QJS_FMT_u8:
                case QJS_FMT_loc8:
                    fprintf(out, " %u", bc[pc + 1]);
                    break;
                case QJS_FMT_const8:
                    fprintf(out, " c[%d]", cpool_base + bc[pc + 1]);
                    break;
                case QJS_FMT_i16:
                    fprintf(out, " %d", (int16_t)rd_u16(bc + pc + 1, r->big_endian));
                    break;
                case QJS_FMT_u16:
                case QJS_FMT_npop_u16:
                    fprintf(out, " %u", rd_u16(bc + pc + 1, r->big_endian));
                    break;
                case QJS_FMT_i32:
                    fprintf(out, " %d (0x%X)", (int32_t)rd_u32(bc + pc + 1, r->big_endian),
                            rd_u32(bc + pc + 1, r->big_endian));
                    break;
                case QJS_FMT_u32:
                    fprintf(out, " 0x%X", rd_u32(bc + pc + 1, r->big_endian));
                    break;
                case QJS_FMT_loc:
                case QJS_FMT_arg:
                case QJS_FMT_var_ref:
                    /* size 3 = 1 byte op + 2 byte u16 operand */
                    fprintf(out, " %u", rd_u16(bc + pc + 1, r->big_endian));
                    break;
                case QJS_FMT_const:
                    fprintf(out, " c[%d]", cpool_base + rd_u32(bc + pc + 1, r->big_endian));
                    break;
                case QJS_FMT_npop:
                    fprintf(out, " nargs=%u", rd_u16(bc + pc + 1, r->big_endian));
                    break;
                case QJS_FMT_npopx:
                    /* no operand - nargs is encoded in the opcode (call0..call3) */
                    break;
                case QJS_FMT_atom: {
                    const char *a = resolve_atom_operand(r, bc, pc + 1);
                    fprintf(out, " %s", a);
                    break;
                }
                case QJS_FMT_atom_u8: {
                    const char *a = resolve_atom_operand(r, bc, pc + 1);
                    fprintf(out, " %s %u", a, bc[pc + 5]);
                    break;
                }
                case QJS_FMT_atom_u16: {
                    const char *a = resolve_atom_operand(r, bc, pc + 1);
                    fprintf(out, " %s %u", a, rd_u16(bc + pc + 5, r->big_endian));
                    break;
                }
                case QJS_FMT_label8:
                case QJS_FMT_label16:
                case QJS_FMT_label:
                case QJS_FMT_label_u16: {
                    int32_t tgt;
                    if (qjs_resolve_label(bc, len, pc, sz, info->fmt, r->big_endian, &tgt)) {
                        fprintf(out, " -> 0x%04X", (uint32_t)tgt);
                    } else {
                        fprintf(out, " -> <invalid>");
                    }
                    break;
                }
                case QJS_FMT_atom_label_u8: {
                    const char *a = resolve_atom_operand(r, bc, pc + 1);
                    int32_t tgt;
                    if (qjs_resolve_label(bc, len, pc, sz, info->fmt, r->big_endian, &tgt)) {
                        fprintf(out, " %s -> 0x%04X", a, (uint32_t)tgt);
                    } else {
                        fprintf(out, " %s -> <invalid>", a);
                    }
                    break;
                }
                case QJS_FMT_atom_label_u16: {
                    const char *a = resolve_atom_operand(r, bc, pc + 1);
                    int32_t tgt;
                    if (qjs_resolve_label(bc, len, pc, sz, info->fmt, r->big_endian, &tgt)) {
                        fprintf(out, " %s -> 0x%04X", a, (uint32_t)tgt);
                    } else {
                        fprintf(out, " %s -> <invalid>", a);
                    }
                    break;
                }
            }

            /* stack effect comment */
            fprintf(out, "    ; stack -%d +%d", info->n_pop, info->n_push);
            fprintf(out, "\n");
        } else if (mode == QJS_OUT_JSON) {
            if (!first_insn) fprintf(out, ",");
            fprintf(out, "\n");
            put_indent(out, indent + 1);
            fprintf(out, "{\"pc\": %u, \"op\": \"%s\", \"size\": %d, \"pop\": %d, \"push\": %d",
                    pc, info->name, sz, info->n_pop, info->n_push);

            /* operands */
            switch (info->fmt) {
                case QJS_FMT_i8:
                    fprintf(out, ", \"operand\": %d", (int8_t)bc[pc + 1]);
                    break;
                case QJS_FMT_u8:
                case QJS_FMT_loc8:
                    fprintf(out, ", \"operand\": %u", bc[pc + 1]);
                    break;
                case QJS_FMT_const8:
                    fprintf(out, ", \"cpool_idx\": %d", cpool_base + bc[pc + 1]);
                    break;
                case QJS_FMT_i16:
                    fprintf(out, ", \"operand\": %d", (int16_t)rd_u16(bc + pc + 1, r->big_endian));
                    break;
                case QJS_FMT_u16:
                case QJS_FMT_npop_u16:
                    fprintf(out, ", \"operand\": %u", rd_u16(bc + pc + 1, r->big_endian));
                    break;
                case QJS_FMT_i32:
                    fprintf(out, ", \"operand\": %d", (int32_t)rd_u32(bc + pc + 1, r->big_endian));
                    break;
                case QJS_FMT_u32:
                    fprintf(out, ", \"operand\": %u", rd_u32(bc + pc + 1, r->big_endian));
                    break;
                case QJS_FMT_loc:
                case QJS_FMT_arg:
                case QJS_FMT_var_ref:
                    fprintf(out, ", \"operand\": %u", rd_u16(bc + pc + 1, r->big_endian));
                    break;
                case QJS_FMT_const:
                    fprintf(out, ", \"cpool_idx\": %d", cpool_base + rd_u32(bc + pc + 1, r->big_endian));
                    break;
                case QJS_FMT_npop:
                    fprintf(out, ", \"nargs\": %u", rd_u16(bc + pc + 1, r->big_endian));
                    break;
                case QJS_FMT_npopx:
                    /* no operand */
                    break;
                case QJS_FMT_atom:
                case QJS_FMT_atom_u8:
                case QJS_FMT_atom_u16: {
                    const char *a = resolve_atom_operand(r, bc, pc + 1);
                    char *escaped = jarona_escape_str(a, strlen(a), 1);
                    fprintf(out, ", \"atom\": %s", escaped);
                    free(escaped);
                    if (info->fmt == QJS_FMT_atom_u8)
                        fprintf(out, ", \"u8\": %u", bc[pc + 5]);
                    else if (info->fmt == QJS_FMT_atom_u16)
                        fprintf(out, ", \"u16\": %u", rd_u16(bc + pc + 5, r->big_endian));
                    break;
                }
                case QJS_FMT_atom_label_u8:
                case QJS_FMT_atom_label_u16: {
                    const char *a = resolve_atom_operand(r, bc, pc + 1);
                    char *escaped = jarona_escape_str(a, strlen(a), 1);
                    fprintf(out, ", \"atom\": %s", escaped);
                    free(escaped);
                    int32_t tgt;
                    if (qjs_resolve_label(bc, len, pc, sz, info->fmt, r->big_endian, &tgt))
                        fprintf(out, ", \"target\": %u", (uint32_t)tgt);
                    break;
                }
                case QJS_FMT_label8:
                case QJS_FMT_label16:
                case QJS_FMT_label:
                case QJS_FMT_label_u16: {
                    int32_t tgt;
                    if (qjs_resolve_label(bc, len, pc, sz, info->fmt, r->big_endian, &tgt))
                        fprintf(out, ", \"target\": %u", (uint32_t)tgt);
                    break;
                }
                default:
                    break;
            }
            fprintf(out, "}");
            first_insn = 0;
        }

        pc += sz;
    }

    if (mode == QJS_OUT_JSON) {
        fprintf(out, "\n");
        put_indent(out, indent);
        fprintf(out, "]\n");
    }
}

/* =========================================================
 * Recursive function disassembler
 *
 * Visits nested functions first (depth-first), so they appear in
 * a logical order in the output.
 * ========================================================= */
int g_cpool_counter = 0;

void qjs_disasm_function(FILE *out, qjs_reader_t *r, qjs_function_t *fn,
                          int cpool_base, qjs_output_mode_t mode, int indent) {
    /* recurse into nested functions first (so they're dumped before this one) */
    if (fn->cpool) {
        for (int i = 0; i < fn->cpool_count; i++) {
            qjs_value_t *v = fn->cpool[i];
            if (v && v->kind == QJS_VAL_FUNCTION) {
                qjs_function_t *nested = v->u.func.fn;
                int nested_base = g_cpool_counter;
                g_cpool_counter += nested->cpool_count;
                qjs_disasm_function(out, r, nested, nested_base, mode, indent);
            }
        }
    }

    if (mode == QJS_OUT_TEXT) {
        fprintf(out, "\n");
    } else if (mode == QJS_OUT_JSON) {
        if (fn->func_idx > 1) fprintf(out, ",\n");
    }

    qjs_print_function_header(out, r, fn, indent, mode);
    print_vardefs(out, r, fn, indent, mode);
    print_closure_vars(out, r, fn, indent, mode);
    qjs_print_cpool(out, r, fn, cpool_base, indent, mode);
    disasm_bytecode(out, r, fn, cpool_base, indent, mode);

    if (mode == QJS_OUT_TEXT) {
        put_indent(out, indent);
        fprintf(out, "; ===== End Function #%d =====\n\n", fn->func_idx);
    }
}

/* =========================================================
 * Top-level value dispatcher
 * ========================================================= */
void qjs_disasm_value(FILE *out, qjs_reader_t *r, qjs_value_t *v,
                       qjs_output_mode_t mode, int indent) {
    if (!v) {
        if (mode == QJS_OUT_TEXT) {
            fprintf(out, "; <null value - parse error>\n");
        }
        return;
    }

    switch (v->kind) {
        case QJS_VAL_FUNCTION: {
            qjs_function_t *fn = v->u.func.fn;
            int base = g_cpool_counter;
            g_cpool_counter += fn->cpool_count;
            qjs_disasm_function(out, r, fn, base, mode, indent);
            break;
        }
        case QJS_VAL_MODULE: {
            qjs_module_t *m = v->u.mod.mod;
            if (mode == QJS_OUT_TEXT) {
                fprintf(out, "; ===== Module: %s =====\n",
                        qjs_atom_str(r, m->module_name_atom));
                if (m->req_module_count > 0) {
                    fprintf(out, "; Imports:\n");
                    for (int i = 0; i < m->req_module_count; i++) {
                        fprintf(out, ";   from \"%s\"\n",
                                qjs_atom_str(r, m->req_modules[i].module_name_atom));
                    }
                }
                if (m->export_count > 0) {
                    fprintf(out, "; Exports:\n");
                    for (int i = 0; i < m->export_count; i++) {
                        qjs_export_entry_t *e = &m->exports[i];
                        if (e->export_type == 0) {
                            fprintf(out, ";   export %s;\n",
                                    qjs_atom_str(r, e->export_name_atom));
                        } else {
                            fprintf(out, ";   export { %s as %s } from \"%s\";\n",
                                    qjs_atom_str(r, e->local_name_atom),
                                    qjs_atom_str(r, e->export_name_atom),
                                    qjs_atom_str(r, m->req_modules[e->var_idx].module_name_atom));
                        }
                    }
                }
                fprintf(out, "\n");
            } else if (mode == QJS_OUT_JSON) {
                fprintf(out, "{\n");
                put_indent(out, indent + 1);
                fprintf(out, "\"type\": \"module\",\n");
                put_indent(out, indent + 1);
                fprintf(out, "\"name\": \"%s\"\n", qjs_atom_str(r, m->module_name_atom));
                put_indent(out, indent);
                fprintf(out, "}\n");
            }

            if (m->func) {
                int base = g_cpool_counter;
                g_cpool_counter += m->func->cpool_count;
                qjs_disasm_function(out, r, m->func, base, mode, indent);
            }
            break;
        }
        default: {
            /* just print the value */
            char *s = qjs_format_value(r, v, 8);
            if (mode == QJS_OUT_TEXT) {
                fprintf(out, "; Top-level value: %s\n", s);
            } else if (mode == QJS_OUT_JSON) {
                fprintf(out, "{\n");
                put_indent(out, indent + 1);
                fprintf(out, "\"type\": \"value\",\n");
                put_indent(out, indent + 1);
                fprintf(out, "\"value\": %s\n", s);
                put_indent(out, indent);
                fprintf(out, "}\n");
            }
            free(s);
            break;
        }
    }
}

/* Reset the global cpool counter (call before each full dump) */
void qjs_disasm_reset(void) {
    g_cpool_counter = 0;
}
