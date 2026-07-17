/*
 * decompile.c - Pseudo-decompiler implementation
 *
 * Uses a virtual stack to track expressions and emits JS-like
 * pseudo-source. This is a best-effort decompiler - it won't
 * produce perfectly idiomatic JS, but it gives a readable
 * approximation of what the bytecode does.
 */
#include "decompile.h"
#include "disasm.h"
#include "value.h"
#include "qjs_opcodes.h"
#include "util.h"
#include <stdarg.h>
#include <ctype.h>
#include <string.h>

#define MAX_STACK  256
#define MAX_LABELS 4096

/* shared global cpool counter (defined in disasm.c) */
extern int g_cpool_counter;

/* =========================================================
 * String builder
 * ========================================================= */
typedef struct {
    char  *buf;
    size_t len;
    size_t cap;
} sbuf_t;

static void sb_init(sbuf_t *s) {
    s->buf = xmalloc(1);
    s->buf[0] = '\0';
    s->len = 0;
    s->cap = 1;
}
static void sb_free(sbuf_t *s) { free(s->buf); s->buf = NULL; s->len = s->cap = 0; }
static void sb_reserve(sbuf_t *s, size_t extra) {
    if (s->len + extra + 1 > s->cap) {
        while (s->len + extra + 1 > s->cap) s->cap = s->cap ? s->cap * 2 : 64;
        s->buf = xrealloc(s->buf, s->cap);
    }
}
static void sb_append(sbuf_t *s, const char *str, size_t n) {
    sb_reserve(s, n);
    memcpy(s->buf + s->len, str, n);
    s->len += n;
    s->buf[s->len] = '\0';
}
static void sb_puts(sbuf_t *s, const char *str) { sb_append(s, str, strlen(str)); }
static void sb_putc(sbuf_t *s, char c) { sb_reserve(s, 1); s->buf[s->len++] = c; s->buf[s->len] = '\0'; }
static void sb_printf(sbuf_t *s, const char *fmt, ...) {
    char tmp[512];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(tmp, sizeof(tmp), fmt, ap);
    va_end(ap);
    if (n < 0) return;
    if ((size_t)n < sizeof(tmp)) {
        sb_append(s, tmp, n);
    } else {
        char *big = xmalloc(n + 1);
        va_start(ap, fmt);
        vsnprintf(big, n + 1, fmt, ap);
        va_end(ap);
        sb_append(s, big, n);
        free(big);
    }
}

/* =========================================================
 * Stack slot
 *
 * Each slot holds a string representation of the value on the
 * virtual stack. We also track whether it's a "simple" expression
 * (a literal or variable) vs a complex one (needs parens).
 * ========================================================= */
typedef struct {
    char *expr;
    int   is_simple;     /* 1 if atom/literal, 0 if complex */
    int   is_lvalue;     /* 1 if can be assigned to */
} slot_t;

typedef struct {
    slot_t slots[MAX_STACK];
    int    top;
} vstack_t;

static void vs_init(vstack_t *vs) {
    memset(vs, 0, sizeof(*vs));
    vs->top = 0;
}

static void vs_free(vstack_t *vs) {
    for (int i = 0; i < vs->top; i++) free(vs->slots[i].expr);
    vs->top = 0;
}

static int vs_push(vstack_t *vs, const char *expr, int is_simple, int is_lvalue) {
    if (vs->top >= MAX_STACK) return -1;
    vs->slots[vs->top].expr = xstrdup(expr ? expr : "<null>");
    vs->slots[vs->top].is_simple = is_simple;
    vs->slots[vs->top].is_lvalue = is_lvalue;
    return vs->top++;
}

static int vs_push_take(vstack_t *vs, char *expr, int is_simple, int is_lvalue) {
    int r = vs_push(vs, expr, is_simple, is_lvalue);
    free(expr);
    return r;
}

static slot_t vs_pop(vstack_t *vs) {
    if (vs->top <= 0) {
        slot_t empty = { xstrdup("<empty>"), 0, 0 };
        return empty;
    }
    return vs->slots[--vs->top];
}

static slot_t vs_peek(vstack_t *vs, int from_top) {
    int idx = vs->top - 1 - from_top;
    if (idx < 0 || idx >= vs->top) {
        slot_t empty = { xstrdup("<empty>"), 0, 0 };
        return empty;
    }
    return vs->slots[idx];
}

/* =========================================================
 * Output buffer with line tracking
 * ========================================================= */
typedef struct {
    FILE *f;
    int   indent;
} out_t;

static void out_line(out_t *o, const char *s) {
    put_indent(o->f, o->indent);
    fputs(s, o->f);
    fputc('\n', o->f);
}

/* =========================================================
 * Atom operand resolver (re-uses disasm logic)
 * ========================================================= */
static const char *atom_op(qjs_reader_t *r, const uint8_t *bc, uint32_t off) {
    uint32_t raw = rd_u32(bc + off, r->big_endian);
    return qjs_atom_str(r, raw);
}

/* =========================================================
 * Format a constant-pool value as a JS literal (re-uses disasm)
 * ========================================================= */
static char *value_to_js(qjs_reader_t *r, qjs_value_t *v) {
    return qjs_format_value(r, v, 6);
}

/* =========================================================
 * Helpers for emitting expressions
 * ========================================================= */
static char *make_binop(const char *a, const char *op, const char *b) {
    size_t la = strlen(a), lb = strlen(b), lo = strlen(op);
    char *r = xmalloc(la + lo + lb + 8);
    sprintf(r, "(%s %s %s)", a, op, b);
    return r;
}

static char *make_unop(const char *op, const char *a) {
    size_t la = strlen(a), lo = strlen(op);
    char *r = xmalloc(la + lo + 4);
    sprintf(r, "(%s%s)", op, a);
    return r;
}

static char *make_call(const char *callee, const char *args) {
    size_t la = strlen(callee), lb = strlen(args);
    char *r = xmalloc(la + lb + 4);
    sprintf(r, "%s(%s)", callee, args);
    return r;
}

__attribute__((unused))
static char *make_method_call(const char *obj, const char *method, const char *args) {
    size_t la = strlen(obj), lb = strlen(method), lc = strlen(args);
    char *r = xmalloc(la + lb + lc + 8);
    sprintf(r, "%s.%s(%s)", obj, method, args);
    return r;
}

static char *make_field_access(const char *obj, const char *field) {
    size_t la = strlen(obj), lb = strlen(field);
    char *r = xmalloc(la + lb + 4);
    sprintf(r, "%s.%s", obj, field);
    return r;
}

static char *make_index_access(const char *obj, const char *idx) {
    size_t la = strlen(obj), lb = strlen(idx);
    char *r = xmalloc(la + lb + 4);
    sprintf(r, "%s[%s]", obj, idx);
    return r;
}

/* =========================================================
 * Check if an atom name is a valid identifier
 * ========================================================= */
static int is_valid_ident(const char *s) {
    if (!s || !*s) return 0;
    if (!(isalpha((unsigned char)s[0]) || s[0] == '_' || s[0] == '$')) return 0;
    for (int i = 1; s[i]; i++) {
        if (!(isalnum((unsigned char)s[i]) || s[i] == '_' || s[i] == '$')) return 0;
    }
    return 1;
}

/* =========================================================
 * Format identifier (with dot or bracket notation)
 * ========================================================= */
static char *field_expr(const char *obj, const char *field) {
    if (is_valid_ident(field)) {
        return make_field_access(obj, field);
    } else {
        sbuf_t sb; sb_init(&sb);
        sb_puts(&sb, obj);
        sb_putc(&sb, '[');
        /* quote the field */
        sb_putc(&sb, '"');
        for (const char *p = field; *p; p++) {
            if (*p == '"' || *p == '\\') { sb_putc(&sb, '\\'); sb_putc(&sb, *p); }
            else if (*p == '\n') sb_puts(&sb, "\\n");
            else sb_putc(&sb, *p);
        }
        sb_putc(&sb, '"');
        sb_putc(&sb, ']');
        return sb.buf;
    }
}

/* =========================================================
 * Decompile bytecode body
 * ========================================================= */
static void decompile_body(out_t *o, qjs_reader_t *r, qjs_function_t *fn, int cpool_base) {
    const uint8_t *bc = fn->byte_code;
    uint32_t len = (uint32_t)fn->byte_code_len;
    vstack_t vs;
    vs_init(&vs);

    /* Pre-scan: collect label targets so we can emit "Lxxx:" markers */
    int *is_label = xcalloc(len + 1, sizeof(int));
    for (uint32_t pc = 0; pc < len;) {
        uint8_t op = bc[pc];
        if (op >= QJS_OP_INFO_COUNT) { pc++; continue; }
        const qjs_op_info_t *info = &qjs_op_info[op];
        int sz = info->size;
        if (pc + sz > len) break;

        int32_t tgt = 0;
        if (qjs_resolve_label(bc, len, pc, sz, info->fmt, r->big_endian, &tgt)) {
            if (tgt >= 0 && (uint32_t)tgt <= len)
                is_label[tgt] = 1;
        }
        pc += sz;
    }

    /* Main pass: walk instructions */
    int last_was_return = 0;
    for (uint32_t pc = 0; pc < len;) {
        /* emit label marker if needed */
        if (is_label[pc]) {
            char buf[32];
            snprintf(buf, sizeof(buf), "L%04X:", pc);
            out_line(o, buf);
        }

        uint8_t op = bc[pc];
        if (op >= QJS_OP_INFO_COUNT) {
            char buf[64];
            snprintf(buf, sizeof(buf), "/* <INVALID OP 0x%02X> */", op);
            out_line(o, buf);
            pc++;
            continue;
        }

        const qjs_op_info_t *info = &qjs_op_info[op];
        int sz = info->size;
        if (pc + sz > len) {
            out_line(o, "/* <TRUNCATED> */");
            break;
        }

        /* decode operand value once */
        uint32_t op_u32 = 0;
        int32_t  op_i32 = 0;
        uint16_t op_u16 = 0;
        int16_t  op_i16 = 0;
        uint8_t  op_u8 = 0;
        int8_t   op_i8 = 0;
        if (sz >= 2) op_u8 = bc[pc + 1];
        if (sz >= 3) op_u16 = rd_u16(bc + pc + 1, r->big_endian);
        if (sz >= 5) op_u32 = rd_u32(bc + pc + 1, r->big_endian);
        op_i8 = (int8_t)op_u8;
        op_i16 = (int16_t)op_u16;
        op_i32 = (int32_t)op_u32;

        const char *atom_name = NULL;
        if (info->fmt == QJS_FMT_atom || info->fmt == QJS_FMT_atom_u8 ||
            info->fmt == QJS_FMT_atom_u16 || info->fmt == QJS_FMT_atom_label_u8 ||
            info->fmt == QJS_FMT_atom_label_u16) {
            atom_name = atom_op(r, bc, pc + 1);
        }

        /* Big switch on opcode */
        switch (op) {
            /* ===== Constants / pushes ===== */
            case qjs_op_push_i32:
                { sbuf_t sb; sb_init(&sb);
                  sb_printf(&sb, "%d", op_i32);
                  vs_push_take(&vs, sb.buf, 1, 0); }
                break;
            case qjs_op_push_const:
            case qjs_op_push_const8:
                {
                    int idx = (op == qjs_op_push_const) ? (int)op_u32 : (int)op_u8;
                    if (idx >= 0 && idx < fn->cpool_count) {
                        char *s = value_to_js(r, fn->cpool[idx]);
                        vs_push(&vs, s, 1, 0);
                        free(s);
                    } else {
                        char buf[64]; snprintf(buf, sizeof(buf), "c[%d]", cpool_base + idx);
                        vs_push(&vs, buf, 1, 0);
                    }
                }
                break;
            case qjs_op_fclosure:
            case qjs_op_fclosure8:
                {
                    int idx = (op == qjs_op_fclosure) ? (int)op_u32 : (int)op_u8;
                    char buf[128];
                    if (idx >= 0 && idx < fn->cpool_count &&
                        fn->cpool[idx] && fn->cpool[idx]->kind == QJS_VAL_FUNCTION) {
                        qjs_function_t *nfn = fn->cpool[idx]->u.func.fn;
                        snprintf(buf, sizeof(buf), "<closure func#%d>", nfn->func_idx);
                    } else {
                        snprintf(buf, sizeof(buf), "<closure c[%d]>", cpool_base + idx);
                    }
                    vs_push(&vs, buf, 1, 0);
                }
                break;
            case qjs_op_push_atom_value: {
                /* push_atom_value pushes the atom as a string value */
                sbuf_t sb; sb_init(&sb);
                sb_putc(&sb, '"');
                const char *a = atom_name ? atom_name : "";
                for (const char *p = a; *p; p++) {
                    if (*p == '"' || *p == '\\') { sb_putc(&sb, '\\'); sb_putc(&sb, *p); }
                    else if (*p == '\n') sb_puts(&sb, "\\n");
                    else if (*p == '\r') sb_puts(&sb, "\\r");
                    else if (*p == '\t') sb_puts(&sb, "\\t");
                    else sb_putc(&sb, *p);
                }
                sb_putc(&sb, '"');
                vs_push_take(&vs, sb.buf, 1, 0);
                break;
            }
            case qjs_op_undefined:
                vs_push(&vs, "undefined", 1, 0); break;
            case qjs_op_null:
                vs_push(&vs, "null", 1, 0); break;
            case qjs_op_push_this:
                vs_push(&vs, "this", 1, 0); break;
            case qjs_op_push_false:
                vs_push(&vs, "false", 1, 0); break;
            case qjs_op_push_true:
                vs_push(&vs, "true", 1, 0); break;
            case qjs_op_object:
                vs_push(&vs, "{}", 1, 0); break;
            case qjs_op_push_minus1: vs_push(&vs, "-1", 1, 0); break;
            case qjs_op_push_0:      vs_push(&vs, "0", 1, 0); break;
            case qjs_op_push_1:      vs_push(&vs, "1", 1, 0); break;
            case qjs_op_push_2:      vs_push(&vs, "2", 1, 0); break;
            case qjs_op_push_3:      vs_push(&vs, "3", 1, 0); break;
            case qjs_op_push_4:      vs_push(&vs, "4", 1, 0); break;
            case qjs_op_push_5:      vs_push(&vs, "5", 1, 0); break;
            case qjs_op_push_6:      vs_push(&vs, "6", 1, 0); break;
            case qjs_op_push_7:      vs_push(&vs, "7", 1, 0); break;
            case qjs_op_push_i8:     { char b[32]; snprintf(b, sizeof(b), "%d", op_i8); vs_push(&vs, b, 1, 0); break; }
            case qjs_op_push_i16:    { char b[32]; snprintf(b, sizeof(b), "%d", op_i16); vs_push(&vs, b, 1, 0); break; }
            case qjs_op_push_empty_string: vs_push(&vs, "\"\"", 1, 0); break;

            /* ===== Stack manipulation ===== */
            case qjs_op_drop: {
                slot_t a = vs_pop(&vs);
                if (a.expr[0] != '<' || !strstr(a.expr, "empty")) {
                    char buf[1024];
                    snprintf(buf, sizeof(buf), "/* drop %s */", a.expr);
                    out_line(o, buf);
                }
                free(a.expr);
                break;
            }
            case qjs_op_dup: {
                slot_t a = vs_peek(&vs, 0);
                vs_push(&vs, a.expr, a.is_simple, a.is_lvalue);
                break;
            }
            case qjs_op_dup1: {
                /* a b -> a a b */
                slot_t b = vs_peek(&vs, 0);
                slot_t a = vs_peek(&vs, 1);
                if (vs.top >= 2) {
                    /* shift b up, insert a */
                    free(vs.slots[vs.top].expr);
                    vs.slots[vs.top].expr = xstrdup(b.expr);
                    vs.slots[vs.top].is_simple = b.is_simple;
                    vs.slots[vs.top].is_lvalue = b.is_lvalue;
                    vs.top++;
                    /* now insert a at position top-2 */
                    free(vs.slots[vs.top - 1].expr);
                    vs.slots[vs.top - 1].expr = xstrdup(a.expr);
                    vs.slots[vs.top - 1].is_simple = a.is_simple;
                    vs.slots[vs.top - 1].is_lvalue = a.is_lvalue;
                }
                break;
            }
            case qjs_op_swap: {
                if (vs.top >= 2) {
                    slot_t tmp = vs.slots[vs.top - 1];
                    vs.slots[vs.top - 1] = vs.slots[vs.top - 2];
                    vs.slots[vs.top - 2] = tmp;
                }
                break;
            }
            case qjs_op_nip: {
                /* a b -> b (remove second-from-top) */
                if (vs.top >= 2) {
                    free(vs.slots[vs.top - 2].expr);
                    vs.slots[vs.top - 2] = vs.slots[vs.top - 1];
                    vs.top--;
                }
                break;
            }

            /* ===== Locals / args ===== */
            /* Note: args and vars are in SEPARATE index spaces.
             * get_arg0..3 / get_arg N -> vardefs[N]
             * get_loc0..3 / get_loc8 / get_loc N -> vardefs[arg_count + N]
             * Also note: get_loc/get_arg/get_var_ref use u16 operands (size 3),
             * not u32. */
            case qjs_op_get_loc:
            case qjs_op_get_loc8:
            case qjs_op_get_loc0:
            case qjs_op_get_loc1:
            case qjs_op_get_loc2:
            case qjs_op_get_loc3:
            case qjs_op_get_loc_check:
            case qjs_op_get_loc_checkthis: {
                uint32_t loc = 0;
                if (op == qjs_op_get_loc) loc = rd_u16(bc + pc + 1, r->big_endian);
                else if (op == qjs_op_get_loc8) loc = op_u8;
                else if (op >= qjs_op_get_loc0 && op <= qjs_op_get_loc3) loc = op - qjs_op_get_loc0;
                else if (op == qjs_op_get_loc_check || op == qjs_op_get_loc_checkthis) loc = rd_u16(bc + pc + 1, r->big_endian);
                uint32_t vd_idx = fn->arg_count + loc;
                char buf[64];
                if (vd_idx < (uint32_t)fn->vardefs_count)
                    snprintf(buf, sizeof(buf), "%s", qjs_atom_str(r, fn->vardefs[vd_idx].var_name_atom));
                else
                    snprintf(buf, sizeof(buf), "loc%d", loc);
                vs_push(&vs, buf, 1, 1);
                break;
            }
            case qjs_op_get_arg:
            case qjs_op_get_arg0:
            case qjs_op_get_arg1:
            case qjs_op_get_arg2:
            case qjs_op_get_arg3: {
                uint32_t arg = 0;
                if (op == qjs_op_get_arg) arg = rd_u16(bc + pc + 1, r->big_endian);
                else arg = op - qjs_op_get_arg0;
                char buf[64];
                if (arg < (uint32_t)fn->vardefs_count)
                    snprintf(buf, sizeof(buf), "%s", qjs_atom_str(r, fn->vardefs[arg].var_name_atom));
                else
                    snprintf(buf, sizeof(buf), "arg%d", arg);
                vs_push(&vs, buf, 1, 1);
                break;
            }
            case qjs_op_put_loc:
            case qjs_op_put_loc8:
            case qjs_op_put_loc0:
            case qjs_op_put_loc1:
            case qjs_op_put_loc2:
            case qjs_op_put_loc3:
            case qjs_op_set_loc:
            case qjs_op_set_loc8:
            case qjs_op_set_loc0:
            case qjs_op_set_loc1:
            case qjs_op_set_loc2:
            case qjs_op_set_loc3:
            case qjs_op_put_arg:
            case qjs_op_put_arg0:
            case qjs_op_put_arg1:
            case qjs_op_put_arg2:
            case qjs_op_put_arg3:
            case qjs_op_set_arg:
            case qjs_op_set_arg0:
            case qjs_op_set_arg1:
            case qjs_op_set_arg2:
            case qjs_op_set_arg3:
            case qjs_op_put_loc_check:
            case qjs_op_put_loc_check_init: {
                uint32_t idx = 0;
                int is_set = 0;
                int is_arg = 0;
                if (op == qjs_op_put_loc || op == qjs_op_put_loc_check || op == qjs_op_put_loc_check_init) { idx = rd_u16(bc + pc + 1, r->big_endian); is_arg = 0; }
                else if (op == qjs_op_set_loc) { idx = rd_u16(bc + pc + 1, r->big_endian); is_set = 1; is_arg = 0; }
                else if (op == qjs_op_put_loc8) { idx = op_u8; is_arg = 0; }
                else if (op == qjs_op_set_loc8) { idx = op_u8; is_set = 1; is_arg = 0; }
                else if (op >= qjs_op_put_loc0 && op <= qjs_op_put_loc3) { idx = op - qjs_op_put_loc0; is_arg = 0; }
                else if (op >= qjs_op_set_loc0 && op <= qjs_op_set_loc3) { idx = op - qjs_op_set_loc0; is_set = 1; is_arg = 0; }
                else if (op == qjs_op_put_arg) { idx = rd_u16(bc + pc + 1, r->big_endian); is_arg = 1; }
                else if (op == qjs_op_set_arg) { idx = rd_u16(bc + pc + 1, r->big_endian); is_set = 1; is_arg = 1; }
                else if (op >= qjs_op_put_arg0 && op <= qjs_op_put_arg3) { idx = op - qjs_op_put_arg0; is_arg = 1; }
                else if (op >= qjs_op_set_arg0 && op <= qjs_op_set_arg3) { idx = op - qjs_op_set_arg0; is_set = 1; is_arg = 1; }

                /* For loc ops, the vardef index is arg_count + idx */
                uint32_t vd_idx = is_arg ? idx : (fn->arg_count + idx);
                char name[64];
                if (vd_idx < (uint32_t)fn->vardefs_count)
                    snprintf(name, sizeof(name), "%s", qjs_atom_str(r, fn->vardefs[vd_idx].var_name_atom));
                else
                    snprintf(name, sizeof(name), "%s%d", is_arg ? "arg" : "loc", idx);

                slot_t val = vs_pop(&vs);
                char buf[2048];
                if (is_set) {
                    /* set_loc also pushes the value back */
                    snprintf(buf, sizeof(buf), "%s = %s;", name, val.expr);
                    vs_push(&vs, name, 1, 1);
                } else {
                    snprintf(buf, sizeof(buf), "%s = %s;", name, val.expr);
                }
                out_line(o, buf);
                free(val.expr);
                break;
            }

            /* ===== Variables ===== */
            case qjs_op_get_var:
            case qjs_op_get_var_undef:
            case qjs_op_check_var: {
                vs_push(&vs, atom_name ? atom_name : "<var>", 1, 1);
                break;
            }
            case qjs_op_put_var:
            case qjs_op_put_var_init:
            case qjs_op_put_var_strict: {
                slot_t val = vs_pop(&vs);
                char buf[1024];
                snprintf(buf, sizeof(buf), "%s = %s;", atom_name ? atom_name : "<var>", val.expr);
                out_line(o, buf);
                free(val.expr);
                break;
            }

            /* ===== Field access ===== */
            case qjs_op_get_field:
            case qjs_op_get_field2: {
                slot_t obj = vs_pop(&vs);
                char *e = field_expr(obj.expr, atom_name ? atom_name : "");
                if (op == qjs_op_get_field2) {
                    /* get_field2 leaves: obj (below), value (on top) */
                    vs_push(&vs, obj.expr, obj.is_simple, obj.is_lvalue);
                    vs_push_take(&vs, e, 0, 1);
                } else {
                    vs_push_take(&vs, e, 0, 1);
                }
                free(obj.expr);
                break;
            }
            case qjs_op_get_array_el:
            case qjs_op_get_array_el2: {
                slot_t idx = vs_pop(&vs);
                slot_t obj = vs_pop(&vs);
                char *e = make_index_access(obj.expr, idx.expr);
                if (op == qjs_op_get_array_el2) {
                    /* leaves: obj (below), value (on top) */
                    vs_push(&vs, obj.expr, obj.is_simple, obj.is_lvalue);
                    vs_push_take(&vs, e, 0, 1);
                } else {
                    vs_push_take(&vs, e, 0, 1);
                }
                free(idx.expr); free(obj.expr);
                break;
            }
            case qjs_op_put_field: {
                slot_t val = vs_pop(&vs);
                slot_t obj = vs_pop(&vs);
                char *fld = field_expr(obj.expr, atom_name ? atom_name : "");
                char buf[2048];
                snprintf(buf, sizeof(buf), "%s = %s;", fld, val.expr);
                out_line(o, buf);
                free(val.expr); free(obj.expr); free(fld);
                break;
            }
            case qjs_op_put_array_el: {
                slot_t val = vs_pop(&vs);
                slot_t idx = vs_pop(&vs);
                slot_t obj = vs_pop(&vs);
                char *e = make_index_access(obj.expr, idx.expr);
                char buf[2048];
                snprintf(buf, sizeof(buf), "%s = %s;", e, val.expr);
                out_line(o, buf);
                free(val.expr); free(idx.expr); free(obj.expr); free(e);
                break;
            }
            case qjs_op_get_length: {
                slot_t obj = vs_pop(&vs);
                char *e = make_field_access(obj.expr, "length");
                vs_push_take(&vs, e, 0, 1);
                free(obj.expr);
                break;
            }

            /* ===== Binary ops ===== */
            case qjs_op_add: case qjs_op_sub: case qjs_op_mul: case qjs_op_div:
            case qjs_op_mod: case qjs_op_pow: case qjs_op_shl: case qjs_op_sar:
            case qjs_op_shr: case qjs_op_and: case qjs_op_or:  case qjs_op_xor:
            case qjs_op_lt:  case qjs_op_lte: case qjs_op_gt:  case qjs_op_gte:
            case qjs_op_eq:  case qjs_op_neq: case qjs_op_strict_eq: case qjs_op_strict_neq:
            case qjs_op_instanceof: case qjs_op_in: {
                slot_t b = vs_pop(&vs);
                slot_t a = vs_pop(&vs);
                const char *sym = "+";
                switch (op) {
                    case qjs_op_add: sym = "+"; break;
                    case qjs_op_sub: sym = "-"; break;
                    case qjs_op_mul: sym = "*"; break;
                    case qjs_op_div: sym = "/"; break;
                    case qjs_op_mod: sym = "%%"; break;
                    case qjs_op_pow: sym = "**"; break;
                    case qjs_op_shl: sym = "<<"; break;
                    case qjs_op_sar: sym = ">>"; break;
                    case qjs_op_shr: sym = ">>>"; break;
                    case qjs_op_and: sym = "&"; break;
                    case qjs_op_or:  sym = "|"; break;
                    case qjs_op_xor: sym = "^"; break;
                    case qjs_op_lt:  sym = "<"; break;
                    case qjs_op_lte: sym = "<="; break;
                    case qjs_op_gt:  sym = ">"; break;
                    case qjs_op_gte: sym = ">="; break;
                    case qjs_op_eq:  sym = "=="; break;
                    case qjs_op_neq: sym = "!="; break;
                    case qjs_op_strict_eq:  sym = "==="; break;
                    case qjs_op_strict_neq: sym = "!=="; break;
                    case qjs_op_instanceof: sym = "instanceof"; break;
                    case qjs_op_in: sym = "in"; break;
                }
                char *e = make_binop(a.expr, sym, b.expr);
                vs_push_take(&vs, e, 0, 0);
                free(a.expr); free(b.expr);
                break;
            }

            /* ===== Unary ops ===== */
            case qjs_op_neg: {
                slot_t a = vs_pop(&vs);
                char *e = make_unop("-", a.expr);
                vs_push_take(&vs, e, 0, 0);
                free(a.expr);
                break;
            }
            case qjs_op_plus: {
                slot_t a = vs_pop(&vs);
                char *e = make_unop("+", a.expr);
                vs_push_take(&vs, e, 0, 0);
                free(a.expr);
                break;
            }
            case qjs_op_not: {
                slot_t a = vs_pop(&vs);
                char *e = make_unop("~", a.expr);
                vs_push_take(&vs, e, 0, 0);
                free(a.expr);
                break;
            }
            case qjs_op_lnot: {
                slot_t a = vs_pop(&vs);
                char *e = make_unop("!", a.expr);
                vs_push_take(&vs, e, 0, 0);
                free(a.expr);
                break;
            }
            case qjs_op_typeof: {
                slot_t a = vs_pop(&vs);
                char *e = make_unop("typeof ", a.expr);
                vs_push_take(&vs, e, 0, 0);
                free(a.expr);
                break;
            }
            case qjs_op_inc: case qjs_op_dec: {
                slot_t a = vs_pop(&vs);
                const char *op_s = (op == qjs_op_inc) ? "++" : "--";
                char buf[256];
                snprintf(buf, sizeof(buf), "%s%s", a.expr, op_s);
                vs_push(&vs, buf, 0, 0);
                free(a.expr);
                break;
            }
            case qjs_op_post_inc: case qjs_op_post_dec: {
                slot_t a = vs_pop(&vs);
                const char *op_s = (op == qjs_op_post_inc) ? "++" : "--";
                char buf[256];
                snprintf(buf, sizeof(buf), "%s%s", a.expr, op_s);
                vs_push(&vs, buf, 0, 0);
                /* also keep original value */
                vs_push(&vs, a.expr, a.is_simple, a.is_lvalue);
                free(a.expr);
                break;
            }
            case qjs_op_inc_loc: case qjs_op_dec_loc: {
                uint32_t loc = op_u8;
                uint32_t vd_idx = fn->arg_count + loc;
                char name[64];
                if (vd_idx < (uint32_t)fn->vardefs_count)
                    snprintf(name, sizeof(name), "%s", qjs_atom_str(r, fn->vardefs[vd_idx].var_name_atom));
                else
                    snprintf(name, sizeof(name), "loc%d", loc);
                char buf[128];
                snprintf(buf, sizeof(buf), "%s%s;", name, (op == qjs_op_inc_loc) ? "++" : "--");
                out_line(o, buf);
                break;
            }
            case qjs_op_add_loc: {
                uint32_t loc = op_u8;
                uint32_t vd_idx = fn->arg_count + loc;
                char name[64];
                if (vd_idx < (uint32_t)fn->vardefs_count)
                    snprintf(name, sizeof(name), "%s", qjs_atom_str(r, fn->vardefs[vd_idx].var_name_atom));
                else
                    snprintf(name, sizeof(name), "loc%d", loc);
                slot_t v = vs_pop(&vs);
                char buf[256];
                snprintf(buf, sizeof(buf), "%s += %s;", name, v.expr);
                out_line(o, buf);
                free(v.expr);
                break;
            }

            /* ===== Calls ===== */
            case qjs_op_call:
            case qjs_op_call0:
            case qjs_op_call1:
            case qjs_op_call2:
            case qjs_op_call3: {
                int nargs = (op == qjs_op_call) ? (int)op_u16 : (op - qjs_op_call0);
                /* stack: ... callee arg1 ... argN (argN on top) */
                /* pop args in reverse, then build forward-order string */
                if (vs.top >= nargs + 1) {
                    slot_t *argv = xcalloc(nargs > 0 ? nargs : 1, sizeof(slot_t));
                    for (int i = nargs - 1; i >= 0; i--) {
                        argv[i] = vs_pop(&vs);
                    }
                    sbuf_t args; sb_init(&args);
                    for (int i = 0; i < nargs; i++) {
                        if (i > 0) sb_puts(&args, ", ");
                        sb_puts(&args, argv[i].expr);
                        free(argv[i].expr);
                    }
                    slot_t callee = vs_pop(&vs);
                    char *e = make_call(callee.expr, args.buf);
                    vs_push_take(&vs, e, 0, 0);
                    free(callee.expr);
                    sb_free(&args);
                    free(argv);
                }
                break;
            }
            case qjs_op_call_method: {
                int nargs = op_u16;
                if (vs.top >= nargs + 2) {
                    slot_t *argv = xcalloc(nargs > 0 ? nargs : 1, sizeof(slot_t));
                    for (int i = nargs - 1; i >= 0; i--) {
                        argv[i] = vs_pop(&vs);
                    }
                    sbuf_t args; sb_init(&args);
                    for (int i = 0; i < nargs; i++) {
                        if (i > 0) sb_puts(&args, ", ");
                        sb_puts(&args, argv[i].expr);
                        free(argv[i].expr);
                    }
                    slot_t method = vs_pop(&vs);
                    slot_t obj = vs_pop(&vs);
                    /* method.expr already contains "obj.field" from get_field2 */
                    char *e = make_call(method.expr, args.buf);
                    vs_push_take(&vs, e, 0, 0);
                    free(method.expr); free(obj.expr);
                    sb_free(&args);
                    free(argv);
                }
                break;
            }
            case qjs_op_call_constructor: {
                int nargs = op_u16;
                if (vs.top >= nargs + 2) {
                    slot_t *argv = xcalloc(nargs > 0 ? nargs : 1, sizeof(slot_t));
                    for (int i = nargs - 1; i >= 0; i--) {
                        argv[i] = vs_pop(&vs);
                    }
                    sbuf_t args; sb_init(&args);
                    for (int i = 0; i < nargs; i++) {
                        if (i > 0) sb_puts(&args, ", ");
                        sb_puts(&args, argv[i].expr);
                        free(argv[i].expr);
                    }
                    slot_t new_target = vs_pop(&vs);
                    free(new_target.expr);
                    slot_t ctor = vs_pop(&vs);
                    sbuf_t sb; sb_init(&sb);
                    sb_puts(&sb, "(new ");
                    sb_puts(&sb, ctor.expr);
                    sb_putc(&sb, '(');
                    sb_puts(&sb, args.buf);
                    sb_putc(&sb, ')');
                    sb_putc(&sb, ')');
                    vs_push_take(&vs, sb.buf, 0, 0);
                    free(ctor.expr);
                    sb_free(&args);
                    free(argv);
                }
                break;
            }
            case qjs_op_array_from: {
                int nargs = op_u16;
                if (vs.top >= nargs) {
                    slot_t *argv = xcalloc(nargs > 0 ? nargs : 1, sizeof(slot_t));
                    for (int i = nargs - 1; i >= 0; i--) {
                        argv[i] = vs_pop(&vs);
                    }
                    sbuf_t args; sb_init(&args);
                    for (int i = 0; i < nargs; i++) {
                        if (i > 0) sb_puts(&args, ", ");
                        sb_puts(&args, argv[i].expr);
                        free(argv[i].expr);
                    }
                    sbuf_t sb; sb_init(&sb);
                    sb_putc(&sb, '[');
                    sb_puts(&sb, args.buf);
                    sb_putc(&sb, ']');
                    vs_push_take(&vs, sb.buf, 1, 0);
                    sb_free(&args);
                    free(argv);
                }
                break;
            }

            /* ===== Returns / throws ===== */
            case qjs_op_return: {
                slot_t v = vs_pop(&vs);
                char buf[1024];
                snprintf(buf, sizeof(buf), "return %s;", v.expr);
                out_line(o, buf);
                free(v.expr);
                last_was_return = 1;
                break;
            }
            case qjs_op_return_undef:
                out_line(o, "return;");
                last_was_return = 1;
                break;
            case qjs_op_throw: {
                slot_t v = vs_pop(&vs);
                char buf[1024];
                snprintf(buf, sizeof(buf), "throw %s;", v.expr);
                out_line(o, buf);
                free(v.expr);
                break;
            }
            case qjs_op_throw_error: {
                char buf[256];
                snprintf(buf, sizeof(buf), "throw new Error(\"%s\"); /* type=%u */",
                         atom_name ? atom_name : "", op_u8);
                out_line(o, buf);
                break;
            }

            /* ===== Control flow ===== */
            case qjs_op_goto:
            case qjs_op_goto8:
            case qjs_op_goto16: {
                int32_t tgt;
                if (qjs_resolve_label(bc, len, pc, sz, info->fmt, r->big_endian, &tgt)) {
                    char buf[64];
                    snprintf(buf, sizeof(buf), "goto L%04X;", (uint32_t)tgt);
                    out_line(o, buf);
                }
                break;
            }
            case qjs_op_if_false:
            case qjs_op_if_false8:
            case qjs_op_if_true:
            case qjs_op_if_true8: {
                slot_t cond = vs_pop(&vs);
                int32_t tgt;
                if (qjs_resolve_label(bc, len, pc, sz, info->fmt, r->big_endian, &tgt)) {
                    const char *kw = (op == qjs_op_if_false || op == qjs_op_if_false8) ? "if (!" : "if (";
                    const char *close = (op == qjs_op_if_false || op == qjs_op_if_false8) ? ")" : ")";
                    char buf[1024];
                    snprintf(buf, sizeof(buf), "%s%s%s goto L%04X;", kw, cond.expr, close, (uint32_t)tgt);
                    out_line(o, buf);
                }
                free(cond.expr);
                break;
            }

            /* ===== Object/array construction ===== */
            case qjs_op_define_field:
            case qjs_op_set_name: {
                /* stack: obj val -> obj (with field set) */
                slot_t val = vs_pop(&vs);
                slot_t obj = vs_pop(&vs);
                char *fld = field_expr(obj.expr, atom_name ? atom_name : "");
                char buf[2048];
                snprintf(buf, sizeof(buf), "%s = %s;", fld, val.expr);
                out_line(o, buf);
                vs_push(&vs, obj.expr, obj.is_simple, obj.is_lvalue);
                free(val.expr); free(obj.expr); free(fld);
                break;
            }
            case qjs_op_define_array_el: {
                /* obj val idx -> obj (with arr[idx] = val) */
                slot_t idx = vs_pop(&vs);
                slot_t val = vs_pop(&vs);
                slot_t obj = vs_pop(&vs);
                char *e = make_index_access(obj.expr, idx.expr);
                char buf[2048];
                snprintf(buf, sizeof(buf), "%s = %s;", e, val.expr);
                out_line(o, buf);
                vs_push(&vs, obj.expr, obj.is_simple, obj.is_lvalue);
                free(idx.expr); free(val.expr); free(obj.expr); free(e);
                break;
            }

            /* ===== Var/func definitions ===== */
            case qjs_op_define_var: {
                char buf[128];
                const char *kw = (op_u8 & 2) ? "let" : (op_u8 & 4) ? "const" : "var";
                snprintf(buf, sizeof(buf), "%s %s;", kw, atom_name ? atom_name : "");
                out_line(o, buf);
                break;
            }
            case qjs_op_define_func: {
                slot_t fn_val = vs_pop(&vs);
                char buf[256];
                snprintf(buf, sizeof(buf), "function %s() { /* %s */ };",
                         atom_name ? atom_name : "", fn_val.expr);
                out_line(o, buf);
                free(fn_val.expr);
                break;
            }

            /* ===== typeof / delete ===== */
            case qjs_op_delete: {
                slot_t a = vs_pop(&vs);
                slot_t b = vs_pop(&vs);
                char *e = make_unop("delete ", make_index_access(b.expr, a.expr));
                vs_push_take(&vs, e, 0, 0);
                free(a.expr); free(b.expr);
                break;
            }
            case qjs_op_delete_var: {
                char *e = make_unop("delete ", atom_name ? atom_name : "");
                vs_push_take(&vs, e, 0, 0);
                break;
            }

            /* ===== Misc ===== */
            case qjs_op_nop:
                break;
            case qjs_op_special_object: {
                const char *name = "<special>";
                switch (op_u8) {
                    case 0: name = "this"; break;
                    case 1: name = "new.target"; break;
                    case 2: name = "home_object"; break;
                    case 3: name = "function"; break;
                }
                vs_push(&vs, name, 1, 0);
                break;
            }
            case qjs_op_await: {
                slot_t a = vs_pop(&vs);
                char *e = make_unop("await ", a.expr);
                vs_push_take(&vs, e, 0, 0);
                free(a.expr);
                break;
            }
            case qjs_op_yield: {
                slot_t a = vs_pop(&vs);
                char *e = make_unop("yield ", a.expr);
                vs_push_take(&vs, e, 0, 0);
                free(a.expr);
                break;
            }
            case qjs_op_import:
                vs_push(&vs, "import()", 1, 0);
                break;
            case qjs_op_regexp: {
                /* stack: pattern flags -> regex */
                slot_t flags = vs_pop(&vs);
                slot_t pat = vs_pop(&vs);
                sbuf_t sb; sb_init(&sb);
                sb_putc(&sb, '/');
                sb_puts(&sb, pat.expr);
                sb_putc(&sb, '/');
                sb_puts(&sb, flags.expr);
                vs_push_take(&vs, sb.buf, 1, 0);
                free(pat.expr); free(flags.expr);
                break;
            }

            /* For ops we don't handle specially, dump a comment */
            default: {
                sbuf_t sb; sb_init(&sb);
                sb_printf(&sb, "/* %s", info->name);
                if (atom_name) sb_printf(&sb, " %s", atom_name);
                sb_puts(&sb, " */");
                out_line(o, sb.buf);
                sb_free(&sb);

                /* Adjust the virtual stack based on pop/push */
                int pops = info->n_pop;
                int pushes = info->n_push;
                while (pops > 0 && vs.top > 0) {
                    slot_t s = vs_pop(&vs);
                    free(s.expr);
                    pops--;
                }
                while (pushes > 0) {
                    vs_push(&vs, "<unknown>", 0, 0);
                    pushes--;
                }
                break;
            }
        }

        pc += sz;
    }

    free(is_label);
    vs_free(&vs);
    (void)last_was_return;
}

/* =========================================================
 * Decompile a function
 * ========================================================= */
void qjs_decompile_function(FILE *out, qjs_reader_t *r, qjs_function_t *fn,
                             int cpool_base, int indent) {
    /* recurse into nested functions first */
    if (fn->cpool) {
        for (int i = 0; i < fn->cpool_count; i++) {
            qjs_value_t *v = fn->cpool[i];
            if (v && v->kind == QJS_VAL_FUNCTION) {
                qjs_function_t *nested = v->u.func.fn;
                int nested_base = g_cpool_counter;
                g_cpool_counter += nested->cpool_count;
                qjs_decompile_function(out, r, nested, nested_base, indent);
            }
        }
    }

    /* Print function header */
    const char *name = qjs_atom_str(r, fn->func_name_atom);
    const char *kind = "function";
    if (fn->flags.func_kind == 1) kind = "function*";
    else if (fn->flags.func_kind == 2) kind = "async function";
    else if (fn->flags.func_kind == 3) kind = "async function*";

    /* Build arg list - only the first arg_count vardefs are args */
    sbuf_t args; sb_init(&args);
    int n_args = fn->arg_count;
    if (n_args > fn->vardefs_count) n_args = fn->vardefs_count;
    for (int i = 0; i < n_args; i++) {
        if (i > 0) sb_puts(&args, ", ");
        sb_puts(&args, qjs_atom_str(r, fn->vardefs[i].var_name_atom));
    }

    out_t o = { out, indent };
    char header[256];
    snprintf(header, sizeof(header), "%s %s(%s) {", kind, name[0] ? name : "anon", args.buf);
    out_line(&o, header);
    o.indent++;
    decompile_body(&o, r, fn, cpool_base);
    o.indent--;
    out_line(&o, "}");
    out_line(&o, "");

    sb_free(&args);
}

/* Global counter is declared at the top of this file (extern) */

void qjs_decompile_value(FILE *out, qjs_reader_t *r, qjs_value_t *v, int indent) {
    if (!v) {
        fprintf(out, "/* <null value> */\n");
        return;
    }
    switch (v->kind) {
        case QJS_VAL_FUNCTION: {
            qjs_function_t *fn = v->u.func.fn;
            int base = g_cpool_counter;
            g_cpool_counter += fn->cpool_count;
            qjs_decompile_function(out, r, fn, base, indent);
            break;
        }
        case QJS_VAL_MODULE: {
            qjs_module_t *m = v->u.mod.mod;
            out_t o = { out, indent };
            out_line(&o, "/* ===== Module ===== */");
            for (int i = 0; i < m->req_module_count; i++) {
                char buf[256];
                snprintf(buf, sizeof(buf), "import * from \"%s\";",
                         qjs_atom_str(r, m->req_modules[i].module_name_atom));
                out_line(&o, buf);
            }
            for (int i = 0; i < m->export_count; i++) {
                qjs_export_entry_t *e = &m->exports[i];
                char buf[256];
                if (e->export_type == 0) {
                    snprintf(buf, sizeof(buf), "export %s;",
                             qjs_atom_str(r, e->export_name_atom));
                } else {
                    snprintf(buf, sizeof(buf), "export { %s as %s };",
                             qjs_atom_str(r, e->local_name_atom),
                             qjs_atom_str(r, e->export_name_atom));
                }
                out_line(&o, buf);
            }
            out_line(&o, "");
            if (m->func) {
                int base = g_cpool_counter;
                g_cpool_counter += m->func->cpool_count;
                qjs_decompile_function(out, r, m->func, base, indent);
            }
            break;
        }
        default: {
            char *s = qjs_format_value(r, v, 8);
            fprintf(out, "/* top-level value: %s */\n", s);
            free(s);
            break;
        }
    }
}
