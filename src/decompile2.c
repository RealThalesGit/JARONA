/*
 * decompile2.c - Statement-based decompiler with control flow recovery
 *
 * Replaces the old line-by-line decompiler with a two-pass approach:
 *   1. Decode bytecode into IR instructions
 *   2. Walk instructions, building statements with structured control flow
 *
 * Recognizes: if/else, while, for, do-while, break, continue, try/catch
 */
#include "decompile.h"
#include "ir.h"
#include "value.h"
#include "disasm.h"
#include "qjs_opcodes.h"
#include "qjs_opcodes_frida.h"
#include "expr.h"
#include "util.h"
#include <stdarg.h>
#include <ctype.h>
#include <string.h>

#define MAX_STACK  256

/* =========================================================
 * String builder (reused from old decompiler)
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
 * Virtual stack slot
 * ========================================================= */
typedef struct {
    char *expr;
    int   is_simple;     /* 1 if atom/literal, 0 if complex */
    int   is_lvalue;     /* 1 if can be assigned to */
    int   prec;          /* operator precedence (higher = tighter binding) */
} slot_t;

typedef struct {
    slot_t slots[MAX_STACK];
    int    top;
} vstack_t;

static void vs_init(vstack_t *vs) { memset(vs, 0, sizeof(*vs)); vs->top = 0; }
static void vs_free(vstack_t *vs) {
    for (int i = 0; i < vs->top; i++) free(vs->slots[i].expr);
    vs->top = 0;
}

/* Push with explicit precedence */
static int vs_push_prec(vstack_t *vs, const char *expr, int prec, int is_lvalue) {
    if (vs->top >= MAX_STACK) return -1;
    vs->slots[vs->top].expr = xstrdup(expr ? expr : "<null>");
    vs->slots[vs->top].is_simple = (prec >= PREC_ATOM);
    vs->slots[vs->top].is_lvalue = is_lvalue;
    vs->slots[vs->top].prec = prec;
    return vs->top++;
}

/* Push simple value (atom/literal/variable) - convenience wrapper */
static int vs_push(vstack_t *vs, const char *expr, int is_simple, int is_lvalue) {
    return vs_push_prec(vs, expr, is_simple ? PREC_ATOM : PREC_COMMA, is_lvalue);
}

/* Push and take ownership of expr */
static int vs_push_take_prec(vstack_t *vs, char *expr, int prec, int is_lvalue) {
    int r = vs_push_prec(vs, expr, prec, is_lvalue);
    free(expr);
    return r;
}

static int vs_push_take(vstack_t *vs, char *expr, int is_simple, int is_lvalue) {
    return vs_push_take_prec(vs, expr, is_simple ? PREC_ATOM : PREC_COMMA, is_lvalue);
}

static slot_t vs_pop(vstack_t *vs) {
    if (vs->top <= 0) {
        slot_t empty = { xstrdup("undefined"), 1, 0, PREC_ATOM };
        return empty;
    }
    return vs->slots[--vs->top];
}
static slot_t vs_peek(vstack_t *vs, int from_top) {
    int idx = vs->top - 1 - from_top;
    if (idx < 0 || idx >= vs->top) {
        slot_t empty = { xstrdup("undefined"), 1, 0, PREC_ATOM };
        return empty;
    }
    return vs->slots[idx];
}

/* =========================================================
 * Statement list
 * ========================================================= */
typedef struct {
    ir_stmt_t **items;
    int count;
    int cap;
} stmt_list_t;

static void sl_init(stmt_list_t *sl) { sl->items = NULL; sl->count = 0; sl->cap = 0; }
static void sl_free(stmt_list_t *sl) {
    for (int i = 0; i < sl->count; i++) ir_stmt_free(sl->items[i]);
    free(sl->items);
    sl->items = NULL; sl->count = sl->cap = 0;
}
static void sl_push(stmt_list_t *sl, ir_stmt_t *s) {
    if (sl->count >= sl->cap) {
        sl->cap = sl->cap ? sl->cap * 2 : 8;
        sl->items = xrealloc(sl->items, sl->cap * sizeof(ir_stmt_t *));
    }
    sl->items[sl->count++] = s;
}

/* =========================================================
 * Statement constructors
 * ========================================================= */
static ir_stmt_t *stmt_new(ir_stmt_kind_t kind) {
    ir_stmt_t *s = xcalloc(1, sizeof(*s));
    s->kind = kind;
    return s;
}

static ir_stmt_t *stmt_expr(char *expr) {
    ir_stmt_t *s = stmt_new(IR_STMT_EXPR);
    s->expr = expr;
    return s;
}

static ir_stmt_t *stmt_return(char *expr) {
    ir_stmt_t *s = stmt_new(IR_STMT_RETURN);
    s->expr = expr;
    return s;
}

static ir_stmt_t *stmt_throw(char *expr) {
    ir_stmt_t *s = stmt_new(IR_STMT_THROW);
    s->expr = expr;
    return s;
}

static ir_stmt_t *stmt_assign(char *lv, char *rhs) {
    ir_stmt_t *s = stmt_new(IR_STMT_ASSIGN);
    s->lvalue = lv;
    s->rhs = rhs;
    return s;
}

static ir_stmt_t *stmt_compound_assign(char *lv, const char *op, char *rhs) {
    ir_stmt_t *s = stmt_new(IR_STMT_COMPOUND_ASSIGN);
    s->lvalue = lv;
    s->op = xstrdup(op);
    s->rhs = rhs;
    return s;
}

static ir_stmt_t *stmt_decl(const char *name, char *rhs, int decl_kind) {
    ir_stmt_t *s = stmt_new(IR_STMT_DECL);
    s->lvalue = xstrdup(name);
    s->rhs = rhs;
    s->decl_kind = decl_kind;
    return s;
}

static ir_stmt_t *stmt_break(void) { return stmt_new(IR_STMT_BREAK); }
static ir_stmt_t *stmt_continue(void) { return stmt_new(IR_STMT_CONTINUE); }

static ir_stmt_t *stmt_label(const char *name) {
    ir_stmt_t *s = stmt_new(IR_STMT_LABEL);
    s->label = xstrdup(name);
    return s;
}

static ir_stmt_t *stmt_goto(const char *name) {
    ir_stmt_t *s = stmt_new(IR_STMT_GOTO);
    s->label = xstrdup(name);
    return s;
}

static ir_stmt_t *stmt_raw(const char *comment) {
    ir_stmt_t *s = stmt_new(IR_STMT_RAW);
    s->expr = xstrdup(comment);
    return s;
}

static ir_stmt_t *stmt_block(stmt_list_t *sl) {
    ir_stmt_t *s = stmt_new(IR_STMT_BLOCK);
    if (sl) {
        s->children = sl->items;
        s->n_children = sl->count;
        sl->items = NULL; sl->count = sl->cap = 0;
    } else {
        s->children = NULL;
        s->n_children = 0;
    }
    return s;
}

static ir_stmt_t *stmt_if(char *cond, ir_stmt_t *then_s, ir_stmt_t *else_s) {
    ir_stmt_t *s = stmt_new(IR_STMT_IF);
    s->cond = cond;
    s->body = then_s;
    s->else_body = else_s;
    return s;
}

static ir_stmt_t *stmt_while(char *cond, ir_stmt_t *body) {
    ir_stmt_t *s = stmt_new(IR_STMT_WHILE);
    s->cond = cond;
    s->body = body;
    return s;
}

static ir_stmt_t *stmt_do_while(char *cond, ir_stmt_t *body) {
    ir_stmt_t *s = stmt_new(IR_STMT_DO_WHILE);
    s->cond = cond;
    s->body = body;
    return s;
}

static ir_stmt_t *stmt_for(ir_stmt_t *init, char *cond, ir_stmt_t *update, ir_stmt_t *body) {
    ir_stmt_t *s = stmt_new(IR_STMT_FOR);
    s->init = init;
    s->cond = cond;
    s->update = update;
    s->body = body;
    return s;
}

/* =========================================================
 * Free statement tree
 * ========================================================= */
void ir_stmt_free(ir_stmt_t *s) {
    if (!s) return;
    free(s->expr);
    free(s->lvalue);
    free(s->rhs);
    free(s->op);
    free(s->cond);
    free(s->label);
    free(s->catch_var);
    ir_stmt_free(s->body);
    ir_stmt_free(s->else_body);
    ir_stmt_free(s->init);
    ir_stmt_free(s->update);
    ir_stmt_free(s->catch_body);
    ir_stmt_free(s->finally_body);
    if (s->children) {
        for (int i = 0; i < s->n_children; i++) ir_stmt_free(s->children[i]);
        free(s->children);
    }
    free(s);
}

/* =========================================================
 * Helpers
 * ========================================================= */
static const char *atom_name_of(qjs_reader_t *r, ir_insn_t *insn) {
    if (!insn || !insn->info) return "";
    switch (insn->info->fmt) {
        case QJS_FMT_atom:
        case QJS_FMT_atom_u8:
        case QJS_FMT_atom_u16:
        case QJS_FMT_atom_label_u8:
        case QJS_FMT_atom_label_u16:
            return qjs_atom_str(r, insn->atom_val);
        default:
            return "";
    }
}

static int is_valid_ident(const char *s) {
    if (!s || !*s) return 0;
    if (!(isalpha((unsigned char)s[0]) || s[0] == '_' || s[0] == '$')) return 0;
    for (int i = 1; s[i]; i++) {
        if (!(isalnum((unsigned char)s[i]) || s[i] == '_' || s[i] == '$')) return 0;
    }
    return 1;
}

static char *field_expr(const char *obj, const char *field) {
    if (is_valid_ident(field)) {
        size_t la = strlen(obj), lb = strlen(field);
        char *r = xmalloc(la + lb + 2);
        sprintf(r, "%s.%s", obj, field);
        return r;
    } else {
        sbuf_t sb; sb_init(&sb);
        sb_puts(&sb, obj);
        sb_putc(&sb, '[');
        sb_putc(&sb, '"');
        for (const char *p = field; *p; p++) {
            if (*p == '"' || *p == '\\') { sb_putc(&sb, '\\'); sb_putc(&sb, *p); }
            else if (*p == '\n') sb_puts(&sb, "\\n");
            else if (*p == '\r') sb_puts(&sb, "\\r");
            else if (*p == '\t') sb_puts(&sb, "\\t");
            else sb_putc(&sb, *p);
        }
        sb_putc(&sb, '"');
        sb_putc(&sb, ']');
        return sb.buf;
    }
}

static char *make_binop(const char *a, const char *op, const char *b) {
    sbuf_t sb; sb_init(&sb);
    sb_puts(&sb, a);
    sb_putc(&sb, ' ');
    sb_puts(&sb, op);
    sb_putc(&sb, ' ');
    sb_puts(&sb, b);
    return sb.buf;
}

static char *make_unop(const char *op, const char *a) {
    sbuf_t sb; sb_init(&sb);
    sb_puts(&sb, op);
    sb_puts(&sb, a);
    return sb.buf;
}

/* Close an open object literal expression in-place */
static void close_obj_if_open(slot_t *s) {
    if (s->expr && s->expr[0] == '{' && s->expr[strlen(s->expr)-1] != '}') {
        size_t len = strlen(s->expr);
        char *new_expr = xmalloc(len + 2);
        memcpy(new_expr, s->expr, len);
        new_expr[len] = '}';
        new_expr[len+1] = '\0';
        free(s->expr);
        s->expr = new_expr;
    }
}

/* Check if an expression is already fully parenthesized (starts with '(' and
 * the first '(' matches the last ')'). This prevents double-wrapping. */
static int already_parenthesized(const char *expr) {
    if (!expr || !*expr || expr[0] != '(') return 0;
    size_t len = strlen(expr);
    if (expr[len - 1] != ')') return 0;
    int depth = 0;
    for (size_t i = 0; i < len; i++) {
        if (expr[i] == '(') depth++;
        else if (expr[i] == ')') {
            depth--;
            if (depth == 0 && i < len - 1) return 0; /* closing before end */
        }
    }
    return depth == 0;
}

/* Readability heuristic: add parens around arithmetic/logical expressions
 * when used as operands of bitwise/shift/equality operators.
 * This makes code like "(a + b) & 255" clearer even though
 * "a + b & 255" is semantically equivalent. */
static int should_paren_for_readability(int child_prec, int parent_prec) {
    /* Precedence hierarchy (lower = looser binding):
     * BOR(6) < BXOR(7) < BAND(8) < EQ(9) < REL(10) < SHIFT(11) < ADD(12) < MUL(13)
     *
     * If child is arithmetic/shift (PREC_SHIFT to PREC_MUL, i.e., 11-13)
     * and parent is bitwise/equality/relational (PREC_BOR to PREC_REL, i.e., 6-10),
     * add parens for clarity. */
    if (child_prec >= PREC_SHIFT && child_prec <= PREC_MUL) {
        /* Child is shift or arithmetic (11-13) */
        if (parent_prec >= PREC_BOR && parent_prec <= PREC_REL) {
            /* Parent is bitwise/equality/relational (6-10) */
            return 1;
        }
    }
    /* If child is bitwise (6-8) and parent is equality/relational (9-10), add parens */
    if (child_prec >= PREC_BOR && child_prec <= PREC_BAND) {
        if (parent_prec >= PREC_EQ && parent_prec <= PREC_REL) {
            return 1;
        }
    }
    return 0;
}

/* Build a binary op with proper parenthesization based on precedence.
 * Takes ownership of a.expr and b.expr. */
static char *build_binop(slot_t a, const char *op, slot_t b) {
    int oprec = op_prec(op);
    int ra = is_right_assoc(op);

    /* Wrap left if needed (precedence-based) */
    if (needs_parens_left(a.prec, oprec, ra) && !already_parenthesized(a.expr)) {
        a.expr = wrap_parens(a.expr);
    }
    /* Readability: add parens for arithmetic in bitwise/equality context */
    else if (should_paren_for_readability(a.prec, oprec) && !already_parenthesized(a.expr)) {
        a.expr = wrap_parens(a.expr);
    }

    /* Wrap right if needed (precedence-based) */
    if (needs_parens_right(b.prec, oprec, ra) && !already_parenthesized(b.expr)) {
        b.expr = wrap_parens(b.expr);
    }
    /* Readability: add parens for arithmetic in bitwise/equality context */
    else if (should_paren_for_readability(b.prec, oprec) && !already_parenthesized(b.expr)) {
        b.expr = wrap_parens(b.expr);
    }

    char *result = make_binop(a.expr, op, b.expr);
    free(a.expr);
    free(b.expr);
    return result;
}

/* Build a unary op with proper parenthesization.
 * Takes ownership of a.expr. */
static char *build_unop(const char *op, slot_t a) {
    /* For prefix unary, child needs parens if its prec < PREC_UNARY */
    if (a.prec < PREC_UNARY && !already_parenthesized(a.expr)) {
        a.expr = wrap_parens(a.expr);
    }
    char *result = make_unop(op, a.expr);
    free(a.expr);
    return result;
}

static char *make_call(const char *callee, const char *args) {
    sbuf_t sb; sb_init(&sb);
    sb_puts(&sb, callee);
    sb_putc(&sb, '(');
    sb_puts(&sb, args);
    sb_putc(&sb, ')');
    return sb.buf;
}

static char *make_index_access(const char *obj, const char *idx) {
    sbuf_t sb; sb_init(&sb);
    sb_puts(&sb, obj);
    sb_putc(&sb, '[');
    sb_puts(&sb, idx);
    sb_putc(&sb, ']');
    return sb.buf;
}

static char *quote_string(const char *s) {
    sbuf_t sb; sb_init(&sb);
    sb_putc(&sb, '"');
    for (const char *p = s; *p; p++) {
        if (*p == '"' || *p == '\\') { sb_putc(&sb, '\\'); sb_putc(&sb, *p); }
        else if (*p == '\n') sb_puts(&sb, "\\n");
        else if (*p == '\r') sb_puts(&sb, "\\r");
        else if (*p == '\t') sb_puts(&sb, "\\t");
        else if (*p == '\b') sb_puts(&sb, "\\b");
        else if (*p == '\f') sb_puts(&sb, "\\f");
        else if ((unsigned char)*p < 0x20) sb_printf(&sb, "\\x%02x", (unsigned char)*p);
        else sb_putc(&sb, *p);
    }
    sb_putc(&sb, '"');
    return sb.buf;
}

static char *value_to_js(qjs_reader_t *r, qjs_value_t *v) {
    return qjs_format_value(r, v, 6);
}

/* =========================================================
 * Local variable name lookup
 * ========================================================= */
static char *loc_name(qjs_reader_t *r, qjs_function_t *fn, uint32_t loc) {
    uint32_t vd_idx = fn->arg_count + loc;
    if (vd_idx < (uint32_t)fn->vardefs_count) {
        return xstrdup(qjs_atom_str(r, fn->vardefs[vd_idx].var_name_atom));
    }
    char buf[64]; snprintf(buf, sizeof(buf), "loc%d", loc);
    return xstrdup(buf);
}

static char *arg_name(qjs_reader_t *r, qjs_function_t *fn, uint32_t arg) {
    if (arg < (uint32_t)fn->vardefs_count) {
        return xstrdup(qjs_atom_str(r, fn->vardefs[arg].var_name_atom));
    }
    char buf[64]; snprintf(buf, sizeof(buf), "arg%d", arg);
    return xstrdup(buf);
}

/* =========================================================
 * Statement builder context
 * ========================================================= */
typedef struct {
    qjs_reader_t *r;
    qjs_function_t *fn;
    ir_function_t *ir;
    int cpool_base;
    vstack_t vs;
    /* loop tracking for break/continue */
    int loop_depth;
    uint32_t loop_end_targets[32];   /* break targets */
    uint32_t loop_start_targets[32]; /* continue targets */
} decomp_ctx_t;

/* Forward declarations */
static ir_stmt_t *decompile_range(decomp_ctx_t *ctx, int start_idx, int end_idx);
static ir_stmt_t *decompile_range_top(decomp_ctx_t *ctx, int start_idx, int end_idx, int is_toplevel);
static ir_stmt_t *decompile_block(decomp_ctx_t *ctx, int start_idx, int end_idx);
static char *strip_outer_parens(char *expr);
static int is_internal_var(const char *name);
static int is_reserved_word(const char *name);
static void convert_while_to_for(ir_stmt_t *s);

/* =========================================================
 * Core expression decoder
 *
 * Decodes a single instruction into stack effects.
 * Returns:
 *   0 = instruction handled (stack updated)
 *   1 = instruction is a control-flow instruction (caller should handle)
 *  -1 = unknown instruction (push placeholder)
 * ========================================================= */
typedef enum {
    DECODE_OK,
    DECODE_CONTROL_FLOW,
    DECODE_UNKNOWN,
    DECODE_SKIP,    /* instruction produces no visible effect (e.g., nop) */
} decode_result_t;

static decode_result_t decode_insn(decomp_ctx_t *ctx, ir_insn_t *insn) {
    vstack_t *vs = &ctx->vs;
    qjs_reader_t *r = ctx->r;
    qjs_function_t *fn = ctx->fn;
    int cpool_base = ctx->cpool_base;
    int op = insn->op; // Use int for remapped temp opcodes
    const qjs_op_info_t *info = insn->info;
    const char *atom_name = atom_name_of(r, insn);

    /* Skip temporary (phase 1) opcodes mapped to 0x1000+ */
    if (op >= 0x1000) {
        return DECODE_SKIP;
    }

    switch (op) {
        /* ===== Constants ===== */
        case qjs_op_push_i32:
            { char b[32]; snprintf(b, sizeof(b), "%d", insn->i32_val); vs_push(vs, b, 1, 0); break; }
        case qjs_op_push_const:
        case qjs_op_push_const8: {
            int idx = (op == qjs_op_push_const) ? (int)insn->u32_val : (int)insn->u32_val;
            if (op == qjs_op_push_const8) idx = insn->u32_val;
            if (idx >= 0 && idx < fn->cpool_count) {
                char *s = value_to_js(r, fn->cpool[idx]);
                vs_push_take(vs, s, 1, 0);
            } else {
                /* Out of bounds cpool index - likely Frida opcode misalignment.
                 * Push undefined instead of garbage c[N] reference. */
                vs_push(vs, "undefined", 1, 0);
            }
            break;
        }
        case qjs_op_fclosure:
        case qjs_op_fclosure8: {
            int idx = (op == qjs_op_fclosure) ? (int)insn->u32_val : (int)insn->u32_val;
            char buf[128];
            if (idx >= 0 && idx < fn->cpool_count &&
                fn->cpool[idx] && fn->cpool[idx]->kind == QJS_VAL_FUNCTION) {
                qjs_function_t *nfn = fn->cpool[idx]->u.func.fn;
                snprintf(buf, sizeof(buf), "_closure_%d", nfn->func_idx);
            } else {
                /* Out of bounds - push undefined */
                vs_push(vs, "undefined", 1, 0);
                break;
            }
            vs_push(vs, buf, 1, 0);
            break;
        }
        case qjs_op_push_atom_value:
            vs_push_take(vs, quote_string(atom_name), 1, 0);
            break;
        case qjs_op_undefined: vs_push(vs, "undefined", 1, 0); break;
        case qjs_op_null:      vs_push(vs, "null", 1, 0); break;
        case qjs_op_push_this: vs_push(vs, "this", 1, 0); break;
        case qjs_op_push_false: vs_push(vs, "false", 1, 0); break;
        case qjs_op_push_true: vs_push(vs, "true", 1, 0); break;
        /* qjs_op_object handled specially below for object literal construction */
        case qjs_op_push_minus1: vs_push(vs, "-1", 1, 0); break;
        case qjs_op_push_0: vs_push(vs, "0", 1, 0); break;
        case qjs_op_push_1: vs_push(vs, "1", 1, 0); break;
        case qjs_op_push_2: vs_push(vs, "2", 1, 0); break;
        case qjs_op_push_3: vs_push(vs, "3", 1, 0); break;
        case qjs_op_push_4: vs_push(vs, "4", 1, 0); break;
        case qjs_op_push_5: vs_push(vs, "5", 1, 0); break;
        case qjs_op_push_6: vs_push(vs, "6", 1, 0); break;
        case qjs_op_push_7: vs_push(vs, "7", 1, 0); break;
        case qjs_op_push_i8: { char b[32]; snprintf(b, sizeof(b), "%d", insn->i32_val); vs_push(vs, b, 1, 0); break; }
        case qjs_op_push_i16: { char b[32]; snprintf(b, sizeof(b), "%d", insn->i32_val); vs_push(vs, b, 1, 0); break; }
        case qjs_op_push_empty_string: vs_push(vs, "\"\"", 1, 0); break;

        /* ===== Stack manipulation ===== */
        case qjs_op_dup: {
            slot_t a = vs_peek(vs, 0);
            vs_push_prec(vs, a.expr, a.prec, a.is_lvalue);
            break;
        }
        case qjs_op_swap: {
            if (vs->top >= 2) {
                slot_t tmp = vs->slots[vs->top - 1];
                vs->slots[vs->top - 1] = vs->slots[vs->top - 2];
                vs->slots[vs->top - 2] = tmp;
            }
            break;
        }
        case qjs_op_nip: {
            if (vs->top >= 2) {
                free(vs->slots[vs->top - 2].expr);
                vs->slots[vs->top - 2] = vs->slots[vs->top - 1];
                vs->top--;
            }
            break;
        }
        case qjs_op_nip1: {
            /* a b c -> b c (remove third from top) */
            if (vs->top >= 3) {
                free(vs->slots[vs->top - 3].expr);
                vs->slots[vs->top - 3] = vs->slots[vs->top - 2];
                vs->slots[vs->top - 2] = vs->slots[vs->top - 1];
                vs->top--;
            }
            break;
        }
        case qjs_op_dup1: {
            if (vs->top >= 2) {
                slot_t a = vs->slots[vs->top - 2];
                /* insert a copy below top */
                slot_t top = vs->slots[vs->top - 1];
                if (vs->top < MAX_STACK) {
                    vs->slots[vs->top] = top;
                    vs->slots[vs->top].expr = xstrdup(top.expr);
                    vs->slots[vs->top - 1].expr = xstrdup(a.expr);
                    vs->slots[vs->top - 1].is_simple = a.is_simple;
                    vs->slots[vs->top - 1].is_lvalue = a.is_lvalue;
                    vs->top++;
                }
            }
            break;
        }
        case qjs_op_dup2: {
            if (vs->top >= 2) {
                slot_t a = vs->slots[vs->top - 2];
                slot_t b = vs->slots[vs->top - 1];
                vs_push_prec(vs, a.expr, a.prec, a.is_lvalue);
                vs_push_prec(vs, b.expr, b.prec, b.is_lvalue);
            }
            break;
        }
        case qjs_op_dup3: {
            if (vs->top >= 3) {
                for (int i = 3; i >= 1; i--) {
                    slot_t a = vs->slots[vs->top - i];
                    vs_push_prec(vs, a.expr, a.prec, a.is_lvalue);
                }
            }
            break;
        }
        case qjs_op_insert2: { /* obj a -> a obj a */
            if (vs->top >= 2) {
                slot_t a = vs->slots[vs->top - 1];
                slot_t obj = vs->slots[vs->top - 2];
                vs->slots[vs->top - 2] = a;
                vs->slots[vs->top - 2].expr = xstrdup(a.expr);
                vs->slots[vs->top - 1] = obj;
                vs->slots[vs->top - 1].expr = xstrdup(obj.expr);
                vs_push_prec(vs, a.expr, a.prec, a.is_lvalue);
            }
            break;
        }
        case qjs_op_perm3: { /* obj a b -> a obj b */
            /* QuickJS: perm3 rotates the top 3 elements.
             * Stack before: ... obj a b
             * Stack after:  ... a obj b
             * This is: swap positions of obj and a, keep b */
            if (vs->top >= 3) {
                slot_t tmp = vs->slots[vs->top - 3];
                vs->slots[vs->top - 3] = vs->slots[vs->top - 2];
                vs->slots[vs->top - 2] = tmp;
            }
            break;
        }
        case qjs_op_perm4: { /* obj prop a b -> a obj prop b */
            /* top-4=obj, top-3=prop, top-2=a, top-1=b
             * After: top-4=a, top-3=obj, top-2=prop, top-1=b */
            if (vs->top >= 4) {
                slot_t obj = vs->slots[vs->top - 4];
                vs->slots[vs->top - 4] = vs->slots[vs->top - 2]; /* a */
                vs->slots[vs->top - 2] = vs->slots[vs->top - 3]; /* prop */
                vs->slots[vs->top - 3] = obj;                    /* obj */
            }
            break;
        }
        case qjs_op_perm5: { /* this obj prop a b -> a this obj prop b */
            /* top-5=this, top-4=obj, top-3=prop, top-2=a, top-1=b
             * After: top-5=a, top-4=this, top-3=obj, top-2=prop, top-1=b */
            if (vs->top >= 5) {
                slot_t this_s = vs->slots[vs->top - 5];
                vs->slots[vs->top - 5] = vs->slots[vs->top - 2]; /* a */
                vs->slots[vs->top - 2] = vs->slots[vs->top - 3]; /* prop */
                vs->slots[vs->top - 3] = vs->slots[vs->top - 4]; /* obj */
                vs->slots[vs->top - 4] = this_s;                 /* this */
            }
            break;
        }
        case qjs_op_insert3: { /* obj prop a -> a obj prop a (dup_x2) */
            if (vs->top >= 3) {
                slot_t a = vs->slots[vs->top - 1];
                /* Shift up: positions top-3, top-2 become copies of top-2, top-1 */
                vs->slots[vs->top] = vs->slots[vs->top - 1]; /* save a */
                vs->slots[vs->top - 1] = vs->slots[vs->top - 2]; /* prop -> top-1 */
                vs->slots[vs->top - 2] = vs->slots[vs->top - 3]; /* obj -> top-2 */
                vs->slots[vs->top - 3].expr = xstrdup(a.expr); /* a -> top-3 */
                vs->top++;
            }
            break;
        }
        case qjs_op_insert4: { /* this obj prop a -> a this obj prop a */
            if (vs->top >= 4) {
                slot_t a = vs->slots[vs->top - 1];
                vs->slots[vs->top] = vs->slots[vs->top - 1];
                vs->slots[vs->top - 1] = vs->slots[vs->top - 2];
                vs->slots[vs->top - 2] = vs->slots[vs->top - 3];
                vs->slots[vs->top - 3] = vs->slots[vs->top - 4];
                vs->slots[vs->top - 4].expr = xstrdup(a.expr);
                vs->top++;
            }
            break;
        }
        case qjs_op_rot3l: { /* x a b -> a b x */
            if (vs->top >= 3) {
                slot_t x = vs->slots[vs->top - 3];
                vs->slots[vs->top - 3] = vs->slots[vs->top - 2];
                vs->slots[vs->top - 2] = vs->slots[vs->top - 1];
                vs->slots[vs->top - 1] = x;
            }
            break;
        }
        case qjs_op_rot3r: { /* a b x -> x a b */
            if (vs->top >= 3) {
                slot_t x = vs->slots[vs->top - 1];
                vs->slots[vs->top - 1] = vs->slots[vs->top - 2];
                vs->slots[vs->top - 2] = vs->slots[vs->top - 3];
                vs->slots[vs->top - 3] = x;
            }
            break;
        }

        /* ===== Locals / args ===== */
        case qjs_op_get_loc:
        case qjs_op_get_loc8:
        case qjs_op_get_loc0:
        case qjs_op_get_loc1:
        case qjs_op_get_loc2:
        case qjs_op_get_loc3:
        case qjs_op_get_loc_check:
        case qjs_op_get_loc_checkthis: {
            uint32_t loc = insn->u32_val;
            vs_push_take(vs, loc_name(r, fn, loc), 1, 1);
            break;
        }
        case qjs_op_get_arg:
        case qjs_op_get_arg0:
        case qjs_op_get_arg1:
        case qjs_op_get_arg2:
        case qjs_op_get_arg3: {
            uint32_t arg = insn->u32_val;
            vs_push_take(vs, arg_name(r, fn, arg), 1, 1);
            break;
        }

        /* ===== Closure vars ===== */
        case qjs_op_get_var_ref:
        case qjs_op_get_var_ref0:
        case qjs_op_get_var_ref1:
        case qjs_op_get_var_ref2:
        case qjs_op_get_var_ref3:
        case qjs_op_get_var_ref_check: {
            uint32_t vref = insn->u32_val;
            if (vref < (uint32_t)fn->closure_var_count) {
                vs_push(vs, qjs_atom_str(r, fn->closure_vars[vref].var_name_atom), 1, 1);
            } else {
                char b[64]; snprintf(b, sizeof(b), "var_ref%d", vref); vs_push(vs, b, 1, 1);
            }
            break;
        }

        /* ===== Variables ===== */
        case qjs_op_get_var:
        case qjs_op_get_var_undef:
        case qjs_op_check_var:
            vs_push(vs, atom_name, 1, 1);
            break;

        /* ===== Field access ===== */
        case qjs_op_get_field:
        case qjs_op_get_field2: {
            slot_t obj = vs_pop(vs);
            /* Wrap obj in parens if it's a complex expression (e.g., (a+b).c) */
            if (obj.prec < PREC_CALL && !already_parenthesized(obj.expr))
                obj.expr = wrap_parens(obj.expr);
            char *e = field_expr(obj.expr, atom_name);
            if (op == qjs_op_get_field2) {
                vs_push_prec(vs, obj.expr, PREC_CALL, obj.is_lvalue);
                vs_push_take_prec(vs, e, PREC_CALL, 1);
            } else {
                vs_push_take_prec(vs, e, PREC_CALL, 1);
            }
            free(obj.expr);
            break;
        }
        case qjs_op_get_array_el:
        case qjs_op_get_array_el2: {
            slot_t idx = vs_pop(vs);
            slot_t obj = vs_pop(vs);
            if (obj.prec < PREC_CALL && !already_parenthesized(obj.expr))
                obj.expr = wrap_parens(obj.expr);
            char *e = make_index_access(obj.expr, idx.expr);
            if (op == qjs_op_get_array_el2) {
                vs_push_prec(vs, obj.expr, PREC_CALL, obj.is_lvalue);
                vs_push_take_prec(vs, e, PREC_CALL, 1);
            } else {
                vs_push_take_prec(vs, e, PREC_CALL, 1);
            }
            free(idx.expr); free(obj.expr);
            break;
        }
        case qjs_op_get_length: {
            slot_t obj = vs_pop(vs);
            if (obj.prec < PREC_CALL && !already_parenthesized(obj.expr))
                obj.expr = wrap_parens(obj.expr);
            char *e = field_expr(obj.expr, "length");
            vs_push_take_prec(vs, e, PREC_CALL, 1);
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
            slot_t b = vs_pop(vs);
            slot_t a = vs_pop(vs);
            const char *sym = "+";
            switch (op) {
                case qjs_op_add: sym = "+"; break;
                case qjs_op_sub: sym = "-"; break;
                case qjs_op_mul: sym = "*"; break;
                case qjs_op_div: sym = "/"; break;
                case qjs_op_mod: sym = "%"; break;
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
            int oprec = op_prec(sym);
            char *e = build_binop(a, sym, b);
            vs_push_take_prec(vs, e, oprec, 0);
            break;
        }

        /* ===== Unary ops ===== */
        case qjs_op_neg: { slot_t a = vs_pop(vs); char *e = build_unop("-", a); vs_push_take_prec(vs, e, PREC_UNARY, 0); break; }
        case qjs_op_plus: { slot_t a = vs_pop(vs); char *e = build_unop("+", a); vs_push_take_prec(vs, e, PREC_UNARY, 0); break; }
        case qjs_op_not: { slot_t a = vs_pop(vs); char *e = build_unop("~", a); vs_push_take_prec(vs, e, PREC_UNARY, 0); break; }
        case qjs_op_lnot: { slot_t a = vs_pop(vs); char *e = build_unop("!", a); vs_push_take_prec(vs, e, PREC_UNARY, 0); break; }
        case qjs_op_typeof: { slot_t a = vs_pop(vs); char *e = build_unop("typeof ", a); vs_push_take_prec(vs, e, PREC_UNARY, 0); break; }
        case qjs_op_inc: case qjs_op_dec: {
            slot_t a = vs_pop(vs);
            const char *op_s = (op == qjs_op_inc) ? "++" : "--";
            sbuf_t sb; sb_init(&sb);
            sb_puts(&sb, a.expr);
            sb_puts(&sb, op_s);
            vs_push_take_prec(vs, sb.buf, PREC_UNARY, 0);
            free(a.expr);
            break;
        }
        case qjs_op_post_inc: case qjs_op_post_dec: {
            slot_t a = vs_pop(vs);
            const char *op_s = (op == qjs_op_post_inc) ? "++" : "--";
            /* post_inc/post_dec: a -> a, a++ (pushes old value AND new value)
             * n_pop=1, n_push=2
             * Stack: a -> a, a++ */
            /* Push old value (the original expression) */
            vs_push_prec(vs, a.expr, a.prec, a.is_lvalue);
            /* Push new value (with ++/-- suffix) */
            sbuf_t sb; sb_init(&sb);
            sb_puts(&sb, a.expr);
            sb_puts(&sb, op_s);
            vs_push_take_prec(vs, sb.buf, PREC_UNARY, 0);
            free(a.expr);
            break;
        }

        /* ===== Calls ===== */
        case qjs_op_call:
        case qjs_op_call0:
        case qjs_op_call1:
        case qjs_op_call2:
        case qjs_op_call3: {
            int nargs = (op == qjs_op_call) ? (int)insn->u32_val : (op - qjs_op_call0);
            if (vs->top >= nargs + 1) {
                slot_t *argv = xcalloc(nargs > 0 ? nargs : 1, sizeof(slot_t));
                for (int i = nargs - 1; i >= 0; i--) { argv[i] = vs_pop(vs); close_obj_if_open(&argv[i]); }
                sbuf_t args; sb_init(&args);
                for (int i = 0; i < nargs; i++) {
                    if (i > 0) sb_puts(&args, ", ");
                    sb_puts(&args, argv[i].expr);
                    free(argv[i].expr);
                }
                slot_t callee = vs_pop(vs);
                /* Wrap callee in parens if it's a complex expression */
                if (callee.prec < PREC_CALL && !already_parenthesized(callee.expr))
                    callee.expr = wrap_parens(callee.expr);
                char *e = make_call(callee.expr, args.buf);
                vs_push_take_prec(vs, e, PREC_CALL, 0);
                free(callee.expr);
                sb_free(&args);
                free(argv);
            }
            break;
        }
        case qjs_op_call_method: {
            int nargs = insn->u32_val;
            if (vs->top >= nargs + 2) {
                slot_t *argv = xcalloc(nargs > 0 ? nargs : 1, sizeof(slot_t));
                for (int i = nargs - 1; i >= 0; i--) { argv[i] = vs_pop(vs); close_obj_if_open(&argv[i]); }
                sbuf_t args; sb_init(&args);
                for (int i = 0; i < nargs; i++) {
                    if (i > 0) sb_puts(&args, ", ");
                    sb_puts(&args, argv[i].expr);
                    free(argv[i].expr);
                }
                slot_t method = vs_pop(vs);
                slot_t obj = vs_pop(vs);
                char *e = make_call(method.expr, args.buf);
                vs_push_take_prec(vs, e, PREC_CALL, 0);
                free(method.expr); free(obj.expr);
                sb_free(&args);
                free(argv);
            }
            break;
        }
        case qjs_op_call_constructor: {
            int nargs = insn->u32_val;
            if (vs->top >= nargs + 2) {
                slot_t *argv = xcalloc(nargs > 0 ? nargs : 1, sizeof(slot_t));
                for (int i = nargs - 1; i >= 0; i--) { argv[i] = vs_pop(vs); close_obj_if_open(&argv[i]); }
                sbuf_t args; sb_init(&args);
                for (int i = 0; i < nargs; i++) {
                    if (i > 0) sb_puts(&args, ", ");
                    sb_puts(&args, argv[i].expr);
                    free(argv[i].expr);
                }
                slot_t new_target = vs_pop(vs);
                free(new_target.expr);
                slot_t ctor = vs_pop(vs);
                sbuf_t sb; sb_init(&sb);
                /* If constructor is "super", use super() not new super() */
                if (strcmp(ctor.expr, "super") == 0) {
                    sb_puts(&sb, "super(");
                } else {
                    sb_puts(&sb, "new ");
                    sb_puts(&sb, ctor.expr);
                    sb_putc(&sb, '(');
                }
                sb_puts(&sb, args.buf);
                sb_putc(&sb, ')');
                vs_push_take_prec(vs, sb.buf, PREC_CALL, 0);
                free(ctor.expr);
                sb_free(&args);
                free(argv);
            }
            break;
        }
        case qjs_op_array_from: {
            int nargs = insn->u32_val;
            if (vs->top >= nargs) {
                slot_t *argv = xcalloc(nargs > 0 ? nargs : 1, sizeof(slot_t));
                for (int i = nargs - 1; i >= 0; i--) { argv[i] = vs_pop(vs); close_obj_if_open(&argv[i]); }
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
                vs_push_take_prec(vs, sb.buf, PREC_CALL, 0);
                sb_free(&args);
                free(argv);
            }
            break;
        }

        /* ===== Misc pushes ===== */
        case qjs_op_special_object: {
            const char *name = "<special>";
            switch (insn->u32_val) {
                case 0: name = "this"; break;
                case 1: name = "new.target"; break;
                case 2: name = "home_object"; break;
                case 3: name = "<active_func>"; break;
            }
            vs_push(vs, name, 1, 0);
            break;
        }
        case qjs_op_await: { slot_t a = vs_pop(vs); char *e = build_unop("await ", a); vs_push_take_prec(vs, e, PREC_UNARY, 0); break; }
        case qjs_op_yield: { slot_t a = vs_pop(vs); char *e = build_unop("yield ", a); vs_push_take_prec(vs, e, PREC_UNARY, 0); break; }
        case qjs_op_yield_star: { slot_t a = vs_pop(vs); char *e = build_unop("yield* ", a); vs_push_take_prec(vs, e, PREC_UNARY, 0); break; }
        case qjs_op_get_super: {
            /* get_super pushes the parent constructor.
             * In the context of `super(args)`, we push "super".
             * The value on stack before is the current function, which we discard. */
            slot_t a = vs_pop(vs);
            free(a.expr);
            vs_push_prec(vs, "super", PREC_ATOM, 0);
            break;
        }
        case qjs_op_regexp: {
            slot_t flags = vs_pop(vs);
            slot_t pat = vs_pop(vs);
            sbuf_t sb; sb_init(&sb);
            sb_putc(&sb, '/');
            sb_puts(&sb, pat.expr);
            sb_putc(&sb, '/');
            sb_puts(&sb, flags.expr);
            vs_push_take(vs, sb.buf, 1, 0);
            free(pat.expr); free(flags.expr);
            break;
        }

        /* ===== Operations that should NOT produce statements ===== */
        case qjs_op_drop:
            /* If we're about to drop a value, it means the previous expression
             * was a statement. But we handle this at the statement level,
             * so just pop it here. */
            {
                slot_t s = vs_pop(vs);
                free(s.expr);
            }
            break;
        case qjs_op_nop:
        case qjs_op_set_loc_uninitialized:
        case qjs_op_check_define_var:
        case qjs_op_define_var:
        case qjs_op_check_ctor:
        case qjs_op_check_brand:
        case qjs_op_add_brand:
        case qjs_op_set_home_object:
        case qjs_op_close_loc:
        case qjs_op_define_class:
        case qjs_op_define_class_computed:
            /* These are metadata/structural ops - skip silently */
            return DECODE_SKIP;

        case qjs_op_define_method:
            /* define_method: obj func -> obj (with obj[name] = func)
             * n_pop=2, n_push=1
             * Similar to define_field but for methods.
             * Used in object literals: { onEnter: function() {} } */
            {
                slot_t val = vs_pop(vs);
                slot_t obj = vs_pop(vs);
                const char *mname = atom_name_of(r, insn);
                /* If obj is "{}" (empty object literal), start building it */
                if (strcmp(obj.expr, "{}") == 0) {
                    sbuf_t sb; sb_init(&sb);
                    sb_putc(&sb, '{');
                    sb_printf(&sb, " %s: %s", mname, val.expr);
                    sb_putc(&sb, ' ');
                    free(obj.expr);
                    free(val.expr);
                    vs_push_take_prec(vs, sb.buf, PREC_ATOM, 0);
                } else if (obj.expr[0] == '{' && obj.expr[strlen(obj.expr)-1] != '}') {
                    /* Continuing object construction - append field */
                    sbuf_t sb; sb_init(&sb);
                    sb_puts(&sb, obj.expr);
                    sb_puts(&sb, ", ");
                    sb_printf(&sb, "%s: %s", mname, val.expr);
                    sb_putc(&sb, ' ');
                    free(obj.expr);
                    free(val.expr);
                    vs_push_take_prec(vs, sb.buf, PREC_ATOM, 0);
                } else {
                    /* Not an object literal - emit as assignment */
                    char *fld = field_expr(obj.expr, mname);
                    sbuf_t sb; sb_init(&sb);
                    sb_putc(&sb, '(');
                    sb_puts(&sb, fld);
                    sb_puts(&sb, " = ");
                    sb_puts(&sb, val.expr);
                    sb_putc(&sb, ')');
                    free(fld);
                    free(obj.expr);
                    free(val.expr);
                    vs_push_take_prec(vs, sb.buf, PREC_COMMA, 0);
                }
            }
            return DECODE_OK;

        case qjs_op_define_method_computed:
            /* Similar but with computed key - rare, skip for now */
            {
                slot_t val = vs_pop(vs);
                slot_t key = vs_pop(vs);
                slot_t obj = vs_pop(vs);
                /* Just push obj back, discard key and val */
                vs_push_prec(vs, obj.expr, obj.prec, obj.is_lvalue);
                free(obj.expr);
                free(key.expr);
                free(val.expr);
            }
            return DECODE_SKIP;
        case qjs_op_set_proto:
        case qjs_op_copy_data_properties:
        case qjs_op_nip_catch:
        case qjs_op_ret:  /* gosub return (not function return) */
        case qjs_op_for_await_of_start:
        case qjs_op_iterator_check_object:
        case qjs_op_iterator_get_value_done:
        case qjs_op_iterator_close:
        case qjs_op_iterator_next:
        case qjs_op_iterator_call:
        case qjs_op_initial_yield:
        case qjs_op_to_object:
        case qjs_op_to_propkey:
        case qjs_op_to_propkey2:
            /* to_propkey2: n_pop=2, n_push=2 - no-op on stack */
            return DECODE_SKIP;
        case qjs_op_check_ctor_return:
        /* Stack manipulation ops that are rare or internal */
        case qjs_op_swap2:
        case qjs_op_rot4l:
        case qjs_op_rot5l:
        case qjs_op_define_array_el:
        case qjs_op_append:
        case qjs_op_get_super_value:
        case qjs_op_put_super_value:
        case qjs_op_get_ref_value:
        case qjs_op_put_ref_value:
        case qjs_op_with_get_var:
        case qjs_op_with_put_var:
        case qjs_op_with_delete_var:
        case qjs_op_with_make_ref:
        case qjs_op_with_get_ref:
        case qjs_op_with_get_ref_undef:
        case qjs_op_make_loc_ref:
        case qjs_op_make_arg_ref:
        case qjs_op_make_var_ref_ref:
        case qjs_op_make_var_ref:
        case qjs_op_private_symbol:
        case qjs_op_define_private_field:
        case qjs_op_get_private_field:
        case qjs_op_put_private_field:
        case qjs_op_private_in:
        case qjs_op_mul_pow10:
        case qjs_op_math_mod:
        case qjs_op_is_undefined_or_null:
        case qjs_op_apply:
        case qjs_op_apply_eval:
        case qjs_op_eval:
            /* These are metadata/structural/rare ops - skip silently */
            return DECODE_SKIP;

        /* ===== Object construction ===== */
        case qjs_op_object:
            /* Push empty object literal marker (will be built by define_field) */
            vs_push_prec(vs, "{}", PREC_ATOM, 0);
            return DECODE_OK;

        case qjs_op_set_name:
            /* set_name: obj -> obj (with name set as toString)
             * This is a no-op for our purposes - the object already has its value.
             * n_pop=1, n_push=1, so we leave the stack unchanged. */
            return DECODE_SKIP;

        case qjs_op_define_field:
            /* define_field: obj value -> obj (with obj[field] = value)
             * n_pop=2, n_push=1
             * This is used for object literals: { field: value, ... }
             * Pattern: object; value; define_field x; value; define_field y;
             * We track object construction in a special way. */
            {
                slot_t val = vs_pop(vs);
                slot_t obj = vs_pop(vs);
                /* If obj is "{}" (empty object literal), start building it */
                if (strcmp(obj.expr, "{}") == 0) {
                    sbuf_t sb; sb_init(&sb);
                    sb_putc(&sb, '{');
                    sb_printf(&sb, " %s: %s", atom_name_of(r, insn), val.expr);
                    sb_putc(&sb, ' ');
                    /* Don't close - more fields may follow */
                    free(obj.expr);
                    free(val.expr);
                    /* Push the partially-built object (marked as open) */
                    vs_push_take_prec(vs, sb.buf, PREC_ATOM, 0);
                } else if (obj.expr[0] == '{' && obj.expr[strlen(obj.expr)-1] != '}') {
                    /* Continuing object construction - append field */
                    sbuf_t sb; sb_init(&sb);
                    sb_puts(&sb, obj.expr);
                    sb_puts(&sb, ", ");
                    sb_printf(&sb, "%s: %s", atom_name_of(r, insn), val.expr);
                    sb_putc(&sb, ' ');
                    free(obj.expr);
                    free(val.expr);
                    vs_push_take_prec(vs, sb.buf, PREC_ATOM, 0);
                } else {
                    /* Not an object literal - emit as assignment */
                    /* obj.field = value; (but this is in expression context) */
                    /* For now, just push the object back */
                    char *fld = field_expr(obj.expr, atom_name_of(r, insn));
                    /* We can't emit a statement here, so wrap as IIFE-like */
                    sbuf_t sb; sb_init(&sb);
                    sb_putc(&sb, '(');
                    sb_puts(&sb, fld);
                    sb_puts(&sb, " = ");
                    sb_puts(&sb, val.expr);
                    sb_putc(&sb, ')');
                    free(fld);
                    free(obj.expr);
                    free(val.expr);
                    vs_push_take_prec(vs, sb.buf, PREC_COMMA, 0);
                }
            }
            return DECODE_OK;

        /* ===== For-in / For-of iteration ===== */
        case qjs_op_for_in_start:
            /* for_in_start: obj -> iterator (pops obj, pushes iterator) */
            /* Pop the object, push a placeholder for the iterator */
            { slot_t a = vs_pop(vs); free(a.expr); }
            vs_push_prec(vs, "_iter", PREC_ATOM, 0);
            return DECODE_OK;

        case qjs_op_for_of_start:
            /* for_of_start: obj -> iterator catch_offset (pops obj, pushes 3) */
            { slot_t a = vs_pop(vs); free(a.expr); }
            vs_push_prec(vs, "_iter", PREC_ATOM, 0);
            vs_push_prec(vs, "_iter_catch", PREC_ATOM, 0);
            vs_push_prec(vs, "_iter_next", PREC_ATOM, 0);
            return DECODE_OK;

        case qjs_op_for_in_next:
            /* for_in_next: iterator -> iterator next_val done (pops 1, pushes 3) */
            { slot_t a = vs_pop(vs); free(a.expr); }
            vs_push_prec(vs, "_iter", PREC_ATOM, 0);
            vs_push_prec(vs, "_iter_val", PREC_ATOM, 0);
            vs_push_prec(vs, "_iter_done", PREC_ATOM, 0);
            return DECODE_OK;

        case qjs_op_for_of_next:
            /* for_of_next: iter_next iter catch -> iter_next iter val done catch (pops 3, pushes 5) */
            { slot_t a = vs_pop(vs); free(a.expr); }
            { slot_t b = vs_pop(vs); free(b.expr); }
            { slot_t c = vs_pop(vs); free(c.expr); }
            vs_push_prec(vs, "_iter_next", PREC_ATOM, 0);
            vs_push_prec(vs, "_iter", PREC_ATOM, 0);
            vs_push_prec(vs, "_iter_val", PREC_ATOM, 0);
            vs_push_prec(vs, "_iter_done", PREC_ATOM, 0);
            vs_push_prec(vs, "_iter_catch", PREC_ATOM, 0);
            return DECODE_OK;

        /* ===== Catch and gosub - skip for now (try/catch not fully reconstructed) ===== */
        case qjs_op_catch:
            /* catch pushes a context value on stack - just push a placeholder */
            vs_push_prec(vs, "_catch", PREC_ATOM, 0);
            return DECODE_OK;
        case qjs_op_gosub:
            /* gosub jumps to finally block - skip */
            return DECODE_SKIP;

        /* ===== Control flow (caller handles) ===== */
        case qjs_op_if_false:
        case qjs_op_if_false8:
        case qjs_op_if_true:
        case qjs_op_if_true8:
        case qjs_op_goto:
        case qjs_op_goto8:
        case qjs_op_goto16:
        case qjs_op_return:
        case qjs_op_return_undef:
        case qjs_op_return_async:
        case qjs_op_throw:
        case qjs_op_throw_error:
            return DECODE_CONTROL_FLOW;

        /* ===== Tail calls - treat like normal calls, they'll be followed by return ===== */
        case qjs_op_tail_call:
        case qjs_op_tail_call_method:
            /* Convert to the non-tail version for decompilation purposes */
            if (op == qjs_op_tail_call) {
                /* Same as call: nargs = u16 operand */
                int nargs = insn->u32_val;
                if (vs->top >= nargs + 1) {
                    slot_t *argv = xcalloc(nargs > 0 ? nargs : 1, sizeof(slot_t));
                    for (int i = nargs - 1; i >= 0; i--) { argv[i] = vs_pop(vs); close_obj_if_open(&argv[i]); }
                    sbuf_t args; sb_init(&args);
                    for (int i = 0; i < nargs; i++) {
                        if (i > 0) sb_puts(&args, ", ");
                        sb_puts(&args, argv[i].expr);
                        free(argv[i].expr);
                    }
                    slot_t callee = vs_pop(vs);
                    if (callee.prec < PREC_CALL && !already_parenthesized(callee.expr))
                        callee.expr = wrap_parens(callee.expr);
                    char *e = make_call(callee.expr, args.buf);
                    vs_push_take_prec(vs, e, PREC_CALL, 0);
                    free(callee.expr);
                    sb_free(&args);
                    free(argv);
                }
            } else {
                /* tail_call_method: same as call_method */
                int nargs = insn->u32_val;
                if (vs->top >= nargs + 2) {
                    slot_t *argv = xcalloc(nargs > 0 ? nargs : 1, sizeof(slot_t));
                    for (int i = nargs - 1; i >= 0; i--) { argv[i] = vs_pop(vs); close_obj_if_open(&argv[i]); }
                    sbuf_t args; sb_init(&args);
                    for (int i = 0; i < nargs; i++) {
                        if (i > 0) sb_puts(&args, ", ");
                        sb_puts(&args, argv[i].expr);
                        free(argv[i].expr);
                    }
                    slot_t method = vs_pop(vs);
                    slot_t obj = vs_pop(vs);
                    char *e = make_call(method.expr, args.buf);
                    vs_push_take_prec(vs, e, PREC_CALL, 0);
                    free(method.expr); free(obj.expr);
                    sb_free(&args);
                    free(argv);
                }
            }
            break;

        default:
            return DECODE_UNKNOWN;
    }
    (void)info;
    return DECODE_OK;
}

/* =========================================================
 * Check if a value on stack is a "side-effect expression"
 * (i.e., a call, assignment, etc.) that should be emitted as a statement
 * ========================================================= */
static int is_statement_worthy(const char *expr) {
    if (!expr || !*expr) return 0;
    /* Calls, new, await, yield, assignments, increments are statement-worthy */
    /* Simple literals, variables, field accesses are NOT (they're pure reads) */
    if (strchr(expr, '(')) return 1;
    if (strstr(expr, "++") || strstr(expr, "--")) return 1;
    if (strstr(expr, " = ") && expr[0] == '(') return 0; /* comparison, not assignment */
    return 0;
}

/* =========================================================
 * Main decompiler: decode a range of instructions into a statement block
 * ========================================================= */
/* Wrapper for backward compatibility (non-toplevel) */
static ir_stmt_t *decompile_range(decomp_ctx_t *ctx, int start_idx, int end_idx) {
    return decompile_range_top(ctx, start_idx, end_idx, 0);
}

static ir_stmt_t *decompile_range_top(decomp_ctx_t *ctx, int start_idx, int end_idx, int is_toplevel) {
    stmt_list_t sl; sl_init(&sl);
    qjs_function_t *fn = ctx->fn;
    ir_function_t *ir = ctx->ir;
    qjs_reader_t *r = ctx->r;

    /* Track sl.count at each instruction index - used for do-while detection */
    int *insn_stmt_count = xcalloc(ir->count + 2, sizeof(int));
    for (int j = 0; j < ir->count + 2; j++) insn_stmt_count[j] = -1;

    int i = start_idx;
    while (i < end_idx && i < ir->count) {
        /* Record current statement count for this instruction */
        insn_stmt_count[i] = sl.count;

        ir_insn_t *insn = &ir->insns[i];
        if (!insn->info) {
            /* invalid opcode - skip silently */
            i++;
            continue;
        }

        int op = insn->op; // Use int for remapped temp opcodes

        /* Check for do-while back-edge: if_true with backward jump */
        if (insn->is_conditional && insn->is_backward &&
            (op == qjs_op_if_true || op == qjs_op_if_true8)) {
            slot_t cond = vs_pop(&ctx->vs);
            int32_t body_start_pc = insn->label_target;
            int body_start_idx = ir_find_insn(ir, (uint32_t)body_start_pc);

            /* Find the statement count at body_start_idx */
            int body_stmt_start = 0;
            if (body_start_idx >= 0 && body_start_idx < ir->count + 2 &&
                insn_stmt_count[body_start_idx] >= 0) {
                body_stmt_start = insn_stmt_count[body_start_idx];
            }

            /* Pop statements from body_stmt_start onwards - they form the do-while body */
            if (body_stmt_start < sl.count) {
                /* Re-decompile the body with proper loop context */
                if (ctx->loop_depth < 32) {
                    ctx->loop_start_targets[ctx->loop_depth] = (uint32_t)body_start_pc;
                    ctx->loop_end_targets[ctx->loop_depth] = (uint32_t)(insn->pc + insn->info->size);
                    ctx->loop_depth++;
                }

                /* Free the already-emitted body statements (they'll be re-decompiled) */
                for (int j = body_stmt_start; j < sl.count; j++) {
                    ir_stmt_free(sl.items[j]);
                }
                sl.count = body_stmt_start;

                ir_stmt_t *body = decompile_range(ctx, body_start_idx, i);
                if (ctx->loop_depth > 0) ctx->loop_depth--;

                char *cond_str = xstrdup(cond.expr);
                free(cond.expr);
                strip_outer_parens(cond_str);
                sl_push(&sl, stmt_do_while(cond_str, body));
            } else {
                char *cond_str = xstrdup(cond.expr);
                free(cond.expr);
                ir_stmt_t *body = stmt_block(NULL);
                sl_push(&sl, stmt_do_while(cond_str, body));
            }
            i++;
            continue;
        }

        /* Handle control flow specially */
        if (op == qjs_op_return || op == qjs_op_return_async) {
            slot_t v = vs_pop(&ctx->vs);
            sl_push(&sl, stmt_return(v.expr));
            /* v.expr ownership transferred to statement */
            i++;
            continue;
        }
        if (op == qjs_op_return_undef) {
            /* return_undef has n_pop=0, n_push=0.
             * It does NOT modify the stack - it just returns undefined.
             * However, any values left on the stack at this point are
             * side-effect expressions that should be emitted as statements
             * before the return. */
            while (ctx->vs.top > 0) {
                slot_t v = vs_pop(&ctx->vs);
                if (v.expr && *v.expr) {
                    int has_side_effects = 0;
                    char *paren = strchr(v.expr, '(');
                    if (paren && !already_parenthesized(v.expr)) {
                        if (paren == v.expr) has_side_effects = 1;
                        else {
                            char before = paren[-1];
                            if (isalnum((unsigned char)before) || before == '_' ||
                                before == '$' || before == ')' || before == ']')
                                has_side_effects = 1;
                        }
                    }
                    if (strncmp(v.expr, "new ", 4) == 0) has_side_effects = 1;
                    if (strstr(v.expr, "++") || strstr(v.expr, "--")) has_side_effects = 1;
                    if (strchr(v.expr, '=') && !strstr(v.expr, "==") && !strstr(v.expr, "!="))
                        has_side_effects = 1;
                    if (has_side_effects) {
                        sl_push(&sl, stmt_expr(v.expr));
                    } else {
                        free(v.expr);
                    }
                } else {
                    free(v.expr);
                }
            }
            sl_push(&sl, stmt_return(NULL));
            i++;
            continue;
        }
        if (op == qjs_op_throw) {
            slot_t v = vs_pop(&ctx->vs);
            sl_push(&sl, stmt_throw(v.expr));
            /* v.expr ownership transferred to statement */
            i++;
            continue;
        }
        if (op == qjs_op_throw_error) {
            const char *a = atom_name_of(r, insn);
            /* Skip if atom name is a placeholder (starts with _atom_oob_) */
            if (a && strncmp(a, "_atom_oob_", 10) == 0) {
                i++;
                continue;
            }
            char *msg = quote_string(a);
            char buf[256];
            snprintf(buf, sizeof(buf), "throw new Error(%s);", msg);
            sl_push(&sl, stmt_raw(buf));
            free(msg);
            i++;
            continue;
        }

        /* Handle jumps */
        if (insn->is_jump && !insn->is_conditional) {
            /* Unconditional goto */
            int32_t tgt = insn->label_target;
            if (tgt >= 0 && (uint32_t)tgt < ir->bc_len) {
                /* Check if it's a backward jump (loop) */
                if (insn->is_backward) {
                    /* This is a loop back-edge. The loop body is between tgt and here.
                     * We've already decompiled it as part of the current block.
                     * The while-loop pattern was: cond; if_false -> end; body; goto -> start
                     * We need to handle this in the caller, so emit a continue. */
                    if (ctx->loop_depth > 0 &&
                        ctx->loop_start_targets[ctx->loop_depth - 1] == (uint32_t)tgt) {
                        sl_push(&sl, stmt_continue());
                    } else {
                        char buf[32];
                        snprintf(buf, sizeof(buf), "goto L%04X;", (uint32_t)tgt);
                        sl_push(&sl, stmt_raw(buf));
                    }
                } else {
                    /* Forward goto - could be break or just a goto */
                    if (ctx->loop_depth > 0 &&
                        ctx->loop_end_targets[ctx->loop_depth - 1] == (uint32_t)tgt) {
                        sl_push(&sl, stmt_break());
                    } else {
                        /* Check if this goto skips to after an if-block (else branch) */
                        /* For now, emit as raw goto */
                        char buf[32];
                        snprintf(buf, sizeof(buf), "goto L%04X;", (uint32_t)tgt);
                        sl_push(&sl, stmt_raw(buf));
                    }
                }
            }
            i++;
            continue;
        }

        /* Handle conditional jumps (if_false, if_true) */
        if (insn->is_conditional) {
            slot_t cond = vs_pop(&ctx->vs);
            int32_t tgt = insn->label_target;

            /* Check if this is a break/continue pattern:
             * if_true -> loop_end  means  if (cond) break;
             * if_true -> inside_loop (forward) means if (cond) continue;
             * (continue in for loops jumps to update part, not condition) */
            if (ctx->loop_depth > 0) {
                int is_break = 0, is_continue = 0;
                int cond_negate = 0;
                for (int d = 0; d < ctx->loop_depth; d++) {
                    if ((uint32_t)tgt == ctx->loop_end_targets[d]) {
                        is_break = 1;
                        if (op == qjs_op_if_false || op == qjs_op_if_false8)
                            cond_negate = 1;
                        break;
                    }
                    /* Check for continue: target is inside the loop body
                     * (between loop_start and loop_end) and is a forward jump */
                    if ((uint32_t)tgt == ctx->loop_start_targets[d]) {
                        is_continue = 1;
                        if (op == qjs_op_if_false || op == qjs_op_if_false8)
                            cond_negate = 1;
                        break;
                    }
                    /* For for-loops: continue jumps to the update part,
                     * which is inside the loop body. Detect this by checking
                     * if the target is a forward jump within the loop. */
                    if ((op == qjs_op_if_true || op == qjs_op_if_true8) &&
                        tgt > (int32_t)insn->pc &&
                        (uint32_t)tgt < ctx->loop_end_targets[d] &&
                        (uint32_t)tgt > ctx->loop_start_targets[d]) {
                        /* Check if target is a basic block start (jump target) */
                        if (ir_is_target(ir, (uint32_t)tgt)) {
                            is_continue = 1;
                            break;
                        }
                    }
                }
                if (is_break || is_continue) {
                    char *cond_str;
                    if (cond_negate) {
                        sbuf_t sb; sb_init(&sb);
                        sb_putc(&sb, '!');
                        sb_putc(&sb, '(');
                        sb_puts(&sb, cond.expr);
                        sb_putc(&sb, ')');
                        cond_str = sb.buf;
                    } else {
                        cond_str = xstrdup(cond.expr);
                    }
                    free(cond.expr);

                    /* Build: if (cond) { break; } or if (cond) { continue; } */
                    stmt_list_t body_sl; sl_init(&body_sl);
                    sl_push(&body_sl, is_break ? stmt_break() : stmt_continue());
                    ir_stmt_t *body = stmt_block(&body_sl);
                    sl_push(&sl, stmt_if(cond_str, body, NULL));
                    i++;
                    continue;
                }
            }

            /* Find the index of the target instruction */
            int tgt_idx = ir_find_insn(ir, (uint32_t)tgt);
            if (tgt_idx < 0 || tgt_idx > ir->count) tgt_idx = end_idx;
            if (tgt_idx <= i) tgt_idx = i + 1; /* safety */

            /* The "then" block is from i+1 to tgt_idx */
            int then_start = i + 1;
            int then_end = tgt_idx;

            /* Check if there's an else block:
             * Pattern: cond; if_false -> Lelse; then; goto -> Lend; Lelse: else; Lend:
             * The instruction just before tgt_idx (at tgt_idx-1) should be a goto.
             * BUT: if the goto is a break/continue (targets loop end/start), it's NOT an else. */
            int else_start = -1, else_end = -1;
            int has_else = 0;
            int end_idx_after = tgt_idx;

            if (then_end > then_start && then_end <= end_idx) {
                /* Check if instruction at then_end - 1 is an unconditional goto */
                int last_then_idx = then_end - 1;
                if (last_then_idx >= 0 && last_then_idx < ir->count) {
                    ir_insn_t *last = &ir->insns[last_then_idx];
                    if (last->is_jump && !last->is_conditional && !last->is_backward) {
                        int32_t end_tgt = last->label_target;
                        /* Check if this goto is actually a break (targets loop end) */
                        int is_break = 0;
                        if (ctx->loop_depth > 0) {
                            for (int d = 0; d < ctx->loop_depth; d++) {
                                if (ctx->loop_end_targets[d] == (uint32_t)end_tgt) {
                                    is_break = 1;
                                    break;
                                }
                            }
                        }
                        if (end_tgt > tgt && !is_break) {
                            /* This is an if/else: then block ends with goto -> Lend */
                            has_else = 1;
                            else_start = tgt_idx;
                            else_end = ir_find_insn(ir, (uint32_t)end_tgt);
                            if (else_end < 0 || else_end > ir->count) else_end = end_idx;
                            end_idx_after = else_end;
                        }
                    }
                }
            }

            /* Check for Frida while-true loop pattern:
             * Lstart: body; cond; if_true8/if_false8 (cond) -> Lend;
             *         <push_true via array_from;lnot;lnot>; if_true -> Lstart (backward); Lend:
             * The then-block (i+1..tgt_idx-1) ends with a backward if_true to Lstart.
             * Frida emits unconditional backward jumps as "if_true(!![])" instead of "goto". */
            {
                if (tgt_idx > i + 1 && tgt_idx <= ir->count) {
                    int lt_idx = tgt_idx - 1;
                    ir_insn_t *lt = &ir->insns[lt_idx];
                    if (lt->is_jump && lt->is_conditional && lt->is_backward &&
                        (lt->op == qjs_op_if_true || lt->op == qjs_op_if_true8) &&
                        lt->label_target >= 0) {
                        uint32_t loop_start = (uint32_t)lt->label_target;
                        int loop_start_idx = ir_find_insn(ir, loop_start);
                        if (loop_start_idx >= 0 && loop_start_idx <= i) {
                            /* Frida while-true loop detected! */
                            int body_stmt_start = 0;
                            if (loop_start_idx < ir->count + 2 &&
                                insn_stmt_count[loop_start_idx] >= 0) {
                                body_stmt_start = insn_stmt_count[loop_start_idx];
                            }

                            /* Build break condition:
                             * if_true  (cond) -> exit  => if (cond) break;
                             * if_false (cond) -> exit  => if (!(cond)) break; */
                            char *cond_str;
                            if (op == qjs_op_if_false || op == qjs_op_if_false8) {
                                sbuf_t sb; sb_init(&sb);
                                sb_putc(&sb, '!');
                                sb_putc(&sb, '(');
                                sb_puts(&sb, cond.expr);
                                sb_putc(&sb, ')');
                                cond_str = sb.buf;
                            } else {
                                cond_str = xstrdup(cond.expr);
                            }
                            free(cond.expr);
                            strip_outer_parens(cond_str);

                            /* Free statements from body_stmt_start onwards
                             * (they'll be re-decompiled as the loop body) */
                            for (int j = body_stmt_start; j < sl.count; j++) {
                                ir_stmt_free(sl.items[j]);
                            }
                            sl.count = body_stmt_start;

                            /* Push loop context for break/continue */
                            if (ctx->loop_depth < 32) {
                                ctx->loop_start_targets[ctx->loop_depth] = loop_start;
                                ctx->loop_end_targets[ctx->loop_depth] = (uint32_t)tgt;
                                ctx->loop_depth++;
                            }

                            /* Re-decompile the body (from loop_start_idx to i,
                             * excluding the exit condition) */
                            ir_stmt_t *body = decompile_range(ctx, loop_start_idx, i);

                            /* Pop loop context */
                            if (ctx->loop_depth > 0) ctx->loop_depth--;

                            /* Ensure body is a block */
                            if (!body) body = stmt_block(NULL);
                            if (body->kind != IR_STMT_BLOCK) {
                                stmt_list_t wrap; sl_init(&wrap);
                                sl_push(&wrap, body);
                                body = stmt_block(&wrap);
                            }

                            /* Build "if (cond) break;" and append to body */
                            stmt_list_t bbody; sl_init(&bbody);
                            sl_push(&bbody, stmt_break());
                            ir_stmt_t *break_if = stmt_if(cond_str,
                                                          stmt_block(&bbody), NULL);
                            /* cond_str ownership transferred to break_if */

                            int new_n = body->n_children + 1;
                            body->children = xrealloc(body->children,
                                                     (new_n > 0 ? new_n : 1) *
                                                         sizeof(ir_stmt_t *));
                            body->children[body->n_children] = break_if;
                            body->n_children = new_n;

                            /* Emit while (true) { body; if (cond) break; } */
                            sl_push(&sl, stmt_while(xstrdup("true"), body));

                            /* Skip to after the then-block (past Lend) */
                            i = tgt_idx;
                            continue;
                        }
                    }
                }
            }

            /* Check for while loop pattern:
             * The target is BEFORE the current instruction (backward jump from a goto)
             * OR: if_false jumps forward, and there's a backward goto at the end of the body
             * Pattern: Lstart: cond; if_false -> Lend; body; goto -> Lstart; Lend: */
            {
                /* Check if the instruction just before tgt_idx is a backward goto
                 * to a PC <= insn->pc */
                if (tgt_idx > 0 && tgt_idx <= ir->count) {
                    int last_body_idx = tgt_idx - 1;
                    if (last_body_idx > i && last_body_idx < ir->count) {
                        ir_insn_t *last_body = &ir->insns[last_body_idx];
                        if (last_body->is_jump && !last_body->is_conditional &&
                            last_body->is_backward &&
                            last_body->label_target >= 0) {
                            uint32_t loop_start = (uint32_t)last_body->label_target;
                            /* Check if loop_start points to the condition */
                            int loop_start_idx = ir_find_insn(ir, loop_start);
                            if (loop_start_idx <= i) {
                                /* This is a while loop!
                                 * cond was already popped. */
                                char *cond_str = xstrdup(cond.expr);
                                free(cond.expr);

                                /* Set up loop tracking for break/continue */
                                uint32_t loop_start_pc = loop_start;
                                uint32_t loop_end_pc = (uint32_t)ir->insns[last_body_idx + 1].pc;

                                /* Body is from i+1 to last_body_idx */
                                /* Push loop context */
                                if (ctx->loop_depth < 32) {
                                    ctx->loop_start_targets[ctx->loop_depth] = loop_start_pc;
                                    ctx->loop_end_targets[ctx->loop_depth] = loop_end_pc;
                                    ctx->loop_depth++;
                                }

                                ir_stmt_t *body = decompile_range(ctx, i + 1, last_body_idx);

                                /* Pop loop context */
                                if (ctx->loop_depth > 0) ctx->loop_depth--;

                                sl_push(&sl, stmt_while(cond_str, body));

                                /* Skip to after the backward goto */
                                i = last_body_idx + 1;
                                continue;
                            }
                        }
                    }
                }
            }

            /* Regular if/if-else (do-while is already handled above) */
            char *cond_str = xstrdup(cond.expr);
            free(cond.expr);

            /* If there's an else, the then-block ends just before the else-skip goto.
             * Exclude the goto from the then-block decompilation. */
            int then_decompile_end = then_end;
            if (has_else) {
                then_decompile_end = then_end - 1; /* exclude the goto */
            }

            /* Ternary detection: save stack depth before branches.
             * Also: save and restore stack VALUES around then-branch decompilation
             * to handle switch/case patterns where `return` inside the then-branch
             * would consume the switch value from the shared stack. */
            int stack_before = ctx->vs.top;

            /* Save stack values that the then-branch might consume */
            int n_saved = 0;
            slot_t saved_slots[MAX_STACK];
            for (int si = 0; si < stack_before && si < MAX_STACK; si++) {
                saved_slots[si] = ctx->vs.slots[si];
                n_saved++;
            }

            ir_stmt_t *then_s = decompile_range(ctx, then_start, then_decompile_end);
            int stack_after_then = ctx->vs.top;
            int then_extra = stack_after_then - stack_before;

            /* If then-branch consumed stack values (e.g., return inside switch/case),
             * restore the saved stack so the continuation has access to them. */
            if (stack_after_then < stack_before) {
                /* Restore saved stack values */
                ctx->vs.top = stack_before;
                for (int si = 0; si < stack_before && si < MAX_STACK; si++) {
                    ctx->vs.slots[si] = saved_slots[si];
                    /* Re-duplicate the expr since the original might have been freed */
                    ctx->vs.slots[si].expr = xstrdup(saved_slots[si].expr);
                }
                stack_after_then = stack_before;
                then_extra = 0;
            }

            /* Capture then-branch's extra values (if any) */
            char *then_val = NULL;
            if (then_extra == 1) {
                slot_t v = vs_pop(&ctx->vs);
                then_val = v.expr;
            } else if (then_extra > 1) {
                while (ctx->vs.top > stack_before) {
                    slot_t v = vs_pop(&ctx->vs);
                    free(v.expr);
                }
            }

            ir_stmt_t *else_s = NULL;
            char *else_val = NULL;
            if (has_else) {
                else_s = decompile_range(ctx, else_start, else_end);
                int stack_after_else = ctx->vs.top;
                int else_extra = stack_after_else - stack_before;

                if (else_extra == 1) {
                    slot_t v = vs_pop(&ctx->vs);
                    else_val = v.expr;
                } else {
                    while (ctx->vs.top > stack_before) {
                        slot_t v = vs_pop(&ctx->vs);
                        free(v.expr);
                    }
                }
            }

            /* Check if this is a ternary expression:
             * - Both branches pushed exactly 1 value
             * - Neither branch produced any statements (or empty blocks)
             * - There IS an else branch */
            if (has_else && then_val && else_val) {
                int then_empty = (!then_s || (then_s->kind == IR_STMT_BLOCK && then_s->n_children == 0));
                int else_empty = (!else_s || (else_s->kind == IR_STMT_BLOCK && else_s->n_children == 0));

                if (then_empty && else_empty) {
                    /* This is a ternary: cond ? then_val : else_val */
                    strip_outer_parens(cond_str);
                    sbuf_t sb; sb_init(&sb);
                    sb_putc(&sb, '(');
                    sb_puts(&sb, cond_str);
                    sb_puts(&sb, " ? ");
                    sb_puts(&sb, then_val);
                    sb_puts(&sb, " : ");
                    sb_puts(&sb, else_val);
                    sb_putc(&sb, ')');
                    vs_push_take_prec(&ctx->vs, sb.buf, PREC_COND, 0);

                    free(cond_str);
                    free(then_val);
                    free(else_val);
                    ir_stmt_free(then_s);
                    ir_stmt_free(else_s);
                    i = end_idx_after;
                    continue;
                }
            }

            /* Not a ternary - push values back or emit as if/else */
            if (then_val) {
                vs_push_prec(&ctx->vs, then_val, PREC_ATOM, 0);
            }
            if (else_val) {
                /* This shouldn't happen for non-ternary, but just in case */
                /* Push else_val as a separate value? No, that would corrupt the stack. */
                /* For now, free it. */
                free(else_val);
            }

            sl_push(&sl, stmt_if(cond_str, then_s, else_s));
            i = end_idx_after;
            continue;
        }

        /* Handle drop specially: if the dropped value is a duplicate of
         * what was just assigned (from dup + put_loc + drop pattern),
         * suppress it entirely. Otherwise, emit as statement if it has side effects. */
        if (op == qjs_op_drop) {
            slot_t v = vs_pop(&ctx->vs);

            /* Check if this is a residual from dup + put_loc pattern.
             * If the previous statement was an assignment and this expression
             * matches the assigned RHS, skip it. */
            int is_duplicate = 0;
            if (sl.count > 0) {
                ir_stmt_t *prev_stmt = sl.items[sl.count - 1];
                if ((prev_stmt->kind == IR_STMT_ASSIGN || prev_stmt->kind == IR_STMT_COMPOUND_ASSIGN) &&
                    prev_stmt->rhs && v.expr && strcmp(prev_stmt->rhs, v.expr) == 0) {
                    is_duplicate = 1;
                }
            }

            if (is_duplicate) {
                free(v.expr);
                i++;
                continue;
            }

            /* Check if it's a statement-worthy expression.
             * Any function call is worthy (side effects).
             * Also check for method calls (obj.method()). */
            int worthy = 0;
            if (v.expr && *v.expr) {
                /* Check for function calls - any '(' that's part of a call */
                /* First, check if it's a simple identifier call: funcName(...) */
                if (!already_parenthesized(v.expr)) {
                    /* Check for call patterns */
                    char *paren = strchr(v.expr, '(');
                    if (paren) {
                        /* Has a paren - check if it's a call (not grouping) */
                        /* A call has identifier or ')' or ']' immediately before '(' */
                        if (paren == v.expr) {
                            /* Starts with ( - could be (expr)(args) - treat as call */
                            worthy = 1;
                        } else {
                            char before = paren[-1];
                            if (isalnum((unsigned char)before) || before == '_' ||
                                before == '$' || before == ')' || before == ']') {
                                worthy = 1;
                            }
                        }
                    }
                    /* Check for ++ and -- */
                    if (strstr(v.expr, "++") || strstr(v.expr, "--")) {
                        worthy = 1;
                    }
                    /* Check for "new X(...)" pattern */
                    if (strncmp(v.expr, "new ", 4) == 0) {
                        worthy = 1;
                    }
                    /* Check for assignment patterns (= but not == or === or !=) */
                    if (strchr(v.expr, '=') && !strstr(v.expr, "==") &&
                        !strstr(v.expr, "!=") && !strstr(v.expr, "<=") &&
                        !strstr(v.expr, ">=") && !strstr(v.expr, "=>")) {
                        worthy = 1;
                    }
                } else {
                    /* Parenthesized expression - check for call inside */
                    char *p = v.expr + 1;
                    while (*p && *p != ')') {
                        if ((isalpha((unsigned char)*p) || *p == '_') && p[1] == '(') {
                            worthy = 1;
                            break;
                        }
                        p++;
                    }
                }
            }
            if (worthy) {
                sl_push(&sl, stmt_expr(v.expr));
            } else {
                free(v.expr);
            }
            i++;
            continue;
        }

        /* Handle put_loc/put_arg/put_var/put_var_ref: these are assignments */
        if (op == qjs_op_put_loc || op == qjs_op_put_loc8 ||
            op == qjs_op_put_loc0 || op == qjs_op_put_loc1 ||
            op == qjs_op_put_loc2 || op == qjs_op_put_loc3 ||
            op == qjs_op_put_arg || op == qjs_op_put_arg0 ||
            op == qjs_op_put_arg1 || op == qjs_op_put_arg2 ||
            op == qjs_op_put_arg3 ||
            op == qjs_op_put_loc_check || op == qjs_op_put_loc_check_init ||
            op == qjs_op_put_var || op == qjs_op_put_var_init || op == qjs_op_put_var_strict ||
            op == qjs_op_put_var_ref || op == qjs_op_put_var_ref0 || op == qjs_op_put_var_ref1 ||
            op == qjs_op_put_var_ref2 || op == qjs_op_put_var_ref3 ||
            op == qjs_op_put_var_ref_check || op == qjs_op_put_var_ref_check_init) {

            char *lv = NULL;
            if (op == qjs_op_put_loc || op == qjs_op_put_loc8 ||
                op == qjs_op_put_loc0 || op == qjs_op_put_loc1 ||
                op == qjs_op_put_loc2 || op == qjs_op_put_loc3 ||
                op == qjs_op_put_loc_check || op == qjs_op_put_loc_check_init) {
                lv = loc_name(r, fn, insn->u32_val);
            } else if (op == qjs_op_put_arg || op == qjs_op_put_arg0 ||
                       op == qjs_op_put_arg1 || op == qjs_op_put_arg2 ||
                       op == qjs_op_put_arg3) {
                lv = arg_name(r, fn, insn->u32_val);
            } else if (op == qjs_op_put_var_ref || op == qjs_op_put_var_ref0 ||
                       op == qjs_op_put_var_ref1 || op == qjs_op_put_var_ref2 ||
                       op == qjs_op_put_var_ref3 ||
                       op == qjs_op_put_var_ref_check || op == qjs_op_put_var_ref_check_init) {
                /* Closure variable */
                uint32_t vref = insn->u32_val;
                if (vref < (uint32_t)fn->closure_var_count)
                    lv = xstrdup(qjs_atom_str(r, fn->closure_vars[vref].var_name_atom));
                else {
                    char b[64]; snprintf(b, sizeof(b), "_var_ref_%d", vref);
                    lv = xstrdup(b);
                }
            } else {
                /* put_var */
                lv = xstrdup(atom_name_of(r, insn));
            }

            slot_t val = vs_pop(&ctx->vs);

            /* Check for compound assignment pattern:
             * The value expression is "lv OP rhs" (without outer parens now).
             * We check if the expression starts with "lv " followed by a binary op.
             * CRITICAL: the found OP must be the TOP-LEVEL operator (val.prec must match). */
            if (val.expr && lv[0] && val.prec >= PREC_OR && val.prec <= PREC_MUL) {
                size_t lvlen = strlen(lv);
                if (strlen(val.expr) > lvlen + 2 &&
                    strncmp(val.expr, lv, lvlen) == 0 &&
                    val.expr[lvlen] == ' ') {
                    /* Extract the operator (everything between lv+space and next space) */
                    char *op_start = val.expr + lvlen + 1;
                    char *op_end = strchr(op_start, ' ');
                    if (op_end) {
                        size_t op_len = op_end - op_start;
                        /* Check it's a valid binary op (not ++ or --) */
                        char *op_str_check = xmalloc(op_len + 1);
                        memcpy(op_str_check, op_start, op_len);
                        op_str_check[op_len] = '\0';
                        int is_binop = (strcmp(op_str_check, "+") == 0 || strcmp(op_str_check, "-") == 0 ||
                                        strcmp(op_str_check, "*") == 0 || strcmp(op_str_check, "/") == 0 ||
                                        strcmp(op_str_check, "%") == 0 || strcmp(op_str_check, "**") == 0 ||
                                        strcmp(op_str_check, "<<") == 0 || strcmp(op_str_check, ">>") == 0 ||
                                        strcmp(op_str_check, ">>>") == 0 || strcmp(op_str_check, "&") == 0 ||
                                        strcmp(op_str_check, "|") == 0 || strcmp(op_str_check, "^") == 0);
                        /* CRITICAL: verify the found op IS the top-level operator.
                         * If val.prec != op_prec(found_op), the op is nested inside
                         * a lower-precedence operator (e.g., & wraps +), so we must
                         * NOT convert to compound assignment. */
                        if (is_binop && val.prec == op_prec(op_str_check)) {
                            /* Build compound op: OP + "=" */
                            char *comp_op = xmalloc(op_len + 2);
                            memcpy(comp_op, op_start, op_len);
                            comp_op[op_len] = '=';
                            comp_op[op_len + 1] = '\0';
                            /* RHS is everything after "op_end + 1" */
                            char *rhs = xstrdup(op_end + 1);
                            sl_push(&sl, stmt_compound_assign(lv, comp_op, rhs));
                            free(comp_op);
                            free(val.expr);
                            i++;
                            continue;
                        }
                        free(op_str_check);
                    }
                }
            }

            /* Check for post-inc/dec pattern: "lv++" or "lv--" (no parens now) */
            if (val.expr && lv[0]) {
                size_t lvlen = strlen(lv);
                if (strlen(val.expr) == lvlen + 2 &&
                    strncmp(val.expr, lv, lvlen) == 0 &&
                    val.expr[lvlen] == '+' && val.expr[lvlen + 1] == '+') {
                    /* It's lv++ - emit lv++ */
                    sbuf_t sb; sb_init(&sb);
                    sb_puts(&sb, lv);
                    sb_puts(&sb, "++");
                    sl_push(&sl, stmt_expr(sb.buf));
                    free(lv); free(val.expr);
                    i++;
                    continue;
                }
                if (strlen(val.expr) == lvlen + 2 &&
                    strncmp(val.expr, lv, lvlen) == 0 &&
                    val.expr[lvlen] == '-' && val.expr[lvlen + 1] == '-') {
                    sbuf_t sb; sb_init(&sb);
                    sb_puts(&sb, lv);
                    sb_puts(&sb, "--");
                    sl_push(&sl, stmt_expr(sb.buf));
                    free(lv); free(val.expr);
                    i++;
                    continue;
                }
            }

            /* Regular assignment - stmt_assign takes ownership of lv and val.expr */
            sl_push(&sl, stmt_assign(lv, val.expr));
            /* Do NOT free val.expr - ownership transferred to statement */
            i++;
            continue;
        }

        /* Handle set_loc/set_arg/set_var_ref: like put but also leaves value on stack */
        if (op == qjs_op_set_loc || op == qjs_op_set_loc8 ||
            op == qjs_op_set_loc0 || op == qjs_op_set_loc1 ||
            op == qjs_op_set_loc2 || op == qjs_op_set_loc3 ||
            op == qjs_op_set_arg || op == qjs_op_set_arg0 ||
            op == qjs_op_set_arg1 || op == qjs_op_set_arg2 ||
            op == qjs_op_set_arg3 ||
            op == qjs_op_set_var_ref || op == qjs_op_set_var_ref0 ||
            op == qjs_op_set_var_ref1 || op == qjs_op_set_var_ref2 ||
            op == qjs_op_set_var_ref3) {
            /* set_loc: pops value, pushes it back. Used in expression context. */
            /* Don't emit as statement - just leave the value on stack */
            /* The value is already on stack (set doesn't pop in our model since
             * we pushed it). Actually set_loc pops AND pushes.
             * In our model: the value is on top, set_loc replaces it with itself.
             * So: no change to stack. */
            i++;
            continue;
        }

        /* Handle inc_loc/dec_loc */
        if (op == qjs_op_inc_loc || op == qjs_op_dec_loc) {
            char *lv = loc_name(r, fn, insn->u32_val);
            sbuf_t sb; sb_init(&sb);
            sb_puts(&sb, lv);
            sb_puts(&sb, (op == qjs_op_inc_loc) ? "++" : "--");
            sl_push(&sl, stmt_expr(sb.buf));
            free(lv);
            i++;
            continue;
        }
        if (op == qjs_op_add_loc) {
            char *lv = loc_name(r, fn, insn->u32_val);
            slot_t v = vs_pop(&ctx->vs);
            sl_push(&sl, stmt_compound_assign(lv, "+=", v.expr));
            /* v.expr ownership transferred to statement */
            free(lv);
            i++;
            continue;
        }

        /* Handle define_func - skip since nested functions are already
         * printed before the parent function. Just pop the closure value. */
        if (op == qjs_op_define_func) {
            slot_t fn_val = vs_pop(&ctx->vs);
            free(fn_val.expr);
            i++;
            continue;
        }

        /* Handle put_field, put_array_el (define_field handled in decode_insn) */
        if (op == qjs_op_put_field) {
            slot_t val = vs_pop(&ctx->vs);
            slot_t obj = vs_pop(&ctx->vs);
            char *fld = field_expr(obj.expr, atom_name_of(r, insn));

            /* Check for this.field++ pattern (same as put_array_el post_inc fix):
             * If val is "fld++"/"fld--" and the value below equals fld,
             * append ++/-- to the value below instead of emitting "fld = fld++". */
            int is_post_inc_pattern = 0;
            if (val.expr && fld && ctx->vs.top > 0) {
                size_t flen = strlen(fld);
                size_t vlen = strlen(val.expr);
                if (vlen == flen + 2 && strncmp(val.expr, fld, flen) == 0 &&
                    ((val.expr[flen] == '+' && val.expr[flen+1] == '+') ||
                     (val.expr[flen] == '-' && val.expr[flen+1] == '-'))) {
                    slot_t *old_slot = &ctx->vs.slots[ctx->vs.top - 1];
                    if (old_slot->expr && strcmp(old_slot->expr, fld) == 0) {
                        is_post_inc_pattern = 1;
                        size_t old_len = strlen(old_slot->expr);
                        char *new_old = xmalloc(old_len + 3);
                        memcpy(new_old, old_slot->expr, old_len);
                        new_old[old_len] = val.expr[flen];
                        new_old[old_len+1] = val.expr[flen+1];
                        new_old[old_len+2] = '\0';
                        free(old_slot->expr);
                        old_slot->expr = new_old;
                    }
                }
            }

            if (is_post_inc_pattern) {
                free(val.expr);
                free(obj.expr);
                free(fld);
            } else {
                sl_push(&sl, stmt_assign(fld, val.expr));
                /* val.expr and fld ownership transferred to statement */
                free(obj.expr);
            }
            i++;
            continue;
        }
        if (op == qjs_op_put_array_el) {
            slot_t val = vs_pop(&ctx->vs);
            slot_t idx = vs_pop(&ctx->vs);
            slot_t obj = vs_pop(&ctx->vs);
            char *e = make_index_access(obj.expr, idx.expr);

            /* Check for buffer[index++] pattern:
             * Stack before: ..., OLD, this, index, NEW
             * where OLD = this[index] (pre-increment value from get_array_el)
             * and NEW = this[index]++ (post-inc expression from post_inc)
             * If val (NEW) is "e++"/"e--" and the value below (OLD) equals e,
             * this is a post-increment of e. Don't emit "e = e++" (which is a
             * no-op that resets the value). Instead, append ++ to OLD so the
             * subsequent get_array_el produces "buf[e++]". */
            int is_post_inc_pattern = 0;
            if (val.expr && e && ctx->vs.top > 0) {
                size_t elen = strlen(e);
                size_t vlen = strlen(val.expr);
                if (vlen == elen + 2 && strncmp(val.expr, e, elen) == 0 &&
                    ((val.expr[elen] == '+' && val.expr[elen+1] == '+') ||
                     (val.expr[elen] == '-' && val.expr[elen+1] == '-'))) {
                    slot_t *old_slot = &ctx->vs.slots[ctx->vs.top - 1];
                    if (old_slot->expr && strcmp(old_slot->expr, e) == 0) {
                        is_post_inc_pattern = 1;
                        size_t old_len = strlen(old_slot->expr);
                        char *new_old = xmalloc(old_len + 3);
                        memcpy(new_old, old_slot->expr, old_len);
                        new_old[old_len] = val.expr[elen];
                        new_old[old_len+1] = val.expr[elen+1];
                        new_old[old_len+2] = '\0';
                        free(old_slot->expr);
                        old_slot->expr = new_old;
                    }
                }
            }

            if (is_post_inc_pattern) {
                free(val.expr);
                free(idx.expr);
                free(obj.expr);
                free(e);
            } else {
                sl_push(&sl, stmt_assign(e, val.expr));
                /* val.expr and e ownership transferred to statement */
                free(idx.expr); free(obj.expr);
            }
            i++;
            continue;
        }
        /* define_field and set_name are handled in decode_insn (object literal construction) */

        /* Handle delete */
        if (op == qjs_op_delete) {
            slot_t a = vs_pop(&ctx->vs);
            slot_t b = vs_pop(&ctx->vs);
            if (b.prec < PREC_CALL && !already_parenthesized(b.expr))
                b.expr = wrap_parens(b.expr);
            char *e = make_index_access(b.expr, a.expr);
            char *result = make_unop("delete ", e);
            vs_push_take_prec(&ctx->vs, result, PREC_UNARY, 0);
            free(a.expr); free(b.expr); free(e);
            i++;
            continue;
        }
        if (op == qjs_op_delete_var) {
            const char *a = atom_name_of(r, insn);
            /* If atom is a placeholder (numeric or _atom_oob_), push undefined instead */
            if (a && (strncmp(a, "_atom_oob_", 10) == 0 || 
                       (a[0] >= '0' && a[0] <= '9'))) {
                vs_push_prec(&ctx->vs, "undefined", PREC_ATOM, 0);
            } else {
                char *e = make_unop("delete ", a);
                vs_push_take_prec(&ctx->vs, e, PREC_UNARY, 0);
            }
            i++;
            continue;
        }

        /* ===== For-of / For-in loop detection =====
         * Pattern: for_of_start; goto -> check; put_loc N; body; for_of_next; if_false -> body; drop; iterator_close
         * We detect for_of_start and reconstruct the entire loop. */
        if (op == qjs_op_for_of_start || op == qjs_op_for_in_start) {
            /* Pop the iterable expression (for_of_start pops 1) */
            slot_t iterable_slot = vs_pop(&ctx->vs);
            char *iterable_expr = iterable_slot.expr;
            int is_for_of = (op == qjs_op_for_of_start);

            /* Push placeholder stack values that for_of_start would push */
            if (is_for_of) {
                vs_push_prec(&ctx->vs, "_iter", PREC_ATOM, 0);
                vs_push_prec(&ctx->vs, "_iter_catch", PREC_ATOM, 0);
                vs_push_prec(&ctx->vs, "_iter_next", PREC_ATOM, 0);
            } else {
                vs_push_prec(&ctx->vs, "_iter", PREC_ATOM, 0);
            }

            /* Find the goto8 that should be at i+1 */
            int goto_idx = i + 1;
            if (goto_idx >= ir->count ||
                !(ir->insns[goto_idx].op == qjs_op_goto || ir->insns[goto_idx].op == qjs_op_goto8 ||
                  ir->insns[goto_idx].op == qjs_op_goto16)) {
                /* Not a for-of pattern, just continue normally */
                i++;
                continue;
            }
            ir_insn_t *goto_insn = &ir->insns[goto_idx];
            int32_t check_pc = goto_insn->label_target;
            int check_idx = ir_find_insn(ir, (uint32_t)check_pc);
            if (check_idx < 0 || check_idx >= ir->count) {
                i++;
                continue;
            }

            /* Body starts at goto_idx + 1 */
            int body_start_idx = goto_idx + 1;

            /* At check_idx, expect for_of_next or for_in_next */
            ir_insn_t *check_insn = &ir->insns[check_idx];
            int next_op = check_insn->op;
            if (next_op != qjs_op_for_of_next && next_op != qjs_op_for_in_next) {
                i++;
                continue;
            }

            /* After for_of_next, expect if_false8/if_true8 backward to body_start */
            int after_next = check_idx + 1;
            if (after_next >= ir->count) {
                i++;
                continue;
            }
            ir_insn_t *if_insn = &ir->insns[after_next];
            if (!if_insn->is_conditional || !if_insn->is_backward) {
                i++;
                continue;
            }
            /* The if_false/if_true should jump back to body_start */
            int32_t body_pc = (int32_t)ir->insns[body_start_idx].pc;
            if (if_insn->label_target != body_pc) {
                i++;
                continue;
            }

            /* Find the loop variable: body_start should be put_loc N or put_var_ref */
            ir_insn_t *body_first = &ir->insns[body_start_idx];
            const char *loop_var = NULL;
            int loop_var_decl_kind = 0; /* 0=var, 1=let, 2=const */
            if (body_first->op == qjs_op_put_loc || body_first->op == qjs_op_put_loc0 ||
                body_first->op == qjs_op_put_loc1 || body_first->op == qjs_op_put_loc2 ||
                body_first->op == qjs_op_put_loc3 || body_first->op == qjs_op_put_loc8 ||
                body_first->op == qjs_op_put_loc_check) {
                int loc_idx = (int)body_first->u32_val;
                if (body_first->op == qjs_op_put_loc0) loc_idx = 0;
                else if (body_first->op == qjs_op_put_loc1) loc_idx = 1;
                else if (body_first->op == qjs_op_put_loc2) loc_idx = 2;
                else if (body_first->op == qjs_op_put_loc3) loc_idx = 3;
                if (loc_idx >= 0 && loc_idx < fn->vardefs_count) {
                    loop_var = qjs_atom_str(r, fn->vardefs[loc_idx].var_name_atom);
                    if (fn->vardefs[loc_idx].is_const) loop_var_decl_kind = 2;
                    else if (fn->vardefs[loc_idx].is_lexical) loop_var_decl_kind = 1;
                }
            }

            /* Find the end of the loop (after iterator_close) */
            /* After if_false: drop, drop, drop, iterator_close */
            int loop_end_idx = after_next + 1;
            /* Skip drops and iterator_close */
            while (loop_end_idx < ir->count) {
                int o = ir->insns[loop_end_idx].op;
                if (o == qjs_op_drop || o == qjs_op_iterator_close ||
                    o == qjs_op_iterator_next || o == qjs_op_iterator_call) {
                    loop_end_idx++;
                } else {
                    break;
                }
            }

            /* Body is from body_start_idx+1 to check_idx-1 (exclude put_loc and for_of_next) */
            int body_end_idx = check_idx;

            /* Set up loop context */
            if (ctx->loop_depth < 32) {
                ctx->loop_start_targets[ctx->loop_depth] = (uint32_t)body_pc;
                ctx->loop_end_targets[ctx->loop_depth] = (uint32_t)ir->insns[loop_end_idx].pc;
                ctx->loop_depth++;
            }

            /* Clean up the iterator placeholder values from stack */
            while (ctx->vs.top > 0) {
                slot_t s = vs_pop(&ctx->vs);
                if (s.expr && strncmp(s.expr, "_iter", 5) == 0) {
                    free(s.expr);
                } else {
                    /* Push it back - it's not an iterator placeholder */
                    vs_push_prec(&ctx->vs, s.expr, s.prec, s.is_lvalue);
                    break;
                }
            }

            /* Decompile the body */
            ir_stmt_t *body = decompile_range(ctx, body_start_idx + 1, body_end_idx);

            /* Pop loop context */
            if (ctx->loop_depth > 0) ctx->loop_depth--;

            /* Build the for-of/for-in statement */
            char *iter_str = iterable_expr ? iterable_expr : xstrdup("undefined");
            strip_outer_parens(iter_str);

            if (loop_var) {
                /* Build: for (const var of iterable) { body } */
                sbuf_t sb; sb_init(&sb);
                const char *kw = is_for_of ? "of" : "in";
                const char *decl_kw = (loop_var_decl_kind == 2) ? "const" :
                                      (loop_var_decl_kind == 1) ? "let" : "var";
                sb_printf(&sb, "%s %s %s %s", decl_kw, loop_var, kw, iter_str);
                /* Use stmt_for with init=NULL, cond=loop header, update=NULL */
                ir_stmt_t *for_stmt = stmt_new(IR_STMT_FOR);
                for_stmt->init = NULL;
                for_stmt->cond = sb.buf;
                for_stmt->update = NULL;
                for_stmt->body = body ? body : stmt_block(NULL);
                sl_push(&sl, for_stmt);
            } else {
                /* No loop variable found - emit as while loop with body */
                ir_stmt_t *while_stmt = stmt_while(xstrdup("true"),
                                                    body ? body : stmt_block(NULL));
                sl_push(&sl, while_stmt);
            }
            free(iter_str);

            /* Skip past the entire for-of pattern */
            i = loop_end_idx;
            continue;
        }

        /* Try to decode as expression */
        decode_result_t res = decode_insn(ctx, insn);
        if (res == DECODE_OK || res == DECODE_SKIP) {
            i++;
            continue;
        }
        if (res == DECODE_CONTROL_FLOW) {
            /* Already handled above - shouldn't reach here */
            i++;
            continue;
        }

        /* Unknown instruction - skip silently and adjust stack */
        {
            int pops = insn->info ? insn->info->n_pop : 0;
            int pushes = insn->info ? insn->info->n_push : 0;
            while (pops > 0 && ctx->vs.top > 0) {
                slot_t s = vs_pop(&ctx->vs);
                free(s.expr);
                pops--;
            }
            while (pushes > 0) {
                vs_push(&ctx->vs, "_unknown", 0, 0);
                pushes--;
            }
        }
        i++;
    }

    /* Implicit return: ONLY at top-level (end of function body).
     * In sub-ranges (if branches, while bodies), values left on stack
     * are meant to be used by code after the branch (e.g., ternary expr,
     * conditional assignment), NOT returned. */
    if (is_toplevel && ctx->vs.top > 0) {
        slot_t v = vs_pop(&ctx->vs);
        /* Close any open object literal */
        if (v.expr && v.expr[0] == '{' && v.expr[strlen(v.expr)-1] != '}') {
            sbuf_t sb; sb_init(&sb);
            sb_puts(&sb, v.expr);
            sb_putc(&sb, '}');
            free(v.expr);
            v.expr = sb.buf;
        }
        if (v.expr && *v.expr && strcmp(v.expr, "_unknown") != 0 &&
            strcmp(v.expr, "undefined") != 0) {
            sl_push(&sl, stmt_return(v.expr));
        } else {
            free(v.expr);
        }
    }
    /* Clear remaining stack ONLY at top-level.
     * For sub-ranges, leave values on stack for the caller to use
     * (e.g., ternary expression values from if/else branches). */
    if (is_toplevel) {
        while (ctx->vs.top > 0) {
            slot_t v = vs_pop(&ctx->vs);
            /* Close open object literals */
            if (v.expr && v.expr[0] == '{' && v.expr[strlen(v.expr)-1] != '}') {
                sbuf_t sb; sb_init(&sb);
                sb_puts(&sb, v.expr);
                sb_putc(&sb, '}');
                free(v.expr);
                v.expr = sb.buf;
            }
            free(v.expr);
        }
    }

    free(insn_stmt_count);
    return stmt_block(&sl);
}

/* Fix for the goto label hack above */
static inline void vs_pop_and_free(vstack_t *vs) {
    slot_t s = vs_pop(vs);
    free(s.expr);
}

/* =========================================================
 * Pre-scan: collect variable names declared via define_var / check_define_var
 * These are global/function-scoped variables declared with `var`.
 * ========================================================= */
typedef struct {
    char **names;
    int *kinds;  /* 0=var, 1=let, 2=const */
    int count;
    int cap;
} var_decl_set_t;

static void vds_init(var_decl_set_t *s) { s->names = NULL; s->kinds = NULL; s->count = 0; s->cap = 0; }
static void vds_free(var_decl_set_t *s) {
    for (int i = 0; i < s->count; i++) free(s->names[i]);
    free(s->names);
    free(s->kinds);
    s->names = NULL; s->kinds = NULL; s->count = s->cap = 0;
}
static void vds_add(var_decl_set_t *s, const char *name, int kind) {
    /* Check if already present - update kind if so */
    for (int i = 0; i < s->count; i++) {
        if (strcmp(s->names[i], name) == 0) {
            /* Update kind (define_func with -1 overrides previous) */
            if (kind == -1) s->kinds[i] = -1;
            return;
        }
    }
    if (s->count >= s->cap) {
        s->cap = s->cap ? s->cap * 2 : 16;
        s->names = xrealloc(s->names, s->cap * sizeof(char *));
        s->kinds = xrealloc(s->kinds, s->cap * sizeof(int));
    }
    s->names[s->count] = xstrdup(name);
    s->kinds[s->count] = kind;
    s->count++;
}
static int vds_lookup(var_decl_set_t *s, const char *name, int *kind) {
    for (int i = 0; i < s->count; i++) {
        if (strcmp(s->names[i], name) == 0) {
            if (kind) *kind = s->kinds[i];
            return 1;
        }
    }
    return 0;
}

static void collect_var_decls(ir_function_t *ir, qjs_reader_t *r, var_decl_set_t *vds) {
    for (int i = 0; i < ir->count; i++) {
        ir_insn_t *insn = &ir->insns[i];
        if (!insn->info) continue;
        if (insn->op == qjs_op_define_var || insn->op == qjs_op_check_define_var) {
            const char *name = qjs_atom_str(r, insn->atom_val);
            int kind = 0; /* var by default */
            if (insn->u32_val & 1) kind = 1; /* let */
            if (insn->u32_val & 2) kind = 2; /* const */
            vds_add(vds, name, kind);
        }
    }
    /* Also collect define_func names - these are function declarations
     * that are already printed, so they shouldn't be hoisted as var decls */
    for (int i = 0; i < ir->count; i++) {
        ir_insn_t *insn = &ir->insns[i];
        if (!insn->info) continue;
        if (insn->op == qjs_op_define_func) {
            const char *name = qjs_atom_str(r, insn->atom_val);
            /* Mark as already declared (kind = -1 means "skip hoisting") */
            vds_add(vds, name, -1);
        }
    }
}

/* =========================================================
 * Post-processing: convert first assignment to declaration
 * for lexical variables (let/const) and var-declared variables.
 * Only converts the FIRST assignment to each variable (tracks seen set).
 * ========================================================= */
typedef struct {
    const char **names;
    int count;
    int cap;
} seen_set_t;

static void seen_init(seen_set_t *s) { s->names = NULL; s->count = 0; s->cap = 0; }
static void seen_free(seen_set_t *s) { free(s->names); s->names = NULL; s->count = s->cap = 0; }
static int seen_contains(seen_set_t *s, const char *name) {
    for (int i = 0; i < s->count; i++)
        if (strcmp(s->names[i], name) == 0) return 1;
    return 0;
}
static void seen_add(seen_set_t *s, const char *name) {
    if (s->count >= s->cap) {
        s->cap = s->cap ? s->cap * 2 : 16;
        s->names = xrealloc(s->names, s->cap * sizeof(const char *));
    }
    s->names[s->count++] = name;
}

static void hoist_declarations_rec(ir_stmt_t *s, qjs_function_t *fn, qjs_reader_t *r,
                                    seen_set_t *seen, var_decl_set_t *vds) {
    if (!s) return;
    if (s->kind == IR_STMT_BLOCK) {
        for (int i = 0; i < s->n_children; i++) {
            hoist_declarations_rec(s->children[i], fn, r, seen, vds);
        }
        return;
    }
    /* Convert first assignment to a lexical/var local into a declaration */
    if (s->kind == IR_STMT_ASSIGN && s->lvalue && !is_internal_var(s->lvalue) &&
        !is_reserved_word(s->lvalue)) {
        /* Check if lvalue is a declared variable in vardefs */
        int found = 0;
        int decl_kind = 0;
        int is_param = 0;
        for (int j = 0; j < fn->vardefs_count; j++) {
            const char *varname = qjs_atom_str(r, fn->vardefs[j].var_name_atom);
            if (strcmp(s->lvalue, varname) == 0) {
                found = 1;
                /* Check if this is a function parameter (not a local var) */
                if (j < fn->arg_count) {
                    is_param = 1;
                }
                if (fn->vardefs[j].is_const) decl_kind = 2;
                else if (fn->vardefs[j].is_lexical) decl_kind = 1;
                else decl_kind = 0;
                break;
            }
        }
        /* If not in vardefs, check var_decl_set (define_var declarations) */
        if (!found) {
            int kind;
            if (vds_lookup(vds, s->lvalue, &kind)) {
                if (kind == -1) {
                    /* This is a function declaration (define_func) - already printed,
                     * don't hoist as var declaration */
                    found = 0;
                } else {
                    found = 1;
                    decl_kind = kind;
                }
            }
        }
        /* Only convert if not already seen (first assignment) AND not a parameter */
        if (found && !seen_contains(seen, s->lvalue) && !is_param) {
            s->kind = IR_STMT_DECL;
            s->decl_kind = decl_kind;
            seen_add(seen, s->lvalue);
        }
    }
    /* Recurse into sub-statements */
    if (s->body) hoist_declarations_rec(s->body, fn, r, seen, vds);
    if (s->else_body) hoist_declarations_rec(s->else_body, fn, r, seen, vds);
    if (s->init) hoist_declarations_rec(s->init, fn, r, seen, vds);
    if (s->update) hoist_declarations_rec(s->update, fn, r, seen, vds);
}

static void hoist_declarations(ir_stmt_t *s, qjs_function_t *fn, qjs_reader_t *r,
                                ir_function_t *ir) {
    seen_set_t seen;
    seen_init(&seen);
    var_decl_set_t vds;
    vds_init(&vds);
    collect_var_decls(ir, r, &vds);
    hoist_declarations_rec(s, fn, r, &seen, &vds);
    vds_free(&vds);
    seen_free(&seen);
}

/* Forward declaration */
static char *strip_outer_parens(char *expr);

/* =========================================================
 * Helper: check if a variable name appears in an expression string.
 * Uses word-boundary matching to avoid partial matches.
 * ========================================================= */
static int expr_contains_var(const char *expr, const char *varname) {
    if (!expr || !varname || !*varname) return 0;
    size_t vlen = strlen(varname);
    const char *p = expr;
    while ((p = strstr(p, varname)) != NULL) {
        /* Check word boundary before */
        if (p > expr) {
            char before = p[-1];
            if (isalnum((unsigned char)before) || before == '_' || before == '$') {
                p += vlen;
                continue;
            }
        }
        /* Check word boundary after */
        char after = p[vlen];
        if (isalnum((unsigned char)after) || after == '_' || after == '$') {
            p += vlen;
            continue;
        }
        return 1;
    }
    return 0;
}

/* Recursively check if a variable name is referenced anywhere in the
 * statement tree (excluding the declaration statement itself). */
static int var_used_in_tree(ir_stmt_t *s, const char *varname, ir_stmt_t *exclude) {
    if (!s || s == exclude) return 0;
    switch (s->kind) {
        case IR_STMT_EXPR:
        case IR_STMT_RETURN:
        case IR_STMT_THROW:
            if (expr_contains_var(s->expr, varname)) return 1;
            break;
        case IR_STMT_ASSIGN:
        case IR_STMT_COMPOUND_ASSIGN:
            if (expr_contains_var(s->lvalue, varname)) return 1;
            if (expr_contains_var(s->rhs, varname)) return 1;
            break;
        case IR_STMT_DECL:
            if (expr_contains_var(s->lvalue, varname)) return 1;
            if (expr_contains_var(s->rhs, varname)) return 1;
            break;
        case IR_STMT_IF:
        case IR_STMT_WHILE:
        case IR_STMT_DO_WHILE:
            if (expr_contains_var(s->cond, varname)) return 1;
            break;
        case IR_STMT_FOR:
            if (s->init && var_used_in_tree(s->init, varname, exclude)) return 1;
            if (expr_contains_var(s->cond, varname)) return 1;
            if (s->update && var_used_in_tree(s->update, varname, exclude)) return 1;
            break;
        default:
            break;
    }
    /* Recurse into children */
    if (s->body && var_used_in_tree(s->body, varname, exclude)) return 1;
    if (s->else_body && var_used_in_tree(s->else_body, varname, exclude)) return 1;
    if (s->init && var_used_in_tree(s->init, varname, exclude)) return 1;
    if (s->update && var_used_in_tree(s->update, varname, exclude)) return 1;
    if (s->catch_body && var_used_in_tree(s->catch_body, varname, exclude)) return 1;
    if (s->finally_body && var_used_in_tree(s->finally_body, varname, exclude)) return 1;
    if (s->children) {
        for (int i = 0; i < s->n_children; i++) {
            if (var_used_in_tree(s->children[i], varname, exclude)) return 1;
        }
    }
    return 0;
}

/* =========================================================
 * Post-processing: clean up statements
 * - Remove assignments to <ret> (compiler-internal)
 * - Convert "return <ret>;" to "return;" 
 * - Strip extra parens from return expressions
 * ========================================================= */
static int is_internal_var(const char *name) {
    if (!name) return 0;
    /* Internal compiler variables (stored as built-in atoms) */
    if (strcmp(name, "<ret>") == 0) return 1;
    if (strcmp(name, "<var>") == 0) return 1;
    if (strcmp(name, "<arg_var>") == 0) return 1;
    if (strcmp(name, "<with>") == 0) return 1;
    if (strcmp(name, "<home_object>") == 0) return 1;
    if (strcmp(name, "<active_func>") == 0) return 1;
    if (strcmp(name, "<class_fields_init>") == 0) return 1;
    if (strcmp(name, "<brand>") == 0) return 1;
    if (strcmp(name, "<eval>") == 0) return 1;
    /* New placeholder names (JS-valid but internal) */
    if (strcmp(name, "_catch") == 0) return 1;
    if (strcmp(name, "_unknown") == 0) return 1;
    if (strcmp(name, "_iter") == 0) return 1;
    if (strcmp(name, "_iter_val") == 0) return 1;
    if (strcmp(name, "_iter_done") == 0) return 1;
    if (strcmp(name, "_iter_next") == 0) return 1;
    if (strcmp(name, "_iter_catch") == 0) return 1;
    return 0;
}

/* Check if a name is a JS reserved word that can't be used as a variable name */
static int is_reserved_word(const char *name) {
    if (!name) return 0;
    static const char *reserved[] = {
        "this", "true", "false", "null", "undefined", "new", "delete",
        "typeof", "void", "in", "instanceof", "var", "let", "const",
        "function", "return", "if", "else", "for", "while", "do",
        "break", "continue", "switch", "case", "default", "throw",
        "try", "catch", "finally", "class", "extends", "super",
        "import", "export", "yield", "await", "async", "static",
        NULL
    };
    for (int i = 0; reserved[i]; i++) {
        if (strcmp(name, reserved[i]) == 0) return 1;
    }
    return 0;
}

static void cleanup_statements(ir_stmt_t *s);
static void simplify_booleans(ir_stmt_t *s);
static void simplify_index_access(ir_stmt_t *s);

/* Simplify !![] -> true and ![] -> false in all expression fields */
static void simplify_booleans(ir_stmt_t *s) {
    if (!s) return;
    char **fields[] = { &s->expr, &s->cond, &s->rhs, &s->lvalue, NULL };
    for (int fi = 0; fields[fi] != NULL; fi++) {
        char *expr = *fields[fi];
        if (!expr) continue;
        char *p = expr;
        int n_true = 0, n_false = 0;
        while (*p) {
            if (strncmp(p, "!![]", 4) == 0) { n_true++; p += 4; }
            else if (strncmp(p, "![]", 3) == 0) { n_false++; p += 3; }
            else p++;
        }
        if (n_true > 0 || n_false > 0) {
            size_t oldlen = strlen(expr);
            size_t newlen = oldlen + n_false * 2;
            char *result = xmalloc(newlen + 1);
            char *src = expr;
            char *dst = result;
            while (*src) {
                if (strncmp(src, "!![]", 4) == 0) {
                    memcpy(dst, "true", 4);
                    dst += 4; src += 4;
                } else if (strncmp(src, "![]", 3) == 0) {
                    memcpy(dst, "false", 5);
                    dst += 5; src += 3;
                } else {
                    *dst++ = *src++;
                }
            }
            *dst = '\0';
            free(expr);
            *fields[fi] = result;
        }
    }
}

/* Simplify obj["valid_ident"] -> obj.valid_ident in all expression fields.
 * This is safe because JS treats obj.foo and obj["foo"] identically
 * when foo is a valid identifier.
 * CRITICAL: Only convert when [ is preceded by an expression-ending char
 * (identifier, ), ]) to avoid breaking array literals like ["pointer"]. */
static void simplify_index_access(ir_stmt_t *s) {
    if (!s) return;
    char **fields[] = { &s->expr, &s->cond, &s->rhs, &s->lvalue, NULL };
    for (int fi = 0; fields[fi] != NULL; fi++) {
        char *expr = *fields[fi];
        if (!expr || !*expr) continue;
        /* Scan for ["..."] patterns where ... is a valid identifier */
        int replacements = 0;
        char *p = expr;
        while ((p = strstr(p, "[\"")) != NULL) {
            char *start = p;
            p += 2; /* skip [" */
            /* Check preceding char: must be expression-ending */
            char before = start > expr ? start[-1] : '\0';
            int prec_ok = (isalnum((unsigned char)before) || before == '_' ||
                           before == '$' || before == ')' || before == ']');
            if (!prec_ok) {
                continue; /* skip - likely array literal */
            }
            /* Read identifier */
            if (*p && (isalpha((unsigned char)*p) || *p == '_' || *p == '$')) {
                p++;
                while (*p && (isalnum((unsigned char)*p) || *p == '_' || *p == '$'))
                    p++;
                /* Check for closing "] */
                if (p[0] == '"' && p[1] == ']') {
                    replacements++;
                    p += 2;
                }
            }
        }
        if (replacements > 0) {
            size_t oldlen = strlen(expr);
            size_t newlen = oldlen - replacements * 2;
            char *result = xmalloc(newlen + 1);
            char *src = expr;
            char *dst = result;
            while (*src) {
                if (src[0] == '[' && src[1] == '"') {
                    /* Check preceding char in the OUTPUT */
                    char before = dst > result ? dst[-1] : '\0';
                    int prec_ok = (isalnum((unsigned char)before) || before == '_' ||
                                   before == '$' || before == ')' || before == ']');
                    if (prec_ok) {
                        /* Check if this is a valid identifier */
                        char *id = src + 2;
                        char *q = id;
                        if (*q && (isalpha((unsigned char)*q) || *q == '_' || *q == '$')) {
                            q++;
                            while (*q && (isalnum((unsigned char)*q) || *q == '_' || *q == '$'))
                                q++;
                            if (q[0] == '"' && q[1] == ']') {
                                /* Replace ["ident"] with .ident */
                                *dst++ = '.';
                                memcpy(dst, id, q - id);
                                dst += q - id;
                                src = q + 2;
                                continue;
                            }
                        }
                    }
                }
                *dst++ = *src++;
            }
            *dst = '\0';
            free(expr);
            *fields[fi] = result;
        }
    }
}

static void cleanup_statements(ir_stmt_t *s) {
    if (!s) return;

    /* Simplify boolean expressions FIRST (before any type-specific handling) */
    simplify_booleans(s);
    /* Simplify obj["valid_ident"] -> obj.valid_ident */
    simplify_index_access(s);

    if (s->kind == IR_STMT_BLOCK) {
        /* Filter out internal variable assignments, but keep the RHS
         * as an expression statement if it has side effects. */
        int write_idx = 0;
        for (int i = 0; i < s->n_children; i++) {
            ir_stmt_t *child = s->children[i];
            int remove = 0;

            /* Remove assignments to internal/reserved variables.
             * NOTE: Don't remove assignments to obj.field (like arr.push = fn)
             * - these are legitimate method assignments. */
            if (child->kind == IR_STMT_ASSIGN && child->lvalue &&
                (is_internal_var(child->lvalue) || is_reserved_word(child->lvalue))) {
                /* Instead of removing, convert to expression statement if RHS has side effects */
                if (child->rhs) {
                    int has_side_effects = 0;
                    if (strchr(child->rhs, '(')) has_side_effects = 1;
                    if (strstr(child->rhs, "++") || strstr(child->rhs, "--")) has_side_effects = 1;
                    if (has_side_effects && !is_internal_var(child->rhs) &&
                        !strstr(child->rhs, "home_object") &&
                        !strstr(child->rhs, "<active_func>") &&
                        !strstr(child->rhs, "new.target")) {
                        free(child->lvalue);
                        child->lvalue = NULL;
                        char *expr = child->rhs;
                        child->rhs = NULL;
                        child->kind = IR_STMT_EXPR;
                        child->expr = expr;
                    } else {
                        remove = 1;
                    }
                } else {
                    remove = 1;
                }
            }

            /* Remove declarations of internal/reserved variables */
            if (child->kind == IR_STMT_DECL && child->lvalue &&
                (is_internal_var(child->lvalue) || is_reserved_word(child->lvalue) ||
                 strchr(child->lvalue, '.') != NULL)) {
                remove = 1;
            }
            /* Remove assignments/decls with <catch> as RHS */
            if ((child->kind == IR_STMT_ASSIGN || child->kind == IR_STMT_DECL) &&
                child->rhs && (strcmp(child->rhs, "_catch") == 0 ||
                               strcmp(child->rhs, "_unknown") == 0 ||
                               strcmp(child->rhs, "_iter") == 0 ||
                               strcmp(child->rhs, "_iter_val") == 0 ||
                               strcmp(child->rhs, "_iter_done") == 0 ||
                               strcmp(child->rhs, "_iter_next") == 0 ||
                               strcmp(child->rhs, "_iter_catch") == 0)) {
                remove = 1;
            }

            /* Remove expression statements that are calls to internal variables
             * (e.g., <class_fields_init>()) */
            if (child->kind == IR_STMT_EXPR && child->expr) {
                /* Check if it's a call to an internal variable */
                if (strstr(child->expr, "<class_fields_init>") ||
                    strstr(child->expr, "<brand>")) {
                    remove = 1;
                }
                /* Remove bare special values */
                if (strcmp(child->expr, "home_object") == 0 ||
                    strcmp(child->expr, "<active_func>") == 0 ||
                    strcmp(child->expr, "new.target") == 0 ||
                    strcmp(child->expr, "_catch") == 0 ||
                    strcmp(child->expr, "_unknown") == 0) {
                    remove = 1;
                }
                /* Remove raw comment statements (/* ... *\/) */
                if (child->expr[0] == '/' && child->expr[1] == '*') {
                    remove = 1;
                }
                /* Remove "throw undefined" (rethrow placeholder) */
                if (strcmp(child->expr, "undefined") == 0 &&
                    child->kind == IR_STMT_EXPR) {
                    remove = 1;
                }
            }

            /* Remove declarations with undefined or <unknown> as RHS.
             * CRITICAL: const without initializer is SyntaxError in JS.
             * If const has no RHS, convert to var (which allows no init). */
            if (child->kind == IR_STMT_DECL && child->rhs &&
                (strcmp(child->rhs, "undefined") == 0 ||
                 strcmp(child->rhs, "_unknown") == 0)) {
                free(child->rhs);
                child->rhs = NULL;
                /* const without init is invalid JS - use var instead */
                child->decl_kind = 0;
            }
            /* Also fix const declarations without any RHS at all */
            if (child->kind == IR_STMT_DECL && !child->rhs && child->decl_kind == 2) {
                child->decl_kind = 0; /* var instead of const */
            }

            /* Only remove assignments where lvalue is purely numeric (e.g., "1992146687").
             * Do NOT remove lvalues starting with digit if they contain dots/brackets
             * (e.g., "4.a" might be a valid Frida pattern). */
            if (child->kind == IR_STMT_ASSIGN && child->lvalue && child->lvalue[0]) {
                if (isdigit((unsigned char)child->lvalue[0])) {
                    int all_digits = 1;
                    for (const char *p = child->lvalue; *p; p++) {
                        if (!isdigit((unsigned char)*p)) { all_digits = 0; break; }
                    }
                    if (all_digits) remove = 1;
                }
            }

            /* Only remove expression statements that are bare numeric literals
             * with no dots, calls, or side effects. Keep strings and identifiers. */
            if (child->kind == IR_STMT_EXPR && child->expr && child->expr[0]) {
                const char *e = child->expr;
                /* Only remove pure numeric expressions (no letters, no dots, no parens) */
                int is_pure_number = 1;
                for (const char *p = e; *p; p++) {
                    if (!isdigit((unsigned char)*p) && *p != '-') {
                        is_pure_number = 0;
                        break;
                    }
                }
                if (is_pure_number && strlen(e) > 0) remove = 1;
            }

            /* For declarations with _atom_oob_ in RHS: keep as bare var.
             * For assignments with _atom_oob_: keep but sanitize. */
            if ((child->kind == IR_STMT_ASSIGN || child->kind == IR_STMT_DECL) &&
                (child->rhs && strstr(child->rhs, "_atom_oob_"))) {
                if (child->kind == IR_STMT_DECL) {
                    free(child->rhs);
                    child->rhs = NULL;
                    child->decl_kind = 0;
                } else {
                    /* Keep assignment but replace _atom_oob_ RHS with undefined */
                    free(child->rhs);
                    child->rhs = xstrdup("undefined");
                }
            }

            /* For expression statements with _atom_oob_: replace with undefined, don't remove */
            if (child->kind == IR_STMT_EXPR && child->expr &&
                strstr(child->expr, "_atom_oob_")) {
                free(child->expr);
                child->expr = xstrdup("undefined");
            }

            /* For return statements with _atom_oob_: convert to bare return */
            if (child->kind == IR_STMT_RETURN && child->expr &&
                (strstr(child->expr, "_atom_oob_") ||
                 strcmp(child->expr, "_unknown") == 0)) {
                free(child->expr);
                child->expr = NULL;
            }

            /* Remove "throw undefined" (rethrow from catch) */
            if (child->kind == IR_STMT_THROW && child->expr &&
                (strcmp(child->expr, "undefined") == 0 ||
                 strcmp(child->expr, "_catch") == 0)) {
                remove = 1;
            }

            /* Remove "goto L0xxx" (unresolved jumps from try/catch) */
            if (child->kind == IR_STMT_RAW && child->expr &&
                strncmp(child->expr, "goto L", 6) == 0) {
                remove = 1;
            }

            /* Remove "return <unknown>" (from nip_catch pattern) */
            if (child->kind == IR_STMT_RETURN && child->expr &&
                strcmp(child->expr, "_unknown") == 0) {
                remove = 1;
            }

            if (remove) {
                ir_stmt_free(child);
            } else {
                cleanup_statements(child);
                /* Remove duplicate expression at start of if-then block that
                 * matches the if condition. Pattern: if (cond) { cond; ... }
                 * Caused by dup before if_false8 in bytecode. */
                if (child->kind == IR_STMT_IF && child->cond && child->body &&
                    child->body->kind == IR_STMT_BLOCK &&
                    child->body->n_children > 0) {
                    ir_stmt_t *first = child->body->children[0];
                    if (first->kind == IR_STMT_EXPR && first->expr) {
                        char *cond_copy = xstrdup(child->cond);
                        strip_outer_parens(cond_copy);
                        char *expr_copy = xstrdup(first->expr);
                        strip_outer_parens(expr_copy);
                        if (strcmp(cond_copy, expr_copy) == 0) {
                            ir_stmt_free(first);
                            for (int j = 1; j < child->body->n_children; j++)
                                child->body->children[j - 1] = child->body->children[j];
                            child->body->n_children--;
                        }
                        free(cond_copy);
                        free(expr_copy);
                    }
                }
                /* Remove empty if blocks (if (false) {} or if with empty body) */
                if (child->kind == IR_STMT_IF) {
                    int body_empty = (!child->body ||
                        (child->body->kind == IR_STMT_BLOCK && child->body->n_children == 0));
                    int else_empty = (!child->else_body ||
                        (child->else_body->kind == IR_STMT_BLOCK && child->else_body->n_children == 0));
                    if (body_empty && else_empty) {
                        ir_stmt_free(child);
                        continue;
                    }
                    /* Remove if with TRULY dead condition only:
                     * - undefined (standalone, no comparison)
                     * - _unknown
                     * - false
                     * NOTE: Do NOT remove "undefined === ..." branches!
                     * These are switch/case patterns where the variable was lost.
                     * Better to keep them visible (even if broken) than to lose them. */
                    if (child->cond &&
                        (strcmp(child->cond, "undefined") == 0 ||
                         strcmp(child->cond, "_unknown") == 0 ||
                         strcmp(child->cond, "false") == 0)) {
                        /* Keep else body if present, else remove entirely */
                        if (child->else_body && !else_empty) {
                            /* Extract else body statements inline */
                            ir_stmt_t *eb = child->else_body;
                            if (eb->kind == IR_STMT_BLOCK) {
                                for (int j = 0; j < eb->n_children; j++)
                                    s->children[write_idx++] = eb->children[j];
                                eb->n_children = 0;
                            }
                            ir_stmt_free(child->else_body);
                            child->else_body = NULL;
                            ir_stmt_free(child);
                            continue;
                        } else {
                            ir_stmt_free(child);
                            continue;
                        }
                    }
                    /* If body is empty but else has content, swap and negate */
                    if (body_empty && !else_empty) {
                        ir_stmt_t *tmp = child->body;
                        child->body = child->else_body;
                        child->else_body = tmp;
                        /* Negate condition */
                        sbuf_t sb; sb_init(&sb);
                        sb_putc(&sb, '!');
                        sb_putc(&sb, '(');
                        sb_puts(&sb, child->cond ? child->cond : "true");
                        sb_putc(&sb, ')');
                        free(child->cond);
                        child->cond = sb.buf;
                    }
                }
                /* Remove empty expression statements */
                if (child->kind == IR_STMT_EXPR && (!child->expr || !*child->expr)) {
                    ir_stmt_free(child);
                    continue;
                }
                s->children[write_idx++] = child;
            }
        }
        s->n_children = write_idx;

        /* Second pass: remove standalone expression statements that duplicate
         * the immediately preceding if's condition.
         * Pattern: if (cond) { ... } cond;  ->  if (cond) { ... }
         * Caused by dup before if_false8 where the duplicate value leaks
         * to the next block as an expression statement. The dup'd value
         * has no side effects (condition was already evaluated for the if). */
        {
            int write2 = 0;
            for (int j = 0; j < s->n_children; j++) {
                ir_stmt_t *child = s->children[j];
                if (child->kind == IR_STMT_EXPR && child->expr && write2 > 0) {
                    ir_stmt_t *prev = s->children[write2 - 1];
                    if (prev->kind == IR_STMT_IF && prev->cond) {
                        char *cond_copy = xstrdup(prev->cond);
                        strip_outer_parens(cond_copy);
                        char *expr_copy = xstrdup(child->expr);
                        strip_outer_parens(expr_copy);
                        int is_dup = (strcmp(cond_copy, expr_copy) == 0);
                        free(cond_copy);
                        free(expr_copy);
                        if (is_dup) {
                            ir_stmt_free(child);
                            continue;
                        }
                    }
                }
                s->children[write2++] = child;
            }
            s->n_children = write2;
        }

        /* Third pass: remove unused bare var declarations.
         * Pattern: "var X;" (no initializer) where X is never referenced
         * anywhere else in this block or its sub-blocks. These come from
         * catch variables and hoisted vars that lost their RHS (internal vars). */
        {
            int write3 = 0;
            for (int j = 0; j < s->n_children; j++) {
                ir_stmt_t *child = s->children[j];
                if (child->kind == IR_STMT_DECL && !child->rhs &&
                    child->lvalue && child->decl_kind == 0) {
                    /* Check if varname is used anywhere in this block
                     * (excluding the declaration itself) */
                    const char *varname = child->lvalue;
                    int used = 0;
                    for (int k = 0; k < s->n_children; k++) {
                        if (s->children[k] == child) continue;
                        if (var_used_in_tree(s->children[k], varname, NULL)) {
                            used = 1;
                            break;
                        }
                    }
                    if (!used) {
                        ir_stmt_free(child);
                        continue;
                    }
                }
                s->children[write3++] = child;
            }
            s->n_children = write3;
        }
        return;
    }

    /* Recurse into if/while/etc to clean up empty blocks */
    if (s->kind == IR_STMT_IF) {
        if (s->body) cleanup_statements(s->body);
        if (s->else_body) cleanup_statements(s->else_body);
        /* Remove dead code after return/throw/break/continue inside if body */
        if (s->body && s->body->kind == IR_STMT_BLOCK) {
            int write_idx = 0;
            int seen_terminator = 0;
            for (int j = 0; j < s->body->n_children; j++) {
                ir_stmt_t *child = s->body->children[j];
                if (seen_terminator) {
                    ir_stmt_free(child);
                    continue;
                }
                if (child->kind == IR_STMT_RETURN || child->kind == IR_STMT_THROW ||
                    child->kind == IR_STMT_BREAK || child->kind == IR_STMT_CONTINUE) {
                    seen_terminator = 1;
                }
                s->body->children[write_idx++] = child;
            }
            s->body->n_children = write_idx;
        }
        /* Same for else body */
        if (s->else_body && s->else_body->kind == IR_STMT_BLOCK) {
            int write_idx = 0;
            int seen_terminator = 0;
            for (int j = 0; j < s->else_body->n_children; j++) {
                ir_stmt_t *child = s->else_body->children[j];
                if (seen_terminator) {
                    ir_stmt_free(child);
                    continue;
                }
                if (child->kind == IR_STMT_RETURN || child->kind == IR_STMT_THROW ||
                    child->kind == IR_STMT_BREAK || child->kind == IR_STMT_CONTINUE) {
                    seen_terminator = 1;
                }
                s->else_body->children[write_idx++] = child;
            }
            s->else_body->n_children = write_idx;
        }
        /* If condition is internal and body is empty, mark for removal */
        if (s->cond && is_internal_var(s->cond)) {
            if ((!s->body || (s->body->kind == IR_STMT_BLOCK && s->body->n_children == 0)) &&
                (!s->else_body || (s->else_body->kind == IR_STMT_BLOCK && s->else_body->n_children == 0))) {
                /* Replace with empty block */
                if (s->body) { ir_stmt_free(s->body); s->body = NULL; }
                if (s->else_body) { ir_stmt_free(s->else_body); s->else_body = NULL; }
                free(s->cond);
                s->cond = xstrdup("false");
            }
        }
        /* If condition contains internal iterator placeholders (_iter_*),
         * remove the entire if block (it's dead code from for-of/for-in) */
        if (s->cond) {
            int has_iter = 0;
            if (strstr(s->cond, "_iter_catch") || strstr(s->cond, "_iter_done") ||
                strstr(s->cond, "_iter_next") || strstr(s->cond, "_iter_val") ||
                (strstr(s->cond, "_iter") && !strstr(s->cond, "_iterator"))) {
                has_iter = 1;
            }
            if (has_iter) {
                /* Check if body is just continue/break (common pattern) */
                if (s->body && s->body->kind == IR_STMT_BLOCK) {
                    if (s->body->n_children == 1 &&
                        (s->body->children[0]->kind == IR_STMT_CONTINUE ||
                         s->body->children[0]->kind == IR_STMT_BREAK)) {
                        /* Remove the entire if - it's iterator cleanup */
                        if (s->body) { ir_stmt_free(s->body); s->body = NULL; }
                        if (s->else_body) { ir_stmt_free(s->else_body); s->else_body = NULL; }
                        free(s->cond);
                        s->cond = xstrdup("false");
                    }
                }
            }
        }
        return;
    }
    if (s->kind == IR_STMT_WHILE || s->kind == IR_STMT_DO_WHILE) {
        if (s->body) cleanup_statements(s->body);
        return;
    }

    /* Convert "return <ret>;" to "return;" */
    if (s->kind == IR_STMT_RETURN && s->expr && is_internal_var(s->expr)) {
        free(s->expr);
        s->expr = NULL;
    }
    /* Strip outer parens from return expressions */
    if (s->kind == IR_STMT_RETURN && s->expr) {
        strip_outer_parens(s->expr);
    }
    if (s->kind == IR_STMT_THROW && s->expr) {
        strip_outer_parens(s->expr);
    }
    if (s->kind == IR_STMT_EXPR && s->expr) {
        strip_outer_parens(s->expr);
    }
    /* Recurse into sub-statements */
    if (s->body) cleanup_statements(s->body);
    if (s->else_body) cleanup_statements(s->else_body);
    if (s->init) cleanup_statements(s->init);
    if (s->update) cleanup_statements(s->update);
}

/* =========================================================
 * Post-processing: split "return <call>()" into "<call>(); return;"
 * This produces cleaner output for top-level statements that end with
 * a function call (very common in QuickJS bytecode).
 * ========================================================= */
static void split_return_calls(ir_stmt_t *s) {
    if (!s) return;
    if (s->kind == IR_STMT_BLOCK) {
        /* We may need to expand the array, so build a new one */
        stmt_list_t new_list; sl_init(&new_list);
        for (int i = 0; i < s->n_children; i++) {
            ir_stmt_t *child = s->children[i];
            /* Recurse first */
            split_return_calls(child);
            /* Check if this is "return <call>()" */
            if (child->kind == IR_STMT_RETURN && child->expr &&
                !is_internal_var(child->expr) && child->expr[0] != '\0') {
                /* Check if expr is ENTIRELY a function call (not a binary op ending in call).
                 * A function call looks like: identifier(...), obj.method(...), new X(...), super(...)
                 * We need to verify there are no top-level binary operators. */
                char *expr = child->expr;
                size_t len = strlen(expr);
                int is_call = 0;
                if (len > 2 && expr[len-1] == ')') {
                    /* Check if there's a top-level operator (outside all parens) */
                    int depth = 0;
                    int has_top_level_op = 0;
                    for (size_t j = 0; j < len; j++) {
                        if (expr[j] == '(') depth++;
                        else if (expr[j] == ')') depth--;
                        else if (depth == 0) {
                            /* At top level - check for binary operators */
                            /* Skip the first token (could be 'new', 'await', etc.) */
                            if (j > 0 && expr[j] == ' ' && expr[j+1] != '\0') {
                                /* Check if this is a binary operator: + - * / % etc */
                                char next = expr[j+1];
                                char next2 = expr[j+2];
                                /* " && ", " || ", " + " etc are binary ops */
                                if (next == '+' || next == '-' || next == '*' || next == '/' ||
                                    next == '%' || next == '&' || next == '|' || next == '^' ||
                                    next == '<' || next == '>' || next == '=' || next == '!') {
                                    /* But not "=>" (arrow) or unary */
                                    if (!(next == '=' && next2 == '>')) {
                                        has_top_level_op = 1;
                                        break;
                                    }
                                }
                                /* Check for word operators: instanceof, in */
                                if (j + 12 < len && strncmp(expr + j + 1, "instanceof ", 11) == 0) {
                                    has_top_level_op = 1;
                                    break;
                                }
                                if (j + 4 < len && strncmp(expr + j + 1, "in ", 3) == 0) {
                                    has_top_level_op = 1;
                                    break;
                                }
                            }
                        }
                    }
                    if (!has_top_level_op) {
                        /* No top-level binary op - check if it starts with a call pattern */
                        /* Patterns: identifier(, obj.method(, new X(, super(, await expr( */
                        if (strncmp(expr, "new ", 4) == 0) is_call = 1;
                        else if (strncmp(expr, "super(", 6) == 0) is_call = 1;
                        else if (strncmp(expr, "await ", 6) == 0) is_call = 1;
                        else {
                            /* Check if it's identifier(...) or obj.prop(...) */
                            char *paren = strchr(expr, '(');
                            if (paren && paren == expr + len - 1) {
                                /* expr is just "identifier(" - shouldn't happen */
                            } else if (paren) {
                                /* Check that everything before ( is a valid callee */
                                /* (identifier or obj.method, no spaces except in "new X") */
                                int valid = 1;
                                for (size_t j = 0; j < (size_t)(paren - expr); j++) {
                                    char c = expr[j];
                                    if (!(isalnum((unsigned char)c) || c == '_' || c == '$' || c == '.')) {
                                        valid = 0;
                                        break;
                                    }
                                }
                                if (valid) is_call = 1;
                            }
                        }
                    }
                }
                if (is_call) {
                    /* Split: push expr as statement, then bare return.
                     * stmt_expr takes ownership of the string. */
                    char *expr_copy = xstrdup(child->expr);
                    sl_push(&new_list, stmt_expr(expr_copy));
                    /* Do NOT free expr_copy - ownership transferred to statement */
                    /* Change return to bare return */
                    free(child->expr);
                    child->expr = NULL;
                }
            }
            sl_push(&new_list, child);
        }
        /* Replace children */
        free(s->children);
        s->children = new_list.items;
        s->n_children = new_list.count;
        return;
    }
    /* Recurse into sub-statements */
    if (s->body) split_return_calls(s->body);
    if (s->else_body) split_return_calls(s->else_body);
    if (s->init) split_return_calls(s->init);
    if (s->update) split_return_calls(s->update);
}

/* =========================================================
 * Post-processing: convert while loops to for loops
 *
 * Pattern: init_stmt; while(cond) { body; update_stmt; }
 * Becomes: for(init_stmt; cond; update_stmt) { body; }
 *
 * The init_stmt must be a simple assignment or declaration.
 * The update_stmt must be the LAST statement in the body and be
 * a simple increment, compound assignment, or assignment.
 * ========================================================= */

/* Extract the variable name from a statement (for matching init/update) */
static const char *stmt_var_name(ir_stmt_t *s) {
    if (!s) return NULL;
    if (s->kind == IR_STMT_ASSIGN || s->kind == IR_STMT_DECL || s->kind == IR_STMT_COMPOUND_ASSIGN)
        return s->lvalue;
    if (s->kind == IR_STMT_EXPR && s->expr) {
        /* Check for "var++" or "var--" pattern */
        size_t len = strlen(s->expr);
        if (len >= 3) {
            /* Find ++ or -- at the end */
            if (strcmp(s->expr + len - 2, "++") == 0 || strcmp(s->expr + len - 2, "--") == 0) {
                /* Extract variable name (everything before ++/--) */
                /* We need to return a pointer, but this is tricky since we'd need to modify the string.
                 * For simplicity, just check if it's a simple identifier. */
                /* Return a pointer to the start of the expression - the caller will compare */
                return s->expr;
            }
        }
    }
    return NULL;
}

/* Check if an expression is "var++" or "var--" matching the given var name */
static int is_inc_dec_of(ir_stmt_t *s, const char *varname) {
    if (!s || s->kind != IR_STMT_EXPR || !s->expr) return 0;
    size_t vlen = strlen(varname);
    size_t elen = strlen(s->expr);
    if (elen != vlen + 2) return 0;
    if (strncmp(s->expr, varname, vlen) != 0) return 0;
    return (s->expr[vlen] == '+' && s->expr[vlen+1] == '+') ||
           (s->expr[vlen] == '-' && s->expr[vlen+1] == '-');
}

static void convert_while_to_for(ir_stmt_t *s) {
    if (!s) return;

    /* Recurse into sub-statements first */
    if (s->body) convert_while_to_for(s->body);
    if (s->else_body) convert_while_to_for(s->else_body);
    if (s->init) convert_while_to_for(s->init);
    if (s->update) convert_while_to_for(s->update);

    if (s->kind != IR_STMT_BLOCK) return;

    /* Build a new children list, converting while->for where possible */
    stmt_list_t new_list; sl_init(&new_list);

    for (int i = 0; i < s->n_children; i++) {
        ir_stmt_t *child = s->children[i];

        /* Recurse into non-while children */
        if (child->kind != IR_STMT_WHILE) {
            convert_while_to_for(child);
            sl_push(&new_list, child);
            continue;
        }

        /* Found a while loop - recurse into its body first */
        if (child->body) convert_while_to_for(child->body);

        /* Check if we can convert to a for loop:
         * Need: (1) previous statement in new_list is an init,
         *       (2) last statement in body is an update to the same var */
        if (new_list.count == 0) {
            sl_push(&new_list, child);
            continue;
        }

        ir_stmt_t *prev = new_list.items[new_list.count - 1];
        if (prev->kind != IR_STMT_DECL && prev->kind != IR_STMT_ASSIGN) {
            sl_push(&new_list, child);
            continue;
        }
        if (!prev->lvalue) {
            sl_push(&new_list, child);
            continue;
        }

        /* Check body */
        if (!child->body || child->body->kind != IR_STMT_BLOCK ||
            child->body->n_children == 0) {
            sl_push(&new_list, child);
            continue;
        }

        ir_stmt_t *body_block = child->body;
        ir_stmt_t *last = body_block->children[body_block->n_children - 1];
        const char *init_var = prev->lvalue;

        int update_matches = 0;
        if (is_inc_dec_of(last, init_var)) {
            update_matches = 1;
        } else if (last->kind == IR_STMT_COMPOUND_ASSIGN && last->lvalue &&
                   strcmp(last->lvalue, init_var) == 0) {
            update_matches = 1;
        } else if (last->kind == IR_STMT_ASSIGN && last->lvalue &&
                   strcmp(last->lvalue, init_var) == 0) {
            update_matches = 1;
        }

        if (!update_matches) {
            sl_push(&new_list, child);
            continue;
        }

        /* Convert to for loop! */
        ir_stmt_t *init_stmt = prev;  /* take ownership */
        new_list.count--;

        /* Build new body without the update statement */
        ir_stmt_t *new_body = stmt_block(NULL);
        if (body_block->n_children > 1) {
            new_body->children = xcalloc(body_block->n_children - 1, sizeof(ir_stmt_t *));
            for (int j = 0; j < body_block->n_children - 1; j++) {
                new_body->children[j] = body_block->children[j];
            }
            new_body->n_children = body_block->n_children - 1;
        }

        ir_stmt_t *update_stmt = last;

        /* Detach body_block contents */
        body_block->n_children = 0;
        body_block->children = NULL;

        /* Build the for statement */
        char *cond_str = child->cond ? strip_outer_parens(xstrdup(child->cond)) : xstrdup("");
        ir_stmt_t *for_stmt = stmt_for(init_stmt, cond_str, update_stmt, new_body);

        /* Free the old while (cond string, empty body, struct) */
        free(child->cond);
        child->cond = NULL;
        ir_stmt_free(child->body);
        child->body = NULL;
        ir_stmt_free(child);

        sl_push(&new_list, for_stmt);
    }

    /* Replace children with new list */
    free(s->children);
    s->children = new_list.items;
    s->n_children = new_list.count;
}

    /* Close any open object literals in statement expressions */
static void close_open_objects(ir_stmt_t *s) {
    if (!s) return;
    /* Check and close open object literals in expr fields */
    #define CLOSE_OBJ(expr) \
        do { \
            if (expr && expr[0] == '{' && expr[strlen(expr)-1] != '}') { \
                size_t _len = strlen(expr); \
                char *_new = xmalloc(_len + 2); \
                memcpy(_new, expr, _len); \
                _new[_len] = '}'; \
                _new[_len+1] = '\0'; \
                free(expr); \
                expr = _new; \
            } \
        } while(0)

    CLOSE_OBJ(s->expr);
    CLOSE_OBJ(s->rhs);
    CLOSE_OBJ(s->lvalue);
    CLOSE_OBJ(s->cond);

    if (s->body) close_open_objects(s->body);
    if (s->else_body) close_open_objects(s->else_body);
    if (s->init) close_open_objects(s->init);
    if (s->update) close_open_objects(s->update);
    if (s->children) {
        for (int i = 0; i < s->n_children; i++)
            close_open_objects(s->children[i]);
    }
    #undef CLOSE_OBJ
}

/* =========================================================
 * Top-level function decompiler
 * ========================================================= */
ir_stmt_t *ir_decompile_function(qjs_reader_t *r, qjs_function_t *fn, int cpool_base) {
    ir_function_t *ir = ir_build(r, fn);
    if (!ir || ir->count == 0) {
        ir_free(ir);
        return NULL;
    }

    decomp_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.r = r;
    ctx.fn = fn;
    ctx.ir = ir;
    ctx.cpool_base = cpool_base;
    ctx.loop_depth = 0;
    vs_init(&ctx.vs);

    ir_stmt_t *result = decompile_range_top(&ctx, 0, ir->count, 1);

    /* Post-process: hoist variable declarations */
    if (result) {
        hoist_declarations(result, fn, r, ir);
        /* Clean up internal variables and simplify expressions */
        cleanup_statements(result);
        /* NOTE: split_return_calls removed - it was incorrectly splitting
         * legitimate "return func()" statements. The cleanup already handles
         * the <ret> = call() pattern correctly. */
        /* split_return_calls(result); */
        /* Convert while loops to for loops where pattern matches */
        convert_while_to_for(result);
        /* Close any open object literals in expressions */
        close_open_objects(result);
        /* Remove trailing bare "return;" from top-level (eval) functions.
         * Also remove trailing "return undefined;" and "return _unknown;" */
        if (result && result->kind == IR_STMT_BLOCK && result->n_children > 0) {
            ir_stmt_t *last = result->children[result->n_children - 1];
            if (last->kind == IR_STMT_RETURN &&
                (!last->expr || !*last->expr ||
                 strcmp(last->expr, "undefined") == 0 ||
                 strcmp(last->expr, "_unknown") == 0)) {
                ir_stmt_free(last);
                result->n_children--;
            }
        }
        /* Remove duplicate returns: "return;" followed by "return expr;" */
        if (result && result->kind == IR_STMT_BLOCK) {
            int write_idx = 0;
            int seen_terminator = 0; /* Track if we've seen return/throw/break/continue */
            for (int j = 0; j < result->n_children; j++) {
                ir_stmt_t *child = result->children[j];
                /* If we've seen a terminator, remove all subsequent statements (dead code) */
                if (seen_terminator) {
                    ir_stmt_free(child);
                    continue;
                }
                /* Check if previous was bare return and this is also a return */
                if (write_idx > 0) {
                    ir_stmt_t *prev = result->children[write_idx - 1];
                    if (prev->kind == IR_STMT_RETURN &&
                        (!prev->expr || !*prev->expr) &&
                        child->kind == IR_STMT_RETURN) {
                        /* Remove the bare return, keep this one */
                        ir_stmt_free(prev);
                        write_idx--;
                    }
                }
                /* Mark terminators */
                if (child->kind == IR_STMT_RETURN || child->kind == IR_STMT_THROW ||
                    child->kind == IR_STMT_BREAK || child->kind == IR_STMT_CONTINUE) {
                    seen_terminator = 1;
                }
                result->children[write_idx++] = child;
            }
            result->n_children = write_idx;
        }
    }

    vs_free(&ctx.vs);
    ir_free(ir);
    return result;
}

/* =========================================================
 * Strip outer parentheses from an expression (for cleaner conditions)
 * ========================================================= */
static char *strip_outer_parens(char *expr) {
    if (!expr || !*expr) return expr;
    /* Loop to strip multiple levels of parens */
    while (expr[0] == '(') {
        size_t len = strlen(expr);
        if (expr[len - 1] != ')') break;
        /* Check that the parens are matching (not e.g. (a) + (b)) */
        int depth = 0;
        int is_outer = 1;
        for (size_t i = 0; i < len; i++) {
            if (expr[i] == '(') depth++;
            else if (expr[i] == ')') {
                depth--;
                if (depth == 0 && i < len - 1) { is_outer = 0; break; }
            }
        }
        if (!is_outer) break;
        /* Strip first and last char */
        memmove(expr, expr + 1, len - 2);
        expr[len - 2] = '\0';
    }
    return expr;
}

/* =========================================================
 * Statement printer
 * ========================================================= */
static void print_stmt_list(FILE *out, ir_stmt_t **items, int n, int indent);

static void print_stmt(FILE *out, ir_stmt_t *s, int indent) {
    if (!s) return;
    /* For BLOCK, don't print indent here - children print their own */
    if (s->kind != IR_STMT_BLOCK) {
        put_indent(out, indent);
    }
    switch (s->kind) {
        case IR_STMT_EXPR:
            fprintf(out, "%s;\n", s->expr ? s->expr : "");
            break;
        case IR_STMT_ASSIGN:
            fprintf(out, "%s = %s;\n", s->lvalue ? s->lvalue : "", s->rhs ? s->rhs : "");
            break;
        case IR_STMT_COMPOUND_ASSIGN:
            fprintf(out, "%s %s %s;\n", s->lvalue ? s->lvalue : "", s->op ? s->op : "+=", s->rhs ? s->rhs : "");
            break;
        case IR_STMT_DECL: {
            const char *kw = (s->decl_kind == 2) ? "const" : (s->decl_kind == 1) ? "let" : "var";
            if (s->rhs)
                fprintf(out, "%s %s = %s;\n", kw, s->lvalue ? s->lvalue : "", s->rhs);
            else
                fprintf(out, "%s %s;\n", kw, s->lvalue ? s->lvalue : "");
            break;
        }
        case IR_STMT_RETURN:
            if (s->expr) fprintf(out, "return %s;\n", s->expr);
            else fprintf(out, "return;\n");
            break;
        case IR_STMT_THROW:
            fprintf(out, "throw %s;\n", s->expr ? s->expr : "");
            break;
        case IR_STMT_BREAK:
            fprintf(out, "break;\n");
            break;
        case IR_STMT_CONTINUE:
            fprintf(out, "continue;\n");
            break;
        case IR_STMT_IF: {
            char *cond = s->cond ? strip_outer_parens(xstrdup(s->cond)) : xstrdup("true");
            fprintf(out, "if (%s) {\n", cond);
            if (s->body) print_stmt(out, s->body, indent + 1);
            if (s->else_body) {
                put_indent(out, indent);
                fprintf(out, "} else {\n");
                print_stmt(out, s->else_body, indent + 1);
            }
            put_indent(out, indent);
            fprintf(out, "}\n");
            free(cond);
            break;
        }
        case IR_STMT_WHILE: {
            char *cond = s->cond ? strip_outer_parens(xstrdup(s->cond)) : xstrdup("true");
            fprintf(out, "while (%s) {\n", cond);
            if (s->body) print_stmt(out, s->body, indent + 1);
            put_indent(out, indent);
            fprintf(out, "}\n");
            free(cond);
            break;
        }
        case IR_STMT_DO_WHILE: {
            char *cond = s->cond ? strip_outer_parens(xstrdup(s->cond)) : xstrdup("true");
            fprintf(out, "do {\n");
            if (s->body) print_stmt(out, s->body, indent + 1);
            put_indent(out, indent);
            fprintf(out, "} while (%s);\n", cond);
            free(cond);
            break;
        }
        case IR_STMT_FOR: {
            /* Check if this is a for-of/for-in loop (no init, no update, cond contains " of " or " in ") */
            if (!s->init && !s->update && s->cond) {
                int has_of = (strstr(s->cond, " of ") != NULL);
                int has_in = (strstr(s->cond, " in ") != NULL);
                if (has_of || has_in) {
                    /* for-of/for-in: for (cond) { body } */
                    fprintf(out, "for (%s) {\n", s->cond);
                    if (s->body) print_stmt(out, s->body, indent + 1);
                    put_indent(out, indent);
                    fprintf(out, "}\n");
                    break;
                }
            }
            fprintf(out, "for (");
            if (s->init) {
                /* Print init inline (no newline) */
                /* This is a hack - we need an inline print */
                if (s->init->kind == IR_STMT_ASSIGN)
                    fprintf(out, "%s = %s", s->init->lvalue ? s->init->lvalue : "", s->init->rhs ? s->init->rhs : "");
                else if (s->init->kind == IR_STMT_DECL && s->init->rhs)
                    fprintf(out, "%s %s = %s",
                            s->init->decl_kind == 2 ? "const" : s->init->decl_kind == 1 ? "let" : "var",
                            s->init->lvalue ? s->init->lvalue : "",
                            s->init->rhs);
                else if (s->init->kind == IR_STMT_DECL)
                    fprintf(out, "%s %s",
                            s->init->decl_kind == 2 ? "const" : s->init->decl_kind == 1 ? "let" : "var",
                            s->init->lvalue ? s->init->lvalue : "");
                else if (s->init->expr)
                    fprintf(out, "%s", s->init->expr);
            }
            fprintf(out, "; %s; ", s->cond ? s->cond : "");
            if (s->update) {
                if (s->update->expr)
                    fprintf(out, "%s", s->update->expr);
                else if (s->update->kind == IR_STMT_ASSIGN)
                    fprintf(out, "%s = %s", s->update->lvalue ? s->update->lvalue : "", s->update->rhs ? s->update->rhs : "");
                else if (s->update->kind == IR_STMT_COMPOUND_ASSIGN)
                    fprintf(out, "%s %s %s", s->update->lvalue ? s->update->lvalue : "", s->update->op ? s->update->op : "", s->update->rhs ? s->update->rhs : "");
            }
            fprintf(out, ") {\n");
            if (s->body) print_stmt(out, s->body, indent + 1);
            put_indent(out, indent);
            fprintf(out, "}\n");
            break;
        }
        case IR_STMT_BLOCK: {
            print_stmt_list(out, s->children, s->n_children, indent);
            break;
        }
        case IR_STMT_LABEL:
            fprintf(out, "%s\n", s->label ? s->label : "");
            break;
        case IR_STMT_GOTO:
            fprintf(out, "goto %s;\n", s->label ? s->label : "");
            break;
        case IR_STMT_RAW:
            fprintf(out, "%s\n", s->expr ? s->expr : "");
            break;
        case IR_STMT_EMPTY:
            fprintf(out, ";\n");
            break;
        default:
            fprintf(out, "/* unknown stmt %d */\n", s->kind);
            break;
    }
}

static void print_stmt_list(FILE *out, ir_stmt_t **items, int n, int indent) {
    for (int i = 0; i < n; i++) {
        print_stmt(out, items[i], indent);
    }
}

void ir_stmt_print(FILE *out, ir_stmt_t *s, int indent) {
    print_stmt(out, s, indent);
}

/* =========================================================
 * Public API (replaces old decompile functions)
 * ========================================================= */
extern int g_cpool_counter;

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

    const char *name = qjs_atom_str(r, fn->func_name_atom);
    const char *kind = "function";
    if (fn->flags.func_kind == 1) kind = "function*";
    else if (fn->flags.func_kind == 2) kind = "async function";
    else if (fn->flags.func_kind == 3) kind = "async function*";

    /* Check if this is the top-level eval function (internal name <eval>) */
    int is_toplevel = (strcmp(name, "<eval>") == 0);

    /* Build arg list */
    sbuf_t args; sb_init(&args);
    int n_args = fn->arg_count;
    if (n_args > fn->vardefs_count) n_args = fn->vardefs_count;
    for (int i = 0; i < n_args; i++) {
        if (i > 0) sb_puts(&args, ", ");
        sb_puts(&args, qjs_atom_str(r, fn->vardefs[i].var_name_atom));
    }

    ir_stmt_t *body = ir_decompile_function(r, fn, cpool_base);

    if (is_toplevel) {
        /* For top-level eval, just print the body without the function wrapper */
        if (body) {
            print_stmt(out, body, indent);
            ir_stmt_free(body);
        }
        fprintf(out, "\n");
    } else {
        /* Generate a valid function name.
         * If the function name is a placeholder, invalid, or contains special chars,
         * generate a synthetic name based on the function index. */
        const char *display_name = name;
        char synth_name[64];
        int need_synth = 0;

        /* Check if name is empty */
        if (!name[0]) need_synth = 1;

        /* Check if name is a placeholder */
        if (strncmp(name, "_builtin_", 9) == 0 || strncmp(name, "_atom_", 6) == 0)
            need_synth = 1;

        /* Check if name contains invalid chars for JS identifier */
        if (!need_synth && name[0]) {
            /* First char must be letter, _ or $ */
            if (!(isalpha((unsigned char)name[0]) || name[0] == '_' || name[0] == '$'))
                need_synth = 1;
            /* Rest must be alphanumeric, _, $ or . (for property names) */
            if (!need_synth) {
                for (const char *p = name + 1; *p; p++) {
                    if (!(isalnum((unsigned char)*p) || *p == '_' || *p == '$')) {
                        need_synth = 1;
                        break;
                    }
                }
            }
        }

        if (need_synth) {
            snprintf(synth_name, sizeof(synth_name), "_anon_%d", fn->func_idx);
            display_name = synth_name;
        }

        /* Also sanitize argument names - replace invalid ones with _argN */
        sbuf_t clean_args; sb_init(&clean_args);
        int arg_idx = 0;
        int n_args_printed = fn->arg_count;
        if (n_args_printed > fn->vardefs_count) n_args_printed = fn->vardefs_count;
        for (int i = 0; i < n_args_printed; i++) {
            if (i > 0) sb_puts(&clean_args, ", ");
            const char *argname = qjs_atom_str(r, fn->vardefs[i].var_name_atom);
            /* Check if arg name is valid */
            int arg_valid = 0;
            if (argname[0] && (isalpha((unsigned char)argname[0]) || argname[0] == '_' || argname[0] == '$')) {
                arg_valid = 1;
                for (const char *p = argname + 1; *p; p++) {
                    if (!(isalnum((unsigned char)*p) || *p == '_' || *p == '$')) {
                        arg_valid = 0;
                        break;
                    }
                }
            }
            if (arg_valid) {
                sb_puts(&clean_args, argname);
            } else {
                sb_printf(&clean_args, "_arg%d", i);
            }
            arg_idx++;
        }

        put_indent(out, indent);
        fprintf(out, "%s %s(%s) {\n", kind, display_name[0] ? display_name : "anon", clean_args.buf);
        sb_free(&clean_args);
        if (body) {
            print_stmt(out, body, indent + 1);
            ir_stmt_free(body);
        }
        put_indent(out, indent);
        fprintf(out, "}\n\n");
    }
    sb_free(&args);
}

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
            put_indent(out, indent);
            fprintf(out, "/* ===== Module: %s ===== */\n", qjs_atom_str(r, m->module_name_atom));
            for (int i = 0; i < m->req_module_count; i++) {
                put_indent(out, indent);
                fprintf(out, "import * from \"%s\";\n", qjs_atom_str(r, m->req_modules[i].module_name_atom));
            }
            for (int i = 0; i < m->export_count; i++) {
                qjs_export_entry_t *e = &m->exports[i];
                put_indent(out, indent);
                if (e->export_type == 0) {
                    fprintf(out, "export %s;\n", qjs_atom_str(r, e->export_name_atom));
                } else {
                    fprintf(out, "export { %s as %s };\n",
                            qjs_atom_str(r, e->local_name_atom),
                            qjs_atom_str(r, e->export_name_atom));
                }
            }
            fprintf(out, "\n");
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
