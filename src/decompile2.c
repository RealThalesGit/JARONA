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

/* Marks that describe the role of a stack slot for the reconstruction of
 * template literals.  QuickJS compiles a template literal into a chain of
 * "String.prototype.concat" calls:
 *
 *     `a${x}b`   ->   "a".concat(x, "b")
 *
 * The literal chunks are pushed with OP_push_atom_value, the expressions
 * in between are ordinary byte code.  The flags below let the decompiler
 * tell the chunks apart from the expressions. */
typedef enum {
    TMPL_NONE = 0,      /* ordinary value */
    TMPL_CHUNK,         /* literal chunk of a template literal */
    TMPL_CONCAT,        /* the "concat" method of a template literal */
} tmpl_flag_t;

typedef struct {
    char *expr;
    int   is_simple;     /* 1 if atom/literal, 0 if complex */
    int   is_lvalue;     /* 1 if can be assigned to */
    int   prec;          /* operator precedence (higher = tighter binding) */
    int   is_dup_copy;   /* 1 if this slot is the leftover of a "dup; put_*"
                          * pair, i.e. a duplicate of a value that was just
                          * stored somewhere else.  Such leftovers must not be
                          * emitted a second time when they are dropped. */
    int   tmpl_flag;     /* tmpl_flag_t: role in a template literal */
    const qjs_value_t *const_val; /* backing constant, when this slot was
                                   * pushed by push_const (else NULL) */
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
    vs->slots[vs->top].is_dup_copy = 0;
    vs->slots[vs->top].tmpl_flag = TMPL_NONE;
    vs->slots[vs->top].const_val = NULL;
    return vs->top++;
}

/* Push with an explicit template-literal role */
static int vs_push_prec_flag(vstack_t *vs, const char *expr, int prec,
                              int is_lvalue, int tmpl_flag) {
    int r = vs_push_prec(vs, expr, prec, is_lvalue);
    if (r >= 0) vs->slots[r].tmpl_flag = tmpl_flag;
    return r;
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

static int vs_push_take_prec_flag(vstack_t *vs, char *expr, int prec,
                                   int is_lvalue, int tmpl_flag) {
    int r = vs_push_prec_flag(vs, expr, prec, is_lvalue, tmpl_flag);
    free(expr);
    return r;
}

static int vs_push_take(vstack_t *vs, char *expr, int is_simple, int is_lvalue) {
    return vs_push_take_prec(vs, expr, is_simple ? PREC_ATOM : PREC_COMMA, is_lvalue);
}

static slot_t vs_pop(vstack_t *vs) {
    if (vs->top <= 0) {
        slot_t empty = { xstrdup("undefined"), 1, 0, PREC_ATOM, 0, TMPL_NONE, NULL };
        return empty;
    }
    return vs->slots[--vs->top];
}
static slot_t vs_peek(vstack_t *vs, int from_top) {
    int idx = vs->top - 1 - from_top;
    if (idx < 0 || idx >= vs->top) {
        slot_t empty = { xstrdup("undefined"), 1, 0, PREC_ATOM, 0, TMPL_NONE, NULL };
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

/* Destructuring declaration: "const { a, b } = obj;" */
static ir_stmt_t *stmt_destruct(const char *pattern, char *rhs, int decl_kind) {
    ir_stmt_t *s = stmt_new(IR_STMT_DESTRUCTURE);
    s->lvalue = xstrdup(pattern);
    s->rhs = rhs;
    s->decl_kind = decl_kind;
    return s;
}

/* A function declaration: "function name(args) { ... }".
 * `export_name` is the exported name when the declaration belongs to a
 * module ("export function f() {}" / "export default function f() {}"). */
static ir_stmt_t *stmt_func_decl(char *text, const char *export_name) {
    ir_stmt_t *s = stmt_new(IR_STMT_FUNC_DECL);
    s->expr = text;
    if (export_name) s->export_name = xstrdup(export_name);
    return s;
}

static ir_stmt_t *stmt_break(void) { return stmt_new(IR_STMT_BREAK); }
static ir_stmt_t *stmt_continue(void) { return stmt_new(IR_STMT_CONTINUE); }

/* Label and goto statements are the fallback for jumps that cannot be
 * turned into structured control flow.  The printer understands both kinds;
 * the constructors are kept for that reconstruction path. */
static JARONA_UNUSED ir_stmt_t *stmt_label(const char *name) {
    ir_stmt_t *s = stmt_new(IR_STMT_LABEL);
    s->label = xstrdup(name);
    return s;
}

static JARONA_UNUSED ir_stmt_t *stmt_goto(const char *name) {
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

/* switch (cond) { case ...: ... }
 * The children are IR_STMT_CASE statements. */
static ir_stmt_t *stmt_switch(char *cond) {
    ir_stmt_t *s = stmt_new(IR_STMT_SWITCH);
    s->cond = cond;
    return s;
}

/* One case clause of a switch: "case value:" (value == NULL for "default:").
 * `body` is the statement block that follows the label; an empty block means
 * that the clause falls through to the next one. */
static ir_stmt_t *stmt_case(char *value, ir_stmt_t *body) {
    ir_stmt_t *s = stmt_new(IR_STMT_CASE);
    s->expr = value;
    s->body = body;
    return s;
}

static ir_stmt_t *stmt_try(ir_stmt_t *body, char *catch_var, ir_stmt_t *catch_body,
                           ir_stmt_t *finally_body) {    ir_stmt_t *s = stmt_new(IR_STMT_TRY);
    s->body = body;
    s->catch_var = catch_var;
    s->catch_body = catch_body;
    s->finally_body = finally_body;
    return s;
}

/* A class member (method / getter / setter).
 *   name    : member name
 *   args    : argument list, e.g. "a, b"
 *   kind    : 0 = method, 1 = getter, 2 = setter
 *   is_static: 1 for "static" members
 *   body    : the member body (a block) */
static ir_stmt_t *stmt_class_member(const char *name, const char *args,
                                     int kind, int is_static, ir_stmt_t *body) {
    ir_stmt_t *s = stmt_new(IR_STMT_CLASS_MEMBER);
    s->lvalue = xstrdup(name ? name : "");
    s->expr = xstrdup(args ? args : "");
    s->decl_kind = kind;
    s->is_static = is_static;
    s->body = body;
    return s;
}

/* A class declaration/expression.
 *   name     : class name (may be empty for anonymous classes)
 *   heritage : the 'extends' expression, or NULL */
static ir_stmt_t *stmt_class(const char *name, const char *heritage,
                             ir_stmt_t **members, int n_members) {
    ir_stmt_t *s = stmt_new(IR_STMT_CLASS);
    s->class_name = xstrdup(name ? name : "");
    s->class_heritage = heritage ? xstrdup(heritage) : NULL;
    s->children = members;
    s->n_children = n_members;
    return s;
}

/* Append a statement to a block, creating or wrapping the block if needed. */
static ir_stmt_t *block_append(ir_stmt_t *block, ir_stmt_t *s) {
    if (!block) block = stmt_block(NULL);
    if (block->kind != IR_STMT_BLOCK) {
        stmt_list_t wrap; sl_init(&wrap);
        sl_push(&wrap, block);
        block = stmt_block(&wrap);
    }
    int n = block->n_children + 1;
    block->children = xrealloc(block->children, (n > 0 ? n : 1) * sizeof(ir_stmt_t *));
    block->children[block->n_children++] = s;
    return block;
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
    free(s->class_name);
    free(s->class_heritage);
    free(s->export_name);
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

/* Defined with the string helpers below; used by the property-key helpers
 * and the object/class printer. */
static void quote_string_body(sbuf_t *sb, const char *s, size_t n);

static int ident_start_char(unsigned char c) {
    return isalpha(c) || c == '_' || c == '$';
}

static int ident_char(unsigned char c) {
    return isalnum(c) || c == '_' || c == '$';
}

static int is_valid_ident(const char *s) {
    if (!s || !*s) return 0;
    if (!ident_start_char((unsigned char)s[0])) return 0;
    for (int i = 1; s[i]; i++) {
        if (!ident_char((unsigned char)s[i])) return 0;
    }
    return 1;
}

/* Is `s` a JS reserved word?  A binding named "new" would not parse. */
static int is_js_reserved_word(const char *s) {
    static const char *const words[] = {
        "await", "break", "case", "catch", "class", "const", "continue",
        "debugger", "default", "delete", "do", "else", "enum", "export",
        "extends", "false", "finally", "for", "function", "if", "implements",
        "import", "in", "instanceof", "interface", "let", "new", "null",
        "package", "private", "protected", "public", "return", "static",
        "super", "switch", "this", "throw", "true", "try", "typeof", "var",
        "void", "while", "with", "yield",
    };
    for (size_t i = 0; i < sizeof(words) / sizeof(words[0]); i++)
        if (strcmp(s, words[i]) == 0) return 1;
    return 0;
}

/* Names the decompiler must preserve verbatim even though they are not
 * ordinary bindings: the QuickJS pseudo-variables and the internal marker
 * names (written "<...>").  Mangled, they would break the class / generator
 * reconstructions, which match on these exact strings. */
static int is_special_binding_name(const char *s) {
    static const char *const special[] = {
        "this", "home_object", "new_target", "_default_", "arguments",
        /* QuickJS pseudo-local names (they contain a dot on purpose); the
         * statement cleanup recognises them and drops the declarations. */
        "this.active_func", "new.target",
    };
    for (size_t i = 0; i < sizeof(special) / sizeof(special[0]); i++)
        if (strcmp(s, special[i]) == 0) return 1;
    /* Internal markers are enclosed in angle brackets ("<active_func>",
     * "<class_fields_init>", ...). */
    size_t n = strlen(s);
    if (n >= 2 && s[0] == '<' && s[n - 1] == '>') return 1;
    return 0;
}

/* Turn an arbitrary atom text into a valid JavaScript identifier.
 *
 * `AIM-TEST` becomes `AIM_TEST`, `1st` becomes `_1st`, an empty or fully
 * unusable name becomes `_name`.  The mapping is deterministic and only
 * depends on the input, so every occurrence of the same binding ends up
 * with the same identifier.  `suffix` is appended when two different names
 * collide (see the caller's dedup loop).
 *
 * Names that are already valid identifiers - and the QuickJS pseudo- and
 * internal names (see is_special_binding_name()) - are returned unchanged,
 * so ordinary code is not perturbed.  Only names carrying invalid
 * characters are rewritten.
 *
 * Callers own the returned string.  This is only for *bindings* (function
 * names, parameters, variables) - never for string literals or property
 * keys, whose text is data and must stay untouched. */
static char *sanitize_binding_name(const char *s, int suffix) {
    /* Fast path: the name is already usable as written. */
    if (s && suffix < 0 &&
        ((is_valid_ident(s) && !is_js_reserved_word(s)) ||
         is_special_binding_name(s)))
        return xstrdup(s);

    sbuf_t sb; sb_init(&sb);
    if (!s || !*s) {
        sb_puts(&sb, "_name");
    } else {
        for (const char *p = s; *p; p++) {
            unsigned char c = (unsigned char)*p;
            if (ident_char(c)) sb_putc(&sb, (char)c);
            else sb_putc(&sb, '_');
        }
        /* The first character must not be a digit. */
        if (isdigit((unsigned char)sb.buf[0])) {
            sbuf_t fixed; sb_init(&fixed);
            sb_putc(&fixed, '_');
            sb_puts(&fixed, sb.buf);
            sb_free(&sb);
            sb = fixed;
        }
    }
    if (suffix >= 0) sb_printf(&sb, "_%d", suffix);
    if (is_js_reserved_word(sb.buf)) {
        sbuf_t fixed; sb_init(&fixed);
        sb_puts(&fixed, sb.buf);
        sb_puts(&fixed, "_");
        sb_free(&sb);
        sb = fixed;
    }
    return sb.buf;
}

/* Byte length of the atom referenced by a QJS_FMT_atom* instruction. */
static uint32_t key_len_of(qjs_reader_t *r, ir_insn_t *insn) {
    if (!insn || !insn->info) return 0;
    switch (insn->info->fmt) {
        case QJS_FMT_atom:
        case QJS_FMT_atom_u8:
        case QJS_FMT_atom_u16:
        case QJS_FMT_atom_label_u8:
        case QJS_FMT_atom_label_u16: {
            uint32_t len = 0;
            qjs_atom_str_len(r, insn->atom_val, &len);
            return len;
        }
        default:
            return 0;
    }
}

/* Can `s` be written verbatim as an object/method key?  Identifiers and
 * array-index-like strings are fine; everything else needs quoting. */
static int is_valid_property_key(const char *s) {
    if (!s || !*s) return 0;
    if (is_valid_ident(s)) return 1;
    /* a canonical non-negative integer stays valid unquoted */
    int all_digits = 1;
    for (const char *p = s; *p; p++)
        if (!isdigit((unsigned char)*p)) { all_digits = 0; break; }
    if (all_digits) {
        return !(s[0] == '0' && s[1] != '\0');   /* "0123" is not canonical */
    }
    return 0;
}

/* Write `key` as an object literal / method key, quoting it when needed. */
static void put_property_key(sbuf_t *sb, const char *key, uint32_t key_len) {
    if (key_len == (uint32_t)strlen(key) && is_valid_property_key(key)) {
        sb_puts(sb, key);
        return;
    }
    sb_putc(sb, '"');
    quote_string_body(sb, key, key_len);
    sb_putc(sb, '"');
}

static char *field_expr_len(const char *obj, const char *field, uint32_t flen);

static char *field_expr(const char *obj, const char *field) {
    return field_expr_len(obj, field, (uint32_t)strlen(field));
}

/* Access to a private field: private names must keep their leading '#'
 * (obj.#name).  They are not ordinary identifiers, so field_expr() cannot
 * be used for them. */
static char *private_field_expr(const char *obj, const char *name) {
    sbuf_t sb; sb_init(&sb);
    sb_puts(&sb, obj);
    if (name && name[0] == '#') {
        sb_putc(&sb, '.');
        sb_puts(&sb, name);
    } else {
        /* Missing/odd symbol: fall back to bracket notation with the name. */
        sb_puts(&sb, "[\"");
        sb_puts(&sb, name ? name : "");
        sb_puts(&sb, "\"]");
    }
    return sb.buf;
}

static char *field_expr_len(const char *obj, const char *field, uint32_t flen) {
    if (flen == (uint32_t)strlen(field) && is_valid_ident(field)) {
        size_t la = strlen(obj), lb = flen;
        char *r = xmalloc(la + lb + 2);
        sprintf(r, "%s.%s", obj, field);
        return r;
    } else {
        sbuf_t sb; sb_init(&sb);
        sb_puts(&sb, obj);
        sb_putc(&sb, '[');
        sb_putc(&sb, '"');
        quote_string_body(&sb, field, flen);
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

/* =========================================================
 * Object literal helpers
 *
 * Object literals are built incrementally: the "object" opcode pushes the
 * empty marker "{}", every "define_field" appends one property and the
 * result stays "open" (its closing brace is missing) until the literal is
 * used as a value.  At that point the missing braces are appended.
 * ========================================================= */

/*
 * Number of object literals that are still open in `expr`.
 * Braces inside string literals do not count.
 */
static int open_object_count(const char *expr) {
    int depth = 0;
    int in_str = 0;
    char quote = 0;

    if (!expr) return 0;
    for (const char *p = expr; *p; p++) {
        if (in_str) {
            if (*p == '\\') { if (p[1]) p++; continue; }
            if (*p == quote) in_str = 0;
            continue;
        }
        if (*p == '"' || *p == '\'') { in_str = 1; quote = *p; continue; }
        if (*p == '{') depth++;
        else if (*p == '}' && depth > 0) depth--;
    }
    return depth;
}

/* Is this expression an object literal that is still being built? */
static int is_open_object(const char *expr) {
    return expr && expr[0] == '{' && open_object_count(expr) > 0;
}

/*
 * Close an open object literal expression in-place: the missing closing
 * braces are appended (with a separating space) and trailing blanks are
 * removed.
 */
static void close_obj_str(char **expr) {
    if (!expr || !*expr) return;

    int depth = open_object_count(*expr);
    if (depth <= 0) return;

    size_t len = strlen(*expr);
    while (len > 0 && ((*expr)[len - 1] == ' ' || (*expr)[len - 1] == '\t')) len--;

    char *new_expr = xmalloc(len + (size_t)depth * 2 + 1);
    memcpy(new_expr, *expr, len);
    size_t n = len;
    for (int i = 0; i < depth; i++) {
        new_expr[n++] = ' ';
        new_expr[n++] = '}';
    }
    new_expr[n] = '\0';

    free(*expr);
    *expr = new_expr;
}

static void close_obj_if_open(slot_t *s) {
    if (!s) return;
    close_obj_str(&s->expr);
}

/* Append an element (or a spread element) to an array literal expression.
 * QuickJS builds arrays that contain spreads with a dynamic index:
 *     array_from 0; push_i32 idx; <source>; append;
 *     push_i32 value; define_array_el; inc; ...
 * The index is irrelevant for the source text, so elements are simply
 * appended in order.  Returns NULL if `arr` is not a closed array literal. */
static char *array_literal_append(char *arr, const char *elem, int is_spread) {
    if (!arr || !elem) return NULL;
    size_t len = strlen(arr);
    if (len < 2 || arr[0] != '[' || arr[len - 1] != ']') return NULL;

    /* Trim blanks before the closing bracket ("[1, 2 ]" -> "[1, 2"). */
    size_t inner = len - 1;
    while (inner > 1 && (arr[inner - 1] == ' ' || arr[inner - 1] == '\t')) inner--;
    int empty = (inner == 1);

    sbuf_t sb; sb_init(&sb);
    sb_append(&sb, arr, inner);
    if (!empty) sb_puts(&sb, ", ");
    if (is_spread) sb_puts(&sb, "...");
    sb_puts(&sb, elem);
    sb_putc(&sb, ']');
    free(arr);
    return sb.buf;
}

/* Build "get name(...)" / "set name(...)" from a rendered anonymous
 * function expression ("function (v) { ... }").  The parameter list and
 * body are copied verbatim from the function expression. */
static char *accessor_from_function_expr(const char *kw, const char *name,
                                         uint32_t name_len,
                                         const char *fn_expr) {
    if (!fn_expr) return NULL;
    const char *paren = strchr(fn_expr, '(');
    if (!paren) return NULL;
    sbuf_t sb; sb_init(&sb);
    sb_puts(&sb, kw);
    sb_putc(&sb, ' ');
    put_property_key(&sb, name ? name : "", name_len);
    sb_puts(&sb, paren);
    return sb.buf;
}

/* Append a spread property to an object literal that is being built. */
static void object_literal_add_spread(slot_t *obj, slot_t *src) {
    close_obj_if_open(src);
    sbuf_t sb; sb_init(&sb);
    if (strcmp(obj->expr, "{}") == 0) {
        /* Start the literal: "{ ...src" (left open for later fields). */
        sb_puts(&sb, "{ ");
    } else {
        sb_puts(&sb, obj->expr);
        sb_puts(&sb, ", ");
    }
    sb_puts(&sb, "...");
    sb_puts(&sb, src->expr);
    free(obj->expr);
    obj->expr = sb.buf;
    obj->prec = PREC_ATOM;
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

/* A plain integer literal followed by "." is ambiguous with a decimal
 * point ("255.toString()" is a syntax error), so such receivers must be
 * parenthesised before member access. */
static int is_int_literal_expr(const char *s) {
    if (!s || !*s) return 0;
    if (*s == '-') s++;
    if (!*s) return 0;
    for (; *s; s++)
        if (*s < '0' || *s > '9') return 0;
    return 1;
}

/* Append `s` (n bytes, UTF-8) to `sb` as the contents of a JS string
 * literal.  Everything that is not a printable ASCII character is escaped,
 * which keeps the emitted source valid UTF-8 even when the byte code holds
 * raw bytes (QuickJS strings are arbitrary byte sequences, not UTF-8). */
static void quote_string_body(sbuf_t *sb, const char *s, size_t n) {
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        switch (c) {
        case '"':  sb_puts(sb, "\\\""); break;
        case '\\': sb_puts(sb, "\\\\"); break;
        case '\n': sb_puts(sb, "\\n");  break;
        case '\r': sb_puts(sb, "\\r");  break;
        case '\t': sb_puts(sb, "\\t");  break;
        case '\b': sb_puts(sb, "\\b");  break;
        case '\f': sb_puts(sb, "\\f");  break;
        case '\v': sb_puts(sb, "\\v");  break;
        case '\0':
            /* Use \x00 followed by nothing that could extend the escape. */
            sb_puts(sb, "\\x00");
            break;
        default:
            if (c < 0x20 || c == 0x7f) sb_printf(sb, "\\x%02x", c);
            else if (c < 0x80) sb_putc(sb, (char)c);
            else {
                /* Non-ASCII: assume UTF-8 and keep whole code points; a
                 * stray continuation byte is emitted as an escape. */
                size_t nseq = 1;
                if ((c & 0xe0) == 0xc0) nseq = 2;
                else if ((c & 0xf0) == 0xe0) nseq = 3;
                else if ((c & 0xf8) == 0xf0) nseq = 4;
                if (i + nseq <= n) {
                    size_t k;
                    for (k = 1; k < nseq; k++)
                        if (((unsigned char)s[i + k] & 0xc0) != 0x80) break;
                    if (k == nseq) {
                        for (k = 0; k < nseq; k++) sb_putc(sb, s[i + k]);
                        i += nseq - 1;
                        break;
                    }
                }
                sb_printf(sb, "\\x%02x", c);
            }
            break;
        }
    }
}

/* Quote a NUL-terminated string (used when the real length is unknown). */
static char *quote_string(const char *s) {
    sbuf_t sb; sb_init(&sb);
    sb_putc(&sb, '"');
    quote_string_body(&sb, s, strlen(s));
    sb_putc(&sb, '"');
    return sb.buf;
}

/* Quote a string of known length; handles embedded NUL bytes. */
static char *quote_string_len(const char *s, size_t n) {
    sbuf_t sb; sb_init(&sb);
    sb_putc(&sb, '"');
    quote_string_body(&sb, s, n);
    sb_putc(&sb, '"');
    return sb.buf;
}

/* Value of a hexadecimal digit, or -1. */
static int hex_val(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* Inverse of quote_string(): recover the raw text of a string literal.
 *
 * The literal is looked up inside the expression, so that expressions which
 * were wrapped in parentheses are handled as well.  When no literal can be
 * found the expression is returned unchanged. */
static char *unquote_string(const char *lit) {
    const char *start, *end;
    sbuf_t sb;

    if (!lit) return xstrdup("");
    start = strchr(lit, '"');
    if (!start) return xstrdup(lit);
    end = strrchr(start + 1, '"');
    if (!end) return xstrdup(lit);

    sb_init(&sb);
    for (const char *p = start + 1; p < end; p++) {
        if (*p != '\\' || p + 1 >= end) { sb_putc(&sb, *p); continue; }
        p++;
        switch (*p) {
        case 'n': sb_putc(&sb, '\n'); break;
        case 'r': sb_putc(&sb, '\r'); break;
        case 't': sb_putc(&sb, '\t'); break;
        case 'b': sb_putc(&sb, '\b'); break;
        case 'f': sb_putc(&sb, '\f'); break;
        case 'x': {
            int hi = hex_val((unsigned char)p[1]);
            int lo = (hi >= 0) ? hex_val((unsigned char)p[2]) : -1;
            if (lo >= 0) { sb_putc(&sb, (char)(hi * 16 + lo)); p += 2; }
            else sb_putc(&sb, *p);
            break;
        }
        case 'v': sb_putc(&sb, '\v'); break;
        case '0': sb_putc(&sb, '\0'); break;
        default: sb_putc(&sb, *p); break;
        }
    }
    return sb.buf;
}

/* =========================================================
 * Template literals
 *
 * QuickJS compiles a template literal into a chain of
 * "String.prototype.concat" calls; the literal parts are pushed with
 * OP_push_atom_value:
 *
 *     `a${x}b`   ->   "a".concat(x, "b")
 *
 * OP_push_atom_value is used for plain string literals as well, so the
 * decompiler cannot tell the two apart at the push.  It does so later on:
 * only the receiver of a "concat" access and the odd numbered arguments of
 * the resulting call belong to a template literal.  The helpers below
 * rebuild the original template literal from that pattern.
 * ========================================================= */

/* Escape a string so that it can be used inside a template literal. */
static char *escape_template_text(const char *s) {
    sbuf_t sb; sb_init(&sb);
    for (const char *p = s; *p; p++) {
        if (*p == '\\' || *p == '`') { sb_putc(&sb, '\\'); sb_putc(&sb, *p); }
        else if (*p == '$' && p[1] == '{') { sb_puts(&sb, "\\$"); }
        else if (*p == '\n') sb_puts(&sb, "\\n");
        else if (*p == '\r') sb_puts(&sb, "\\r");
        else if (*p == '\t') sb_puts(&sb, "\\t");
        else if (*p == '\b') sb_puts(&sb, "\\b");
        else if (*p == '\f') sb_puts(&sb, "\\f");
        else if ((unsigned char)*p < 0x20) sb_printf(&sb, "\\x%02x", (unsigned char)*p);
        else sb_putc(&sb, *p);
    }
    return sb.buf;
}

/* Build a template literal from the receiver chunk and the arguments of
 * the "concat" call.
 *
 * The receiver is the first literal chunk of the template literal.  The
 * arguments hold the remaining parts: they alternate between the
 * expressions of the template literal and its literal chunks, but empty
 * chunks are not emitted at all, so the alternation is not strict:
 *
 *     `a${x}b`   ->   "a".concat(x, "b")
 *                       ^ receiver  ^arg0  ^arg1
 *     `${x}${y}`  ->   "".concat(x, y)
 *
 * A literal chunk is a string literal, so it is told apart from an
 * expression by looking at the previous argument: after an expression the
 * next string literal is a chunk.
 */
static char *build_template_literal(const char *recv, slot_t *argv, int nargs) {
    sbuf_t sb; sb_init(&sb);
    char *text;
    int prev_is_expr = 1;

    sb_putc(&sb, '`');

    /* The receiver is the first literal chunk. */
    text = unquote_string(recv);
    sb_puts(&sb, escape_template_text(text));
    free(text);

    for (int i = 0; i < nargs; i++) {
        int is_chunk = (i > 0 && prev_is_expr &&
                        argv[i].tmpl_flag == TMPL_CHUNK);
        prev_is_expr = !is_chunk;
        if (is_chunk) {
            /* Literal chunk of the template literal. */
            text = unquote_string(argv[i].expr);
            sb_puts(&sb, escape_template_text(text));
            free(text);
        } else {
            /* Expression of the template literal. */
            sb_puts(&sb, "${");
            sb_puts(&sb, argv[i].expr ? argv[i].expr : "undefined");
            sb_putc(&sb, '}');
        }
    }

    sb_putc(&sb, '`');
    return sb.buf;
}

/* Rebuild a tagged template literal.  QuickJS passes a frozen "template
 * object" as the first argument: an array of cooked strings with a "raw"
 * property holding the source text of each chunk.  Using the raw strings
 * lets us reproduce the original template verbatim.
 *
 * argv[0] is the template object itself and argv[1..] are the
 * substitutions, so argv[i] is the expression between raw[i-1] and raw[i]. */
static char *build_tagged_template(qjs_reader_t *r, const qjs_value_t *tmpl,
                                   slot_t *argv, int nargs) {
    (void)r;
    if (!tmpl || tmpl->kind != QJS_VAL_TEMPLATE_OBJECT) return NULL;
    const qjs_value_t *raw = tmpl->u.arr.raw;
    uint32_t count = tmpl->u.arr.count;
    /* The "raw" array is sealed as well, so it may be serialised with the
     * template-object tag: accept both array kinds. */
    if (!raw || (raw->kind != QJS_VAL_ARRAY &&
                 raw->kind != QJS_VAL_TEMPLATE_OBJECT) ||
        raw->u.arr.count != count)
        return NULL;
    if (count != (uint32_t)nargs) return NULL;

    sbuf_t sb; sb_init(&sb);
    sb_putc(&sb, '`');
    for (uint32_t i = 0; i < count; i++) {
        if (i > 0) {
            sb_puts(&sb, "${");
            sb_puts(&sb, (i < (uint32_t)nargs && argv[i].expr)
                             ? argv[i].expr : "undefined");
            sb_putc(&sb, '}');
        }
        const qjs_value_t *s = raw->u.arr.items[i];
        if (s && s->kind == QJS_VAL_STRING) {
            /* Raw strings are literal source text (escapes included). */
            sb_append(&sb, s->u.str.data, s->u.str.len);
        } else if (s && s->kind != QJS_VAL_UNDEFINED) {
            sb_free(&sb);
            return NULL;
        }
    }
    sb_putc(&sb, '`');
    return sb.buf;
}

static char *value_to_js(qjs_reader_t *r, qjs_value_t *v) {
    return qjs_format_value(r, v, 6);
}

/* Check whether a rendered expression is a function expression. */
static int is_function_expr(const char *s) {
    if (!s) return 0;
    if (strncmp(s, "function", 8) == 0) return 1;
    if (strncmp(s, "async function", 14) == 0) return 1;
    return 0;
}

/* =========================================================
 * Function expression builder
 *
 * Renders a compiled function as a JavaScript function expression:
 *
 *     function (a, b) { ... }
 *     function name(a, b) { ... }
 *     async function* name(a) { ... }
 *
 * The body is produced by the regular statement decompiler; the result is
 * laid out with a relative indentation of one level so that it can be
 * re-indented when the expression is embedded in a statement.
 * ========================================================= */
static void print_stmt(FILE *out, ir_stmt_t *s, int indent);

/* Return the index of the rest parameter ("...args"), or -1.
 *
 * QuickJS emits a "rest <idx>" instruction in the parameter prologue of a
 * function that has a rest parameter.  The opcode only ever appears there,
 * so a linear scan is safe (and handles default parameters that generate
 * code before the "rest" instruction). */
static int fn_rest_arg_index(qjs_function_t *fn) {
    if (!fn->byte_code || fn->byte_code_len < 3) return -1;
    uint32_t len = (uint32_t)fn->byte_code_len;
    qjs_op_mode_t mode = fn->is_frida ? QJS_MODE_FRIDA : QJS_MODE_VANILLA;
    uint32_t pc = 0;
    while (pc < len) {
        uint8_t op = fn->byte_code[pc];
        const qjs_op_info_t *info = qjs_get_op_info(op, mode);
        if (!info || info->size <= 0 || pc + (uint32_t)info->size > len) break;
        if (op == qjs_op_rest) {
            uint32_t idx = (uint32_t)fn->byte_code[pc + 1] |
                           ((uint32_t)fn->byte_code[pc + 2] << 8);
            if (idx < fn->arg_count) return (int)idx;
            return -1;
        }
        pc += (uint32_t)info->size;
    }
    return -1;
}

/* Build the argument list of a function ("a, b").  Arguments whose name is
 * not a valid identifier are replaced by "_argN".
 *
 * Simple default parameters are compiled as a prologue of the form
 *
 *     get_argN; dup; is_undefined; if_false L; drop; <default>; set_argN
 *   L: ...
 *
 * The regular statement decompiler folds that into an assignment at the
 * beginning of the body.  When a decompiled body is available we move those
 * assignments back into the argument list, which restores the source-level
 * default values and, more importantly, stops the body from overwriting an
 * explicitly passed argument. */
static char *fn_args_string_body(qjs_reader_t *r, qjs_function_t *fn,
                                 ir_stmt_t *body) {
    sbuf_t args; sb_init(&args);
    int n_args = fn->arg_count;
    int rest_arg = fn_rest_arg_index(fn);
    if (n_args > fn->vardefs_count) n_args = fn->vardefs_count;

    char **defaults = xcalloc((size_t)(n_args > 0 ? n_args : 1), sizeof(char *));
    int *has_default = xcalloc((size_t)(n_args > 0 ? n_args : 1), sizeof(int));

    /* Scan the prologue for the simple-default pattern. */
    if (n_args > 0 && fn->byte_code && fn->byte_code_len > 0) {
        uint32_t len = (uint32_t)fn->byte_code_len;
        qjs_op_mode_t mode = fn->is_frida ? QJS_MODE_FRIDA : QJS_MODE_VANILLA;
        uint32_t pc = 0;
        while (pc < len) {
            uint8_t op = fn->byte_code[pc];
            const qjs_op_info_t *info = qjs_get_op_info(op, mode);
            if (!info || info->size <= 0 || pc + (uint32_t)info->size > len)
                break;

            int arg = -1;
            if (op >= qjs_op_get_arg0 && op <= qjs_op_get_arg3) {
                arg = op - qjs_op_get_arg0;
            } else if (op == qjs_op_get_arg && pc + 3 <= len) {
                arg = (int)((uint32_t)fn->byte_code[pc + 1] |
                            ((uint32_t)fn->byte_code[pc + 2] << 8));
            }
            if (arg >= 0 && arg < n_args) {
                uint32_t p = pc + (uint32_t)info->size;
                uint8_t o1 = 0, o2 = 0, o3 = 0;
                if (p < len) o1 = fn->byte_code[p];
                const qjs_op_info_t *i1 = qjs_get_op_info(o1, mode);
                uint32_t p2 = p + (i1 && i1->size > 0 ? (uint32_t)i1->size : 0);
                if (p2 < len) o2 = fn->byte_code[p2];
                const qjs_op_info_t *i2 = qjs_get_op_info(o2, mode);
                uint32_t p3 = p2 + (i2 && i2->size > 0 ? (uint32_t)i2->size : 0);
                if (p3 < len) o3 = fn->byte_code[p3];
                if (o1 == qjs_op_dup && o2 == qjs_op_is_undefined &&
                    (o3 == qjs_op_if_false || o3 == qjs_op_if_false8)) {
                    has_default[arg] = 1;
                }
            }
            pc += (uint32_t)info->size;
        }
    }

    /* Recover the expression text from the leading assignments emitted for
     * the prologue and remove them from the body. */
    int search = 0;
    if (body && body->kind == IR_STMT_BLOCK) {
        for (int i = 0; i < n_args; i++) {
            if (!has_default[i]) continue;
            char *an = sanitize_binding_name(
                qjs_atom_str(r, fn->vardefs[i].var_name_atom), -1);
            for (int k = search; k < body->n_children; k++) {
                ir_stmt_t *c = body->children[k];
                if (c && c->kind == IR_STMT_ASSIGN && c->lvalue &&
                    strcmp(c->lvalue, an) == 0 && c->rhs) {
                    defaults[i] = c->rhs;
                    c->rhs = NULL;
                    ir_stmt_free(c);
                    for (int m = k; m + 1 < body->n_children; m++)
                        body->children[m] = body->children[m + 1];
                    body->n_children--;
                    search = k;
                    break;
                }
            }
            free(an);
        }
    }

    for (int i = 0; i < n_args; i++) {
        if (i > 0) sb_puts(&args, ", ");
        if (i == rest_arg) sb_puts(&args, "...");
        char *an = sanitize_binding_name(
            qjs_atom_str(r, fn->vardefs[i].var_name_atom), -1);
        sb_puts(&args, an);
        if (defaults[i]) {
            sb_puts(&args, " = ");
            sb_puts(&args, defaults[i]);
        }
        free(an);
        free(defaults[i]);
    }
    free(defaults);
    free(has_default);
    return args.buf;
}

static char *fn_expr_string(qjs_reader_t *r, qjs_function_t *fn) {
    const char *name = qjs_atom_str(r, fn->func_name_atom);
    const char *kind = "function";
    if (fn->flags.func_kind == 1) kind = "function*";
    else if (fn->flags.func_kind == 2) kind = "async function";
    else if (fn->flags.func_kind == 3) kind = "async function*";

    /* Decompile the body first: default parameter initialisation is
     * reconstructed as leading body assignments, which the argument-list
     * builder moves back into the parameter list. */
    ir_stmt_t *body = ir_decompile_function(r, fn, 0, NULL);
    char *args = fn_args_string_body(r, fn, body);

    sbuf_t out; sb_init(&out);
    sb_puts(&out, kind);
    sb_putc(&out, ' ');
    if (fn->func_name_atom != 0 && name[0] &&
        strncmp(name, "_builtin_", 9) != 0 && strncmp(name, "_atom_", 6) != 0) {
        /* Named function: "function name(...)".  The name is a binding, so
         * invalid characters are sanitized rather than dropped. */
        char *clean = sanitize_binding_name(name, -1);
        sb_puts(&out, clean);
        free(clean);
    }
    sb_putc(&out, '(');
    sb_puts(&out, args);
    sb_puts(&out, ") {\n");

    if (body) {
        char *bbuf = NULL;
        size_t blen = 0;
        FILE *f = open_memstream(&bbuf, &blen);
        if (f) {
            print_stmt(f, body, 1);
            fclose(f);
            sb_puts(&out, bbuf);
            free(bbuf);
        }
        ir_stmt_free(body);
    }
    sb_putc(&out, '}');
    free(args);
    return out.buf;
}

/* =========================================================
 * Local variable name lookup
 * ========================================================= */
static char *loc_name(qjs_reader_t *r, qjs_function_t *fn, uint32_t loc) {
    uint32_t vd_idx = fn->arg_count + loc;
    if (vd_idx < (uint32_t)fn->vardefs_count) {
        /* The vardef may carry characters that are not valid in an
         * identifier; sanitize deterministically so the declaration and
         * every use site agree. */
        return sanitize_binding_name(
            qjs_atom_str(r, fn->vardefs[vd_idx].var_name_atom), -1);
    }
    char buf[64]; snprintf(buf, sizeof(buf), "loc%d", loc);
    return xstrdup(buf);
}

static char *arg_name(qjs_reader_t *r, qjs_function_t *fn, uint32_t arg) {
    if (arg < (uint32_t)fn->vardefs_count) {
        return sanitize_binding_name(
            qjs_atom_str(r, fn->vardefs[arg].var_name_atom), -1);
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
    /* Synthesized labels.  QuickJS does not keep source label names in the
     * bytecode, so when a break/continue targets an outer loop we invent a
     * stable name (L1, L2, ...) and label that loop. */
    char *loop_labels[32];
    int loop_ids[32];
    uint8_t loop_label_needed[32];
    int next_loop_id;
    /* 1 when the current function is the top-level script/module function:
     * a top-level "return X" is not valid JavaScript, so it must be turned
     * into the expression statement "X;". */
    int is_script;
    /* Module support: set when the function being decompiled is the body of
     * an ES module.  The module export/import tables are needed to rebuild
     * the "export"/"import" statements. */
    qjs_module_t *module;
    /* Per closure variable flag: the variable was already emitted as a
     * declaration (module scope only). */
    uint8_t *module_declared;
    int module_declared_count;
    /* Per export entry flag: the entry was consumed by an inline
     * declaration and does not need a separate "export { ... };" line. */
    uint8_t *module_export_used;
    int module_export_used_count;
} decomp_ctx_t;

/* Enter a loop, registering its break/continue targets and allocating a
 * potential label.  Returns the loop nesting index, or -1 when the fixed
 * tracking stack is full. */
static int ctx_enter_loop(decomp_ctx_t *ctx, uint32_t start, uint32_t end) {
    int d = ctx->loop_depth;
    if (d < 0 || d >= 32) return -1;
    ctx->loop_start_targets[d] = start;
    ctx->loop_end_targets[d] = end;
    ctx->loop_ids[d] = ++ctx->next_loop_id;
    char buf[32];
    snprintf(buf, sizeof(buf), "L%d", ctx->loop_ids[d]);
    ctx->loop_labels[d] = xstrdup(buf);
    ctx->loop_label_needed[d] = 0;
    ctx->loop_depth++;
    return d;
}

/* Leave a loop.  Returns an owned copy of its label when a nested
 * break/continue referenced it, otherwise NULL. */
static char *ctx_exit_loop(decomp_ctx_t *ctx, int d) {
    if (d < 0 || d >= 32) {
        if (ctx->loop_depth > 0) ctx->loop_depth--;
        return NULL;
    }
    char *label = NULL;
    if (ctx->loop_label_needed[d] && ctx->loop_labels[d])
        label = xstrdup(ctx->loop_labels[d]);
    free(ctx->loop_labels[d]);
    ctx->loop_labels[d] = NULL;
    ctx->loop_label_needed[d] = 0;
    if (ctx->loop_depth > 0) ctx->loop_depth--;
    return label;
}

static void ctx_mark_loop_label(decomp_ctx_t *ctx, int d) {
    if (d >= 0 && d < 32 && d < ctx->loop_depth)
        ctx->loop_label_needed[d] = 1;
}

/* Forward declarations */
static ir_stmt_t *decompile_range(decomp_ctx_t *ctx, int start_idx, int end_idx);
static ir_stmt_t *decompile_range_top(decomp_ctx_t *ctx, int start_idx, int end_idx, int is_toplevel);
static char *strip_outer_parens(char *expr);
static int is_internal_var(const char *name);
static int is_reserved_word(const char *name);
static void convert_while_to_for(ir_stmt_t *s);
static char *fn_expr_string(qjs_reader_t *r, qjs_function_t *fn);

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
                qjs_value_t *cv = fn->cpool[idx];
                if (cv && cv->kind == QJS_VAL_FUNCTION) {
                    /* A function in the constant pool (e.g. a class
                     * constructor) is inlined as an expression too. */
                    char *s = fn_expr_string(r, cv->u.func.fn);
                    vs_push_take(vs, s, 0, 0);
                } else {
                    char *s = value_to_js(r, cv);
                    int r2 = vs_push_take(vs, s, 1, 0);
                    if (r2 >= 0) vs->slots[r2].const_val = cv;
                }
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
            if (idx >= 0 && idx < fn->cpool_count &&
                fn->cpool[idx] && fn->cpool[idx]->kind == QJS_VAL_FUNCTION) {
                qjs_function_t *nfn = fn->cpool[idx]->u.func.fn;
                /* Inline the function as an expression at its use site so
                 * that the reconstructed source keeps the original shape
                 * (function declarations are rebuilt by OP_define_func). */
                char *s = fn_expr_string(r, nfn);
                vs_push_take(vs, s, 0, 0);
            } else {
                /* Out of bounds - push undefined */
                vs_push(vs, "undefined", 1, 0);
            }
            break;
        }
        case qjs_op_push_atom_value:
            /* A string literal - or a literal chunk of a template literal.
             * The two are only told apart by the way the value is used, so
             * the string is pushed as a plain literal and the template role
             * is resolved when the "concat" chain is decoded. */
            {
                /* Use the exact atom length: strings may contain NUL bytes,
                 * which a strlen() based quote would silently truncate. */
                uint32_t raw_len = 0;
                const char *raw = qjs_atom_str_len(ctx->r, insn->atom_val,
                                                   &raw_len);
                char *lit = raw ? quote_string_len(raw, raw_len)
                                : quote_string(atom_name);
                vs_push_take_prec_flag(vs, lit, PREC_ATOM, 0, TMPL_CHUNK);
            }
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
        case qjs_op_push_empty_string:
            /* The empty string.  QuickJS emits this opcode for the empty
             * literal chunk of a template literal as well. */
            vs_push_take_prec_flag(vs, xstrdup("\"\""), PREC_ATOM, 0,
                                   TMPL_CHUNK);
            break;

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

        /* rest N: the rest parameter is already bound to argument N (the
         * prologue immediately stores it there), so evaluate to its name. */
        case qjs_op_rest: {
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
                const char *raw = qjs_atom_str(
                    r, fn->closure_vars[vref].var_name_atom);
                /* Private names (#name) are not bindings: keep the '#'. */
                char *vn = (raw && raw[0] == '#')
                               ? xstrdup(raw)
                               : sanitize_binding_name(raw, -1);
                vs_push_take(vs, vn, 1, 1);
            } else {
                char b[64]; snprintf(b, sizeof(b), "var_ref%d", vref); vs_push(vs, b, 1, 1);
            }
            break;
        }

        /* ===== Variables ===== */
        case qjs_op_get_var:
        case qjs_op_get_var_undef:
        case qjs_op_check_var: {
            /* Global/var bindings are identifiers, so an atom with invalid
             * characters is sanitized to keep the emitted source parseable. */
            vs_push_take(vs, sanitize_binding_name(atom_name, -1), 1, 1);
            break;
        }

        /* ===== Field access ===== */
        case qjs_op_get_field:
        case qjs_op_get_field2: {
            slot_t obj = vs_pop(vs);
            /* An object literal that is still being built must be closed
             * before it is used as a receiver: { ...a }.b */
            close_obj_if_open(&obj);
            /* Wrap obj in parens if it's a complex expression (e.g., (a+b).c) */
            if ((obj.prec < PREC_CALL || is_int_literal_expr(obj.expr)) &&
                !already_parenthesized(obj.expr))
                obj.expr = wrap_parens(obj.expr);
            char *e = field_expr(obj.expr, atom_name);
            /* "String.prototype.concat" applied to a template literal chunk
             * is how QuickJS compiles a template literal. */
            int mflag = TMPL_NONE;
            if (op == qjs_op_get_field2 && obj.tmpl_flag == TMPL_CHUNK &&
                strcmp(atom_name, "concat") == 0)
                mflag = TMPL_CONCAT;
            if (op == qjs_op_get_field2) {
                vs_push_prec_flag(vs, obj.expr, PREC_CALL, obj.is_lvalue,
                                  obj.tmpl_flag);
                vs_push_take_prec_flag(vs, e, PREC_CALL, 1, mflag);
            } else {
                vs_push_take_prec_flag(vs, e, PREC_CALL, 1, mflag);
            }
            free(obj.expr);
            break;
        }
        case qjs_op_get_array_el:
        case qjs_op_get_array_el2: {
            slot_t idx = vs_pop(vs);
            slot_t obj = vs_pop(vs);
            if ((obj.prec < PREC_CALL || is_int_literal_expr(obj.expr)) &&
                !already_parenthesized(obj.expr))
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
            if ((obj.prec < PREC_CALL || is_int_literal_expr(obj.expr)) &&
                !already_parenthesized(obj.expr))
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

        /* is_null / is_undefined: value -> boolean (strict comparison) */
        case qjs_op_is_null:
        case qjs_op_is_undefined: {
            slot_t a = vs_pop(vs);
            close_obj_if_open(&a);
            slot_t lit = { xstrdup(op == qjs_op_is_null ? "null" : "undefined"),
                           1, 0, PREC_ATOM, 0, TMPL_NONE, NULL };
            char *e = build_binop(a, "===", lit);
            int r = vs_push_take_prec(vs, e, PREC_EQ, 0);
            if (r >= 0) vs->slots[r].is_dup_copy = a.is_dup_copy;
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
            /* OP_inc/OP_dec implement the prefix forms (++x / --x).  The
             * postfix forms have their own opcodes and keep the old value. */
            const char *op_s = (op == qjs_op_inc) ? "++" : "--";
            sbuf_t sb; sb_init(&sb);
            sb_puts(&sb, op_s);
            sb_puts(&sb, a.expr);
            int r = vs_push_take_prec(vs, sb.buf, PREC_UNARY, 0);
            /* Preserve the "internal value" marker (array-literal index). */
            if (r >= 0) vs->slots[r].is_dup_copy = a.is_dup_copy;
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

                /* Tagged template: the first argument is a template object. */
                char *tagged = NULL;
                if (nargs >= 1 && argv[0].const_val)
                    tagged = build_tagged_template(r, argv[0].const_val,
                                                   argv, nargs);
                if (tagged) {
                    slot_t callee = vs_pop(vs);
                    if (callee.prec < PREC_CALL && !already_parenthesized(callee.expr))
                        callee.expr = wrap_parens(callee.expr);
                    sbuf_t sb; sb_init(&sb);
                    sb_puts(&sb, callee.expr);
                    sb_puts(&sb, tagged);
                    for (int i = 0; i < nargs; i++) free(argv[i].expr);
                    free(argv);
                    free(tagged);
                    free(callee.expr);
                    vs_push_take_prec(vs, sb.buf, PREC_CALL, 0);
                    break;
                }

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
                slot_t method = vs_pop(vs);
                slot_t obj = vs_pop(vs);
                /* A template literal is compiled into a "concat" chain:
                 * the receiver is the first literal chunk and the string
                 * literal arguments are the remaining chunks.  When the
                 * receiver is not a literal the call is a regular method
                 * call and is rendered as such. */
                int is_template = (method.tmpl_flag == TMPL_CONCAT &&
                                   obj.tmpl_flag == TMPL_CHUNK);
                if (is_template) {
                    /* Rebuild the template literal the "concat" chain was
                     * compiled from. */
                    char *e = build_template_literal(obj.expr, argv, nargs);
                    vs_push_take_prec(vs, e, PREC_ATOM, 0);
                } else {
                    sbuf_t args; sb_init(&args);
                    for (int i = 0; i < nargs; i++) {
                        if (i > 0) sb_puts(&args, ", ");
                        sb_puts(&args, argv[i].expr);
                    }
                    char *e = make_call(method.expr, args.buf);
                    vs_push_take_prec(vs, e, PREC_CALL, 0);
                    sb_free(&args);
                }
                for (int i = 0; i < nargs; i++) free(argv[i].expr);
                free(method.expr); free(obj.expr);
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
            /* Keep in sync with OP_SPECIAL_OBJECT_* in quickjs.c. */
            switch (insn->u32_val) {
                case 0: name = "arguments"; break;
                case 1: name = "arguments"; break; /* mapped arguments */
                case 2: name = "this.active_func"; break;
                case 3: name = "new.target"; break;
                case 4: name = "home_object"; break;
                case 5: name = "<var_object>"; break;
                case 6: name = "import.meta"; break;
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
            /* The two operands are the pattern string and the compiled
             * libregexp bytecode.  Its first byte holds the flags. */
            slot_t bc = vs_pop(vs);
            slot_t pat = vs_pop(vs);
            sbuf_t sb; sb_init(&sb);
            sb_putc(&sb, '/');
            if (pat.const_val && pat.const_val->kind == QJS_VAL_STRING) {
                sb_puts(&sb, pat.const_val->u.str.data);
            } else {
                sb_puts(&sb, pat.expr);
            }
            sb_putc(&sb, '/');
            if (bc.const_val && bc.const_val->kind == QJS_VAL_STRING &&
                bc.const_val->u.str.len > 0) {
                unsigned fl = (unsigned char)bc.const_val->u.str.data[0];
                if (fl & (1u << 0)) sb_putc(&sb, 'g');
                if (fl & (1u << 1)) sb_putc(&sb, 'i');
                if (fl & (1u << 2)) sb_putc(&sb, 'm');
                if (fl & (1u << 3)) sb_putc(&sb, 's');
                if (fl & (1u << 4)) sb_putc(&sb, 'u');
                if (fl & (1u << 5)) sb_putc(&sb, 'y');
                if (fl & (1u << 6)) sb_putc(&sb, 'd');
            }
            vs_push_take(vs, sb.buf, 1, 0);
            free(pat.expr); free(bc.expr);
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
                int mkind = (int)(insn->u32_val & 3); /* 0=method,1=getter,2=setter */

                /* Build the member text.  Accessors must not be rendered as
                 * "name: function", which would create a data property. */
                char *member;
                if (mkind == 1 || mkind == 2) {
                    member = accessor_from_function_expr(
                        (mkind == 1) ? "get" : "set",
                        mname, key_len_of(r, insn), val.expr);
                } else {
                    sbuf_t msb; sb_init(&msb);
                    put_property_key(&msb, mname, key_len_of(r, insn));
                    sb_puts(&msb, ": ");
                    sb_puts(&msb, val.expr);
                    member = msb.buf;
                }
                if (!member) member = xstrdup(mname ? mname : "");

                /* If obj is "{}" (empty object literal), start building it */
                if (strcmp(obj.expr, "{}") == 0) {
                    sbuf_t sb; sb_init(&sb);
                    sb_putc(&sb, '{');
                    sb_putc(&sb, ' ');
                    sb_puts(&sb, member);
                    free(obj.expr);
                    free(val.expr);
                    free(member);
                    vs_push_take_prec(vs, sb.buf, PREC_ATOM, 0);
                } else if (is_open_object(obj.expr)) {
                    /* Continuing object construction - append member */
                    sbuf_t sb; sb_init(&sb);
                    sb_puts(&sb, obj.expr);
                    sb_puts(&sb, ", ");
                    sb_puts(&sb, member);
                    free(obj.expr);
                    free(val.expr);
                    free(member);
                    vs_push_take_prec(vs, sb.buf, PREC_ATOM, 0);
                } else {
                    free(member);
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
        case qjs_op_private_in:
        case qjs_op_mul_pow10:
        case qjs_op_math_mod:
        case qjs_op_is_undefined_or_null:
        case qjs_op_apply:
        case qjs_op_apply_eval:
        case qjs_op_eval:
            /* These are metadata/structural/rare ops - skip silently */
            return DECODE_SKIP;

        /* get_private_field: obj symbol -> value */
        case qjs_op_get_private_field: {
            slot_t sym = vs_pop(vs);
            slot_t obj = vs_pop(vs);
            char *e = private_field_expr(obj.expr, sym.expr);
            vs_push_take_prec(vs, e, PREC_CALL, 0);
            free(obj.expr);
            free(sym.expr);
            return DECODE_OK;
        }

        /* ===== Array construction with spread elements ===== */
        case qjs_op_append:
        case qjs_op_define_array_el: {
            slot_t val = vs_pop(vs);
            slot_t idx = vs_pop(vs);
            slot_t arr = vs_pop(vs);
            close_obj_if_open(&val);
            char *narr = array_literal_append(arr.expr, val.expr,
                                              op == qjs_op_append);
            if (narr) {
                arr.expr = narr;
                arr.prec = PREC_ATOM;
                arr.is_lvalue = 0;
            }
            free(val.expr);
            /* Keep the array and the (symbolic) index on the stack: the
             * trailing "inc" and "drop" instructions operate on the index.
             * Mark the index as an internal value so its final "drop" does
             * not emit a stray "0++" statement. */
            if (vs->top < MAX_STACK) vs->slots[vs->top++] = arr;
            else free(arr.expr);
            if (vs->top < MAX_STACK) {
                vs->slots[vs->top++] = idx;
                vs->slots[vs->top - 1].is_dup_copy = 1;
            } else {
                free(idx.expr);
            }
            return DECODE_OK;
        }

        /* ===== Object spread ===== */
        case qjs_op_copy_data_properties: {
            /* target source excludeList -> target source excludeList
             * Normally followed by two drops that discard source/exclude. */
            slot_t excl = vs_pop(vs);
            slot_t src = vs_pop(vs);
            slot_t obj = vs_pop(vs);
            if (strcmp(obj.expr, "{}") == 0 || is_open_object(obj.expr))
                object_literal_add_spread(&obj, &src);
            free(src.expr);
            free(excl.expr);
            if (vs->top < MAX_STACK) vs->slots[vs->top++] = obj;
            else free(obj.expr);
            vs_push_prec(vs, "_spread_src", PREC_ATOM, 0);
            vs_push_prec(vs, "_spread_excl", PREC_ATOM, 0);
            return DECODE_OK;
        }

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
                /* The value may itself be an object literal that is still
                 * open - close it before it becomes a property value. */
                close_obj_if_open(&val);
                /* If obj is "{}" (empty object literal), start building it */
                if (strcmp(obj.expr, "{}") == 0) {
                    sbuf_t sb; sb_init(&sb);
                    sb_putc(&sb, '{');
                    sb_puts(&sb, " ");
                    put_property_key(&sb, atom_name_of(r, insn),
                                     key_len_of(r, insn));
                    sb_printf(&sb, ": %s", val.expr);
                    /* Don't close - more fields may follow */
                    free(obj.expr);
                    free(val.expr);
                    /* Push the partially-built object (marked as open) */
                    vs_push_take_prec(vs, sb.buf, PREC_ATOM, 0);
                } else if (is_open_object(obj.expr)) {
                    /* Continuing object construction - append field */
                    sbuf_t sb; sb_init(&sb);
                    sb_puts(&sb, obj.expr);
                    sb_puts(&sb, ", ");
                    put_property_key(&sb, atom_name_of(r, insn),
                                     key_len_of(r, insn));
                    sb_printf(&sb, ": %s", val.expr);
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
 * Try / catch / finally reconstruction
 *
 * QuickJS compiles
 *
 *     try { A } catch (e) { B } finally { C }
 *
 * into
 *
 *     catch -> H            ; install the exception handler
 *     A
 *     nip_catch             ; remove the handler, keeping the completion value
 *     gosub -> F            ; run the finally block
 *     return
 *   H: put_loc e           ; bind the exception to e
 *     catch -> H2           ; handler for exceptions raised inside B
 *     B
 *     nip_catch
 *     gosub -> F
 *     return
 *   H2: gosub -> F          ; run C, then rethrow
 *      throw
 *   F: C
 *      ret
 *
 * The catch clause is optional (without it the handler simply runs the
 * finally block and rethrows), the finally clause is optional and the
 * completion value may be undefined - in that case `drop` replaces
 * `nip_catch`.
 * ========================================================= */

/* Net stack effect of an instruction (positive = net number of pushed slots).
 * The generic table is only accurate for the fixed-arity opcodes; the
 * call-like opcodes pop their arguments as well. */
static int insn_stack_delta(const ir_insn_t *insn) {
    if (!insn->info) return 0;
    int op = insn->op;
    int nargs = (int)insn->u32_val;
    switch (op) {
        case qjs_op_call:
        case qjs_op_call0:
        case qjs_op_call1:
        case qjs_op_call2:
        case qjs_op_call3:
        case qjs_op_tail_call:
            return 1 - (nargs + 1);
        case qjs_op_call_method:
        case qjs_op_tail_call_method:
        case qjs_op_call_constructor:
            return 1 - (nargs + 2);
        case qjs_op_array_from:
            return 1 - nargs;
        case qjs_op_eval:
            return 1 - nargs;
        default:
            return insn->info->n_push - insn->info->n_pop;
    }
}

/* Find the instruction that removes the catch marker installed at
 * `catch_idx`.  The marker lives at the bottom of the protected region's
 * stack frame, so it can only be removed once the frame became empty.
 * Returns the instruction index, or -1 when the region never completes
 * normally (it always throws or returns). */
static int find_catch_marker_end(ir_function_t *ir, int catch_idx, int stop) {
    int depth = 1;              /* the marker itself */
    int j = catch_idx + 1;
    while (j < stop) {
        ir_insn_t *insn = &ir->insns[j];
        if (insn->op == qjs_op_catch) {
            /* A nested protected region: skip over it entirely. */
            int sub = find_catch_marker_end(ir, j, stop);
            if (sub < 0) return -1;
            depth = (ir->insns[sub].op == qjs_op_nip_catch) ? 1 : 0;
            j = sub + 1;
            continue;
        }
        if (insn->op == qjs_op_nip_catch) {
            /* replaces the marker with the completion value */
            if (depth < 2) return -1;
            return j;
        }
        depth += insn_stack_delta(insn);
        if (insn->op == qjs_op_drop && depth == 0) return j;
        if (depth < 0) return -1;
        j++;
    }
    return -1;
}

/* Find the `ret` instruction that ends the finally block starting at `fi`. */
static int find_finally_ret(ir_function_t *ir, int fi, int stop) {
    int j = fi;
    while (j < stop) {
        int op = ir->insns[j].op;
        if (op == qjs_op_gosub) {
            /* a nested finally block - skip it */
            int32_t t = ir->insns[j].label_target;
            int sub = (t >= 0) ? find_finally_ret(ir, ir_find_insn(ir, (uint32_t)t), stop) : -1;
            if (sub < 0) return -1;
            j = sub + 1;
            continue;
        }
        if (op == qjs_op_ret) return j;
        j++;
    }
    return -1;
}

/* Description of the terminator that follows a protected region. */
typedef struct {
    int marker_end;   /* index of the marker removal, -1 if none */
    int exit_idx;     /* index of the return/goto leaving the region, -1 if none */
    int gosub_idx;    /* index of the gosub running the finally block, -1 if none */
} try_region_t;

static void analyze_try_region(ir_function_t *ir, int catch_idx, int stop, try_region_t *out) {
    out->marker_end = find_catch_marker_end(ir, catch_idx, stop);
    out->exit_idx = -1;
    out->gosub_idx = -1;
    int from = (out->marker_end >= 0) ? out->marker_end : stop;
    for (int j = from; j < stop; j++) {
        int op = ir->insns[j].op;
        if (out->gosub_idx < 0 && op == qjs_op_gosub) {
            out->gosub_idx = j;
            continue;
        }
        if (op == qjs_op_return || op == qjs_op_return_undef ||
            op == qjs_op_return_async || op == qjs_op_goto ||
            op == qjs_op_goto8 || op == qjs_op_goto16) {
            out->exit_idx = j;
            break;
        }
    }
}

/* Decompile a protected region and handle its terminator.
 *
 * `body_start`/`body_end` delimit the region's instructions, `ri` describes
 * the terminator that follows.  The region's completion value (if any) is
 * returned through *value_out; the caller takes ownership of it. */
static ir_stmt_t *decompile_try_region(decomp_ctx_t *ctx, int body_start, int body_end,
                                        const try_region_t *ri, char **value_out) {
    ir_function_t *ir = ctx->ir;
    int stack_base = ctx->vs.top;
    /* the catch marker sits at the bottom of the region's stack frame */
    vs_push_prec(&ctx->vs, "_catch", PREC_ATOM, 0);

    ir_stmt_t *body = decompile_range(ctx, body_start, body_end);

    /* The marker removal is not part of the body: emulate it here. */
    char *value = NULL;
    if (ri->marker_end >= 0 && ir->insns[ri->marker_end].op == qjs_op_nip_catch &&
        ctx->vs.top > stack_base + 1) {
        slot_t v = vs_pop(&ctx->vs);
        value = v.expr;
    }
    while (ctx->vs.top > stack_base) {
        slot_t v = vs_pop(&ctx->vs);
        free(v.expr);
    }

    /* A "return" right after the marker removal returns the region's
     * completion value, so the region ends with "return <value>". */
    int exit_op = (ri->exit_idx >= 0) ? ir->insns[ri->exit_idx].op : -1;
    if (value) {
        if (exit_op == qjs_op_return || exit_op == qjs_op_return_async) {
            body = block_append(body, ctx->is_script ? stmt_expr(value) : stmt_return(value));
            value = NULL;
        } else if (exit_op == qjs_op_return_undef) {
            free(value);
            value = NULL;
        }
    }
    if (value_out) *value_out = value;
    else free(value);
    return body;
}

/* Recognise a try/catch/finally construct starting at the `catch`
 * instruction `i`.  On success *out receives the statement and *next_idx
 * the index of the first instruction after the construct. */
static int recognize_try(decomp_ctx_t *ctx, int i, int *next_idx, ir_stmt_t **out) {
    ir_function_t *ir = ctx->ir;
    qjs_reader_t *r = ctx->r;
    qjs_function_t *fn = ctx->fn;

    ir_insn_t *insn = &ir->insns[i];
    if (insn->op != qjs_op_catch) return 0;
    if (insn->label_target < 0) return 0;

    int hc = ir_find_insn(ir, (uint32_t)insn->label_target);
    if (hc <= i || hc >= ir->count) return 0;

    /* ---- the catch clause ---- */
    char *catch_var = NULL;
    int catch_body_start = -1;
    int h2c = -1;
    int hop = ir->insns[hc].op;
    if (hop == qjs_op_put_loc || hop == qjs_op_put_loc8 ||
        hop == qjs_op_put_loc0 || hop == qjs_op_put_loc1 ||
        hop == qjs_op_put_loc2 || hop == qjs_op_put_loc3) {
        catch_var = loc_name(r, fn, ir->insns[hc].u32_val);
        catch_body_start = hc + 1;
    } else if (hop == qjs_op_put_arg || hop == qjs_op_put_arg0 ||
               hop == qjs_op_put_arg1 || hop == qjs_op_put_arg2 ||
               hop == qjs_op_put_arg3) {
        catch_var = arg_name(r, fn, ir->insns[hc].u32_val);
        catch_body_start = hc + 1;
    } else if (hop == qjs_op_drop && hc + 1 < ir->count &&
               ir->insns[hc + 1].op == qjs_op_catch) {
        catch_body_start = hc + 1;      /* optional catch binding */
    }
    if (catch_body_start >= 0) {
        if (catch_body_start >= ir->count ||
            ir->insns[catch_body_start].op != qjs_op_catch) {
            free(catch_var);
            return 0;                   /* cannot determine the catch extent */
        }
        int32_t t = ir->insns[catch_body_start].label_target;
        h2c = (t >= 0) ? ir_find_insn(ir, (uint32_t)t) : -1;
        catch_body_start++;
        if (h2c <= catch_body_start || h2c >= ir->count) {
            free(catch_var);
            return 0;
        }
    }

    /* ---- the try body ----
     *
     * On the normal-completion path QuickJS appends
     *
     *     drop; undefined; gosub -> F; drop; goto -> end
     *
     * right before the catch handler.  When that tail is present the
     * protected region ends at its first "drop" (the one removing the catch
     * offset).  When it is absent every path leaves the region (return,
     * break, continue or throw) and each such path carries its own
     * "nip_catch; gosub" pair, so the region ends at the handler itself.
     * Using the handler for that case keeps every early exit inside the
     * region: a linear "first nip_catch" scan would stop at the first
     * "return" and silently drop the rest of the block. */
    int normal_end = -1;
    if (hc - 5 >= i + 1 &&
        (ir->insns[hc - 1].op == qjs_op_goto ||
         ir->insns[hc - 1].op == qjs_op_goto8 ||
         ir->insns[hc - 1].op == qjs_op_goto16) &&
        ir->insns[hc - 2].op == qjs_op_drop &&
        ir->insns[hc - 3].op == qjs_op_gosub &&
        ir->insns[hc - 4].op == qjs_op_undefined &&
        ir->insns[hc - 5].op == qjs_op_drop)
        normal_end = hc - 5;

    try_region_t r1;
    r1.marker_end = normal_end;
    r1.exit_idx = (normal_end >= 0) ? hc - 1 : -1;
    r1.gosub_idx = -1;
    for (int j = i + 1; j < hc; j++) {
        if (ir->insns[j].op != qjs_op_gosub) continue;
        int32_t t = ir->insns[j].label_target;
        if (t < 0) continue;
        /* A nested try/finally inside the protected region has its own
         * gosub, but its finally block sits *before* this try's catch
         * handler (the parser emits the outer one only after all the
         * handlers).  This try's own finally therefore starts after `hc`. */
        if (ir_find_insn(ir, (uint32_t)t) < hc) continue;
        r1.gosub_idx = j;
        break;
    }

    int try_body_start = i + 1;
    int try_body_end = (normal_end >= 0) ? normal_end : hc;

    char *try_value = NULL;
    ir_stmt_t *try_body = decompile_try_region(ctx, try_body_start, try_body_end, &r1, &try_value);

    /* ---- the catch clause body ---- */
    ir_stmt_t *catch_body = NULL;
    if (catch_body_start >= 0) {
        try_region_t r2;
        analyze_try_region(ir, catch_body_start - 1, h2c, &r2);
        int cb_end = (r2.marker_end >= 0) ? r2.marker_end : h2c;
        char *cv = NULL;
        catch_body = decompile_try_region(ctx, catch_body_start, cb_end, &r2, &cv);
        free(cv);
    }

    /* ---- the finally block ---- */
    ir_stmt_t *finally_body = NULL;
    int end_idx = -1;
    if (r1.gosub_idx >= 0) {
        int32_t fpc = ir->insns[r1.gosub_idx].label_target;
        int fi = (fpc >= 0) ? ir_find_insn(ir, (uint32_t)fpc) : -1;
        if (fi >= 0 && fi < ir->count) {
            int ret_idx = find_finally_ret(ir, fi, ir->count);
            int fend = (ret_idx >= 0) ? ret_idx + 1 : ir->count;
            /* the finally block runs on top of the pending completion value
             * and the gosub return address - keep the stack balanced */
            int saved_top = ctx->vs.top;
            finally_body = decompile_range(ctx, fi, fend);
            while (ctx->vs.top > saved_top) {
                slot_t v = vs_pop(&ctx->vs);
                free(v.expr);
            }
            end_idx = fend;
        }
    }
    if (end_idx < 0) {
        /* without a finally block the construct ends after the handler that
         * rethrows the exception */
        end_idx = (h2c >= 0) ? h2c + 1 : hc;
    }

    /* The completion value survives a "goto" exit (it is the value of the
     * try statement); a "return" exit consumed it already. */
    int exit_op = (r1.exit_idx >= 0) ? ir->insns[r1.exit_idx].op : -1;
    if (try_value) {
        if (exit_op == qjs_op_goto || exit_op == qjs_op_goto8 || exit_op == qjs_op_goto16 ||
            exit_op < 0) {
            vs_push_take(&ctx->vs, try_value, 0, 0);
        } else {
            free(try_value);
        }
    }

    *out = stmt_try(try_body, catch_var, catch_body, finally_body);
    *next_idx = end_idx;
    return 1;
}

/* =========================================================
 * Class reconstruction
 *
 * QuickJS compiles a class declaration into a fixed instruction
 * sequence (see js_parse_class() in quickjs.c):
 *
 *   set_loc_uninitialized <cls_var>    ; inner (const) class name binding
 *   <heritage expression>               ; "undefined" when there is no
 *                                       ; 'extends' clause
 *   set_loc_uninitialized <fields_var>  ; <class_fields_init>
 *   push_const8 <ctor>
 *   define_class <Name> <flags>
 *   [ swap ] fclosure8 <m> define_method <name> <flags> [ swap ] ...
 *   undefined                            ; value of <class_fields_init>
 *   put_loc <fields_var>
 *   drop                                  ; drop the prototype
 *   set_loc <cls_var>
 *   [ dup fclosure8 <f> set_home_object call_method 0 drop ]   ; static fields
 *   close_loc <fields_var>
 *   put_var_init <Name>
 *
 * A 'swap' in front of a member marks it as static; the matching 'swap'
 * after the member restores the stack layout.  A static *field* produces an
 * empty "swap ... swap" pair because its initialiser lives in a separate
 * function.
 * ========================================================= */

/* Return the constant pool entry of the current function as a function. */
static qjs_function_t *cpool_func(decomp_ctx_t *ctx, uint32_t idx) {
    qjs_function_t *fn = ctx->fn;
    if (idx < (uint32_t)fn->cpool_count && fn->cpool[idx] &&
        fn->cpool[idx]->kind == QJS_VAL_FUNCTION)
        return fn->cpool[idx]->u.func.fn;
    return NULL;
}

static int is_op_put(const ir_insn_t *insn) {
    return insn->op == qjs_op_put_loc || insn->op == qjs_op_put_loc8 ||
           insn->op == qjs_op_put_loc0 || insn->op == qjs_op_put_loc1 ||
           insn->op == qjs_op_put_loc2 || insn->op == qjs_op_put_loc3;
}
static int is_op_set(const ir_insn_t *insn) {
    return insn->op == qjs_op_set_loc || insn->op == qjs_op_set_loc8 ||
           insn->op == qjs_op_set_loc0 || insn->op == qjs_op_set_loc1 ||
           insn->op == qjs_op_set_loc2 || insn->op == qjs_op_set_loc3;
}
static int is_op_fclosure(const ir_insn_t *insn) {
    return insn->op == qjs_op_fclosure || insn->op == qjs_op_fclosure8;
}

/* =========================================================
 * Class field initialisers
 *
 * A class with fields gets a hidden "class_fields_init" closure whose
 * body is a sequence of "this.<name> = <value>" statements.  Static
 * fields are run once on the class object, instance fields on every
 * construction.  Decompile that closure and turn the assignments back
 * into class field members.
 * ========================================================= */
static void harvest_class_fields(qjs_reader_t *r, qjs_function_t *fn,
                                 int is_static, stmt_list_t *members) {
    if (!fn) return;
    ir_stmt_t *body = ir_decompile_function(r, fn, 0, NULL);
    if (!body) return;

    ir_stmt_t **kids = body->children;
    int n = body->n_children;
    for (int i = 0; i < n; i++) {
        ir_stmt_t *s = kids[i];
        if (!s) continue;
        const char *text = NULL;
        char *own = NULL;
        if (s->kind == IR_STMT_EXPR && s->expr) {
            text = s->expr;
        } else if (s->kind == IR_STMT_ASSIGN && s->lvalue && s->rhs) {
            own = xmalloc(strlen(s->lvalue) + strlen(s->rhs) + 4);
            sprintf(own, "%s = %s", s->lvalue, s->rhs);
            text = own;
        }
        if (text && strncmp(text, "this.", 5) == 0) {
            const char *p = text + 5;
            const char *eq = strstr(p, " = ");
            if (eq && eq != p) {
                size_t nlen = (size_t)(eq - p);
                char *name = xmalloc(nlen + 1);
                memcpy(name, p, nlen);
                name[nlen] = '\0';
                char *value = xstrdup(eq + 3);
                sl_push(members, stmt_class_member(name, value, 3,
                                                   is_static, NULL));
                free(name);
                free(value);
            }
        }
        free(own);
    }
    ir_stmt_free(body);
}

/* =========================================================
 * ES module support
 * ========================================================= */

/* Find the index of the export entry that exports the module level variable
 * `var_idx` under the name `ename`, or -1 when there is none. */
static int module_find_export(decomp_ctx_t *ctx, int var_idx, const char *ename) {
    if (!ctx->module) return -1;
    for (int i = 0; i < ctx->module->export_count; i++) {
        qjs_export_entry_t *e = &ctx->module->exports[i];
        if (e->export_type != 0 || e->var_idx != var_idx) continue;
        if (strcmp(qjs_atom_str(ctx->r, e->export_name_atom), ename) == 0)
            return i;
    }
    return -1;
}

/* Mark an export entry as consumed by an inline declaration. */
static void module_use_export(decomp_ctx_t *ctx, int entry) {
    if (entry >= 0 && entry < ctx->module_export_used_count)
        ctx->module_export_used[entry] = 1;
}

/* Name of a module level closure variable. */
static char *module_var_name(decomp_ctx_t *ctx, int var_idx) {
    if (var_idx < 0 || var_idx >= ctx->fn->closure_var_count)
        return xstrdup("");
    return sanitize_binding_name(
        qjs_atom_str(ctx->r, ctx->fn->closure_vars[var_idx].var_name_atom), -1);
}

/* True when the closure variable is bound by an import statement. */
static int module_is_import(decomp_ctx_t *ctx, int var_idx) {
    if (!ctx->module) return 0;
    for (int i = 0; i < ctx->module->import_count; i++)
        if (ctx->module->imports[i].var_idx == var_idx) return 1;
    return 0;
}

static void module_mark_declared(decomp_ctx_t *ctx, int var_idx) {
    if (var_idx >= 0 && var_idx < ctx->module_declared_count)
        ctx->module_declared[var_idx] = 1;
}

static int module_is_declared(decomp_ctx_t *ctx, int var_idx) {
    if (var_idx < 0 || var_idx >= ctx->module_declared_count) return 0;
    return ctx->module_declared[var_idx];
}

/* Determine how a module level function declaration is exported:
 *   NULL      - the function is not exported
 *   "default" - "export default function ..."
 *   <name>    - "export function <name>(...)"
 * The matching export entry is marked as consumed. */
/* Returns a malloc'd export name, or NULL when the function is not exported.
 * The caller owns the result. */
static char *module_func_export(decomp_ctx_t *ctx, int vref) {
    char *lname = module_var_name(ctx, vref);
    int e = module_find_export(ctx, vref, lname);
    if (e >= 0) {
        module_use_export(ctx, e);
        return lname;
    }
    e = module_find_export(ctx, vref, "default");
    if (e >= 0) {
        module_use_export(ctx, e);
        free(lname);
        return xstrdup("default");
    }
    free(lname);
    return NULL;
}

/* Build the statement for a module level variable definition.
 * The closure variable flags tell whether the binding is a "const", a "let"
 * or a plain "var"; the module export table tells whether it is exported. */
static ir_stmt_t *module_decl_stmt(decomp_ctx_t *ctx, int vref, char *rhs) {
    qjs_closure_var_t *cv = &ctx->fn->closure_vars[vref];
    const char *rawname = qjs_atom_str(ctx->r, cv->var_name_atom);
    /* Module bindings are identifiers too, so sanitize before emitting. */
    char *name = sanitize_binding_name(rawname, -1);
    int kind = cv->is_const ? 2 : (cv->is_lexical ? 1 : 0);

    if (strcmp(rawname, "_default_") == 0) {
        /* "export default <expr>;" - the value is stored in the internal
         * "_default_" binding. */
        int e = module_find_export(ctx, vref, "default");
        module_use_export(ctx, e);
        sbuf_t sb; sb_init(&sb);
        if (e >= 0) sb_puts(&sb, "export default ");
        else sb_printf(&sb, "%s = ", name);
        sb_puts(&sb, rhs ? rhs : "undefined");
        free(rhs);
        free(name);
        return stmt_expr(sb.buf);
    }

    ir_stmt_t *s = stmt_decl(name, rhs, kind);
    free(name);
    int e = module_find_export(ctx, vref, rawname);
    if (e >= 0) {
        module_use_export(ctx, e);
        s->export_name = xstrdup(s->lvalue);
    }
    return s;
}

/* Append the "export { ... };" statements for all export entries that were
 * not consumed by an inline declaration.  This covers aliased exports
 * ("export { a as b };") and re-exported imports. */
static void module_add_missing_exports(decomp_ctx_t *ctx, ir_stmt_t *result) {
    if (!ctx->module || !result || result->kind != IR_STMT_BLOCK) return;
    for (int i = 0; i < ctx->module->export_count; i++) {
        qjs_export_entry_t *e = &ctx->module->exports[i];
        if (e->export_type != 0) continue;             /* indirect export */
        if (i < ctx->module_export_used_count && ctx->module_export_used[i]) continue;
        int vref = e->var_idx;
        if (vref < 0 || vref >= ctx->fn->closure_var_count) continue;
        const char *ename = qjs_atom_str(ctx->r, e->export_name_atom);
        char *lname = module_var_name(ctx, vref);
        if (!lname || !*lname) { free(lname); continue; }
        sbuf_t sb; sb_init(&sb);
        if (strcmp(ename, lname) == 0)
            sb_printf(&sb, "export { %s }", lname);
        else
            sb_printf(&sb, "export { %s as %s }", lname, ename);
        free(lname);
        block_append(result, stmt_expr(sb.buf));
    }
}

/* Recognise the module prologue that QuickJS emits for hoisted function
 * declarations (instantiate_hoisted_definitions() in quickjs.c):
 *
 *     push_this
 *     if_false8  L
 *     fclosure8  <cpool>      ; the function object
 *     put_var_ref<n> <var>    ; store it into the module scope variable
 *     ...
 *     return_undef
 *   L:
 *
 * The "if (this)" guard is never taken inside a module (the module scope
 * "this" is undefined), so the block is dead code at run time.  The function
 * declarations are re-materialised as top level declarations instead.
 *
 * On success *out receives a malloc'ed array of statements, *out_count its
 * size and *next_idx the index of the first instruction after the prologue.
 */
static int recognize_module_prologue(decomp_ctx_t *ctx, int i, int *next_idx,
                                      ir_stmt_t ***out_items, int *out_count) {
    ir_function_t *ir = ctx->ir;
    qjs_reader_t *r = ctx->r;

    *out_items = NULL;
    *out_count = 0;

    if (i + 1 >= ir->count) return 0;
    if (ir->insns[i].op != qjs_op_push_this) return 0;
    ir_insn_t *br = &ir->insns[i + 1];
    if (br->op != qjs_op_if_false && br->op != qjs_op_if_false8) return 0;

    stmt_list_t sl; sl_init(&sl);
    int j = i + 2;
    while (j < ir->count) {
        ir_insn_t *fc = &ir->insns[j];
        if (!is_op_fclosure(fc)) break;
        if (j + 1 >= ir->count) { sl_free(&sl); return 0; }
        ir_insn_t *pv = &ir->insns[j + 1];
        if (pv->op != qjs_op_put_var_ref && pv->op != qjs_op_put_var_ref0 &&
            pv->op != qjs_op_put_var_ref1 && pv->op != qjs_op_put_var_ref2 &&
            pv->op != qjs_op_put_var_ref3) { sl_free(&sl); return 0; }
        qjs_function_t *f = cpool_func(ctx, fc->u32_val);
        if (!f) { sl_free(&sl); return 0; }
        int vref = (int)pv->u32_val;
        if (vref < 0 || vref >= ctx->fn->closure_var_count) { sl_free(&sl); return 0; }

        char *text = fn_expr_string(r, f);
        char *ename = module_func_export(ctx, vref);
        sl_push(&sl, stmt_func_decl(text, ename));
        free(ename);
        module_mark_declared(ctx, vref);
        j += 2;
    }

    /* The prologue must be terminated by "return_undef" and the branch must
     * target the instruction right behind it. */
    if (j >= ir->count || ir->insns[j].op != qjs_op_return_undef) { sl_free(&sl); return 0; }
    if (j + 1 >= ir->count || ir->insns[j + 1].pc != (uint32_t)br->label_target) {
        sl_free(&sl);
        return 0;
    }

    *out_items = sl.items;
    *out_count = sl.count;
    sl.items = NULL; sl.count = sl.cap = 0;
    *next_idx = j + 1;
    return 1;
}

/* Recognise a class declaration whose OP_define_class is at index `i`.
 * On success *out receives the class statement and *next_idx the index of
 * the first instruction after the class. */
static int recognize_class(decomp_ctx_t *ctx, int i, int *next_idx, ir_stmt_t **out) {
    ir_function_t *ir = ctx->ir;
    qjs_reader_t *r = ctx->r;

    ir_insn_t *def = &ir->insns[i];
    if (def->op != qjs_op_define_class) return 0;

    /* The constructor is pushed right before define_class. */
    if (i < 1) return 0;
    ir_insn_t *prev = &ir->insns[i - 1];
    if (prev->op != qjs_op_push_const && prev->op != qjs_op_push_const8) return 0;
    qjs_function_t *ctor_fn = cpool_func(ctx, prev->u32_val);
    if (!ctor_fn) return 0;

    /* Class name */
    const char *cname = atom_name_of(r, def);
    if (!cname || !*cname || strncmp(cname, "_atom_oob_", 10) == 0) return 0;

    /* The heritage expression is the value below the constructor. */
    if (ctx->vs.top < 2) return 0;

    /* ---- collect the members ---- */
    stmt_list_t members; sl_init(&members);

    /* The constructor is the function referenced by "push_const8 <ctor>". */
    {
        ir_stmt_t *body = ir_decompile_function(r, ctor_fn, 0, NULL);
        char *args = fn_args_string_body(r, ctor_fn, body);
        /* Synthesized constructors (the class has no explicit one) reduce
         * to an empty body once their internal initialisation is removed.
         * Leave them out: the implicit JavaScript constructor is identical. */
        int empty = body && body->kind == IR_STMT_BLOCK && body->n_children == 0;
        if (empty) {
            ir_stmt_free(body);
        } else {
            sl_push(&members, stmt_class_member("constructor", args, 0, 0, body));
        }
        free(args);
    }

    int j = i + 1;
    int failed = 0;

    /* Classes with private members start with one "private_symbol; put_loc"
     * pair per private name, followed by stack shuffles.  These values only
     * feed the hidden field initialiser closures, so skip them here.  The
     * private field names themselves are recovered from the initialiser. */
    while (j < ir->count && ir->insns[j].op == qjs_op_private_symbol) {
        j++;
        if (j < ir->count && is_op_put(&ir->insns[j])) j++;
        while (j < ir->count && ir->insns[j].op == qjs_op_swap) j++;
    }

    while (j < ir->count) {
        int is_static = 0;
        if (ir->insns[j].op == qjs_op_swap) {
            is_static = 1;
            j++;
        }
        if (j < ir->count && is_op_fclosure(&ir->insns[j]) &&
            j + 1 < ir->count && ir->insns[j + 1].op == qjs_op_define_method) {
            qjs_function_t *mfn = cpool_func(ctx, ir->insns[j].u32_val);
            if (!mfn) { failed = 1; break; }
            const char *mname = atom_name_of(r, &ir->insns[j + 1]);
            uint32_t flags = ir->insns[j + 1].u32_val;
            int kind = (int)(flags & 3);   /* 0=method 1=getter 2=setter */
            ir_stmt_t *body = ir_decompile_function(r, mfn, 0, NULL);
            char *args = fn_args_string_body(r, mfn, body);
            sl_push(&members, stmt_class_member(mname, args, kind, is_static, body));
            free(args);
            j += 2;
            if (is_static) {
                /* the matching swap restores the stack layout */
                if (j < ir->count && ir->insns[j].op == qjs_op_swap) j++;
                else { failed = 1; break; }
            }
            continue;
        }
        if (is_static) {
            /* a static field: "swap ... swap" with an empty body */
            if (j < ir->count && ir->insns[j].op == qjs_op_swap) { j++; continue; }
            failed = 1;
        }
        break;
    }
    if (failed) {
        sl_free(&members);
        return 0;
    }

    /* ---- the tail of the class statement ---- */
    qjs_function_t *fields_fn = NULL;   /* instance field initialiser */
    qjs_function_t *static_fn = NULL;   /* static field initialiser */
    /* value of <class_fields_init>: "undefined" or a closure */
    if (j < ir->count && ir->insns[j].op == qjs_op_undefined) {
        j++;
    } else if (j < ir->count && is_op_fclosure(&ir->insns[j]) &&
               j + 1 < ir->count && ir->insns[j + 1].op == qjs_op_set_home_object) {
        fields_fn = cpool_func(ctx, ir->insns[j].u32_val);
        j += 2;
    } else {
        sl_free(&members);
        return 0;
    }
    /* put_loc <fields_var> */
    if (j >= ir->count || !is_op_put(&ir->insns[j])) { sl_free(&members); return 0; }
    j++;
    /* drop (the prototype) */
    if (j < ir->count && ir->insns[j].op == qjs_op_drop) j++;
    /* set_loc <cls_var> */
    if (j < ir->count && is_op_set(&ir->insns[j])) j++;
    /* static field initialiser: dup fclosure8 <f> set_home_object call_method 0 drop */
    if (j < ir->count && ir->insns[j].op == qjs_op_dup &&
        j + 1 < ir->count && is_op_fclosure(&ir->insns[j + 1]) &&
        j + 2 < ir->count && ir->insns[j + 2].op == qjs_op_set_home_object) {
        static_fn = cpool_func(ctx, ir->insns[j + 1].u32_val);
        j += 3;
        if (j < ir->count && ir->insns[j].op == qjs_op_call_method) j++;
        if (j < ir->count && ir->insns[j].op == qjs_op_drop) j++;
    }
    /* close_loc <fields_var> (one per captured class variable) */
    while (j < ir->count && ir->insns[j].op == qjs_op_close_loc) j++;
    /* put_var_init <Name> */
    if (j >= ir->count || ir->insns[j].op != qjs_op_put_var_init) {
        sl_free(&members);
        return 0;
    }
    j++;

    /* ---- collect class fields (methods first, fields prepended) ---- */
    {
        stmt_list_t fields; sl_init(&fields);
        harvest_class_fields(r, fields_fn, 0, &fields);
        harvest_class_fields(r, static_fn, 1, &fields);
        if (fields.count > 0) {
            int total = fields.count + members.count;
            ir_stmt_t **all = xmalloc((size_t)total * sizeof(ir_stmt_t *));
            for (int k = 0; k < fields.count; k++) all[k] = fields.items[k];
            for (int k = 0; k < members.count; k++) all[fields.count + k] = members.items[k];
            free(fields.items);
            free(members.items);
            members.items = all;
            members.count = total;
            members.cap = total;
        }
    }

    /* ---- build the statement ---- */
    /* The heritage is the second entry from the top of the value stack. */
    slot_t ctor_slot = vs_pop(&ctx->vs);
    slot_t heritage = vs_pop(&ctx->vs);
    free(ctor_slot.expr);

    char *heritage_str = NULL;
    if (heritage.expr && *heritage.expr &&
        strcmp(heritage.expr, "undefined") != 0 &&
        strcmp(heritage.expr, "_unknown") != 0) {
        heritage_str = heritage.expr;
        heritage.expr = NULL;
    }
    free(heritage.expr);

    /* The class value itself is consumed by "put_var_init". */
    ir_stmt_t *cls = stmt_class(cname, heritage_str, members.items, members.count);
    members.items = NULL; members.count = members.cap = 0;
    free(heritage_str);

    *out = cls;
    *next_idx = j;
    return 1;
}

/* =========================================================
 * Destructuring patterns
 *
 * QuickJS compiles "const {a, b} = obj" (and the array
 * equivalent) into a fixed instruction sequence:
 *
 *      undefined          ; placeholder for the source value
 *      dup
 *      is_undefined
 *      if_true8  Lsrc    ; always taken (the test is constant)
 *  Lbody:
 *      to_object          ; object pattern
 *      get_field2 a
 *      put_var_init a
 *      ...
 *      drop
 *      goto8    Lend
 *  Lsrc:
 *      drop
 *      <instructions producing the source value>
 *      goto8    Lbody
 *  Lend:
 *
 * The array variant uses "for_of_start" / "for_of_next" instead
 * of "to_object" / "get_field2".
 * ========================================================= */

/* A small list of strings used to build pattern texts. */
typedef struct {
    char **v;
    int n;
    int cap;
} patlist_t;

static void pat_init(patlist_t *p) { p->v = NULL; p->n = 0; p->cap = 0; }
static void pat_free(patlist_t *p) {
    for (int i = 0; i < p->n; i++) free(p->v[i]);
    free(p->v);
    p->v = NULL; p->n = p->cap = 0;
}
static void pat_add(patlist_t *p, char *s) {
    if (p->n >= p->cap) {
        p->cap = p->cap ? p->cap * 2 : 8;
        p->v = xrealloc(p->v, p->cap * sizeof(char *));
    }
    p->v[p->n++] = s;
}
static char *pat_join(patlist_t *p, const char *sep) {
    sbuf_t sb; sb_init(&sb);
    for (int i = 0; i < p->n; i++) {
        if (i) sb_puts(&sb, sep);
        sb_puts(&sb, p->v[i]);
    }
    return sb.buf;
}

/* Name of the variable a "put_*" instruction stores into (NULL if the
 * instruction is not a store). */
static char *put_target_name(decomp_ctx_t *ctx, ir_insn_t *insn) {
    qjs_reader_t *r = ctx->r;
    qjs_function_t *fn = ctx->fn;
    int op = insn->op;

    if (op == qjs_op_put_loc || op == qjs_op_put_loc8 ||
        op == qjs_op_put_loc0 || op == qjs_op_put_loc1 ||
        op == qjs_op_put_loc2 || op == qjs_op_put_loc3 ||
        op == qjs_op_put_loc_check || op == qjs_op_put_loc_check_init)
        return loc_name(r, fn, insn->u32_val);
    if (op == qjs_op_put_arg || op == qjs_op_put_arg0 ||
        op == qjs_op_put_arg1 || op == qjs_op_put_arg2 || op == qjs_op_put_arg3)
        return arg_name(r, fn, insn->u32_val);
    if (op == qjs_op_put_var || op == qjs_op_put_var_init ||
        op == qjs_op_put_var_strict)
        return sanitize_binding_name(atom_name_of(r, insn), -1);
    if (op == qjs_op_put_var_ref || op == qjs_op_put_var_ref0 ||
        op == qjs_op_put_var_ref1 || op == qjs_op_put_var_ref2 ||
        op == qjs_op_put_var_ref3 || op == qjs_op_put_var_ref_check ||
        op == qjs_op_put_var_ref_check_init) {
        uint32_t vref = insn->u32_val;
        if (vref < (uint32_t)fn->closure_var_count)
            return sanitize_binding_name(
                qjs_atom_str(r, fn->closure_vars[vref].var_name_atom), -1);
    }
    return NULL;
}

/* Decode the expression produced by the instruction range [start, end)
 * using an isolated value stack. */
static char *decode_range_expr(decomp_ctx_t *ctx, int start, int end) {
    decomp_ctx_t tmp;
    memset(&tmp, 0, sizeof(tmp));
    tmp.r = ctx->r;
    tmp.fn = ctx->fn;
    tmp.ir = ctx->ir;
    tmp.cpool_base = ctx->cpool_base;
    tmp.is_script = ctx->is_script;
    vs_init(&tmp.vs);

    ir_stmt_t *blk = decompile_range(&tmp, start, end);

    char *res = NULL;
    if (tmp.vs.top > 0) {
        slot_t *top = &tmp.vs.slots[tmp.vs.top - 1];
        /* A "dup; put_x" sequence leaves the value plus a marker.  In an
         * expression context (for example the right side of && or ||) the
         * side effect is part of the expression: reconstruct "(x = value)". */
        if (top->is_dup_copy && blk && blk->kind == IR_STMT_BLOCK &&
            blk->n_children > 0 && top->expr) {
            ir_stmt_t *last = blk->children[blk->n_children - 1];
            if (last && last->kind == IR_STMT_ASSIGN && last->lvalue &&
                last->rhs && strcmp(last->rhs, top->expr) == 0) {
                sbuf_t sb; sb_init(&sb);
                sb_putc(&sb, '(');
                sb_puts(&sb, last->lvalue);
                sb_puts(&sb, " = ");
                sb_puts(&sb, last->rhs);
                sb_putc(&sb, ')');
                res = sb.buf;
            }
        }
        if (!res && top->expr && *top->expr) res = xstrdup(top->expr);
    }
    ir_stmt_free(blk);
    vs_free(&tmp.vs);
    return res;
}

/* Like decode_range_expr(), but starts with "base" on the value stack.  This
 * is used to reconstruct the access part of an optional chain: the bytecode
 * branch contains only ".field" / "[index]" / "(args)" and needs the object
 * expression injected again. */
static char *decode_range_expr_base(decomp_ctx_t *ctx, const char *base,
                                    int start, int end) {
    decomp_ctx_t tmp;
    memset(&tmp, 0, sizeof(tmp));
    tmp.r = ctx->r;
    tmp.fn = ctx->fn;
    tmp.ir = ctx->ir;
    tmp.cpool_base = ctx->cpool_base;
    tmp.is_script = ctx->is_script;
    vs_init(&tmp.vs);
    if (base) vs_push_prec(&tmp.vs, xstrdup(base), PREC_ATOM, 0);

    ir_stmt_t *blk = decompile_range(&tmp, start, end);
    char *res = NULL;
    if (tmp.vs.top > 0) {
        const char *e = tmp.vs.slots[tmp.vs.top - 1].expr;
        if (e && *e) res = xstrdup(e);
    }
    ir_stmt_free(blk);
    vs_free(&tmp.vs);
    return res;
}

/* Parse the body of an object destructuring pattern.
 *
 * On entry the "to_object" instruction has been consumed and *j points at
 * the first field access.  The pattern parts are appended to *parts and the
 * bound variable names to *names.  On success *j points at the "drop" that
 * closes this nesting level. */
static int dstr_obj_body(decomp_ctx_t *ctx, int *jp, patlist_t *parts, patlist_t *names) {
    ir_function_t *ir = ctx->ir;
    qjs_reader_t *r = ctx->r;
    int j = *jp;

    while (j < ir->count) {
        int op = ir->insns[j].op;

        if (op == qjs_op_get_field2) {
            char *prop = xstrdup(atom_name_of(r, &ir->insns[j]));
            j++;
            if (j >= ir->count) { free(prop); return 0; }

            /* nested object pattern */
            if (ir->insns[j].op == qjs_op_to_object) {
                j++;
                patlist_t inner; pat_init(&inner);
                patlist_t innern; pat_init(&innern);
                int inner_start = j;
                if (!dstr_obj_body(ctx, &inner_start, &inner, &innern)) {
                    pat_free(&inner); pat_free(&innern); free(prop);
                    return 0;
                }
                j = inner_start;
                /* the inner level is closed by a "drop" */
                if (j >= ir->count || ir->insns[j].op != qjs_op_drop) {
                    pat_free(&inner); pat_free(&innern); free(prop);
                    return 0;
                }
                j++;
                sbuf_t sb; sb_init(&sb);
                sb_puts(&sb, prop);
                sb_puts(&sb, ": ");
                sb_puts(&sb, pat_join(&inner, ", "));
                pat_free(&inner);
                free(prop);
                pat_add(parts, sb.buf);
                for (int k = 0; k < innern.n; k++) pat_add(names, xstrdup(innern.v[k]));
                pat_free(&innern);
                continue;
            }

            /* default value: "dup; is_undefined; if_false <target>" */
            if (j + 2 < ir->count &&
                ir->insns[j].op == qjs_op_dup &&
                ir->insns[j + 1].op == qjs_op_is_undefined &&
                (ir->insns[j + 2].op == qjs_op_if_false ||
                 ir->insns[j + 2].op == qjs_op_if_false8)) {
                int32_t tgt = ir->insns[j + 2].label_target;
                int t_idx = ir_find_insn(ir, (uint32_t)tgt);
                if (t_idx < 0) { free(prop); return 0; }
                char *def = NULL;
                if (t_idx > j + 4) def = decode_range_expr(ctx, j + 4, t_idx);
                if (!def) def = xstrdup("undefined");
                /* the store follows the branch target */
                j = t_idx;
                if (j >= ir->count) { free(prop); free(def); return 0; }
                char *target = put_target_name(ctx, &ir->insns[j]);
                if (!target) { free(prop); free(def); return 0; }
                j++;
                sbuf_t sb; sb_init(&sb);
                sb_puts(&sb, prop);
                sb_puts(&sb, " = ");
                sb_puts(&sb, def);
                free(prop);
                free(def);
                pat_add(parts, sb.buf);
                pat_add(names, xstrdup(target));
                free(target);
                continue;
            }

            /* plain property */
            char *target = put_target_name(ctx, &ir->insns[j]);
            if (!target) { free(prop); return 0; }
            j++;
            if (strcmp(prop, target) == 0) {
                pat_add(parts, prop);          /* shorthand - takes ownership */
            } else {
                sbuf_t sb; sb_init(&sb);
                sb_puts(&sb, prop);
                sb_puts(&sb, ": ");
                sb_puts(&sb, target);
                free(prop);
                pat_add(parts, sb.buf);
            }
            pat_add(names, xstrdup(target));
            free(target);
            continue;
        }

        /* "var" destructuring uses a variable reference:
         *   dup; make_var_ref <name>; rot3l; get_field <prop>; put_ref_value */
        if (op == qjs_op_dup && j + 4 < ir->count &&
            ir->insns[j + 1].op == qjs_op_make_var_ref &&
            ir->insns[j + 2].op == qjs_op_rot3l &&
            ir->insns[j + 3].op == qjs_op_get_field &&
            ir->insns[j + 4].op == qjs_op_put_ref_value) {
            char *target = xstrdup(atom_name_of(r, &ir->insns[j + 1]));
            char *prop = xstrdup(atom_name_of(r, &ir->insns[j + 3]));
            j += 5;
            pat_add(names, xstrdup(target));
            if (strcmp(prop, target) == 0) {
                pat_add(parts, target);          /* takes ownership */
            } else {
                sbuf_t sb; sb_init(&sb);
                sb_puts(&sb, prop);
                sb_puts(&sb, ": ");
                sb_puts(&sb, target);
                free(target);
                pat_add(parts, sb.buf);
            }
            free(prop);
            continue;
        }

        break;
    }
    *jp = j;
    return 1;
}

/* Parse the body of an array destructuring pattern.
 *
 * On entry the "for_of_start" instruction has been consumed and *j points
 * at the first "for_of_next".  On success *j points at the
 * "iterator_close". */
static int dstr_arr_body(decomp_ctx_t *ctx, int *jp, patlist_t *parts, patlist_t *names) {
    ir_function_t *ir = ctx->ir;
    int j = *jp;

    while (j < ir->count && ir->insns[j].op == qjs_op_for_of_next) {
        j++;
        if (j < ir->count && ir->insns[j].op == qjs_op_drop) j++;
        else return 0;
        if (j >= ir->count) return 0;
        char *target = put_target_name(ctx, &ir->insns[j]);
        if (!target) return 0;
        j++;
        pat_add(names, xstrdup(target));
        pat_add(parts, target);       /* takes ownership */
    }
    *jp = j;
    return 1;
}

/* Determine the declaration kind (0=var, 1=let, 2=const) of a variable. */
static int decl_kind_of(decomp_ctx_t *ctx, const char *name) {
    qjs_reader_t *r = ctx->r;
    qjs_function_t *fn = ctx->fn;
    ir_function_t *ir = ctx->ir;

    for (int j = 0; j < fn->vardefs_count; j++) {
        /* `name` is sanitized at the use site; sanitize the vardef name the
         * same way before comparing. */
        char *vn = sanitize_binding_name(
            qjs_atom_str(r, fn->vardefs[j].var_name_atom), -1);
        int match = (strcmp(vn, name) == 0);
        free(vn);
        if (!match) continue;
        if (fn->vardefs[j].is_const) return 2;
        if (fn->vardefs[j].is_lexical) return 1;
        return 0;
    }
    for (int j = 0; j < ir->count; j++) {
        if (ir->insns[j].op != qjs_op_define_var) continue;
        char *dn = sanitize_binding_name(atom_name_of(r, &ir->insns[j]), -1);
        int match = (strcmp(dn, name) == 0);
        free(dn);
        if (!match) continue;
        uint32_t flags = ir->insns[j].u32_val;
        if (flags & 0x40) return 0;                 /* function declaration */
        if (flags & 0x80) return (flags & 0x02) ? 1 : 2;
        return 0;
    }
    return 0;
}

/* Recognise a destructuring declaration whose prologue starts at index `i`.
 * On success *out receives the declaration and *next_idx the index of the
 * first instruction after the pattern. */
static int recognize_destructuring(decomp_ctx_t *ctx, int i, int *next_idx,
                                   ir_stmt_t **out) {
    ir_function_t *ir = ctx->ir;

    if (i + 3 >= ir->count) return 0;
    if (ir->insns[i].op != qjs_op_undefined) return 0;
    if (ir->insns[i + 1].op != qjs_op_dup) return 0;
    if (ir->insns[i + 2].op != qjs_op_is_undefined) return 0;
    if (ir->insns[i + 3].op != qjs_op_if_true &&
        ir->insns[i + 3].op != qjs_op_if_true8) return 0;

    int32_t src_pc = ir->insns[i + 3].label_target;
    int src_idx = ir_find_insn(ir, (uint32_t)src_pc);
    if (src_idx < 0 || src_idx <= i + 3) return 0;
    /* the source branch starts by dropping the placeholder */
    if (ir->insns[src_idx].op != qjs_op_drop) return 0;

    /* find the "goto" that ends the source branch */
    int goto_idx = -1;
    for (int j = src_idx + 1; j < ir->count; j++) {
        int op = ir->insns[j].op;
        if (op == qjs_op_goto || op == qjs_op_goto8) { goto_idx = j; break; }
        if (op == qjs_op_return || op == qjs_op_return_undef ||
            op == qjs_op_return_async || op == qjs_op_throw)
            return 0;
    }
    if (goto_idx < 0) return 0;

    int32_t body_pc = ir->insns[goto_idx].label_target;
    int body_idx = ir_find_insn(ir, (uint32_t)body_pc);
    if (body_idx < 0) return 0;
    if (body_idx <= i + 3 || body_idx >= goto_idx) return 0;

    /* ---- the pattern body ---- */
    patlist_t parts; pat_init(&parts);
    patlist_t names; pat_init(&names);
    int j = body_idx;
    int is_object = 0;
    int ok = 0;

    if (ir->insns[j].op == qjs_op_to_object) {
        is_object = 1;
        j++;
        ok = dstr_obj_body(ctx, &j, &parts, &names);
        if (ok) {
            if (j >= ir->count || ir->insns[j].op != qjs_op_drop) ok = 0;
            else j++;
        }
    } else if (ir->insns[j].op == qjs_op_for_of_start) {
        j++;
        ok = dstr_arr_body(ctx, &j, &parts, &names);
        if (ok) {
            if (j >= ir->count || ir->insns[j].op != qjs_op_iterator_close) ok = 0;
            else j++;
        }
    }
    if (!ok) {
        pat_free(&parts);
        pat_free(&names);
        return 0;
    }

    /* the pattern body ends with a goto to the continuation */
    if (j >= ir->count ||
        (ir->insns[j].op != qjs_op_goto && ir->insns[j].op != qjs_op_goto8)) {
        pat_free(&parts);
        pat_free(&names);
        return 0;
    }
    int32_t end_pc = ir->insns[j].label_target;
    int end_idx = ir_find_insn(ir, (uint32_t)end_pc);
    if (end_idx < 0) end_idx = j + 1;
    if (end_idx <= goto_idx) {
        pat_free(&parts);
        pat_free(&names);
        return 0;
    }

    /* the source expression */
    char *src = decode_range_expr(ctx, src_idx + 1, goto_idx);
    if (!src || !*src) {
        free(src);
        pat_free(&parts);
        pat_free(&names);
        return 0;
    }

    /* ---- build the statement ---- */
    sbuf_t sb; sb_init(&sb);
    sb_putc(&sb, is_object ? '{' : '[');
    sb_puts(&sb, pat_join(&parts, ", "));
    sb_putc(&sb, is_object ? '}' : ']');
    pat_free(&parts);

    int decl_kind = names.n > 0 ? decl_kind_of(ctx, names.v[0]) : 2;
    pat_free(&names);

    *out = stmt_destruct(sb.buf, src, decl_kind);
    *next_idx = end_idx;
    return 1;
}

/* =========================================================
 * switch reconstruction
 *
 * QuickJS compiles
 *
 *     switch (disc) {
 *       case v1:                       // several labels may share a body
 *       case v2: BODY1
 *       case v3: BODY2
 *       default: BODYD
 *     }
 *
 * into
 *
 *     <disc>
 *     dup; <v1>; strict_eq; if_true  -> BODY1
 *     dup; <v2>; strict_eq; if_false -> NEXT_TEST
 *   BODY1:
 *     ...
 *     goto -> SWITCH_END               ;; "break"
 *   NEXT_TEST:
 *     dup; <v3>; strict_eq; if_false -> DEFAULT
 *   BODY2:
 *     ...
 *     goto -> SWITCH_END
 *   DEFAULT:
 *     BODYD
 *   SWITCH_END:
 *     drop                             ;; discard the discriminant
 *
 * The recogniser rebuilds the switch only when every part can be identified
 * unambiguously; otherwise the caller falls back to the generic
 * conditional-jump reconstruction.
 * ========================================================= */
#define SWITCH_MAX_GROUPS 512

enum {
    SWITCH_TAIL_NONE = 0,
    SWITCH_TAIL_CONTINUE,   /* body ends with "drop; goto <loop update>" */
};

typedef struct {
    char **values;      /* case labels attached to this body (empty for default) */
    int    n_values;
    int    is_default;  /* this clause is the "default:" branch */
    int    test_start;  /* first test instruction of the group (-1 for default) */
    int    body_start;  /* first instruction of the (shared) body */
    int    body_end;    /* first instruction after the body (-1 = unknown) */
    int    tail_kind;   /* SWITCH_TAIL_* */
} switch_group_t;

static void switch_group_free(switch_group_t *g) {
    for (int i = 0; i < g->n_values; i++) free(g->values[i]);
    free(g->values);
    g->values = NULL;
    g->n_values = 0;
}

static int switch_op_is_terminator(int op) {
    return op == qjs_op_return || op == qjs_op_return_undef ||
           op == qjs_op_return_async || op == qjs_op_throw;
}

static int switch_op_is_goto(int op) {
    return op == qjs_op_goto || op == qjs_op_goto8 || op == qjs_op_goto16;
}

/* Copy a value stack, duplicating every expression string. */
static void vs_clone(vstack_t *dst, const vstack_t *src) {
    vs_init(dst);
    for (int i = 0; i < src->top && i < MAX_STACK; i++) {
        dst->slots[i] = src->slots[i];
        dst->slots[i].expr = src->slots[i].expr ? xstrdup(src->slots[i].expr) : NULL;
    }
    dst->top = src->top;
}

/* Is `pc` a continue target of one of the enclosing loops? */
static int switch_is_loop_target(decomp_ctx_t *ctx, uint32_t pc) {
    for (int d = 0; d < ctx->loop_depth && d < 32; d++) {
        uint32_t start = ctx->loop_start_targets[d];
        uint32_t end = ctx->loop_end_targets[d];
        if (start == UINT32_MAX) continue;
        if (pc == start) return 1;
        /* "continue" in a for loop jumps to the update part, which lives
         * inside the loop body and is itself a branch target. */
        if (end != UINT32_MAX && pc > start && pc < end &&
            ir_is_target(ctx->ir, pc))
            return 1;
    }
    return 0;
}

/* Append "continue;" to a clause body. */
static ir_stmt_t *switch_body_add_continue(ir_stmt_t *body) {
    stmt_list_t sl; sl_init(&sl);
    if (body && body->kind == IR_STMT_BLOCK) {
        for (int i = 0; i < body->n_children; i++) sl_push(&sl, body->children[i]);
        body->n_children = 0;
        free(body->children);
        body->children = NULL;
        ir_stmt_free(body);
    } else if (body) {
        sl_push(&sl, body);
    }
    sl_push(&sl, stmt_continue());
    return stmt_block(&sl);
}

/* Decompile [start, end) as the body of one switch clause.  The body runs
 * with the discriminant still on the value stack (exactly as in the original
 * byte code) and with the switch end registered as a break target, so that a
 * trailing "goto" prints as "break;".
 *
 * Returns NULL and sets *ok to 0 when the range does not leave the stack in
 * the expected state (only the discriminant on top), which means that the
 * guessed body boundaries are wrong. */
static ir_stmt_t *decompile_switch_body(decomp_ctx_t *ctx, int start, int end,
                                        uint32_t break_pc, int tail_kind, int *ok) {
    decomp_ctx_t tmp = *ctx;
    vs_clone(&tmp.vs, &ctx->vs);

    int base_top = tmp.vs.top;

    if (tmp.loop_depth < 32) {
        tmp.loop_start_targets[tmp.loop_depth] = UINT32_MAX;
        tmp.loop_end_targets[tmp.loop_depth] = break_pc;
        tmp.loop_depth++;
    }

    ir_stmt_t *body = decompile_range(&tmp, start, end);

    *ok = 0;
    if (tmp.vs.top == base_top && base_top > 0) {
        const char *top = tmp.vs.slots[base_top - 1].expr;
        const char *disc = ctx->vs.slots[base_top - 1].expr;
        if (top && disc && strcmp(top, disc) == 0) *ok = 1;
    }
    vs_free(&tmp.vs);

    if (!*ok) {
        ir_stmt_free(body);
        return NULL;
    }
    if (tail_kind == SWITCH_TAIL_CONTINUE) body = switch_body_add_continue(body);
    return body;
}

/* Classify how a clause body ends and adjust its end accordingly.
 *
 *   - a "goto" to `next_body` only skips the following clause's tests, so it
 *     is a fall-through and is removed from the body;
 *   - a "goto" that leaves the value stack balanced (with the discriminant on
 *     top) is a "break"; *break_idx receives its target;
 *   - "drop; goto <loop>" is a "continue" (the drop discards the
 *     discriminant);
 *   - a terminator or a plain fall-through needs no adjustment.
 *
 * Returns 0 when the body boundaries look wrong. */
static int switch_classify_tail(decomp_ctx_t *ctx, switch_group_t *g,
                                int next_body, int end_idx, int *break_idx) {
    ir_function_t *ir = ctx->ir;
    int last = g->body_end - 1;
    if (last < g->body_start) return 0;
    if (last >= ir->count) return 0;

    ir_insn_t *li = &ir->insns[last];
    if (!switch_op_is_goto(li->op) || li->is_backward) return 1;

    int tidx = ir_find_insn(ir, (uint32_t)li->label_target);
    if (tidx < 0 || tidx > end_idx) return 0;

    if (tidx == next_body && next_body > 0) {
        /* fall-through jump: it only skips the next clause's tests */
        g->body_end = last;
        return (g->body_end > g->body_start);
    }

    int okb = 0;
    ir_stmt_t *probe = decompile_switch_body(ctx, g->body_start, g->body_end,
                                             UINT32_MAX, SWITCH_TAIL_NONE, &okb);
    if (probe) {
        ir_stmt_free(probe);
        if (*break_idx < 0) *break_idx = tidx;
        else if (*break_idx != tidx) return 0;
        return 1;
    }

    if (last - 1 >= g->body_start && ir->insns[last - 1].op == qjs_op_drop &&
        switch_is_loop_target(ctx, (uint32_t)li->label_target)) {
        probe = decompile_switch_body(ctx, g->body_start, last - 1,
                                      UINT32_MAX, SWITCH_TAIL_CONTINUE, &okb);
        if (!probe) return 0;
        ir_stmt_free(probe);
        g->body_end = last - 1;
        g->tail_kind = SWITCH_TAIL_CONTINUE;
        return 1;
    }
    return 0;
}

/* Try to recognise a switch statement starting at instruction index `i`.
 *
 * `i` points either at the first test (a "dup") or - when the first clause is
 * "default:" - at the jump that skips the default body.
 *
 * On success stores the reconstructed statement in *out and the index just
 * past the switch in *next_idx.  The caller's value stack is only modified on
 * success (the discriminant is consumed). */
static int recognize_switch(decomp_ctx_t *ctx, int i, int end_idx,
                            int *next_idx, ir_stmt_t **out) {
    ir_function_t *ir = ctx->ir;
    if (!ir || i < 0 || i >= ir->count) return 0;
    if (i + 1 >= end_idx || i + 1 >= ir->count) return 0;
    if (ctx->vs.top < 1) return 0;
    const slot_t *dslot = &ctx->vs.slots[ctx->vs.top - 1];
    if (!dslot->expr || !*dslot->expr || dslot->is_dup_copy) return 0;

    int first_test = -1;
    int default_first = -1;
    if (ir->insns[i].op == qjs_op_dup) {
        /* The first test is entered by falling through from the discriminant
         * push; a "dup" that is itself a branch target belongs to the middle
         * of a test chain, which the caller handles. */
        if (ir_is_target(ir, ir->insns[i].pc)) return 0;
        first_test = i;
    } else if (switch_op_is_goto(ir->insns[i].op) && !ir->insns[i].is_backward) {
        /* "default:" is the first clause: the compiler jumps over its body. */
        int tg = ir_find_insn(ir, (uint32_t)ir->insns[i].label_target);
        if (tg <= i + 1 || tg >= end_idx || tg >= ir->count) return 0;
        if (ir->insns[tg].op != qjs_op_dup) return 0;
        first_test = tg;
        default_first = i + 1;
    } else {
        return 0;
    }

    switch_group_t groups[SWITCH_MAX_GROUPS];
    memset(groups, 0, sizeof(groups));
    int n_groups = 0;
    int switch_end_idx = -1;
    uint32_t break_pc = 0;
    stmt_list_t cases; sl_init(&cases);
    int ok_build = 0;

    /* ---- walk the test chain, collecting case labels and body ranges ---- */
    int t = first_test;
    int chain_end = -1;
    int backward_default = -1;

    for (;;) {
        if (t < 0 || t >= end_idx || t >= ir->count) goto done;
        if (ir->insns[t].op != qjs_op_dup) { chain_end = t; break; }
        int seen = 0;
        for (int k = 0; k < n_groups; k++)
            if (groups[k].test_start == t) { seen = 1; break; }
        if (seen) { chain_end = t; break; }
        if (n_groups >= SWITCH_MAX_GROUPS) goto done;

        switch_group_t *g = &groups[n_groups++];
        g->test_start = t;
        g->body_start = -1;
        g->body_end = -1;
        int last_br = -1;
        int shared = 0;
        int raw_end = -1;

        for (;;) {
            if (t < 0 || t >= end_idx || t >= ir->count) goto done;
            if (ir->insns[t].op != qjs_op_dup) goto done;

            /* The case value is the straight-line run between this "dup" and
             * the "strict_eq" that precedes the branch. */
            int se = -1;
            for (int j = t + 1; j + 1 < end_idx && j + 1 < ir->count; j++) {
                if (ir->insns[j].is_jump) break;
                if (ir->insns[j].op == qjs_op_strict_eq &&
                    ir->insns[j + 1].is_conditional) {
                    se = j;
                    break;
                }
            }
            if (se < 0) goto done;

            char *val = decode_range_expr(ctx, t + 1, se);
            if (!val || !*val) { free(val); goto done; }
            g->values = xrealloc(g->values, (g->n_values + 1) * sizeof(char *));
            g->values[g->n_values++] = val;

            int br = se + 1;
            int bop = ir->insns[br].op;
            int tgt_idx = ir_find_insn(ir, (uint32_t)ir->insns[br].label_target);
            if (tgt_idx > end_idx) goto done;
            last_br = br;

            if (bop == qjs_op_if_true || bop == qjs_op_if_true8) {
                /* label of a body shared with the following case values */
                if (tgt_idx <= br) goto done;
                if (g->body_start < 0) g->body_start = tgt_idx;
                else if (g->body_start != tgt_idx) goto done;
                shared = 1;
                t = br + 1;
                continue;
            }
            if (bop == qjs_op_if_false || bop == qjs_op_if_false8) {
                if (g->body_start < 0) g->body_start = br + 1;
                raw_end = tgt_idx;
                break;
            }
            goto done;
        }

        if (g->body_start < 0 || g->body_start >= end_idx) goto done;
        if (shared && g->body_start != last_br + 1) goto done;
        if (raw_end < g->test_start) {
            /* the test jumps back to the "default" body, which was emitted
             * before the tests */
            backward_default = raw_end;
            chain_end = g->test_start;
            break;
        }
        if (raw_end <= g->body_start) goto done;   /* empty clause body */
        g->body_end = raw_end;
        t = raw_end;
    }
    if (n_groups <= 0) goto done;

    /* ---- the default clause, if there is one ---- */
    int has_default = 0;
    int default_start = -1, default_end = -1;

    if (default_first >= 0) {
        has_default = 1;
        default_start = default_first;
        default_end = first_test;
        if (backward_default >= 0 && backward_default != default_first) goto done;
    } else if (backward_default >= 0) {
        /* "default:" in the middle: it was emitted right after the body of
         * the clause before it and before the tests of the next clause. */
        has_default = 1;
        default_start = backward_default;
        default_end = -1;
        for (int k = 0; k < n_groups; k++) {
            if (groups[k].test_start > default_start &&
                (default_end < 0 || groups[k].test_start < default_end))
                default_end = groups[k].test_start;
        }
        if (default_end < 0) goto done;
        int prev = -1;
        for (int k = 0; k < n_groups; k++) {
            if (groups[k].body_start >= 0 && groups[k].body_start < default_start &&
                (groups[k].body_end < 0 || groups[k].body_end > default_start))
                prev = k;
        }
        if (prev < 0) goto done;
        groups[prev].body_end = default_start;
    }
    /* A final "default:" clause (the one the tests fall through to) is
     * decided below, once the clause tails are known: its body may itself
     * start with the "drop" that a "continue" needs for the discriminant. */

    /* keep the clauses in byte-code (= source) order, including the default */
    if (has_default) {
        int pos = 0;
        while (pos < n_groups && groups[pos].body_start >= 0 &&
               groups[pos].body_start < default_start)
            pos++;
        if (n_groups >= SWITCH_MAX_GROUPS) goto done;
        memmove(&groups[pos + 1], &groups[pos],
                (size_t)(n_groups - pos) * sizeof(groups[0]));
        memset(&groups[pos], 0, sizeof(groups[0]));
        groups[pos].is_default = 1;
        groups[pos].test_start = -1;
        groups[pos].body_start = default_start;
        groups[pos].body_end = default_end;
        n_groups++;
    }

    /* ---- classify the tail of every clause whose end is known ----
     *
     * A clause body can end in four different ways:
     *   - falling through into the next clause's body: the compiler emits a
     *     "goto" that simply skips the next clause's tests;
     *   - a "goto" to the end of the switch: that is a "break";
     *   - "drop; goto <loop>": a "continue", where the drop discards the
     *     discriminant;
     *   - a terminator (return/throw) or a plain fall-through.
     *
     * A trailing "goto" that leaves the value stack balanced (with the
     * discriminant on top) can only be a break; when it does not, the body is
     * retried without the "drop; goto" pair and must then be a continue. */
    int break_idx = -1;
    for (int k = 0; k < n_groups; k++) {
        switch_group_t *g = &groups[k];
        if (g->body_end < 0) continue;      /* last clause: handled below */
        int next_body = (k + 1 < n_groups) ? groups[k + 1].body_start : -1;
        if (!switch_classify_tail(ctx, g, next_body, end_idx, &break_idx))
            goto done;
    }

    /* ---- a trailing "default:" clause ---- */
    if (!has_default && chain_end >= 0 && chain_end < end_idx &&
        chain_end < ir->count) {
        int is_default;
        if (ir->insns[chain_end].op == qjs_op_drop) {
            /* Usually the drop discards the discriminant at the end of the
             * switch, but a default whose first statement is "continue" also
             * starts with one.  A known break target tells them apart. */
            if (break_idx >= 0) {
                is_default = (chain_end < break_idx);
            } else {
                is_default = (chain_end + 1 < ir->count &&
                              switch_op_is_goto(ir->insns[chain_end + 1].op) &&
                              switch_is_loop_target(
                                  ctx, (uint32_t)ir->insns[chain_end + 1].label_target));
            }
        } else {
            is_default = 1;
        }
        if (is_default) {
            if (n_groups >= SWITCH_MAX_GROUPS) goto done;
            has_default = 1;
            default_start = chain_end;
            default_end = -1;
            /* it is the last clause: all bodies start before it */
            groups[n_groups].is_default = 1;
            groups[n_groups].test_start = -1;
            groups[n_groups].body_start = default_start;
            groups[n_groups].body_end = default_end;
            n_groups++;
        }
    }

    /* ---- locate the last clause and the end of the switch ---- */
    int unknown = -1;
    for (int k = 0; k < n_groups; k++) {
        if (groups[k].body_end < 0) { unknown = k; break; }
    }

    if (break_idx >= 0) {
        if (break_idx > ir->count || break_idx > end_idx) goto done;
        break_pc = (break_idx < ir->count) ? ir->insns[break_idx].pc : ir->bc_len;
        switch_end_idx = (break_idx < ir->count &&
                          ir->insns[break_idx].op == qjs_op_drop)
                             ? break_idx + 1 : break_idx;
        if (switch_end_idx > end_idx) goto done;
        if (unknown >= 0) {
            if (break_idx <= groups[unknown].body_start) goto done;
            groups[unknown].body_end = break_idx;
            if (!switch_classify_tail(ctx, &groups[unknown], -1, end_idx,
                                      &break_idx))
                goto done;
        }
    } else if (unknown >= 0) {
        /* No break anywhere else: find where the last clause ends.  Every
         * candidate boundary is validated by decompiling; the first one that
         * leaves the stack balanced is used.  Cutting early is safe here
         * because the remainder can only be reached by falling out of the
         * switch. */
        switch_group_t *g = &groups[unknown];
        int max_body_start = 0;
        for (int k = 0; k < n_groups; k++)
            if (groups[k].body_start > max_body_start) max_body_start = groups[k].body_start;

        for (int j = g->body_start + 1; j <= end_idx && j <= ir->count; j++) {
            ir_insn_t *prev = &ir->insns[j - 1];
            int bend = -1, send = -1;
            uint32_t pc = 0;
            if (prev->op == qjs_op_drop) {
                bend = j - 1;
                send = j;
                pc = (send < ir->count) ? ir->insns[send].pc : ir->bc_len;
            } else if (switch_op_is_terminator(prev->op)) {
                bend = j;
                send = j;
                pc = (send < ir->count) ? ir->insns[send].pc : ir->bc_len;
            } else if (switch_op_is_goto(prev->op) && !prev->is_backward) {
                /* a trailing "goto" out of the last clause is a break */
                int gt = ir_find_insn(ir, (uint32_t)prev->label_target);
                if (gt < j || gt > end_idx || gt < max_body_start) continue;
                bend = j;
                send = (gt < ir->count && ir->insns[gt].op == qjs_op_drop)
                           ? gt + 1 : gt;
                pc = (gt < ir->count) ? ir->insns[gt].pc : ir->bc_len;
            } else {
                continue;
            }

            int okb = 0;
            ir_stmt_t *b = decompile_switch_body(ctx, g->body_start, bend, pc,
                                                 SWITCH_TAIL_NONE, &okb);
            if (b) {
                ir_stmt_free(b);   /* rebuilt below with the final break_pc */
                g->body_end = bend;
                switch_end_idx = send;
                break_pc = pc;
                break;
            }
        }
        if (g->body_end < 0) goto done;
    } else {
        /* Every clause boundary is known: the switch simply ends after the
         * last body, followed by the discriminant drop. */
        int idx = groups[n_groups - 1].body_end;
        if (idx < 0 || idx > end_idx) goto done;
        switch_end_idx = (idx < ir->count && ir->insns[idx].op == qjs_op_drop)
                             ? idx + 1 : idx;
        break_pc = (switch_end_idx < ir->count)
                       ? ir->insns[switch_end_idx].pc : ir->bc_len;
    }

    /* ---- build one CASE node per label (and one for default) ---- */
    for (int k = 0; k < n_groups; k++) {
        switch_group_t *g = &groups[k];
        if (g->body_end < 0) goto done;
        int okb = 0;
        ir_stmt_t *body = decompile_switch_body(ctx, g->body_start, g->body_end,
                                                break_pc, g->tail_kind, &okb);
        if (!body) goto done;
        if (g->is_default) {
            sl_push(&cases, stmt_case(NULL, body));
            continue;
        }
        if (g->n_values <= 0) { ir_stmt_free(body); goto done; }
        for (int v = 0; v < g->n_values; v++) {
            int lastv = (v + 1 == g->n_values);
            sl_push(&cases, stmt_case(g->values[v], lastv ? body : stmt_block(NULL)));
            g->values[v] = NULL;   /* ownership moved to the CASE node */
        }
    }

    {
        ir_stmt_t *sw = stmt_switch(xstrdup(dslot->expr));
        sw->children = cases.items;
        sw->n_children = cases.count;
        cases.items = NULL;
        cases.count = cases.cap = 0;
        *out = sw;
        *next_idx = switch_end_idx;

        /* the switch consumes the discriminant */
        slot_t d = vs_pop(&ctx->vs);
        free(d.expr);
        ok_build = 1;
    }

done:
    for (int k = 0; k < n_groups; k++) switch_group_free(&groups[k]);
    if (!ok_build) {
        for (int k = 0; k < cases.count; k++) ir_stmt_free(cases.items[k]);
        sl_free(&cases);
    }
    return ok_build;
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
                int loop_idx = ctx_enter_loop(ctx, (uint32_t)body_start_pc,
                    (uint32_t)(insn->pc + insn->info->size));

                /* Free the already-emitted body statements (they'll be re-decompiled) */
                for (int j = body_stmt_start; j < sl.count; j++) {
                    ir_stmt_free(sl.items[j]);
                }
                sl.count = body_stmt_start;

                ir_stmt_t *body = decompile_range(ctx, body_start_idx, i);
                char *loop_label = ctx_exit_loop(ctx, loop_idx);

                char *cond_str = xstrdup(cond.expr);
                free(cond.expr);
                strip_outer_parens(cond_str);
                ir_stmt_t *ds = stmt_do_while(cond_str, body);
                ds->label = loop_label;
                sl_push(&sl, ds);
            } else {
                char *cond_str = xstrdup(cond.expr);
                free(cond.expr);
                ir_stmt_t *body = stmt_block(NULL);
                sl_push(&sl, stmt_do_while(cond_str, body));
            }
            i++;
            continue;
        }

        /* Reconstruct a switch statement.
         *
         * A switch compiles into a chain of "dup; <value>; strict_eq" tests
         * followed by the clause bodies.  The recogniser rebuilds the whole
         * statement from the test chain; when the layout is ambiguous it
         * declines and the generic conditional handling below takes over. */
        if (op == qjs_op_dup) {
            int snext = 0;
            ir_stmt_t *sstmt = NULL;
            if (recognize_switch(ctx, i, end_idx, &snext, &sstmt)) {
                sl_push(&sl, sstmt);
                i = snext;
                continue;
            }
            /* Not recognised - fall through to the generic handling */
        }
        /* A switch whose first clause is "default:" starts with a jump over
         * the default body. */
        if ((op == qjs_op_goto || op == qjs_op_goto8 || op == qjs_op_goto16) &&
            !insn->is_backward) {
            int snext = 0;
            ir_stmt_t *sstmt = NULL;
            if (recognize_switch(ctx, i, end_idx, &snext, &sstmt)) {
                sl_push(&sl, sstmt);
                i = snext;
                continue;
            }
        }

        /* Handle control flow specially */
        if (op == qjs_op_return || op == qjs_op_return_async) {
            slot_t v = vs_pop(&ctx->vs);
            if (ctx->is_script) {
                /* Top-level code: "return X" is illegal in a script/module.
                 * QuickJS uses it to return the completion value, so emit the
                 * value as a plain expression statement instead. */
                if (v.expr && *v.expr) {
                    sl_push(&sl, stmt_expr(v.expr));
                } else {
                    free(v.expr);
                }
            } else {
                sl_push(&sl, stmt_return(v.expr));
            }
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
            if (ctx->is_script) {
                /* Top-level: "return;" has no meaning, drop it. */
            } else {
                sl_push(&sl, stmt_return(NULL));
            }
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

        /* Handle try/catch/finally constructs.
         *
         * QuickJS emits a dedicated `catch` opcode for every protected
         * region; the recogniser rebuilds the whole try/catch/finally
         * statement from the bytecode layout. */
        if (op == qjs_op_catch) {
            int tnext = 0;
            ir_stmt_t *tstmt = NULL;
            if (recognize_try(ctx, i, &tnext, &tstmt)) {
                sl_push(&sl, tstmt);
                i = tnext;
                continue;
            }
            /* Not recognised - fall through to the generic handling */
        }

        /* Handle class declarations.
         *
         * QuickJS emits a whole class as one contiguous instruction
         * sequence; the recogniser rebuilds the class statement (name,
         * heritage, constructor and methods) from it. */
        if (op == qjs_op_define_class) {
            int cnext = 0;
            ir_stmt_t *cstmt = NULL;
            if (recognize_class(ctx, i, &cnext, &cstmt)) {
                sl_push(&sl, cstmt);
                i = cnext;
                continue;
            }
            /* Not recognised - fall through to the generic handling */
        }

        /* Handle destructuring declarations ("const {a, b} = obj;").
         *
         * QuickJS emits a fixed prologue for them; the recogniser
         * rebuilds the pattern from the instruction sequence. */
        if (op == qjs_op_undefined) {
            int dnext = 0;
            ir_stmt_t *dstmt = NULL;
            if (recognize_destructuring(ctx, i, &dnext, &dstmt)) {
                sl_push(&sl, dstmt);
                i = dnext;
                continue;
            }
            /* Not recognised - fall through to the generic handling */
        }

        /* Handle the module prologue.
         *
         * QuickJS emits the hoisted function declarations of a module in a
         * dead "if (this)" block at the very beginning of the module body.
         * The declarations are re-materialised as top level declarations. */
        if (ctx->module && is_toplevel && i == start_idx && op == qjs_op_push_this) {
            int mnext = 0, mcount = 0;
            ir_stmt_t **mitems = NULL;
            if (recognize_module_prologue(ctx, i, &mnext, &mitems, &mcount)) {
                for (int k = 0; k < mcount; k++) sl_push(&sl, mitems[k]);
                free(mitems);
                i = mnext;
                continue;
            }
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
                int target_depth = -1;
                for (int d = 0; d < ctx->loop_depth; d++) {
                    if ((uint32_t)tgt == ctx->loop_end_targets[d]) {
                        is_break = 1;
                        target_depth = d;
                        if (op == qjs_op_if_false || op == qjs_op_if_false8)
                            cond_negate = 1;
                        break;
                    }
                    /* Check for continue: target is inside the loop body
                     * (between loop_start and loop_end) and is a forward jump */
                    if ((uint32_t)tgt == ctx->loop_start_targets[d]) {
                        is_continue = 1;
                        target_depth = d;
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
                            target_depth = d;
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

                    /* A target other than the innermost loop needs a label. */
                    char *label = NULL;
                    if (target_depth >= 0 &&
                        target_depth != ctx->loop_depth - 1 &&
                        ctx->loop_labels[target_depth]) {
                        ctx_mark_loop_label(ctx, target_depth);
                        label = xstrdup(ctx->loop_labels[target_depth]);
                    }

                    /* Build: if (cond) { break; } or if (cond) { continue; } */
                    stmt_list_t body_sl; sl_init(&body_sl);
                    ir_stmt_t *br = is_break ? stmt_break() : stmt_continue();
                    br->label = label;
                    sl_push(&body_sl, br);
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

            /* Optional chaining:
             *   base; dup; is_undefined_or_null; if_false Lok
             *   drop; undefined; goto Lend
             * Lok: <access>; Lend:
             * Reconstruct "base?.access". */
            if ((op == qjs_op_if_false || op == qjs_op_if_false8) &&
                i > 0 &&
                ir->insns[i - 1].op == qjs_op_is_undefined_or_null &&
                i + 3 < ir->count &&
                ir->insns[i + 1].op == qjs_op_drop &&
                ir->insns[i + 2].op == qjs_op_undefined &&
                (ir->insns[i + 3].op == qjs_op_goto ||
                 ir->insns[i + 3].op == qjs_op_goto8 ||
                 ir->insns[i + 3].op == qjs_op_goto16) &&
                tgt_idx > i + 3 && ctx->vs.top > 0) {
                int end_idx = ir_find_insn(
                    ir, (uint32_t)ir->insns[i + 3].label_target);
                if (end_idx > tgt_idx && end_idx <= ir->count) {
                    slot_t base = ctx->vs.slots[ctx->vs.top - 1];
                    char *tail = decode_range_expr_base(
                        ctx, base.expr, tgt_idx, end_idx);
                    if (tail) {
                        sbuf_t sb; sb_init(&sb);
                        size_t blen = strlen(base.expr);
                        if (strncmp(tail, base.expr, blen) == 0 &&
                            (tail[blen] == '.' || tail[blen] == '[' ||
                             tail[blen] == '(')) {
                            sb_puts(&sb, base.expr);
                            sb_puts(&sb, "?.");
                            /* "obj.a" -> "obj?.a"; "obj[0]" -> "obj?.[0]" */
                            const char *rest = tail + blen;
                            if (*rest == '.') rest++;
                            sb_puts(&sb, rest);
                        } else {
                            sb_puts(&sb, base.expr);
                            sb_puts(&sb, "?.");
                            sb_puts(&sb, tail);
                        }
                        free(tail);
                        ctx->vs.top--;      /* consumed base */
                        free(base.expr);
                        vs_push_take_prec(&ctx->vs, sb.buf, PREC_CALL, 0);
                        i = end_idx;
                        continue;
                    }
                }
            }

            /* Nullish coalescing and &&/|| short-circuit expressions:
             *   base; dup; <test>; if_false/if_true L
             *   drop; <rhs>
             * L:
             * The base value is still on the stack; the branch value becomes
             * the right operand of "??", "&&" or "||". */
            if ((op == qjs_op_if_false || op == qjs_op_if_false8 ||
                 op == qjs_op_if_true || op == qjs_op_if_true8) &&
                i + 2 < tgt_idx && i + 1 < ir->count &&
                ir->insns[i + 1].op == qjs_op_drop &&
                ctx->vs.top > 0) {
                const char *bop = NULL;
                int is_nullish = (i > 0 &&
                    ir->insns[i - 1].op == qjs_op_is_undefined_or_null);
                if (is_nullish && (op == qjs_op_if_false ||
                                   op == qjs_op_if_false8)) {
                    bop = "??";
                } else if (i > 0 && ir->insns[i - 1].op == qjs_op_dup) {
                    if (op == qjs_op_if_false || op == qjs_op_if_false8)
                        bop = "&&";
                    else
                        bop = "||";
                }
                if (bop) {
                    char *rhs = decode_range_expr(ctx, i + 2, tgt_idx);
                    if (rhs) {
                        slot_t base = vs_pop(&ctx->vs);
                        slot_t r = { rhs, 0, 0, PREC_COMMA, 0,
                                     TMPL_NONE, NULL };
                        char *e = build_binop(base, bop, r);
                        vs_push_take_prec(&ctx->vs, e, op_prec(bop), 0);
                        i = tgt_idx;
                        continue;
                    }
                }
            }

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
                            int loop_idx = ctx_enter_loop(ctx, loop_start,
                                                          (uint32_t)tgt);

                            /* Re-decompile the body (from loop_start_idx to i,
                             * excluding the exit condition) */
                            ir_stmt_t *body = decompile_range(ctx, loop_start_idx, i);

                            /* Pop loop context */
                            char *loop_label = ctx_exit_loop(ctx, loop_idx);

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
                            ir_stmt_t *ws = stmt_while(xstrdup("true"), body);
                            ws->label = loop_label;
                            sl_push(&sl, ws);

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

                                /* If the condition contains an assignment
                                 * ("dup; put_var x" before the test), the
                                 * assignment is still evaluated on every
                                 * iteration: keep it inside the condition
                                 * and remove the stray pre-loop statement. */
                                if (cond.is_dup_copy && sl.count > 0) {
                                    ir_stmt_t *last = sl.items[sl.count - 1];
                                    size_t rlen = (last->rhs) ? strlen(last->rhs) : 0;
                                    if (last->kind == IR_STMT_ASSIGN &&
                                        last->lvalue && rlen > 0 &&
                                        strncmp(cond.expr, last->rhs, rlen) == 0 &&
                                        (cond.expr[rlen] == '\0' ||
                                         cond.expr[rlen] == ' ')) {
                                        /* Replace the assigned value with
                                         * "(x = value)" inside the condition. */
                                        sbuf_t asb; sb_init(&asb);
                                        sb_putc(&asb, '(');
                                        sb_puts(&asb, last->lvalue);
                                        sb_puts(&asb, " = ");
                                        sb_puts(&asb, last->rhs);
                                        sb_putc(&asb, ')');
                                        sb_puts(&asb, cond.expr + rlen);
                                        free(cond_str);
                                        cond_str = asb.buf;
                                        ir_stmt_free(last);
                                        sl.count--;
                                    }
                                }
                                free(cond.expr);

                                /* A jump to the exit taken when the condition
                                 * is true means the loop continues while it is
                                 * false. */
                                if (op == qjs_op_if_true || op == qjs_op_if_true8) {
                                    sbuf_t nsb; sb_init(&nsb);
                                    sb_putc(&nsb, '!');
                                    sb_putc(&nsb, '(');
                                    sb_puts(&nsb, cond_str);
                                    sb_putc(&nsb, ')');
                                    free(cond_str);
                                    cond_str = nsb.buf;
                                }

                                /* Set up loop tracking for break/continue */
                                uint32_t loop_start_pc = loop_start;
                                uint32_t loop_end_pc = (uint32_t)ir->insns[last_body_idx + 1].pc;

                                /* Body is from i+1 to last_body_idx */
                                /* Push loop context */
                                int loop_idx = ctx_enter_loop(ctx, loop_start_pc,
                                                              loop_end_pc);

                                ir_stmt_t *body = decompile_range(ctx, i + 1, last_body_idx);

                                /* Pop loop context */
                                char *loop_label = ctx_exit_loop(ctx, loop_idx);

                                ir_stmt_t *ws = stmt_while(cond_str, body);
                                ws->label = loop_label;
                                sl_push(&sl, ws);

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
            slot_t saved_slots[MAX_STACK];
            for (int si = 0; si < stack_before && si < MAX_STACK; si++) {
                saved_slots[si] = ctx->vs.slots[si];
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

            /* Generator statement form: disabled (complex, avoid breakage) */

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

            /* A leftover copy of a value that was already stored elsewhere
             * ("dup; put_loc X" ... "drop") must not be emitted again. */
            if (v.is_dup_copy) {
                free(v.expr);
                i++;
                continue;
            }

            /* Check if this is a residual from dup + put_loc pattern.
             * If the previous statement was an assignment and this expression
             * matches the assigned RHS, skip it. */
            int is_duplicate = 0;
            if (sl.count > 0) {
                ir_stmt_t *prev_stmt = sl.items[sl.count - 1];
                if (prev_stmt->rhs && v.expr) {
                    if ((prev_stmt->kind == IR_STMT_ASSIGN ||
                         prev_stmt->kind == IR_STMT_DECL) &&
                        strcmp(prev_stmt->rhs, v.expr) == 0) {
                        is_duplicate = 1;
                    } else if (prev_stmt->kind == IR_STMT_COMPOUND_ASSIGN &&
                               prev_stmt->lvalue && prev_stmt->rhs && v.expr) {
                    size_t lvlen = strlen(prev_stmt->lvalue);
                    if (strncmp(v.expr, prev_stmt->lvalue, lvlen) == 0 &&
                        (v.expr[lvlen] == ' ' || v.expr[lvlen] == '[' ||
                         v.expr[lvlen] == '.')) {
                        if (strstr(v.expr, prev_stmt->rhs) != NULL)
                            is_duplicate = 1;
                    } else if (strcmp(prev_stmt->rhs, v.expr) == 0) {
                        is_duplicate = 1;
                    }
                }
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
            uint32_t vref = 0;
            int is_vref = 0;
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
                vref = insn->u32_val;
                is_vref = 1;
                if (vref < (uint32_t)fn->closure_var_count)
                    lv = sanitize_binding_name(
                        qjs_atom_str(r, fn->closure_vars[vref].var_name_atom), -1);
                else {
                    char b[64]; snprintf(b, sizeof(b), "_var_ref_%d", vref);
                    lv = xstrdup(b);
                }
            } else {
                /* put_var */
                lv = sanitize_binding_name(atom_name_of(r, insn), -1);
            }

            slot_t val = vs_pop(&ctx->vs);

            /* "dup; put_loc X" leaves a copy of the assigned value on the
             * stack.  Mark that leftover so that the "drop" which consumes
             * it later does not emit the expression a second time.
             * This is what QuickJS emits for the implicit "this" binding of
             * a derived class constructor:
             *     <super call>; dup; put_loc_check_init this; ... drop
             */
            if (i > 0 && ir->insns[i - 1].op == qjs_op_dup && ctx->vs.top > 0) {
                ctx->vs.slots[ctx->vs.top - 1].is_dup_copy = 1;
            }

            /* Module scope: the first write to a module level variable is a
             * declaration ("const x = ...", "let x = ...", "var x = ...").
             * Later writes are plain assignments. */
            if (ctx->module && is_vref &&
                vref < (uint32_t)fn->closure_var_count &&
                fn->closure_vars[vref].is_local &&
                !module_is_import(ctx, (int)vref) &&
                !module_is_declared(ctx, (int)vref)) {
                module_mark_declared(ctx, (int)vref);
                sl_push(&sl, module_decl_stmt(ctx, (int)vref, val.expr));
                free(lv);
                i++;
                continue;
            }

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

            /* Prefix increment pattern: get_var; inc; dup; put_var.
             * The put only stores the value already produced by "++lv";
             * evaluating the expression itself performs the store, so the
             * assignment is redundant and must not be emitted again. */
            if (val.expr && lv[0] && i > 0 &&
                ir->insns[i - 1].op == qjs_op_dup) {
                if (((strncmp(val.expr, "++", 2) == 0 &&
                      strcmp(val.expr + 2, lv) == 0) ||
                     (strncmp(val.expr, "--", 2) == 0 &&
                      strcmp(val.expr + 2, lv) == 0))) {
                    free(lv);
                    free(val.expr);
                    i++;
                    continue;
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

        /* Handle define_func: the function expression was inlined at the
         * fclosure site, so turn it back into a function declaration. */
        if (op == qjs_op_define_func) {
            slot_t fn_val = vs_pop(&ctx->vs);
            if (is_function_expr(fn_val.expr)) {
                /* Add a blank line after the declaration for readability */
                size_t l = strlen(fn_val.expr);
                char *t = xmalloc(l + 2);
                memcpy(t, fn_val.expr, l);
                t[l] = '\n';
                t[l + 1] = '\0';
                free(fn_val.expr);
                sl_push(&sl, stmt_raw(t));
                /* ownership of the text transferred to the statement */
            } else {
                free(fn_val.expr);
            }
            i++;
            continue;
        }

        /* Private field writes (class field initialisers / private setters). */
        if (op == qjs_op_define_private_field) {
            slot_t val = vs_pop(&ctx->vs);
            slot_t sym = vs_pop(&ctx->vs);
            slot_t obj = vs_pop(&ctx->vs);
            char *fld = private_field_expr(obj.expr, sym.expr);
            sl_push(&sl, stmt_assign(fld, val.expr));
            /* define_private_field pushes the target object back. */
            if (ctx->vs.top < MAX_STACK) ctx->vs.slots[ctx->vs.top++] = obj;
            else free(obj.expr);
            free(sym.expr);
            i++;
            continue;
        }
        if (op == qjs_op_put_private_field) {
            slot_t sym = vs_pop(&ctx->vs);
            slot_t val = vs_pop(&ctx->vs);
            slot_t obj = vs_pop(&ctx->vs);
            char *fld = private_field_expr(obj.expr, sym.expr);
            sl_push(&sl, stmt_assign(fld, val.expr));
            free(obj.expr);
            free(sym.expr);
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
            } else if (val.expr && fld) {
                /* `get_field2 f; inc/dec; put_field f` is an update of the
                 * field whose result is discarded.  Emit "obj.f++" instead
                 * of the incorrect "obj.f = obj.f++". */
                size_t flen = strlen(fld);
                size_t vlen = strlen(val.expr);
                if (vlen == flen + 2 && strncmp(val.expr, fld, flen) == 0 &&
                    ((val.expr[flen] == '+' && val.expr[flen+1] == '+') ||
                     (val.expr[flen] == '-' && val.expr[flen+1] == '-'))) {
                    char *upd = xmalloc(flen + 3);
                    memcpy(upd, fld, flen);
                    upd[flen] = val.expr[flen];
                    upd[flen+1] = val.expr[flen+1];
                    upd[flen+2] = '\0';
                    sl_push(&sl, stmt_raw(upd));
                    free(fld);
                    free(val.expr);
                    free(obj.expr);
                } else {
                    sl_push(&sl, stmt_assign(fld, val.expr));
                    /* val.expr and fld ownership transferred to statement */
                    free(obj.expr);
                }
            } else {
                sl_push(&sl, stmt_assign(fld, val.expr));
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
            char *loop_var = NULL;   /* owned; freed below */
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
                /* vardefs[] holds the arguments first, then the local
                 * variables, so local slot N is vardefs[arg_count + N]. */
                uint32_t vd_idx = (uint32_t)fn->arg_count + (uint32_t)loc_idx;
                if (loc_idx >= 0 && vd_idx < (uint32_t)fn->vardefs_count) {
                    loop_var = sanitize_binding_name(
                        qjs_atom_str(r, fn->vardefs[vd_idx].var_name_atom), -1);
                    if (fn->vardefs[vd_idx].is_const) loop_var_decl_kind = 2;
                    else if (fn->vardefs[vd_idx].is_lexical) loop_var_decl_kind = 1;
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
            int loop_idx = ctx_enter_loop(ctx, (uint32_t)body_pc,
                                          (uint32_t)ir->insns[loop_end_idx].pc);

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
            char *loop_label = ctx_exit_loop(ctx, loop_idx);

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
                for_stmt->label = loop_label;
                sl_push(&sl, for_stmt);
                loop_label = NULL;
            } else {
                /* No loop variable found - emit as while loop with body */
                ir_stmt_t *while_stmt = stmt_while(xstrdup("true"),
                                                    body ? body : stmt_block(NULL));
                while_stmt->label = loop_label;
                sl_push(&sl, while_stmt);
                loop_label = NULL;
            }
            free(loop_label);
            free(iter_str);
            free(loop_var);

            /* Skip past the entire for-of pattern */
            i = loop_end_idx;
            continue;
        }

        /* Handle tail calls.
         *
         * OP_tail_call / OP_tail_call_method are semantically "call, then
         * return the result": the interpreter performs the call and leaves
         * the function immediately (QuickJS: `goto done`).  decode_insn()
         * builds the call expression and leaves it on the value stack, so we
         * pop it back and turn it into a `return` statement.  Without this
         * the value would simply be dropped and the enclosing branch (e.g.
         * `if (n === 0) return f(x);`) would end up empty and get dropped
         * by cleanup_statements(). */
        if (op == qjs_op_tail_call || op == qjs_op_tail_call_method) {
            decode_result_t tres = decode_insn(ctx, insn);
            if (tres == DECODE_OK || tres == DECODE_SKIP) {
                if (ctx->vs.top > 0) {
                    slot_t v = vs_pop(&ctx->vs);
                    if (v.expr && *v.expr) {
                        if (ctx->is_script) {
                            sl_push(&sl, stmt_expr(v.expr));
                        } else {
                            sl_push(&sl, stmt_return(v.expr));
                        }
                    } else {
                        free(v.expr);
                    }
                }
                i++;
                continue;
            }
            /* fall through to the generic handling below */
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
        /* If this is a duplicate left by "dup; put_*" (e.g. assignment
         * expressions) and the last statement already stored the value,
         * drop it silently. */
        int suppress = 0;
        if (v.is_dup_copy && v.expr && sl.count > 0) {
            ir_stmt_t *last = sl.items[sl.count - 1];
            if ((last->kind == IR_STMT_ASSIGN ||
                 last->kind == IR_STMT_COMPOUND_ASSIGN ||
                 last->kind == IR_STMT_DECL) &&
                last->rhs && strcmp(last->rhs, v.expr) == 0) {
                suppress = 1;
            }
        }
        if (suppress) {
            free(v.expr);
        } else {
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
                if (ctx->is_script) {
                    sl_push(&sl, stmt_expr(v.expr));
                } else {
                    sl_push(&sl, stmt_return(v.expr));
                }
            } else {
                free(v.expr);
            }
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
            else if (s->kinds[i] != -1 && kind > s->kinds[i]) s->kinds[i] = kind;
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
    /* QuickJS global-variable flags (see quickjs.c):
     *   DEFINE_GLOBAL_LEX_VAR  = 1 << 7  (0x80) -> let/const binding
     *   DEFINE_GLOBAL_FUNC_VAR = 1 << 6  (0x40) -> function declaration
     *   JS_PROP_WRITABLE       = 1 << 1  (0x02) -> writable (i.e. not const) */
    for (int i = 0; i < ir->count; i++) {
        ir_insn_t *insn = &ir->insns[i];
        if (!insn->info) continue;
        if (insn->op == qjs_op_define_var || insn->op == qjs_op_check_define_var) {
            const char *name = qjs_atom_str(r, insn->atom_val);
            uint32_t flags = insn->u32_val;
            int kind = 0; /* var by default */
            if (flags & 0x40) {
                /* Function declaration - handled by define_func, don't hoist. */
                kind = -1;
            } else if (flags & 0x80) {
                if (insn->op == qjs_op_define_var && !(flags & 0x02))
                    kind = 2; /* const (not writable) */
                else
                    kind = 1; /* let */
            }
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
    if (s->kind == IR_STMT_SWITCH) {
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
            /* `s->lvalue` already went through the sanitizer, so the vardef
             * name must be sanitized the same way before comparing. */
            char *varname = sanitize_binding_name(
                qjs_atom_str(r, fn->vardefs[j].var_name_atom), -1);
            int match = (strcmp(s->lvalue, varname) == 0);
            free(varname);
            if (match) {
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
        case IR_STMT_SWITCH:
            if (expr_contains_var(s->cond, varname)) return 1;
            break;
        case IR_STMT_CASE:
            if (expr_contains_var(s->expr, varname)) return 1;
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
    /* Sanitized forms of the internal names above (see
     * sanitize_binding_name(), which folds '<'/'>' into '_'). */
    if (strcmp(name, "_class_fields_init_") == 0) return 1;
    if (strcmp(name, "_brand_") == 0) return 1;
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

/* =========================================================
 * Remove the implicit "return this;" that QuickJS appends to
 * every derived class constructor.
 *
 * In JavaScript source a derived constructor returns undefined
 * unless the author writes "return" explicitly, so the
 * reconstructed source must not contain it.
 * ========================================================= */
static void strip_derived_return_this(ir_stmt_t *s) {
    if (!s || s->kind != IR_STMT_BLOCK) return;

    for (int i = s->n_children - 1; i >= 0; i--) {
        ir_stmt_t *c = s->children[i];
        if (c->kind == IR_STMT_RETURN && c->expr && strcmp(c->expr, "this") == 0) {
            ir_stmt_free(c);
            for (int j = i; j < s->n_children - 1; j++)
                s->children[j] = s->children[j + 1];
            s->n_children--;
            continue;
        }
        /* Only trailing returns belong to the implicit epilogue. */
        break;
    }
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
                (is_internal_var(child->lvalue) || is_reserved_word(child->lvalue) ||
                 (strcmp(child->lvalue, "arguments") == 0 && child->rhs &&
                  strcmp(child->rhs, "arguments") == 0))) {
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

            /* Remove self-assignments of a plain binding (generated by the
             * rest-parameter prologue: "rest; put_arg; ..."). */
            if (child->kind == IR_STMT_ASSIGN && child->lvalue && child->rhs &&
                strcmp(child->lvalue, child->rhs) == 0 &&
                !strchr(child->lvalue, '.') && !strchr(child->lvalue, '[')) {
                remove = 1;
            }

            /* Remove declarations of internal/reserved variables */
            if (child->kind == IR_STMT_DECL && child->lvalue &&
                (is_internal_var(child->lvalue) || is_reserved_word(child->lvalue) ||
                 strchr(child->lvalue, '.') != NULL ||
                 (strcmp(child->lvalue, "arguments") == 0 && child->rhs &&
                  strcmp(child->rhs, "arguments") == 0))) {
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
                /* Check if it's a call to an internal variable.  The name
                 * may appear in its raw "<...>" form or sanitized (the
                 * sanitizer folds the brackets into underscores). */
                if (strstr(child->expr, "<class_fields_init>") ||
                    strstr(child->expr, "<brand>") ||
                    strstr(child->expr, "_class_fields_init_") ||
                    strstr(child->expr, "_brand_")) {
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
                /* Remove statements that consist of a single internal
                 * compiler variable (e.g. the top level "<ret>"). */
                if (is_internal_var(child->expr)) remove = 1;
                /* Remove raw comment statements. */
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
    if (s->kind == IR_STMT_TRY) {
        if (s->body) cleanup_statements(s->body);
        if (s->catch_body) cleanup_statements(s->catch_body);
        if (s->finally_body) cleanup_statements(s->finally_body);
        return;
    }
    if (s->kind == IR_STMT_CLASS) {
        for (int i = 0; i < s->n_children; i++) {
            ir_stmt_t *m = s->children[i];
            if (m && m->kind == IR_STMT_CLASS_MEMBER && m->body)
                cleanup_statements(m->body);
        }
        return;
    }
    if (s->kind == IR_STMT_SWITCH) {
        for (int i = 0; i < s->n_children; i++) {
            ir_stmt_t *c = s->children[i];
            if (c && c->kind == IR_STMT_CASE) cleanup_statements(c->body);
        }
        return;
    }
    if (s->kind == IR_STMT_CASE) {
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
 * Post-processing: convert while loops to for loops
 *
 * Pattern: init_stmt; while(cond) { body; update_stmt; }
 * Becomes: for(init_stmt; cond; update_stmt) { body; }
 *
 * The init_stmt must be a simple assignment or declaration.
 * The update_stmt must be the LAST statement in the body and be
 * a simple increment, compound assignment, or assignment.
 * ========================================================= */

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
        for_stmt->label = child->label;
        child->label = NULL;

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
    close_obj_str(&s->expr);
    close_obj_str(&s->rhs);
    close_obj_str(&s->lvalue);
    close_obj_str(&s->cond);

    if (s->body) close_open_objects(s->body);
    if (s->else_body) close_open_objects(s->else_body);
    if (s->init) close_open_objects(s->init);
    if (s->update) close_open_objects(s->update);
    if (s->catch_body) close_open_objects(s->catch_body);
    if (s->finally_body) close_open_objects(s->finally_body);
    if (s->children) {
        for (int i = 0; i < s->n_children; i++)
            close_open_objects(s->children[i]);
    }
}

/* =========================================================
 * Top-level function decompiler
 * ========================================================= */
ir_stmt_t *ir_decompile_function(qjs_reader_t *r, qjs_function_t *fn, int cpool_base,
                                 qjs_module_t *module) {
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
    ctx.module = module;
    vs_init(&ctx.vs);
    /* The top-level script/module function is named "<eval>" by QuickJS. */
    ctx.is_script = (strcmp(qjs_atom_str(r, fn->func_name_atom), "<eval>") == 0);
    if (module && fn->closure_var_count > 0) {
        ctx.module_declared_count = fn->closure_var_count;
        ctx.module_declared = xcalloc((size_t)fn->closure_var_count, 1);
    }
    if (module && module->export_count > 0) {
        ctx.module_export_used_count = module->export_count;
        ctx.module_export_used = xcalloc((size_t)module->export_count, 1);
    }

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
        /* A derived class constructor gets an implicit "return this;"
         * appended by QuickJS - drop it again. */
        if (fn->flags.is_derived_class_constructor) {
            strip_derived_return_this(result);
        }
        /* Re-exported imports have no assignment in the module body; add the
         * missing "export { name };" statements. */
        if (module) {
            module_add_missing_exports(&ctx, result);
        }
    }

    vs_free(&ctx.vs);
    free(ctx.module_declared);
    free(ctx.module_export_used);
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

/* =========================================================
 * Print a possibly multi-line expression.
 *
 * Function expressions are rendered with a relative indentation of one
 * level; when they are embedded in a statement the continuation lines
 * have to be shifted by the indentation of the enclosing statement.
 * ========================================================= */
static void print_multiline(FILE *out, const char *text, int indent) {
    if (!text) return;
    const char *p = text;
    while (*p) {
        const char *nl = strchr(p, '\n');
        if (!nl) { fputs(p, out); break; }
        fwrite(p, 1, (size_t)(nl - p) + 1, out);
        if (nl[1]) put_indent(out, indent);
        p = nl + 1;
    }
}

static void print_stmt(FILE *out, ir_stmt_t *s, int indent) {
    if (!s) return;
    /* For BLOCK, don't print indent here - children print their own */
    if (s->kind != IR_STMT_BLOCK) {
        put_indent(out, indent);
    }
    switch (s->kind) {
        case IR_STMT_EXPR:
            print_multiline(out, s->expr, indent);
            fprintf(out, ";\n");
            break;
        case IR_STMT_ASSIGN:
            print_multiline(out, s->lvalue, indent);
            fprintf(out, " = ");
            print_multiline(out, s->rhs, indent);
            fprintf(out, ";\n");
            break;
        case IR_STMT_COMPOUND_ASSIGN:
            print_multiline(out, s->lvalue, indent);
            fprintf(out, " %s ", s->op ? s->op : "+=");
            print_multiline(out, s->rhs, indent);
            fprintf(out, ";\n");
            break;
        case IR_STMT_DECL: {
            const char *kw = (s->decl_kind == 2) ? "const" : (s->decl_kind == 1) ? "let" : "var";
            if (s->export_name) {
                if (strcmp(s->export_name, "default") == 0) {
                    /* "export default <name>;" - the binding itself stays
                     * unexported, only its value is the default export. */
                    fprintf(out, "export default ");
                    print_multiline(out, s->lvalue, indent);
                    fprintf(out, ";\n");
                    break;
                }
                fprintf(out, "export ");
            }
            fprintf(out, "%s ", kw);
            print_multiline(out, s->lvalue, indent);
            if (s->rhs) {
                fprintf(out, " = ");
                print_multiline(out, s->rhs, indent);
            }
            fprintf(out, ";\n");
            break;
        }
        case IR_STMT_FUNC_DECL: {
            if (s->export_name) {
                if (strcmp(s->export_name, "default") == 0)
                    fprintf(out, "export default ");
                else
                    fprintf(out, "export ");
            }
            print_multiline(out, s->expr, indent);
            fprintf(out, "\n");
            break;
        }
        case IR_STMT_DESTRUCTURE: {
            const char *kw = (s->decl_kind == 2) ? "const" : (s->decl_kind == 1) ? "let" : "var";
            fprintf(out, "%s ", kw);
            print_multiline(out, s->lvalue, indent);
            if (s->rhs) {
                fprintf(out, " = ");
                print_multiline(out, s->rhs, indent);
            }
            fprintf(out, ";\n");
            break;
        }
        case IR_STMT_RETURN:
            if (s->expr) { fprintf(out, "return "); print_multiline(out, s->expr, indent); fprintf(out, ";\n"); }
            else fprintf(out, "return;\n");
            break;
        case IR_STMT_THROW:
            fprintf(out, "throw ");
            print_multiline(out, s->expr, indent);
            fprintf(out, ";\n");
            break;
        case IR_STMT_BREAK:
            if (s->label) fprintf(out, "break %s;\n", s->label);
            else fprintf(out, "break;\n");
            break;
        case IR_STMT_CONTINUE:
            if (s->label) fprintf(out, "continue %s;\n", s->label);
            else fprintf(out, "continue;\n");
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
            if (s->label) fprintf(out, "%s: ", s->label);
            fprintf(out, "while (%s) {\n", cond);
            if (s->body) print_stmt(out, s->body, indent + 1);
            put_indent(out, indent);
            fprintf(out, "}\n");
            free(cond);
            break;
        }
        case IR_STMT_DO_WHILE: {
            char *cond = s->cond ? strip_outer_parens(xstrdup(s->cond)) : xstrdup("true");
            if (s->label) fprintf(out, "%s: ", s->label);
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
                    if (s->label) fprintf(out, "%s: ", s->label);
                    fprintf(out, "for (%s) {\n", s->cond);
                    if (s->body) print_stmt(out, s->body, indent + 1);
                    put_indent(out, indent);
                    fprintf(out, "}\n");
                    break;
                }
            }
            if (s->label) fprintf(out, "%s: ", s->label);
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
        case IR_STMT_SWITCH: {
            char *cond = s->cond ? strip_outer_parens(xstrdup(s->cond)) : xstrdup("true");
            fprintf(out, "switch (%s) {\n", cond);
            for (int i = 0; i < s->n_children; i++) {
                ir_stmt_t *c = s->children[i];
                if (!c || c->kind != IR_STMT_CASE) continue;
                put_indent(out, indent + 1);
                if (c->expr) {
                    fprintf(out, "case ");
                    print_multiline(out, c->expr, indent + 1);
                    fprintf(out, ":\n");
                } else {
                    fprintf(out, "default:\n");
                }
                if (c->body) print_stmt(out, c->body, indent + 2);
            }
            put_indent(out, indent);
            fprintf(out, "}\n");
            free(cond);
            break;
        }
        case IR_STMT_CASE:
            /* printed as part of the enclosing switch */
            break;
        case IR_STMT_TRY: {
            fprintf(out, "try {\n");
            if (s->body) print_stmt(out, s->body, indent + 1);
            put_indent(out, indent);
            if (s->catch_body) {
                fprintf(out, "} catch (%s) {\n", s->catch_var ? s->catch_var : "e");
                print_stmt(out, s->catch_body, indent + 1);
                put_indent(out, indent);
            }
            if (s->finally_body) {
                fprintf(out, "} finally {\n");
                print_stmt(out, s->finally_body, indent + 1);
                put_indent(out, indent);
            }
            fprintf(out, "}\n");
            break;
        }
        case IR_STMT_CLASS: {
            fprintf(out, "class %s", s->class_name ? s->class_name : "");
            if (s->class_heritage && *s->class_heritage)
                fprintf(out, " extends %s", s->class_heritage);
            fprintf(out, " {\n");
            for (int i = 0; i < s->n_children; i++) {
                ir_stmt_t *m = s->children[i];
                if (!m || m->kind != IR_STMT_CLASS_MEMBER) continue;
                put_indent(out, indent + 1);
                if (m->is_static) fprintf(out, "static ");
                /* Method names that are not plain identifiers must be quoted
                 * ("AIM-TEST"), otherwise the emitted class does not parse.
                 * Private names (#x) are identifiers and must stay raw. */
                sbuf_t key; sb_init(&key);
                const char *lname = m->lvalue ? m->lvalue : "";
                if (lname[0] == '#') sb_puts(&key, lname);
                else put_property_key(&key, lname, (uint32_t)strlen(lname));
                if (m->decl_kind == 3) {
                    /* class field: NAME = value; */
                    fprintf(out, "%s", key.buf);
                    if (m->expr && *m->expr) fprintf(out, " = %s", m->expr);
                    fprintf(out, ";\n");
                    free(key.buf);
                    continue;
                }
                switch (m->decl_kind) {
                    case 1: fprintf(out, "get %s()", key.buf); break;
                    case 2: fprintf(out, "set %s(%s)", key.buf,
                                    m->expr ? m->expr : "v"); break;
                    default:
                        fprintf(out, "%s(%s)", key.buf,
                                m->expr ? m->expr : "");
                        break;
                }
                free(key.buf);
                fprintf(out, " {\n");
                if (m->body) print_stmt(out, m->body, indent + 2);
                put_indent(out, indent + 1);
                fprintf(out, "}\n");
            }
            put_indent(out, indent);
            fprintf(out, "}\n");
            break;
        }
        case IR_STMT_CLASS_MEMBER:
            /* printed as part of the enclosing class */
            break;
        case IR_STMT_LABEL:
            fprintf(out, "%s\n", s->label ? s->label : "");
            break;        case IR_STMT_GOTO:
            fprintf(out, "goto %s;\n", s->label ? s->label : "");
            break;
        case IR_STMT_RAW:
            print_multiline(out, s->expr, indent);
            fprintf(out, "\n");
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
                             int cpool_base, int indent, qjs_module_t *module) {
    /* Nested functions are inlined at their use site (OP_fclosure), so they
     * do not have to be emitted separately here. */

    const char *name = qjs_atom_str(r, fn->func_name_atom);
    const char *kind = "function";
    if (fn->flags.func_kind == 1) kind = "function*";
    else if (fn->flags.func_kind == 2) kind = "async function";
    else if (fn->flags.func_kind == 3) kind = "async function*";

    /* Check if this is the top-level eval function (internal name <eval>) */
    int is_toplevel = (strcmp(name, "<eval>") == 0);

    ir_stmt_t *body = ir_decompile_function(r, fn, cpool_base, module);

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

        /* Check if name is a placeholder */
        if (strncmp(name, "_builtin_", 9) == 0 || strncmp(name, "_atom_", 6) == 0)
            need_synth = 1;

        if (need_synth) {
            snprintf(synth_name, sizeof(synth_name), "_anon_%d", fn->func_idx);
            display_name = synth_name;
        } else {
            /* Sanitize invalid characters instead of renaming: "AIM-TEST"
             * becomes "AIM_TEST" so the function keeps its identity. */
            display_name = sanitize_binding_name(name, -1);
        }

        /* Also sanitize argument names, keeping the atoms readable and
         * making sure the result has no duplicates. */
        sbuf_t clean_args; sb_init(&clean_args);
        int n_args_printed = fn->arg_count;
        if (n_args_printed > fn->vardefs_count) n_args_printed = fn->vardefs_count;
        char *printed_names[256];
        int n_printed = 0;
        for (int i = 0; i < n_args_printed; i++) {
            if (i > 0) sb_puts(&clean_args, ", ");
            const char *argname = qjs_atom_str(r, fn->vardefs[i].var_name_atom);
            char *clean = sanitize_binding_name(argname, -1);
            for (int k = 0; k < n_printed; k++) {
                if (strcmp(printed_names[k], clean) == 0) {
                    char *uniq = sanitize_binding_name(argname, i);
                    free(clean);
                    clean = uniq;
                    break;
                }
            }
            if (n_printed < (int)(sizeof(printed_names) / sizeof(printed_names[0])))
                printed_names[n_printed++] = clean;
            sb_puts(&clean_args, clean);
        }

        put_indent(out, indent);
        fprintf(out, "%s %s(%s) {\n", kind,
                display_name[0] ? display_name : "anon", clean_args.buf);
        sb_free(&clean_args);
        if (display_name != name && display_name != synth_name) free((char *)display_name);
        if (body) {
            print_stmt(out, body, indent + 1);
            ir_stmt_free(body);
        }
        put_indent(out, indent);
        fprintf(out, "}\n\n");
        for (int i = 0; i < n_printed; i++) free(printed_names[i]);
    }
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
            qjs_decompile_function(out, r, fn, base, indent, NULL);
            break;
        }
        case QJS_VAL_MODULE: {
            qjs_module_t *m = v->u.mod.mod;
            put_indent(out, indent);
            fprintf(out, "/* ===== Module: %s ===== */\n", qjs_atom_str(r, m->module_name_atom));

            /* --- imports --- */
            for (int i = 0; i < m->import_count; i++) {
                qjs_import_entry_t *ie = &m->imports[i];
                const char *mod_name = "";
                if (ie->req_module_idx >= 0 && ie->req_module_idx < m->req_module_count)
                    mod_name = qjs_atom_str(r, m->req_modules[ie->req_module_idx].module_name_atom);
                const char *iname = qjs_atom_str(r, ie->import_name_atom);
                /* The imported binding is a local identifier - sanitize it;
                 * `iname` (the name in the source module) is data. */
                char *lname = xstrdup("");
                if (ie->var_idx >= 0 && m->func &&
                    ie->var_idx < m->func->closure_var_count) {
                    free(lname);
                    lname = sanitize_binding_name(
                        qjs_atom_str(r, m->func->closure_vars[ie->var_idx].var_name_atom), -1);
                }

                put_indent(out, indent);
                if (strcmp(iname, "*") == 0) {
                    fprintf(out, "import * as %s from \"%s\";\n", lname, mod_name);
                } else if (strcmp(iname, "default") == 0) {
                    fprintf(out, "import %s from \"%s\";\n", lname, mod_name);
                } else if (lname && *lname && strcmp(lname, iname) != 0) {
                    fprintf(out, "import { %s as %s } from \"%s\";\n", iname, lname, mod_name);
                } else {
                    fprintf(out, "import { %s } from \"%s\";\n", iname, mod_name);
                }
                free(lname);
            }

            /* --- "export * from "mod";" --- */
            for (int i = 0; i < m->star_export_count; i++) {
                int idx = m->star_exports[i].req_module_idx;
                if (idx < 0 || idx >= m->req_module_count) continue;
                put_indent(out, indent);
                fprintf(out, "export * from \"%s\";\n",
                        qjs_atom_str(r, m->req_modules[idx].module_name_atom));
            }

            /* --- "export { a as b } from "mod";" --- */
            for (int i = 0; i < m->export_count; i++) {
                qjs_export_entry_t *e = &m->exports[i];
                if (e->export_type == 0) continue;   /* handled by the body */
                if (e->var_idx < 0 || e->var_idx >= m->req_module_count) continue;
                const char *mod_name = qjs_atom_str(r, m->req_modules[e->var_idx].module_name_atom);
                const char *lname = qjs_atom_str(r, e->local_name_atom);
                const char *ename = qjs_atom_str(r, e->export_name_atom);
                put_indent(out, indent);
                if (lname && ename && strcmp(lname, ename) == 0)
                    fprintf(out, "export { %s } from \"%s\";\n", lname, mod_name);
                else
                    fprintf(out, "export { %s as %s } from \"%s\";\n", lname, ename, mod_name);
            }

            fprintf(out, "\n");
            if (m->func) {
                int base = g_cpool_counter;
                g_cpool_counter += m->func->cpool_count;
                qjs_decompile_function(out, r, m->func, base, indent, m);
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
