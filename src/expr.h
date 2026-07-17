/*
 * expr.h - Expression builder with operator precedence
 *
 * Tracks operator precedence to eliminate redundant parentheses
 * in decompiled output.
 */
#ifndef JARONA_EXPR_H
#define JARONA_EXPR_H

/* =========================================================
 * Operator precedence levels (higher = binds tighter)
 * Matches JavaScript spec
 * ========================================================= */
#define PREC_COMMA   1
#define PREC_ASSIGN  2
#define PREC_COND    3   /* ternary */
#define PREC_OR      4   /* || */
#define PREC_AND     5   /* && */
#define PREC_BOR     6   /* | */
#define PREC_BXOR    7   /* ^ */
#define PREC_BAND    8   /* & */
#define PREC_EQ      9   /* == != === !== */
#define PREC_REL     10  /* < <= > >= instanceof in */
#define PREC_SHIFT   11  /* << >> >>> */
#define PREC_ADD     12  /* + - */
#define PREC_MUL     13  /* * / % */
#define PREC_UNARY   14  /* ! ~ - + typeof await yield delete */
#define PREC_POW     15  /* ** (right-associative) */
#define PREC_CALL    16  /* f(), a.b, a[b] */
#define PREC_ATOM    17  /* literals, variables, parenthesized */

/* =========================================================
 * Get precedence for a binary operator string
 * ========================================================= */
static inline int op_prec(const char *op) {
    if (!strcmp(op, "||")) return PREC_OR;
    if (!strcmp(op, "&&")) return PREC_AND;
    if (!strcmp(op, "|")) return PREC_BOR;
    if (!strcmp(op, "^")) return PREC_BXOR;
    if (!strcmp(op, "&")) return PREC_BAND;
    if (!strcmp(op, "==") || !strcmp(op, "!=") ||
        !strcmp(op, "===") || !strcmp(op, "!==")) return PREC_EQ;
    if (!strcmp(op, "<") || !strcmp(op, "<=") ||
        !strcmp(op, ">") || !strcmp(op, ">=") ||
        !strcmp(op, "instanceof") || !strcmp(op, "in")) return PREC_REL;
    if (!strcmp(op, "<<") || !strcmp(op, ">>") || !strcmp(op, ">>>")) return PREC_SHIFT;
    if (!strcmp(op, "+") || !strcmp(op, "-")) return PREC_ADD;
    if (!strcmp(op, "*") || !strcmp(op, "/") || !strcmp(op, "%")) return PREC_MUL;
    if (!strcmp(op, "**")) return PREC_POW;
    return PREC_ATOM;
}

/* =========================================================
 * Check if operator is right-associative
 * ========================================================= */
static inline int is_right_assoc(const char *op) {
    return !strcmp(op, "**");
}

/* =========================================================
 * Check if a child expression needs parentheses when used
 * as a sub-expression of a parent operator.
 *
 * For left-associative ops:
 *   left child:  needs parens if child_prec < parent_prec
 *   right child: needs parens if child_prec <= parent_prec
 *
 * For right-associative ops (**):
 *   left child:  needs parens if child_prec <= parent_prec
 *   right child: needs parens if child_prec < parent_prec
 * ========================================================= */
static inline int needs_parens_left(int child_prec, int parent_prec, int right_assoc) {
    if (right_assoc)
        return child_prec <= parent_prec;
    return child_prec < parent_prec;
}

static inline int needs_parens_right(int child_prec, int parent_prec, int right_assoc) {
    if (right_assoc)
        return child_prec < parent_prec;
    return child_prec <= parent_prec;
}

/* =========================================================
 * Wrap an expression in parentheses (returns new allocation, frees input)
 * ========================================================= */
static inline char *wrap_parens(char *expr) {
    if (!expr) return xstrdup("()");
    size_t len = strlen(expr);
    char *r = xmalloc(len + 3);
    r[0] = '(';
    memcpy(r + 1, expr, len);
    r[len + 1] = ')';
    r[len + 2] = '\0';
    free(expr);
    return r;
}

/* =========================================================
 * Conditionally wrap in parens based on precedence
 * ========================================================= */
static inline char *wrap_if_needed(char *expr, int child_prec, int parent_prec,
                                     int is_right_child, int right_assoc) {
    int needs;
    if (is_right_child)
        needs = needs_parens_right(child_prec, parent_prec, right_assoc);
    else
        needs = needs_parens_left(child_prec, parent_prec, right_assoc);

    if (needs && expr[0] != '(')
        return wrap_parens(expr);
    return expr;
}

#endif /* JARONA_EXPR_H */
