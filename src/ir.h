/*
 * ir.h - Intermediate Representation for decompilation
 *
 * Defines the IR types used for structured control flow recovery:
 *   - ir_insn_t: decoded instruction
 *   - ir_stmt_t: statement (expression, if, while, for, etc.)
 */
#ifndef JARONA_IR_H
#define JARONA_IR_H

#include "qjs_format.h"
#include "reader.h"
#include "qjs_opcodes.h"

/* =========================================================
 * Decoded instruction
 * ========================================================= */
typedef struct {
    uint32_t pc;
    int      op;             /* opcode (remapped for Frida compat) */
    const qjs_op_info_t *info;

    /* decoded operands */
    int32_t  i32_val;      /* for i8/i16/i32 */
    uint32_t u32_val;      /* for u8/u16/u32/loc/arg/var_ref/const */
    uint32_t atom_val;     /* resolved atom value (for atom formats) */
    int32_t  label_target; /* resolved target PC (for label formats) */

    /* derived helpers */
    int      is_jump;      /* 1 if this is a conditional/unconditional jump */
    int      is_backward;  /* 1 if label_target < pc */
    int      is_conditional; /* 1 if if_false/if_true */
    int      is_return_terminator; /* 1 if return/return_undef/throw */
} ir_insn_t;

/* =========================================================
 * Statement types
 * ========================================================= */
typedef enum {
    IR_STMT_EXPR,        /* expression statement */
    IR_STMT_ASSIGN,      /* lvalue = expr */
    IR_STMT_COMPOUND_ASSIGN, /* lvalue += expr */
    IR_STMT_DECL,        /* let/const/var name = expr (or just let name) */
    IR_STMT_RETURN,      /* return expr; or return; */
    IR_STMT_THROW,       /* throw expr; */
    IR_STMT_IF,          /* if (cond) { then } else { else } */
    IR_STMT_WHILE,       /* while (cond) { body } */
    IR_STMT_DO_WHILE,    /* do { body } while (cond); */
    IR_STMT_FOR,         /* for (init; cond; update) { body } */
    IR_STMT_BREAK,       /* break; */
    IR_STMT_CONTINUE,    /* continue; */
    IR_STMT_BLOCK,       /* { ... } */
    IR_STMT_TRY,         /* try { } catch(e) { } finally { } */
    IR_STMT_LABEL,       /* Lxxxx: (for unresolved gotos) */
    IR_STMT_GOTO,        /* goto Lxxxx; (for unresolved jumps) */
    IR_STMT_EMPTY,       /* ; (empty, will be elided) */
    IR_STMT_RAW,         /* raw comment (for unhandled ops) */
} ir_stmt_kind_t;

/* =========================================================
 * Statement
 * ========================================================= */
typedef struct ir_stmt ir_stmt_t;
struct ir_stmt {
    ir_stmt_kind_t kind;

    /* expression fields */
    char *expr;          /* for EXPR, RETURN, THROW */
    char *lvalue;        /* for ASSIGN, COMPOUND_ASSIGN, DECL */
    char *rhs;           /* for ASSIGN, COMPOUND_ASSIGN, DECL */
    char *op;            /* for COMPOUND_ASSIGN: "+=", "-=" etc */
    int   decl_kind;     /* for DECL: 0=var, 1=let, 2=const */

    /* control flow fields */
    char *cond;          /* for IF, WHILE, DO_WHILE, FOR */
    ir_stmt_t *body;     /* for IF(then), WHILE, DO_WHILE, FOR, TRY */
    ir_stmt_t *else_body;/* for IF */
    ir_stmt_t *init;     /* for FOR */
    ir_stmt_t *update;   /* for FOR */
    ir_stmt_t *catch_body;  /* for TRY */
    char *catch_var;     /* for TRY */
    ir_stmt_t *finally_body; /* for TRY */

    /* label */
    char *label;         /* for LABEL, GOTO */

    /* block */
    ir_stmt_t **children; /* for BLOCK */
    int n_children;

    /* source PC range (for debugging) */
    uint32_t start_pc;
    uint32_t end_pc;
};

/* =========================================================
 * IR builder: decode bytecode into instruction array
 * ========================================================= */
typedef struct {
    ir_insn_t *insns;
    int count;
    int cap;
    uint32_t *targets;     /* sorted unique jump targets (basic block starts) */
    int n_targets;
    uint8_t *is_target;    /* is_target[pc] = 1 if pc is a jump target */
    uint32_t bc_len;
} ir_function_t;

/* Build IR from a function's bytecode */
ir_function_t *ir_build(qjs_reader_t *r, qjs_function_t *fn);

/* Free IR */
void ir_free(ir_function_t *ir);

/* =========================================================
 * Statement-based decompiler
 *
 * Takes an ir_function_t and produces a list of statements
 * with reconstructed control flow.
 * ========================================================= */
ir_stmt_t *ir_decompile_function(qjs_reader_t *r, qjs_function_t *fn, int cpool_base);

/* Free a statement tree */
void ir_stmt_free(ir_stmt_t *s);

/* =========================================================
 * Statement printer (emits JS code)
 * ========================================================= */
void ir_stmt_print(FILE *out, ir_stmt_t *s, int indent);

/* =========================================================
 * Helpers
 * ========================================================= */

/* Find instruction index by PC */
int ir_find_insn(ir_function_t *ir, uint32_t pc);

/* Check if a PC is a jump target (basic block start) */
int ir_is_target(ir_function_t *ir, uint32_t pc);

#endif /* JARONA_IR_H */
