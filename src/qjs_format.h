/*
 * qjs_format.h - QuickJS bytecode binary format definitions
 *
 * Defines all the structures, tags, and constants used by the
 * standalone QuickJS bytecode parser. This is a clean reimplementation
 * of the binary format from quickjs.c, with no QuickJS runtime dependency.
 *
 * Part of the JARONA decompiler (refactored from frida-decompile.c).
 */
#ifndef QJS_FORMAT_H
#define QJS_FORMAT_H

#include <stdint.h>
#include <stddef.h>

/* =========================================================
 * Bytecode version
 * ========================================================= */
#define QJS_BC_BASE_VERSION       1
#define QJS_BC_BASE_VERSION_BIGNUM 2
#define QJS_BC_BE_VERSION         0x40   /* big-endian flag */

/* =========================================================
 * Bytecode tags (BCTagEnum in quickjs.c)
 * ========================================================= */
typedef enum {
    QJS_BC_TAG_NULL              = 1,
    QJS_BC_TAG_UNDEFINED         = 2,
    QJS_BC_TAG_BOOL_FALSE        = 3,
    QJS_BC_TAG_BOOL_TRUE         = 4,
    QJS_BC_TAG_INT32             = 5,
    QJS_BC_TAG_FLOAT64           = 6,
    QJS_BC_TAG_STRING            = 7,
    QJS_BC_TAG_OBJECT            = 8,
    QJS_BC_TAG_ARRAY             = 9,
    QJS_BC_TAG_BIG_INT           = 10,
    QJS_BC_TAG_BIG_FLOAT         = 11,
    QJS_BC_TAG_BIG_DECIMAL       = 12,
    QJS_BC_TAG_TEMPLATE_OBJECT   = 13,
    QJS_BC_TAG_FUNCTION_BYTECODE = 14,
    QJS_BC_TAG_MODULE            = 15,
    QJS_BC_TAG_TYPED_ARRAY       = 16,
    QJS_BC_TAG_ARRAY_BUFFER      = 17,
    QJS_BC_TAG_SHARED_ARRAY_BUFFER = 18,
    QJS_BC_TAG_DATE              = 19,
    QJS_BC_TAG_OBJECT_VALUE      = 20,
    QJS_BC_TAG_OBJECT_REFERENCE  = 21,
} qjs_tag_t;

/* =========================================================
 * QBCF magic (embedded bytecode in compiled binaries)
 * ========================================================= */
#define QJS_QBCF_MAGIC "QBCF"

/* =========================================================
 * Function bytecode flags (bitfield stored in u16)
 * ========================================================= */
typedef struct {
    uint8_t has_prototype;
    uint8_t has_simple_parameter_list;
    uint8_t is_derived_class_constructor;
    uint8_t need_home_object;
    uint8_t func_kind;          /* 2 bits: 0=normal,1=generator,2=async,3=async-gen */
    uint8_t new_target_allowed;
    uint8_t super_call_allowed;
    uint8_t super_allowed;
    uint8_t arguments_allowed;
    uint8_t has_debug;
    uint8_t backtrace_barrier;
    uint8_t is_direct_or_indirect_eval;
} qjs_func_flags_t;

/* =========================================================
 * Variable definition (vardefs) - per-local info
 * ========================================================= */
typedef struct {
    uint32_t var_name_atom;     /* atom index (in global atom table) */
    int      scope_level;
    int      scope_next;
    uint8_t  var_kind;          /* 4 bits */
    uint8_t  is_const;
    uint8_t  is_lexical;
    uint8_t  is_captured;
} qjs_vardef_t;

/* =========================================================
 * Closure variable
 * ========================================================= */
typedef struct {
    uint32_t var_name_atom;
    int      var_idx;
    uint8_t  is_local;
    uint8_t  is_arg;
    uint8_t  is_const;
    uint8_t  is_lexical;
    uint8_t  var_kind;
} qjs_closure_var_t;

/* =========================================================
 * Forward declarations
 * ========================================================= */
typedef struct qjs_value_s qjs_value_t;
typedef struct qjs_function_s qjs_function_t;
typedef struct qjs_module_s qjs_module_t;

/* =========================================================
 * JS value (constant pool entry / serialized object)
 * ========================================================= */
typedef enum {
    QJS_VAL_NULL,
    QJS_VAL_UNDEFINED,
    QJS_VAL_BOOL,
    QJS_VAL_INT32,
    QJS_VAL_FLOAT64,
    QJS_VAL_STRING,
    QJS_VAL_OBJECT,
    QJS_VAL_ARRAY,
    QJS_VAL_BIG_INT,
    QJS_VAL_BIG_FLOAT,
    QJS_VAL_BIG_DECIMAL,
    QJS_VAL_TEMPLATE_OBJECT,
    QJS_VAL_FUNCTION,           /* points to qjs_function_t */
    QJS_VAL_MODULE,             /* points to qjs_module_t */
    QJS_VAL_TYPED_ARRAY,
    QJS_VAL_ARRAY_BUFFER,
    QJS_VAL_SHARED_ARRAY_BUFFER,
    QJS_VAL_DATE,
    QJS_VAL_OBJECT_VALUE,
    QJS_VAL_OBJECT_REFERENCE,
    QJS_VAL_ERROR,
} qjs_value_kind_t;

typedef struct qjs_prop_s {
    uint32_t    key_atom;
    qjs_value_t *value;
} qjs_prop_t;

struct qjs_value_s {
    qjs_value_kind_t kind;
    union {
        int      b;                /* bool */
        int32_t  i32;              /* int32 */
        double   f64;              /* float64 */
        struct {
            char  *data;           /* utf-8 (we always decode wide strings) */
            uint32_t len;
            uint8_t is_wide;
        } str;
        struct {
            qjs_prop_t *props;
            uint32_t    count;
            qjs_value_t *proto;
            uint32_t    class_atom;
        } obj;
        struct {
            qjs_value_t **items;
            uint32_t count;
        } arr;
        struct {
            char *digits;          /* raw digit string for display */
            int   sign;
            int64_t expn;
            int   kind;            /* bigint/bigfloat/bigdecimal */
        } bignum;
        struct {
            qjs_function_t *fn;
        } func;
        struct {
            qjs_module_t *mod;
        } mod;
        struct {
            uint32_t ref_idx;
        } ref;
        struct {
            char *msg;
        } err;
    } u;
};

/* =========================================================
 * Function bytecode
 * ========================================================= */
struct qjs_function_s {
    /* header fields */
    qjs_func_flags_t flags;
    uint8_t  js_mode;
    uint32_t func_name_atom;
    uint16_t arg_count;
    uint16_t var_count;
    uint16_t defined_arg_count;
    uint16_t stack_size;
    int      closure_var_count;
    int      cpool_count;
    int      byte_code_len;
    int      local_count;          /* vardefs count */

    /* variable definitions (locals + args) */
    qjs_vardef_t      *vardefs;
    int                vardefs_count;

    /* closure variables */
    qjs_closure_var_t *closure_vars;

    /* bytecode body */
    uint8_t *byte_code;
    /* For each atom operand at offset X, we store the resolved atom index */
    uint32_t *atom_refs;          /* parallel array, length = number of atom operands */
    int       atom_refs_count;

    /* debug info */
    uint32_t debug_filename_atom;
    int      debug_line_num;
    uint8_t *debug_pc2line;
    int      debug_pc2line_len;

    /* constant pool */
    qjs_value_t **cpool;

    /* metadata */
    int       func_idx;           /* global function index */
    int       cpool_base;         /* offset added to cpool indices when displaying */
    void     *user_data;          /* used by disassembler/decompiler */
    int       is_frida;           /* 1 if bytecode uses temporary (phase 1) opcodes */
};

/* =========================================================
 * Module
 * ========================================================= */
typedef struct {
    uint32_t module_name_atom;
} qjs_req_module_entry_t;

typedef struct {
    uint8_t  export_type;          /* 0 = local, 1 = indirect */
    int      var_idx;              /* local: var_idx; indirect: req_module_idx */
    uint32_t local_name_atom;
    uint32_t export_name_atom;
} qjs_export_entry_t;

typedef struct {
    int req_module_idx;
} qjs_star_export_entry_t;

typedef struct {
    int      req_module_idx;
    uint32_t export_name_atom;
} qjs_export_star_entry_t;

struct qjs_module_s {
    uint32_t module_name_atom;
    qjs_req_module_entry_t *req_modules;
    int req_module_count;
    qjs_export_entry_t *exports;
    int export_count;
    qjs_star_export_entry_t *star_exports;
    int star_export_count;
    qjs_export_star_entry_t *export_star;
    int export_star_count;
    qjs_function_t *func;          /* the module body */
};

/* =========================================================
 * Atom table (global, top-level)
 * ========================================================= */
typedef struct {
    char    **atoms;
    uint32_t *atom_lens;
    uint8_t  *atom_wide;
    uint32_t  count;
    uint32_t  first_atom;          /* JS_ATOM_END = 1 normally */
} qjs_atom_table_t;

/* =========================================================
 * Parser state
 * ========================================================= */
typedef struct {
    const uint8_t *buf;
    size_t         buf_len;
    const uint8_t *ptr;
    const uint8_t *end;
    int            error;
    char           error_msg[256];
    int            big_endian;

    /* atom table (parsed once at top level) */
    qjs_atom_table_t atoms;

    /* object references (for BC_TAG_OBJECT_REFERENCE) */
    qjs_value_t **obj_refs;
    int           obj_refs_count;
    int           obj_refs_cap;

    /* statistics */
    int func_count;
    int value_count;
} qjs_reader_t;

/* =========================================================
 * Limits
 * ========================================================= */
#define QJS_MAX_ATOMS         (1 << 20)
#define QJS_MAX_CPOOL         (1 << 20)
#define QJS_MAX_BYTECODE_LEN  (64 * 1024 * 1024)
#define QJS_MAX_DEPTH         4096
#define QJS_MAX_STRING_LEN    (16 * 1024 * 1024)
#define QJS_MAX_OBJ_REFS      (1 << 20)

#endif /* QJS_FORMAT_H */
