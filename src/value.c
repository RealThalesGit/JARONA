/*
 * value.c - JS value parser implementation
 */
#include "value.h"
#include "qjs_opcodes.h"
#include "qjs_opcodes_frida.h"
#include "qjs_builtin_atoms.h"
#include <stdio.h>

/* =========================================================
 * Atom table parsing (called once at the top level)
 * ========================================================= */
static int parse_atom_table(qjs_reader_t *r) {
    uint8_t version;
    if (qjs_get_u8(r, &version) < 0) return -1;

    /* version sanity check: low 6 bits are the version, bit 6 = big-endian */
    int ver = version & 0x3f;
    int be  = (version & 0x40) ? 1 : 0;

    if (ver != 1 && ver != 2) {
        qjs_reader_set_error(r, "unsupported bytecode version");
        return -1;
    }
    r->big_endian = be;

    if (qjs_get_leb128(r, &r->atoms.count) < 0) return -1;
    if (r->atoms.count > QJS_MAX_ATOMS) {
        qjs_reader_set_error(r, "too many atoms");
        return -1;
    }

    if (r->atoms.count == 0) {
        r->atoms.atoms = NULL;
        r->atoms.atom_lens = NULL;
        r->atoms.atom_wide = NULL;
        return 0;
    }

    r->atoms.atoms = xcalloc(r->atoms.count, sizeof(char *));
    r->atoms.atom_lens = xcalloc(r->atoms.count, sizeof(uint32_t));
    r->atoms.atom_wide = xcalloc(r->atoms.count, sizeof(uint8_t));

    for (uint32_t i = 0; i < r->atoms.count; i++) {
        uint32_t len;
        if (qjs_get_leb128(r, &len) < 0) return -1;
        int is_wide = len & 1;
        len >>= 1;

        if (len > QJS_MAX_STRING_LEN) {
            qjs_reader_set_error(r, "atom too long");
            return -1;
        }

        /* always store as UTF-8; if wide, we convert (best-effort) */
        if (!is_wide) {
            char *s = xmalloc(len + 1);
            if (qjs_get_buf(r, (uint8_t *)s, len) < 0) { free(s); return -1; }
            s[len] = '\0';
            r->atoms.atoms[i] = s;
            r->atoms.atom_lens[i] = len;
            r->atoms.atom_wide[i] = 0;
        } else {
            /* wide-char (UTF-16/UCS-2) string: convert to UTF-8 */
            size_t bytes = (size_t)len * 2;
            uint8_t *buf = xmalloc(bytes);
            if (qjs_get_buf(r, buf, bytes) < 0) { free(buf); return -1; }
            /* naive UCS-2 -> UTF-8 conversion */
            size_t out_cap = (size_t)len * 3 + 1;
            char *out = xmalloc(out_cap);
            size_t oi = 0;
            for (uint32_t j = 0; j < len; j++) {
                uint16_t cp = rd_u16(buf + j * 2, r->big_endian);
                if (cp < 0x80) {
                    out[oi++] = (char)cp;
                } else if (cp < 0x800) {
                    out[oi++] = (char)(0xc0 | (cp >> 6));
                    out[oi++] = (char)(0x80 | (cp & 0x3f));
                } else {
                    out[oi++] = (char)(0xe0 | (cp >> 12));
                    out[oi++] = (char)(0x80 | ((cp >> 6) & 0x3f));
                    out[oi++] = (char)(0x80 | (cp & 0x3f));
                }
            }
            out[oi] = '\0';
            free(buf);
            r->atoms.atoms[i] = out;
            r->atoms.atom_lens[i] = (uint32_t)oi;
            r->atoms.atom_wide[i] = 1;
        }
    }
    return 0;
}

/* =========================================================
 * Atom resolution
 *
 * The stored atom_idx uses bit 31 (JS_ATOM_TAG_INT) as the tag:
 *   - If bit 31 is set: tagged-int atom. Integer value = atom_idx & 0x7FFFFFFF.
 *   - Else: regular atom index.
 *     - If idx < first_atom: built-in atom (look up in qjs_builtin_atoms).
 *     - Else: idx -= first_atom, look up in user atom table.
 * ========================================================= */
const char *qjs_atom_str(qjs_reader_t *r, uint32_t atom_idx) {
    static char buf[64];

    if (atom_idx & 0x80000000u) {
        /* tagged-int atom */
        snprintf(buf, sizeof(buf), "%u", atom_idx & 0x7FFFFFFFu);
        return buf;
    }

    uint32_t idx = atom_idx;
    uint32_t first = r->atoms.first_atom;
    if (idx < first) {
        /* built-in atom */
        if (idx < QJS_BUILTIN_ATOM_COUNT && qjs_builtin_atoms[idx]) {
            return qjs_builtin_atoms[idx];
        }
        snprintf(buf, sizeof(buf), "_builtin_%u", idx);
        return buf;
    }
    idx -= first;
    if (idx >= r->atoms.count) {
        snprintf(buf, sizeof(buf), "_atom_oob_%u", atom_idx);
        return buf;
    }
    if (!r->atoms.atoms || !r->atoms.atoms[idx]) {
        snprintf(buf, sizeof(buf), "_atom_null_%u", atom_idx);
        return buf;
    }
    return r->atoms.atoms[idx];
}

char *qjs_atom_dup(qjs_reader_t *r, uint32_t atom_idx) {
    return xstrdup(qjs_atom_str(r, atom_idx));
}


/* =========================================================
 * Forward declarations
 * ========================================================= */
static qjs_function_t *read_function(qjs_reader_t *r);
static qjs_module_t   *read_module(qjs_reader_t *r);

/* =========================================================
 * Read a string (BC_TAG_STRING)
 * ========================================================= */
static int read_string_value(qjs_reader_t *r, char **out, uint32_t *out_len, uint8_t *out_wide) {
    uint32_t len;
    if (qjs_get_leb128(r, &len) < 0) return -1;
    int is_wide = len & 1;
    len >>= 1;

    if (len > QJS_MAX_STRING_LEN) {
        qjs_reader_set_error(r, "string too long");
        return -1;
    }

    if (!is_wide) {
        char *s = xmalloc(len + 1);
        if (qjs_get_buf(r, (uint8_t *)s, len) < 0) { free(s); return -1; }
        s[len] = '\0';
        *out = s;
        if (out_len) *out_len = len;
        if (out_wide) *out_wide = 0;
        return 0;
    } else {
        size_t bytes = (size_t)len * 2;
        uint8_t *buf = xmalloc(bytes);
        if (qjs_get_buf(r, buf, bytes) < 0) { free(buf); return -1; }
        size_t out_cap = (size_t)len * 3 + 1;
        char *out_s = xmalloc(out_cap);
        size_t oi = 0;
        for (uint32_t j = 0; j < len; j++) {
            uint16_t cp = rd_u16(buf + j * 2, r->big_endian);
            if (cp < 0x80) {
                out_s[oi++] = (char)cp;
            } else if (cp < 0x800) {
                out_s[oi++] = (char)(0xc0 | (cp >> 6));
                out_s[oi++] = (char)(0x80 | (cp & 0x3f));
            } else {
                out_s[oi++] = (char)(0xe0 | (cp >> 12));
                out_s[oi++] = (char)(0x80 | ((cp >> 6) & 0x3f));
                out_s[oi++] = (char)(0x80 | (cp & 0x3f));
            }
        }
        out_s[oi] = '\0';
        free(buf);
        *out = out_s;
        if (out_len) *out_len = (uint32_t)oi;
        if (out_wide) *out_wide = 1;
        return 0;
    }
}

/* =========================================================
 * Read a bignum (BC_TAG_BIG_INT / BIG_FLOAT / BIG_DECIMAL)
 *
 * This is a simplified reader that stores the raw sign/exponent
 * and an approximate digit string.
 * ========================================================= */
static qjs_value_t *read_bignum(qjs_reader_t *r, int kind) {
    int32_t e;
    if (qjs_get_sleb128(r, &e) < 0) return NULL;

    qjs_value_t *v = xcalloc(1, sizeof(*v));
    v->kind = (kind == QJS_BC_TAG_BIG_INT) ? QJS_VAL_BIG_INT :
              (kind == QJS_BC_TAG_BIG_FLOAT) ? QJS_VAL_BIG_FLOAT :
              QJS_VAL_BIG_DECIMAL;
    v->u.bignum.kind = kind;
    v->u.bignum.sign = e & 1;
    int64_t exp = e >> 1;
    /* special exponent encoding */
    if (exp == 0)      v->u.bignum.expn = 0;       /* BF_EXP_ZERO */
    else if (exp == 1) v->u.bignum.expn = -1;      /* BF_EXP_INF */
    else if (exp == 2) v->u.bignum.expn = -2;      /* BF_EXP_NAN */
    else if (exp >= 3) v->u.bignum.expn = exp - 3;
    else               v->u.bignum.expn = exp;

    if (v->u.bignum.expn != 0 && v->u.bignum.expn != -1 && v->u.bignum.expn != -2) {
        uint32_t len;
        if (qjs_get_leb128(r, &len) < 0) { qjs_value_free(v); return NULL; }
        if (len == 0) {
            v->u.bignum.digits = xstrdup("0");
        } else {
            /* read raw bytes - for big_int/big_float these are limb bytes;
             * for big_decimal these are packed BCD digits. We just store
             * them as hex for display. */
            uint8_t *raw = xmalloc(len);
            if (qjs_get_buf(r, raw, len) < 0) { free(raw); qjs_value_free(v); return NULL; }
            char *hex = xmalloc(len * 2 + 1);
            for (uint32_t i = 0; i < len; i++)
                sprintf(hex + i * 2, "%02x", raw[i]);
            free(raw);
            v->u.bignum.digits = hex;
        }
    } else {
        v->u.bignum.digits = xstrdup(v->u.bignum.expn == 0 ? "0" :
                                      v->u.bignum.expn == -1 ? "Infinity" : "NaN");
    }
    return v;
}

/* =========================================================
 * Read function bytecode
 * ========================================================= */
static qjs_function_t *read_function(qjs_reader_t *r) {
    uint16_t v16;
    uint8_t v8;

    qjs_function_t *fn = xcalloc(1, sizeof(*fn));

    if (qjs_get_u16(r, &v16) < 0) goto fail;
    int idx = 0;
    fn->flags.has_prototype = get_bits(v16, &idx, 1);
    fn->flags.has_simple_parameter_list = get_bits(v16, &idx, 1);
    fn->flags.is_derived_class_constructor = get_bits(v16, &idx, 1);
    fn->flags.need_home_object = get_bits(v16, &idx, 1);
    fn->flags.func_kind = get_bits(v16, &idx, 2);
    fn->flags.new_target_allowed = get_bits(v16, &idx, 1);
    fn->flags.super_call_allowed = get_bits(v16, &idx, 1);
    fn->flags.super_allowed = get_bits(v16, &idx, 1);
    fn->flags.arguments_allowed = get_bits(v16, &idx, 1);
    fn->flags.has_debug = get_bits(v16, &idx, 1);
    fn->flags.backtrace_barrier = get_bits(v16, &idx, 1);
    fn->flags.is_direct_or_indirect_eval = get_bits(v16, &idx, 1);

    if (qjs_get_u8(r, &v8) < 0) goto fail;
    fn->js_mode = v8;

    if (qjs_get_atom(r, &fn->func_name_atom) < 0) goto fail;
    if (qjs_get_leb128_u16(r, &fn->arg_count) < 0) goto fail;
    if (qjs_get_leb128_u16(r, &fn->var_count) < 0) goto fail;
    if (qjs_get_leb128_u16(r, &fn->defined_arg_count) < 0) goto fail;
    if (qjs_get_leb128_u16(r, &fn->stack_size) < 0) goto fail;
    if (qjs_get_leb128_int(r, &fn->closure_var_count) < 0) goto fail;
    if (qjs_get_leb128_int(r, &fn->cpool_count) < 0) goto fail;
    if (qjs_get_leb128_int(r, &fn->byte_code_len) < 0) goto fail;
    if (qjs_get_leb128_int(r, &fn->local_count) < 0) goto fail;

    if (fn->byte_code_len < 0 || (uint32_t)fn->byte_code_len > QJS_MAX_BYTECODE_LEN) {
        qjs_reader_set_error(r, "bytecode length out of range");
        goto fail;
    }

    fn->vardefs_count = fn->local_count;
    if (fn->vardefs_count > 0) {
        fn->vardefs = xcalloc(fn->vardefs_count, sizeof(qjs_vardef_t));
        for (int i = 0; i < fn->vardefs_count; i++) {
            qjs_vardef_t *vd = &fn->vardefs[i];
            if (qjs_get_atom(r, &vd->var_name_atom) < 0) goto fail;
            if (qjs_get_leb128_int(r, &vd->scope_level) < 0) goto fail;
            if (qjs_get_leb128_int(r, &vd->scope_next) < 0) goto fail;
            vd->scope_next--;
            if (qjs_get_u8(r, &v8) < 0) goto fail;
            idx = 0;
            vd->var_kind = get_bits(v8, &idx, 4);
            vd->is_const = get_bits(v8, &idx, 1);
            vd->is_lexical = get_bits(v8, &idx, 1);
            vd->is_captured = get_bits(v8, &idx, 1);
        }
    }

    if (fn->closure_var_count > 0) {
        fn->closure_vars = xcalloc(fn->closure_var_count, sizeof(qjs_closure_var_t));
        for (int i = 0; i < fn->closure_var_count; i++) {
            qjs_closure_var_t *cv = &fn->closure_vars[i];
            if (qjs_get_atom(r, &cv->var_name_atom) < 0) goto fail;
            if (qjs_get_leb128_int(r, &cv->var_idx) < 0) goto fail;
            if (qjs_get_u8(r, &v8) < 0) goto fail;
            idx = 0;
            cv->is_local = get_bits(v8, &idx, 1);
            cv->is_arg = get_bits(v8, &idx, 1);
            cv->is_const = get_bits(v8, &idx, 1);
            cv->is_lexical = get_bits(v8, &idx, 1);
            cv->var_kind = get_bits(v8, &idx, 4);
        }
    }

    /* bytecode body */
    fn->byte_code = xmalloc(fn->byte_code_len ? (size_t)fn->byte_code_len : 1);
    if (qjs_get_buf(r, fn->byte_code, fn->byte_code_len) < 0) goto fail;

    /* Auto-detect Frida mode (temporary opcodes preserved in bytecode) */
    fn->is_frida = detect_frida_mode(fn->byte_code, fn->byte_code_len, r->big_endian);

    /* Skip atom resolution pass - atoms are resolved on-the-fly during
     * decompilation via qjs_atom_str(). */

    /* debug info */
    if (fn->flags.has_debug) {
        if (qjs_get_atom(r, &fn->debug_filename_atom) < 0) goto fail;
        if (qjs_get_leb128_int(r, &fn->debug_line_num) < 0) goto fail;
        if (qjs_get_leb128_int(r, &fn->debug_pc2line_len) < 0) goto fail;
        if (fn->debug_pc2line_len > 0) {
            fn->debug_pc2line = xmalloc(fn->debug_pc2line_len);
            if (qjs_get_buf(r, fn->debug_pc2line, fn->debug_pc2line_len) < 0)
                goto fail;
        }
    }

    /* constant pool */
    if (fn->cpool_count > 0) {
        if ((uint32_t)fn->cpool_count > QJS_MAX_CPOOL) {
            qjs_reader_set_error(r, "cpool too large");
            goto fail;
        }
        fn->cpool = xcalloc(fn->cpool_count, sizeof(qjs_value_t *));
        for (int i = 0; i < fn->cpool_count; i++) {
            fn->cpool[i] = qjs_read_value(r, 1, 1);
            if (!fn->cpool[i]) goto fail;
            /* Propagate is_frida: if either parent or child detects Frida mode,
             * use Frida mode for both (the opcode table is global, not per-function). */
            if (fn->cpool[i]->kind == QJS_VAL_FUNCTION) {
                qjs_function_t *child = fn->cpool[i]->u.func.fn;
                if (child->is_frida || fn->is_frida) {
                    child->is_frida = 1;
                    fn->is_frida = 1;
                }
            }
        }
    }

    return fn;

fail:
    qjs_function_free(fn);
    return NULL;
}

/* =========================================================
 * Read module
 *
 * Module format (from JS_ReadModule in quickjs.c):
 *   1. module_name_atom
 *   2. req_module_count (LEB128)
 *      for each: module_name_atom
 *   3. export_entries_count (LEB128)
 *      for each: u8 export_type, [var_idx | req_module_idx + local_name], export_name
 *   4. star_export_entries_count (LEB128)
 *      for each: req_module_idx
 *   5. import_entries_count (LEB128)
 *      for each: var_idx, import_name, req_module_idx
 *   6. u8 has_tla
 *   7. function body (recursive value)
 * ========================================================= */
static qjs_module_t *read_module(qjs_reader_t *r) {
    qjs_module_t *m = xcalloc(1, sizeof(*m));

    if (qjs_get_atom(r, &m->module_name_atom) < 0) goto fail;

    if (qjs_get_leb128_int(r, &m->req_module_count) < 0) goto fail;
    if (m->req_module_count > 0) {
        m->req_modules = xcalloc(m->req_module_count, sizeof(qjs_req_module_entry_t));
        for (int i = 0; i < m->req_module_count; i++) {
            if (qjs_get_atom(r, &m->req_modules[i].module_name_atom) < 0) goto fail;
        }
    }

    if (qjs_get_leb128_int(r, &m->export_count) < 0) goto fail;
    if (m->export_count > 0) {
        m->exports = xcalloc(m->export_count, sizeof(qjs_export_entry_t));
        for (int i = 0; i < m->export_count; i++) {
            qjs_export_entry_t *e = &m->exports[i];
            uint8_t t;
            if (qjs_get_u8(r, &t) < 0) goto fail;
            e->export_type = t;
            if (e->export_type == 0) {
                /* JS_EXPORT_TYPE_LOCAL */
                if (qjs_get_leb128_int(r, &e->var_idx) < 0) goto fail;
            } else {
                if (qjs_get_leb128_int(r, &e->var_idx) < 0) goto fail;
                if (qjs_get_atom(r, &e->local_name_atom) < 0) goto fail;
            }
            if (qjs_get_atom(r, &e->export_name_atom) < 0) goto fail;
        }
    }

    if (qjs_get_leb128_int(r, &m->star_export_count) < 0) goto fail;
    if (m->star_export_count > 0) {
        m->star_exports = xcalloc(m->star_export_count, sizeof(qjs_star_export_entry_t));
        for (int i = 0; i < m->star_export_count; i++) {
            if (qjs_get_leb128_int(r, &m->star_exports[i].req_module_idx) < 0) goto fail;
        }
    }

    /* import entries (we skip these for display but must parse them) */
    int import_count = 0;
    if (qjs_get_leb128_int(r, &import_count) < 0) goto fail;
    for (int i = 0; i < import_count; i++) {
        int var_idx;
        uint32_t import_name, req_module_idx;
        if (qjs_get_leb128_int(r, &var_idx) < 0) goto fail;
        if (qjs_get_atom(r, &import_name) < 0) goto fail;
        if (qjs_get_leb128_int(r, &req_module_idx) < 0) goto fail;
        (void)var_idx; (void)import_name; (void)req_module_idx;
    }

    /* has_tla flag */
    uint8_t has_tla = 0;
    if (qjs_get_u8(r, &has_tla) < 0) goto fail;
    (void)has_tla;

    /* the module body is a function */
    qjs_value_t *fv = qjs_read_value(r, 1, 1);
    if (!fv || fv->kind != QJS_VAL_FUNCTION) {
        if (fv) qjs_value_free(fv);
        goto fail;
    }
    m->func = fv->u.func.fn;
    free(fv); /* don't free the function itself */

    return m;

fail:
    qjs_module_free(m);
    return NULL;
}

/* =========================================================
 * Read object (BC_TAG_OBJECT)
 * ========================================================= */
static qjs_value_t *read_object(qjs_reader_t *r) {
    uint32_t class_atom;
    if (qjs_get_atom(r, &class_atom) < 0) return NULL;

    uint32_t count;
    if (qjs_get_leb128(r, &count) < 0) return NULL;

    qjs_value_t *v = xcalloc(1, sizeof(*v));
    v->kind = QJS_VAL_OBJECT;
    v->u.obj.class_atom = class_atom;
    v->u.obj.count = count;
    if (count > 0) {
        v->u.obj.props = xcalloc(count, sizeof(qjs_prop_t));
        for (uint32_t i = 0; i < count; i++) {
            if (qjs_get_atom(r, &v->u.obj.props[i].key_atom) < 0) goto fail;
            v->u.obj.props[i].value = qjs_read_value(r, 1, 1);
            if (!v->u.obj.props[i].value) goto fail;
        }
    }
    v->u.obj.proto = qjs_read_value(r, 1, 1);
    if (!v->u.obj.proto) goto fail;

    if (qjs_add_obj_ref(r, v) < 0) goto fail;
    return v;

fail:
    qjs_value_free(v);
    return NULL;
}

/* =========================================================
 * Read array (BC_TAG_ARRAY / BC_TAG_TEMPLATE_OBJECT)
 * ========================================================= */
static qjs_value_t *read_array(qjs_reader_t *r, int is_template) {
    uint32_t count;
    if (qjs_get_leb128(r, &count) < 0) return NULL;

    qjs_value_t *v = xcalloc(1, sizeof(*v));
    v->kind = is_template ? QJS_VAL_TEMPLATE_OBJECT : QJS_VAL_ARRAY;
    v->u.arr.count = count;
    if (count > 0) {
        v->u.arr.items = xcalloc(count, sizeof(qjs_value_t *));
        for (uint32_t i = 0; i < count; i++) {
            v->u.arr.items[i] = qjs_read_value(r, 1, 1);
            if (!v->u.arr.items[i]) goto fail;
        }
    }
    if (qjs_add_obj_ref(r, v) < 0) goto fail;
    return v;

fail:
    qjs_value_free(v);
    return NULL;
}

/* =========================================================
 * Read typed array (BC_TAG_TYPED_ARRAY)
 * ========================================================= */
static qjs_value_t *read_typed_array(qjs_reader_t *r) {
    /* For now, just skip - this is rarely used in compiled bytecode */
    uint8_t array_type, tranjaronant;
    if (qjs_get_u8(r, &array_type) < 0) return NULL;
    if (qjs_get_u8(r, &tranjaronant) < 0) return NULL;
    qjs_value_t *ab = qjs_read_value(r, 1, 1);
    if (!ab) return NULL;
    int32_t offset, length, byte_length;
    if (qjs_get_leb128_int(r, &offset) < 0) { qjs_value_free(ab); return NULL; }
    if (qjs_get_leb128_int(r, &length) < 0) { qjs_value_free(ab); return NULL; }
    if (qjs_get_leb128_int(r, &byte_length) < 0) { qjs_value_free(ab); return NULL; }

    qjs_value_t *v = xcalloc(1, sizeof(*v));
    v->kind = QJS_VAL_TYPED_ARRAY;
    (void)ab; /* would need to track this properly */
    qjs_value_free(ab);
    return v;
}

/* =========================================================
 * Top-level value reader
 * ========================================================= */
qjs_value_t *qjs_read_value(qjs_reader_t *r, int allow_bytecode, int allow_reference) {
    uint8_t tag;
    if (qjs_get_u8(r, &tag) < 0) return NULL;

    switch (tag) {
        case QJS_BC_TAG_NULL:
            { qjs_value_t *v = xcalloc(1, sizeof(*v)); v->kind = QJS_VAL_NULL; return v; }
        case QJS_BC_TAG_UNDEFINED:
            { qjs_value_t *v = xcalloc(1, sizeof(*v)); v->kind = QJS_VAL_UNDEFINED; return v; }
        case QJS_BC_TAG_BOOL_FALSE:
        case QJS_BC_TAG_BOOL_TRUE:
            { qjs_value_t *v = xcalloc(1, sizeof(*v)); v->kind = QJS_VAL_BOOL; v->u.b = tag - QJS_BC_TAG_BOOL_FALSE; return v; }
        case QJS_BC_TAG_INT32: {
            int32_t val;
            if (qjs_get_sleb128(r, &val) < 0) return NULL;
            qjs_value_t *v = xcalloc(1, sizeof(*v));
            v->kind = QJS_VAL_INT32;
            v->u.i32 = val;
            return v;
        }
        case QJS_BC_TAG_FLOAT64: {
            uint64_t raw;
            if (qjs_get_u64(r, &raw) < 0) return NULL;
            double d;
            memcpy(&d, &raw, sizeof(d));
            qjs_value_t *v = xcalloc(1, sizeof(*v));
            v->kind = QJS_VAL_FLOAT64;
            v->u.f64 = d;
            return v;
        }
        case QJS_BC_TAG_STRING: {
            char *s; uint32_t len; uint8_t wide;
            if (read_string_value(r, &s, &len, &wide) < 0) return NULL;
            qjs_value_t *v = xcalloc(1, sizeof(*v));
            v->kind = QJS_VAL_STRING;
            v->u.str.data = s;
            v->u.str.len = len;
            v->u.str.is_wide = wide;
            return v;
        }
        case QJS_BC_TAG_OBJECT:
            return read_object(r);
        case QJS_BC_TAG_ARRAY:
            return read_array(r, 0);
        case QJS_BC_TAG_TEMPLATE_OBJECT:
            return read_array(r, 1);
        case QJS_BC_TAG_BIG_INT:
        case QJS_BC_TAG_BIG_FLOAT:
        case QJS_BC_TAG_BIG_DECIMAL:
            return read_bignum(r, tag);
        case QJS_BC_TAG_FUNCTION_BYTECODE:
            if (!allow_bytecode) {
                qjs_reader_set_error(r, "bytecode tag not allowed here");
                return NULL;
            }
            {
                qjs_function_t *fn = read_function(r);
                if (!fn) return NULL;
                qjs_value_t *v = xcalloc(1, sizeof(*v));
                v->kind = QJS_VAL_FUNCTION;
                v->u.func.fn = fn;
                r->func_count++;
                fn->func_idx = r->func_count;
                return v;
            }
        case QJS_BC_TAG_MODULE:
            if (!allow_bytecode) {
                qjs_reader_set_error(r, "module tag not allowed here");
                return NULL;
            }
            {
                qjs_module_t *m = read_module(r);
                if (!m) return NULL;
                qjs_value_t *v = xcalloc(1, sizeof(*v));
                v->kind = QJS_VAL_MODULE;
                v->u.mod.mod = m;
                return v;
            }
        case QJS_BC_TAG_TYPED_ARRAY:
            return read_typed_array(r);
        case QJS_BC_TAG_ARRAY_BUFFER:
        case QJS_BC_TAG_SHARED_ARRAY_BUFFER: {
            uint32_t len;
            if (qjs_get_leb128(r, &len) < 0) return NULL;
            uint8_t *data = len ? xmalloc(len) : NULL;
            if (len && qjs_get_buf(r, data, len) < 0) { free(data); return NULL; }
            qjs_value_t *v = xcalloc(1, sizeof(*v));
            v->kind = (tag == QJS_BC_TAG_SHARED_ARRAY_BUFFER) ? QJS_VAL_SHARED_ARRAY_BUFFER : QJS_VAL_ARRAY_BUFFER;
            /* store data as a string for now */
            v->u.str.data = (char *)data;
            v->u.str.len = len;
            v->u.str.is_wide = 0;
            if (qjs_add_obj_ref(r, v) < 0) { qjs_value_free(v); return NULL; }
            return v;
        }
        case QJS_BC_TAG_DATE: {
            qjs_value_t *v = xcalloc(1, sizeof(*v));
            v->kind = QJS_VAL_DATE;
            /* a Date is an object with a single time value (float64) */
            qjs_value_t *proto = qjs_read_value(r, 1, 1);
            if (proto) qjs_value_free(proto); /* ignored */
            uint64_t raw;
            if (qjs_get_u64(r, &raw) < 0) { qjs_value_free(v); return NULL; }
            double d; memcpy(&d, &raw, sizeof(d));
            v->u.f64 = d;
            return v;
        }
        case QJS_BC_TAG_OBJECT_VALUE: {
            qjs_value_t *v = xcalloc(1, sizeof(*v));
            v->kind = QJS_VAL_OBJECT_VALUE;
            /* object-value is an object with extra state; read as object */
            qjs_value_t *obj = read_object(r);
            (void)obj;
            if (obj) qjs_value_free(obj);
            return v;
        }
        case QJS_BC_TAG_OBJECT_REFERENCE: {
            uint32_t ref;
            if (qjs_get_leb128(r, &ref) < 0) return NULL;
            if (!allow_reference) {
                qjs_reader_set_error(r, "object reference not allowed");
                return NULL;
            }
            if (ref >= (uint32_t)r->obj_refs_count) {
                qjs_reader_set_error(r, "invalid object reference");
                return NULL;
            }
            qjs_value_t *v = xcalloc(1, sizeof(*v));
            v->kind = QJS_VAL_OBJECT_REFERENCE;
            v->u.ref.ref_idx = ref;
            return v;
        }
        default:
            qjs_reader_set_error(r, "unknown BC tag");
            return NULL;
    }
}

/* =========================================================
 * Object references
 * ========================================================= */
int qjs_add_obj_ref(qjs_reader_t *r, qjs_value_t *v) {
    if (r->obj_refs_count >= r->obj_refs_cap) {
        int new_cap = r->obj_refs_cap ? r->obj_refs_cap * 2 : 32;
        if (new_cap > QJS_MAX_OBJ_REFS) {
            qjs_reader_set_error(r, "too many object references");
            return -1;
        }
        r->obj_refs = xrealloc(r->obj_refs, new_cap * sizeof(qjs_value_t *));
        r->obj_refs_cap = new_cap;
    }
    r->obj_refs[r->obj_refs_count++] = v;
    return 0;
}

/* Check if any function in the tree has is_frida=1 */
static int check_frida_recursive(qjs_function_t *fn) {
    if (fn->is_frida) return 1;
    if (fn->cpool) {
        for (int i = 0; i < fn->cpool_count; i++) {
            if (fn->cpool[i] && fn->cpool[i]->kind == QJS_VAL_FUNCTION) {
                if (check_frida_recursive(fn->cpool[i]->u.func.fn)) return 1;
            }
        }
    }
    return 0;
}

/* Set is_frida=1 for ALL functions in the tree */
static void set_frida_recursive(qjs_function_t *fn) {
    fn->is_frida = 1;
    if (fn->cpool) {
        for (int i = 0; i < fn->cpool_count; i++) {
            if (fn->cpool[i] && fn->cpool[i]->kind == QJS_VAL_FUNCTION) {
                set_frida_recursive(fn->cpool[i]->u.func.fn);
            }
        }
    }
}

/* =========================================================
 * Top-level parse
 * ========================================================= */
qjs_value_t *qjs_parse_bytecode(const uint8_t *buf, size_t len,
                                 int allow_bytecode, int allow_reference) {
    qjs_reader_t rs;
    qjs_reader_init(&rs, buf, len);

    /* For bytecode mode, first_atom = JS_ATOM_END = QJS_BUILTIN_ATOM_COUNT.
     * For non-bytecode mode, first_atom = 1 (just JS_ATOM_NULL). */
    if (allow_bytecode) {
        rs.atoms.first_atom = QJS_BUILTIN_ATOM_COUNT;
    } else {
        rs.atoms.first_atom = 1;
    }

    if (parse_atom_table(&rs) < 0) {
        return NULL;
    }

    qjs_value_t *v = qjs_read_value(&rs, allow_bytecode, allow_reference);

    /* After parsing, propagate is_frida flag through the entire function tree.
     * If any function uses temporary opcodes, ALL functions should use Frida mode. */
    if (v && v->kind == QJS_VAL_FUNCTION) {
        if (check_frida_recursive(v->u.func.fn))
            set_frida_recursive(v->u.func.fn);
    } else if (v && v->kind == QJS_VAL_MODULE) {
        if (v->u.mod.mod->func) {
            if (check_frida_recursive(v->u.mod.mod->func))
                set_frida_recursive(v->u.mod.mod->func);
        }
    }

    return v;
}

/* =========================================================
 * Free functions
 * ========================================================= */
void qjs_function_free(qjs_function_t *fn) {
    if (!fn) return;
    free(fn->vardefs);
    free(fn->closure_vars);
    free(fn->byte_code);
    free(fn->atom_refs);
    free(fn->debug_pc2line);
    if (fn->cpool) {
        for (int i = 0; i < fn->cpool_count; i++)
            qjs_value_free(fn->cpool[i]);
        free(fn->cpool);
    }
    free(fn);
}

void qjs_module_free(qjs_module_t *m) {
    if (!m) return;
    free(m->req_modules);
    free(m->exports);
    free(m->star_exports);
    free(m->export_star);
    qjs_function_free(m->func);
    free(m);
}

void qjs_value_free(qjs_value_t *v) {
    if (!v) return;
    switch (v->kind) {
        case QJS_VAL_STRING:
        case QJS_VAL_ARRAY_BUFFER:
        case QJS_VAL_SHARED_ARRAY_BUFFER:
            free(v->u.str.data);
            break;
        case QJS_VAL_OBJECT:
            if (v->u.obj.props) {
                for (uint32_t i = 0; i < v->u.obj.count; i++)
                    qjs_value_free(v->u.obj.props[i].value);
                free(v->u.obj.props);
            }
            qjs_value_free(v->u.obj.proto);
            break;
        case QJS_VAL_ARRAY:
        case QJS_VAL_TEMPLATE_OBJECT:
            if (v->u.arr.items) {
                for (uint32_t i = 0; i < v->u.arr.count; i++)
                    qjs_value_free(v->u.arr.items[i]);
                free(v->u.arr.items);
            }
            break;
        case QJS_VAL_BIG_INT:
        case QJS_VAL_BIG_FLOAT:
        case QJS_VAL_BIG_DECIMAL:
            free(v->u.bignum.digits);
            break;
        case QJS_VAL_FUNCTION:
            qjs_function_free(v->u.func.fn);
            break;
        case QJS_VAL_MODULE:
            qjs_module_free(v->u.mod.mod);
            break;
        case QJS_VAL_ERROR:
            free(v->u.err.msg);
            break;
        default:
            break;
    }
    free(v);
}
