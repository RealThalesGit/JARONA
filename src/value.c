/*
 * value.c - JS value parser implementation
 */
#include "value.h"
#include "qjs_opcodes.h"
#include "qjs_builtin_atoms.h"
#include <stdio.h>
#include <inttypes.h>

/* =========================================================
 * Atom table parsing (called once per blob)
 * ========================================================= */

/* Make room for `extra` more user atoms in the shared arena. */
static int atom_arena_reserve(qjs_reader_t *r, uint32_t extra) {
    uint32_t need = r->atoms.count + extra;
    if (need <= r->atoms.arena_cap) return 0;

    uint32_t cap = r->atoms.arena_cap ? r->atoms.arena_cap * 2 : 16;
    while (cap < need) {
        if (cap > QJS_MAX_ATOMS / 2) { cap = need; break; }
        cap *= 2;
    }
    if (cap > QJS_MAX_ATOMS) {
        qjs_reader_set_error(r, "too many atoms");
        return -1;
    }
    r->atoms.atoms     = xrealloc(r->atoms.atoms, (size_t)cap * sizeof(char *));
    r->atoms.atom_lens = xrealloc(r->atoms.atom_lens, (size_t)cap * sizeof(uint32_t));
    r->atoms.atom_wide = xrealloc(r->atoms.atom_wide, (size_t)cap * sizeof(uint8_t));
    r->atoms.arena_cap = cap;
    return 0;
}

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

    uint32_t count;
    if (qjs_get_leb128(r, &count) < 0) return -1;
    if (count > QJS_MAX_ATOMS) {
        qjs_reader_set_error(r, "too many atoms");
        return -1;
    }

    /* The atoms of this blob are appended to the shared arena. */
    r->blob_atom_base  = r->atoms.count;
    r->blob_atom_count = count;
    r->atoms.saw_user_ref = 0;
    r->atoms.max_user_ref = 0;

    if (count == 0) return 0;

    if (atom_arena_reserve(r, count) < 0) return -1;

    for (uint32_t i = 0; i < count; i++) {
        uint32_t len;
        if (qjs_get_leb128(r, &len) < 0) return -1;
        int is_wide = len & 1;
        len >>= 1;

        if (len > QJS_MAX_STRING_LEN) {
            qjs_reader_set_error(r, "atom too long");
            return -1;
        }

        uint32_t slot = r->blob_atom_base + i;

        /* always store as UTF-8; if wide, we convert (best-effort) */
        if (!is_wide) {
            char *s = xmalloc(len + 1);
            if (qjs_get_buf(r, (uint8_t *)s, len) < 0) { free(s); return -1; }
            s[len] = '\0';
            r->atoms.atoms[slot] = s;
            r->atoms.atom_lens[slot] = len;
            r->atoms.atom_wide[slot] = 0;
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
            r->atoms.atoms[slot] = out;
            r->atoms.atom_lens[slot] = (uint32_t)oi;
            r->atoms.atom_wide[slot] = 1;
        }
        r->atoms.count = slot + 1;
    }
    return 0;
}

/* =========================================================
 * Atom resolution
 *
 * The stored atom_idx uses bit 31 (JS_ATOM_TAG_INT) as the tag:
 *   - If bit 31 is set: tagged-int atom. Integer value = atom_idx & 0x7FFFFFFF.
 *   - Else: regular atom index.
 *     - If idx < first_atom: built-in atom (look up in the flavour's table).
 *     - Else: idx -= first_atom, look up in user atom table.
 * ========================================================= */

/* Resolve a built-in atom index for the given flavour. */
static const char *builtin_atom_str(int flavor, uint32_t idx) {
    const char *const *table;
    uint32_t limit;

    if (flavor == QJS_ATOM_FLAVOR_FRIDA) {
        table = qjs_atoms_frida;
        limit = QJS_FRIDA_ATOM_END;
    } else {
        table = qjs_atoms_vanilla;
        limit = QJS_VANILLA_ATOM_END;
    }
    if (idx < limit && table[idx])
        return table[idx];
    return NULL;
}

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
        const char *s = builtin_atom_str(r->atoms.flavor, idx);
        if (s) return s;
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

/* Like qjs_atom_str(), but also reports the exact byte length of the atom.
 * QuickJS strings may contain NUL bytes, so a strlen() based copy would
 * truncate them. */
const char *qjs_atom_str_len(qjs_reader_t *r, uint32_t atom_idx, uint32_t *len) {
    static char buf[64];

    if (len) *len = 0;

    if (atom_idx & 0x80000000u) {
        snprintf(buf, sizeof(buf), "%u", atom_idx & 0x7FFFFFFFu);
        if (len) *len = (uint32_t)strlen(buf);
        return buf;
    }

    uint32_t idx = atom_idx;
    uint32_t first = r->atoms.first_atom;
    if (idx < first) {
        const char *s = builtin_atom_str(r->atoms.flavor, idx);
        if (s) {
            if (len) *len = (uint32_t)strlen(s);
            return s;
        }
        snprintf(buf, sizeof(buf), "_builtin_%u", idx);
        if (len) *len = (uint32_t)strlen(buf);
        return buf;
    }
    idx -= first;
    if (idx >= r->atoms.count) {
        snprintf(buf, sizeof(buf), "_atom_oob_%u", atom_idx);
        if (len) *len = (uint32_t)strlen(buf);
        return buf;
    }
    if (!r->atoms.atoms || !r->atoms.atoms[idx]) {
        snprintf(buf, sizeof(buf), "_atom_null_%u", atom_idx);
        if (len) *len = (uint32_t)strlen(buf);
        return buf;
    }
    if (len && r->atoms.atom_lens)
        *len = r->atoms.atom_lens[idx];
    return r->atoms.atoms[idx];
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
 * Big-number mantissa -> decimal string
 *
 * libbf stores a finite number as  value = B * 2^(expn - 8*len),
 * where B is the little-endian integer formed by the serialised
 * mantissa bytes.  The limb size of the writer cancels out of that
 * formula, so the byte stream alone is enough to recover the value.
 *
 * The conversion below works on a little-endian base-2^32 limb
 * array: it first applies the binary shift and then repeatedly
 * divides by 10 to produce the decimal digits.  No libbf is needed.
 * ========================================================= */
static char *bignum_to_decimal(const uint8_t *raw, uint32_t len,
                               int64_t shift, int neg) {
    size_t n = (len + 3) / 4;
    uint32_t *a = xcalloc(n ? n : 1, sizeof(uint32_t));
    for (uint32_t i = 0; i < len; i++)
        a[i / 4] |= (uint32_t)raw[i] << ((i % 4) * 8);

    if (shift > 0) {
        size_t words = (size_t)((uint64_t)shift / 32);
        int bits = (int)((uint64_t)shift % 32);
        uint32_t *b = xcalloc(n + words + 1, sizeof(uint32_t));
        for (size_t i = 0; i < n; i++) {
            uint64_t v = (uint64_t)a[i] << bits;
            b[i + words] |= (uint32_t)v;
            b[i + words + 1] |= (uint32_t)(v >> 32);
        }
        free(a);
        a = b;
        n = n + words + 1;
    } else if (shift < 0) {
        uint64_t s = (uint64_t)(-shift);
        size_t words = (size_t)(s / 32);
        int bits = (int)(s % 32);
        if (words >= n) {
            free(a);
            a = NULL;
            n = 0;
        } else {
            size_t nn = n - words;
            uint32_t *b = xcalloc(nn, sizeof(uint32_t));
            for (size_t i = 0; i < nn; i++) {
                uint64_t v = a[i + words];
                if (bits && i + words + 1 < n)
                    v |= (uint64_t)a[i + words + 1] << 32;
                b[i] = (uint32_t)(v >> bits);
            }
            free(a);
            a = b;
            n = nn;
        }
    }

    while (n > 0 && a[n - 1] == 0) n--;

    /* 32 bits hold at most 10 decimal digits. */
    char *rev = xmalloc(n * 10 + 2);
    size_t rn = 0;
    while (n > 0) {
        uint64_t rem = 0;
        for (size_t i = n; i-- > 0;) {
            uint64_t cur = (rem << 32) | a[i];
            a[i] = (uint32_t)(cur / 10);
            rem = cur % 10;
        }
        rev[rn++] = (char)('0' + rem);
        while (n > 0 && a[n - 1] == 0) n--;
    }
    if (rn == 0) rev[rn++] = '0';

    int is_zero = (rn == 1 && rev[0] == '0');
    char *out = xmalloc(rn + 2);
    size_t k = 0;
    if (neg && !is_zero) out[k++] = '-';
    for (size_t i = rn; i-- > 0;) out[k++] = rev[i];
    out[k] = '\0';

    free(rev);
    free(a);
    return out;
}

/* Convert the little-endian packed BCD mantissa of a big decimal into a
 * plain decimal digit string (most significant digit first). */
static char *bigdecimal_digits(const uint8_t *raw, uint32_t len) {
    char *out = xmalloc(len + 2);
    size_t k = 0;
    int started = 0;
    for (uint32_t i = len; i-- > 0;) {
        int hi = raw[i] >> 4;
        int lo = raw[i] & 0xf;
        int d[2];
        int nd = 0;
        /* The most significant nibble is a pad zero when len is odd. */
        if (i != len - 1 || (len & 1) == 0) d[nd++] = hi;
        d[nd++] = lo;
        for (int j = 0; j < nd; j++) {
            if (!started && d[j] == 0) {
                if (i == 0 && j == nd - 1) out[k++] = '0';
                continue;
            }
            started = 1;
            out[k++] = (char)('0' + d[j]);
        }
    }
    if (k == 0) out[k++] = '0';
    out[k] = '\0';
    return out;
}

/* =========================================================
 * Read a bignum (BC_TAG_BIG_INT / BIG_FLOAT / BIG_DECIMAL)
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
            uint8_t *raw = xmalloc(len);
            if (qjs_get_buf(r, raw, len) < 0) { free(raw); qjs_value_free(v); return NULL; }
            if (kind == QJS_BC_TAG_BIG_DECIMAL) {
                char *digits = bigdecimal_digits(raw, len);
                int64_t shift = v->u.bignum.expn - (int64_t)len;
                if (shift != 0) {
                    /* Append the decimal exponent so the value survives. */
                    size_t dl = strlen(digits);
                    char *tmp = xmalloc(dl + 32);
                    snprintf(tmp, dl + 32, "%se%" PRId64, digits, shift);
                    free(digits);
                    digits = tmp;
                }
                v->u.bignum.digits = digits;
            } else {
                int64_t shift = v->u.bignum.expn - (int64_t)len * 8;
                v->u.bignum.digits = bignum_to_decimal(raw, len, shift,
                                                       v->u.bignum.sign);
            }
            free(raw);
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
/* =========================================================
 * Read function
 * ========================================================= */

/*
 * Rewrite the atom operands of a byte code body so that they address the
 * shared atom arena.
 *
 * QuickJS stores "first_atom + index_in_the_blob_atom_table" in the byte
 * code.  When a file holds several blobs (one per module) every blob has
 * its own atom table, so the index has to be shifted by the offset of the
 * blob inside the arena.
 *
 * Built-in atoms (< first_atom) and tagged integer atoms keep their value.
 */
static void patch_bytecode_atoms(qjs_reader_t *r, uint8_t *bc, uint32_t len,
                                 qjs_op_mode_t mode) {
    uint32_t base = r->blob_atom_base;
    uint32_t first = r->atoms.first_atom;
    if (base == 0) return;

    for (uint32_t pc = 0; pc < len;) {
        uint8_t op = bc[pc];
        const qjs_op_info_t *info = qjs_get_op_info(op, mode);
        if (!info || info->size == 0) break;

        switch (info->fmt) {
            case QJS_FMT_atom:
            case QJS_FMT_atom_u8:
            case QJS_FMT_atom_u16:
            case QJS_FMT_atom_label_u8:
            case QJS_FMT_atom_label_u16: {
                if (pc + 5 > len) return;
                uint32_t v = rd_u32(bc + pc + 1, r->big_endian);
                if (!(v & 0x80000000u) && v >= first) {
                    wr_u32(bc + pc + 1, v + base, r->big_endian);
                }
                break;
            }
            default:
                break;
        }
        pc += info->size;
    }
}

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

    /* Auto-detect the opcode dialect (stock QuickJS vs Frida's fork). */
    fn->is_frida = (qjs_detect_op_mode(fn->byte_code, fn->byte_code_len,
                                       r->big_endian) == QJS_MODE_FRIDA);

    /* Shift the atom operands into the shared atom arena. */
    patch_bytecode_atoms(r, fn->byte_code, (uint32_t)fn->byte_code_len,
                         fn->is_frida ? QJS_MODE_FRIDA : QJS_MODE_VANILLA);

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

    /* import entries */
    int import_count = 0;
    if (qjs_get_leb128_int(r, &import_count) < 0) goto fail;
    if (import_count > 0) {
        m->imports = xcalloc(import_count, sizeof(qjs_import_entry_t));
        m->import_count = import_count;
        for (int i = 0; i < import_count; i++) {
            qjs_import_entry_t *ie = &m->imports[i];
            if (qjs_get_leb128_int(r, &ie->var_idx) < 0) goto fail;
            if (qjs_get_atom(r, &ie->import_name_atom) < 0) goto fail;
            if (qjs_get_leb128_int(r, &ie->req_module_idx) < 0) goto fail;
        }
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
    /* Tagged-template objects serialise an extra value: the "raw" array.
     * It must be consumed even when we do not use it, otherwise the rest
     * of the stream is misaligned. */
    if (is_template) {
        v->u.arr.raw = qjs_read_value(r, 1, 1);
        if (!v->u.arr.raw) goto fail;
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

/* Parse the bytecode with a specific atom flavour.
 *
 * `strict` enables the atom-table consistency check that tells the vanilla
 * and Frida flavours apart.  All top-level values of the file are parsed;
 * a QuickJS byte code file produced by "qjsc -c" contains the main module
 * followed by all of its dependencies.
 *
 * Returns 0 on success and stores the values in *out_values / *out_count. */
static int parse_with_flavor(qjs_reader_t *rs, const uint8_t *buf,
                              size_t len, int allow_bytecode,
                              int allow_reference, int flavor,
                              int strict, qjs_value_t ***out_values,
                              int *out_count) {
    qjs_reader_init(rs, buf, len);

    /* For bytecode mode, first_atom = JS_ATOM_END of the producing runtime.
     * For non-bytecode mode, first_atom = 1 (just JS_ATOM_NULL). */
    rs->atoms.flavor = flavor;
    rs->atoms.first_atom = allow_bytecode
        ? ((flavor == QJS_ATOM_FLAVOR_FRIDA) ? QJS_FRIDA_ATOM_END
                                             : QJS_VANILLA_ATOM_END)
        : 1;

    /* Read every blob of the file.  A byte code file produced by
     * "qjsc -c" holds one blob per module: the dependencies first, the
     * main module last.  Every blob carries its own atom table, so the
     * blob header (version byte + atom table) is re-read for each of
     * them. */
    qjs_value_t **values = NULL;
    int count = 0, cap = 0;
    while (rs->ptr < rs->end) {
        /* A blob header starts with the byte code version byte. */
        uint8_t peek;
        if (qjs_reader_peek(rs, &peek) < 0) break;
        int ver = peek & 0x3f;
        if (ver != 1 && ver != 2) {
            /* Not a blob header: trailing garbage, stop here. */
            break;
        }

        if (parse_atom_table(rs) < 0) {
            if (count == 0) {
                free(values);
                qjs_reader_cleanup(rs);
                return -1;
            }
            break;
        }

        uint32_t blob_count = rs->blob_atom_count;

        qjs_value_t *v = qjs_read_value(rs, allow_bytecode, allow_reference);
        if (!v) {
            if (count == 0) {
                free(values);
                qjs_reader_cleanup(rs);
                return -1;
            }
            break;
        }

        /* Every atom listed in the blob's atom table was referenced at
         * least once, so the highest user-atom index must be count - 1.
         * A mismatch means the flavour guess was wrong. */
        if (strict && allow_bytecode && blob_count > 0) {
            int consistent = rs->atoms.saw_user_ref &&
                             rs->atoms.max_user_ref == blob_count - 1;
            if (!consistent) {
                qjs_value_free(v);
                for (int i = 0; i < count; i++) qjs_value_free(values[i]);
                free(values);
                qjs_reader_cleanup(rs);
                return -1;
            }
        }

        if (count >= cap) {
            cap = cap ? cap * 2 : 4;
            values = xrealloc(values, (size_t)cap * sizeof(qjs_value_t *));
        }
        values[count++] = v;
    }

    if (count == 0) {
        free(values);
        qjs_reader_cleanup(rs);
        return -1;
    }

    /* After parsing, propagate the is_frida flag through the entire
     * function tree.  If any function uses temporary opcodes, ALL
     * functions should use Frida mode. */
    for (int i = 0; i < count; i++) {
        qjs_value_t *v = values[i];
        if (v->kind == QJS_VAL_FUNCTION) {
            if (check_frida_recursive(v->u.func.fn))
                set_frida_recursive(v->u.func.fn);
        } else if (v->kind == QJS_VAL_MODULE) {
            if (v->u.mod.mod->func) {
                if (check_frida_recursive(v->u.mod.mod->func))
                    set_frida_recursive(v->u.mod.mod->func);
            }
        }
    }

    *out_values = values;
    *out_count = count;
    return 0;
}

int qjs_parse_bytecode_list(qjs_reader_t *rs, const uint8_t *buf, size_t len,
                            int allow_bytecode, int allow_reference,
                            qjs_value_t ***out_values, int *out_count) {
    qjs_value_t **values = NULL;
    int count = 0;

    /* Try vanilla first (by far the most common), then Frida's fork. */
    if (parse_with_flavor(rs, buf, len, allow_bytecode, allow_reference,
                          QJS_ATOM_FLAVOR_VANILLA, 1, &values, &count) == 0) {
        *out_values = values;
        *out_count = count;
        return 0;
    }

    if (parse_with_flavor(rs, buf, len, allow_bytecode, allow_reference,
                          QJS_ATOM_FLAVOR_FRIDA, 1, &values, &count) == 0) {
        *out_values = values;
        *out_count = count;
        return 0;
    }

    /* Both flavours failed.  Retry vanilla without the strict consistency
     * check so the user still gets a (possibly partial) disassembly. */
    if (parse_with_flavor(rs, buf, len, allow_bytecode, allow_reference,
                          QJS_ATOM_FLAVOR_VANILLA, 0, &values, &count) == 0) {
        *out_values = values;
        *out_count = count;
        return 0;
    }

    return -1;
}

qjs_value_t *qjs_parse_bytecode(qjs_reader_t *rs, const uint8_t *buf, size_t len,
                                 int allow_bytecode, int allow_reference) {
    qjs_value_t **values = NULL;
    int count = 0;
    if (qjs_parse_bytecode_list(rs, buf, len, allow_bytecode, allow_reference,
                                &values, &count) < 0)
        return NULL;

    /* Keep the first value and release the rest; callers that need every
     * value of the file use qjs_parse_bytecode_list(). */
    qjs_value_t *first = values[0];
    for (int i = 1; i < count; i++) qjs_value_free(values[i]);
    free(values);
    return first;
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
    free(m->imports);
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
            qjs_value_free(v->u.arr.raw);
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
