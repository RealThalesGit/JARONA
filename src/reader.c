/*
 * reader.c - Binary reader implementation
 */
#include "reader.h"

void qjs_reader_init(qjs_reader_t *r, const uint8_t *buf, size_t len) {
    memset(r, 0, sizeof(*r));
    r->buf = buf;
    r->buf_len = len;
    r->ptr = buf;
    r->end = buf + len;
    r->error = 0;
    r->big_endian = 0;
    r->atoms.atoms = NULL;
    r->atoms.count = 0;
    r->atoms.first_atom = 1; /* JS_ATOM_END */
    r->obj_refs = NULL;
    r->obj_refs_count = 0;
    r->obj_refs_cap = 0;
}

void qjs_reader_set_error(qjs_reader_t *r, const char *msg) {
    if (!r->error) {
        r->error = 1;
        snprintf(r->error_msg, sizeof(r->error_msg), "%s (at offset %zu)",
                 msg ? msg : "unknown error", qjs_reader_pos(r));
    }
}

int qjs_reader_has_error(const qjs_reader_t *r) {
    return r->error;
}

int qjs_get_u8(qjs_reader_t *r, uint8_t *v) {
    if (r->ptr + 1 > r->end) {
        qjs_reader_set_error(r, "unexpected EOF reading u8");
        *v = 0;
        return -1;
    }
    *v = r->ptr[0];
    r->ptr += 1;
    return 0;
}

int qjs_get_i8(qjs_reader_t *r, int8_t *v) {
    uint8_t u;
    if (qjs_get_u8(r, &u) < 0) { *v = 0; return -1; }
    *v = (int8_t)u;
    return 0;
}

int qjs_get_u16(qjs_reader_t *r, uint16_t *v) {
    if (r->ptr + 2 > r->end) {
        qjs_reader_set_error(r, "unexpected EOF reading u16");
        *v = 0;
        return -1;
    }
    *v = rd_u16(r->ptr, r->big_endian);
    r->ptr += 2;
    return 0;
}

int qjs_get_i16(qjs_reader_t *r, int16_t *v) {
    uint16_t u;
    if (qjs_get_u16(r, &u) < 0) { *v = 0; return -1; }
    *v = (int16_t)u;
    return 0;
}

int qjs_get_u32(qjs_reader_t *r, uint32_t *v) {
    if (r->ptr + 4 > r->end) {
        qjs_reader_set_error(r, "unexpected EOF reading u32");
        *v = 0;
        return -1;
    }
    *v = rd_u32(r->ptr, r->big_endian);
    r->ptr += 4;
    return 0;
}

int qjs_get_i32(qjs_reader_t *r, int32_t *v) {
    uint32_t u;
    if (qjs_get_u32(r, &u) < 0) { *v = 0; return -1; }
    *v = (int32_t)u;
    return 0;
}

int qjs_get_u64(qjs_reader_t *r, uint64_t *v) {
    if (r->ptr + 8 > r->end) {
        qjs_reader_set_error(r, "unexpected EOF reading u64");
        *v = 0;
        return -1;
    }
    *v = rd_u64(r->ptr, r->big_endian);
    r->ptr += 8;
    return 0;
}

int qjs_get_leb128(qjs_reader_t *r, uint32_t *v) {
    int n = get_leb128_u32(v, r->ptr, r->end);
    if (n < 0) {
        qjs_reader_set_error(r, "invalid LEB128 or EOF");
        *v = 0;
        return -1;
    }
    r->ptr += n;
    return 0;
}

int qjs_get_sleb128(qjs_reader_t *r, int32_t *v) {
    int n = get_sleb128_i32(v, r->ptr, r->end);
    if (n < 0) {
        qjs_reader_set_error(r, "invalid SLEB128 or EOF");
        *v = 0;
        return -1;
    }
    r->ptr += n;
    return 0;
}

int qjs_get_leb128_int(qjs_reader_t *r, int *v) {
    uint32_t u;
    if (qjs_get_leb128(r, &u) < 0) { *v = 0; return -1; }
    *v = (int)u;
    return 0;
}

int qjs_get_leb128_u16(qjs_reader_t *r, uint16_t *v) {
    uint32_t u;
    if (qjs_get_leb128(r, &u) < 0) { *v = 0; return -1; }
    *v = (uint16_t)u;
    return 0;
}

int qjs_get_buf(qjs_reader_t *r, uint8_t *buf, uint32_t len) {
    if (len == 0) return 0;
    if (r->ptr + len > r->end) {
        qjs_reader_set_error(r, "unexpected EOF reading buffer");
        return -1;
    }
    memcpy(buf, r->ptr, len);
    r->ptr += len;
    return 0;
}

int qjs_get_atom(qjs_reader_t *r, uint32_t *atom_idx) {
    uint32_t v;
    if (qjs_get_leb128(r, &v) < 0) {
        *atom_idx = 0;
        return -1;
    }
    if (v & 1) {
        /* tagged-int atom: store as value | (1U << 31) to match
         * QuickJS __JS_AtomFromUInt32 (which sets JS_ATOM_TAG_INT). */
        *atom_idx = (v >> 1) | 0x80000000u;
        return 0;
    }
    /* regular atom: store the index (= v >> 1), no high bit set */
    *atom_idx = v >> 1;
    return 0;
}
