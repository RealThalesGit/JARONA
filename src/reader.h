/*
 * reader.h - Binary reader for QuickJS bytecode
 *
 * Wraps a buffer with bounds checking, endian awareness, and
 * LEB128 decoding. Mirrors the BCReaderState interface in quickjs.c
 * but without any QuickJS runtime dependency.
 */
#ifndef JARONA_READER_H
#define JARONA_READER_H

#include "qjs_format.h"
#include "util.h"

/* =========================================================
 * Initialize a reader over a buffer
 * ========================================================= */
void qjs_reader_init(qjs_reader_t *r, const uint8_t *buf, size_t len);

/* =========================================================
 * Set/get error state
 * ========================================================= */
void qjs_reader_set_error(qjs_reader_t *r, const char *msg);
int  qjs_reader_has_error(const qjs_reader_t *r);

/* =========================================================
 * Bounds check
 * ========================================================= */
static inline int qjs_reader_has(const qjs_reader_t *r, size_t n) {
    return r->ptr + n <= r->end;
}

/* =========================================================
 * Primitive readers (return -1 on error, 0 on success)
 * ========================================================= */
int qjs_get_u8(qjs_reader_t *r, uint8_t *v);
int qjs_get_u16(qjs_reader_t *r, uint16_t *v);
int qjs_get_u32(qjs_reader_t *r, uint32_t *v);
int qjs_get_i8(qjs_reader_t *r, int8_t *v);
int qjs_get_i16(qjs_reader_t *r, int16_t *v);
int qjs_get_i32(qjs_reader_t *r, int32_t *v);
int qjs_get_u64(qjs_reader_t *r, uint64_t *v);
int qjs_get_leb128(qjs_reader_t *r, uint32_t *v);
int qjs_get_sleb128(qjs_reader_t *r, int32_t *v);
int qjs_get_leb128_int(qjs_reader_t *r, int *v);
int qjs_get_leb128_u16(qjs_reader_t *r, uint16_t *v);
int qjs_get_buf(qjs_reader_t *r, uint8_t *buf, uint32_t len);

/* =========================================================
 * Atom reader (handles tagged-int atoms vs atom-table indices)
 *
 * Returns the resolved atom INDEX in the atom table on success,
 * or -1 on error. Tagged-int atoms (e.g. integer atoms used as
 * property names) are encoded as (idx << 1) | 1.
 * ========================================================= */
int qjs_get_atom(qjs_reader_t *r, uint32_t *atom_idx);

/* =========================================================
 * Get current position (for error messages)
 * ========================================================= */
static inline size_t qjs_reader_pos(const qjs_reader_t *r) {
    return (size_t)(r->ptr - r->buf);
}

/* =========================================================
 * Peek next byte without consuming
 * ========================================================= */
static inline int qjs_reader_peek(const qjs_reader_t *r, uint8_t *v) {
    if (r->ptr >= r->end) return -1;
    *v = *r->ptr;
    return 0;
}

#endif /* JARONA_READER_H */
