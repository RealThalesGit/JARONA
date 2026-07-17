/*
 * util.h - Utility functions for the JARONA decompiler
 */
#ifndef JARONA_UTIL_H
#define JARONA_UTIL_H

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* =========================================================
 * Memory helpers
 * ========================================================= */
static inline void *xmalloc(size_t sz) {
    void *p = malloc(sz ? sz : 1);
    if (!p) { fprintf(stderr, "out of memory\n"); abort(); }
    return p;
}

static inline void *xcalloc(size_t n, size_t sz) {
    void *p = calloc(n ? n : 1, sz ? sz : 1);
    if (!p) { fprintf(stderr, "out of memory\n"); abort(); }
    return p;
}

static inline void *xrealloc(void *p, size_t sz) {
    void *q = realloc(p, sz ? sz : 1);
    if (!q) { fprintf(stderr, "out of memory\n"); abort(); }
    return q;
}

static inline char *xstrdup(const char *s) {
    size_t n = strlen(s);
    char *p = xmalloc(n + 1);
    memcpy(p, s, n + 1);
    return p;
}

/* =========================================================
 * Endian helpers
 * ========================================================= */
static inline uint16_t rd_u16(const uint8_t *p, int big_endian) {
    return big_endian ? ((uint16_t)p[0] << 8) | p[1]
                      : ((uint16_t)p[1] << 8) | p[0];
}
static inline int16_t rd_i16(const uint8_t *p, int big_endian) {
    return (int16_t)rd_u16(p, big_endian);
}
static inline uint32_t rd_u32(const uint8_t *p, int big_endian) {
    return big_endian ? ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
                        ((uint32_t)p[2] << 8) | p[3]
                      : ((uint32_t)p[3] << 24) | ((uint32_t)p[2] << 16) |
                        ((uint32_t)p[1] << 8) | p[0];
}
static inline int32_t rd_i32(const uint8_t *p, int big_endian) {
    return (int32_t)rd_u32(p, big_endian);
}
static inline uint64_t rd_u64(const uint8_t *p, int big_endian) {
    uint64_t v = 0;
    if (big_endian) {
        for (int i = 0; i < 8; i++) v = (v << 8) | p[i];
    } else {
        for (int i = 7; i >= 0; i--) v = (v << 8) | p[i];
    }
    return v;
}

/* =========================================================
 * LEB128 decoders (matches quickjs get_leb128 / get_sleb128)
 * ========================================================= */
/* Returns number of bytes consumed, or -1 on error. */
static inline int get_leb128_u32(uint32_t *pval, const uint8_t *p, const uint8_t *end) {
    uint32_t v = 0, shift = 0;
    int n = 0;
    while (p < end) {
        uint8_t b = *p++;
        n++;
        v |= (uint32_t)(b & 0x7f) << shift;
        if (!(b & 0x80)) {
            *pval = v;
            return n;
        }
        shift += 7;
        if (shift >= 32) return -1;
    }
    return -1;
}

static inline int get_sleb128_i32(int32_t *pval, const uint8_t *p, const uint8_t *end) {
    int32_t v = 0;
    int shift = 0, n = 0;
    uint8_t b = 0;
    while (p < end) {
        b = *p++;
        n++;
        v |= (int32_t)(b & 0x7f) << shift;
        shift += 7;
        if (!(b & 0x80)) {
            if (shift < 32 && (b & 0x40))
                v |= -((int32_t)1 << shift);
            *pval = v;
            return n;
        }
        if (shift >= 32) return -1;
    }
    return -1;
}

/* =========================================================
 * String escaping
 * ========================================================= */
/* Returns a malloc'd string with C-style escapes. */
char *jarona_escape_str(const char *s, size_t len, int for_json);

/* =========================================================
 * Indentation helper
 * ========================================================= */
static inline void put_indent(FILE *f, int n) {
    for (int i = 0; i < n; i++) fputs("  ", f);
}

/* =========================================================
 * Bit extraction helper (matches bc_get_flags)
 * ========================================================= */
static inline uint32_t get_bits(uint32_t flags, int *idx, int n) {
    uint32_t mask = (n >= 32) ? 0xFFFFFFFFu : ((1u << n) - 1u);
    uint32_t v = (flags >> *idx) & mask;
    *idx += n;
    return v;
}

#endif /* JARONA_UTIL_H */
