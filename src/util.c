/*
 * util.c - Utility function implementations
 */
#include "util.h"
#include <ctype.h>

char *jarona_escape_str(const char *s, size_t len, int for_json) {
    /* worst case: each char becomes 6 chars (\u00XX) */
    char *out = xmalloc(len * 6 + 3);
    char *p = out;
    *p++ = '"';
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)s[i];
        switch (c) {
            case '"':  *p++ = '\\'; *p++ = '"'; break;
            case '\\': *p++ = '\\'; *p++ = '\\'; break;
            case '\n': *p++ = '\\'; *p++ = 'n'; break;
            case '\r': *p++ = '\\'; *p++ = 'r'; break;
            case '\t': *p++ = '\\'; *p++ = 't'; break;
            case '\b': *p++ = '\\'; *p++ = 'b'; break;
            case '\f': *p++ = '\\'; *p++ = 'f'; break;
            default:
                if (c < 0x20) {
                    if (for_json) {
                        p += sprintf(p, "\\u%04X", c);
                    } else {
                        p += sprintf(p, "\\x%02X", c);
                    }
                } else if (c < 0x7f) {
                    *p++ = c;
                } else {
                    /* pass through UTF-8 bytes as-is */
                    *p++ = c;
                }
                break;
        }
    }
    *p++ = '"';
    *p = '\0';
    return out;
}
