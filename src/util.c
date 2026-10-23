/*
 * util.c - Utility function implementations
 */
#include "util.h"
#include <ctype.h>
#include <math.h>

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

/* =========================================================
 * Double formatting
 *
 * Reproduces the output of ECMA-262 "Number::toString" (radix 10):
 * the shortest decimal digit string that converts back to the very same
 * double, laid out with the exponent rules of the specification.
 * ========================================================= */
void jarona_format_double(double d, char *out, size_t outlen) {
    if (outlen == 0) return;

    if (isnan(d)) { snprintf(out, outlen, "NaN"); return; }
    if (isinf(d)) { snprintf(out, outlen, d < 0 ? "-Infinity" : "Infinity"); return; }
    if (d == 0) { snprintf(out, outlen, "0"); return; }

    int neg = 0;
    if (d < 0) { neg = 1; d = -d; }

    /* Find the shortest precision that round-trips exactly. */
    char tmp[64];
    int prec = 17;
    for (int p = 1; p <= 17; p++) {
        snprintf(tmp, sizeof(tmp), "%.*e", p - 1, d);
        if (strtod(tmp, NULL) == d) { prec = p; break; }
    }
    snprintf(tmp, sizeof(tmp), "%.*e", prec - 1, d);

    /* Split the "%e" output into sign, digits and decimal exponent. */
    const char *p = tmp;
    char digits[32];
    int ndig = 0;
    for (; *p && *p != 'e' && *p != 'E'; p++) {
        if (*p == '.') continue;
        if (ndig < (int)sizeof(digits) - 1) digits[ndig++] = *p;
    }
    digits[ndig] = '\0';
    int exp10 = (*p == 'e' || *p == 'E') ? atoi(p + 1) : 0;

    /* Drop trailing zeros - they are not part of the shortest form. */
    while (ndig > 1 && digits[ndig - 1] == '0') digits[--ndig] = '\0';

    /* The value is 0.<digits> * 10^n. */
    int n = exp10 + 1;
    int k = ndig;

    char buf[64];
    int len = 0;
    buf[0] = '\0';

    if (k <= n && n <= 21) {
        /* Integer with trailing zeros: "12300" */
        memcpy(buf, digits, (size_t)k);
        len = k;
        for (int i = k; i < n; i++) buf[len++] = '0';
        buf[len] = '\0';
    } else if (0 < n && n <= 21) {
        /* "123.45" */
        memcpy(buf, digits, (size_t)n);
        len = n;
        buf[len++] = '.';
        memcpy(buf + len, digits + n, (size_t)(k - n));
        len += k - n;
        buf[len] = '\0';
    } else if (-6 < n && n <= 0) {
        /* "0.00123" */
        len = snprintf(buf, sizeof(buf), "0.");
        for (int i = 0; i < -n; i++) buf[len++] = '0';
        memcpy(buf + len, digits, (size_t)k);
        len += k;
        buf[len] = '\0';
    } else {
        /* Exponential notation: "1.2345e+30" */
        len = 0;
        buf[len++] = digits[0];
        if (k > 1) {
            buf[len++] = '.';
            memcpy(buf + len, digits + 1, (size_t)(k - 1));
            len += k - 1;
        }
        len += snprintf(buf + len, sizeof(buf) - (size_t)len, "e%c%d",
                       (n - 1) < 0 ? '-' : '+', abs(n - 1));
    }

    if (neg) {
        /* prepend the sign */
        char out2[80];
        snprintf(out2, sizeof(out2), "-%s", buf);
        snprintf(out, outlen, "%s", out2);
    } else {
        snprintf(out, outlen, "%s", buf);
    }
}
