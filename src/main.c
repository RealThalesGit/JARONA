/*
 * main.c - JARONA QuickJS bytecode decompiler (refactored)
 *
 * Standalone tool that parses QuickJS bytecode binary format directly
 * (no QuickJS runtime dependency) and produces:
 *   - assembly-style disassembly (default)
 *   - JSON-structured output (--json)
 *   - pseudo-JS decompilation (--decompile)
 *
 * Usage:
 *   jarona-decompile [options] <bytecode_file>
 *
 * Options:
 *   -c                Treat input as compiled binary (search for QBCF magic)
 *   --json            Output JSON instead of text
 *   --decompile       Output pseudo-JS decompilation
 *   --stats           Print statistics to stderr
 *   --atoms           Print atom table
 *   -o <file>         Write output to file
 *   -h, --help        Show help
 *
 * Build:
 *   make
 *   (or see Makefile)
 */
#include "qjs_format.h"
#include "qjs_opcodes.h"
#include "qjs_builtin_atoms.h"
#include "reader.h"
#include "value.h"
#include "disasm.h"
#include "decompile.h"
#include "util.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <getopt.h>

#define PROGRAM_NAME "jarona-decompile"
#define PROGRAM_VERSION "5.0"

/* =========================================================
 * Help text
 * ========================================================= */
static void print_help(void) {
    fprintf(stderr,
        "JARONA QuickJS Bytecode Decompiler v" PROGRAM_VERSION "\n"
        "Usage: " PROGRAM_NAME " [options] <bytecode_file>\n"
        "\n"
        "Options:\n"
        "  -c, --compiled        Treat input as compiled binary (search for QBCF magic)\n"
        "  -j, --json            Output JSON-structured data\n"
        "  -d, --decompile       Output pseudo-JS decompilation\n"
        "  -s, --stats           Print statistics to stderr\n"
        "  -a, --atoms           Print atom table to stderr\n"
        "  -o, --output <file>   Write output to file (default: stdout)\n"
        "  -h, --help            Show this help\n"
        "\n"
        "The tool automatically detects:\n"
        "  - Raw QuickJS bytecode (.bin)\n"
        "  - QBCF-embedded bytecode (compiled binaries)\n"
        "  - Big-endian vs little-endian\n"
        "  - Bytecode version (v1 or v2 / Bignum)\n"
        "\n"
        "Examples:\n"
        "  " PROGRAM_NAME " test.qjsc                 # disassemble raw bytecode\n"
        "  " PROGRAM_NAME " -c program                # extract QBCF from binary\n"
        "  " PROGRAM_NAME " -d test.qjsc > out.js     # pseudo-decompile to JS\n"
        "  " PROGRAM_NAME " -j test.qjsc > out.json   # structured JSON\n"
    );
}

/* =========================================================
 * Read entire file into a malloc'd buffer
 * ========================================================= */
static uint8_t *read_file(const char *path, size_t *out_len) {
    struct stat st;
    if (stat(path, &st) < 0) {
        perror("stat");
        return NULL;
    }
    if (st.st_size <= 0) {
        fprintf(stderr, "error: empty file\n");
        return NULL;
    }
    if ((size_t)st.st_size > QJS_MAX_BYTECODE_LEN * 4) {
        fprintf(stderr, "error: file too large\n");
        return NULL;
    }

    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        perror("open");
        return NULL;
    }

    uint8_t *buf = xmalloc(st.st_size);
    ssize_t total = 0;
    while (total < st.st_size) {
        ssize_t n = read(fd, buf + total, st.st_size - total);
        if (n < 0) {
            perror("read");
            free(buf);
            close(fd);
            return NULL;
        }
        if (n == 0) break;
        total += n;
    }
    close(fd);

    if (total != st.st_size) {
        fprintf(stderr, "error: short read\n");
        free(buf);
        return NULL;
    }

    *out_len = (size_t)total;
    return buf;
}

/* =========================================================
 * Search for QBCF magic and extract the embedded payload
 * Tries multiple header sizes for compatibility with different
 * QuickJS/Frida compiled binary formats.
 * ========================================================= */
static uint8_t *extract_qbcf(uint8_t *buf, size_t size, size_t *out_payload_size) {
    /* Try different header sizes: 4 (magic only), 8, 12, 16 */
    const size_t hdr_sizes[] = {4, 8, 12, 16, 20, 24};
    const int n_hdr_sizes = sizeof(hdr_sizes) / sizeof(hdr_sizes[0]);

    for (size_t i = 0; i + 4 <= size; i++) {
        if (memcmp(buf + i, QJS_QBCF_MAGIC, 4) == 0) {
            /* Try each header size */
            for (int h = 0; h < n_hdr_sizes; h++) {
                size_t hdr_size = hdr_sizes[h];
                if (i + hdr_size >= size) continue;
                size_t payload = size - i - hdr_size;
                if (payload == 0 || payload > QJS_MAX_BYTECODE_LEN) continue;

                /* Check if payload starts with a valid bytecode version byte.
                 * Valid versions: 1 (no bignum), 2 (bignum), possibly with 0x40 flag
                 * for big-endian. */
                uint8_t first_byte = buf[i + hdr_size];
                int ver = first_byte & 0x3f;
                if (ver == 1 || ver == 2) {
                    *out_payload_size = payload;
                    return buf + i + hdr_size;
                }
            }
        }
    }

    /* If QBCF not found, try searching for raw bytecode directly.
     * QuickJS bytecode starts with a version byte (1 or 2, possibly | 0x40),
     * followed by a LEB128 atom count. */
    for (size_t i = 0; i + 2 <= size; i++) {
        uint8_t first_byte = buf[i];
        int ver = first_byte & 0x3f;
        if (ver != 1 && ver != 2) continue;
        /* Check that the next byte could be a valid LEB128 atom count
         * (not 0xFF which would be invalid) */
        uint8_t next = buf[i + 1];
        if (next == 0xFF) continue;
        /* Check that we have enough data for a minimal bytecode */
        if (i + 10 > size) continue;
        /* Look ahead: after version + atom_count, there should be string data
         * (atoms). The first atom's length should be reasonable. */
        *out_payload_size = size - i;
        if (*out_payload_size > QJS_MAX_BYTECODE_LEN) continue;
        fprintf(stderr, "info: raw bytecode found at offset %zu (version %d)\n", i, ver);
        return buf + i;
    }

    return NULL;
}

/* =========================================================
 * Print atom table (to stderr for --atoms)
 * ========================================================= */
static void print_atoms(FILE *out, qjs_reader_t *r) {
    fprintf(out, "; ===== Atom Table (%u atoms) =====\n", r->atoms.count);
    for (uint32_t i = 0; i < r->atoms.count; i++) {
        fprintf(out, ";   [%u] ", r->atoms.first_atom + i);
        if (r->atoms.atom_wide[i]) fprintf(out, "(wide) ");
        const char *s = r->atoms.atoms[i];
        /* print with escapes */
        fputc('"', out);
        for (const char *p = s; *p; p++) {
            if (*p == '"' || *p == '\\') { fputc('\\', out); fputc(*p, out); }
            else if (*p == '\n') fputs("\\n", out);
            else if (*p == '\r') fputs("\\r", out);
            else if (*p == '\t') fputs("\\t", out);
            else if ((unsigned char)*p < 0x20) fprintf(out, "\\x%02x", (unsigned char)*p);
            else fputc(*p, out);
        }
        fputc('"', out);
        fputc('\n', out);
    }
    fprintf(out, "\n");
}

/* =========================================================
 * Print statistics
 * ========================================================= */
static void print_stats(FILE *out, qjs_reader_t *r, qjs_value_t *v) {
    fprintf(out, "; ===== Statistics =====\n");
    fprintf(out, ";   atoms:        %u\n", r->atoms.count);
    fprintf(out, ";   obj_refs:     %d\n", r->obj_refs_count);
    fprintf(out, ";   big_endian:   %s\n", r->big_endian ? "yes" : "no");
    fprintf(out, ";   functions:    %d\n", r->func_count);

    /* count total bytecode bytes and instructions */
    /* (would need a recursive walker; omitted for brevity) */
    (void)v;
}

/* =========================================================
 * Main
 * ========================================================= */
int main(int argc, char **argv) {
    int compiled_mode = 0;
    int want_json = 0;
    int want_decompile = 0;
    int want_stats = 0;
    int want_atoms = 0;
    const char *output_path = NULL;

    static struct option long_opts[] = {
        { "compiled",   no_argument,       0, 'c' },
        { "json",       no_argument,       0, 'j' },
        { "decompile",  no_argument,       0, 'd' },
        { "stats",      no_argument,       0, 's' },
        { "atoms",      no_argument,       0, 'a' },
        { "output",     required_argument, 0, 'o' },
        { "help",       no_argument,       0, 'h' },
        { 0, 0, 0, 0 }
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "cjdso:ah", long_opts, NULL)) != -1) {
        switch (opt) {
            case 'c': compiled_mode = 1; break;
            case 'j': want_json = 1; break;
            case 'd': want_decompile = 1; break;
            case 's': want_stats = 1; break;
            case 'a': want_atoms = 1; break;
            case 'o': output_path = optarg; break;
            case 'h': print_help(); return 0;
            default:  print_help(); return 1;
        }
    }

    if (optind >= argc) {
        print_help();
        return 1;
    }

    const char *path = argv[optind];

    /* Read input file */
    size_t file_len;
    uint8_t *file_buf = read_file(path, &file_len);
    if (!file_buf) return 1;

    /* Find actual bytecode (extract from QBCF if requested, or auto-detect) */
    uint8_t *bc = file_buf;
    size_t   bc_len = file_len;

    if (compiled_mode) {
        size_t payload_len;
        uint8_t *p = extract_qbcf(file_buf, file_len, &payload_len);
        if (p) {
            bc = p;
            bc_len = payload_len;
            fprintf(stderr, "info: QBCF payload extracted: %zu bytes\n", bc_len);
        } else {
            fprintf(stderr, "warning: no QBCF magic found, using raw file\n");
        }
    } else {
        /* Auto-detect: if file starts with QBCF, peel it off */
        if (file_len >= 12 && memcmp(file_buf, QJS_QBCF_MAGIC, 4) == 0) {
            bc = file_buf + 12;
            bc_len = file_len - 12;
            fprintf(stderr, "info: auto-detected QBCF wrapper, payload: %zu bytes\n", bc_len);
        }
    }

    /* Parse the bytecode */
    qjs_value_t *v = qjs_parse_bytecode(bc, bc_len, 1, 1);
    if (!v) {
        fprintf(stderr, "error: failed to parse bytecode\n");
        free(file_buf);
        return 1;
    }

    /* Set up output */
    FILE *out = stdout;
    if (output_path) {
        out = fopen(output_path, "w");
        if (!out) {
            perror("fopen");
            qjs_value_free(v);
            free(file_buf);
            return 1;
        }
    }

    /* Determine output mode */
    qjs_output_mode_t mode = QJS_OUT_TEXT;
    if (want_json) mode = QJS_OUT_JSON;

    /* Reset the global cpool counter */
    qjs_disasm_reset();

    /* Build a reader for atom resolution (re-init from the parsed state) */
    /* We need to reconstruct the reader with the atom table - parse_bytecode
     * created one internally. To keep things simple, we re-parse for the
     * atom table only: */
    qjs_reader_t rs;
    qjs_reader_init(&rs, bc, bc_len);
    /* Match parse_bytecode's first_atom setting (allow_bytecode=1) */
    rs.atoms.first_atom = QJS_BUILTIN_ATOM_COUNT;
    /* re-run the atom table parse to populate rs.atoms */
    {
        uint8_t version;
        if (qjs_get_u8(&rs, &version) == 0) {
            int ver = version & 0x3f;
            int be = (version & 0x40) ? 1 : 0;
            (void)ver;
            rs.big_endian = be;
            uint32_t atom_count;
            if (qjs_get_leb128(&rs, &atom_count) == 0) {
                rs.atoms.count = atom_count;
                if (atom_count > 0) {
                    rs.atoms.atoms = xcalloc(atom_count, sizeof(char *));
                    rs.atoms.atom_lens = xcalloc(atom_count, sizeof(uint32_t));
                    rs.atoms.atom_wide = xcalloc(atom_count, sizeof(uint8_t));
                    for (uint32_t i = 0; i < atom_count; i++) {
                        uint32_t len;
                        if (qjs_get_leb128(&rs, &len) < 0) break;
                        int is_wide = len & 1;
                        len >>= 1;
                        if (!is_wide) {
                            char *s = xmalloc(len + 1);
                            if (qjs_get_buf(&rs, (uint8_t *)s, len) < 0) { free(s); break; }
                            s[len] = '\0';
                            rs.atoms.atoms[i] = s;
                            rs.atoms.atom_lens[i] = len;
                        } else {
                            size_t bytes = (size_t)len * 2;
                            uint8_t *buf2 = xmalloc(bytes);
                            if (qjs_get_buf(&rs, buf2, bytes) < 0) { free(buf2); break; }
                            size_t out_cap = (size_t)len * 3 + 1;
                            char *out_s = xmalloc(out_cap);
                            size_t oi = 0;
                            for (uint32_t j = 0; j < len; j++) {
                                uint16_t cp = rd_u16(buf2 + j * 2, be);
                                if (cp < 0x80) out_s[oi++] = (char)cp;
                                else if (cp < 0x800) {
                                    out_s[oi++] = (char)(0xc0 | (cp >> 6));
                                    out_s[oi++] = (char)(0x80 | (cp & 0x3f));
                                } else {
                                    out_s[oi++] = (char)(0xe0 | (cp >> 12));
                                    out_s[oi++] = (char)(0x80 | ((cp >> 6) & 0x3f));
                                    out_s[oi++] = (char)(0x80 | (cp & 0x3f));
                                }
                            }
                            out_s[oi] = '\0';
                            free(buf2);
                            rs.atoms.atoms[i] = out_s;
                            rs.atoms.atom_lens[i] = (uint32_t)oi;
                            rs.atoms.atom_wide[i] = 1;
                        }
                    }
                }
            }
        }
    }

    /* Print header (only for disassembly mode, not decompile mode) */
    if (mode == QJS_OUT_TEXT && !want_decompile) {
        fprintf(out, "; ============================================\n");
        fprintf(out, "; JARONA QuickJS Bytecode Decompiler v" PROGRAM_VERSION "\n");
        fprintf(out, "; File: %s\n", path);
        fprintf(out, "; Size: %zu bytes (%zu bytes bytecode payload)\n", file_len, bc_len);
        fprintf(out, "; ============================================\n\n");
    } else if (mode == QJS_OUT_JSON) {
        fprintf(out, "{\n");
        fprintf(out, "  \"file\": \"%s\",\n", path);
        fprintf(out, "  \"size\": %zu,\n", file_len);
        fprintf(out, "  \"bytecode_size\": %zu,\n", bc_len);
        fprintf(out, "  \"big_endian\": %s,\n", rs.big_endian ? "true" : "false");
        fprintf(out, "  \"atom_count\": %u,\n", rs.atoms.count);
        fprintf(out, "  \"functions\": [\n");
    }

    /* Print atom table if requested */
    if (want_atoms && mode == QJS_OUT_TEXT) {
        print_atoms(stderr, &rs);
    }

    /* Main output */
    if (want_decompile) {
        qjs_decompile_value(out, &rs, v, 1);
    } else {
        qjs_disasm_value(out, &rs, v, mode, 1);
    }

    /* JSON closing */
    if (mode == QJS_OUT_JSON) {
        fprintf(out, "\n  ]\n}\n");
    }

    /* Stats */
    if (want_stats) {
        print_stats(stderr, &rs, v);
    }

    /* Cleanup */
    if (out != stdout) fclose(out);
    qjs_value_free(v);
    /* Free atom table in rs */
    if (rs.atoms.atoms) {
        for (uint32_t i = 0; i < rs.atoms.count; i++)
            free(rs.atoms.atoms[i]);
        free(rs.atoms.atoms);
        free(rs.atoms.atom_lens);
        free(rs.atoms.atom_wide);
    }
    free(rs.obj_refs);
    free(file_buf);

    return 0;
}
