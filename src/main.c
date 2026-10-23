/*
 * main.c - JARONA QuickJS bytecode decompiler
 *
 * Standalone tool that parses QuickJS bytecode binary format directly
 * (no QuickJS runtime dependency) and produces:
 *   - assembly-style disassembly (default)
 *   - JSON-structured output (--json)
 *   - pseudo-JS decompilation (--decompile)
 *
 * Usage:
 *   jarona-decompile [options] <bytecode_file>
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
#define PROGRAM_VERSION "6.0"

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
        "  -x, --hex             Print a hex dump of the bytecode payload\n"
        "      --vanilla         Force the vanilla QuickJS built-in atom table\n"
        "      --frida           Force Frida's QuickJS built-in atom table\n"
        "  -o, --output <file>   Write output to file (default: stdout)\n"
        "  -h, --help            Show this help\n"
        "\n"
        "The tool automatically detects:\n"
        "  - Raw QuickJS bytecode (.bin)\n"
        "  - QBCF-embedded bytecode (compiled binaries)\n"
        "  - Big-endian vs little-endian\n"
        "  - Bytecode version (v1 or v2 / Bignum)\n"
        "  - Vanilla vs Frida built-in atom table\n"
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
 * Print a hex dump of the bytecode payload
 * ========================================================= */
static void print_hex_dump(FILE *out, const uint8_t *buf, size_t len) {
    fprintf(out, "; ===== Hex dump (%zu bytes) =====\n", len);
    for (size_t i = 0; i < len; i += 16) {
        fprintf(out, "%08zx  ", i);
        for (size_t j = 0; j < 16; j++) {
            if (i + j < len)
                fprintf(out, "%02x ", buf[i + j]);
            else
                fputs("   ", out);
            if (j == 7) fputc(' ', out);
        }
        fprintf(out, " |");
        for (size_t j = 0; j < 16 && i + j < len; j++) {
            uint8_t c = buf[i + j];
            fputc((c >= 0x20 && c < 0x7f) ? c : '.', out);
        }
        fprintf(out, "|\n");
    }
}

/* =========================================================
 * Print atom table (to stderr for --atoms)
 * ========================================================= */
static void print_atoms(FILE *out, qjs_reader_t *r) {
    fprintf(out, "; ===== Atom Table (%u atoms, first_atom=%u, flavour=%s) =====\n",
            r->atoms.count, r->atoms.first_atom,
            r->atoms.flavor == QJS_ATOM_FLAVOR_FRIDA ? "frida" : "vanilla");
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
 * Count functions / instructions recursively (for --stats)
 * ========================================================= */
typedef struct {
    int functions;
    int instructions;
    int total_bytes;
    int cpool_entries;
    int atoms_used;
} qjs_stats_t;

static void collect_stats(qjs_function_t *fn, qjs_stats_t *st) {
    if (!fn) return;
    st->functions++;
    st->total_bytes += fn->byte_code_len;
    st->cpool_entries += fn->cpool_count;
    for (int i = 0; i < fn->cpool_count; i++) {
        qjs_value_t *v = fn->cpool[i];
        if (!v) continue;
        if (v->kind == QJS_VAL_FUNCTION)
            collect_stats(v->u.func.fn, st);
    }
}

/* =========================================================
 * Print statistics
 * ========================================================= */
static void print_stats(FILE *out, qjs_reader_t *r, qjs_value_t **values, int count) {
    qjs_stats_t st = {0, 0, 0, 0, 0};

    for (int i = 0; i < count; i++) {
        qjs_value_t *v = values[i];
        if (!v) continue;
        if (v->kind == QJS_VAL_FUNCTION)
            collect_stats(v->u.func.fn, &st);
        else if (v->kind == QJS_VAL_MODULE && v->u.mod.mod->func)
            collect_stats(v->u.mod.mod->func, &st);
    }

    fprintf(out, "; ===== Statistics =====\n");
    fprintf(out, ";   atoms:        %u\n", r->atoms.count);
    fprintf(out, ";   first_atom:   %u\n", r->atoms.first_atom);
    fprintf(out, ";   atom flavour: %s\n",
            r->atoms.flavor == QJS_ATOM_FLAVOR_FRIDA ? "frida" : "vanilla");
    fprintf(out, ";   obj_refs:     %d\n", r->obj_refs_count);
    fprintf(out, ";   big_endian:   %s\n", r->big_endian ? "yes" : "no");
    fprintf(out, ";   modules:      %d\n", count);
    fprintf(out, ";   functions:    %d\n", st.functions);
    fprintf(out, ";   cpool:        %d\n", st.cpool_entries);
    fprintf(out, ";   bytecode:     %d bytes\n", st.total_bytes);
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
    int want_hex = 0;
    int force_flavor = -1;   /* -1 auto, 0 vanilla, 1 frida */
    const char *output_path = NULL;

    static struct option long_opts[] = {
        { "compiled",   no_argument,       0, 'c' },
        { "json",       no_argument,       0, 'j' },
        { "decompile",  no_argument,       0, 'd' },
        { "stats",      no_argument,       0, 's' },
        { "atoms",      no_argument,       0, 'a' },
        { "hex",        no_argument,       0, 'x' },
        { "vanilla",    no_argument,       0, 1000 },
        { "frida",      no_argument,       0, 1001 },
        { "output",     required_argument, 0, 'o' },
        { "help",       no_argument,       0, 'h' },
        { 0, 0, 0, 0 }
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "cjdso:axh", long_opts, NULL)) != -1) {
        switch (opt) {
            case 'c': compiled_mode = 1; break;
            case 'j': want_json = 1; break;
            case 'd': want_decompile = 1; break;
            case 's': want_stats = 1; break;
            case 'a': want_atoms = 1; break;
            case 'x': want_hex = 1; break;
            case 'o': output_path = optarg; break;
            case 'h': print_help(); return 0;
            case 1000: force_flavor = QJS_ATOM_FLAVOR_VANILLA; break;
            case 1001: force_flavor = QJS_ATOM_FLAVOR_FRIDA; break;
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

    /* Parse the bytecode.  The reader keeps the atom table around so atoms
     * can be resolved while printing.  A file may hold several modules
     * (one blob each); all of them are parsed. */
    qjs_reader_t rs;
    qjs_value_t **values = NULL;
    int value_count = 0;
    if (qjs_parse_bytecode_list(&rs, bc, bc_len, 1, 1, &values, &value_count) < 0) {
        fprintf(stderr, "error: failed to parse bytecode\n");
        qjs_reader_cleanup(&rs);
        free(file_buf);
        return 1;
    }

    /* An explicitly requested flavour overrides the auto-detection. */
    if (force_flavor >= 0 && force_flavor != rs.atoms.flavor) {
        int saved_flavor = rs.atoms.flavor;
        uint32_t saved_first = rs.atoms.first_atom;
        rs.atoms.flavor = force_flavor;
        rs.atoms.first_atom = (force_flavor == QJS_ATOM_FLAVOR_FRIDA)
                            ? QJS_FRIDA_ATOM_END : QJS_VANILLA_ATOM_END;
        (void)saved_flavor;
        (void)saved_first;
        fprintf(stderr, "info: forced %s atom table (first_atom=%u)\n",
                force_flavor == QJS_ATOM_FLAVOR_FRIDA ? "frida" : "vanilla",
                rs.atoms.first_atom);
    }

    /* Set up output */
    FILE *out = stdout;
    if (output_path) {
        out = fopen(output_path, "w");
        if (!out) {
            perror("fopen");
            for (int i = 0; i < value_count; i++) qjs_value_free(values[i]);
            free(values);
            qjs_reader_cleanup(&rs);
            free(file_buf);
            return 1;
        }
    }

    /* Determine output mode */
    qjs_output_mode_t mode = QJS_OUT_TEXT;
    if (want_json) mode = QJS_OUT_JSON;

    /* Reset the global cpool counter */
    qjs_disasm_reset();

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
        fprintf(out, "  \"first_atom\": %u,\n", rs.atoms.first_atom);
        fprintf(out, "  \"atom_flavour\": \"%s\",\n",
                rs.atoms.flavor == QJS_ATOM_FLAVOR_FRIDA ? "frida" : "vanilla");
        fprintf(out, "  \"functions\": [\n");
    }

    /* Print atom table if requested */
    if (want_atoms && mode == QJS_OUT_TEXT) {
        print_atoms(stderr, &rs);
    }

    /* Hex dump if requested */
    if (want_hex) {
        print_hex_dump(out, bc, bc_len);
    }

    /* Main output */
    if (want_decompile) {
        for (int i = 0; i < value_count; i++)
            qjs_decompile_value(out, &rs, values[i], 0);
    } else {
        for (int i = 0; i < value_count; i++)
            qjs_disasm_value(out, &rs, values[i], mode, 1);
    }

    /* JSON closing */
    if (mode == QJS_OUT_JSON) {
        fprintf(out, "\n  ]\n}\n");
    }

    /* Stats */
    if (want_stats) {
        print_stats(stderr, &rs, values, value_count);
    }

    /* Cleanup */
    if (out != stdout) fclose(out);
    for (int i = 0; i < value_count; i++) qjs_value_free(values[i]);
    free(values);
    qjs_reader_cleanup(&rs);
    free(file_buf);

    return 0;
}
