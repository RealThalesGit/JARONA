#ifndef CONFIG_VERSION
#define CONFIG_VERSION "Frida-QuickJS"
#endif
#define SHORT_OPCODES 1
#define CONFIG_BIGNUM 1
#define CONFIG_ATOMICS 1

#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <ctype.h>

/* ========================================================= */
/* QUICKJS INTERNALS + PATCH SETUP                          */
/* ========================================================= */
#define JS_INTERNALS 1

#define BC_add_object_ref1 BC_add_object_ref1_orig
#include "quickjs.c"
#undef BC_add_object_ref1

#include "list.h"

#undef malloc
#undef free
#undef realloc

/* ========================================================= */
/* MAGIC & LIMITS                                            */
/* ========================================================= */
#define QBC_MAGIC "QBCF"

#define MAX_CPOOL    65536
#define MAX_VISITED  65536
#define MAX_DEPTH    4096
#define MAX_BYTECODE (64 * 1024 * 1024)

/* ========================================================= */
/* QUICKJS PATCH - BC_add_object_ref1                        */
/* ========================================================= */
__attribute__((used))
static int BC_add_object_ref1(BCReaderState *s, JSObject *p)
{
    if (!s->allow_reference)
        return 0;

    if (s->objects_count >= s->objects_size) {
        size_t new_size = s->objects_size ? s->objects_size * 2 : 64;

        if (new_size > MAX_CPOOL)
            return -1;

        JSObject **new_tab = js_realloc2(
            s->ctx,
            s->objects,
            new_size * sizeof(JSObject *),
            &new_size
        );

        if (!new_tab)
            return -1;

        s->objects = new_tab;
        s->objects_size = new_size;
    }

    s->objects[s->objects_count++] = p;
    return 0;
}

/* ========================================================= */
/* QBC HEADER                                                */
/* ========================================================= */
typedef struct {
    char magic[4];
    uint32_t version;
    uint32_t flags;
} qbc_header_t;

/* ========================================================= */
/* OPCODES ENUM                                              */
/* ========================================================= */
enum ops {
#define def(...)
#define DEF(x, ...) op_##x,
#include "quickjs-opcode.h"
#undef DEF
    _op_pad
};

/* ========================================================= */
/* FORMAT ENUM                                               */
/* ========================================================= */
typedef enum {
    FMT_none,
    FMT_none_int,
    FMT_none_loc,
    FMT_none_arg,
    FMT_none_var_ref,
    FMT_u8,
    FMT_i8,
    FMT_loc8,
    FMT_const8,
    FMT_label8,
    FMT_u16,
    FMT_i16,
    FMT_label16,
    FMT_npop,
    FMT_npopx,
    FMT_npop_u16,
    FMT_loc,
    FMT_arg,
    FMT_var_ref,
    FMT_u32,
    FMT_u32x2,
    FMT_i32,
    FMT_const,
    FMT_label,
    FMT_atom,
    FMT_atom_u8,
    FMT_atom_u16,
    FMT_atom_label_u8,
    FMT_atom_label_u16,
    FMT_label_u16
} OpFmt;

/* ========================================================= */
/* OPCODE MAPPING FUNCTIONS                                  */
/* ========================================================= */
static const char *op2str(uint8_t op)
{
#define def(...)
#define DEF(x, ...) if (op == op_##x) return #x;
#include "quickjs-opcode.h"
#undef DEF
    return "<INVALID>";
}

static OpFmt op2fmt(uint8_t op)
{
#define def(...)
#define DEF(x, size, n_pop, n_push, f) if (op == op_##x) return FMT_##f;
#include "quickjs-opcode.h"
#undef DEF
    return FMT_none;
}

static int op_size(uint8_t op)
{
#define def(...)
#define DEF(x, size, ...) if (op == op_##x) return size;
#include "quickjs-opcode.h"
#undef DEF
    return -1;
}

static int op_pop(uint8_t op)
{
#define def(...)
#define DEF(x, size, n_pop, n_push, f) if (op == op_##x) return n_pop;
#include "quickjs-opcode.h"
#undef DEF
    return -1;
}

static int op_push(uint8_t op)
{
#define def(...)
#define DEF(x, size, n_pop, n_push, f) if (op == op_##x) return n_push;
#include "quickjs-opcode.h"
#undef DEF
    return -1;
}

/* ========================================================= */
/* SAFE READ HELPER                                          */
/* ========================================================= */
static int read_bytes(const uint8_t *buf, uint32_t len,
                      uint32_t off, void *out, size_t sz)
{
    if (!buf || !out || sz == 0)
        return 0;
    if (off + sz > len || off + sz < off) /* overflow check */
        return 0;
    memcpy(out, buf + off, sz);
    return 1;
}

/* ========================================================= */
/* HEX PRINTING HELPERS                                      */
/* ========================================================= */
static void print_hex_i32(int32_t v)
{
    if (v < 0)
        printf("-0x%X", (uint32_t)(-v));
    else
        printf("0x%X", (uint32_t)v);
}

static void print_hex_u32(uint32_t v)
{
    printf("0x%X", v);
}

/* ========================================================= */
/* IMPROVED ATOM TO STRING - MAIS ESTÁVEL                    */
/* ========================================================= */
static char *atom_to_cstr_safe(JSContext *ctx, JSAtom atom)
{
    if (!ctx || !ctx->rt) {
        char tmp[64];
        snprintf(tmp, sizeof(tmp), "<atom:%u:no-ctx>", (uint32_t)atom);
        return strdup(tmp);
    }

    uint32_t a = (uint32_t)atom;

    /* Verificação de limites mais robusta */
    if (a == 0) {
        return strdup("<atom:null>");
    }

    if (a >= ctx->rt->atom_count) {
        char tmp[64];
        snprintf(tmp, sizeof(tmp), "<atom:%u:out-of-range>", a);
        return strdup(tmp);
    }

    /* Tentar converter o atom para string */
    JSValue v = JS_AtomToString(ctx, atom);
    
    if (JS_IsException(v)) {
        JS_FreeValue(ctx, v);
        char tmp[64];
        snprintf(tmp, sizeof(tmp), "<atom:%u:exception>", a);
        return strdup(tmp);
    }

    if (JS_IsUndefined(v)) {
        JS_FreeValue(ctx, v);
        char tmp[64];
        snprintf(tmp, sizeof(tmp), "<atom:%u:undefined>", a);
        return strdup(tmp);
    }

    const char *s = JS_ToCString(ctx, v);
    JS_FreeValue(ctx, v);

    if (!s) {
        char tmp[64];
        snprintf(tmp, sizeof(tmp), "<atom:%u:null-str>", a);
        return strdup(tmp);
    }

    /* Sanitizar string para evitar caracteres problemáticos */
    size_t len = strlen(s);
    char *out = malloc(len * 4 + 1); /* Espaço extra para escape */
    if (!out) {
        JS_FreeCString(ctx, s);
        return strdup("<atom:alloc-fail>");
    }

    char *p = out;
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c >= 32 && c < 127 && c != '"' && c != '\\') {
            *p++ = c;
        } else {
            /* Escape caracteres especiais */
            switch (c) {
                case '\n': *p++ = '\\'; *p++ = 'n'; break;
                case '\r': *p++ = '\\'; *p++ = 'r'; break;
                case '\t': *p++ = '\\'; *p++ = 't'; break;
                case '"':  *p++ = '\\'; *p++ = '"'; break;
                case '\\': *p++ = '\\'; *p++ = '\\'; break;
                default:
                    p += sprintf(p, "\\x%02X", c);
                    break;
            }
        }
    }
    *p = '\0';

    JS_FreeCString(ctx, s);
    return out;
}

/* ========================================================= */
/* LABEL RESOLUTION - MELHORADO                              */
/* ========================================================= */
static int32_t resolve_label(uint32_t pc, uint32_t size,
                              const uint8_t *bc, uint32_t len,
                              OpFmt fmt, int *ok)
{
    int32_t rel = 0;
    *ok = 1;

    switch (fmt) {
    case FMT_label8: {
        /* Offset relativo de 8 bits com sinal */
        int8_t v;
        if (!read_bytes(bc, len, pc + 1, &v, 1)) goto bad;
        rel = v;
        break;
    }
    case FMT_label16: {
        /* Offset relativo de 16 bits com sinal */
        int16_t v;
        if (!read_bytes(bc, len, pc + 1, &v, 2)) goto bad;
        rel = v;
        break;
    }
    case FMT_label: {
        /* Offset relativo de 32 bits com sinal */
        int32_t v;
        if (!read_bytes(bc, len, pc + 1, &v, 4)) goto bad;
        rel = v;
        break;
    }
    case FMT_label_u16: {
        /* Offset relativo de 16 bits SEM sinal (usado em catch) */
        uint16_t v;
        if (!read_bytes(bc, len, pc + 1, &v, 2)) goto bad;
        rel = (int32_t)v;
        break;
    }
    case FMT_atom_label_u8: {
        /* Atom (4 bytes) + label u8 (1 byte) */
        int8_t v;
        if (!read_bytes(bc, len, pc + 5, &v, 1)) goto bad;
        rel = v;
        break;
    }
    case FMT_atom_label_u16: {
        /* Atom (4 bytes) + label u16 (2 bytes) */
        int16_t v;
        if (!read_bytes(bc, len, pc + 5, &v, 2)) goto bad;
        rel = v;
        break;
    }
    default:
        *ok = 0;
        return -1;
    }

    /* 
     * O target absoluto é calculado como: PC atual + tamanho da instrução + offset relativo
     * Isso porque o offset é relativo ao PRÓXIMO opcode, não ao atual
     */
    int32_t tgt = (int32_t)(pc + size + rel);
    
    /* Validação de limites */
    if (tgt < 0 || (uint32_t)tgt >= len)
        goto bad;

    return tgt;

bad:
    *ok = 0;
    return -1;
}

/* ========================================================= */
/* GLOBAL STATE                                              */
/* ========================================================= */
static JSFunctionBytecode *visited[MAX_VISITED];
static int depth;
static int gfi; /* global function index */

/* ========================================================= */
/* CONSTANT POOL DUMP - MELHORADO                            */
/* ========================================================= */
static void dump_cpool(JSContext *ctx, JSFunctionBytecode *fn, int base)
{
    if (!fn || !fn->cpool)
        return;
    
    if (fn->cpool_count <= 0 || fn->cpool_count > MAX_CPOOL)
        return;

    for (uint32_t i = 0; i < (uint32_t)fn->cpool_count; i++) {
        JSValue v = fn->cpool[i];
        int tag = JS_VALUE_GET_TAG(v);

        printf("; c[%d] ", base + i);

        switch (tag) {
        case JS_TAG_STRING: {
            const char *s = JS_ToCString(ctx, v);
            if (s) {
                printf("string \"");
                /* Print com escape de caracteres especiais */
                for (const char *p = s; *p; p++) {
                    if (*p >= 32 && *p < 127 && *p != '"' && *p != '\\')
                        putchar(*p);
                    else if (*p == '\n')
                        printf("\\n");
                    else if (*p == '\r')
                        printf("\\r");
                    else if (*p == '\t')
                        printf("\\t");
                    else if (*p == '"')
                        printf("\\\"");
                    else if (*p == '\\')
                        printf("\\\\");
                    else
                        printf("\\x%02X", (unsigned char)*p);
                }
                printf("\"");
                JS_FreeCString(ctx, s);
            } else {
                printf("string <error>");
            }
            break;
        }
        case JS_TAG_INT:
            printf("int %d", JS_VALUE_GET_INT(v));
            break;
        case JS_TAG_FLOAT64:
            printf("double %.17g", JS_VALUE_GET_FLOAT64(v));
            break;
        case JS_TAG_BOOL:
            printf("bool %s", JS_VALUE_GET_BOOL(v) ? "true" : "false");
            break;
        case JS_TAG_NULL:
            printf("null");
            break;
        case JS_TAG_UNDEFINED:
            printf("undefined");
            break;
        case JS_TAG_FUNCTION_BYTECODE:
            printf("function");
            break;
        case JS_TAG_OBJECT: {
            JSObject *obj = JS_VALUE_GET_OBJ(v);
            printf("object %p", (void *)obj);
            break;
        }
        case JS_TAG_BIG_INT:
            printf("bigint");
            break;
        case JS_TAG_BIG_FLOAT:
            printf("bigfloat");
            break;
        case JS_TAG_SYMBOL:
            printf("symbol");
            break;
        default:
            printf("<tag:%d>", tag);
            break;
        }
        printf("\n");
    }
}

/* ========================================================= */
/* BYTECODE DUMP - MELHORADO COM MAIS FORMATOS               */
/* ========================================================= */
static void dump_bytecode(JSContext *ctx, JSFunctionBytecode *fn, int cgb)
{
    if (!fn || !fn->byte_code_buf || fn->byte_code_len == 0)
        return;
    
    if (fn->byte_code_len > MAX_BYTECODE)
        return;

    const uint8_t *bc = fn->byte_code_buf;
    uint32_t len = fn->byte_code_len;

    for (uint32_t pc = 0; pc < len;) {
        uint8_t op = bc[pc];
        int size = op_size(op);

        if (op >= _op_pad || size <= 0 || pc + size > len) {
            printf("[0x%04X] INVALID_OP 0x%02X\n", pc, op);
            pc++;
            continue;
        }

        OpFmt fmt = op2fmt(op);

        printf("[0x%04X] %-28s ; stack -%d +%d",
               pc, op2str(op), op_pop(op), op_push(op));

        switch (fmt) {
        case FMT_i8: {
            int8_t v;
            if (read_bytes(bc, len, pc + 1, &v, 1))
                printf(" %d", v);
            break;
        }
        case FMT_u8:
        case FMT_loc8: {
            uint8_t v;
            if (read_bytes(bc, len, pc + 1, &v, 1))
                printf(" %u", v);
            break;
        }
        case FMT_i16: {
            int16_t v;
            if (read_bytes(bc, len, pc + 1, &v, 2))
                printf(" %d", v);
            break;
        }
        case FMT_u16:
        case FMT_npop_u16: {
            uint16_t v;
            if (read_bytes(bc, len, pc + 1, &v, 2))
                printf(" %u", v);
            break;
        }
        case FMT_i32: {
            int32_t v;
            if (read_bytes(bc, len, pc + 1, &v, 4)) {
                printf(" ");
                print_hex_i32(v);
            }
            break;
        }
        case FMT_u32:
        case FMT_loc:
        case FMT_arg:
        case FMT_var_ref: {
            uint32_t v;
            if (read_bytes(bc, len, pc + 1, &v, 4)) {
                printf(" ");
                print_hex_u32(v);
            }
            break;
        }
        case FMT_u32x2: {
            uint32_t a, b;
            if (read_bytes(bc, len, pc + 1, &a, 4) &&
                read_bytes(bc, len, pc + 5, &b, 4))
                printf(" %u %u", a, b);
            break;
        }
        case FMT_atom: {
            JSAtom a;
            if (read_bytes(bc, len, pc + 1, &a, 4)) {
                char *s = atom_to_cstr_safe(ctx, a);
                printf(" %s", s);
                free(s);
            }
            break;
        }
        case FMT_atom_u8: {
            JSAtom a;
            uint8_t v;
            if (read_bytes(bc, len, pc + 1, &a, 4) &&
                read_bytes(bc, len, pc + 5, &v, 1)) {
                char *s = atom_to_cstr_safe(ctx, a);
                printf(" %s %u", s, v);
                free(s);
            }
            break;
        }
        case FMT_atom_u16: {
            JSAtom a;
            uint16_t v;
            if (read_bytes(bc, len, pc + 1, &a, 4) &&
                read_bytes(bc, len, pc + 5, &v, 2)) {
                char *s = atom_to_cstr_safe(ctx, a);
                printf(" %s %u", s, v);
                free(s);
            }
            break;
        }
        case FMT_const:
        case FMT_npop:
        case FMT_npopx: {
            uint32_t v;
            if (read_bytes(bc, len, pc + 1, &v, 4))
                printf(" c[%d]", cgb + v);
            break;
        }
        case FMT_const8: {
            uint8_t v;
            if (read_bytes(bc, len, pc + 1, &v, 1))
                printf(" c[%d]", cgb + v);
            break;
        }
        case FMT_label:
        case FMT_label8:
        case FMT_label16:
        case FMT_label_u16: {
            int ok;
            int32_t tgt = resolve_label(pc, size, bc, len, fmt, &ok);
            if (ok)
                printf(" -> 0x%04X", (uint32_t)tgt);
            else {
                /* Tentar calcular de qualquer forma para debug */
                int32_t raw_offset = 0;
                if (fmt == FMT_label8) {
                    int8_t v;
                    if (read_bytes(bc, len, pc + 1, &v, 1))
                        raw_offset = v;
                } else if (fmt == FMT_label16) {
                    int16_t v;
                    if (read_bytes(bc, len, pc + 1, &v, 2))
                        raw_offset = v;
                } else if (fmt == FMT_label) {
                    int32_t v;
                    if (read_bytes(bc, len, pc + 1, &v, 4))
                        raw_offset = v;
                } else if (fmt == FMT_label_u16) {
                    uint16_t v;
                    if (read_bytes(bc, len, pc + 1, &v, 2))
                        raw_offset = v;
                }
                int32_t calc_tgt = (int32_t)(pc + size + raw_offset);
                printf(" -> 0x%04X (invalid, offset=%d)", 
                       calc_tgt >= 0 ? (uint32_t)calc_tgt : 0, raw_offset);
            }
            break;
        }
        case FMT_atom_label_u8: {
            JSAtom a;
            if (read_bytes(bc, len, pc + 1, &a, 4)) {
                char *s = atom_to_cstr_safe(ctx, a);
                printf(" %s", s);
                free(s);
                
                int ok;
                int32_t tgt = resolve_label(pc, size, bc, len, fmt, &ok);
                if (ok)
                    printf(" -> 0x%04X", (uint32_t)tgt);
                else {
                    int8_t v;
                    if (read_bytes(bc, len, pc + 5, &v, 1)) {
                        int32_t calc_tgt = (int32_t)(pc + size + v);
                        printf(" -> 0x%04X (invalid, offset=%d)", 
                               calc_tgt >= 0 ? (uint32_t)calc_tgt : 0, (int)v);
                    } else {
                        printf(" -> <read error>");
                    }
                }
            }
            break;
        }
        case FMT_atom_label_u16: {
            JSAtom a;
            if (read_bytes(bc, len, pc + 1, &a, 4)) {
                char *s = atom_to_cstr_safe(ctx, a);
                printf(" %s", s);
                free(s);
                
                int ok;
                int32_t tgt = resolve_label(pc, size, bc, len, fmt, &ok);
                if (ok)
                    printf(" -> 0x%04X", (uint32_t)tgt);
                else {
                    int16_t v;
                    if (read_bytes(bc, len, pc + 5, &v, 2)) {
                        int32_t calc_tgt = (int32_t)(pc + size + v);
                        printf(" -> 0x%04X (invalid, offset=%d)", 
                               calc_tgt >= 0 ? (uint32_t)calc_tgt : 0, (int)v);
                    } else {
                        printf(" -> <read error>");
                    }
                }
            }
            break;
        }
        default:
            break;
        }

        printf("\n");
        pc += size;
    }
}

/* ========================================================= */
/* DECOMPILER RECURSIVO                                      */
/* ========================================================= */
static void decompile(JSContext *ctx, JSValue obj)
{
    if (JS_VALUE_GET_TAG(obj) != JS_TAG_FUNCTION_BYTECODE)
        return;

    if (++depth > MAX_DEPTH) {
        fprintf(stderr, "Warning: MAX_DEPTH exceeded\n");
        depth--;
        return;
    }

    JSFunctionBytecode *fn = JS_VALUE_GET_PTR(obj);
    if (!fn) {
        depth--;
        return;
    }

    /* Hash simples para detecção de ciclos */
    uintptr_t h = ((uintptr_t)fn >> 4) & (MAX_VISITED - 1);
    if (visited[h] == fn) {
        depth--;
        return;
    }
    visited[h] = fn;

    int cgb = gfi;
    gfi += fn->cpool_count;

    /* Recursão nas funções aninhadas primeiro */
    if (fn->cpool && fn->cpool_count > 0 && fn->cpool_count <= MAX_CPOOL) {
        for (int i = 0; i < fn->cpool_count; i++) {
            if (JS_VALUE_GET_TAG(fn->cpool[i]) == JS_TAG_FUNCTION_BYTECODE)
                decompile(ctx, fn->cpool[i]);
        }
    }

    /* Dump do constant pool e bytecode */
    printf("\n; ===== Function at %p =====\n", (void *)fn);
    dump_cpool(ctx, fn, cgb);
    printf("; ----- Bytecode -----\n");
    dump_bytecode(ctx, fn, cgb);

    depth--;
}

/* ========================================================= */
/* QBC EXTRACTION                                            */
/* ========================================================= */
static uint8_t *extract_qbc(uint8_t *buf, size_t size, size_t *out)
{
    if (!buf || size < sizeof(qbc_header_t))
        return NULL;

    for (size_t i = 0; i + sizeof(qbc_header_t) <= size; i++) {
        if (!memcmp(buf + i, QBC_MAGIC, 4)) {
            qbc_header_t *h = (qbc_header_t *)(buf + i);
            
            if (h->version == 0 || h->version > 0x1000)
                continue;
            
            size_t payload = size - (i + sizeof(*h));
            if (payload == 0 || payload > MAX_BYTECODE)
                continue;
            
            *out = payload;
            return buf + i + sizeof(*h);
        }
    }
    
    return NULL;
}

/* ========================================================= */
/* MAIN                                                      */
/* ========================================================= */
int main(int argc, char **argv)
{
    const char *path = NULL;
    int compile_mode = 0;

    if (argc == 3 && !strcmp(argv[1], "-c")) {
        compile_mode = 1;
        path = argv[2];
    } else if (argc == 2) {
        path = argv[1];
    } else {
        fprintf(stderr, "Usage: %s [-c] <bytecode_file>\n", argv[0]);
        fprintf(stderr, "  -c : Extract from compiled binary (QBCF format)\n");
        return 1;
    }

    struct stat st;
    if (stat(path, &st) < 0) {
        perror("stat");
        return 1;
    }
    
    if (st.st_size <= 0 || st.st_size > MAX_BYTECODE * 2) {
        fprintf(stderr, "Invalid file size\n");
        return 1;
    }

    uint8_t *buf = malloc(st.st_size);
    if (!buf) {
        perror("malloc");
        return 1;
    }

    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        perror("open");
        free(buf);
        return 1;
    }

    ssize_t bytes_read = read(fd, buf, st.st_size);
    close(fd);

    if (bytes_read != st.st_size) {
        fprintf(stderr, "Read error\n");
        free(buf);
        return 1;
    }

    uint8_t *real = buf;
    size_t real_size = st.st_size;

    /* Extração de QBC se em modo compilado */
    if (compile_mode) {
        uint8_t *p = extract_qbc(buf, st.st_size, &real_size);
        if (p) {
            real = p;
            fprintf(stderr, "QBC payload found: %zu bytes\n", real_size);
        } else {
            fprintf(stderr, "Warning: No QBC magic found, using raw file\n");
        }
    }

    /* Inicializar runtime */
    JSRuntime *rt = JS_NewRuntime();
    if (!rt) {
        fprintf(stderr, "Failed to create runtime\n");
        free(buf);
        return 1;
    }

    JS_SetMemoryLimit(rt, 64 * 1024 * 1024);
    JS_SetMaxStackSize(rt, 1 << 20);

    JSContext *ctx = JS_NewContext(rt);
    if (!ctx) {
        fprintf(stderr, "Failed to create context\n");
        JS_FreeRuntime(rt);
        free(buf);
        return 1;
    }

    /* Ler objeto bytecode */
    JSValue obj = JS_ReadObject(
        ctx,
        real,
        real_size,
        JS_READ_OBJ_BYTECODE | JS_READ_OBJ_REFERENCE
    );

    if (JS_IsException(obj)) {
        fprintf(stderr, "Failed to read bytecode object\n");
        JSValue exc = JS_GetException(ctx);
        const char *err = JS_ToCString(ctx, exc);
        if (err) {
            fprintf(stderr, "Error: %s\n", err);
            JS_FreeCString(ctx, err);
        }
        JS_FreeValue(ctx, exc);
    } else {
        /* Resetar estado global */
        memset(visited, 0, sizeof(visited));
        depth = 0;
        gfi = 0;

        /* Decompilação */
        printf("; QuickJS Bytecode Decompiler\n");
        printf("; File: %s\n", path);
        printf("; Size: %zu bytes\n\n", real_size);
        
        decompile(ctx, obj);
        
        printf("\n; ===== End of decompilation =====\n");
    }

    JS_FreeValue(ctx, obj);
    JS_FreeContext(ctx);
    JS_FreeRuntime(rt);
    free(buf);

    return 0;
}
