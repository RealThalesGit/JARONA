/*
 * qjs_opcodes.c - Opcode tables and mode detection (universal)
 *
 * Single source of truth for QuickJS opcode information across
 * vanilla QuickJS and Frida-QuickJS bytecode variants.
 *
 * Part of the JARONA decompiler.
 */
#include "qjs_opcodes.h"
#define JARONA_DEFINE_ATOM_TABLE
#include "qjs_builtin_atoms.h"
#include <string.h>

/* =========================================================
 * Vanilla QuickJS opcode table (256 entries)
 *
 * Matches quickjs-opcode.h exactly:
 *   0x00 .. 0xB5 : 182 base opcodes (invalid .. nop)
 *   0xB6 .. 0xF7 : 66 short opcodes (push_minus1 .. typeof_is_function)
 *   0xF8 .. 0xFF : invalid (unused)
 * ========================================================= */
const qjs_op_info_t qjs_op_info_vanilla[QJS_OP_TABLE_SIZE] = {
    /* 0x00 */ [0x00] = { "invalid",          1,  0,  0, QJS_FMT_none },
    /* 0x01 */ [0x01] = { "push_i32",         5,  0,  1, QJS_FMT_i32 },
    /* 0x02 */ [0x02] = { "push_const",       5,  0,  1, QJS_FMT_const },
    /* 0x03 */ [0x03] = { "fclosure",         5,  0,  1, QJS_FMT_const },
    /* 0x04 */ [0x04] = { "push_atom_value",  5,  0,  1, QJS_FMT_atom },
    /* 0x05 */ [0x05] = { "private_symbol",   5,  0,  1, QJS_FMT_atom },
    /* 0x06 */ [0x06] = { "undefined",        1,  0,  1, QJS_FMT_none },
    /* 0x07 */ [0x07] = { "null",             1,  0,  1, QJS_FMT_none },
    /* 0x08 */ [0x08] = { "push_this",        1,  0,  1, QJS_FMT_none },
    /* 0x09 */ [0x09] = { "push_false",       1,  0,  1, QJS_FMT_none },
    /* 0x0A */ [0x0A] = { "push_true",        1,  0,  1, QJS_FMT_none },
    /* 0x0B */ [0x0B] = { "object",           1,  0,  1, QJS_FMT_none },
    /* 0x0C */ [0x0C] = { "special_object",   2,  0,  1, QJS_FMT_u8 },
    /* 0x0D */ [0x0D] = { "rest",             3,  0,  1, QJS_FMT_u16 },
    /* 0x0E */ [0x0E] = { "drop",             1,  1,  0, QJS_FMT_none },
    /* 0x0F */ [0x0F] = { "nip",              1,  2,  1, QJS_FMT_none },
    /* 0x10 */ [0x10] = { "nip1",             1,  3,  2, QJS_FMT_none },
    /* 0x11 */ [0x11] = { "dup",              1,  1,  2, QJS_FMT_none },
    /* 0x12 */ [0x12] = { "dup1",             1,  2,  3, QJS_FMT_none },
    /* 0x13 */ [0x13] = { "dup2",             1,  2,  4, QJS_FMT_none },
    /* 0x14 */ [0x14] = { "dup3",             1,  3,  6, QJS_FMT_none },
    /* 0x15 */ [0x15] = { "insert2",          1,  2,  3, QJS_FMT_none },
    /* 0x16 */ [0x16] = { "insert3",          1,  3,  4, QJS_FMT_none },
    /* 0x17 */ [0x17] = { "insert4",          1,  4,  5, QJS_FMT_none },
    /* 0x18 */ [0x18] = { "perm3",            1,  3,  3, QJS_FMT_none },
    /* 0x19 */ [0x19] = { "perm4",            1,  4,  4, QJS_FMT_none },
    /* 0x1A */ [0x1A] = { "perm5",            1,  5,  5, QJS_FMT_none },
    /* 0x1B */ [0x1B] = { "swap",             1,  2,  2, QJS_FMT_none },
    /* 0x1C */ [0x1C] = { "swap2",            1,  4,  4, QJS_FMT_none },
    /* 0x1D */ [0x1D] = { "rot3l",            1,  3,  3, QJS_FMT_none },
    /* 0x1E */ [0x1E] = { "rot3r",            1,  3,  3, QJS_FMT_none },
    /* 0x1F */ [0x1F] = { "rot4l",            1,  4,  4, QJS_FMT_none },
    /* 0x20 */ [0x20] = { "rot5l",            1,  5,  5, QJS_FMT_none },
    /* 0x21 */ [0x21] = { "call_constructor", 3,  2,  1, QJS_FMT_npop },
    /* 0x22 */ [0x22] = { "call",             3,  1,  1, QJS_FMT_npop },
    /* 0x23 */ [0x23] = { "tail_call",        3,  1,  0, QJS_FMT_npop },
    /* 0x24 */ [0x24] = { "call_method",      3,  2,  1, QJS_FMT_npop },
    /* 0x25 */ [0x25] = { "tail_call_method", 3,  2,  0, QJS_FMT_npop },
    /* 0x26 */ [0x26] = { "array_from",       3,  0,  1, QJS_FMT_npop },
    /* 0x27 */ [0x27] = { "apply",            3,  3,  1, QJS_FMT_u16 },
    /* 0x28 */ [0x28] = { "return",           1,  1,  0, QJS_FMT_none },
    /* 0x29 */ [0x29] = { "return_undef",     1,  0,  0, QJS_FMT_none },
    /* 0x2A */ [0x2A] = { "check_ctor_return",1,  1,  2, QJS_FMT_none },
    /* 0x2B */ [0x2B] = { "check_ctor",       1,  0,  0, QJS_FMT_none },
    /* 0x2C */ [0x2C] = { "check_brand",      1,  2,  2, QJS_FMT_none },
    /* 0x2D */ [0x2D] = { "add_brand",        1,  2,  0, QJS_FMT_none },
    /* 0x2E */ [0x2E] = { "return_async",     1,  1,  0, QJS_FMT_none },
    /* 0x2F */ [0x2F] = { "throw",            1,  1,  0, QJS_FMT_none },
    /* 0x30 */ [0x30] = { "throw_error",      6,  0,  0, QJS_FMT_atom_u8 },
    /* 0x31 */ [0x31] = { "eval",             5,  1,  1, QJS_FMT_npop_u16 },
    /* 0x32 */ [0x32] = { "apply_eval",       3,  2,  1, QJS_FMT_u16 },
    /* 0x33 */ [0x33] = { "regexp",           1,  2,  1, QJS_FMT_none },
    /* 0x34 */ [0x34] = { "get_super",        1,  1,  1, QJS_FMT_none },
    /* 0x35 */ [0x35] = { "import",           1,  1,  1, QJS_FMT_none },
    /* 0x36 */ [0x36] = { "check_var",        5,  0,  1, QJS_FMT_atom },
    /* 0x37 */ [0x37] = { "get_var_undef",    5,  0,  1, QJS_FMT_atom },
    /* 0x38 */ [0x38] = { "get_var",          5,  0,  1, QJS_FMT_atom },
    /* 0x39 */ [0x39] = { "put_var",          5,  1,  0, QJS_FMT_atom },
    /* 0x3A */ [0x3A] = { "put_var_init",     5,  1,  0, QJS_FMT_atom },
    /* 0x3B */ [0x3B] = { "put_var_strict",   5,  2,  0, QJS_FMT_atom },
    /* 0x3C */ [0x3C] = { "get_ref_value",    1,  2,  3, QJS_FMT_none },
    /* 0x3D */ [0x3D] = { "put_ref_value",    1,  3,  0, QJS_FMT_none },
    /* 0x3E */ [0x3E] = { "define_var",       6,  0,  0, QJS_FMT_atom_u8 },
    /* 0x3F */ [0x3F] = { "check_define_var", 6,  0,  0, QJS_FMT_atom_u8 },
    /* 0x40 */ [0x40] = { "define_func",      6,  1,  0, QJS_FMT_atom_u8 },
    /* 0x41 */ [0x41] = { "get_field",        5,  1,  1, QJS_FMT_atom },
    /* 0x42 */ [0x42] = { "get_field2",       5,  1,  2, QJS_FMT_atom },
    /* 0x43 */ [0x43] = { "put_field",        5,  2,  0, QJS_FMT_atom },
    /* 0x44 */ [0x44] = { "get_private_field",1,  2,  1, QJS_FMT_none },
    /* 0x45 */ [0x45] = { "put_private_field",1,  3,  0, QJS_FMT_none },
    /* 0x46 */ [0x46] = { "define_private_field",1, 3, 1, QJS_FMT_none },
    /* 0x47 */ [0x47] = { "get_array_el",     1,  2,  1, QJS_FMT_none },
    /* 0x48 */ [0x48] = { "get_array_el2",    1,  2,  2, QJS_FMT_none },
    /* 0x49 */ [0x49] = { "put_array_el",     1,  3,  0, QJS_FMT_none },
    /* 0x4A */ [0x4A] = { "get_super_value",  1,  3,  1, QJS_FMT_none },
    /* 0x4B */ [0x4B] = { "put_super_value",  1,  4,  0, QJS_FMT_none },
    /* 0x4C */ [0x4C] = { "define_field",     5,  2,  1, QJS_FMT_atom },
    /* 0x4D */ [0x4D] = { "set_name",         5,  1,  1, QJS_FMT_atom },
    /* 0x4E */ [0x4E] = { "set_name_computed",1,  2,  2, QJS_FMT_none },
    /* 0x4F */ [0x4F] = { "set_proto",        1,  2,  1, QJS_FMT_none },
    /* 0x50 */ [0x50] = { "set_home_object",  1,  2,  2, QJS_FMT_none },
    /* 0x51 */ [0x51] = { "define_array_el",  1,  3,  2, QJS_FMT_none },
    /* 0x52 */ [0x52] = { "append",           1,  3,  2, QJS_FMT_none },
    /* 0x53 */ [0x53] = { "copy_data_properties", 2, 3, 3, QJS_FMT_u8 },
    /* 0x54 */ [0x54] = { "define_method",    6,  2,  1, QJS_FMT_atom_u8 },
    /* 0x55 */ [0x55] = { "define_method_computed", 2, 3, 1, QJS_FMT_u8 },
    /* 0x56 */ [0x56] = { "define_class",     6,  2,  2, QJS_FMT_atom_u8 },
    /* 0x57 */ [0x57] = { "define_class_computed", 6, 3, 3, QJS_FMT_atom_u8 },
    /* 0x58 */ [0x58] = { "get_loc",          3,  0,  1, QJS_FMT_loc },
    /* 0x59 */ [0x59] = { "put_loc",          3,  1,  0, QJS_FMT_loc },
    /* 0x5A */ [0x5A] = { "set_loc",          3,  1,  1, QJS_FMT_loc },
    /* 0x5B */ [0x5B] = { "get_arg",          3,  0,  1, QJS_FMT_arg },
    /* 0x5C */ [0x5C] = { "put_arg",          3,  1,  0, QJS_FMT_arg },
    /* 0x5D */ [0x5D] = { "set_arg",          3,  1,  1, QJS_FMT_arg },
    /* 0x5E */ [0x5E] = { "get_var_ref",      3,  0,  1, QJS_FMT_var_ref },
    /* 0x5F */ [0x5F] = { "put_var_ref",      3,  1,  0, QJS_FMT_var_ref },
    /* 0x60 */ [0x60] = { "set_var_ref",      3,  1,  1, QJS_FMT_var_ref },
    /* 0x61 */ [0x61] = { "set_loc_uninitialized", 3, 0, 0, QJS_FMT_loc },
    /* 0x62 */ [0x62] = { "get_loc_check",    3,  0,  1, QJS_FMT_loc },
    /* 0x63 */ [0x63] = { "put_loc_check",    3,  1,  0, QJS_FMT_loc },
    /* 0x64 */ [0x64] = { "put_loc_check_init", 3, 1, 0, QJS_FMT_loc },
    /* 0x65 */ [0x65] = { "get_loc_checkthis", 3, 0, 1, QJS_FMT_loc },
    /* 0x66 */ [0x66] = { "get_var_ref_check", 3, 0, 1, QJS_FMT_var_ref },
    /* 0x67 */ [0x67] = { "put_var_ref_check", 3, 1, 0, QJS_FMT_var_ref },
    /* 0x68 */ [0x68] = { "put_var_ref_check_init", 3, 1, 0, QJS_FMT_var_ref },
    /* 0x69 */ [0x69] = { "close_loc",        3,  0,  0, QJS_FMT_loc },
    /* 0x6A */ [0x6A] = { "if_false",         5,  1,  0, QJS_FMT_label },
    /* 0x6B */ [0x6B] = { "if_true",          5,  1,  0, QJS_FMT_label },
    /* 0x6C */ [0x6C] = { "goto",             5,  0,  0, QJS_FMT_label },
    /* 0x6D */ [0x6D] = { "catch",            5,  0,  1, QJS_FMT_label },
    /* 0x6E */ [0x6E] = { "gosub",            5,  0,  0, QJS_FMT_label },
    /* 0x6F */ [0x6F] = { "ret",              1,  1,  0, QJS_FMT_none },
    /* 0x70 */ [0x70] = { "nip_catch",        1,  2,  1, QJS_FMT_none },
    /* 0x71 */ [0x71] = { "to_object",        1,  1,  1, QJS_FMT_none },
    /* 0x72 */ [0x72] = { "to_propkey",       1,  1,  1, QJS_FMT_none },
    /* 0x73 */ [0x73] = { "to_propkey2",      1,  2,  2, QJS_FMT_none },
    /* 0x74 */ [0x74] = { "with_get_var",     10, 1,  0, QJS_FMT_atom_label_u8 },
    /* 0x75 */ [0x75] = { "with_put_var",     10, 2,  1, QJS_FMT_atom_label_u8 },
    /* 0x76 */ [0x76] = { "with_delete_var",  10, 1,  0, QJS_FMT_atom_label_u8 },
    /* 0x77 */ [0x77] = { "with_make_ref",    10, 1,  0, QJS_FMT_atom_label_u8 },
    /* 0x78 */ [0x78] = { "with_get_ref",     10, 1,  0, QJS_FMT_atom_label_u8 },
    /* 0x79 */ [0x79] = { "with_get_ref_undef", 10, 1, 0, QJS_FMT_atom_label_u8 },
    /* 0x7A */ [0x7A] = { "make_loc_ref",     7,  0,  2, QJS_FMT_atom_u16 },
    /* 0x7B */ [0x7B] = { "make_arg_ref",     7,  0,  2, QJS_FMT_atom_u16 },
    /* 0x7C */ [0x7C] = { "make_var_ref_ref", 7,  0,  2, QJS_FMT_atom_u16 },
    /* 0x7D */ [0x7D] = { "make_var_ref",     5,  0,  2, QJS_FMT_atom },
    /* 0x7E */ [0x7E] = { "for_in_start",     1,  1,  1, QJS_FMT_none },
    /* 0x7F */ [0x7F] = { "for_of_start",     1,  1,  3, QJS_FMT_none },
    /* 0x80 */ [0x80] = { "for_await_of_start", 1, 1, 3, QJS_FMT_none },
    /* 0x81 */ [0x81] = { "for_in_next",      1,  1,  3, QJS_FMT_none },
    /* 0x82 */ [0x82] = { "for_of_next",      2,  3,  5, QJS_FMT_u8 },
    /* 0x83 */ [0x83] = { "iterator_check_object", 1, 1, 1, QJS_FMT_none },
    /* 0x84 */ [0x84] = { "iterator_get_value_done", 1, 1, 2, QJS_FMT_none },
    /* 0x85 */ [0x85] = { "iterator_close",   1,  3,  0, QJS_FMT_none },
    /* 0x86 */ [0x86] = { "iterator_next",    1,  4,  4, QJS_FMT_none },
    /* 0x87 */ [0x87] = { "iterator_call",    2,  4,  5, QJS_FMT_u8 },
    /* 0x88 */ [0x88] = { "initial_yield",    1,  0,  0, QJS_FMT_none },
    /* 0x89 */ [0x89] = { "yield",            1,  1,  2, QJS_FMT_none },
    /* 0x8A */ [0x8A] = { "yield_star",       1,  1,  2, QJS_FMT_none },
    /* 0x8B */ [0x8B] = { "async_yield_star", 1,  1,  2, QJS_FMT_none },
    /* 0x8C */ [0x8C] = { "await",            1,  1,  1, QJS_FMT_none },
    /* 0x8D */ [0x8D] = { "neg",              1,  1,  1, QJS_FMT_none },
    /* 0x8E */ [0x8E] = { "plus",             1,  1,  1, QJS_FMT_none },
    /* 0x8F */ [0x8F] = { "dec",              1,  1,  1, QJS_FMT_none },
    /* 0x90 */ [0x90] = { "inc",              1,  1,  1, QJS_FMT_none },
    /* 0x91 */ [0x91] = { "post_dec",         1,  1,  2, QJS_FMT_none },
    /* 0x92 */ [0x92] = { "post_inc",         1,  1,  2, QJS_FMT_none },
    /* 0x93 */ [0x93] = { "dec_loc",          2,  0,  0, QJS_FMT_loc8 },
    /* 0x94 */ [0x94] = { "inc_loc",          2,  0,  0, QJS_FMT_loc8 },
    /* 0x95 */ [0x95] = { "add_loc",          2,  1,  0, QJS_FMT_loc8 },
    /* 0x96 */ [0x96] = { "not",              1,  1,  1, QJS_FMT_none },
    /* 0x97 */ [0x97] = { "lnot",             1,  1,  1, QJS_FMT_none },
    /* 0x98 */ [0x98] = { "typeof",           1,  1,  1, QJS_FMT_none },
    /* 0x99 */ [0x99] = { "delete",           1,  2,  1, QJS_FMT_none },
    /* 0x9A */ [0x9A] = { "delete_var",       5,  0,  1, QJS_FMT_atom },
    /* 0x9B */ [0x9B] = { "mul",              1,  2,  1, QJS_FMT_none },
    /* 0x9C */ [0x9C] = { "div",              1,  2,  1, QJS_FMT_none },
    /* 0x9D */ [0x9D] = { "mod",              1,  2,  1, QJS_FMT_none },
    /* 0x9E */ [0x9E] = { "add",              1,  2,  1, QJS_FMT_none },
    /* 0x9F */ [0x9F] = { "sub",              1,  2,  1, QJS_FMT_none },
    /* 0xA0 */ [0xA0] = { "pow",              1,  2,  1, QJS_FMT_none },
    /* 0xA1 */ [0xA1] = { "shl",              1,  2,  1, QJS_FMT_none },
    /* 0xA2 */ [0xA2] = { "sar",              1,  2,  1, QJS_FMT_none },
    /* 0xA3 */ [0xA3] = { "shr",              1,  2,  1, QJS_FMT_none },
    /* 0xA4 */ [0xA4] = { "lt",               1,  2,  1, QJS_FMT_none },
    /* 0xA5 */ [0xA5] = { "lte",              1,  2,  1, QJS_FMT_none },
    /* 0xA6 */ [0xA6] = { "gt",               1,  2,  1, QJS_FMT_none },
    /* 0xA7 */ [0xA7] = { "gte",              1,  2,  1, QJS_FMT_none },
    /* 0xA8 */ [0xA8] = { "instanceof",       1,  2,  1, QJS_FMT_none },
    /* 0xA9 */ [0xA9] = { "in",               1,  2,  1, QJS_FMT_none },
    /* 0xAA */ [0xAA] = { "eq",               1,  2,  1, QJS_FMT_none },
    /* 0xAB */ [0xAB] = { "neq",              1,  2,  1, QJS_FMT_none },
    /* 0xAC */ [0xAC] = { "strict_eq",        1,  2,  1, QJS_FMT_none },
    /* 0xAD */ [0xAD] = { "strict_neq",       1,  2,  1, QJS_FMT_none },
    /* 0xAE */ [0xAE] = { "and",              1,  2,  1, QJS_FMT_none },
    /* 0xAF */ [0xAF] = { "xor",              1,  2,  1, QJS_FMT_none },
    /* 0xB0 */ [0xB0] = { "or",               1,  2,  1, QJS_FMT_none },
    /* 0xB1 */ [0xB1] = { "is_undefined_or_null", 1, 1, 1, QJS_FMT_none },
    /* 0xB2 */ [0xB2] = { "private_in",       1,  2,  1, QJS_FMT_none },
    /* 0xB3 */ [0xB3] = { "mul_pow10",        1,  2,  1, QJS_FMT_none },
    /* 0xB4 */ [0xB4] = { "math_mod",         1,  2,  1, QJS_FMT_none },
    /* 0xB5 */ [0xB5] = { "nop",              1,  0,  0, QJS_FMT_none },

    /* 0xB6 .. 0xF7 : short opcodes */
    /* 0xB6 */ [0xB6] = { "push_minus1",      1,  0,  1, QJS_FMT_none_int },
    /* 0xB7 */ [0xB7] = { "push_0",           1,  0,  1, QJS_FMT_none_int },
    /* 0xB8 */ [0xB8] = { "push_1",           1,  0,  1, QJS_FMT_none_int },
    /* 0xB9 */ [0xB9] = { "push_2",           1,  0,  1, QJS_FMT_none_int },
    /* 0xBA */ [0xBA] = { "push_3",           1,  0,  1, QJS_FMT_none_int },
    /* 0xBB */ [0xBB] = { "push_4",           1,  0,  1, QJS_FMT_none_int },
    /* 0xBC */ [0xBC] = { "push_5",           1,  0,  1, QJS_FMT_none_int },
    /* 0xBD */ [0xBD] = { "push_6",           1,  0,  1, QJS_FMT_none_int },
    /* 0xBE */ [0xBE] = { "push_7",           1,  0,  1, QJS_FMT_none_int },
    /* 0xBF */ [0xBF] = { "push_i8",          2,  0,  1, QJS_FMT_i8 },
    /* 0xC0 */ [0xC0] = { "push_i16",         3,  0,  1, QJS_FMT_i16 },
    /* 0xC1 */ [0xC1] = { "push_const8",      2,  0,  1, QJS_FMT_const8 },
    /* 0xC2 */ [0xC2] = { "fclosure8",        2,  0,  1, QJS_FMT_const8 },
    /* 0xC3 */ [0xC3] = { "push_empty_string",1,  0,  1, QJS_FMT_none },
    /* 0xC4 */ [0xC4] = { "get_loc8",         2,  0,  1, QJS_FMT_loc8 },
    /* 0xC5 */ [0xC5] = { "put_loc8",         2,  1,  0, QJS_FMT_loc8 },
    /* 0xC6 */ [0xC6] = { "set_loc8",         2,  1,  1, QJS_FMT_loc8 },
    /* 0xC7 */ [0xC7] = { "get_loc0",         1,  0,  1, QJS_FMT_none_loc },
    /* 0xC8 */ [0xC8] = { "get_loc1",         1,  0,  1, QJS_FMT_none_loc },
    /* 0xC9 */ [0xC9] = { "get_loc2",         1,  0,  1, QJS_FMT_none_loc },
    /* 0xCA */ [0xCA] = { "get_loc3",         1,  0,  1, QJS_FMT_none_loc },
    /* 0xCB */ [0xCB] = { "put_loc0",         1,  1,  0, QJS_FMT_none_loc },
    /* 0xCC */ [0xCC] = { "put_loc1",         1,  1,  0, QJS_FMT_none_loc },
    /* 0xCD */ [0xCD] = { "put_loc2",         1,  1,  0, QJS_FMT_none_loc },
    /* 0xCE */ [0xCE] = { "put_loc3",         1,  1,  0, QJS_FMT_none_loc },
    /* 0xCF */ [0xCF] = { "set_loc0",         1,  1,  1, QJS_FMT_none_loc },
    /* 0xD0 */ [0xD0] = { "set_loc1",         1,  1,  1, QJS_FMT_none_loc },
    /* 0xD1 */ [0xD1] = { "set_loc2",         1,  1,  1, QJS_FMT_none_loc },
    /* 0xD2 */ [0xD2] = { "set_loc3",         1,  1,  1, QJS_FMT_none_loc },
    /* 0xD3 */ [0xD3] = { "get_arg0",         1,  0,  1, QJS_FMT_none_arg },
    /* 0xD4 */ [0xD4] = { "get_arg1",         1,  0,  1, QJS_FMT_none_arg },
    /* 0xD5 */ [0xD5] = { "get_arg2",         1,  0,  1, QJS_FMT_none_arg },
    /* 0xD6 */ [0xD6] = { "get_arg3",         1,  0,  1, QJS_FMT_none_arg },
    /* 0xD7 */ [0xD7] = { "put_arg0",         1,  1,  0, QJS_FMT_none_arg },
    /* 0xD8 */ [0xD8] = { "put_arg1",         1,  1,  0, QJS_FMT_none_arg },
    /* 0xD9 */ [0xD9] = { "put_arg2",         1,  1,  0, QJS_FMT_none_arg },
    /* 0xDA */ [0xDA] = { "put_arg3",         1,  1,  0, QJS_FMT_none_arg },
    /* 0xDB */ [0xDB] = { "set_arg0",         1,  1,  1, QJS_FMT_none_arg },
    /* 0xDC */ [0xDC] = { "set_arg1",         1,  1,  1, QJS_FMT_none_arg },
    /* 0xDD */ [0xDD] = { "set_arg2",         1,  1,  1, QJS_FMT_none_arg },
    /* 0xDE */ [0xDE] = { "set_arg3",         1,  1,  1, QJS_FMT_none_arg },
    /* 0xDF */ [0xDF] = { "get_var_ref0",     1,  0,  1, QJS_FMT_none_var_ref },
    /* 0xE0 */ [0xE0] = { "get_var_ref1",     1,  0,  1, QJS_FMT_none_var_ref },
    /* 0xE1 */ [0xE1] = { "get_var_ref2",     1,  0,  1, QJS_FMT_none_var_ref },
    /* 0xE2 */ [0xE2] = { "get_var_ref3",     1,  0,  1, QJS_FMT_none_var_ref },
    /* 0xE3 */ [0xE3] = { "put_var_ref0",     1,  1,  0, QJS_FMT_none_var_ref },
    /* 0xE4 */ [0xE4] = { "put_var_ref1",     1,  1,  0, QJS_FMT_none_var_ref },
    /* 0xE5 */ [0xE5] = { "put_var_ref2",     1,  1,  0, QJS_FMT_none_var_ref },
    /* 0xE6 */ [0xE6] = { "put_var_ref3",     1,  1,  0, QJS_FMT_none_var_ref },
    /* 0xE7 */ [0xE7] = { "set_var_ref0",     1,  1,  1, QJS_FMT_none_var_ref },
    /* 0xE8 */ [0xE8] = { "set_var_ref1",     1,  1,  1, QJS_FMT_none_var_ref },
    /* 0xE9 */ [0xE9] = { "set_var_ref2",     1,  1,  1, QJS_FMT_none_var_ref },
    /* 0xEA */ [0xEA] = { "set_var_ref3",     1,  1,  1, QJS_FMT_none_var_ref },
    /* 0xEB */ [0xEB] = { "get_length",       1,  1,  1, QJS_FMT_none },
    /* 0xEC */ [0xEC] = { "if_false8",        2,  1,  0, QJS_FMT_label8 },
    /* 0xED */ [0xED] = { "if_true8",         2,  1,  0, QJS_FMT_label8 },
    /* 0xEE */ [0xEE] = { "goto8",            2,  0,  0, QJS_FMT_label8 },
    /* 0xEF */ [0xEF] = { "goto16",           3,  0,  0, QJS_FMT_label16 },
    /* 0xF0 */ [0xF0] = { "call0",            1,  1,  1, QJS_FMT_npopx },
    /* 0xF1 */ [0xF1] = { "call1",            1,  1,  1, QJS_FMT_npopx },
    /* 0xF2 */ [0xF2] = { "call2",            1,  1,  1, QJS_FMT_npopx },
    /* 0xF3 */ [0xF3] = { "call3",            1,  1,  1, QJS_FMT_npopx },
    /* 0xF4 */ [0xF4] = { "is_undefined",     1,  1,  1, QJS_FMT_none },
    /* 0xF5 */ [0xF5] = { "is_null",          1,  1,  1, QJS_FMT_none },
    /* 0xF6 */ [0xF6] = { "typeof_is_undefined", 1, 1, 1, QJS_FMT_none },
    /* 0xF7 */ [0xF7] = { "typeof_is_function", 1, 1, 1, QJS_FMT_none },
    /* 0xF8 .. 0xFF : unused — zero-initialised to { NULL, 0, ... } = invalid */
};

/* =========================================================
 * Frida QuickJS opcode table (256 entries)
 *
 * Frida's variant preserves the 19 temporary opcodes in the
 * emitted bytecode. They occupy 0xB6-0xC8, pushing the short
 * opcodes up by 19. Because opcodes are single bytes, only the
 * first 53 short opcodes (push_minus1 .. get_length) fit into
 * 0xC9-0xFE, plus if_false8 at 0xFF. The remaining 12 short
 * opcodes (if_true8, goto8, goto16, call0..3, is_undefined,
 * is_null, typeof_is_undefined, typeof_is_function) would need
 * byte values >= 0x100 and are therefore NOT representable in
 * this encoding — a Frida compiler that preserves temps must
 * emit the long-form opcode (if_true, goto, goto16->goto, call,
 * is_undefined->is_undefined_or_null, etc.) instead.
 * ========================================================= */
const qjs_op_info_t qjs_op_info_frida[QJS_OP_TABLE_SIZE] = {
    /* 0x00 .. 0xB5 : identical to vanilla */
    [0x00] = { "invalid",          1,  0,  0, QJS_FMT_none },
    [0x01] = { "push_i32",         5,  0,  1, QJS_FMT_i32 },
    [0x02] = { "push_const",       5,  0,  1, QJS_FMT_const },
    [0x03] = { "fclosure",         5,  0,  1, QJS_FMT_const },
    [0x04] = { "push_atom_value",  5,  0,  1, QJS_FMT_atom },
    [0x05] = { "private_symbol",   5,  0,  1, QJS_FMT_atom },
    [0x06] = { "undefined",        1,  0,  1, QJS_FMT_none },
    [0x07] = { "null",             1,  0,  1, QJS_FMT_none },
    [0x08] = { "push_this",        1,  0,  1, QJS_FMT_none },
    [0x09] = { "push_false",       1,  0,  1, QJS_FMT_none },
    [0x0A] = { "push_true",        1,  0,  1, QJS_FMT_none },
    [0x0B] = { "object",           1,  0,  1, QJS_FMT_none },
    [0x0C] = { "special_object",   2,  0,  1, QJS_FMT_u8 },
    [0x0D] = { "rest",             3,  0,  1, QJS_FMT_u16 },
    [0x0E] = { "drop",             1,  1,  0, QJS_FMT_none },
    [0x0F] = { "nip",              1,  2,  1, QJS_FMT_none },
    [0x10] = { "nip1",             1,  3,  2, QJS_FMT_none },
    [0x11] = { "dup",              1,  1,  2, QJS_FMT_none },
    [0x12] = { "dup1",             1,  2,  3, QJS_FMT_none },
    [0x13] = { "dup2",             1,  2,  4, QJS_FMT_none },
    [0x14] = { "dup3",             1,  3,  6, QJS_FMT_none },
    [0x15] = { "insert2",          1,  2,  3, QJS_FMT_none },
    [0x16] = { "insert3",          1,  3,  4, QJS_FMT_none },
    [0x17] = { "insert4",          1,  4,  5, QJS_FMT_none },
    [0x18] = { "perm3",            1,  3,  3, QJS_FMT_none },
    [0x19] = { "perm4",            1,  4,  4, QJS_FMT_none },
    [0x1A] = { "perm5",            1,  5,  5, QJS_FMT_none },
    [0x1B] = { "swap",             1,  2,  2, QJS_FMT_none },
    [0x1C] = { "swap2",            1,  4,  4, QJS_FMT_none },
    [0x1D] = { "rot3l",            1,  3,  3, QJS_FMT_none },
    [0x1E] = { "rot3r",            1,  3,  3, QJS_FMT_none },
    [0x1F] = { "rot4l",            1,  4,  4, QJS_FMT_none },
    [0x20] = { "rot5l",            1,  5,  5, QJS_FMT_none },
    [0x21] = { "call_constructor", 3,  2,  1, QJS_FMT_npop },
    [0x22] = { "call",             3,  1,  1, QJS_FMT_npop },
    [0x23] = { "tail_call",        3,  1,  0, QJS_FMT_npop },
    [0x24] = { "call_method",      3,  2,  1, QJS_FMT_npop },
    [0x25] = { "tail_call_method", 3,  2,  0, QJS_FMT_npop },
    [0x26] = { "array_from",       3,  0,  1, QJS_FMT_npop },
    [0x27] = { "apply",            3,  3,  1, QJS_FMT_u16 },
    [0x28] = { "return",           1,  1,  0, QJS_FMT_none },
    [0x29] = { "return_undef",     1,  0,  0, QJS_FMT_none },
    [0x2A] = { "check_ctor_return",1,  1,  2, QJS_FMT_none },
    [0x2B] = { "check_ctor",       1,  0,  0, QJS_FMT_none },
    [0x2C] = { "check_brand",      1,  2,  2, QJS_FMT_none },
    [0x2D] = { "add_brand",        1,  2,  0, QJS_FMT_none },
    [0x2E] = { "return_async",     1,  1,  0, QJS_FMT_none },
    [0x2F] = { "throw",            1,  1,  0, QJS_FMT_none },
    [0x30] = { "throw_error",      6,  0,  0, QJS_FMT_atom_u8 },
    [0x31] = { "eval",             5,  1,  1, QJS_FMT_npop_u16 },
    [0x32] = { "apply_eval",       3,  2,  1, QJS_FMT_u16 },
    [0x33] = { "regexp",           1,  2,  1, QJS_FMT_none },
    [0x34] = { "get_super",        1,  1,  1, QJS_FMT_none },
    [0x35] = { "import",           1,  1,  1, QJS_FMT_none },
    [0x36] = { "check_var",        5,  0,  1, QJS_FMT_atom },
    [0x37] = { "get_var_undef",    5,  0,  1, QJS_FMT_atom },
    [0x38] = { "get_var",          5,  0,  1, QJS_FMT_atom },
    [0x39] = { "put_var",          5,  1,  0, QJS_FMT_atom },
    [0x3A] = { "put_var_init",     5,  1,  0, QJS_FMT_atom },
    [0x3B] = { "put_var_strict",   5,  2,  0, QJS_FMT_atom },
    [0x3C] = { "get_ref_value",    1,  2,  3, QJS_FMT_none },
    [0x3D] = { "put_ref_value",    1,  3,  0, QJS_FMT_none },
    [0x3E] = { "define_var",       6,  0,  0, QJS_FMT_atom_u8 },
    [0x3F] = { "check_define_var", 6,  0,  0, QJS_FMT_atom_u8 },
    [0x40] = { "define_func",      6,  1,  0, QJS_FMT_atom_u8 },
    [0x41] = { "get_field",        5,  1,  1, QJS_FMT_atom },
    [0x42] = { "get_field2",       5,  1,  2, QJS_FMT_atom },
    [0x43] = { "put_field",        5,  2,  0, QJS_FMT_atom },
    [0x44] = { "get_private_field",1,  2,  1, QJS_FMT_none },
    [0x45] = { "put_private_field",1,  3,  0, QJS_FMT_none },
    [0x46] = { "define_private_field",1, 3, 1, QJS_FMT_none },
    [0x47] = { "get_array_el",     1,  2,  1, QJS_FMT_none },
    [0x48] = { "get_array_el2",    1,  2,  2, QJS_FMT_none },
    [0x49] = { "put_array_el",     1,  3,  0, QJS_FMT_none },
    [0x4A] = { "get_super_value",  1,  3,  1, QJS_FMT_none },
    [0x4B] = { "put_super_value",  1,  4,  0, QJS_FMT_none },
    [0x4C] = { "define_field",     5,  2,  1, QJS_FMT_atom },
    [0x4D] = { "set_name",         5,  1,  1, QJS_FMT_atom },
    [0x4E] = { "set_name_computed",1,  2,  2, QJS_FMT_none },
    [0x4F] = { "set_proto",        1,  2,  1, QJS_FMT_none },
    [0x50] = { "set_home_object",  1,  2,  2, QJS_FMT_none },
    [0x51] = { "define_array_el",  1,  3,  2, QJS_FMT_none },
    [0x52] = { "append",           1,  3,  2, QJS_FMT_none },
    [0x53] = { "copy_data_properties", 2, 3, 3, QJS_FMT_u8 },
    [0x54] = { "define_method",    6,  2,  1, QJS_FMT_atom_u8 },
    [0x55] = { "define_method_computed", 2, 3, 1, QJS_FMT_u8 },
    [0x56] = { "define_class",     6,  2,  2, QJS_FMT_atom_u8 },
    [0x57] = { "define_class_computed", 6, 3, 3, QJS_FMT_atom_u8 },
    [0x58] = { "get_loc",          3,  0,  1, QJS_FMT_loc },
    [0x59] = { "put_loc",          3,  1,  0, QJS_FMT_loc },
    [0x5A] = { "set_loc",          3,  1,  1, QJS_FMT_loc },
    [0x5B] = { "get_arg",          3,  0,  1, QJS_FMT_arg },
    [0x5C] = { "put_arg",          3,  1,  0, QJS_FMT_arg },
    [0x5D] = { "set_arg",          3,  1,  1, QJS_FMT_arg },
    [0x5E] = { "get_var_ref",      3,  0,  1, QJS_FMT_var_ref },
    [0x5F] = { "put_var_ref",      3,  1,  0, QJS_FMT_var_ref },
    [0x60] = { "set_var_ref",      3,  1,  1, QJS_FMT_var_ref },
    [0x61] = { "set_loc_uninitialized", 3, 0, 0, QJS_FMT_loc },
    [0x62] = { "get_loc_check",    3,  0,  1, QJS_FMT_loc },
    [0x63] = { "put_loc_check",    3,  1,  0, QJS_FMT_loc },
    [0x64] = { "put_loc_check_init", 3, 1, 0, QJS_FMT_loc },
    [0x65] = { "get_loc_checkthis", 3, 0, 1, QJS_FMT_loc },
    [0x66] = { "get_var_ref_check", 3, 0, 1, QJS_FMT_var_ref },
    [0x67] = { "put_var_ref_check", 3, 1, 0, QJS_FMT_var_ref },
    [0x68] = { "put_var_ref_check_init", 3, 1, 0, QJS_FMT_var_ref },
    [0x69] = { "close_loc",        3,  0,  0, QJS_FMT_loc },
    [0x6A] = { "if_false",         5,  1,  0, QJS_FMT_label },
    [0x6B] = { "if_true",          5,  1,  0, QJS_FMT_label },
    [0x6C] = { "goto",             5,  0,  0, QJS_FMT_label },
    [0x6D] = { "catch",            5,  0,  1, QJS_FMT_label },
    [0x6E] = { "gosub",            5,  0,  0, QJS_FMT_label },
    [0x6F] = { "ret",              1,  1,  0, QJS_FMT_none },
    [0x70] = { "nip_catch",        1,  2,  1, QJS_FMT_none },
    [0x71] = { "to_object",        1,  1,  1, QJS_FMT_none },
    [0x72] = { "to_propkey",       1,  1,  1, QJS_FMT_none },
    [0x73] = { "to_propkey2",      1,  2,  2, QJS_FMT_none },
    [0x74] = { "with_get_var",     10, 1,  0, QJS_FMT_atom_label_u8 },
    [0x75] = { "with_put_var",     10, 2,  1, QJS_FMT_atom_label_u8 },
    [0x76] = { "with_delete_var",  10, 1,  0, QJS_FMT_atom_label_u8 },
    [0x77] = { "with_make_ref",    10, 1,  0, QJS_FMT_atom_label_u8 },
    [0x78] = { "with_get_ref",     10, 1,  0, QJS_FMT_atom_label_u8 },
    [0x79] = { "with_get_ref_undef", 10, 1, 0, QJS_FMT_atom_label_u8 },
    [0x7A] = { "make_loc_ref",     7,  0,  2, QJS_FMT_atom_u16 },
    [0x7B] = { "make_arg_ref",     7,  0,  2, QJS_FMT_atom_u16 },
    [0x7C] = { "make_var_ref_ref", 7,  0,  2, QJS_FMT_atom_u16 },
    [0x7D] = { "make_var_ref",     5,  0,  2, QJS_FMT_atom },
    [0x7E] = { "for_in_start",     1,  1,  1, QJS_FMT_none },
    [0x7F] = { "for_of_start",     1,  1,  3, QJS_FMT_none },
    [0x80] = { "for_await_of_start", 1, 1, 3, QJS_FMT_none },
    [0x81] = { "for_in_next",      1,  1,  3, QJS_FMT_none },
    [0x82] = { "for_of_next",      2,  3,  5, QJS_FMT_u8 },
    [0x83] = { "iterator_check_object", 1, 1, 1, QJS_FMT_none },
    [0x84] = { "iterator_get_value_done", 1, 1, 2, QJS_FMT_none },
    [0x85] = { "iterator_close",   1,  3,  0, QJS_FMT_none },
    [0x86] = { "iterator_next",    1,  4,  4, QJS_FMT_none },
    [0x87] = { "iterator_call",    2,  4,  5, QJS_FMT_u8 },
    [0x88] = { "initial_yield",    1,  0,  0, QJS_FMT_none },
    [0x89] = { "yield",            1,  1,  2, QJS_FMT_none },
    [0x8A] = { "yield_star",       1,  1,  2, QJS_FMT_none },
    [0x8B] = { "async_yield_star", 1,  1,  2, QJS_FMT_none },
    [0x8C] = { "await",            1,  1,  1, QJS_FMT_none },
    [0x8D] = { "neg",              1,  1,  1, QJS_FMT_none },
    [0x8E] = { "plus",             1,  1,  1, QJS_FMT_none },
    [0x8F] = { "dec",              1,  1,  1, QJS_FMT_none },
    [0x90] = { "inc",              1,  1,  1, QJS_FMT_none },
    [0x91] = { "post_dec",         1,  1,  2, QJS_FMT_none },
    [0x92] = { "post_inc",         1,  1,  2, QJS_FMT_none },
    [0x93] = { "dec_loc",          2,  0,  0, QJS_FMT_loc8 },
    [0x94] = { "inc_loc",          2,  0,  0, QJS_FMT_loc8 },
    [0x95] = { "add_loc",          2,  1,  0, QJS_FMT_loc8 },
    [0x96] = { "not",              1,  1,  1, QJS_FMT_none },
    [0x97] = { "lnot",             1,  1,  1, QJS_FMT_none },
    [0x98] = { "typeof",           1,  1,  1, QJS_FMT_none },
    [0x99] = { "delete",           1,  2,  1, QJS_FMT_none },
    [0x9A] = { "delete_var",       5,  0,  1, QJS_FMT_atom },
    [0x9B] = { "mul",              1,  2,  1, QJS_FMT_none },
    [0x9C] = { "div",              1,  2,  1, QJS_FMT_none },
    [0x9D] = { "mod",              1,  2,  1, QJS_FMT_none },
    [0x9E] = { "add",              1,  2,  1, QJS_FMT_none },
    [0x9F] = { "sub",              1,  2,  1, QJS_FMT_none },
    [0xA0] = { "pow",              1,  2,  1, QJS_FMT_none },
    [0xA1] = { "shl",              1,  2,  1, QJS_FMT_none },
    [0xA2] = { "sar",              1,  2,  1, QJS_FMT_none },
    [0xA3] = { "shr",              1,  2,  1, QJS_FMT_none },
    [0xA4] = { "lt",               1,  2,  1, QJS_FMT_none },
    [0xA5] = { "lte",              1,  2,  1, QJS_FMT_none },
    [0xA6] = { "gt",               1,  2,  1, QJS_FMT_none },
    [0xA7] = { "gte",              1,  2,  1, QJS_FMT_none },
    [0xA8] = { "instanceof",       1,  2,  1, QJS_FMT_none },
    [0xA9] = { "in",               1,  2,  1, QJS_FMT_none },
    [0xAA] = { "eq",               1,  2,  1, QJS_FMT_none },
    [0xAB] = { "neq",              1,  2,  1, QJS_FMT_none },
    [0xAC] = { "strict_eq",        1,  2,  1, QJS_FMT_none },
    [0xAD] = { "strict_neq",       1,  2,  1, QJS_FMT_none },
    [0xAE] = { "and",              1,  2,  1, QJS_FMT_none },
    [0xAF] = { "xor",              1,  2,  1, QJS_FMT_none },
    [0xB0] = { "or",               1,  2,  1, QJS_FMT_none },
    [0xB1] = { "is_undefined_or_null", 1, 1, 1, QJS_FMT_none },
    [0xB2] = { "private_in",       1,  2,  1, QJS_FMT_none },
    [0xB3] = { "mul_pow10",        1,  2,  1, QJS_FMT_none },
    [0xB4] = { "math_mod",         1,  2,  1, QJS_FMT_none },
    [0xB5] = { "nop",              1,  0,  0, QJS_FMT_none },

    /* 0xB6 .. 0xC8 : 19 temporary opcodes (preserved in Frida mode) */
    [0xB6] = { "enter_scope",      3,  0,  0, QJS_FMT_u16 },
    [0xB7] = { "leave_scope",      3,  0,  0, QJS_FMT_u16 },
    [0xB8] = { "label",            5,  0,  0, QJS_FMT_label },
    [0xB9] = { "scope_get_var_undef", 7, 0, 1, QJS_FMT_atom_u16 },
    [0xBA] = { "scope_get_var",    7,  0,  1, QJS_FMT_atom_u16 },
    [0xBB] = { "scope_put_var",    7,  1,  0, QJS_FMT_atom_u16 },
    [0xBC] = { "scope_delete_var", 7,  0,  1, QJS_FMT_atom_u16 },
    [0xBD] = { "scope_make_ref",  11,  0,  2, QJS_FMT_atom_label_u16 },
    [0xBE] = { "scope_get_ref",    7,  0,  2, QJS_FMT_atom_u16 },
    [0xBF] = { "scope_put_var_init", 7, 0, 2, QJS_FMT_atom_u16 },
    [0xC0] = { "scope_get_var_checkthis", 7, 0, 1, QJS_FMT_atom_u16 },
    [0xC1] = { "scope_get_private_field", 7, 1, 1, QJS_FMT_atom_u16 },
    [0xC2] = { "scope_get_private_field2", 7, 1, 2, QJS_FMT_atom_u16 },
    [0xC3] = { "scope_put_private_field", 7, 2, 0, QJS_FMT_atom_u16 },
    [0xC4] = { "scope_in_private_field", 7, 1, 1, QJS_FMT_atom_u16 },
    [0xC5] = { "get_field_opt_chain", 5, 1, 1, QJS_FMT_atom },
    [0xC6] = { "get_array_el_opt_chain", 1, 2, 1, QJS_FMT_none },
    [0xC7] = { "set_class_name",   5,  1,  1, QJS_FMT_u32 },
    [0xC8] = { "line_num",         5,  0,  0, QJS_FMT_u32 },

    /* 0xC9 .. 0xFF : short opcodes shifted by 19.
     * Only the first 54 (push_minus1 .. get_length) fit into
     * 0xC9..0xFE, plus if_false8 at 0xFF. The remaining 12
     * short opcodes are not representable in this mode. */
    [0xC9] = { "push_minus1",      1,  0,  1, QJS_FMT_none_int },
    [0xCA] = { "push_0",           1,  0,  1, QJS_FMT_none_int },
    [0xCB] = { "push_1",           1,  0,  1, QJS_FMT_none_int },
    [0xCC] = { "push_2",           1,  0,  1, QJS_FMT_none_int },
    [0xCD] = { "push_3",           1,  0,  1, QJS_FMT_none_int },
    [0xCE] = { "push_4",           1,  0,  1, QJS_FMT_none_int },
    [0xCF] = { "push_5",           1,  0,  1, QJS_FMT_none_int },
    [0xD0] = { "push_6",           1,  0,  1, QJS_FMT_none_int },
    [0xD1] = { "push_7",           1,  0,  1, QJS_FMT_none_int },
    [0xD2] = { "push_i8",          2,  0,  1, QJS_FMT_i8 },
    [0xD3] = { "push_i16",         3,  0,  1, QJS_FMT_i16 },
    [0xD4] = { "push_const8",      2,  0,  1, QJS_FMT_const8 },
    [0xD5] = { "fclosure8",        2,  0,  1, QJS_FMT_const8 },
    [0xD6] = { "push_empty_string",1,  0,  1, QJS_FMT_none },
    [0xD7] = { "get_loc8",         2,  0,  1, QJS_FMT_loc8 },
    [0xD8] = { "put_loc8",         2,  1,  0, QJS_FMT_loc8 },
    [0xD9] = { "set_loc8",         2,  1,  1, QJS_FMT_loc8 },
    [0xDA] = { "get_loc0",         1,  0,  1, QJS_FMT_none_loc },
    [0xDB] = { "get_loc1",         1,  0,  1, QJS_FMT_none_loc },
    [0xDC] = { "get_loc2",         1,  0,  1, QJS_FMT_none_loc },
    [0xDD] = { "get_loc3",         1,  0,  1, QJS_FMT_none_loc },
    [0xDE] = { "put_loc0",         1,  1,  0, QJS_FMT_none_loc },
    [0xDF] = { "put_loc1",         1,  1,  0, QJS_FMT_none_loc },
    [0xE0] = { "put_loc2",         1,  1,  0, QJS_FMT_none_loc },
    [0xE1] = { "put_loc3",         1,  1,  0, QJS_FMT_none_loc },
    [0xE2] = { "set_loc0",         1,  1,  1, QJS_FMT_none_loc },
    [0xE3] = { "set_loc1",         1,  1,  1, QJS_FMT_none_loc },
    [0xE4] = { "set_loc2",         1,  1,  1, QJS_FMT_none_loc },
    [0xE5] = { "set_loc3",         1,  1,  1, QJS_FMT_none_loc },
    [0xE6] = { "get_arg0",         1,  0,  1, QJS_FMT_none_arg },
    [0xE7] = { "get_arg1",         1,  0,  1, QJS_FMT_none_arg },
    [0xE8] = { "get_arg2",         1,  0,  1, QJS_FMT_none_arg },
    [0xE9] = { "get_arg3",         1,  0,  1, QJS_FMT_none_arg },
    [0xEA] = { "put_arg0",         1,  1,  0, QJS_FMT_none_arg },
    [0xEB] = { "put_arg1",         1,  1,  0, QJS_FMT_none_arg },
    [0xEC] = { "put_arg2",         1,  1,  0, QJS_FMT_none_arg },
    [0xED] = { "put_arg3",         1,  1,  0, QJS_FMT_none_arg },
    [0xEE] = { "set_arg0",         1,  1,  1, QJS_FMT_none_arg },
    [0xEF] = { "set_arg1",         1,  1,  1, QJS_FMT_none_arg },
    [0xF0] = { "set_arg2",         1,  1,  1, QJS_FMT_none_arg },
    [0xF1] = { "set_arg3",         1,  1,  1, QJS_FMT_none_arg },
    [0xF2] = { "get_var_ref0",     1,  0,  1, QJS_FMT_none_var_ref },
    [0xF3] = { "get_var_ref1",     1,  0,  1, QJS_FMT_none_var_ref },
    [0xF4] = { "get_var_ref2",     1,  0,  1, QJS_FMT_none_var_ref },
    [0xF5] = { "get_var_ref3",     1,  0,  1, QJS_FMT_none_var_ref },
    [0xF6] = { "put_var_ref0",     1,  1,  0, QJS_FMT_none_var_ref },
    [0xF7] = { "put_var_ref1",     1,  1,  0, QJS_FMT_none_var_ref },
    [0xF8] = { "put_var_ref2",     1,  1,  0, QJS_FMT_none_var_ref },
    [0xF9] = { "put_var_ref3",     1,  1,  0, QJS_FMT_none_var_ref },
    [0xFA] = { "set_var_ref0",     1,  1,  1, QJS_FMT_none_var_ref },
    [0xFB] = { "set_var_ref1",     1,  1,  1, QJS_FMT_none_var_ref },
    [0xFC] = { "set_var_ref2",     1,  1,  1, QJS_FMT_none_var_ref },
    [0xFD] = { "set_var_ref3",     1,  1,  1, QJS_FMT_none_var_ref },
    [0xFE] = { "get_length",       1,  1,  1, QJS_FMT_none },
    [0xFF] = { "if_false8",        2,  1,  0, QJS_FMT_label8 },
    /* 0x100+ not representable as a single byte — left invalid */
};

/* =========================================================
 * Global default mode
 * ========================================================= */
static qjs_op_mode_t g_default_mode = QJS_MODE_AUTO;

void qjs_set_default_mode(qjs_op_mode_t mode) { g_default_mode = mode; }
qjs_op_mode_t qjs_get_default_mode(void)      { return g_default_mode; }

const char *qjs_mode_name(qjs_op_mode_t mode) {
    switch (mode) {
        case QJS_MODE_AUTO:    return "auto";
        case QJS_MODE_VANILLA: return "vanilla";
        case QJS_MODE_FRIDA:   return "frida";
        default:               return "unknown";
    }
}

/* =========================================================
 * Get opcode info for a raw byte in a given mode.
 * Never returns NULL — out-of-range entries fall through to the
 * zero-initialised "invalid" slot { NULL, 0, ... }.
 * ========================================================= */
const qjs_op_info_t *qjs_get_op_info(uint8_t op, qjs_op_mode_t mode) {
    if (mode == QJS_MODE_FRIDA)
        return &qjs_op_info_frida[op];
    return &qjs_op_info_vanilla[op];
}

/* =========================================================
 * Walk the bytecode with a given table and compute a score.
 *
 * Scoring:
 *   +100  if the walk lands exactly on bc_len (clean termination)
 *   -10   per opcode with size 0 (invalid / overflow slot)
 *   -5    per truncation (instruction would read past end)
 *   -1    per backward jump to a non-instruction-boundary (heuristic)
 *
 * Returns the score; higher is better.
 * ========================================================= */
static int score_walk(const qjs_op_info_t *table,
                      const uint8_t *bc, uint32_t bc_len,
                      int big_endian, int want_temps) {
    (void)big_endian;
    uint32_t pos = 0;
    int score = 0;
    int n_invalid = 0;
    int n_trunc = 0;
    int n_temp = 0;

    while (pos < bc_len) {
        uint8_t op = bc[pos];
        const qjs_op_info_t *info = &table[op];

        if (info->size == 0 || info->name == NULL) {
            /* invalid opcode */
            n_invalid++;
            pos++;   /* skip 1 byte and try to resync */
            continue;
        }

        /* Detect temporary opcodes in vanilla mode (they shouldn't appear) */
        if (!want_temps && op >= 0xB6 && op <= 0xC8) {
            /* In vanilla mode this range is short opcodes like push_minus1.
             * If we see a byte here that the vanilla table calls a short
             * opcode but the surrounding context looks temp-ish, we can't
             * easily tell. Skip this heuristic — rely on termination. */
        }
        if (want_temps && op >= 0xB6 && op <= 0xC8) n_temp++;

        if (pos + info->size > bc_len) {
            n_trunc++;
            break;
        }

        pos += info->size;
    }

    /* Strong reward for landing exactly on the end. */
    if (pos == bc_len && n_invalid == 0 && n_trunc == 0)
        score += 100;
    else if (pos == bc_len)
        score += 40;
    else
        score -= 20;   /* didn't reach the end cleanly */

    score -= 10 * n_invalid;
    score -= 5  * n_trunc;

    /* Seeing temp opcodes is only expected in frida mode. */
    if (want_temps && n_temp > 0) score += 5;

    return score;
}

/* =========================================================
 * Auto-detect the opcode mode for a bytecode body.
 *
 * Strategy:
 *   1. Score the vanilla walk.
 *   2. Score the frida walk.
 *   3. Return frida ONLY if it's strictly better AND vanilla is
 *      not clean. Otherwise return vanilla (the common case).
 * ========================================================= */
qjs_op_mode_t qjs_detect_op_mode(const uint8_t *bc, uint32_t bc_len,
                                  int big_endian) {
    /* Trivial: empty or tiny bodies are always vanilla. */
    if (bc_len == 0) return QJS_MODE_VANILLA;

    int s_vanilla = score_walk(qjs_op_info_vanilla, bc, bc_len, big_endian, 0);
    int s_frida   = score_walk(qjs_op_info_frida,   bc, bc_len, big_endian, 1);

    /* Prefer vanilla unless frida is clearly better. */
    if (s_frida > s_vanilla && s_vanilla < 90)
        return QJS_MODE_FRIDA;
    return QJS_MODE_VANILLA;
}
