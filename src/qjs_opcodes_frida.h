/*
 * qjs_opcodes_frida.h - Frida QuickJS opcode table
 *
 * Frida's QuickJS variant may preserve temporary (phase 1) opcodes
 * in the final bytecode. These opcodes occupy the byte range 0xB6-0xC8,
 * shifting all short opcodes up by 19 positions.
 *
 * Detection: if walking bytecode with standard table causes truncation
 * errors, switch to this Frida table.
 */
#ifndef QJS_OPCODES_FRIDA_H
#define QJS_OPCODES_FRIDA_H

#include "qjs_opcodes.h"

/* Number of temporary opcodes */
#define QJS_TEMP_OPCODE_COUNT 19

/* Frida opcode table: 0x00-0xB5 same as standard,
 * 0xB6-0xC8 = temporary opcodes,
 * 0xC9-0x10A = short opcodes (shifted by 19) */
static const qjs_op_info_t qjs_op_info_frida[] = {
    /* 0x00-0xB5: same as standard table */
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

    /* 0xB6-0xC8: temporary opcodes (phase 1) */
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

    /* 0xC9-0x10A: short opcodes (shifted by 19 from standard) */
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
    [0x100] = { "if_true8",        2,  1,  0, QJS_FMT_label8 },
    [0x101] = { "goto8",           2,  0,  0, QJS_FMT_label8 },
    [0x102] = { "goto16",          3,  0,  0, QJS_FMT_label16 },
    [0x103] = { "call0",           1,  1,  1, QJS_FMT_npopx },
    [0x104] = { "call1",           1,  1,  1, QJS_FMT_npopx },
    [0x105] = { "call2",           1,  1,  1, QJS_FMT_npopx },
    [0x106] = { "call3",           1,  1,  1, QJS_FMT_npopx },
    [0x107] = { "is_undefined",    1,  1,  1, QJS_FMT_none },
    [0x108] = { "is_null",         1,  1,  1, QJS_FMT_none },
    [0x109] = { "typeof_is_undefined", 1, 1, 1, QJS_FMT_none },
    [0x10A] = { "typeof_is_function", 1, 1, 1, QJS_FMT_none },
};

#define QJS_FRIDA_OP_COUNT 0x10B  /* 267 entries */

/* Auto-detect: try walking bytecode with both standard and Frida tables.
 * Returns 1 if Frida mode is more likely, 0 if standard mode. */
static int detect_frida_mode(const uint8_t *bc, uint32_t bc_len, int big_endian) {
    /* Try standard table first */
    uint32_t pos_std = 0;
    int trunc_std = 0;
    while (pos_std < bc_len) {
        uint8_t op = bc[pos_std];
        if (op >= QJS_OP_INFO_COUNT) { trunc_std = 999; break; }
        int sz = qjs_op_info[op].size;
        if (pos_std + sz > bc_len) { trunc_std++; break; }
        pos_std += sz;
    }

    /* Try Frida table */
    uint32_t pos_frida = 0;
    int trunc_frida = 0;
    while (pos_frida < bc_len) {
        uint8_t op = bc[pos_frida];
        if (op >= QJS_FRIDA_OP_COUNT) { trunc_frida = 999; break; }
        int sz = qjs_op_info_frida[op].size;
        if (sz == 0) { trunc_frida++; break; }
        if (pos_frida + sz > bc_len) { trunc_frida++; break; }
        pos_frida += sz;
    }

    /* Prefer standard mode unless:
     * 1. Standard walk fails (truncation or doesn't end at bc_len) AND
     * 2. Frida walk succeeds (no truncation and ends at bc_len) */
    if (trunc_frida == 0 && pos_frida == bc_len &&
        (trunc_std > 0 || pos_std != bc_len)) {
        return 1;
    }
    return 0;
}

/* Get the appropriate opcode info based on mode */
static inline const qjs_op_info_t *get_op_info(uint8_t op, int is_frida) {
    if (is_frida) {
        if (op < QJS_FRIDA_OP_COUNT)
            return &qjs_op_info_frida[op];
        return NULL;
    }
    if (op < QJS_OP_INFO_COUNT)
        return &qjs_op_info[op];
    return NULL;
}

#endif /* QJS_OPCODES_FRIDA_H */
