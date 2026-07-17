/*
 * ir.c - IR builder implementation
 *
 * Decodes bytecode into an instruction array and identifies
 * basic block boundaries (jump targets).
 */
#include "ir.h"
#include "util.h"
#include "qjs_opcodes_frida.h"
#include <string.h>

/* =========================================================
 * Build IR from bytecode
 * ========================================================= */
ir_function_t *ir_build(qjs_reader_t *r, qjs_function_t *fn) {
    ir_function_t *ir = xcalloc(1, sizeof(*ir));
    const uint8_t *bc = fn->byte_code;
    uint32_t len = (uint32_t)fn->byte_code_len;
    ir->bc_len = len;

    /* allocate instruction array (at most len entries) */
    ir->insns = xcalloc(len + 1, sizeof(ir_insn_t));
    ir->cap = len + 1;

    /* allocate target bitmap */
    ir->is_target = xcalloc(len + 1, sizeof(uint8_t));

    /* First pass: decode all instructions */
    uint32_t pc = 0;
    while (pc < len) {
        uint8_t op = bc[pc];
        const qjs_op_info_t *info = get_op_info(op, fn->is_frida);
        if (!info) {
            /* invalid opcode - record and skip */
            ir->insns[ir->count].pc = pc;
            ir->insns[ir->count].op = op;
            ir->insns[ir->count].info = NULL;
            ir->count++;
            pc++;
            continue;
        }

        int sz = info->size;
        if (pc + sz > len) {
            /* truncated */
            ir->insns[ir->count].pc = pc;
            ir->insns[ir->count].op = op;
            ir->insns[ir->count].info = info;
            ir->count++;
            break;
        }

        ir_insn_t *insn = &ir->insns[ir->count];
        insn->pc = pc;
        insn->op = op;
        insn->info = info;

        /* In Frida mode, remap opcode to standard enum value for the decompiler.
         * Opcodes 0x00-0xB5 are the same in both modes.
         * Temporary opcodes (0xB6-0xC8) are mapped to their standard equivalents
         * or to a skip range (0x1000+).
         * Short opcodes in Frida (0xC9+) are remapped by subtracting 19. */
        if (fn->is_frida && op >= 0xB6) {
            if (op <= 0xC8) {
                /* Temporary opcode - map to standard equivalent or skip */
                switch (op) {
                    case 0xB9: insn->op = qjs_op_get_var_undef; break; /* scope_get_var_undef */
                    case 0xBA: insn->op = qjs_op_get_var; break;       /* scope_get_var */
                    case 0xBB: insn->op = qjs_op_put_var; break;       /* scope_put_var */
                    case 0xBC: insn->op = qjs_op_delete_var; break;    /* scope_delete_var */
                    case 0xBF: insn->op = qjs_op_put_var_init; break;  /* scope_put_var_init */
                    case 0xC0: insn->op = qjs_op_get_var; break;       /* scope_get_var_checkthis */
                    case 0xC5: insn->op = qjs_op_get_field; break;     /* get_field_opt_chain */
                    case 0xC6: insn->op = qjs_op_get_array_el; break;  /* get_array_el_opt_chain */
                    default:   insn->op = 0x1000 + (op - 0xB6); break; /* skip */
                }
            } else {
                /* Short opcode - remap to standard value */
                insn->op = op - QJS_TEMP_OPCODE_COUNT;
            }
        }

        /* decode operands based on format */
        switch (info->fmt) {
            case QJS_FMT_i8:
                insn->i32_val = (int8_t)bc[pc + 1];
                break;
            case QJS_FMT_u8:
            case QJS_FMT_loc8:
            case QJS_FMT_const8:
                insn->u32_val = bc[pc + 1];
                break;
            case QJS_FMT_i16:
                insn->i32_val = (int16_t)rd_u16(bc + pc + 1, r->big_endian);
                break;
            case QJS_FMT_u16:
            case QJS_FMT_npop_u16:
                insn->u32_val = rd_u16(bc + pc + 1, r->big_endian);
                break;
            case QJS_FMT_i32:
                insn->i32_val = (int32_t)rd_u32(bc + pc + 1, r->big_endian);
                break;
            case QJS_FMT_u32:
                insn->u32_val = rd_u32(bc + pc + 1, r->big_endian);
                break;
            case QJS_FMT_loc:
            case QJS_FMT_arg:
            case QJS_FMT_var_ref:
                /* size 3 = u16 operand */
                insn->u32_val = rd_u16(bc + pc + 1, r->big_endian);
                break;
            case QJS_FMT_const:
                insn->u32_val = rd_u32(bc + pc + 1, r->big_endian);
                break;
            case QJS_FMT_npop:
                /* npop has size 3 = 1 byte op + 2 byte u16 operand */
                insn->u32_val = rd_u16(bc + pc + 1, r->big_endian);
                break;
            case QJS_FMT_npopx:
                /* no operand */
                break;
            case QJS_FMT_atom:
            case QJS_FMT_atom_u8:
            case QJS_FMT_atom_u16:
                insn->atom_val = rd_u32(bc + pc + 1, r->big_endian);
                if (info->fmt == QJS_FMT_atom_u8)
                    insn->u32_val = bc[pc + 5];
                else if (info->fmt == QJS_FMT_atom_u16)
                    insn->u32_val = rd_u16(bc + pc + 5, r->big_endian);
                break;
            case QJS_FMT_atom_label_u8:
                insn->atom_val = rd_u32(bc + pc + 1, r->big_endian);
                insn->label_target = (int32_t)(pc + 5 + (int8_t)bc[pc + 5]);
                break;
            case QJS_FMT_atom_label_u16:
                insn->atom_val = rd_u32(bc + pc + 1, r->big_endian);
                insn->label_target = (int32_t)(pc + 5 + (int16_t)rd_u16(bc + pc + 5, r->big_endian));
                break;
            case QJS_FMT_label8:
                /* QuickJS: target = pc + 1 + (int8_t)offset
                 * (pc points to opcode, offset is at pc+1, target is relative to pc+1) */
                insn->label_target = (int32_t)(pc + 1 + (int8_t)bc[pc + 1]);
                break;
            case QJS_FMT_label16:
                insn->label_target = (int32_t)(pc + 1 + (int16_t)rd_u16(bc + pc + 1, r->big_endian));
                break;
            case QJS_FMT_label:
                insn->label_target = (int32_t)(pc + 1 + (int32_t)rd_u32(bc + pc + 1, r->big_endian));
                break;
            case QJS_FMT_label_u16:
                insn->label_target = (int32_t)(pc + 1 + (int16_t)rd_u16(bc + pc + 1, r->big_endian));
                break;
            default:
                break;
        }

        /* mark jump properties and fix short opcode operands.
         * Use insn->op (remapped) instead of op (raw byte) for Frida compatibility. */
        switch (insn->op) {
            /* Short opcodes: arg/loc/var_ref index is encoded in the opcode itself */
            case qjs_op_get_loc0: case qjs_op_get_loc1: case qjs_op_get_loc2: case qjs_op_get_loc3:
            case qjs_op_put_loc0: case qjs_op_put_loc1: case qjs_op_put_loc2: case qjs_op_put_loc3:
            case qjs_op_set_loc0: case qjs_op_set_loc1: case qjs_op_set_loc2: case qjs_op_set_loc3:
                insn->u32_val = insn->op - qjs_op_get_loc0;
                /* But put_loc0 is at a different offset than get_loc0...
                 * Actually they're interleaved: get_loc0,1,2,3, put_loc0,1,2,3, set_loc0,1,2,3
                 * So we need to compute relative to the start of each group */
                if (insn->op >= qjs_op_get_loc0 && insn->op <= qjs_op_get_loc3)
                    insn->u32_val = insn->op - qjs_op_get_loc0;
                else if (insn->op >= qjs_op_put_loc0 && insn->op <= qjs_op_put_loc3)
                    insn->u32_val = insn->op - qjs_op_put_loc0;
                else if (insn->op >= qjs_op_set_loc0 && insn->op <= qjs_op_set_loc3)
                    insn->u32_val = insn->op - qjs_op_set_loc0;
                break;
            case qjs_op_get_arg0: case qjs_op_get_arg1: case qjs_op_get_arg2: case qjs_op_get_arg3:
            case qjs_op_put_arg0: case qjs_op_put_arg1: case qjs_op_put_arg2: case qjs_op_put_arg3:
            case qjs_op_set_arg0: case qjs_op_set_arg1: case qjs_op_set_arg2: case qjs_op_set_arg3:
                if (insn->op >= qjs_op_get_arg0 && insn->op <= qjs_op_get_arg3)
                    insn->u32_val = insn->op - qjs_op_get_arg0;
                else if (insn->op >= qjs_op_put_arg0 && insn->op <= qjs_op_put_arg3)
                    insn->u32_val = insn->op - qjs_op_put_arg0;
                else if (insn->op >= qjs_op_set_arg0 && insn->op <= qjs_op_set_arg3)
                    insn->u32_val = insn->op - qjs_op_set_arg0;
                break;
            case qjs_op_get_var_ref0: case qjs_op_get_var_ref1: case qjs_op_get_var_ref2: case qjs_op_get_var_ref3:
            case qjs_op_put_var_ref0: case qjs_op_put_var_ref1: case qjs_op_put_var_ref2: case qjs_op_put_var_ref3:
            case qjs_op_set_var_ref0: case qjs_op_set_var_ref1: case qjs_op_set_var_ref2: case qjs_op_set_var_ref3:
                if (insn->op >= qjs_op_get_var_ref0 && insn->op <= qjs_op_get_var_ref3)
                    insn->u32_val = insn->op - qjs_op_get_var_ref0;
                else if (insn->op >= qjs_op_put_var_ref0 && insn->op <= qjs_op_put_var_ref3)
                    insn->u32_val = insn->op - qjs_op_put_var_ref0;
                else if (insn->op >= qjs_op_set_var_ref0 && insn->op <= qjs_op_set_var_ref3)
                    insn->u32_val = insn->op - qjs_op_set_var_ref0;
                break;
            /* Short call opcodes: nargs is encoded in opcode */
            case qjs_op_call0: case qjs_op_call1: case qjs_op_call2: case qjs_op_call3:
                insn->u32_val = insn->op - qjs_op_call0;
                break;

            case qjs_op_if_false:
            case qjs_op_if_false8:
            case qjs_op_if_true:
            case qjs_op_if_true8:
                insn->is_jump = 1;
                insn->is_conditional = 1;
                insn->is_backward = (insn->label_target < (int32_t)pc) ? 1 : 0;
                if (insn->label_target >= 0 && (uint32_t)insn->label_target < len)
                    ir->is_target[insn->label_target] = 1;
                break;
            case qjs_op_goto:
            case qjs_op_goto8:
            case qjs_op_goto16:
                insn->is_jump = 1;
                insn->is_backward = (insn->label_target < (int32_t)pc) ? 1 : 0;
                if (insn->label_target >= 0 && (uint32_t)insn->label_target < len)
                    ir->is_target[insn->label_target] = 1;
                break;
            case qjs_op_catch:
                /* catch is handled in decode_insn (pushes catch context) */
                /* Don't mark as jump since we handle it as a stack op */
                break;
            case qjs_op_return:
            case qjs_op_return_undef:
            case qjs_op_return_async:
            case qjs_op_throw:
                insn->is_return_terminator = 1;
                break;
            default:
                break;
        }

        ir->count++;
        pc += sz;
    }

    /* Mark function start as a target */
    ir->is_target[0] = 1;

    /* Build sorted target list */
    int n = 0;
    for (uint32_t i = 0; i <= len; i++) {
        if (ir->is_target[i]) n++;
    }
    ir->n_targets = n;
    ir->targets = xcalloc(n + 1, sizeof(uint32_t));
    int ti = 0;
    for (uint32_t i = 0; i <= len; i++) {
        if (ir->is_target[i]) ir->targets[ti++] = i;
    }

    return ir;
}

/* =========================================================
 * Free IR
 * ========================================================= */
void ir_free(ir_function_t *ir) {
    if (!ir) return;
    free(ir->insns);
    free(ir->targets);
    free(ir->is_target);
    free(ir);
}

/* =========================================================
 * Find instruction index by PC
 *
 * Returns the index of the instruction at exactly `pc`, or if not found,
 * the index of the first instruction at or after `pc` (snapping forward).
 * This handles cases where a jump target lands in the middle of an
 * instruction (which shouldn't happen but can due to off-by-one errors).
 * ========================================================= */
int ir_find_insn(ir_function_t *ir, uint32_t pc) {
    /* binary search */
    int lo = 0, hi = ir->count - 1;
    while (lo <= hi) {
        int mid = (lo + hi) / 2;
        if (ir->insns[mid].pc == pc) return mid;
        if (ir->insns[mid].pc < pc) lo = mid + 1;
        else hi = mid - 1;
    }
    /* lo is the insertion point = first instruction with pc > target */
    if (lo < ir->count) {
        /* Check if the target is within the instruction at lo-1 */
        if (lo > 0) {
            uint32_t prev_pc = ir->insns[lo - 1].pc;
            uint32_t prev_sz = ir->insns[lo - 1].info ? ir->insns[lo - 1].info->size : 1;
            if (pc < prev_pc + prev_sz) {
                /* Target is inside the previous instruction - return the next one */
                return lo;
            }
        }
        return lo;
    }
    return ir->count;  /* past the end */
}

/* =========================================================
 * Check if a PC is a jump target
 * ========================================================= */
int ir_is_target(ir_function_t *ir, uint32_t pc) {
    if (pc > ir->bc_len) return 0;
    return ir->is_target[pc];
}
