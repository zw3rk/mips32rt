/*
 * src/dbt/emit_int.c -- AArch64 integer emitter (Phase 2, L2c).
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stddef.h>
#include <stdint.h>
#include "mips32rt.h"
#include "rt32/a64_emit.h"
#include "interp/decode.h"
/* Cached guest GPR -> host W register (SPEC 2.1 order). */
static const int8_t kGprHost[32] = {
    -1, -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, -1, -1,
    12, 13, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 14, -1, 15
};
static const uint8_t kCached[16] = {
    2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 16, 17, 29, 31
};
static int gpr_host(unsigned g) { return (g < 32U) ? (int)kGprHost[g] : -1; }
/* Guest GPR value into a host register (cached host, wzr, or tmp load). */
static unsigned op_val(a64_buf_t *b, unsigned g, unsigned tmp)
{
    int h;
    if (g == MIPS32_REG_ZERO) return A64_ZR;
    h = gpr_host(g);
    if (h >= 0) return (unsigned)h;
    a64_emit_ldr_imm_w(b, tmp, A64_XCTX, (uint32_t)g * 4U);
    return tmp;
}

/* $0 as an ADD/SUB/CMP operand: plain ZR would read SP. */
static unsigned op_sp(a64_buf_t *b, unsigned g, unsigned tmp)
{
    if (g != MIPS32_REG_ZERO) return op_val(b, g, tmp);
    a64_emit_mov_imm32(b, tmp, 0U);
    return tmp;
}

/* Write host src back to guest GPR ($0 dropped). */
static void put_rd(a64_buf_t *b, unsigned g, unsigned src)
{
    int h;
    if (g == MIPS32_REG_ZERO) return;
    h = gpr_host(g);
    if (h >= 0) { a64_emit_mov_w(b, (unsigned)h, src); return; }
    a64_emit_str_imm_w(b, src, A64_XCTX, (uint32_t)g * 4U);
}

/* rd = rn + simm (32-bit wrap). */
static void add_off(a64_buf_t *b, unsigned rd, unsigned rn, int32_t simm)
{
    if (simm >= 0 && simm <= 4095) {
        a64_emit_add_imm_w(b, false, rd, rn, (uint16_t)simm, 0U);
    } else if (simm < 0 && simm >= -4095) {
        a64_emit_sub_imm_w(b, false, rd, rn, (uint16_t)(-simm), 0U);
    } else {
        a64_emit_mov_imm32(b, A64_TMP1, (uint32_t)simm);
        a64_emit_add_reg_w(b, false, rd, rn, A64_TMP1, A64_SHIFT_LSL, 0U);
    }
}

/* CMP rs, simm / CMP rs, rt (32-bit). */
static void cmp_simm(a64_buf_t *b, unsigned rs, int32_t v)
{
    unsigned ra = op_sp(b, rs, A64_TMP1);
    if (v >= 0 && v <= 4095) {
        a64_emit_sub_imm_w(b, true, A64_ZR, ra, (uint16_t)v, 0U);
    } else if (v < 0 && v >= -4095) {
        a64_emit_add_imm_w(b, true, A64_ZR, ra, (uint16_t)(-v), 0U);
    } else {
        a64_emit_mov_imm32(b, A64_TMP2, (uint32_t)v);
        a64_emit_sub_reg_w(b, true, A64_ZR, ra, A64_TMP2, A64_SHIFT_LSL, 0U);
    }
}
static void br_cmp2(a64_buf_t *b, unsigned rs, unsigned rt)
{
    unsigned ra = op_sp(b, rs, A64_TMP1);
    unsigned rb = op_sp(b, rt, A64_TMP2);
    a64_emit_sub_reg_w(b, true, A64_ZR, ra, rb, A64_SHIFT_LSL, 0U);
}

/* w22 = rs + simm (guest effective address, 32-bit wrap). */
static void emit_ea(a64_buf_t *b, unsigned rs, int32_t simm)
{
    int h = (rs == MIPS32_REG_ZERO) ? -1 : gpr_host(rs);
    if (h < 0 && rs == MIPS32_REG_ZERO)
        a64_emit_mov_imm32(b, A64_ADDR, (uint32_t)simm);
    else {
        if (h < 0) a64_emit_ldr_imm_w(b, A64_ADDR, A64_XCTX, rs * 4U);
        else a64_emit_mov_w(b, A64_ADDR, (unsigned)h);
        add_off(b, A64_ADDR, A64_ADDR, simm);
    }
}

static void emit_prologue(a64_buf_t *b)
{
    unsigned i;
    for (i = 0U; i < 16U; i++)
        a64_emit_ldr_imm_w(b, (unsigned)kGprHost[kCached[i]], A64_XCTX,
                           (uint32_t)kCached[i] * 4U);
}
static void emit_flush(a64_buf_t *b)
{
    unsigned i;
    for (i = 0U; i < 16U; i++)
        a64_emit_str_imm_w(b, (unsigned)kGprHost[kCached[i]], A64_XCTX,
                           (uint32_t)kCached[i] * 4U);
}
/* RC4: flush cached GPRs + record fpc in ctx->pc before a guest-memory access that can host-fault (delivery reads ctx). */
static void emit_sync_pc(a64_buf_t *b, uint32_t fpc)
{
    emit_flush(b);
    a64_emit_mov_imm32(b, A64_TMP1, fpc);
    a64_emit_str_imm_w(b, A64_TMP1, A64_XCTX, MIPS32_CTX_PC_OFFSET);
}
static void emit_pc_imm(a64_buf_t *b, uint32_t pc, uint32_t npc)
{
    a64_emit_mov_imm32(b, A64_TMP1, pc);
    a64_emit_str_imm_w(b, A64_TMP1, A64_XCTX, MIPS32_CTX_PC_OFFSET);
    a64_emit_mov_imm32(b, A64_TMP1, npc);
    a64_emit_str_imm_w(b, A64_TMP1, A64_XCTX, MIPS32_CTX_NEXT_PC_OFFSET);
}
static void emit_reason(a64_buf_t *b, unsigned reason, uint32_t info)
{
    a64_emit_mov_imm32(b, 0U, reason);
    a64_emit_mov_imm32(b, 1U, info);
    a64_emit_ret(b);
}
/* Full exit: flush, pc/npc immediates, w0/w1, ret. */
static void emit_exit_imm(a64_buf_t *b, unsigned reason, uint32_t info,
                          uint32_t pc, uint32_t npc)
{
    emit_flush(b);
    emit_pc_imm(b, pc, npc);
    emit_reason(b, reason, info);
}
/* Indirect exit: target already saved in x23 (JR/JALR). */
static void emit_exit_indirect(a64_buf_t *b)
{
    emit_flush(b);
    a64_emit_str_imm_w(b, 23U, A64_XCTX, MIPS32_CTX_PC_OFFSET);
    a64_emit_add_imm_w(b, false, A64_TMP1, 23U, 4U, 0U);
    a64_emit_str_imm_w(b, A64_TMP1, A64_XCTX, MIPS32_CTX_NEXT_PC_OFFSET);
    a64_emit_mov_imm32(b, 0U, MIPS32_EXIT_BRANCH);
    a64_emit_mov_imm32(b, 1U, 0U);
    a64_emit_ret(b);
}
/* B.cond to a fault exit with info = cur (flags already set). */
static void emit_cond_fault(a64_buf_t *b, unsigned cond, uint32_t cur,
                            uint32_t fpc)
{
    size_t ph_f = a64_emit_b_cond_placeholder(b, cond);
    size_t ph_c = a64_emit_b_cond_placeholder(b, A64_COND_AL);
    a64_patch_b_cond(b, ph_f, b->count);
    emit_exit_imm(b, MIPS32_EXIT_FAULT, cur, fpc, fpc + 4U);
    a64_patch_b_cond(b, ph_c, b->count);
}
/* Alignment guard (fault info = runtime address in w22). */
static void emit_align_fault(a64_buf_t *b, unsigned mask_bits, uint32_t fpc)
{
    size_t ph_f, ph_c;
    a64_emit_ubfm_w(b, A64_TMP1, A64_ADDR, 0U, mask_bits);
    ph_f = a64_emit_cbz_w_placeholder(b, true, A64_TMP1);
    ph_c = a64_emit_b_cond_placeholder(b, A64_COND_AL);
    a64_patch_cbz_w(b, ph_f, b->count);
    emit_flush(b);
    emit_pc_imm(b, fpc, fpc + 4U);
    a64_emit_mov_imm32(b, 0U, MIPS32_EXIT_FAULT);
    a64_emit_mov_w(b, 1U, A64_ADDR);
    a64_emit_ret(b);
    a64_patch_b_cond(b, ph_c, b->count);
}

/* 3-operand ALU into dst (cached host or TMP1) + writeback. */
#define ALU3(fn, rd, ra, rb) \
    do { \
        int h_ = gpr_host(rd); \
        unsigned dst_ = (h_ >= 0) ? (unsigned)h_ : A64_TMP1; \
        a64_emit_##fn(b, false, dst_, ra, rb, A64_SHIFT_LSL, 0U); \
        put_rd(b, rd, dst_); \
    } while (0)
#define ALU3S(fn, rd, ra, rb) \
    do { \
        int h__ = gpr_host(rd); \
        unsigned dst__ = (h__ >= 0) ? (unsigned)h__ : A64_TMP1; \
        a64_emit_##fn(b, dst__, ra, rb, A64_SHIFT_LSL, 0U); \
        put_rd(b, rd, dst__); \
    } while (0)

/* ADDI/ADDU/SLTI/SLTIU/ANDI/ORI/XORI/LUI. -1 declines. */
static int emit_imm_op(a64_buf_t *b, const mips_dec_t *d, uint32_t cur,
                       uint32_t fpc)
{
    unsigned rs = d->rs, rt = d->rt, ra;
    switch (d->op) {
    case MIPS_OP_ADDI:
        ra = op_sp(b, rs, A64_TMP3);
        if (d->simm >= 0 && d->simm <= 4095)
            a64_emit_add_imm_w(b, true, A64_TMP1, ra, (uint16_t)d->simm, 0U);
        else if (d->simm < 0 && d->simm >= -4095)
            a64_emit_sub_imm_w(b, true, A64_TMP1, ra, (uint16_t)(-d->simm),
                               0U);
        else {
            a64_emit_mov_imm32(b, A64_TMP2, (uint32_t)d->simm);
            a64_emit_add_reg_w(b, true, A64_TMP1, ra, A64_TMP2,
                               A64_SHIFT_LSL, 0U);
        }
        emit_cond_fault(b, A64_COND_VS, cur, fpc);
        put_rd(b, rt, A64_TMP1);
        return 0;
    case MIPS_OP_ADDIU:
        ra = op_sp(b, rs, A64_TMP3);
        if (gpr_host(rt) >= 0 && (unsigned)gpr_host(rt) != ra)
            add_off(b, (unsigned)gpr_host(rt), ra, d->simm);
        else { add_off(b, A64_TMP1, ra, d->simm); put_rd(b, rt, A64_TMP1); }
        return 0;
    case MIPS_OP_SLTI:
    case MIPS_OP_SLTIU:
        cmp_simm(b, rs, d->simm);
        a64_emit_mov_imm32(b, A64_TMP1, 1U);
        a64_emit_csel_w(b, A64_TMP1, A64_TMP1, A64_ZR,
                        (d->op == MIPS_OP_SLTI) ? A64_COND_LT
                                                : A64_COND_CC);
        put_rd(b, rt, A64_TMP1);
        return 0;
    case MIPS_OP_ANDI:
    case MIPS_OP_ORI:
    case MIPS_OP_XORI:
        a64_emit_mov_imm32(b, A64_TMP1, d->uimm);
        ra = op_val(b, rs, A64_TMP3);
        if (d->op == MIPS_OP_ANDI)
            ALU3(and_reg_w, rt, ra, A64_TMP1);
        else if (d->op == MIPS_OP_ORI)
            ALU3S(orr_reg_w, rt, ra, A64_TMP1);
        else ALU3S(eor_reg_w, rt, ra, A64_TMP1);
        return 0;
    case MIPS_OP_LUI:
        a64_emit_mov_imm32(b, A64_TMP1, d->uimm << 16);
        put_rd(b, rt, A64_TMP1);
        return 0;
    default:
        return -1;
    }
}

/* Imm shifts (sa == 0 is a move) and variable shifts. */
static int emit_shift(a64_buf_t *b, const mips_dec_t *d)
{
    unsigned sa = d->sa & 31U, dst;
    unsigned type;
    int h;
    if (d->op != MIPS_OP_SPECIAL) return -1;
    switch (d->funct) {
    case MIPS_FUNCT_SLL: case 0x04U: type = A64_SHIFT_LSL; break;
    case MIPS_FUNCT_SRL:
        type = (d->rs == 1U) ? A64_SHIFT_ROR : A64_SHIFT_LSR; break;
    case 0x06U:
        type = (d->sa == 1U) ? A64_SHIFT_ROR : A64_SHIFT_LSR; break;
    case MIPS_FUNCT_SRA: case 0x07U: type = A64_SHIFT_ASR; break;
    default: return -1;
    }
    if (d->funct >= 0x04U) sa = 32U;
    if (sa == 0U) { put_rd(b, d->rd, op_val(b, d->rt, A64_TMP1)); return 0; }
    h = gpr_host(d->rd);
    dst = (h >= 0) ? (unsigned)h : A64_TMP1;
    if (sa > 31U) {
        a64_emit_shift_reg_w(b, dst, op_val(b, d->rt, A64_TMP1),
                             op_val(b, d->rs, A64_TMP2), type);
    } else {
        a64_emit_shift_imm_w(b, dst, op_val(b, d->rt, A64_TMP1), type, sa,
                             false, NULL);
    }
    put_rd(b, d->rd, dst);
    return 0;
}

/* MULT/MULTU/DIV/DIVU/MADD/MADDU/MSUB/MSUBU/MUL/CLZ/CLO + hi/lo moves. */
static int emit_muldiv(a64_buf_t *b, const mips_dec_t *d)
{
    unsigned ra, rb, dst;
    int h;
    if (d->funct >= MIPS_FUNCT_MFHI && d->funct <= MIPS_FUNCT_MTLO) {
        uint32_t off = (d->funct == MIPS_FUNCT_MFHI ||
                        d->funct == MIPS_FUNCT_MTHI)
                           ? MIPS32_CTX_HI_OFFSET
                           : MIPS32_CTX_LO_OFFSET;
        if (d->funct == MIPS_FUNCT_MFHI || d->funct == MIPS_FUNCT_MFLO) {
            a64_emit_ldr_imm_w(b, A64_TMP1, A64_XCTX, off);
            put_rd(b, d->rd, A64_TMP1);
        } else a64_emit_str_imm_w(b, op_val(b, d->rs, A64_TMP1), A64_XCTX,
                                  off);
        return 0;
    }
    ra = op_val(b, d->rs, A64_TMP3);
    rb = op_val(b, d->rt, A64_ADDR);
    h = gpr_host(d->rd);
    dst = (h >= 0) ? (unsigned)h : A64_TMP1;
    switch (d->funct) {
    case MIPS_FUNCT_MULT:
        a64_emit_smaddl_x(b, A64_TMP1, ra, rb, A64_ZR);
        break;
    case MIPS_FUNCT_MULTU:
        a64_emit_umaddl_x(b, A64_TMP1, ra, rb, A64_ZR);
        break;
    case MIPS_FUNCT_DIV:
    case MIPS_FUNCT_DIVU: {
        size_t ph = a64_emit_cbz_w_placeholder(b, false, rb); /* skip div-by-0 */
        if (d->funct == MIPS_FUNCT_DIV)
            a64_emit_sdiv_w(b, A64_TMP1, ra, rb);
        else a64_emit_udiv_w(b, A64_TMP1, ra, rb);
        a64_emit_str_imm_w(b, A64_TMP1, A64_XCTX, MIPS32_CTX_LO_OFFSET);
        a64_emit_msub_w(b, A64_TMP2, A64_TMP1, rb, ra);
        a64_emit_str_imm_w(b, A64_TMP2, A64_XCTX, MIPS32_CTX_HI_OFFSET);
        a64_patch_cbz_w(b, ph, b->count);
        return 0;
    }
    case 0x02U: /* MUL (SPECIAL2): low word only */
        a64_emit_madd_w(b, dst, ra, rb, A64_ZR);
        put_rd(b, d->rd, dst);
        return 0;
    case 0x00U: /* MADD */ case 0x01U: /* MADDU */
    case 0x04U: /* MSUB */ case 0x05U: { /* MSUBU */
        int is_sub = (d->funct == 0x04U || d->funct == 0x05U);
        int is_sgn = (d->funct == 0x00U || d->funct == 0x04U);
        if (is_sgn != 0) a64_emit_smaddl_x(b, A64_TMP1, ra, rb, A64_ZR);
        else a64_emit_umaddl_x(b, A64_TMP1, ra, rb, A64_ZR);
        a64_emit_ubfx_x_to_w(b, A64_TMP2, A64_TMP1, 32U, 32U);
        a64_emit_ldr_imm_w(b, A64_TMP3, A64_XCTX, MIPS32_CTX_LO_OFFSET);
        a64_emit_ldr_imm_w(b, A64_ADDR, A64_XCTX, MIPS32_CTX_HI_OFFSET);
        if (is_sub != 0) {
            a64_emit_sub_reg_w(b, true, A64_TMP3, A64_TMP3, A64_TMP1,
                               A64_SHIFT_LSL, 0U);
            a64_emit_sbc_w(b, false, A64_ADDR, A64_ADDR, A64_TMP2);
        } else {
            a64_emit_add_reg_w(b, true, A64_TMP3, A64_TMP3, A64_TMP1,
                               A64_SHIFT_LSL, 0U);
            a64_emit_adc_w(b, false, A64_ADDR, A64_ADDR, A64_TMP2);
        }
        a64_emit_str_imm_w(b, A64_TMP3, A64_XCTX, MIPS32_CTX_LO_OFFSET);
        a64_emit_str_imm_w(b, A64_ADDR, A64_XCTX, MIPS32_CTX_HI_OFFSET);
        return 0;
    }
    case 0x20U: /* CLZ */ case 0x21U: /* CLO */
        if (d->funct == 0x21U) {
            a64_emit_mvn_reg_w(b, A64_TMP1, ra, A64_SHIFT_LSL, 0U);
            ra = A64_TMP1;
        }
        a64_emit_clz_w(b, dst, ra);
        put_rd(b, d->rd, dst);
        return 0;
    default:
        return -1;
    }
    a64_emit_ubfx_x_to_w(b, A64_TMP2, A64_TMP1, 32U, 32U);
    a64_emit_str_imm_w(b, A64_TMP1, A64_XCTX, MIPS32_CTX_LO_OFFSET);
    a64_emit_str_imm_w(b, A64_TMP2, A64_XCTX, MIPS32_CTX_HI_OFFSET);
    return 0;
}

/* SPECIAL ALU/shifts/MOVZ/MOVN/traps + SYSCALL/BREAK exits. */
static int emit_special(a64_buf_t *b, const mips_dec_t *d, uint32_t cur,
                        uint32_t fpc)
{
    static const uint8_t kCond[8] = { 10U, 2U, 11U, 3U, 0U, 0U, 1U, 0U };
    unsigned ra, rb;
    switch (d->funct) {
    case MIPS_FUNCT_SLL: case MIPS_FUNCT_SRL: case MIPS_FUNCT_SRA:
    case 0x04U: case 0x06U: case 0x07U:
        return emit_shift(b, d);
    case 0x0AU: case 0x0BU: { /* MOVZ / MOVN */
        unsigned cond = (d->funct == 0x0AU) ? A64_COND_EQ : A64_COND_NE;
        unsigned rsr, old;
        int h;
        if (d->rd == MIPS32_REG_ZERO) return 0;
        rsr = op_val(b, d->rs, A64_TMP1);
        a64_emit_sub_imm_w(b, true, A64_ZR, op_sp(b, d->rt, A64_TMP2), 0U,
                           0U);
        h = gpr_host(d->rd);
        if (h >= 0) {
            a64_emit_csel_w(b, (unsigned)h, rsr, (unsigned)h, cond);
            return 0;
        }
        old = op_val(b, d->rd, A64_TMP2);
        a64_emit_csel_w(b, A64_TMP1, rsr, old, cond);
        put_rd(b, d->rd, A64_TMP1);
        return 0;
    }
    case 0x01u: { /* MOVCI cc=(rt>>2)&7 tf=rt&1 */
        unsigned cc = ((unsigned)d->rt >> 2u) & 7u, fcc = (cc == 0u) ? 23u : 24u + cc, rsr = op_val(b, d->rs, A64_TMP1), old;
        int h = 0;
        if (d->rd == MIPS32_REG_ZERO) return 0;
        a64_emit_ldr_imm_w(b, A64_TMP2, A64_XCTX, MIPS32_CTX_FCSR_OFFSET); a64_emit_ubfm_w(b, A64_TMP2, A64_TMP2, fcc, fcc);
        a64_emit_mov_imm32(b, A64_TMP3, (unsigned)d->rt & 1u); a64_emit_sub_reg_w(b, true, A64_ZR, A64_TMP2, A64_TMP3, A64_SHIFT_LSL, 0u);
        h = gpr_host(d->rd); if (h >= 0) { a64_emit_csel_w(b, (unsigned)h, rsr, (unsigned)h, A64_COND_EQ); return 0; }
        old = op_val(b, d->rd, A64_TMP3); a64_emit_csel_w(b, A64_TMP1, rsr, old, A64_COND_EQ); put_rd(b, d->rd, A64_TMP1);
        return 0;
    }
    case MIPS_FUNCT_SYSCALL:
        emit_flush(b);
        emit_pc_imm(b, cur + 4U, cur + 8U);
        emit_reason(b, MIPS32_EXIT_SYSCALL, 0U);
        return 1;
    case MIPS_FUNCT_BREAK: case 0x3FU: /* SDBBP */
        emit_exit_imm(b, MIPS32_EXIT_FAULT, cur, fpc, fpc + 4U);
        return 1;
    case 0x0FU: /* SYNC */
        return 0;
    case MIPS_FUNCT_MFHI: case MIPS_FUNCT_MFLO: case MIPS_FUNCT_MTHI:
    case MIPS_FUNCT_MTLO: case MIPS_FUNCT_MULT: case MIPS_FUNCT_MULTU:
    case MIPS_FUNCT_DIV: case MIPS_FUNCT_DIVU:
        return emit_muldiv(b, d);
    default:
        break;
    }
    ra = op_sp(b, d->rs, A64_TMP3);
    rb = op_sp(b, d->rt, A64_ADDR);
    switch (d->funct) {
    case MIPS_FUNCT_ADD:
        a64_emit_add_reg_w(b, true, A64_TMP1, ra, rb, A64_SHIFT_LSL, 0U);
        emit_cond_fault(b, A64_COND_VS, cur, fpc);
        put_rd(b, d->rd, A64_TMP1);
        return 0;
    case MIPS_FUNCT_ADDU: ALU3(add_reg_w, d->rd, ra, rb); return 0;
    case MIPS_FUNCT_SUB:
        a64_emit_sub_reg_w(b, true, A64_TMP1, ra, rb, A64_SHIFT_LSL, 0U);
        emit_cond_fault(b, A64_COND_VS, cur, fpc);
        put_rd(b, d->rd, A64_TMP1);
        return 0;
    case 0x23U: ALU3(sub_reg_w, d->rd, ra, rb); return 0; /* SUBU */
    case MIPS_FUNCT_AND: ALU3(and_reg_w, d->rd, ra, rb); return 0;
    case MIPS_FUNCT_OR: ALU3S(orr_reg_w, d->rd, ra, rb); return 0;
    case MIPS_FUNCT_XOR: ALU3S(eor_reg_w, d->rd, ra, rb); return 0;
    case MIPS_FUNCT_NOR:
        a64_emit_orr_reg_w(b, A64_TMP1, ra, rb, A64_SHIFT_LSL, 0U);
        a64_emit_mvn_reg_w(b, A64_TMP1, A64_TMP1, A64_SHIFT_LSL, 0U);
        put_rd(b, d->rd, A64_TMP1);
        return 0;
    case MIPS_FUNCT_SLT: case MIPS_FUNCT_SLTU: {
        unsigned cond = (d->funct == MIPS_FUNCT_SLT) ? A64_COND_LT
                                                     : A64_COND_CC;
        a64_emit_sub_reg_w(b, true, A64_ZR, ra, rb, A64_SHIFT_LSL, 0U);
        a64_emit_mov_imm32(b, A64_TMP1, 1U);
        a64_emit_csel_w(b, A64_TMP1, A64_TMP1, A64_ZR, cond);
        put_rd(b, d->rd, A64_TMP1);
        return 0;
    }
    case 0x30U: case 0x31U: case 0x32U: case 0x33U: /* TGE/TLT */
    case 0x34U: case 0x36U: /* TEQ/TNE */
        a64_emit_sub_reg_w(b, true, A64_ZR, ra, rb, A64_SHIFT_LSL, 0U);
        emit_cond_fault(b, kCond[(d->funct - 0x30U) & 7U], cur, fpc);
        return 0;
    default:
        return -1;
    }
}

/* SPECIAL3: EXT/INS/BSHFL(WSBH/SEB/SEH)/RDHWR. */
static int emit_special3(a64_buf_t *b, const mips_dec_t *d)
{
    unsigned lsb, msb, size, src, dst;
    int h;
    switch (d->funct) {
    case 0x00U: /* EXT: size = rd + 1 (rd holds size-1). */
        lsb = d->sa & 31U;
        size = (unsigned)d->rd + 1U;
        if (d->rt == MIPS32_REG_ZERO) return 0;
        src = op_val(b, d->rs, A64_TMP1);
        h = gpr_host(d->rt);
        dst = (h >= 0) ? (unsigned)h : A64_TMP1;
        a64_emit_ubfm_w(b, dst, src, lsb, lsb + size - 1U);
        put_rd(b, d->rt, dst);
        return 0;
    case 0x04U: /* INS */
        lsb = d->sa & 31U;
        msb = d->rd & 31U;
        if (msb < lsb || d->rt == MIPS32_REG_ZERO) return 0;
        size = msb - lsb + 1U;
        src = op_val(b, d->rs, A64_TMP1);
        h = gpr_host(d->rt);
        if (h >= 0) {
            a64_emit_bfm_w(b, (unsigned)h, src, (32U - lsb) & 31U,
                           size - 1U);
            return 0;
        }
        dst = op_val(b, d->rt, A64_TMP2);
        if (dst != A64_TMP1) a64_emit_mov_w(b, A64_TMP1, dst);
        a64_emit_bfm_w(b, A64_TMP1, src, (32U - lsb) & 31U, size - 1U);
        put_rd(b, d->rt, A64_TMP1);
        return 0;
    case 0x20U: /* BSHFL: source is rt (rs is unused, always $0). */
        src = op_val(b, d->rt, A64_TMP1);
        h = gpr_host(d->rd);
        dst = (h >= 0) ? (unsigned)h : A64_TMP1;
        if (d->sa == 2U) a64_emit_rev16_w(b, dst, src);
        else if (d->sa == 16U) a64_emit_sbfm_w(b, dst, src, 0U, 7U);
        else if (d->sa == 24U) a64_emit_sbfm_w(b, dst, src, 0U, 15U);
        else return -1;
        put_rd(b, d->rd, dst);
        return 0;
    case 0x3BU: /* RDHWR */
        if (d->rd != MIPS32_RDHWR_ULR) return -1;
        a64_emit_ldr_imm_w(b, A64_TMP1, A64_XCTX, MIPS32_CTX_ULR_OFFSET);
        put_rd(b, d->rt, A64_TMP1);
        return 0;
    default:
        return -1;
    }
}

/* REGIMM traps (fault shape mirrors SPECIAL traps), SYNCI NOP. */
static int emit_regimm(a64_buf_t *b, const mips_dec_t *d, uint32_t cur,
                       uint32_t fpc)
{
    static const uint8_t kCond[8] = { 10U, 2U, 11U, 12U, 13U, 0U, 0U, 1U };
    unsigned idx;
    switch (d->rt) {
    case 0x08U: idx = 0U; break; /* TGEI */
    case 0x09U: idx = 1U; break; /* TGEIU */
    case 0x0AU: idx = 2U; break; /* TLTI */
    case 0x0BU: idx = 3U; break; /* TLTIU */
    case 0x0CU: idx = 4U; break; /* TEQI */
    case 0x0EU: idx = 7U; break; /* TNEI */
    case 0x1FU: return 0; /* SYNCI */
    default: return -1;
    }
    cmp_simm(b, d->rs, d->simm);
    emit_cond_fault(b, kCond[idx], cur, fpc);
    return 0;
}

/* COP0 MFC0/DMFC0 ulr alias (rd 4, sel 2); everything else declines. */
static int emit_cop0(a64_buf_t *b, const mips_dec_t *d)
{
    if ((d->rs == 0U || d->rs == 1U) && d->rd == 4U && (d->funct & 7U) == 2U) {
        a64_emit_ldr_imm_w(b, A64_TMP1, A64_XCTX, MIPS32_CTX_ULR_OFFSET);
        put_rd(b, d->rt, A64_TMP1);
        return 0;
    }
    return -1;
}

/* Aligned LB/LH/LW/LBU/LHU/SB/SH/SW fast path (EA already in w22). */
static void emit_mem_aligned(a64_buf_t *b, const mips_dec_t *d,
                             uint32_t fpc, int be)
{
    unsigned rt = d->rt, v, dst;
    emit_sync_pc(b, fpc);
    int h = gpr_host(rt);
    dst = (h >= 0) ? (unsigned)h : A64_TMP1;
    switch (d->op) {
    case MIPS_OP_LB: case MIPS_OP_LBU:
        if (d->op == MIPS_OP_LB) a64_emit_guest_ldrsb_w(b, dst, A64_ADDR);
        else a64_emit_guest_ldrb_w(b, dst, A64_ADDR);
        put_rd(b, rt, dst);
        return;
    case MIPS_OP_LH: case MIPS_OP_LHU:
        emit_align_fault(b, 0U, fpc);
        a64_emit_guest_ldrh_w(b, dst, A64_ADDR);
        if (be != 0) a64_emit_rev16_w(b, dst, dst);
        if (d->op == MIPS_OP_LH) a64_emit_sbfm_w(b, dst, dst, 0U, 15U);
        put_rd(b, rt, dst);
        return;
    case MIPS_OP_LW:
        emit_align_fault(b, 1U, fpc);
        a64_emit_guest_ldr_w(b, dst, A64_ADDR);
        if (be != 0) a64_emit_rev_w(b, dst, dst);
        put_rd(b, rt, dst);
        return;
    case MIPS_OP_SB:
        a64_emit_guest_strb_w(b, op_val(b, rt, A64_TMP1), A64_ADDR);
        return;
    case MIPS_OP_SH: case MIPS_OP_SW:
        v = op_val(b, rt, A64_TMP2); /* TMP2: the check below clobbers TMP1. */
        emit_align_fault(b, (d->op == MIPS_OP_SH) ? 0U : 1U, fpc);
        if (be == 0) {
            if (d->op == MIPS_OP_SH)
                a64_emit_guest_strh_w(b, v, A64_ADDR);
            else a64_emit_guest_str_w(b, v, A64_ADDR);
            return;
        }
        if (d->op == MIPS_OP_SH) a64_emit_rev16_w(b, A64_TMP1, v);
        else a64_emit_rev_w(b, A64_TMP1, v);
        if (d->op == MIPS_OP_SH) a64_emit_guest_strh_w(b, A64_TMP1, A64_ADDR);
        else a64_emit_guest_str_w(b, A64_TMP1, A64_ADDR);
        return;
    default:
        break;
    }
}

/* E05 byte position (0 = LSB) of memory byte i for the k-th offset. */
static unsigned merge_pos(unsigned op, int be, unsigned i, unsigned k)
{
    if (op == MIPS_OP_LWL || op == MIPS_OP_SWL)
        return (be != 0) ? (3U - (i - k)) : (3U - k + i);
    return (be != 0) ? (k - i) : (i - k);
}

/* LWL/LWR/SWL/SWR: 4-way k dispatch, straight-line byte paths (E05). */
static void emit_mem_unaligned(a64_buf_t *b, const mips_dec_t *d, uint32_t fpc, int be)
{
    unsigned rt = d->rt, lo, hi, i, k, o;
    emit_sync_pc(b, fpc);
    int is_load = (d->op == MIPS_OP_LWL || d->op == MIPS_OP_LWR);
    int left = (d->op == MIPS_OP_LWL || d->op == MIPS_OP_SWL);
    size_t ph_cbz[3], ph_end[3];
    a64_emit_ubfm_w(b, A64_TMP1, A64_ADDR, 0U, 1U);
    a64_emit_shift_imm_w(b, A64_TMP3, A64_ADDR, A64_SHIFT_LSR, 2U, false,
                         NULL);
    a64_emit_shift_imm_w(b, A64_TMP3, A64_TMP3, A64_SHIFT_LSL, 2U, false,
                         NULL);
    for (k = 0U; k < 3U; k++) {
        ph_cbz[k] = a64_emit_cbz_w_placeholder(b, false, A64_TMP1);
        a64_emit_sub_imm_w(b, true, A64_TMP1, A64_TMP1, 1U, 0U);
    }
    for (o = 0U, k = 3U; o < 4U; o++, k = (o == 1U) ? 0U : k + 1U) { /* k=3,0,1,2: fall-through enters k=3. */
        if (k < 3U) a64_patch_cbz_w(b, ph_cbz[k], b->count);
        if (left != 0) { lo = (be != 0) ? k : 0U; hi = (be != 0) ? 3U : k; }
        else { lo = (be != 0) ? 0U : k; hi = (be != 0) ? k : 3U; }
        if (is_load != 0) {
            unsigned acc = op_val(b, rt, A64_TMP2);
            if (acc != A64_TMP2) a64_emit_mov_w(b, A64_TMP2, acc);
            for (i = lo; i <= hi; i++) {
                unsigned pos = merge_pos(d->op, be, i, k);
                a64_emit_add_imm_w(b, false, A64_ADDR, A64_TMP3, (uint16_t)i,
                                   0U);
                a64_emit_guest_ldrb_w(b, A64_TMP1, A64_ADDR);
                a64_emit_mov_imm32(b, 24U, 0xFFU << (8U * pos));
                a64_emit_bic_reg_w(b, false, A64_TMP2, A64_TMP2, 24U,
                                   A64_SHIFT_LSL, 0U);
                a64_emit_shift_imm_w(b, A64_TMP1, A64_TMP1, A64_SHIFT_LSL,
                                     8U * pos, false, NULL);
                a64_emit_orr_reg_w(b, A64_TMP2, A64_TMP2, A64_TMP1,
                                   A64_SHIFT_LSL, 0U);
            }
            put_rd(b, rt, A64_TMP2);
        } else {
            unsigned v = op_val(b, rt, A64_TMP2);
            for (i = lo; i <= hi; i++) {
                unsigned pos = merge_pos(d->op, be, i, k);
                a64_emit_add_imm_w(b, false, A64_ADDR, A64_TMP3, (uint16_t)i,
                                   0U);
                if (pos == 0U) a64_emit_mov_w(b, A64_TMP1, v);
                else a64_emit_shift_imm_w(b, A64_TMP1, v, A64_SHIFT_LSR,
                                          8U * pos, false, NULL);
                a64_emit_guest_strb_w(b, A64_TMP1, A64_ADDR);
            }
        }
        if (o < 3U) ph_end[o] = a64_emit_b_cond_placeholder(b, A64_COND_AL);
    }
    for (o = 0U; o < 3U; o++) a64_patch_b_cond(b, ph_end[o], b->count);
}

/* LL: aligned load + llbit/lladdr/llval record (align guard syncs). */
static void emit_ll(a64_buf_t *b, const mips_dec_t *d, uint32_t fpc, int be)
{
    emit_align_fault(b, 1U, fpc);
    a64_emit_guest_ldr_w(b, A64_TMP1, A64_ADDR);
    if (be != 0) a64_emit_rev_w(b, A64_TMP1, A64_TMP1);
    put_rd(b, d->rt, A64_TMP1);
    a64_emit_mov_imm32(b, A64_TMP2, 1U);
    a64_emit_strb_imm_w(b, A64_TMP2, A64_XCTX, MIPS32_CTX_LLBIT_OFFSET);
    a64_emit_str_imm_w(b, A64_ADDR, A64_XCTX, MIPS32_CTX_LLADDR_OFFSET);
    a64_emit_str_imm_w(b, A64_TMP1, A64_XCTX, MIPS32_CTX_LLVAL_OFFSET);
}

/* SC: LDXR first (fault side effect even when llbit is clear, matching
 * interp), then llbit/llval check, STXR retry loop in x24/w16. */
static void emit_sc(a64_buf_t *b, const mips_dec_t *d, uint32_t fpc, int be)
{
    unsigned data = op_val(b, d->rt, A64_TMP3);
    size_t ph_fail1, ph_fail2, ph_done, ph_retry, retry_ldxr;
    emit_align_fault(b, 1U, fpc);
    a64_emit_add_uxtw_x(b, 24U, A64_XG, A64_ADDR);
    retry_ldxr = b->count; /* STXR failure clears it: restart at LDXR. */
    a64_emit_ldxr_w(b, A64_TMP1, 24U);
    a64_emit_ldrb_imm_w(b, A64_TMP2, A64_XCTX, MIPS32_CTX_LLBIT_OFFSET);
    ph_fail1 = a64_emit_cbz_w_placeholder(b, false, A64_TMP2);
    if (be != 0) a64_emit_rev_w(b, A64_TMP1, A64_TMP1);
    a64_emit_ldr_imm_w(b, A64_TMP2, A64_XCTX, MIPS32_CTX_LLVAL_OFFSET);
    a64_emit_sub_reg_w(b, true, A64_ZR, A64_TMP1, A64_TMP2, A64_SHIFT_LSL,
                       0U);
    ph_fail2 = a64_emit_b_cond_placeholder(b, A64_COND_NE);
    if (be != 0) {
        a64_emit_rev_w(b, A64_TMP3, data);
        data = A64_TMP3;
    }
    a64_emit_stxr_w(b, A64_TMP1, data, 24U);
    ph_retry = a64_emit_cbz_w_placeholder(b, true, A64_TMP1);
    a64_patch_cbz_w(b, ph_retry, retry_ldxr);
    a64_emit_mov_imm32(b, A64_TMP1, 1U);
    ph_done = a64_emit_b_cond_placeholder(b, A64_COND_AL);
    a64_patch_cbz_w(b, ph_fail1, b->count);
    a64_patch_b_cond(b, ph_fail2, b->count);
    a64_emit_clrex(b);
    a64_emit_mov_imm32(b, A64_TMP1, 0U);
    a64_patch_b_cond(b, ph_done, b->count);
    a64_emit_strb_imm_w(b, A64_ZR, A64_XCTX, MIPS32_CTX_LLBIT_OFFSET);
    put_rd(b, d->rt, A64_TMP1);
}

static int emit_one(a64_buf_t *b, const mips_dec_t *d, uint32_t cur,
                    uint32_t fpc, int be);

/* Control with delay slot (REGIMM 0x12/0x13 included, mirroring interp). */
static int is_ctl(const mips_dec_t *d)
{
    return mips_is_branch(d) != 0 || mips_is_jump(d) != 0 ||
        (d->op == MIPS_OP_REGIMM && (d->rt == 0x12U || d->rt == 0x13U));
}
static void emit_link_imm(a64_buf_t *b, unsigned rd, uint32_t val)
{
    int h;
    if (rd == MIPS32_REG_ZERO) return;
    h = gpr_host(rd);
    if (h >= 0) a64_emit_mov_imm32(b, (unsigned)h, val);
    else { a64_emit_mov_imm32(b, A64_TMP1, val); a64_emit_str_imm_w(b, A64_TMP1, A64_XCTX, rd * 4U); }
}

/* Branch + inline delay slot (flags before link write; x23 holds the indirect target across the slot). */
static void emit_branch(a64_buf_t *b, const mips_dec_t *d,
                        const mips_dec_t *s, uint32_t cur, int be)
{
    uint32_t nottaken = cur + 8U, taken = 0U;
    unsigned cond = A64_COND_AL;
    int indirect = 0, link_rd = -1;
    size_t ph_t;
    switch (d->op) {
    case MIPS_OP_J: case MIPS_OP_JAL:
        taken = ((cur + 4U) & 0xF0000000U) | (d->target << 2);
        if (d->op == MIPS_OP_JAL) link_rd = (int)MIPS32_REG_RA;
        break;
    case MIPS_OP_SPECIAL: /* JR / JALR */
        indirect = 1;
        if (d->funct == MIPS_FUNCT_JALR) link_rd = (int)d->rd;
        break;
    case MIPS_OP_BEQ: case MIPS_OP_BEQL:
        br_cmp2(b, d->rs, d->rt); cond = A64_COND_EQ; break;
    case MIPS_OP_BNE: case MIPS_OP_BNEL:
        br_cmp2(b, d->rs, d->rt); cond = A64_COND_NE; break;
    case MIPS_OP_BLEZ: case MIPS_OP_BLEZL:
        br_cmp2(b, d->rs, MIPS32_REG_ZERO); cond = A64_COND_LE; break;
    case MIPS_OP_BGTZ: case MIPS_OP_BGTZL:
        br_cmp2(b, d->rs, MIPS32_REG_ZERO); cond = A64_COND_GT; break;
    case MIPS_OP_REGIMM:
        br_cmp2(b, d->rs, MIPS32_REG_ZERO);
        switch (d->rt) {
        case 0x00U: case 0x02U: cond = A64_COND_LT; break;
        case 0x01U: case 0x03U: cond = A64_COND_GE; break;
        case 0x10U: case 0x12U: case 0x11U: case 0x13U:
            cond = ((d->rt & 1U) != 0U) ? A64_COND_GE : A64_COND_LT;
            link_rd = (int)MIPS32_REG_RA; break;
        default: break;
        }
        break;
    default:
        break;
    }
    if (d->op != MIPS_OP_J && d->op != MIPS_OP_JAL && d->op != MIPS_OP_SPECIAL)
        taken = cur + 4U + (uint32_t)(d->simm * 4);
    if (indirect != 0) a64_emit_mov_w(b, 23U, op_val(b, d->rs, A64_TMP1));
    if (link_rd >= 0) emit_link_imm(b, (unsigned)link_rd, cur + 8U);
    if (indirect != 0) {
        (void)emit_one(b, s, cur + 4U, cur, be);
        emit_exit_indirect(b);
        return;
    }
    if (cond == A64_COND_AL) {
        (void)emit_one(b, s, cur + 4U, cur, be);
        emit_exit_imm(b, MIPS32_EXIT_BRANCH, 0U, taken, taken + 4U);
        return;
    }
    ph_t = a64_emit_b_cond_placeholder(b, cond);
    if (mips_is_branch_likely(d) == 0 && (d->op != MIPS_OP_REGIMM ||
        (d->rt != 0x12U && d->rt != 0x13U)))
        (void)emit_one(b, s, cur + 4U, cur, be);
    emit_exit_imm(b, MIPS32_EXIT_BRANCH, 0U, nottaken, nottaken + 4U);
    a64_patch_b_cond(b, ph_t, b->count);
    (void)emit_one(b, s, cur + 4U, cur, be);
    emit_exit_imm(b, MIPS32_EXIT_BRANCH, 0U, taken, taken + 4U);
}

/* One straight-line insn: 0 continue, 1 exit, -1 decline. */
static int emit_one(a64_buf_t *b, const mips_dec_t *d, uint32_t cur,
                    uint32_t fpc, int be)
{
    switch (d->op) {
    case MIPS_OP_SPECIAL: return emit_special(b, d, cur, fpc);
    case MIPS_OP_SPECIAL2: return emit_muldiv(b, d);
    case MIPS_OP_SPECIAL3: return emit_special3(b, d);
    case MIPS_OP_REGIMM: return emit_regimm(b, d, cur, fpc);
    case MIPS_OP_ADDI: case MIPS_OP_ADDIU: case MIPS_OP_SLTI:
    case MIPS_OP_SLTIU: case MIPS_OP_ANDI: case MIPS_OP_ORI:
    case MIPS_OP_XORI: case MIPS_OP_LUI: return emit_imm_op(b, d, cur, fpc);
    case MIPS_OP_COP0: return emit_cop0(b, d);
    case MIPS_OP_LB: case MIPS_OP_LH: case MIPS_OP_LW: case MIPS_OP_LBU:
    case MIPS_OP_LHU: case MIPS_OP_SB: case MIPS_OP_SH: case MIPS_OP_SW:
        emit_ea(b, d->rs, d->simm);
        emit_mem_aligned(b, d, fpc, be);
        return 0;
    case MIPS_OP_LWL: case MIPS_OP_LWR: case MIPS_OP_SWL: case MIPS_OP_SWR:
        emit_ea(b, d->rs, d->simm);
        emit_mem_unaligned(b, d, fpc, be);
        return 0;
    case MIPS_OP_LL: case MIPS_OP_SC:
        emit_ea(b, d->rs, d->simm);
        if (d->op == MIPS_OP_LL) emit_ll(b, d, fpc, be);
        else emit_sc(b, d, fpc, be);
        return 0;
    case 0x2FU: case 0x33U: return 0; /* CACHE / PREF */
    default: return -1;
    }
}

/* Delay-slot predicate: only inline classes with no exit of their own. */
static int slot_ok(const mips_dec_t *d)
{
    switch (d->op) {
    case MIPS_OP_SPECIAL: {
        unsigned f = d->funct;
        if (f == MIPS_FUNCT_JR || f == MIPS_FUNCT_JALR ||
            f == MIPS_FUNCT_SYSCALL || f == MIPS_FUNCT_BREAK) return 0;
        if (f <= 0x07U) return f != 0x01U && f != 0x05U;
        if (f <= 0x13U) return f >= 0x0AU && f != 0x0CU && f != 0x0DU &&
            f != 0x0EU;
        if (f <= 0x1BU) return f >= 0x18U;
        return (f >= 0x20U && f <= 0x27U) || f == 0x2AU || f == 0x2BU;
    }
    case MIPS_OP_SPECIAL2: {
        unsigned f = d->funct;
        return f <= 0x02U || f == 0x04U || f == 0x05U || f == 0x20U ||
            f == 0x21U;
    }
    case MIPS_OP_SPECIAL3: {
        unsigned f = d->funct;
        return f == 0x00U || f == 0x04U ||
            (f == 0x20U && (d->sa == 2U || d->sa == 16U || d->sa == 24U)) ||
            (f == 0x3BU && d->rd == MIPS32_RDHWR_ULR);
    }
    case MIPS_OP_REGIMM: return d->rt == 0x1FU;
    case MIPS_OP_ADDI: case MIPS_OP_ADDIU: case MIPS_OP_SLTI:
    case MIPS_OP_SLTIU: case MIPS_OP_ANDI: case MIPS_OP_ORI:
    case MIPS_OP_XORI: case MIPS_OP_LUI: case MIPS_OP_LB: case MIPS_OP_LH:
    case MIPS_OP_LW: case MIPS_OP_LBU: case MIPS_OP_LHU: case MIPS_OP_SB:
    case MIPS_OP_SH: case MIPS_OP_SW: case MIPS_OP_LWL: case MIPS_OP_LWR:
    case MIPS_OP_SWL: case MIPS_OP_SWR: case MIPS_OP_LL: case MIPS_OP_SC:
    case 0x2FU: case 0x33U: return 1;
    default: return 0;
    }
}

/* Frozen contract: insns[0..count) at guest pc into out[0..cap); a mid-block decline exits EXIT_UNDEF with *out_end past the prefix. */
int dbt_emit_int(mips32_ctx_t *ctx, uint32_t pc, const mips_dec_t *insns,
                 unsigned count, uint8_t *out, size_t cap,
                 size_t *out_len, uint32_t *out_end)
{
    a64_buf_t b;
    int be;
    unsigned i;
    uint32_t cur;
    if (ctx == NULL || insns == NULL || out == NULL || out_len == NULL ||
        out_end == NULL || count == 0U || count > MIPS32_DBT_MAX_INSNS ||
        cap < 4U || (cap & 3U) != 0U)
        return -1;
    be = mips_is_be(ctx);
    a64_buf_init(&b, (uint32_t *)out, cap / 4U);
    emit_prologue(&b);
    cur = pc;
    for (i = 0U; i < count; i++) {
        const mips_dec_t *d = &insns[i];
        int rc;
        if (d->op == MIPS_OP_COP1) {
            int dbt_emit_fp(a64_buf_t *, const mips_dec_t *, uint32_t, uint32_t, int, int, int);
            if (!dbt_emit_fp(&b, d, cur, cur, be, ctx->fr_mode, ctx->nan2008)) { cur += 4U; continue; }
        }
        if (is_ctl(d) != 0) {
            if (d->op == MIPS_OP_COP1 || i + 1U >= count || slot_ok(&insns[i + 1]) == 0) {
                emit_exit_imm(&b, MIPS32_EXIT_SINGLE_STEP, 0U, cur, cur + 4U);
                *out_end = cur; break;
            }
            emit_branch(&b, d, &insns[i + 1], cur, be);
            *out_end = cur + 8U;
            break;
        }
        rc = emit_one(&b, d, cur, cur, be);
        if (rc == 0) { cur += 4U; continue; }
        if (rc < 0) emit_exit_imm(&b, MIPS32_EXIT_UNDEF, 0U, cur, cur + 4U);
        *out_end = cur + (rc < 0 ? 0U : 4U);
        break;
    }
    if (b.overflow) { *out_len = 0U; *out_end = pc; return -1; }
    if (i >= count) {
        emit_exit_imm(&b, MIPS32_EXIT_BRANCH, 0U, cur, cur + 4U);
        *out_end = cur;
    }
    if (b.overflow) { *out_len = 0U; *out_end = pc; return -1; }
    *out_len = b.count * 4U;
    return 0;
}
