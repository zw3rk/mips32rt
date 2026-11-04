/*
 * src/dbt/emit_fp_cvt.c — AArch64 FPU conversions (Wave P lane P4 split).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Float<->integer conversions for the COP1 emitter: CVT.W/CVT.L and
 * ROUND/TRUNC/CEIL/FLOOR from S/D (fp_to_int_op), CVT.S/CVT.D between
 * precisions (fp_cvt_float_op), and CVT.S/CVT.D from W/L (fp_from_int_op).
 * Split from src/dbt/emit_fp.c (line-limit split, no behavior change);
 * shared helpers live in src/dbt/emit_fp.c via dbt/emit_fp_priv.h.
 */

#include <stddef.h>
#include <stdint.h>

#include "mips32rt.h"
#include "rt32/a64_emit.h"
#include "interp/decode.h"
#include "dbt/emit_fp_priv.h"

/* Wave P13: single-precision FPR writes invalidate the cached copies
 * they supersede (shared fpr_slot() from emit_fp_priv.h, so lookup
 * and invalidation can never drift apart). */
void fp_invalidate_single(a64_buf_t *b, unsigned fs)
{
    unsigned pair = (b->fr_mode == 0U) ? (fs ^ 1U) : fs;
    unsigned s0 = fpr_slot(fs);
    unsigned s1 = fpr_slot(pair);
    uint32_t m = (1U << fs) | (1U << pair);

    if ((((b->fpr_cache_valid >> s0) & 1U) != 0U) &&
        b->fpr_cache_reg[s0] == (uint8_t)fs) {
        b->fpr_cache_valid &= (uint16_t)~(1U << s0);
    }
    if ((((b->fpr_cache_valid >> s1) & 1U) != 0U) &&
        b->fpr_cache_reg[s1] == (uint8_t)pair) {
        b->fpr_cache_valid &= (uint16_t)~(1U << s1);
    }
    b->fpr_non_nan &= ~m;
    b->fpr_no_snan &= ~m;
}

/* Store a W integer conversion result to an FPR low half (a value).
 * The raw bits supersede any cached FP copy of the lane (and its
 * pair double), so invalidate before returning. */
void fp_store_w(a64_buf_t *b, unsigned wsrc, uint32_t off, int be)
{
    (void)be;
    a64_emit_str_imm_w(b, wsrc, A64_XCTX, off);
    fp_invalidate_single(b, (off - MIPS32_CTX_FPR_OFFSET) >> 3U);
}

/* Raw 64-bit ctx loads/stores (imm12 = byte_off / 8). */
static void fp_mem_d(a64_buf_t *b, unsigned is_store, unsigned vt,
                     unsigned rn_x, uint32_t byte_off)
{
    uint32_t base = (is_store != 0U) ? 0xFD000000U : 0xFD400000U;

    a64_emit(b, base | (((byte_off >> 3) & 0xFFFU) << 10) |
                    ((rn_x & 31U) << 5) | (vt & 31U));
}

/* S-reg i is the low 32 bits of fpr[i] (upper half preserved by
 * stores); D-reg fs is the full 64-bit fpr[fs] slot in FR=1 or the
 * even/odd low-half pair in FR=0.  Wave P12: 16-slot write-through
 * cache in v16..v31 (fpr_slot() from emit_fp_priv.h, creg = 16+slot). */
void fp_ld(a64_buf_t *b, unsigned vd, unsigned fs, int be,
           unsigned is_d)
{
    unsigned slot = fpr_slot(fs), creg = 16U + slot;
    unsigned want_d = (is_d != 0U) ? 1U : 0U;

    (void)be; /* FPR lanes hold values, not guest-ordered bytes. */
    if ((((b->fpr_cache_valid >> slot) & 1U) != 0U) &&
        b->fpr_cache_reg[slot] == (uint8_t)fs &&
        (((b->fpr_cache_is_d >> slot) & 1U) == want_d)) {
        if (vd != creg) {
            fp_emit1(b, want_d, 0U, 0x10U, vd, creg);
        }
        return;
    }
    b->fpr_non_nan &= ~(1U << fs);
    b->fpr_no_snan &= ~(1U << fs);
    if (is_d == 0U) {
        uint32_t off = fp_slot(fs);
        a64_emit(b, 0xBD400000U | (((off >> 2U) & 0xFFFU) << 10) |
            ((A64_XCTX & 31U) << 5) | (creg & 31U));
    } else if (b->fr_mode == 0U) {
        a64_emit_ldr_imm_w(b, A64_TMP1, A64_XCTX, fp_slot(fs & ~1U));
        a64_emit_ldr_imm_w(b, A64_TMP2, A64_XCTX, fp_slot(fs | 1U));
        a64_emit_bfi_x(b, A64_TMP1, A64_TMP2, 32U, 32U);
        fp_cvt(b, 1U, 1U, 0x07U, creg, A64_TMP1);
    } else {
        fp_mem_d(b, 0U, creg, A64_XCTX, fp_slot(fs));
    }
    b->fpr_cache_valid |= (uint16_t)(1U << slot);
    b->fpr_cache_reg[slot] = (uint8_t)fs;
    if (is_d != 0U) { b->fpr_cache_is_d |= (uint16_t)(1U << slot); }
    else { b->fpr_cache_is_d &= (uint16_t)~(1U << slot); }
    if (vd != creg) {
        fp_emit1(b, want_d, 0U, 0x10U, vd, creg);
    }
}

void fp_st(a64_buf_t *b, unsigned vd, unsigned fs, int be,
           unsigned is_d)
{
    unsigned slot = fpr_slot(fs), creg = 16U + slot;
    unsigned want_d = (is_d != 0U) ? 1U : 0U;

    (void)be; /* FPR lanes hold values, not guest-ordered bytes. */
    fp_invalidate_single(b, fs);
    if (is_d == 0U) {
        uint32_t off = fp_slot(fs);
        a64_emit(b, 0xBD000000U | (((off >> 2U) & 0xFFFU) << 10) |
            ((A64_XCTX & 31U) << 5) | (vd & 31U));
    } else if (b->fr_mode == 0U) {
        fp_cvt(b, 1U, 1U, 0x06U, A64_TMP1, vd);
        a64_emit_str_imm_w(b, A64_TMP1, A64_XCTX, fp_slot(fs & ~1U));
        a64_emit_ubfx_x_to_w(b, A64_TMP2, A64_TMP1, 32U, 32U);
        a64_emit_str_imm_w(b, A64_TMP2, A64_XCTX, fp_slot(fs | 1U));
    } else {
        fp_mem_d(b, 1U, vd, A64_XCTX, fp_slot(fs));
    }
    if (vd != creg) {
        fp_emit1(b, want_d, 0U, 0x10U, creg, vd);
    }
    b->fpr_cache_valid |= (uint16_t)(1U << slot);
    b->fpr_cache_reg[slot] = (uint8_t)fs;
    if (is_d != 0U) { b->fpr_cache_is_d |= (uint16_t)(1U << slot); }
    else { b->fpr_cache_is_d &= (uint16_t)~(1U << slot); }
}

/* CVT.W/CVT.L and ROUND/TRUNC/CEIL/FLOOR from S/D. */
int fp_to_int_op(a64_buf_t *b, const mips_dec_t *d, uint32_t cur,
                 int be, int nan2008)
{
    unsigned fs = d->rd;
    unsigned fd = d->sa;
    unsigned is_d = (d->rs == FP_FMT_D) ? 1U : 0U;
    unsigned is_l = (d->funct == FP_FUNCT_CVT_L) ? 1U : 0U;

    if (fs >= 32U || fd >= 32U) {
        return -1;
    }
    if (d->rs != FP_FMT_S && d->rs != FP_FMT_D) {
        return -1;
    }
    if (b->fr_mode == 0U &&
        ((is_d != 0U && (fs & 1U) != 0U) || (is_l != 0U && (fd & 1U) != 0U))) {
        return -1;
    }
    fp_ld(b, 0U, fs, be, is_d);
    a64_emit_ldr_imm_w(b, 21U, A64_XCTX, MIPS32_CTX_FCSR_OFFSET);
    fp_fpsr_clear(b);
    /* Shelter unrounded V0 in V3 so FCMP V3,V0 below reconstructs
     * Inexact (M32-R4-4, M32-R7-15) across all rounding modes. */
    fp_emit1(b, is_d, 0x00U, 0x10U, 3U, 0U);
    if (d->funct == FP_FUNCT_ROUND) {
        fp_emit1(b, is_d, 0x04U, 0x10U, 0U, 0U);
    } else if (d->funct == FP_FUNCT_TRUNC) {
        fp_emit1(b, is_d, 0x05U, 0x30U, 0U, 0U);
    } else if (d->funct == FP_FUNCT_CEIL) {
        fp_emit1(b, is_d, 0x04U, 0x30U, 0U, 0U);
    } else if (d->funct == FP_FUNCT_FLOOR) {
        fp_emit1(b, is_d, 0x05U, 0x10U, 0U, 0U);
    } else if (d->funct == FP_FUNCT_CVT_W || d->funct == FP_FUNCT_CVT_L) {
        size_t ph_bit1, ph_bit0, ph_d0, ph_d1, ph_d2;

        a64_emit_ubfm_w(b, 23U, 21U, 1U, 1U);
        ph_bit1 = a64_emit_cbz_w_placeholder(b, false, 23U);
        a64_emit_ubfm_w(b, 22U, 21U, 0U, 0U);
        ph_bit0 = a64_emit_cbz_w_placeholder(b, false, 22U);
        fp_emit1(b, is_d, 0x05U, 0x10U, 0U, 0U);
        ph_d0 = a64_emit_b_cond_placeholder(b, A64_COND_AL);
        a64_patch_cbz_w(b, ph_bit0, b->count);
        fp_emit1(b, is_d, 0x04U, 0x30U, 0U, 0U);
        ph_d1 = a64_emit_b_cond_placeholder(b, A64_COND_AL);
        a64_patch_cbz_w(b, ph_bit1, b->count);
        a64_emit_ubfm_w(b, 22U, 21U, 0U, 0U);
        ph_bit0 = a64_emit_cbz_w_placeholder(b, false, 22U);
        fp_emit1(b, is_d, 0x05U, 0x30U, 0U, 0U);
        ph_d2 = a64_emit_b_cond_placeholder(b, A64_COND_AL);
        a64_patch_cbz_w(b, ph_bit0, b->count);
        fp_emit1(b, is_d, 0x04U, 0x10U, 0U, 0U);
        a64_patch_b_cond(b, ph_d0, b->count);
        a64_patch_b_cond(b, ph_d1, b->count);
        a64_patch_b_cond(b, ph_d2, b->count);
    } else {
        return -1;
    }
    /* is_nan in FP_STICKY: exponent all-ones and nonzero fraction. */
    if (is_d == 0U) {
        a64_emit_fmov_s_to_w(b, A64_TMP1, 0U);
        a64_emit_ubfm_w(b, A64_TMP2, A64_TMP1, 23U, 30U);
        a64_emit_mov_imm32(b, 22U, 0xFFU);
        a64_emit_sub_reg_w(b, true, A64_ZR, A64_TMP2, 22U, A64_SHIFT_LSL,
                           0U);
        a64_emit_mov_imm32(b, 22U, 1U);
        a64_emit_csel_w(b, FP_STICKY, 22U, A64_ZR, A64_COND_EQ);
        a64_emit_ubfm_w(b, A64_TMP2, A64_TMP1, 0U, 22U);
        a64_emit_and_reg_w(b, true, A64_ZR, A64_TMP2, A64_TMP2,
                           A64_SHIFT_LSL, 0U);
        a64_emit_csel_w(b, A64_TMP1, 22U, A64_ZR, A64_COND_NE);
        a64_emit_and_reg_w(b, false, FP_STICKY, FP_STICKY, A64_TMP1, A64_SHIFT_LSL,
                           0U);
    } else {
        fp_cvt(b, 1U, 1U, 0x06U, 22U, 0U);
        a64_emit_ubfx_x_to_w(b, A64_TMP2, 22U, 32U, 32U);
        a64_emit_ubfm_w(b, A64_TMP1, A64_TMP2, 20U, 30U);
        a64_emit_mov_imm32(b, 23U, 0x7FFU);
        a64_emit_sub_reg_w(b, true, A64_ZR, A64_TMP1, 23U, A64_SHIFT_LSL,
                           0U);
        a64_emit_mov_imm32(b, 23U, 1U);
        a64_emit_csel_w(b, FP_STICKY, 23U, A64_ZR, A64_COND_EQ);
        a64_emit_mov_w(b, A64_TMP1, 22U);
        a64_emit_ubfm_w(b, 23U, A64_TMP2, 0U, 19U);
        a64_emit_orr_reg_w(b, 23U, 23U, A64_TMP1, A64_SHIFT_LSL, 0U);
        a64_emit_and_reg_w(b, true, A64_ZR, 23U, 23U, A64_SHIFT_LSL, 0U);
        a64_emit_mov_imm32(b, A64_TMP1, 1U);
        a64_emit_csel_w(b, 23U, A64_TMP1, A64_ZR, A64_COND_NE);
        a64_emit_and_reg_w(b, false, FP_STICKY, FP_STICKY, 23U, A64_SHIFT_LSL, 0U);
    }
    if (is_l == 0U) {
        if (is_d == 0U) {
            a64_emit_fcvtzs_s_to_w(b, A64_TMP1, 0U);
        } else {
            a64_emit_fcvtzs_d_to_w(b, A64_TMP1, 0U);
        }
    } else {
        fp_cvt(b, 1U, is_d, 0x18U, 22U, 0U);
        a64_emit_mov_w(b, A64_TMP1, 22U);
        a64_emit_ubfx_x_to_w(b, A64_TMP2, 22U, 32U, 32U);
    }
    fp_cmp(b, is_d, 3U, 0U);
    fp_fpsr_read(b, 22U);
    {
        size_t ph_vs = a64_emit_b_cond_placeholder(b, A64_COND_VS);
        size_t ph_eq = a64_emit_b_cond_placeholder(b, A64_COND_EQ);
        size_t ph_iv;

        a64_emit_ubfm_w(b, 23U, 22U, 0U, 0U);
        ph_iv = a64_emit_cbz_w_placeholder(b, true, 23U);
        a64_emit_mov_imm32(b, 23U, 0x10U);
        a64_emit_orr_reg_w(b, 22U, 22U, 23U, A64_SHIFT_LSL, 0U);
        a64_patch_cbz_w(b, ph_iv, b->count);
        a64_patch_b_cond(b, ph_vs, b->count);
        a64_patch_b_cond(b, ph_eq, b->count);
    }
    if (nan2008 == 0) {
        /* Legacy NaN selects INTMAX; negative overflow saturates (M32-R7-17). */
        a64_emit_and_reg_w(b, true, A64_ZR, FP_STICKY, FP_STICKY,
                           A64_SHIFT_LSL, 0U);
        if (is_l == 0U) {
            a64_emit_mov_imm32(b, A64_TMP2, 0x7FFFFFFFU);
            a64_emit_csel_w(b, A64_TMP1, A64_TMP2, A64_TMP1, A64_COND_NE);
            a64_emit_mov_imm32(b, A64_TMP2, 0x80000000U);
            a64_emit_sub_reg_w(b, true, A64_ZR, A64_TMP1, A64_TMP2,
                               A64_SHIFT_LSL, 0U);
            a64_emit_mov_imm32(b, A64_TMP2, 1U);
            a64_emit_csel_w(b, A64_TMP2, A64_TMP2, A64_ZR, A64_COND_EQ);
            a64_emit_ubfm_w(b, 23U, 22U, 0U, 0U);
            a64_emit_and_reg_w(b, false, A64_TMP2, A64_TMP2, 23U,
                               A64_SHIFT_LSL, 0U);
            a64_emit_and_reg_w(b, true, A64_ZR, A64_TMP2, A64_TMP2,
                               A64_SHIFT_LSL, 0U);
            a64_emit_mov_imm32(b, A64_TMP2, 0x7FFFFFFFU);
            a64_emit_csel_w(b, A64_TMP1, A64_TMP2, A64_TMP1, A64_COND_NE);
        } else {
            a64_emit_mov_imm32(b, 23U, 0xFFFFFFFFU);
            a64_emit_csel_w(b, A64_TMP1, 23U, A64_TMP1, A64_COND_NE);
            a64_emit_mov_imm32(b, 23U, 0x7FFFFFFFU);
            a64_emit_csel_w(b, A64_TMP2, 23U, A64_TMP2, A64_COND_NE);
            a64_emit_mov_imm32(b, 23U, 0x80000000U);
            a64_emit_sub_reg_w(b, true, A64_ZR, A64_TMP2, 23U, A64_SHIFT_LSL,
                               0U);
            a64_emit_mov_imm32(b, 24U, 1U);
            a64_emit_csel_w(b, 24U, 24U, A64_ZR, A64_COND_EQ);
            a64_emit_and_reg_w(b, true, A64_ZR, A64_TMP1, A64_TMP1,
                               A64_SHIFT_LSL, 0U);
            a64_emit_csel_w(b, 24U, 24U, A64_ZR, A64_COND_EQ);
            a64_emit_ubfm_w(b, 23U, 22U, 0U, 0U);
            a64_emit_and_reg_w(b, false, 24U, 24U, 23U,
                               A64_SHIFT_LSL, 0U);
            a64_emit_and_reg_w(b, true, A64_ZR, 24U, 24U,
                               A64_SHIFT_LSL, 0U);
            a64_emit_mov_imm32(b, 23U, 0xFFFFFFFFU);
            a64_emit_csel_w(b, A64_TMP1, 23U, A64_TMP1, A64_COND_NE);
            a64_emit_mov_imm32(b, 23U, 0x7FFFFFFFU);
            a64_emit_csel_w(b, A64_TMP2, 23U, A64_TMP2, A64_COND_NE);
        }
    }
    a64_emit_mov_w(b, 23U, A64_TMP1);
    if (is_l != 0U) {
        a64_emit_mov_w(b, 24U, A64_TMP2);
    }
    a64_emit_orr_reg_w(b, 22U, 22U, FP_STICKY, A64_SHIFT_LSL, 0U);
    fp_finish(b, 22U, cur);
    fp_store_w(b, 23U, fp_slot(fd), be);
    if (is_l != 0U) {
        uint32_t hi_off = (b->fr_mode == 0U) ? fp_slot(fd | 1U)
                                             : (fp_slot(fd) + 4U);
        fp_store_w(b, 24U, hi_off, be);
    }
    return 0;
}

/* CVT.S.D / CVT.D.S: exact FCVT, legacy canonicalization both sides. */
int fp_cvt_float_op(a64_buf_t *b, const mips_dec_t *d, uint32_t cur,
                    int be, int nan2008, unsigned is_d)
{
    unsigned fs = d->rd;
    unsigned fd = d->sa;
    unsigned src_nn;

    if (fs >= 32U || fd >= 32U) {
        return -1;
    }
    if (b->fr_mode == 0U &&
        (((is_d == 0U) ? (fs & 1U) : (fd & 1U)) != 0U)) {
        return -1;
    }
    fp_ld(b, 0U, fs, be, is_d ^ 1U);
    src_nn = (b->fpr_non_nan >> fs) & 1U;
    a64_emit_mov_imm32(b, FP_STICKY, 0U);
    if (nan2008 == 0) {
        fp_quiet_reg(b, 0U, fs, FP_STICKY, is_d ^ 1U);
    }
    a64_emit_ldr_imm_w(b, 21U, A64_XCTX, MIPS32_CTX_FCSR_OFFSET);
    fp_fpcr_sync(b);
    fp_fpsr_clear(b);
    if (is_d == 0U) {
        a64_emit_fcvt_d_to_s(b, 2U, 0U);
    } else {
        a64_emit_fcvt_s_to_d(b, 2U, 0U);
    }
    fp_fpsr_read(b, 22U);
    fp_fpcr_restore(b);
    a64_emit_orr_reg_w(b, 24U, 22U, FP_STICKY, A64_SHIFT_LSL, 0U);
    if (nan2008 == 0) {
        size_t ph_can;

        fp_fix(b, 2U, is_d);
        ph_can = a64_emit_cbz_w_placeholder(b, false, FP_STICKY);
        if (is_d == 0u) {
            a64_emit_mov_imm32(b, A64_TMP1, 0x7FBFFFFFu);
            a64_emit_fmov_w_to_s(b, 2U, A64_TMP1);
        } else {
            a64_emit_mov_imm32(b, A64_TMP2, 0x7FF7FFFFu);
            a64_emit_mov_imm32(b, A64_TMP1, 0xFFFFFFFFu);
            a64_emit_mov_w(b, 23U, A64_TMP2);
            a64_emit_mov_w(b, 22U, A64_TMP1);
            a64_emit_bfi_x(b, 22U, 23U, 32U, 32U);
            fp_cvt(b, 1U, 1U, 0x07U, 2U, 22U);
        }
        a64_patch_cbz_w(b, ph_can, b->count);
    }
    fp_finish(b, 24U, cur);
    fp_st(b, 2U, fd, be, is_d);
    b->fpr_no_snan |= (1U << fd);
    if (src_nn != 0U) {
        b->fpr_non_nan |= (1U << fd);
    }
    return 0;
}

/* CVT.S/D from W/L: architectural source is FPR fs (d->rd), not a GPR. */
int fp_from_int_op(a64_buf_t *b, const mips_dec_t *d, uint32_t cur,
                   int be, unsigned is_d)
{
    unsigned fs = d->rd;
    unsigned fd = d->sa;
    unsigned is_l = (d->rs == FP_FMT_L) ? 1U : 0U;

    if (fs >= 32U || fd >= 32U) {
        return -1;
    }
    if (d->rs != FP_FMT_W && d->rs != FP_FMT_L) {
        return -1;
    }
    if (b->fr_mode == 0U &&
        ((is_l != 0U && (fs & 1U) != 0U) || (is_d != 0U && (fd & 1U) != 0U))) {
        return -1;
    }
    a64_emit_ldr_imm_w(b, 21U, A64_XCTX, MIPS32_CTX_FCSR_OFFSET);
    fp_fpcr_sync(b);
    fp_fpsr_clear(b);
    if (is_l == 0U) {
        a64_emit_ldr_imm_w(b, A64_TMP1, A64_XCTX, fp_slot(fs));
        if (is_d == 0U) {
            a64_emit_scvtf_w_to_s(b, 0U, A64_TMP1);
        } else {
            a64_emit_scvtf_w_to_d(b, 0U, A64_TMP1);
        }
    } else {
        if (b->fr_mode == 0U) {
            a64_emit_ldr_imm_w(b, A64_TMP1, A64_XCTX, fp_slot(fs & ~1U));
            a64_emit_ldr_imm_w(b, A64_TMP2, A64_XCTX, fp_slot(fs | 1U));
            a64_emit_bfi_x(b, A64_TMP1, A64_TMP2, 32U, 32U);
        } else {
            a64_emit_ldr_imm_x(b, A64_TMP1, A64_XCTX, fp_slot(fs));
        }
        fp_cvt(b, 1U, is_d, 0x02U, 0U, A64_TMP1);
    }
    fp_fpsr_read(b, 22U);
    fp_fpcr_restore(b);
    fp_finish(b, 22U, cur);
    fp_st(b, 0U, fd, be, is_d);
    b->fpr_non_nan |= (1U << fd);
    b->fpr_no_snan |= (1U << fd);
    return 0;
}
