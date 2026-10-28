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

/* CVT.W/CVT.L and ROUND/TRUNC/CEIL/FLOOR from S/D.  V0 holds the float
 * (FRINT pre-round for the fixed modes).  NaN inputs select INTMAX with
 * Invalid; negative overflow that set Invalid saturates to INTMAX
 * (matches the positive side; RC3 will confirm against the oracle).
 * Both selections use CSEL on values, so no control flow is needed. */
int fp_to_int_op(a64_buf_t *b, const mips_dec_t *d, uint32_t cur,
                        int be)
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
    fp_ld(b, 0U, fs, be, is_d);
    a64_emit_ldr_imm_w(b, 21U, A64_XCTX, MIPS32_CTX_FCSR_OFFSET);
    fp_fpcr_sync(b);
    fp_fpsr_clear(b);
    /* Fixed-mode FRINT pre-round (Wave P lane P4): ROUND/TRUNC/CEIL/
     * FLOOR ignore FCSR RM (interp fp_to_int forced_rm), so the FRINT
     * direction must be forced, not FPCR-following.  Triples verified
     * against GAS ground truth (the pre-existing triples emitted
     * unallocated words and SIGILLed): ROUND=FRINTN (0x04, 0x10,
     * ties-even), TRUNC=FRINT32Z/FRINT64Z (0x08/0x09, 0x10, toward
     * zero; 32-bit range for .W, 64-bit for .L), CEIL=FRINTP (0x04,
     * 0x30, toward +inf), FLOOR=FRINTM (0x05, 0x10, toward -inf).
     * Saturation/Invalid for out-of-range inputs still comes from the
     * FRINT (32/64 variants) or the following FCVTZS. */
    if (d->funct == FP_FUNCT_ROUND) {
        fp_emit1(b, is_d, 0x04U, 0x10U, 0U, 0U);
    } else if (d->funct == FP_FUNCT_TRUNC) {
        if (is_l == 0U) {
            fp_emit1(b, is_d, 0x08U, 0x10U, 0U, 0U);
        } else {
            fp_emit1(b, is_d, 0x09U, 0x10U, 0U, 0U);
        }
    } else if (d->funct == FP_FUNCT_CEIL) {
        fp_emit1(b, is_d, 0x04U, 0x30U, 0U, 0U);
    } else if (d->funct == FP_FUNCT_FLOOR) {
        fp_emit1(b, is_d, 0x05U, 0x10U, 0U, 0U);
    } else if (d->funct == FP_FUNCT_CVT_W || d->funct == FP_FUNCT_CVT_L) {
        /* CVT.W/CVT.L round per FCSR RM (interp default_rm).  The host
         * scalar fcvtzs ignores FPCR RMode (always truncates), so steer
         * with an explicit RM-selected FRINT and convert the resulting
         * integer-valued V0 exactly below.  W21 still holds FCSR here;
         * W22/W23 scratch (reused by the NaN probe below).  Triples match
         * the fixed-mode ones above (GAS-verified, incl. D variants). */
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
        if (is_l == 0U) {
            fp_emit1(b, is_d, 0x08U, 0x10U, 0U, 0U);
        } else {
            fp_emit1(b, is_d, 0x09U, 0x10U, 0U, 0U);
        }
        ph_d2 = a64_emit_b_cond_placeholder(b, A64_COND_AL);
        a64_patch_cbz_w(b, ph_bit0, b->count);
        fp_emit1(b, is_d, 0x04U, 0x10U, 0U, 0U);
        a64_patch_b_cond(b, ph_d0, b->count);
        a64_patch_b_cond(b, ph_d1, b->count);
        a64_patch_b_cond(b, ph_d2, b->count);
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
    fp_fpsr_read(b, 22U);
    fp_fpcr_restore(b);
    /* NaN selects INTMAX; negative overflow with Invalid saturates. */
    a64_emit_and_reg_w(b, true, A64_ZR, FP_STICKY, FP_STICKY, A64_SHIFT_LSL, 0U);
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
        fp_store_w(b, A64_TMP1, fp_slot(fd), be);
    } else {
        a64_emit_mov_imm32(b, 23U, 0xFFFFFFFFU);
        a64_emit_csel_w(b, A64_TMP1, 23U, A64_TMP1, A64_COND_NE);
        a64_emit_mov_imm32(b, 23U, 0x7FFFFFFFU);
        a64_emit_csel_w(b, A64_TMP2, 23U, A64_TMP2, A64_COND_NE);
        a64_emit_mov_imm32(b, 23U, 0x80000000U);
        a64_emit_sub_reg_w(b, true, A64_ZR, A64_TMP2, 23U, A64_SHIFT_LSL,
                           0U);
        a64_emit_mov_imm32(b, 23U, 1U);
        a64_emit_csel_w(b, 23U, 23U, A64_ZR, A64_COND_EQ);
        a64_emit_and_reg_w(b, true, A64_ZR, A64_TMP1, A64_TMP1,
                           A64_SHIFT_LSL, 0U);
        a64_emit_csel_w(b, A64_TMP1, 23U, A64_ZR, A64_COND_EQ);
        a64_emit_and_reg_w(b, false, A64_TMP1, 23U, A64_TMP1,
                           A64_SHIFT_LSL, 0U);
        a64_emit_ubfm_w(b, 23U, 22U, 0U, 0U);
        a64_emit_and_reg_w(b, false, A64_TMP1, A64_TMP1, 23U,
                           A64_SHIFT_LSL, 0U);
        a64_emit_and_reg_w(b, true, A64_ZR, A64_TMP1, A64_TMP1,
                           A64_SHIFT_LSL, 0U);
        a64_emit_mov_imm32(b, 23U, 0xFFFFFFFFU);
        a64_emit_csel_w(b, A64_TMP1, 23U, A64_TMP1, A64_COND_NE);
        a64_emit_mov_imm32(b, 23U, 0x7FFFFFFFU);
        a64_emit_csel_w(b, A64_TMP2, 23U, A64_TMP2, A64_COND_NE);
        fp_store_w(b, A64_TMP1, fp_slot(fd), be);
        fp_store_w(b, A64_TMP2, fp_slot(fd) + 4U, be);
    }
    a64_emit_orr_reg_w(b, 22U, 22U, FP_STICKY, A64_SHIFT_LSL, 0U);
    fp_finish(b, 22U, cur);
    return 0;
}

/* CVT.S.D / CVT.D.S: exact FCVT, legacy canonicalization both sides. */
int fp_cvt_float_op(a64_buf_t *b, const mips_dec_t *d, uint32_t cur,
                           int be, int nan2008, unsigned is_d)
{
    unsigned fs = d->rd;
    unsigned fd = d->sa;

    if (fs >= 32U || fd >= 32U) {
        return -1;
    }
    fp_ld(b, 0U, fs, be, is_d ^ 1U);
    a64_emit_mov_imm32(b, FP_STICKY, 0U);
    if (nan2008 == 0) {
        fp_quiet(b, 0U, FP_STICKY, is_d ^ 1U);
    }
    a64_emit_ldr_imm_w(b, 21U, A64_XCTX, MIPS32_CTX_FCSR_OFFSET);
    fp_fpsr_clear(b);
    if (is_d == 0U) {
        a64_emit_fcvt_d_to_s(b, 2U, 0U);
    } else {
        a64_emit_fcvt_s_to_d(b, 2U, 0U);
    }
    fp_fpsr_read(b, 22U);
    /* Flags + sticky live in W24 from here: fp_fix and the D-canonical
     * swap below clobber W22, while X24 is dead (host FPSR already
     * restored by fp_fpsr_read). */
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
    fp_st(b, 2U, fd, be, is_d);
    fp_finish(b, 24U, cur);
    return 0;
}

/* CVT.S/D from W (single GPR) or L (even-odd GPR pair, O32 order). */
int fp_from_int_op(a64_buf_t *b, const mips_dec_t *d, uint32_t cur,
                          int be, unsigned is_d)
{
    unsigned rt = d->rt;
    unsigned fd = d->sa;
    unsigned src;

    if (rt >= 32U || fd >= 32U) {
        return -1;
    }
    if (d->rs == FP_FMT_W) {
        src = fp_get(b, rt, A64_TMP1);
        a64_emit_ldr_imm_w(b, 21U, A64_XCTX, MIPS32_CTX_FCSR_OFFSET);
        fp_fpcr_sync(b);
        fp_fpsr_clear(b);
        if (is_d == 0U) {
            a64_emit_scvtf_w_to_s(b, 2U, src);
        } else {
            a64_emit_scvtf_w_to_d(b, 2U, src);
        }
    } else if (d->rs == FP_FMT_L) {
        unsigned lo;
        unsigned hi;
        unsigned vlo;
        unsigned vhi;

        if ((rt & 1U) != 0U || rt + 1U >= 32U) {
            return -1;
        }
        lo = (be != 0) ? rt + 1U : rt;
        hi = (be != 0) ? rt : rt + 1U;
        vlo = fp_get(b, lo, A64_TMP1);
        vhi = fp_get(b, hi, A64_TMP2);
        a64_emit_mov_w(b, 22U, vlo);
        a64_emit_mov_w(b, 23U, vhi);
        a64_emit_bfi_x(b, 22U, 23U, 32U, 32U);
        a64_emit_ldr_imm_w(b, 21U, A64_XCTX, MIPS32_CTX_FCSR_OFFSET);
        fp_fpcr_sync(b);
        fp_fpsr_clear(b);
        fp_cvt(b, 1U, is_d, 0x02U, 2U, 22U);
    } else {
        return -1;
    }
    fp_fpsr_read(b, 22U);
    fp_fpcr_restore(b);
    fp_st(b, 2U, fd, be, is_d);
    fp_finish(b, 22U, cur);
    return 0;
}
