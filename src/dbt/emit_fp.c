/*
 * src/dbt/emit_fp.c — AArch64 FPU emitter (Phase 3, lane L3b).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Single-instruction COP1 emitter called from dbt_emit_int's COP1 case
 * (tried first; nonzero return declines to the fallback).  Uses only
 * src/rt32/a64_emit.h: declared helpers plus raw FP/SIMD, MRS/MSR and
 * LDR/STR words via a64_emit(), each verified against GAS ground truth.
 *
 * Semantics (SPEC 2.2, E03): S-reg i is the low 32 bits of fpr[i]
 * (upper preserved); D-reg fs is the full 64-bit slot (FR-agnostic,
 * mirroring fpmove.c).  2008 NaN mode runs natively; legacy NaN inputs
 * are pre-normalized to AArch64-quiet form (sNaN recorded) and results
 * post-canonicalized to legacy-quiet (E03 defaults).  ABS/NEG/MOV never
 * signal.  FPCR RM syncs from FCSR RM around rounding ops.  Cause is
 * replaced, Flags accumulate, E set on enabled exceptions, which exit
 * EXIT_TRAP for interp_step re-execution.  BC1, fp-mem, DMFC1/DMTC1,
 * COP1X/COP2 decline (BC1 lives in the dbt_emit_int hook hunk).
 * Never touches x18; cached GPRs flush on trap exits.
 */

#include <stddef.h>
#include <stdint.h>

#include "mips32rt.h"
#include "rt32/a64_emit.h"
#include "interp/decode.h"
#include "dbt/emit_fp_priv.h"

/* Raw A64 FP/SIMD words (GAS-verified; ptype 0 = S, 1 = D). */
static void fp_emit2(a64_buf_t *b, unsigned ptype, unsigned opc, unsigned vd,
                     unsigned vn, unsigned vm)
{
    a64_emit(b, 0x1E000000U | ((ptype & 1U) << 22) | (1U << 21) |
                    ((vm & 31U) << 16) | ((opc & 63U) << 10) |
                    ((vn & 31U) << 5) | (vd & 31U));
}

void fp_emit1(a64_buf_t *b, unsigned ptype, unsigned op5, unsigned opc6,
                     unsigned vd, unsigned vn)
{
    a64_emit(b, 0x1E000000U | ((ptype & 1U) << 22) | (1U << 21) |
                    ((op5 & 31U) << 16) | ((opc6 & 63U) << 10) |
                    ((vn & 31U) << 5) | (vd & 31U));
}

static void fp_cmp(a64_buf_t *b, unsigned ptype, unsigned rn, unsigned rm)
{
    a64_emit(b, 0x1E000000U | ((ptype & 1U) << 22) | (1U << 21) |
                    ((rm & 31U) << 16) | (0x08U << 10) | ((rn & 31U) << 5));
}

/* Integer <-> FP conversions (sf 0 = W, 1 = X).  Sub-opcodes:
 * 0x18 FCVTZS, 0x19 FCVTZU, 0x02 SCVTF, 0x03 UCVTF, 0x07 FMOV D,X,
 * 0x06 FMOV X,D. */
void fp_cvt(a64_buf_t *b, unsigned sf, unsigned ptype, unsigned sub,
                   unsigned rd, unsigned rn)
{
    a64_emit(b, 0x1E000000U | ((sf & 1U) << 31) | ((ptype & 1U) << 22) |
                    (1U << 21) | ((sub & 31U) << 16) | ((rn & 31U) << 5) |
                    (rd & 31U));
}

/* Raw 64-bit ctx loads/stores (imm12 = byte_off / 8). */
static void fp_mem_d(a64_buf_t *b, unsigned is_store, unsigned vt,
                     unsigned rn_x, uint32_t byte_off)
{
    uint32_t base = (is_store != 0U) ? 0xFD000000U : 0xFD400000U;

    a64_emit(b, base | (((byte_off >> 3) & 0xFFFU) << 10) |
                    ((rn_x & 31U) << 5) | (vt & 31U));
}

/* MRS/MSR FPSR/FPCR (is_msr 0 = MRS Xt,sys; 1 = MSR sys,Xt).
 * GAS ground truth (Wave P lane P4): S3_4_C4_C4_op2 with CRm=4, i.e.
 * bases 0xD53B4400/0xD51B4400; op2 (bit 5) selects FPSR (1) vs FPCR
 * (0).  The pre-existing bases missed CRm and emitted unallocated
 * system-register words (SIGILL on the first FP arithmetic). */
static void fp_sys(a64_buf_t *b, unsigned is_msr, unsigned is_fpcr,
                   unsigned xt)
{
    uint32_t base = (is_msr != 0U) ? 0xD51B4400U : 0xD53B4400U;

    if (is_fpcr == 0U) {
        base |= 0x20U;
    }
    a64_emit(b, base | (xt & 31U));
}

/* Cached guest GPR -> host W register (SPEC 2.1; mirrors emit_int.c).
 * $0 reads as zero and is never written back. */
static const int8_t kFpGprHost[32] = {
    -1, -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, -1, -1,
    12, 13, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 14, -1, 15
};

static const uint8_t kFpCached[16] = {
    2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 16, 17, 29, 31
};

unsigned fp_get(a64_buf_t *b, unsigned g, unsigned tmp)
{
    int h;

    if (g == MIPS32_REG_ZERO) {
        return A64_ZR;
    }
    h = (g < 32U) ? (int)kFpGprHost[g] : -1;
    if (h >= 0) {
        return (unsigned)h;
    }
    a64_emit_ldr_imm_w(b, tmp, A64_XCTX, g * 4U);
    return tmp;
}

static void fp_put(a64_buf_t *b, unsigned g, unsigned src)
{
    int h;

    if (g == MIPS32_REG_ZERO) {
        return;
    }
    h = (g < 32U) ? (int)kFpGprHost[g] : -1;
    if (h >= 0) {
        a64_emit_mov_w(b, (unsigned)h, src);
        return;
    }
    a64_emit_str_imm_w(b, src, A64_XCTX, g * 4U);
}

uint32_t fp_slot(unsigned fs)
{
    return MIPS32_CTX_FPR_OFFSET + fs * 8U;
}

/* S-reg i is the low 32 bits of fpr[i] (upper half preserved by
 * stores); D-reg fs is the full 64-bit fpr[fs] slot.  FR-agnostic,
 * mirroring fpmove.c LWC1/LDC1. */
void fp_ld(a64_buf_t *b, unsigned vd, unsigned fs, int be,
                  unsigned is_d)
{
    (void)be; /* FPR lanes hold values, not guest-ordered bytes. */
    if (is_d == 0U) {
        a64_emit_ldr_imm_w(b, A64_TMP1, A64_XCTX, fp_slot(fs));
        a64_emit_fmov_w_to_s(b, vd, A64_TMP1);
        return;
    }
    fp_mem_d(b, 0U, vd, A64_XCTX, fp_slot(fs));
    return;
}

void fp_st(a64_buf_t *b, unsigned vd, unsigned fs, int be,
                  unsigned is_d)
{
    (void)be; /* FPR lanes hold values, not guest-ordered bytes. */
    if (is_d == 0U) {
        a64_emit_fmov_s_to_w(b, A64_TMP1, vd);
        a64_emit_str_imm_w(b, A64_TMP1, A64_XCTX, fp_slot(fs));
        return;
    }
    fp_mem_d(b, 1U, vd, A64_XCTX, fp_slot(fs));
}

/* Sync the host FPCR rounding mode from FCSR (W21) with a fast path
 * (Wave P lane P4): when (FCSR & FP_FCSR_FAST_MASK) == 0 the guest runs
 * round-to-nearest with no enabled traps and no flush-to-zero, so the
 * host FPCR already matches and the sync is skipped.  Only the slow
 * path saves the original FPCR in X23 and programs RM.  A64_TMP2
 * carries the mask: it is dead at every sync/restore call site (the
 * sync body itself reuses it). */
/* Sync the host FPCR rounding mode from FCSR (W21) with a fast path
 * (Wave P lane P4): when (FCSR & FP_FCSR_FAST_MASK) == 0 the guest runs
 * round-to-nearest with no enabled traps and no flush-to-zero, so the
 * host FPCR already matches and the sync is skipped.  Only the slow
 * path saves the original FPCR in X23 and programs RM.  A64_TMP2
 * carries the mask: it is dead at every sync/restore call site (the
 * sync body re-extracts RM into it on the slow path). */
void fp_fpcr_sync(a64_buf_t *b)
{
    size_t ph;

    a64_emit_mov_imm32(b, A64_TMP2, FP_FCSR_FAST_MASK);
    a64_emit_and_reg_w(b, true, A64_ZR, 21U, A64_TMP2, A64_SHIFT_LSL,
                       0U);
    ph = a64_emit_b_cond_placeholder(b, A64_COND_EQ);
    /* Slow path: re-extract RM (TMP2 held the mask above). */
    a64_emit_ubfm_w(b, A64_TMP2, 21U, 0U, 1U);
    fp_sys(b, 0U, 1U, 23U);
    fp_cvt(b, 1U, 1U, 0x07U, 7U, 23U);
    fp_cvt(b, 1U, 1U, 0x06U, 24U, 7U);
    a64_emit_ubfm_w(b, A64_TMP1, A64_TMP2, 0U, 0U);
    a64_emit_ubfm_w(b, 22U, A64_TMP2, 1U, 1U);
    a64_emit_eor_reg_w(b, A64_TMP1, A64_TMP1, 22U, A64_SHIFT_LSL, 0U);
    a64_emit_bfm_w(b, A64_TMP1, A64_TMP2, 31U, 0U);
    /* Zero-extend via W-form MOV (top zeroed by architecture): the
     * extended-ADD form cannot take XZR (Rn=31 encodes SP there). */
    a64_emit_mov_w(b, 22U, A64_TMP1);
    a64_emit_bfi_x(b, 24U, 22U, 22U, 2U);
    fp_sys(b, 1U, 1U, 24U);
    /* Context-synchronize the new RM (architecturally required after
     * MSR FPCR; retained even though this host's scalar converts
     * ignore FPCR RMode — conversions steer via explicit FRINT). */
    a64_emit_isb(b);
    a64_patch_b_cond(b, ph, b->count);
}

void fp_fpcr_restore(a64_buf_t *b)
{
    size_t ph;

    a64_emit_mov_imm32(b, A64_TMP2, FP_FCSR_FAST_MASK);
    a64_emit_and_reg_w(b, true, A64_ZR, 21U, A64_TMP2, A64_SHIFT_LSL,
                       0U);
    ph = a64_emit_b_cond_placeholder(b, A64_COND_EQ);
    fp_sys(b, 1U, 1U, 23U);
    /* Context-synchronize the restored FPCR (architecturally required;
     * a later fast-path skip relies on the host mode being back). */
    a64_emit_isb(b);
    a64_patch_b_cond(b, ph, b->count);
}

/* Save host FPSR in X24 and clear the cumulative flags. */
void fp_fpsr_clear(a64_buf_t *b)
{
    fp_sys(b, 0U, 0U, 24U);
    fp_sys(b, 1U, 0U, 31U);
}

/* Read cumulative flags into wdst and restore the saved host FPSR. */
void fp_fpsr_read(a64_buf_t *b, unsigned wdst)
{
    fp_sys(b, 0U, 0U, 22U);
    a64_emit_mov_w(b, wdst, 22U);
    fp_sys(b, 1U, 0U, 24U);
}

/* Split operand Vd into halves (hi W17, lo W16); S operands copy the
 * word to both halves so shared NaN logic works on either precision. */
static void fp_halves(a64_buf_t *b, unsigned vd, unsigned is_d)
{
    if (is_d == 0U) {
        a64_emit_fmov_s_to_w(b, A64_TMP1, vd);
        a64_emit_mov_w(b, A64_TMP2, A64_TMP1);
    } else {
        fp_cvt(b, 1U, 1U, 0x06U, 22U, vd);
        a64_emit_mov_w(b, A64_TMP1, 22U);
        a64_emit_ubfx_x_to_w(b, A64_TMP2, 22U, 32U, 32U);
    }
}

/* Shared NaN classifier: halves in W17/W16, quiet-bit in W22.
 * Non-NaN (or infinite) inputs branch to the caller's end; the caller
 * patches ph1/ph2 after emitting its writeback. */
static void fp_nan_test(a64_buf_t *b, unsigned vd, unsigned is_d,
                        size_t *ph1, size_t *ph2)
{
    unsigned elsb = (is_d == 0U) ? 23U : 20U;
    unsigned emax = (is_d == 0U) ? 0xFFU : 0x7FFU;
    unsigned qbit = (is_d == 0U) ? 22U : 19U;

    fp_halves(b, vd, is_d);
    a64_emit_ubfm_w(b, 22U, A64_TMP2, elsb, 30U);
    a64_emit_mov_imm32(b, 23U, emax);
    a64_emit_sub_reg_w(b, true, A64_ZR, 22U, 23U, A64_SHIFT_LSL, 0U);
    *ph1 = a64_emit_b_cond_placeholder(b, A64_COND_NE);
    if (is_d == 0U) {
        a64_emit_ubfm_w(b, 22U, A64_TMP1, 0U, 22U);
    } else {
        a64_emit_ubfm_w(b, 22U, A64_TMP2, 0U, 19U);
        a64_emit_orr_reg_w(b, 22U, 22U, A64_TMP1, A64_SHIFT_LSL, 0U);
    }
    *ph2 = a64_emit_cbz_w_placeholder(b, false, 22U);
    a64_emit_ubfm_w(b, 22U, (is_d == 0U) ? A64_TMP1 : A64_TMP2, qbit, qbit);
}

/* Legacy pre-normalization: set the quiet bit (payload preserved) and
 * record a set input quiet bit (sNaN) in the sticky Invalid bit. */
void fp_quiet(a64_buf_t *b, unsigned vd, unsigned wsticky,
                     unsigned is_d)
{
    size_t ph1, ph2;
    unsigned qbit = (is_d == 0U) ? 22U : 19U;

    fp_nan_test(b, vd, is_d, &ph1, &ph2);
    a64_emit_mov_imm32(b, 23U, 1U << qbit);
    a64_emit_orr_reg_w(b, wsticky, wsticky, 22U, A64_SHIFT_LSL, 0U);
    if (is_d == 0U) {
        a64_emit_orr_reg_w(b, A64_TMP1, A64_TMP1, 23U, A64_SHIFT_LSL, 0U);
        a64_emit_fmov_w_to_s(b, vd, A64_TMP1);
    } else {
        a64_emit_orr_reg_w(b, A64_TMP2, A64_TMP2, 23U, A64_SHIFT_LSL, 0U);
        a64_emit_mov_w(b, 23U, A64_TMP2);
        a64_emit_mov_w(b, 22U, A64_TMP1);
        a64_emit_bfi_x(b, 22U, 23U, 32U, 32U);
        fp_cvt(b, 1U, 1U, 0x07U, vd, 22U);
    }
    a64_patch_b_cond(b, ph1, b->count);
    a64_patch_cbz_w(b, ph2, b->count);
}

/* Legacy post-canonicalization: clear a set quiet bit (AArch64 default
 * NaNs carry the 2008 MSB); a payload that would vanish becomes the
 * default legacy QNaN (E03). */
void fp_fix(a64_buf_t *b, unsigned vd, unsigned is_d)
{
    size_t ph1, ph2, ph3, ph4;
    unsigned qbit = (is_d == 0U) ? 22U : 19U;

    fp_nan_test(b, vd, is_d, &ph1, &ph2);
    ph3 = a64_emit_cbz_w_placeholder(b, false, 22U);
    a64_emit_mov_imm32(b, 23U, 1U << qbit);
    if (is_d == 0U) {
        a64_emit_bic_reg_w(b, false, A64_TMP1, A64_TMP1, 23U, A64_SHIFT_LSL,
                           0U);
        a64_emit_ubfm_w(b, 22U, A64_TMP1, 0U, 21U);
        ph4 = a64_emit_cbz_w_placeholder(b, true, 22U);
        a64_emit_mov_imm32(b, A64_TMP1, 0x7FBFFFFFU);
        a64_patch_cbz_w(b, ph4, b->count);
        a64_emit_fmov_w_to_s(b, vd, A64_TMP1);
    } else {
        a64_emit_bic_reg_w(b, false, A64_TMP2, A64_TMP2, 23U,
                           A64_SHIFT_LSL, 0U);
        a64_emit_ubfm_w(b, 22U, A64_TMP2, 0U, 18U);
        a64_emit_orr_reg_w(b, 22U, 22U, A64_TMP1, A64_SHIFT_LSL, 0U);
        ph4 = a64_emit_cbz_w_placeholder(b, true, 22U);
        a64_emit_mov_imm32(b, A64_TMP2, 0x7FF7FFFFU);
        a64_emit_mov_imm32(b, A64_TMP1, 0xFFFFFFFFU);
        a64_patch_cbz_w(b, ph4, b->count);
        a64_emit_mov_w(b, 23U, A64_TMP2);
        a64_emit_mov_w(b, 22U, A64_TMP1);
        a64_emit_bfi_x(b, 22U, 23U, 32U, 32U);
        fp_cvt(b, 1U, 1U, 0x07U, vd, 22U);
    }
    a64_patch_b_cond(b, ph1, b->count);
    a64_patch_cbz_w(b, ph2, b->count);
    a64_patch_cbz_w(b, ph3, b->count);
}

/* Merge an operation's exception bits (FPSR IOC/DZC/OFC/UFC/IXC in the
 * low 5 bits of wfpsr5) into FCSR (W21): Cause[17:12] is replaced
 * (cleared then set, E never set: qemu reports 0x10800 on Invalid
 * trap), Flags[6:2] accumulate.  An enabled exception stores FCSR and
 * exits EXIT_TRAP at cur (Flags left untouched); otherwise Flags are
 * updated and emission continues.
 * RBIT maps bit k to bit 31-k, so LSR 15 lands V..I on Cause 16..12
 * and LSR 25 on Flags 6..2. */
void fp_finish(a64_buf_t *b, unsigned wfpsr5, uint32_t cur)
{
    size_t ph;
    unsigned i;

    a64_emit_ubfm_w(b, 22U, wfpsr5, 0U, 4U);
    a64_emit_rbit_w(b, 22U, 22U);
    a64_emit_shift_imm_w(b, A64_TMP1, 22U, A64_SHIFT_LSR, 15U, false,
                         NULL);
    a64_emit_shift_imm_w(b, A64_TMP2, 22U, A64_SHIFT_LSR, 25U, false,
                         NULL);
    a64_emit_mov_imm32(b, 22U, FP_FCSR_CAUSE_MASK | FP_FCSR_E_BIT);
    a64_emit_and_reg_w(b, false, A64_TMP1, A64_TMP1, 22U, A64_SHIFT_LSL,
                       0U);
    a64_emit_mov_imm32(b, 22U, 0x7CU);
    a64_emit_and_reg_w(b, false, A64_TMP2, A64_TMP2, 22U, A64_SHIFT_LSL,
                       0U);
    a64_emit_mov_imm32(b, 22U, FP_FCSR_CAUSE_MASK | FP_FCSR_E_BIT);
    a64_emit_bic_reg_w(b, false, 21U, 21U, 22U, A64_SHIFT_LSL, 0U);
    a64_emit_orr_reg_w(b, 21U, 21U, A64_TMP1, A64_SHIFT_LSL, 0U);
    a64_emit_ubfm_w(b, 22U, 21U, FP_FCSR_ENABLE_SHIFT,
                     FP_FCSR_ENABLE_SHIFT + 4U);
    /* Align Enable[4:0] (V..I) with Cause[16:12]: shift 12, not 5. */
    a64_emit_shift_imm_w(b, 22U, 22U, A64_SHIFT_LSL, 12U, false, NULL);
    a64_emit_and_reg_w(b, false, 22U, 22U, A64_TMP1, A64_SHIFT_LSL, 0U);
    ph = a64_emit_cbz_w_placeholder(b, false, 22U);
    a64_emit_str_imm_w(b, 21U, A64_XCTX, MIPS32_CTX_FCSR_OFFSET);
    for (i = 0U; i < 16U; i++) {
        a64_emit_str_imm_w(b, (unsigned)kFpGprHost[kFpCached[i]], A64_XCTX,
                           (uint32_t)kFpCached[i] * 4U);
    }
    a64_emit_mov_imm32(b, A64_TMP1, cur);
    a64_emit_str_imm_w(b, A64_TMP1, A64_XCTX, MIPS32_CTX_PC_OFFSET);
    a64_emit_mov_imm32(b, A64_TMP1, cur + 4U);
    a64_emit_str_imm_w(b, A64_TMP1, A64_XCTX, MIPS32_CTX_NEXT_PC_OFFSET);
    a64_emit_mov_imm32(b, 0U, MIPS32_EXIT_TRAP);
    a64_emit_mov_imm32(b, 1U, cur);
    a64_emit_ret(b);
    a64_patch_cbz_w(b, ph, b->count);
    a64_emit_orr_reg_w(b, 21U, 21U, A64_TMP2, A64_SHIFT_LSL, 0U);
    a64_emit_str_imm_w(b, 21U, A64_XCTX, MIPS32_CTX_FCSR_OFFSET);
}

/* C.cond.fmt: ordered/unordered compare per E03, FCC[cc] writeback.
 * Signalling variants set Invalid on unordered input; the sticky bit
 * (FP_STICKY) carries pre-quiet Invalid through the FPSR merge. */
static int fp_cmp_op(a64_buf_t *b, const mips_dec_t *d, uint32_t cur, int be,
                     int nan2008)
{
    unsigned fs = d->rd;
    unsigned ft = d->rt;
    unsigned cc = ((unsigned)d->sa >> 2U) & 7U;
    unsigned cond = (unsigned)d->funct & 0xFU;
    unsigned base = cond & 7U;
    unsigned ptype = (d->rs == FP_FMT_D) ? 1U : 0U;
    unsigned fccpos = (cc == 0U) ? 23U : (24U + cc);
    size_t ph;

    if (fs >= 32U || ft >= 32U) {
        return -1;
    }
    if (d->rs != FP_FMT_S && d->rs != FP_FMT_D) {
        return -1;
    }
    fp_ld(b, 0U, fs, be, ptype);
    fp_ld(b, 1U, ft, be, ptype);
    a64_emit_mov_imm32(b, FP_STICKY, 0U);
    if (nan2008 == 0) {
        fp_quiet(b, 0U, FP_STICKY, ptype);
        fp_quiet(b, 1U, FP_STICKY, ptype);
    }
    a64_emit_ldr_imm_w(b, 21U, A64_XCTX, MIPS32_CTX_FCSR_OFFSET);
    fp_fpsr_clear(b);
    fp_cmp(b, ptype, 0U, 1U);
    a64_emit_mov_imm32(b, 17U, 0U);
    a64_emit_mov_imm32(b, 16U, 1U);
    if ((cond & 8U) != 0U) {
        ph = a64_emit_b_cond_placeholder(b, A64_COND_VC);
        a64_emit_mov_imm32(b, FP_STICKY, 1U);
        a64_patch_b_cond(b, ph, b->count);
    }
    /* Ordered predicates need !V; unordered-inclusive ones accept V. */
    if (base != 0U) {
        static const uint8_t kCmpA[8] = { 0U, A64_COND_VS, A64_COND_EQ, A64_COND_EQ,
                                          A64_COND_LT, A64_COND_LT, A64_COND_LE,
                                          A64_COND_LE };
        a64_emit_csel_w(b, 17U, 16U, 17U, kCmpA[base]);
        if (base >= 3U) {
            if ((base & 1U) != 0U) {
                a64_emit_csel_w(b, 17U, 16U, 17U, A64_COND_VS);
            } else {
                a64_emit_mov_imm32(b, 22U, 0U);
                a64_emit_csel_w(b, 17U, 17U, 22U, A64_COND_VC);
            }
        }
    }
    fp_fpsr_read(b, 22U);
    a64_emit_orr_reg_w(b, 22U, 22U, FP_STICKY, A64_SHIFT_LSL, 0U);
    /* Shelter the compare result in W24: fp_finish reuses W16/W17
     * (A64_TMP1/TMP2) as scratch, so W17 would not survive.  W24 is
     * dead across fp_finish (no fp_sys inside) but live across
     * fp_fpsr_read (MSR reads X24), hence the move goes here. */
    a64_emit_mov_w(b, 24U, 17U);
    fp_finish(b, 22U, cur);
    a64_emit_mov_imm32(b, 22U, 1U << fccpos);
    a64_emit_bic_reg_w(b, false, 21U, 21U, 22U, A64_SHIFT_LSL, 0U);
    a64_emit_orr_reg_w(b, 21U, 21U, 24U, A64_SHIFT_LSL, fccpos);
    a64_emit_str_imm_w(b, 21U, A64_XCTX, MIPS32_CTX_FCSR_OFFSET);
    return 0;
}

/* S/D ADD/SUB/MUL/DIV/SQRT with FPCR sync, FPSR merge and legacy
 * canonicalization.  Operands in V0/V1 (SQRT uses V0 only), result V2. */
static int fp_arith_op(a64_buf_t *b, const mips_dec_t *d, uint32_t cur,
                       int be, int nan2008)
{
    unsigned fs = d->rd;
    unsigned ft = d->rt;
    unsigned fd = d->sa;
    unsigned ptype = (d->rs == FP_FMT_D) ? 1U : 0U;
    unsigned opc;

    if (fs >= 32U || ft >= 32U || fd >= 32U) {
        return -1;
    }
    switch (d->funct) {
    case FP_FUNCT_ADD: opc = 0x0AU; break;
    case FP_FUNCT_SUB: opc = 0x0EU; break;
    case FP_FUNCT_MUL: opc = 0x02U; break;
    case FP_FUNCT_DIV: opc = 0x06U; break;
    case FP_FUNCT_SQRT: opc = 0xFFU; break;
    default: return -1;
    }
    fp_ld(b, 0U, fs, be, ptype);
    if (opc != 0xFFU) {
        fp_ld(b, 1U, ft, be, ptype);
    }
    a64_emit_mov_imm32(b, FP_STICKY, 0U);
    if (nan2008 == 0) {
        fp_quiet(b, 0U, FP_STICKY, ptype);
        if (opc != 0xFFU) {
            fp_quiet(b, 1U, FP_STICKY, ptype);
        }
    }
    a64_emit_ldr_imm_w(b, 21U, A64_XCTX, MIPS32_CTX_FCSR_OFFSET);
    fp_fpcr_sync(b);
    fp_fpsr_clear(b);
    if (opc == 0xFFU) {
        fp_emit1(b, ptype, 0x01U, 0x30U, 2U, 0U);
    } else {
        fp_emit2(b, ptype, opc, 2U, 0U, 1U);
    }
    fp_fpsr_read(b, 22U);
    fp_fpcr_restore(b);
    /* Flags + sticky live in W24 from here: fp_fix and the D-canonical
     * swap below clobber W22 (fp_nan_test ubfm, add X22), while X24 is
     * dead (host FPSR already restored by fp_fpsr_read). */
    a64_emit_orr_reg_w(b, 24U, 22U, FP_STICKY, A64_SHIFT_LSL, 0U);
    if (nan2008 == 0) {
        size_t ph_can;

        fp_fix(b, 2U, ptype);
        /* Legacy sNaN arithmetic delivers the canonical Legacy QNaN
         * (S 0x7fbfffff, D 0x7ff7ffffffffffff, matching qemu for partial
         * double payloads); W15 nonzero records an sNaN input. */
        ph_can = a64_emit_cbz_w_placeholder(b, false, FP_STICKY);
        if (ptype == 0u) {
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
    fp_st(b, 2U, fd, be, ptype);
    fp_finish(b, 24U, cur);
    return 0;
}

/* ABS/NEG/MOV: non-arithmetic sign-bit operations (E03: never signal,
 * no FCSR update) shared by both NaN modes. */
static int fp_unary_op(a64_buf_t *b, const mips_dec_t *d, int be)
{
    unsigned fs = d->rd;
    unsigned fd = d->sa;
    unsigned ptype = (d->rs == FP_FMT_D) ? 1U : 0U;
    unsigned op5;
    unsigned opc6;

    if (fs >= 32U || fd >= 32U) {
        return -1;
    }
    switch (d->funct) {
    case FP_FUNCT_ABS: op5 = 0x00U; opc6 = 0x30U; break;
    case FP_FUNCT_NEG: op5 = 0x01U; opc6 = 0x10U; break;
    case FP_FUNCT_MOV: op5 = 0x00U; opc6 = 0x10U; break;
    default: return -1;
    }
    fp_ld(b, 0U, fs, be, ptype);
    fp_emit1(b, ptype, op5, opc6, 1U, 0U);
    fp_st(b, 1U, fd, be, ptype);
    return 0;
}

/* Store a W integer conversion result to an FPR low half (a value). */
void fp_store_w(a64_buf_t *b, unsigned wsrc, uint32_t off, int be)
{
    (void)be;
    a64_emit_str_imm_w(b, wsrc, A64_XCTX, off);
}

/* MFC1/MTC1/MFHC1/MTHC1/CFC1/CTC1: bit moves, mirroring fpmove.c.
 * FPR halves byte-swap in BE; FCSR words never do. */
static int fp_move_op(a64_buf_t *b, const mips_dec_t *d, int be)
{
    unsigned rt = d->rt;
    unsigned fs = d->rd;
    unsigned off;
    unsigned v;

    if (rt >= 32U || fs >= 32U) {
        return -1;
    }
    if (d->rs == FP_RS_CFC1 || d->rs == FP_RS_CTC1) {
        if (fs != 31U) {
            return -1;
        }
        off = MIPS32_CTX_FCSR_OFFSET;
    } else if (d->rs == FP_RS_MFC1 || d->rs == FP_RS_MTC1) {
        off = fp_slot(fs);
    } else if (d->rs == FP_RS_MFHC1 || d->rs == FP_RS_MTHC1) {
        off = fp_slot(fs) + 4U;
    } else {
        return -1;
    }
    if (d->rs == FP_RS_MFC1 || d->rs == FP_RS_MFHC1 || d->rs == FP_RS_CFC1) {
        a64_emit_ldr_imm_w(b, A64_TMP1, A64_XCTX, off);
        fp_put(b, rt, A64_TMP1);
        return 0;
    }
    v = fp_get(b, rt, A64_TMP1);
    if (d->rs == FP_RS_CTC1) {
        a64_emit_str_imm_w(b, v, A64_XCTX, off);
    } else {
        fp_store_w(b, v, off, be);
    }
    return 0;
}

/* Public entry: 0 emitted (advance 4), nonzero declines to the
 * dispatcher's fallback.  BC1 declines here; its native branch lives
 * in the dbt_emit_int hook, which owns the delay-slot instruction. */
int dbt_emit_fp(a64_buf_t *b, const mips_dec_t *d, uint32_t cur, uint32_t fpc,
                int be, int fr_mode, int nan2008)
{
    (void)fpc;

    if (b == NULL || d == NULL) {
        return -1;
    }
    if (d->op != MIPS_OP_COP1) {
        return -1;
    }
    /* Mode flags are single bits; anything else declines. */
    if ((unsigned)(be | fr_mode | nan2008) > 1U) {
        return -1;
    }
    if (d->rs <= FP_RS_MTHC1) {
        return fp_move_op(b, d, be); /* DMFC1/DMTC1 decline inside */
    }
    if (d->rs == MIPS_COP1_RS_BC) {
        return -1;
    }
    if (d->rs == FP_FMT_S || d->rs == FP_FMT_D) {
        switch (d->funct) {
        case FP_FUNCT_ADD:
        case FP_FUNCT_SUB:
        case FP_FUNCT_MUL:
        case FP_FUNCT_DIV:
        case FP_FUNCT_SQRT:
            return fp_arith_op(b, d, cur, be, nan2008);
        case FP_FUNCT_ABS:
        case FP_FUNCT_NEG:
        case FP_FUNCT_MOV:
            return fp_unary_op(b, d, be);
        case FP_FUNCT_ROUND:
        case FP_FUNCT_TRUNC:
        case FP_FUNCT_CEIL:
        case FP_FUNCT_FLOOR:
        case FP_FUNCT_CVT_W:
        case FP_FUNCT_CVT_L:
            return fp_to_int_op(b, d, cur, be);
        case FP_FUNCT_CVT_S:
            return (d->rs == FP_FMT_D)
                ? fp_cvt_float_op(b, d, cur, be, nan2008, 0U)
                : -1;
        case FP_FUNCT_CVT_D:
            return (d->rs == FP_FMT_S)
                ? fp_cvt_float_op(b, d, cur, be, nan2008, 1U)
                : -1;
        default:
            if ((d->funct & 0x30U) == 0x30U) {
                return fp_cmp_op(b, d, cur, be, nan2008);
            }
            return -1;
        }
    }
    if (d->rs == FP_FMT_W || d->rs == FP_FMT_L) {
        if (d->funct == FP_FUNCT_CVT_S || d->funct == FP_FUNCT_CVT_D) {
            return fp_from_int_op(b, d, cur, be,
                                  (d->funct == FP_FUNCT_CVT_D) ? 1U : 0U);
        }
    }
    return -1;
}
