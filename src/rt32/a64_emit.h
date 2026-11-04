/*
 * src/rt32/a64_emit.h — Direct 32-bit AArch64 instruction encoder (integer + FP/SIMD)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Vendored from ../i686rt/src/rt32/rt32_a64_emit.h: retyped on
 * mips32_ctx_t.  The i686-only block-exit chaining prototypes and the
 * ARM-DSP lowering helpers were dropped with their implementations
 * (see a64_emit.c); they return with src/dbt/ in Phase 2.
 */

#ifndef A64_EMIT_H
#define A64_EMIT_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "mips32rt.h"

/*
 * Host AArch64 register allocation inside translated fragments (MIPS DBT,
 * SPEC 2.1):
 *   w0..w15  : 16 hot guest GPRs when live: $v0 ($2), $v1 ($3),
 *              $a0..$a3 ($4..$7), $t0..$t5 ($8..$13), $s0 ($16),
 *              $s1 ($17), $sp ($29), $ra ($31)
 *   w15/x15  : Scratch 0
 *   w16/x16  : Scratch 1
 *   w17/x17  : Scratch 2
 *   x19      : Pointer to `mips32_ctx_t` (xCtx)
 *   x20      : Guest window base `G` (xG)
 *   w21/x21  : Scratch 3
 *   w22/x22  : Guest effective address scratch
 *   x23..x24 : Scratch
 *   x18      : Permanently reserved, never touched
 *   v0..v7   : Scratch FP/SIMD registers for FPU lowering
 */
#define A64_TMP0 15U
#define A64_TMP1 16U
#define A64_TMP2 17U
#define A64_XCTX 19U
#define A64_XG   20U
#define A64_TMP3 21U
#define A64_ADDR 22U
#define A64_ZR   31U

/* Shift types */
#define A64_SHIFT_LSL 0U
#define A64_SHIFT_LSR 1U
#define A64_SHIFT_ASR 2U
#define A64_SHIFT_ROR 3U

/* Condition codes */
#define A64_COND_EQ 0U
#define A64_COND_NE 1U
#define A64_COND_CS 2U
#define A64_COND_CC 3U
#define A64_COND_MI 4U
#define A64_COND_PL 5U
#define A64_COND_VS 6U
#define A64_COND_VC 7U
#define A64_COND_HI 8U
#define A64_COND_LS 9U
#define A64_COND_GE 10U
#define A64_COND_LT 11U
#define A64_COND_GT 12U
#define A64_COND_LE 13U
#define A64_COND_AL 14U

#define A64_MAX_EXIT_SLOTS  8U

typedef struct a64_buf {
    uint32_t *words;
    size_t    count;
    size_t    cap;
    bool      overflow;
    /* Bit g set: cached guest GPR g holds a value newer than ctx->r[g]
     * and must be stored back by the next flush.  Bit index is the
     * guest register number (only the 16 kCached GPRs are ever set). */
    uint32_t  gpr_dirty;
    unsigned  cond_branch_depth;
    uint32_t  guest_start_pc;
    uint32_t  guest_end_pc;
    bool      is_call;
    bool      lr_written_from_pc;
    bool      has_self_loop;
    size_t    loop_body_offset;
    uint32_t  exit_slot_pcs[A64_MAX_EXIT_SLOTS];
    unsigned  exit_slot_count;
    /* Wave P5 FP batch: fp_defer_finish defers this op's FPSR sync to
     * the batch-final op; fp_batch_open tracks an open batch. */
    uint8_t   fp_defer_finish;
    uint8_t   fp_batch_open;
    /* M32-R8-4: JR/JALR delay-slot link restore.  Armed only while a
     * JALR rd==rs delay slot emits: its fault/single-step exits then
     * restore guest GPR ind_link_rs from ctx->delay_target (the link
     * already clobbered the jump source). */
    uint8_t   ind_link_restore;
    uint8_t   ind_link_rs;
    uint8_t   ind_slot;
    uint8_t   fr_mode;
    /* Wave P12 16-slot write-through FPR cache in v16..v31 (slot =
     * ((fs>>1)^((fs&1)<<3))&15, creg = 16+slot; even O32 regs map 1-1)
     * plus known-non-NaN / known-no-sNaN bitmaps (bit = guest FPR). */
    uint16_t  fpr_cache_valid;
    uint16_t  fpr_cache_is_d;
    uint8_t   fpr_cache_reg[16];
    uint32_t  fpr_non_nan;
    uint32_t  fpr_no_snan;
} a64_buf_t;

static inline void a64_buf_init(a64_buf_t *b, uint32_t *storage, size_t cap)
{
    memset(b, 0, sizeof(*b));
    b->words = storage;
    b->cap   = cap;
    b->gpr_dirty = 0U;
}

static inline void a64_emit(a64_buf_t *b, uint32_t insn)
{
    if (b->count < b->cap) {
        b->words[b->count++] = insn;
    } else {
        b->overflow = true;
    }
}

/* Move immediate & register moves */
void a64_emit_movz_w(a64_buf_t *b, unsigned rd, uint16_t imm16, unsigned hw);
void a64_emit_movk_w(a64_buf_t *b, unsigned rd, uint16_t imm16, unsigned hw);
void a64_emit_mov_imm32(a64_buf_t *b, unsigned rd, uint32_t val);
void a64_emit_mov_pc32(a64_buf_t *b, unsigned rd, uint32_t pc_val);
void a64_emit_mov_w(a64_buf_t *b, unsigned rd, unsigned rm);
void a64_emit_mvn_reg_w(a64_buf_t *b, unsigned rd, unsigned rm, unsigned shift, unsigned amount);

static inline uint32_t rt32_ror32(uint32_t val, unsigned rot)
{
    rot &= 31U;
    if (rot == 0U) {
        return val;
    }
    return (val >> rot) | (val << (32U - rot));
}

/* Arithmetic (32-bit W) */
void a64_emit_add_imm_w(a64_buf_t *b, bool set_flags, unsigned rd, unsigned rn, uint16_t imm12, unsigned sh);
void a64_emit_add_imm_x(a64_buf_t *b, bool set_flags, unsigned rd_x, unsigned rn_x, uint32_t imm12, unsigned sh);
void a64_emit_sub_imm_x(a64_buf_t *b, bool set_flags, unsigned rd_x, unsigned rn_x, uint32_t imm12, unsigned sh);
void a64_emit_sub_imm_w(a64_buf_t *b, bool set_flags, unsigned rd, unsigned rn, uint16_t imm12, unsigned sh);
void a64_emit_add_reg_w(a64_buf_t *b, bool set_flags, unsigned rd, unsigned rn, unsigned rm, unsigned shift, unsigned amount);
void a64_emit_sub_reg_w(a64_buf_t *b, bool set_flags, unsigned rd, unsigned rn, unsigned rm, unsigned shift, unsigned amount);
void a64_emit_adc_w(a64_buf_t *b, bool set_flags, unsigned rd, unsigned rn, unsigned rm);
void a64_emit_sbc_w(a64_buf_t *b, bool set_flags, unsigned rd, unsigned rn, unsigned rm);
void a64_emit_add_uxtw_x(a64_buf_t *b, unsigned rd_x, unsigned rn_x, unsigned rm_w);

/* Logical (32-bit W) */
void a64_emit_and_reg_w(a64_buf_t *b, bool set_flags, unsigned rd, unsigned rn, unsigned rm, unsigned shift, unsigned amount);
void a64_emit_bic_reg_w(a64_buf_t *b, bool set_flags, unsigned rd, unsigned rn, unsigned rm, unsigned shift, unsigned amount);
void a64_emit_orr_reg_w(a64_buf_t *b, unsigned rd, unsigned rn, unsigned rm, unsigned shift, unsigned amount);
void a64_emit_orn_reg_w(a64_buf_t *b, unsigned rd, unsigned rn, unsigned rm, unsigned shift, unsigned amount);
void a64_emit_eor_reg_w(a64_buf_t *b, unsigned rd, unsigned rn, unsigned rm, unsigned shift, unsigned amount);

/* Shifts, bitfields, multiply/divide */
void a64_emit_shift_reg_w(a64_buf_t *b, unsigned rd, unsigned rn, unsigned rm, unsigned shift_type);
void a64_emit_shift_imm_w(a64_buf_t *b, unsigned dst_w, unsigned src_m, unsigned shift_type,
                          unsigned imm5, bool want_carry, unsigned *out_carry_reg);
void a64_emit_ubfm_w(a64_buf_t *b, unsigned rd, unsigned rn, unsigned immr, unsigned imms);
void a64_emit_sbfm_w(a64_buf_t *b, unsigned rd, unsigned rn, unsigned immr, unsigned imms);
void a64_emit_bfm_w(a64_buf_t *b, unsigned rd, unsigned rn, unsigned immr, unsigned imms);
void a64_emit_ubfx_x_to_w(a64_buf_t *b, unsigned rd_w, unsigned rn_x, unsigned lsb, unsigned width);
void a64_emit_bfi_x(a64_buf_t *b, unsigned rd_x, unsigned rn_x, unsigned lsb, unsigned width);
void a64_emit_clz_w(a64_buf_t *b, unsigned rd, unsigned rn);
void a64_emit_rbit_w(a64_buf_t *b, unsigned rd, unsigned rn);
void a64_emit_rev_w(a64_buf_t *b, unsigned rd, unsigned rn);
void a64_emit_rev16_w(a64_buf_t *b, unsigned rd, unsigned rn);
void a64_emit_madd_w(a64_buf_t *b, unsigned rd, unsigned rn, unsigned rm, unsigned ra);
void a64_emit_msub_w(a64_buf_t *b, unsigned rd, unsigned rn, unsigned rm, unsigned ra);
void a64_emit_umaddl_x(a64_buf_t *b, unsigned rd_x, unsigned rn_w, unsigned rm_w, unsigned ra_x);
void a64_emit_smaddl_x(a64_buf_t *b, unsigned rd_x, unsigned rn_w, unsigned rm_w, unsigned ra_x);
void a64_emit_smsubl_x(a64_buf_t *b, unsigned rd_x, unsigned rn_w, unsigned rm_w, unsigned ra_x);
void a64_emit_udiv_w(a64_buf_t *b, unsigned rd, unsigned rn, unsigned rm);
void a64_emit_sdiv_w(a64_buf_t *b, unsigned rd, unsigned rn, unsigned rm);

/* Conditional select & flags */
void a64_emit_csel_w(a64_buf_t *b, unsigned rd, unsigned rn, unsigned rm, unsigned cond);
void a64_emit_csneg_w(a64_buf_t *b, unsigned rd, unsigned rn, unsigned rm, unsigned cond);
void a64_emit_mrs_nzcv(a64_buf_t *b, unsigned rt);
void a64_emit_msr_nzcv(a64_buf_t *b, unsigned rt);

/*
 * Flag helpers for logical operations with S=1:
 *   - a64_emit_update_nz_keep_cv: updates N and Z from `res_reg`, preserves C and V.
 *   - a64_emit_update_nzc_keep_v_imm: updates N and Z from `res_reg`, sets C = `carry_bit`, preserves V.
 *   - a64_emit_update_nzc_keep_v_reg: updates N and Z from `res_reg`, sets C = `carry_reg[0]`, preserves V.
 */
void a64_emit_update_nz_keep_cv(a64_buf_t *b, unsigned res_reg);
void a64_emit_update_nzc_keep_v_imm(a64_buf_t *b, unsigned res_reg, unsigned carry_bit);
void a64_emit_update_nzc_keep_v_reg(a64_buf_t *b, unsigned res_reg, unsigned carry_reg);
void a64_emit_logical_flags(a64_buf_t *b, unsigned res_reg, bool has_imm_carry,
                            unsigned imm_carry, unsigned shift_carry_reg);

/* Guest memory loads/stores via [xG, wAddr, uxtw] */
void a64_emit_guest_ldr_w(a64_buf_t *b, unsigned rt, unsigned addr_w);
void a64_emit_guest_str_w(a64_buf_t *b, unsigned rt, unsigned addr_w);
void a64_emit_guest_ldrd_w(a64_buf_t *b, unsigned rt, unsigned rt2, unsigned addr_w);
void a64_emit_guest_strd_w(a64_buf_t *b, unsigned rt, unsigned rt2, unsigned addr_w);
void a64_emit_guest_ldrb_w(a64_buf_t *b, unsigned rt, unsigned addr_w);
void a64_emit_guest_ldrsb_w(a64_buf_t *b, unsigned rt, unsigned addr_w);
void a64_emit_guest_strb_w(a64_buf_t *b, unsigned rt, unsigned addr_w);
void a64_emit_guest_ldrh_w(a64_buf_t *b, unsigned rt, unsigned addr_w);
void a64_emit_guest_ldrsh_w(a64_buf_t *b, unsigned rt, unsigned addr_w);
void a64_emit_guest_strh_w(a64_buf_t *b, unsigned rt, unsigned addr_w);

/* Host context loads/stores via [Xn, #byte_offset] */
void a64_emit_ldrb_imm_w(a64_buf_t *b, unsigned rt, unsigned rn_x, uint32_t byte_offset);
void a64_emit_strb_imm_w(a64_buf_t *b, unsigned rt, unsigned rn_x, uint32_t byte_offset);
void a64_emit_ldrh_imm_w(a64_buf_t *b, unsigned rt, unsigned rn_x, uint32_t byte_offset);
void a64_emit_strh_imm_w(a64_buf_t *b, unsigned rt, unsigned rn_x, uint32_t byte_offset);
void a64_emit_ldr_imm_w(a64_buf_t *b, unsigned rt, unsigned rn_x, uint32_t byte_offset);
void a64_emit_str_imm_w(a64_buf_t *b, unsigned rt, unsigned rn_x, uint32_t byte_offset);
void a64_emit_ldr_imm_x(a64_buf_t *b, unsigned rt_x, unsigned rn_x, uint32_t byte_offset);
void a64_emit_str_imm_x(a64_buf_t *b, unsigned rt_x, unsigned rn_x, uint32_t byte_offset);
void a64_emit_eor_reg_x(a64_buf_t *b, unsigned rd_x, unsigned rn_x, unsigned rm_x);
size_t a64_emit_cbz_x_placeholder(a64_buf_t *b, bool is_cbnz, unsigned rt_x);
void a64_patch_cbz_x(a64_buf_t *b, size_t patch_idx, size_t target_idx);

/* Guest memory FP loads/stores via [xG, wAddr, uxtw] */
void a64_emit_guest_ldr_s(a64_buf_t *b, unsigned vt, unsigned addr_w);
void a64_emit_guest_str_s(a64_buf_t *b, unsigned vt, unsigned addr_w);
void a64_emit_guest_ldr_d(a64_buf_t *b, unsigned vt, unsigned addr_w);
void a64_emit_guest_str_d(a64_buf_t *b, unsigned vt, unsigned addr_w);

/* Scalar FP instructions */
void a64_emit_fmov_w_to_s(a64_buf_t *b, unsigned vd, unsigned rn_w);
void a64_emit_fmov_s_to_w(a64_buf_t *b, unsigned rd_w, unsigned vn);
void a64_emit_fcvt_s_to_d(a64_buf_t *b, unsigned vd, unsigned vn);
void a64_emit_fcvt_d_to_s(a64_buf_t *b, unsigned vd, unsigned vn);
void a64_emit_fcvtzs_s_to_w(a64_buf_t *b, unsigned rd_w, unsigned vn);
void a64_emit_fcvtzu_s_to_w(a64_buf_t *b, unsigned rd_w, unsigned vn);
void a64_emit_fcvtzs_d_to_w(a64_buf_t *b, unsigned rd_w, unsigned vn);
void a64_emit_fcvtzu_d_to_w(a64_buf_t *b, unsigned rd_w, unsigned vn);
void a64_emit_scvtf_w_to_s(a64_buf_t *b, unsigned vd, unsigned rn_w);
void a64_emit_ucvtf_w_to_s(a64_buf_t *b, unsigned vd, unsigned rn_w);
void a64_emit_scvtf_w_to_d(a64_buf_t *b, unsigned vd, unsigned rn_w);
void a64_emit_ucvtf_w_to_d(a64_buf_t *b, unsigned vd, unsigned rn_w);

/* Exclusives & barriers */
void a64_emit_ldxr_b(a64_buf_t *b, unsigned rt_w, unsigned rn_x);
void a64_emit_stxr_b(a64_buf_t *b, unsigned rs_w, unsigned rt_w, unsigned rn_x);
void a64_emit_ldxr_h(a64_buf_t *b, unsigned rt_w, unsigned rn_x);
void a64_emit_stxr_h(a64_buf_t *b, unsigned rs_w, unsigned rt_w, unsigned rn_x);
void a64_emit_ldxr_w(a64_buf_t *b, unsigned rt_w, unsigned rn_x);
void a64_emit_stxr_w(a64_buf_t *b, unsigned rs_w, unsigned rt_w, unsigned rn_x);
void a64_emit_ldxr_x(a64_buf_t *b, unsigned rt_x, unsigned rn_x);
void a64_emit_stxr_x(a64_buf_t *b, unsigned rs_w, unsigned rt_x, unsigned rn_x);
void a64_emit_clrex(a64_buf_t *b);
void a64_emit_dmb_ish(a64_buf_t *b);
void a64_emit_dsb_ish(a64_buf_t *b);
void a64_emit_isb(a64_buf_t *b);

/* Branches */
size_t a64_emit_b_cond_placeholder(a64_buf_t *b, unsigned cond);
void   a64_patch_b_cond(a64_buf_t *b, size_t patch_idx, size_t target_idx);
size_t a64_emit_cbz_w_placeholder(a64_buf_t *b, bool is_cbnz, unsigned rt);
void   a64_patch_cbz_w(a64_buf_t *b, size_t patch_idx, size_t target_idx);
void   a64_emit_ret(a64_buf_t *b);

/* Block-exit chaining sequences (RAS/IBTC dispatch on the mips32_ctx_t
 * layout) arrive with src/dbt/ in Phase 2. */

#endif /* A64_EMIT_H */
