/*
 * src/dbt/emit_mem.c -- AArch64 memory emitter: EA, aligned/unaligned
 * loads/stores, LL/SC (Phase 2, RC-U3).
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stddef.h>
#include <stdint.h>

#include "mips32rt.h"
#include "rt32/a64_emit.h"
#include "interp/decode.h"
#include "dbt/emit_priv.h"

/* w22 = rs + simm (guest effective address, 32-bit wrap). */
void emit_ea(a64_buf_t *b, unsigned rs, int32_t simm)
{
    int h = (rs == MIPS32_REG_ZERO) ? -1 : gpr_host(rs);

    if (h < 0 && rs == MIPS32_REG_ZERO) {
        a64_emit_mov_imm32(b, A64_ADDR, (uint32_t)simm);
    } else {
        if (h < 0) {
            a64_emit_ldr_imm_w(b, A64_ADDR, A64_XCTX, rs * 4U);
        } else {
            a64_emit_mov_w(b, A64_ADDR, (unsigned)h);
        }
        if (simm >= 0 && simm <= 4095) {
            a64_emit_add_imm_w(b, false, A64_ADDR, A64_ADDR,
                               (uint16_t)simm, 0U);
        } else if (simm < 0 && simm >= -4095) {
            a64_emit_sub_imm_w(b, false, A64_ADDR, A64_ADDR,
                               (uint16_t)(-simm), 0U);
        } else {
            a64_emit_mov_imm32(b, A64_TMP1, (uint32_t)simm);
            a64_emit_add_reg_w(b, false, A64_ADDR, A64_ADDR, A64_TMP1,
                               A64_SHIFT_LSL, 0U);
        }
    }
}

/* RC4: flush cached GPRs + record fpc in ctx->pc before a guest-memory
 * access that can host-fault (delivery reads ctx).  In a JR/JALR delay
 * slot ctx->next_pc also recovers from ctx->delay_target (the dynamic
 * jump target is otherwise only in x23, lost on a host fault). */
static void emit_sync_pc(a64_buf_t *b, uint32_t fpc, int ind_slot)
{
    emit_flush(b);
    a64_emit_mov_imm32(b, A64_TMP1, fpc);
    a64_emit_str_imm_w(b, A64_TMP1, A64_XCTX, MIPS32_CTX_PC_OFFSET);
    if (ind_slot != 0) {
        emit_load_delay_target(b, A64_TMP1);
        a64_emit_str_imm_w(b, A64_TMP1, A64_XCTX,
                           MIPS32_CTX_NEXT_PC_OFFSET);
    }
}

/* RC-U3-R2/R3 shared LL/SC epoch (see src/os/mem.c): 4096 64-bit
 * generations at G + EMIT_LL_EPOCH_OFFSET indexed by (addr >> 6) & 4095,
 * plus the 64-bit exclusion spinlock at G + EMIT_LL_LOCK_OFFSET.  Table
 * entry address forms as Xtab = x20 + (OFF + idx*8) with plain W/X
 * moves and adds (UBFM #6,#11 extracts the masked index).  Scratch
 * discipline: idx in W17 (never W16), table math in W16/X16.
 * A64_ADDR survives every sequence below.  All epoch traffic runs
 * under the spinlock (emit_ll_lock/unlock): plain X loads/stores are
 * then atomic and ordered, no LDXR/STXR retry loops needed. */
static void emit_epoch_addr(a64_buf_t *b, unsigned idx_w)
{
    a64_emit_mov_imm32(b, A64_TMP1, EMIT_LL_EPOCH_OFFSET);
    a64_emit_add_reg_w(b, false, A64_TMP1, A64_TMP1, idx_w,
                       A64_SHIFT_LSL, 3U);
    a64_emit_add_uxtw_x(b, A64_TMP1, A64_XG, A64_TMP1);
}

/* Xdst = table[idx_w] (clobbers W16/X16). */
static void emit_epoch_load(a64_buf_t *b, unsigned idx_w, unsigned dst_x)
{
    emit_epoch_addr(b, idx_w);
    a64_emit_ldr_imm_x(b, dst_x, A64_TMP1, 0U);
}

/* table[idx_w]++ (clobbers W16/X16 and W17 unless it is idx_w).
 * Caller must hold the LL spinlock. */
static void emit_epoch_bump_idx(a64_buf_t *b, unsigned idx_w)
{
    emit_epoch_addr(b, idx_w);
    a64_emit_ldr_imm_x(b, A64_TMP2, A64_TMP1, 0U);
    a64_emit_add_imm_x(b, false, A64_TMP2, A64_TMP2, 1U, 0U);
    a64_emit_str_imm_x(b, A64_TMP2, A64_TMP1, 0U);
}

/* Advance the lines covering the len-byte store at [addr_w, addr_w+len):
 * idx(first) always, plus idx(last) for len > 1 (a same-line double
 * bump is harmless: the SC compares for change, not count).  Clobbers
 * W16/W17/X16; addr_w survives. */
static void emit_epoch_bump_len(a64_buf_t *b, unsigned addr_w, unsigned len)
{
    a64_emit_ubfm_w(b, A64_TMP2, addr_w, 6U, 17U);
    emit_epoch_bump_idx(b, A64_TMP2);
    if (len > 1u) {
        a64_emit_add_imm_w(b, false, A64_TMP2, addr_w,
                           (uint16_t)(len - 1u), 0U);
        a64_emit_ubfm_w(b, A64_TMP2, A64_TMP2, 6U, 17U);
        emit_epoch_bump_idx(b, A64_TMP2);
    }
}

/* Record the full 64-bit table[(addr_w >> 6) & 4095] generation into
 * ctx->ll_epoch_snap (matches src/os/mem.c).  Clobbers W16/X16/X17;
 * addr_w survives. */
static void emit_epoch_record(a64_buf_t *b, unsigned addr_w)
{
    a64_emit_ubfm_w(b, A64_TMP2, addr_w, 6U, 17U);
    emit_epoch_load(b, A64_TMP2, A64_TMP2);
    a64_emit_mov_imm32(b, A64_TMP1, EMIT_LL_SEQ_OFFSET);
    a64_emit_add_uxtw_x(b, A64_TMP1, A64_XCTX, A64_TMP1);
    a64_emit_str_imm_x(b, A64_TMP2, A64_TMP1, 0U);
}

/* Lock protocol (RC-U3-r4): the spinlock word lives at G +
 * EMIT_LL_LOCK_OFFSET and the owning ctx at +8 (see src/os/mem.c).
 * Both engines lock the same word: LDXR/STXR here, C11 atomics
 * there. W30/x30 is NEVER touched (it holds the return address
 * across emitted blocks); X21 is spilled to an explicitly allocated
 * stack slot instead (async-signal-safe: never the red zone).
 * Clobbers X16/W17/X21 inside; everything else survives. */
static void emit_ll_lock(a64_buf_t *b)
{
    size_t retry;
    size_t ph_taken;
    size_t ph_fail;

    a64_emit_sub_imm_x(b, false, 31U, 31U, 16U, 0U);
    a64_emit_str_imm_x(b, A64_TMP3, 31U, 0U);
    a64_emit_mov_imm32(b, A64_TMP1, EMIT_LL_LOCK_OFFSET);
    a64_emit_add_uxtw_x(b, A64_TMP1, A64_XG, A64_TMP1);
    retry = b->count;
    a64_emit_ldxr_w(b, A64_TMP2, A64_TMP1);
    ph_taken = a64_emit_cbz_w_placeholder(b, true, A64_TMP2);
    a64_patch_cbz_w(b, ph_taken, retry);
    a64_emit_mov_imm32(b, A64_TMP2, 1U);
    a64_emit_stxr_w(b, A64_TMP3, A64_TMP2, A64_TMP1);
    ph_fail = a64_emit_cbz_w_placeholder(b, true, A64_TMP3);
    a64_patch_cbz_w(b, ph_fail, retry);
    a64_emit_str_imm_x(b, A64_XCTX, A64_TMP1, 8U);
    a64_emit_dmb_ish(b);
    a64_emit_ldr_imm_x(b, A64_TMP3, 31U, 0U);
    a64_emit_add_imm_x(b, false, 31U, 31U, 16U, 0U);
}

/* Release: clear owner, then the lock word, with release ordering.
 * Recomputes its address locally; X16 is the only scratch used. */
static void emit_ll_unlock(a64_buf_t *b)
{
    a64_emit_mov_imm32(b, A64_TMP1, EMIT_LL_LOCK_OFFSET);
    a64_emit_add_uxtw_x(b, A64_TMP1, A64_XG, A64_TMP1);
    a64_emit_dmb_ish(b);
    a64_emit_str_imm_x(b, A64_ZR, A64_TMP1, 8U);
    a64_emit_str_imm_w(b, A64_ZR, A64_TMP1, 0U);
}

/* Alignment guard (fault info = runtime address in w22).  Linux MIPS
 * TIF_FIXADE: when ctx->fixade_enabled is set the misaligned access is
 * not an address error; exit SINGLE_STEP (info = address) so the
 * dispatcher re-executes it via interp_step and resumes DBT.  With
 * FIXADE clear the AdEL fault exits inline as before. */
static void emit_align_fault(a64_buf_t *b, unsigned mask_bits, uint32_t fpc,
                             int ind_slot)
{
    size_t ph_mis, ph_fix;
    size_t ph_fault;

    a64_emit_ubfm_w(b, A64_TMP1, A64_ADDR, 0U, mask_bits);
    ph_mis = a64_emit_cbz_w_placeholder(b, true, A64_TMP1);
    ph_fix = a64_emit_b_cond_placeholder(b, A64_COND_AL);
    a64_patch_cbz_w(b, ph_mis, b->count);
    emit_flush(b);
    if (ind_slot != 0) {
        a64_emit_mov_imm32(b, A64_TMP1, fpc);
        a64_emit_str_imm_w(b, A64_TMP1, A64_XCTX, MIPS32_CTX_PC_OFFSET);
        emit_load_delay_target(b, A64_TMP1);
        a64_emit_str_imm_w(b, A64_TMP1, A64_XCTX,
                           MIPS32_CTX_NEXT_PC_OFFSET);
    } else {
        a64_emit_mov_imm32(b, A64_TMP1, fpc);
        a64_emit_str_imm_w(b, A64_TMP1, A64_XCTX, MIPS32_CTX_PC_OFFSET);
        a64_emit_mov_imm32(b, A64_TMP1, fpc + 4U);
        a64_emit_str_imm_w(b, A64_TMP1, A64_XCTX,
                           MIPS32_CTX_NEXT_PC_OFFSET);
    }
    a64_emit_mov_imm32(b, A64_TMP1, EMIT_FIXADE_OFFSET);
    a64_emit_add_uxtw_x(b, A64_TMP1, A64_XCTX, A64_TMP1);
    a64_emit_ldrb_imm_w(b, A64_TMP1, A64_TMP1, 0U);
    ph_fault = a64_emit_cbz_w_placeholder(b, false, A64_TMP1);
    a64_emit_mov_w(b, 1U, A64_ADDR);
    a64_emit_mov_imm32(b, 0U, MIPS32_EXIT_SINGLE_STEP);
    a64_emit_ret(b);
    a64_patch_cbz_w(b, ph_fault, b->count);
    a64_emit_mov_imm32(b, 0U, MIPS32_EXIT_FAULT);
    a64_emit_mov_w(b, 1U, A64_ADDR);
    a64_emit_ret(b);
    a64_patch_b_cond(b, ph_fix, b->count);
}

/* Ordinary stores break a same-word LL reservation (the later SC then
 * fails its llbit/lladdr/llval checks; spurious failure is always
 * legal).  SW compares the full word address; sub-word stores compare
 * word indices, which is exact for aligned halfwords, single bytes,
 * and same-word byte groups. */
static void emit_reservation_break(a64_buf_t *b, unsigned addr_w, int exact)
{
    size_t ph_keep;
    size_t ph_same;

    a64_emit_ldrb_imm_w(b, A64_TMP1, A64_XCTX, MIPS32_CTX_LLBIT_OFFSET);
    ph_keep = a64_emit_cbz_w_placeholder(b, false, A64_TMP1);
    a64_emit_ldr_imm_w(b, A64_TMP2, A64_XCTX, MIPS32_CTX_LLADDR_OFFSET);
    if (exact != 0) {
        a64_emit_sub_reg_w(b, true, A64_ZR, addr_w, A64_TMP2,
                           A64_SHIFT_LSL, 0U);
    } else {
        a64_emit_shift_imm_w(b, A64_TMP2, A64_TMP2, A64_SHIFT_LSR, 2U,
                             false, NULL);
        a64_emit_ubfm_w(b, A64_TMP1, addr_w, 2U, 31U);
        a64_emit_sub_reg_w(b, true, A64_ZR, A64_TMP1, A64_TMP2,
                           A64_SHIFT_LSL, 0U);
    }
    ph_same = a64_emit_b_cond_placeholder(b, A64_COND_NE);
    a64_emit_strb_imm_w(b, A64_ZR, A64_XCTX, MIPS32_CTX_LLBIT_OFFSET);
    a64_patch_b_cond(b, ph_same, b->count);
    a64_patch_cbz_w(b, ph_keep, b->count);
}

/* Aligned LB/LH/LW/LBU/LHU/SB/SH/SW fast path (EA already in w22). */
void emit_mem_aligned(a64_buf_t *b, const mips_dec_t *d, uint32_t fpc,
                      int be, int ind_slot)
{
    unsigned rt = d->rt, v, dst;
    int h;

    emit_sync_pc(b, fpc, ind_slot);
    h = gpr_host(rt);
    dst = (h >= 0) ? (unsigned)h : A64_TMP1;
    switch (d->op) {
    case MIPS_OP_LB: case MIPS_OP_LBU:
        if (d->op == MIPS_OP_LB) {
            a64_emit_guest_ldrsb_w(b, dst, A64_ADDR);
        } else {
            a64_emit_guest_ldrb_w(b, dst, A64_ADDR);
        }
        put_rd(b, rt, dst);
        return;
    case MIPS_OP_LH: case MIPS_OP_LHU:
        emit_align_fault(b, 0U, fpc, ind_slot);
        a64_emit_guest_ldrh_w(b, dst, A64_ADDR);
        if (be != 0) {
            a64_emit_rev16_w(b, dst, dst);
        }
        if (d->op == MIPS_OP_LH) {
            a64_emit_sbfm_w(b, dst, dst, 0U, 15U);
        }
        put_rd(b, rt, dst);
        return;
    case MIPS_OP_LW:
        emit_align_fault(b, 1U, fpc, ind_slot);
        a64_emit_guest_ldr_w(b, dst, A64_ADDR);
        if (be != 0) {
            a64_emit_rev_w(b, dst, dst);
        }
        put_rd(b, rt, dst);
        return;
    case MIPS_OP_SB:
        emit_ll_lock(b);
        a64_emit_guest_strb_w(b, op_val(b, rt, A64_TMP1), A64_ADDR);
        emit_epoch_bump_len(b, A64_ADDR, 1u);
        emit_reservation_break(b, A64_ADDR, 0);
        emit_ll_unlock(b);
        return;
    case MIPS_OP_SH: case MIPS_OP_SW:
        /* The alignment guard runs first: on a misaligned exit the
         * lock must never be taken (its RET paths skip unlock). */
        emit_align_fault(b, (d->op == MIPS_OP_SH) ? 0U : 1U, fpc,
                         ind_slot);
        emit_ll_lock(b);
        /* TMP2: the check below clobbers TMP1. */
        v = op_val(b, rt, A64_TMP2);
        if (be == 0) {
            if (d->op == MIPS_OP_SH) {
                a64_emit_guest_strh_w(b, v, A64_ADDR);
            } else {
                a64_emit_guest_str_w(b, v, A64_ADDR);
            }
            emit_epoch_bump_len(b, A64_ADDR,
                                (d->op == MIPS_OP_SW) ? 4u : 2u);
            emit_reservation_break(b, A64_ADDR,
                                   (d->op == MIPS_OP_SW) ? 1 : 0);
            emit_ll_unlock(b);
            return;
        }
        if (d->op == MIPS_OP_SH) {
            a64_emit_rev16_w(b, A64_TMP1, v);
        } else {
            a64_emit_rev_w(b, A64_TMP1, v);
        }
        if (d->op == MIPS_OP_SH) {
            a64_emit_guest_strh_w(b, A64_TMP1, A64_ADDR);
        } else {
            a64_emit_guest_str_w(b, A64_TMP1, A64_ADDR);
        }
        emit_epoch_bump_len(b, A64_ADDR, (d->op == MIPS_OP_SW) ? 4u : 2u);
        emit_reservation_break(b, A64_ADDR,
                               (d->op == MIPS_OP_SW) ? 1 : 0);
        emit_ll_unlock(b);
        return;
    default:
        break;
    }
}

/* E05 byte position (0 = LSB) of memory byte i for the k-th offset. */
static unsigned merge_pos(unsigned op, int be, unsigned i, unsigned k)
{
    if (op == MIPS_OP_LWL || op == MIPS_OP_SWL) {
        return (be != 0) ? (3U - (i - k)) : (3U - k + i);
    }
    return (be != 0) ? (k - i) : (i - k);
}

/* LWL/LWR/SWL/SWR: 4-way k dispatch, straight-line byte paths (E05).
 * ind_slot threads through to the fault sync so a JR/JALR delay-slot
 * access recovers next_pc from ctx->delay_target. */
void emit_mem_unaligned(a64_buf_t *b, const mips_dec_t *d, uint32_t fpc,
                        int be, int ind_slot)
{
    unsigned rt = d->rt, lo, hi, i, k, o;
    int is_load = (d->op == MIPS_OP_LWL || d->op == MIPS_OP_LWR);
    int left = (d->op == MIPS_OP_LWL || d->op == MIPS_OP_SWL);
    size_t ph_cbz[3], ph_end[3];

    emit_sync_pc(b, fpc, ind_slot);
    /* Lock before the k dispatch so every offset path (0-3) holds it;
     * acquiring inside the loop body would let offsets 0-2 skip it. */
    if (is_load == 0) {
        emit_ll_lock(b);
    }
    a64_emit_ubfm_w(b, A64_TMP1, A64_ADDR, 0U, 1U);
    a64_emit_shift_imm_w(b, A64_TMP3, A64_ADDR, A64_SHIFT_LSR, 2U, false,
                         NULL);
    a64_emit_shift_imm_w(b, A64_TMP3, A64_TMP3, A64_SHIFT_LSL, 2U, false,
                         NULL);
    for (k = 0U; k < 3U; k++) {
        ph_cbz[k] = a64_emit_cbz_w_placeholder(b, false, A64_TMP1);
        a64_emit_sub_imm_w(b, true, A64_TMP1, A64_TMP1, 1U, 0U);
    }
    /* k=3,0,1,2: fall-through enters k=3. */
    for (o = 0U, k = 3U; o < 4U; o++, k = (o == 1U) ? 0U : k + 1U) {
        if (k < 3U) {
            a64_patch_cbz_w(b, ph_cbz[k], b->count);
        }
        if (left != 0) {
            lo = (be != 0) ? k : 0U;
            hi = (be != 0) ? 3U : k;
        } else {
            lo = (be != 0) ? 0U : k;
            hi = (be != 0) ? k : 3U;
        }
        if (is_load != 0) {
            unsigned acc = op_val(b, rt, A64_TMP2);

            if (acc != A64_TMP2) {
                a64_emit_mov_w(b, A64_TMP2, acc);
            }
            for (i = lo; i <= hi; i++) {
                unsigned pos = merge_pos(d->op, be, i, k);

                a64_emit_add_imm_w(b, false, A64_ADDR, A64_TMP3,
                                   (uint16_t)i, 0U);
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

                a64_emit_add_imm_w(b, false, A64_ADDR, A64_TMP3,
                                   (uint16_t)i, 0U);
                if (pos == 0U) {
                    a64_emit_mov_w(b, A64_TMP1, v);
                } else {
                    a64_emit_shift_imm_w(b, A64_TMP1, v, A64_SHIFT_LSR,
                                         8U * pos, false, NULL);
                }
                a64_emit_guest_strb_w(b, A64_TMP1, A64_ADDR);
            }
        }
        if (o < 3U) {
            ph_end[o] = a64_emit_b_cond_placeholder(b, A64_COND_AL);
        }
    }
    for (o = 0U; o < 3U; o++) {
        a64_patch_b_cond(b, ph_end[o], b->count);
    }
    if (is_load == 0) {
        /* TMP3 still holds the aligned word base: same-word stores
         * break a live LL reservation.  Written bytes sit inside
         * [pa, pa + 4), so bump both lines in case the group spans a
         * 64-byte boundary. */
        emit_epoch_bump_len(b, A64_TMP3, 4u);
        emit_reservation_break(b, A64_TMP3, 0);
        emit_ll_unlock(b);
    }
}

/* LWC1/SWC1/LDC1/SDC1 (Wave P lane P4): COP1 memory moves through the
 * same direct-window guest accessors as integer loads/stores (EA already
 * in w22).  Semantics mirror interp fpmove_mem: LWC1/SWC1 need word
 * alignment, LDC1/SDC1 doubleword alignment (AdEL/AdES via
 * emit_align_fault, honoring FIXADE exactly like integer LW/SW); S-word
 * ops touch only the low 32 bits of the fpr slot (a 32-bit ctx store
 * preserves the upper lane); BE guests byte-swap around the host-endian
 * slot.  Stores serialize under the LL spinlock and bump/break exactly
 * like integer SW (SDC1 covers both touched words). */
void emit_fp_mem(a64_buf_t *b, const mips_dec_t *d, uint32_t fpc,
                 int be, int ind_slot)
{
    unsigned fs = d->rt;
    uint32_t off = MIPS32_CTX_FPR_OFFSET + fs * 8U;

    emit_sync_pc(b, fpc, ind_slot);
    switch (d->op) {
    case 0x31u: /* LWC1 */
        emit_align_fault(b, 1U, fpc, ind_slot);
        a64_emit_guest_ldr_w(b, A64_TMP1, A64_ADDR);
        if (be != 0) {
            a64_emit_rev_w(b, A64_TMP1, A64_TMP1);
        }
        a64_emit_str_imm_w(b, A64_TMP1, A64_XCTX, off);
        return;
    case 0x39u: /* SWC1 */
        emit_align_fault(b, 1U, fpc, ind_slot);
        /* Data loads after the lock: emit_ll_lock clobbers W16/W17. */
        emit_ll_lock(b);
        a64_emit_ldr_imm_w(b, A64_TMP1, A64_XCTX, off);
        if (be != 0) {
            a64_emit_rev_w(b, A64_TMP1, A64_TMP1);
        }
        a64_emit_guest_str_w(b, A64_TMP1, A64_ADDR);
        emit_epoch_bump_len(b, A64_ADDR, 4u);
        emit_reservation_break(b, A64_ADDR, 1);
        emit_ll_unlock(b);
        return;
    case 0x35u: /* LDC1 */
        emit_align_fault(b, 2U, fpc, ind_slot);
        a64_emit_guest_ldrd_w(b, A64_TMP1, A64_TMP2, A64_ADDR);
        if (be != 0) {
            a64_emit_rev_w(b, A64_TMP1, A64_TMP1);
            a64_emit_rev_w(b, A64_TMP2, A64_TMP2);
            a64_emit_str_imm_w(b, A64_TMP2, A64_XCTX, off);
            a64_emit_str_imm_w(b, A64_TMP1, A64_XCTX, off + 4U);
        } else {
            a64_emit_str_imm_w(b, A64_TMP1, A64_XCTX, off);
            a64_emit_str_imm_w(b, A64_TMP2, A64_XCTX, off + 4U);
        }
        return;
    case 0x3du: /* SDC1 */
        emit_align_fault(b, 2U, fpc, ind_slot);
        /* Data loads after the lock: emit_ll_lock clobbers W16/W17. */
        emit_ll_lock(b);
        a64_emit_ldr_imm_w(b, A64_TMP1, A64_XCTX, off);
        a64_emit_ldr_imm_w(b, A64_TMP2, A64_XCTX, off + 4U);
        if (be != 0) {
            a64_emit_rev_w(b, A64_TMP1, A64_TMP1);
            a64_emit_rev_w(b, A64_TMP2, A64_TMP2);
        }
        /* W21 is dead here (no FCSR traffic in this op). */
        a64_emit_add_imm_w(b, false, A64_TMP3, A64_ADDR, 4U, 0U);
        if (be != 0) {
            a64_emit_guest_str_w(b, A64_TMP2, A64_ADDR);
            a64_emit_guest_str_w(b, A64_TMP1, A64_TMP3);
        } else {
            a64_emit_guest_str_w(b, A64_TMP1, A64_ADDR);
            a64_emit_guest_str_w(b, A64_TMP2, A64_TMP3);
        }
        emit_epoch_bump_len(b, A64_ADDR, 8u);
        emit_reservation_break(b, A64_ADDR, 0);
        emit_reservation_break(b, A64_TMP3, 0);
        emit_ll_unlock(b);
        return;
    default:
        break;
    }
}

/* LL: aligned load + llbit/lladdr/llval record (align guard syncs). */
void emit_ll(a64_buf_t *b, const mips_dec_t *d, uint32_t fpc, int be,
             int ind_slot)
{
    emit_sync_pc(b, fpc, ind_slot);
    emit_align_fault(b, 1U, fpc, ind_slot);
    /* RC-U3-R2: snapshot the line epoch for the later SC check (first:
     * TMP1/TMP2 are still free and the value load below reuses them). */
    emit_epoch_record(b, A64_ADDR);
    a64_emit_guest_ldr_w(b, A64_TMP1, A64_ADDR);
    if (be != 0) {
        a64_emit_rev_w(b, A64_TMP1, A64_TMP1);
    }
    put_rd(b, d->rt, A64_TMP1);
    a64_emit_mov_imm32(b, A64_TMP2, 1U);
    a64_emit_strb_imm_w(b, A64_TMP2, A64_XCTX, MIPS32_CTX_LLBIT_OFFSET);
    a64_emit_str_imm_w(b, A64_ADDR, A64_XCTX, MIPS32_CTX_LLADDR_OFFSET);
    a64_emit_str_imm_w(b, A64_TMP1, A64_XCTX, MIPS32_CTX_LLVAL_OFFSET);
}

/* SC: verify-then-commit under the LL spinlock (RC-U3-r3).  The lock
 * makes the epoch check, the value compare, the data store, and the
 * epoch bump one atomic unit: no ordinary store can slip between the
 * verification and the commit, closing the same-value race that a
 * check-then-CAS leaves open.  Plain loads/stores are used throughout
 * (no LDXR/STXR retry loop is needed once stores are serialized).
 * Register plan: data in TMP3-or-mapped (untouched), A64_ADDR holds
 * the guest VA into the epoch verify, X24 the host address from then
 * on; TMP1/TMP2/X16/X17 are scratch (never x30: it holds the return
 * address across emitted blocks). The snapshot load reuses X16 after
 * the entry address is dead; the bump recomputes it. */
void emit_sc(a64_buf_t *b, const mips_dec_t *d, uint32_t fpc, int be,
             int ind_slot)
{
    unsigned data = op_val(b, d->rt, A64_TMP3);
    size_t ph_fail1, ph_fail2, ph_fail3, ph_fail4;
    size_t ph_done;

    emit_sync_pc(b, fpc, ind_slot);
    emit_align_fault(b, 1U, fpc, ind_slot);
    a64_emit_add_uxtw_x(b, 24U, A64_XG, A64_ADDR);
    emit_ll_lock(b);
    /* Probe + value load (faults like the old LDXR did, even when the
     * reservation below is dead). A host fault here abandons the
     * block; mips_ll_abandon releases the lock for the faulting ctx. */
    a64_emit_ldr_imm_w(b, A64_TMP1, 24U, 0U);
    a64_emit_ldrb_imm_w(b, A64_TMP2, A64_XCTX, MIPS32_CTX_LLBIT_OFFSET);
    ph_fail1 = a64_emit_cbz_w_placeholder(b, false, A64_TMP2);
    /* The reservation is address-specific: a live bit for another word
     * must not let this SC succeed (matches interp lladdr check). */
    a64_emit_ldr_imm_w(b, A64_TMP2, A64_XCTX, MIPS32_CTX_LLADDR_OFFSET);
    a64_emit_sub_reg_w(b, true, A64_ZR, A64_ADDR, A64_TMP2,
                       A64_SHIFT_LSL, 0U);
    ph_fail2 = a64_emit_b_cond_placeholder(b, A64_COND_NE);
    if (be != 0) {
        a64_emit_rev_w(b, A64_TMP1, A64_TMP1);
    }
    a64_emit_ldr_imm_w(b, A64_TMP2, A64_XCTX, MIPS32_CTX_LLVAL_OFFSET);
    a64_emit_sub_reg_w(b, true, A64_ZR, A64_TMP1, A64_TMP2,
                       A64_SHIFT_LSL, 0U);
    ph_fail3 = a64_emit_b_cond_placeholder(b, A64_COND_NE);
    /* Epoch gate: the full 64-bit table entry must equal the LL
     * snapshot in ctx->ll_epoch_snap.  Verified BEFORE the store, so
     * a failed SC never commits a write. */
    a64_emit_ubfm_w(b, A64_TMP2, A64_ADDR, 6U, 17U);
    a64_emit_mov_imm32(b, A64_TMP1, EMIT_LL_EPOCH_OFFSET);
    a64_emit_add_reg_w(b, false, A64_TMP1, A64_TMP1, A64_TMP2,
                       A64_SHIFT_LSL, 3U);
    a64_emit_add_uxtw_x(b, A64_TMP1, A64_XG, A64_TMP1);
    a64_emit_ldr_imm_x(b, A64_TMP2, A64_TMP1, 0U);
    a64_emit_mov_imm32(b, A64_TMP1, EMIT_LL_SEQ_OFFSET);
    a64_emit_add_uxtw_x(b, A64_TMP1, A64_XCTX, A64_TMP1);
    a64_emit_ldr_imm_x(b, A64_TMP1, A64_TMP1, 0U);
    a64_emit_eor_reg_x(b, A64_TMP2, A64_TMP2, A64_TMP1);
    ph_fail4 = a64_emit_cbz_x_placeholder(b, true, A64_TMP2);
    if (be != 0) {
        a64_emit_rev_w(b, A64_TMP3, data);
        data = A64_TMP3;
    }
    a64_emit_str_imm_w(b, data, 24U, 0U);
    emit_epoch_bump_len(b, A64_ADDR, 4U);
    emit_ll_unlock(b);
    a64_emit_mov_imm32(b, A64_TMP1, 1U);
    ph_done = a64_emit_b_cond_placeholder(b, A64_COND_AL);
    a64_patch_cbz_w(b, ph_fail1, b->count);
    a64_patch_b_cond(b, ph_fail2, b->count);
    a64_patch_b_cond(b, ph_fail3, b->count);
    a64_patch_cbz_x(b, ph_fail4, b->count);
    emit_ll_unlock(b);
    a64_emit_mov_imm32(b, A64_TMP1, 0U);
    a64_patch_b_cond(b, ph_done, b->count);
    a64_emit_strb_imm_w(b, A64_ZR, A64_XCTX, MIPS32_CTX_LLBIT_OFFSET);
    put_rd(b, d->rt, A64_TMP1);
}
