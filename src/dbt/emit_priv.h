/*
 * src/dbt/emit_priv.h — Shared internals of the AArch64 integer emitter.
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Split from src/dbt/emit_int.c (line-limit split, no behavior change):
 * the memory subsystem lives in src/dbt/emit_mem.c while ALU/branch
 * emission stays in src/dbt/emit_int.c.  Both translation units share
 * the register-cache helpers and the C-tail field accessors below.
 */

#ifndef MIPS32RT_EMIT_PRIV_H
#define MIPS32RT_EMIT_PRIV_H

#include <stddef.h>
#include <stdint.h>

#include "mips32rt.h"
#include "rt32/a64_emit.h"
#include "interp/decode.h"

/* C-tail ctx fields beyond the LDR/STR imm12 reach (see mips32rt.h):
 * emitters materialize the offset and add it to x19 (xCtx). */
#define EMIT_FIXADE_OFFSET ((uint32_t)offsetof(mips32_ctx_t, fixade_enabled))
#define EMIT_DELAY_TARGET_OFFSET \
    ((uint32_t)offsetof(mips32_ctx_t, delay_target))
/* RC-U3-R2/R3 LL epoch snapshot: the full 64-bit generation in
 * ctx->ll_epoch_snap (struct tail; see src/os/mem.c). */
#define EMIT_LL_SEQ_OFFSET ((uint32_t)offsetof(mips32_ctx_t, ll_epoch_snap))
_Static_assert(offsetof(mips32_ctx_t, ll_epoch_snap) % 8u == 0u,
    "ll_epoch_snap must be 8-byte aligned for LDR Xt");
/* NOTE: the offset exceeds the 12-bit unsigned LDR range; emitters
 * materialize it with mov_imm32 + base add (see emit_epoch_record),
 * never as an immediate offset. */
/* Guest VA of the shared 32 KiB epoch table (G-relative, unmappable:
 * above MIPS32_TASK_SIZE_TOP).  JIT forms Xtab = x20 + (OFF + idx*8). */
#define EMIT_LL_EPOCH_OFFSET 0xFFFF0000u
/* Guest VA of the 64-bit LL exclusion spinlock: the first word after
 * the epoch table. JIT forms Xlock = x20 + LOCK_OFF. */
#define EMIT_LL_LOCK_OFFSET (0xFFFF0000u + 4096u * 8u)
/* Wave P4 ll_active flag: unused upper 32 bits of tab[4096] (lock word).
 * JIT tests ldrb Wt,[x20,wOff,uxtw] here; 0 skips all spinlock/DMB/epoch
 * traffic and runs only the plain guest store. */
#define EMIT_LL_ACTIVE_OFFSET (0xFFFF0000u + 4096u * 8u + 4u)

/* Register-cache core (src/dbt/emit_int.c). */
int      gpr_host(unsigned g);
unsigned op_val(a64_buf_t *b, unsigned g, unsigned tmp);
unsigned op_sp(a64_buf_t *b, unsigned g, unsigned tmp);
void     put_rd(a64_buf_t *b, unsigned g, unsigned src);
void     emit_flush(a64_buf_t *b);
/* Load ctx->delay_target (JR/JALR recovery) into dst. */
void     emit_load_delay_target(a64_buf_t *b, unsigned dst);
/* M32-R8-4: on an armed JALR rd==rs delay-slot exit, restore the jump
 * source from ctx->delay_target (no-op unless emit_branch armed it). */
void     emit_ind_link_restore(a64_buf_t *b);

/* Memory subsystem (src/dbt/emit_mem.c).  EA lands in w22 (A64_ADDR);
 * ind_slot is nonzero for JR/JALR delay slots (next_pc recovers from
 * ctx->delay_target instead of fpc + 4 on fault exits). */
void emit_ea(a64_buf_t *b, unsigned rs, int32_t simm);
void emit_mem_aligned(a64_buf_t *b, const mips_dec_t *d, uint32_t fpc,
                      int be, int ind_slot);
void emit_mem_unaligned(a64_buf_t *b, const mips_dec_t *d, uint32_t fpc,
                        int be, int ind_slot);
/* COP1 memory moves (Wave P lane P4): LWC1/SWC1/LDC1/SDC1. EA lands in
 * w22 (A64_ADDR) via emit_ea before the call. */
int emit_fp_mem(a64_buf_t *b, const mips_dec_t *d, uint32_t fpc, int be,
                int fr_mode, int ind_slot);
void emit_ll(a64_buf_t *b, const mips_dec_t *d, uint32_t fpc, int be,
             int ind_slot);
void emit_sc(a64_buf_t *b, const mips_dec_t *d, uint32_t fpc, int be,
             int ind_slot);

/* Wave P5/P13 FP batch predicates (emit_int.c gating): arith covers
 * COP1 S/D ADD/SUB/MUL/DIV/SQRT and COP1X MADD/MSUB/NMADD/NMSUB;
 * unary covers COP1 S/D MOV/ABS/NEG (sign-bit ops that never touch
 * FPSR/FPCR, so a deferred batch stays open across them); transparent
 * covers every instruction the next-FP-arithmetic lookahead may skip
 * (FP memory moves, unary ops, and the non-trapping integer ALU ops
 * that vfp_simd interleaves for pointer arithmetic).  Everything else
 * (CFC1/CTC1/MFC1/MTC1/BC1, C.cond.fmt, CVT.*, branches, traps,
 * trapping ALU, unknown/D2 words) stops the scan. */
static inline int fp_batch_is_arith(const mips_dec_t *d, int fr_mode)
{
    if (d == NULL) {
        return 0;
    }
    if (d->op == 0x11U) {
        if (d->rs != 16U && d->rs != 17U) {
            return 0;
        }
        if (d->funct > 0x04U) {
            return 0;
        }
        if (fr_mode == 0 && d->rs == 17U &&
            (((d->rd | d->sa | ((d->funct == 0x04U) ? 0U : d->rt)) & 1U) != 0U)) {
            return 0;
        }
        return 1;
    }
    if (d->op == 0x13U) {
        if ((d->funct & 0x26U) != 0x20U) {
            return 0;
        }
        if (fr_mode == 0 && (d->funct & 1U) != 0U &&
            (((d->rs | d->rt | d->rd | d->sa) & 1U) != 0U)) {
            return 0;
        }
        return 1;
    }
    return 0;
}

static inline int fp_batch_is_unary(const mips_dec_t *d, int fr_mode)
{
    if (d == NULL || d->op != 0x11U) {
        return 0;
    }
    if (d->rs != 16U && d->rs != 17U) {
        return 0;
    }
    if (d->funct < 0x05U || d->funct > 0x07U) {
        return 0;
    }
    if (fr_mode == 0 && d->rs == 17U && (((d->rd | d->sa) & 1U) != 0U)) {
        return 0;
    }
    return 1;
}

/* An FP batch starts on arithmetic and stays open across unary ops
 * while a later arithmetic op still needs the accumulated flags. */
static inline int fp_batch_starts(const mips_dec_t *d, int fr_mode)
{
    return fp_batch_is_arith(d, fr_mode) != 0 ||
        fp_batch_is_unary(d, fr_mode) != 0;
}

static inline int fp_batch_is_transparent(const mips_dec_t *d, int fr_mode)
{
    unsigned o;

    if (d == NULL) {
        return 0;
    }
    o = d->op;
    /* LWC1/LDC1/SWC1/SDC1: no FCSR interaction (double loads populate
     * the d16..d23 write-through cache, stores read it on hits). */
    if (o == 0x31U || o == 0x35U || o == 0x39U || o == 0x3DU) {
        if (fr_mode == 0 && (o == 0x35U || o == 0x3DU) &&
            (d->rt & 1U) != 0U) {
            return 0;
        }
        return 1;
    }
    if (o == 0x11U) {
        return fp_batch_is_unary(d, fr_mode);
    }
    /* Non-trapping integer ALU only (trapping ADD/SUB, MULT/DIV/MADD,
     * shifts with variable counts, loads/stores, and LUI stop the
     * scan: a fault or HI/LO write between batched ops ends the run). */
    if (o == MIPS_OP_ADDIU || o == MIPS_OP_SLTI || o == MIPS_OP_SLTIU ||
        o == MIPS_OP_ANDI || o == MIPS_OP_ORI || o == MIPS_OP_XORI) {
        return 1;
    }
    if (o != MIPS_OP_SPECIAL) {
        return 0;
    }
    switch (d->funct) {
    case MIPS_FUNCT_SLL:
    case MIPS_FUNCT_SRL:
    case MIPS_FUNCT_SRA:
    case MIPS_FUNCT_ADDU:
    case 0x23U: /* SUBU (no decode.h macro; cf. emit_int.c) */
    case MIPS_FUNCT_AND:
    case MIPS_FUNCT_OR:
    case MIPS_FUNCT_XOR:
    case MIPS_FUNCT_NOR:
    case MIPS_FUNCT_SLT:
    case MIPS_FUNCT_SLTU:
        return 1;
    default:
        return 0;
    }
}

#endif /* MIPS32RT_EMIT_PRIV_H */
