/*
 * src/interp/fp.h — FPU reference interpreter interface (Phase 3, lane L3a).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * fp_exec() implements the COP1 floating-point instructions that
 * fpmove.c deliberately leaves faulting: S/D arithmetic (ADD/SUB/MUL/
 * DIV/SQRT), ABS/NEG/MOV, conversions (CVT.*, ROUND/TRUNC/CEIL/FLOOR),
 * C.cond comparisons, BC1F/BC1T/BC1FL/BC1TL branches, MFHC1/MTHC1, and
 * the W/L integer-source converts.  Plain moves (MFC1/MTC1/CFC1/CTC1,
 * LWC1/SWC1/LDC1/SDC1) stay in fpmove.c and are never duplicated here;
 * the interp.c COP1 case tries fpmove_cop1() first and only falls
 * through to fp_exec() for the rest.  DMFC1/DMTC1 fault (MIPS32 has no
 * 64-bit GPRs); paired-single (PS) faults as unimplemented.
 *
 * FCSR (FCR31) bit layout shared with the L3b emitter:
 *   bits 1:0 RM, 6:2 sticky flags (I,U,O,Z,V = bits 2,3,4,5,6),
 *   11:7 enables (I,U,O,Z,V = bits 7,8,9,10,11),
 *   17:12 causes (E + I,U,O,Z,V = bits 12,13,14,15,16; E is never set),
 *   bit 23 fcc0, bits 31:25 fcc7..1.  Bits 19:18 (ABS2008/NAN2008 under
 *   qemu 7.2, reset 0x000c0000 in 2008 mode) are read-only indicators;
 *   the executed NaN mode comes from ctx->nan2008 (E03: qemu selects it
 *   from ELF e_flags, not from FCSR writes).
 */

#ifndef MIPS32RT_INTERP_FP_H
#define MIPS32RT_INTERP_FP_H

#include <stdint.h>

#include "mips32rt.h"

/* FCSR field positions (SPEC 2.1 locked fcsr word, E03-verified numbers:
 * Cause.V = bit 16, Flags.V = bit 6, Enable.V = bit 11). */
#define MIPS_FP_FLAG_I  (1u << 2)
#define MIPS_FP_FLAG_U  (1u << 3)
#define MIPS_FP_FLAG_O  (1u << 4)
#define MIPS_FP_FLAG_Z  (1u << 5)
#define MIPS_FP_FLAG_V  (1u << 6)
#define MIPS_FP_CAUSE_I (1u << 12)
#define MIPS_FP_CAUSE_U (1u << 13)
#define MIPS_FP_CAUSE_O (1u << 14)
#define MIPS_FP_CAUSE_Z (1u << 15)
#define MIPS_FP_CAUSE_V (1u << 16)

/* FCC bit for condition code cc (0..7): cc0 lives in bit 23, ccN in
 * bit 24+N.  Shared with the L3b DBT emitter. */
static inline uint32_t fp_fcc_mask(unsigned cc)
{
    return (cc == 0u) ? (1u << 23) : (1u << (24u + cc));
}

/* FR-aware FPR accessors (M32-R7-1): FR=1 keeps one 64-bit lane per
 * register; FR=0 pairs even/odd low halves for D/L values (even holds
 * the low word, odd the high word) while single words stay in the
 * addressed lane's low half. MFHC1/MTHC1 high halves stay flat
 * (E03 qemu round-trip) and are untouched here. */
static inline uint64_t mips_fpr_get_d(const mips32_ctx_t *ctx, unsigned fd)
{
    if (ctx->fr_mode == 0u) {
        unsigned e = fd & ~1u;
        uint32_t lo = (uint32_t)ctx->fpr[e];
        uint32_t hi = (uint32_t)ctx->fpr[e + 1u];
        return ((uint64_t)hi << 32) | (uint64_t)lo;
    }
    return ctx->fpr[fd];
}

static inline void mips_fpr_set_d_raw(mips32_ctx_t *ctx, unsigned fd,
                                      uint64_t v)
{
    if (ctx->fr_mode == 0u) {
        unsigned e = fd & ~1u;
        ctx->fpr[e] = (ctx->fpr[e] & 0xFFFFFFFF00000000ULL) |
                      (uint32_t)v;
        ctx->fpr[e + 1u] = (ctx->fpr[e + 1u] & 0xFFFFFFFF00000000ULL) |
                           (uint32_t)(v >> 32);
        return;
    }
    ctx->fpr[fd] = v;
}

static inline uint32_t mips_fpr_get_w(const mips32_ctx_t *ctx, unsigned fs)
{
    return (uint32_t)ctx->fpr[fs];
}

static inline void mips_fpr_set_w_raw(mips32_ctx_t *ctx, unsigned fd,
                                      uint32_t v)
{
    ctx->fpr[fd] = (ctx->fpr[fd] & 0xFFFFFFFF00000000ULL) | v;
}

/* FR=0 even-register rule for D/L (R7-1). */
static inline int fp_even(mips32_ctx_t *ctx, uint32_t pc, unsigned r)
{
    if (ctx->fr_mode == 0u && (r & 1u) != 0u) {
        mips_trap(ctx, 4, pc);
        return MIPS_FAULT;
    }
    return 0;
}

/*
 * Execute one COP1 floating-point instruction at guest pc.
 * Returns 0 (caller advances pc), 2 (ctx->pc already set: BC1 taken /
 * annulled path, caller keeps it), 1 (stop, exit_reason already set:
 * delay-slot syscall moved pc), or MIPS_FAULT (mips_fault already
 * recorded, e.g. trap-enabled FP exception or reserved encoding).
 */
int fp_exec(mips32_ctx_t *ctx, uint32_t pc, const mips_dec_t *d);

#endif /* MIPS32RT_INTERP_FP_H */
