/*
 * src/interp/interp.h — lane-internal helpers for the integer reference
 * interpreter (Phase 1, lane L1b).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Only src/interp/interp.c includes this header.  All cross-lane
 * interaction goes through the frozen contracts in src/mips32rt.h
 * (mips_decode/mips_fetch, guest_ld/st, mips_syscall, mips_fault,
 * mips_is_be).  No FP/COP1 state is touched here (Phase 3 owns it).
 *
 * Interface assumptions (implemented by lanes L1a/L1c, recorded here so
 * the RC1 integration can verify them):
 * - mips_fetch returns 0 with *word set, or MIPS_FAULT on a bad pc.
 * - guest_ld/st return 0 on success and MIPS_FAULT on fault; the
 *   aligned-only variants fault on misaligned input, so interp checks
 *   alignment first and reports mips_fault with the data address.
 * - mips_syscall performs the O32 call including its $v0/$a3 writeback,
 *   leaves ctx->pc alone for a continuing call (interp advances it), and
 *   either sets ctx->exit_reason (guest exit / fatal fault) or returns
 *   nonzero status on failure.
 *
 * interp_step/interp_run return contract:
 * - 0 continues, MIPS_FAULT stops after mips_fault recorded EXIT_FAULT,
 *   1 stops with ctx->exit_reason already set (guest exit path).
 */

#ifndef MIPS32RT_INTERP_H
#define MIPS32RT_INTERP_H

#include <stdint.h>

#include "mips32rt.h"

/* $0 is hardwired zero: every write through this helper drops r == 0. */
static inline void interp_set_reg(mips32_ctx_t *ctx, unsigned r, uint32_t v)
{
    if (r != MIPS32_REG_ZERO) {
        ctx->gpr[r] = v;
    }
}

/* True when the decoded instruction transfers control with a delay slot:
 * J/JAL, all (likely and non-likely) integer branches, JR/JALR.  Traps,
 * SYSCALL/BREAK and SYNCI are not control transfers (no delay slot). */
static inline int interp_is_control(const mips_dec_t *d)
{
    switch (d->op) {
    case 0x02u: /* J */
    case 0x03u: /* JAL */
    case 0x04u: /* BEQ */
    case 0x05u: /* BNE */
    case 0x06u: /* BLEZ */
    case 0x07u: /* BGTZ */
    case 0x14u: /* BEQL */
    case 0x15u: /* BNEL */
    case 0x16u: /* BLEZL */
    case 0x17u: /* BGTZL */
        return 1;
    case 0x01u: /* REGIMM */
        switch (d->rt) {
        case 0x00u: /* BLTZ */
        case 0x01u: /* BGEZ */
        case 0x02u: /* BLTZL */
        case 0x03u: /* BGEZL */
        case 0x10u: /* BLTZAL */
        case 0x11u: /* BGEZAL */
        case 0x12u: /* BLTZALL */
        case 0x13u: /* BGEZALL */
            return 1;
        default:
            return 0;
        }
    case 0x00u: /* SPECIAL */
        return d->funct == 0x08u || d->funct == 0x09u; /* JR / JALR */
    default:
        return 0;
    }
}

#endif /* MIPS32RT_INTERP_H */
