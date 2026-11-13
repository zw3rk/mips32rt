/*
 * src/interp/fpmove.c — FPR data-movement for the reference interpreter.
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Phase-1 subset only: LWC1/SWC1/LDC1/SDC1 and MFC1/MTC1/CFC1/CTC1 move
 * bits between memory, GPRs, fcr31 and the 32x64-bit FPR file WITHOUT
 * interpreting them (no arithmetic, no NaN/canonicalization rules).
 * glibc startup and sigsetjmp/siglongjmp need these moves; every FP
 * arithmetic opcode still faults for Phase 3 (src/interp/fp.c), which
 * refines FR=0/FR=1 pairing and Legacy/2008 NaN semantics (E03).
 *
 * LWC1/SWC1 require 4-byte alignment and LDC1/SDC1 8-byte alignment:
 * a misaligned address delivers an address-alignment fault via
 * mips_fault_align (never emulated, never a mapping fault); aligned
 * transfers move bytes through guest_ld/st8, endianness follows mips_is_be.
 */

#include <stdint.h>

#include "mips32rt.h"
#include "interp/fp.h"
#include "interp/interp.h"

/* Byte i (0 = lowest guest address) of a 32/64-bit FPR lane. */
static uint32_t lane_byte_u32(uint32_t v, unsigned i, int be)
{
    unsigned p = be ? (3u - i) : i;

    return (v >> (8u * p)) & 0xFFu;
}

static uint32_t lane_byte_u64(uint64_t v, unsigned i, int be)
{
    unsigned p = be ? (7u - i) : i;

    return (uint32_t)((v >> (8u * p)) & 0xFFu);
}

static uint32_t build_u32(const uint8_t m[4], int be)
{
    uint32_t v = 0u;
    unsigned i;

    for (i = 0u; i < 4u; i++) {
        unsigned p = be ? (3u - i) : i;

        v |= (uint32_t)m[i] << (8u * p);
    }
    return v;
}

static uint64_t build_u64(const uint8_t m[8], int be)
{
    uint64_t v = 0u;
    unsigned i;

    for (i = 0u; i < 8u; i++) {
        unsigned p = be ? (7u - i) : i;

        v |= (uint64_t)m[i] << (8u * p);
    }
    return v;
}

/* LWC1/SWC1/LDC1/SDC1: 0 ok, MIPS_FAULT for anything else (caller maps
 * the fault with the data address).  Guest access failures are recorded
 * by the mem layer itself. */
int fpmove_mem(mips32_ctx_t *ctx, const mips_dec_t *d)
{
    uint32_t addr = ctx->gpr[d->rs] + (uint32_t)d->simm;
    unsigned fs = d->rt;
    int be = mips_is_be(ctx);
    unsigned i;

    if (fs >= 32u) {
        return MIPS_FAULT;
    }
    /* MIPS32r2 AdEL/AdES: LWC1/SWC1 require word alignment, LDC1/SDC1
     * require doubleword alignment (verified against qemu-mipsel/qemu-mips
     * via test_p3_fpu unaligned-lwc1: SIGBUS sig=10 AdEL). Explicit
     * alignment faults, never mapping (M32-R7-6). */
    if ((d->op == 0x31u || d->op == 0x39u)) {
        if ((addr & 3u) != 0u) {
            mips_fault_align(ctx, addr);
            return MIPS_FAULT;
        }
    }
    if ((d->op == 0x35u || d->op == 0x3Du)) {
        if ((addr & 7u) != 0u) {
            mips_fault_align(ctx, addr);
            return MIPS_FAULT;
        }
    }
    switch (d->op) {
    case 0x31u: { /* LWC1: low 32 bits, upper lane preserved (FR-agnostic) */
        uint8_t m[4];

        for (i = 0u; i < 4u; i++) {
            uint32_t v = 0u;

            if (guest_ld8(ctx, addr + i, &v) != 0) {
                return MIPS_FAULT;
            }
            m[i] = (uint8_t)v;
        }
        ctx->fpr[fs] = (ctx->fpr[fs] & 0xFFFFFFFF00000000ULL) | build_u32(m, be);
        return 0;
    }
    case 0x39u: { /* SWC1 */
        uint32_t v = (uint32_t)ctx->fpr[fs];

        for (i = 0u; i < 4u; i++) {
            if (guest_st8(ctx, addr + i, lane_byte_u32(v, i, be)) != 0) {
                return MIPS_FAULT;
            }
        }
        return 0;
    }
    case 0x35u: { /* LDC1 (M32-R7-1: FR=0 splits across the pair) */
        uint64_t v;
        uint8_t m[8];
        for (i = 0u; i < 8u; i++) {
            uint32_t b = 0u;
            if (guest_ld8(ctx, addr + i, &b) != 0) {
                return MIPS_FAULT;
            }
            m[i] = (uint8_t)b;
        }
        v = build_u64(m, be);
        if (ctx->fr_mode == 0u) {
            if ((fs & 1u) != 0u) {
                mips_trap(ctx, 4, ctx->pc);
                return MIPS_FAULT;
            }
            mips_fpr_set_d_raw(ctx, fs, v);
        } else {
            ctx->fpr[fs] = v;
        }
        return 0;
    }
    case 0x3Du: { /* SDC1 (M32-R7-1: FR=0 combines the pair lows) */
        uint64_t v = (ctx->fr_mode == 0u) ? mips_fpr_get_d(ctx, fs) : ctx->fpr[fs];
        if (ctx->fr_mode == 0u && (fs & 1u) != 0u) {
            mips_trap(ctx, 4, ctx->pc);
            return MIPS_FAULT;
        }
        for (i = 0u; i < 8u; i++) {
            if (guest_st8(ctx, addr + i, lane_byte_u64(v, i, be)) != 0) {
                return MIPS_FAULT;
            }
        }
        return 0;
    }
    default:
        return MIPS_FAULT;
    }
}

/* MFC1/MTC1/CFC1/CTC1: 0 ok, MIPS_FAULT otherwise (caller maps it). */
int fpmove_cop1(mips32_ctx_t *ctx, const mips_dec_t *d)
{
    unsigned rt = d->rt;
    unsigned fs = d->rd;

    if (rt >= 32u || fs >= 32u) {
        return MIPS_FAULT;
    }
    switch (d->rs) {
    case 0x00u: /* MFC1 */
        interp_set_reg(ctx, rt, (uint32_t)ctx->fpr[fs]);
        return 0;
    case 0x04u: /* MTC1: low 32 bits, upper lane preserved */
        ctx->fpr[fs] = (ctx->fpr[fs] & 0xFFFFFFFF00000000ULL) | ctx->gpr[rt];
        return 0;
    case 0x02u: { /* CFC1 (M32-R7-19: QEMU aliases 25/26/28). */
        uint32_t f = ctx->fcsr;
        if (fs == 31u) {
            interp_set_reg(ctx, rt, f);
            return 0;
        }
        if (fs == 0u) {
            interp_set_reg(ctx, rt, 0x00739300u);
            return 0;
        }
        if (fs == 25u) {
            interp_set_reg(ctx, rt, ((f >> 24) & 0xFEu) | ((f >> 23) & 1u));
            return 0;
        }
        if (fs == 26u) {
            interp_set_reg(ctx, rt, f & 0x0003F07Cu);
            return 0;
        }
        if (fs == 28u) {
            interp_set_reg(ctx, rt, (f & 0x00000F83u) | ((f >> 22) & 4u));
            return 0;
        }
        return MIPS_FAULT;
    }
    case 0x06u: { /* CTC1 (M32-R7-19: masks + aliases + pending check). */
        uint32_t v = ctx->gpr[rt];
        uint32_t f = ctx->fcsr;
        int32_t code = 7;
        if (fs == 31u) {
            f = (v & 0xFF81FFFFu) | (f & ~0xFF81FFFFu);
        } else if (fs == 0u) {
            return 0;
        } else if (fs == 25u) {
            if ((v & 0xFFFFFF00u) != 0u)
                return 0;
            f = (f & 0x017FFFFFu) | ((v & 0xFEu) << 24) | ((v & 1u) << 23);
        } else if (fs == 26u) {
            if ((v & 0x007C0000u) != 0u)
                return 0;
            f = (f & 0xFFFC0F83u) | (v & 0x0003F07Cu);
        } else if (fs == 28u) {
            if ((v & 0x007C0000u) != 0u)
                return 0;
            f = (f & 0xFEFFF07Cu) | (v & 0x00000F83u) | ((v & 4u) << 22);
        } else {
            return MIPS_FAULT;
        }
        ctx->fcsr = f;
        if ((((f >> 7) & 0x1Fu) & ((f >> 12) & 0x1Fu)) != 0u) {
            if ((f & 0x10000u) != 0u && (f & 0x800u) != 0u)
                code = 7;
            else if ((f & 0x8000u) != 0u && (f & 0x400u) != 0u)
                code = 3;
            else if ((f & 0x4000u) != 0u && (f & 0x200u) != 0u)
                code = 4;
            else if ((f & 0x2000u) != 0u && (f & 0x100u) != 0u)
                code = 5;
            else if ((f & 0x1000u) != 0u && (f & 0x80u) != 0u)
                code = 6;
            mips_trap_code(ctx, 8, code, ctx->pc);
            return MIPS_FAULT;
        }
        return 0;
    }
    default:
        return MIPS_FAULT;
    }
}
