/*
 * src/interp/unaligned.c — unaligned load/store merge helpers (Phase 1).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Byte-granular LWL/LWR/SWL/SWR merge rules from the E05 tables, shared
 * by interp.c.  Bodies are verbatim from the original interp.c; only the
 * file changed (line-limit split, no behavior change).
 */

#include <stdint.h>

#include "mips32rt.h"
#include "interp/interp.h"

/* Byte position p (0 = LSB) of a 32-bit value. */
static uint32_t get_pos(uint32_t v, unsigned p)
{
    return (v >> (8u * p)) & 0xFFu;
}

static uint32_t set_pos(uint32_t v, unsigned p, uint32_t b)
{
    return (v & ~((uint32_t)0xFFu << (8u * p))) | ((b & 0xFFu) << (8u * p));
}

/* Load the 4 bytes of the aligned word PA (endianness-neutral).
 * guest_ld8 records the fault itself; just propagate MIPS_FAULT so a
 * delivered handler frame is not faulted a second time (M32-R7-3). */
static int load_bytes(mips32_ctx_t *ctx, uint32_t pa, uint8_t m[4])
{
    unsigned i;

    for (i = 0u; i < 4u; i++) {
        uint32_t v = 0u;

        if (guest_ld8(ctx, pa + i, &v) != 0) {
            return MIPS_FAULT;
        }
        m[i] = (uint8_t)v;
    }
    return 0;
}

/* Store m[lo..hi] to PA+lo..PA+hi (endianness-neutral, same rule). */
static int store_bytes(mips32_ctx_t *ctx, uint32_t pa, const uint8_t m[4],
                       unsigned lo, unsigned hi)
{
    unsigned i;

    for (i = lo; i <= hi; i++) {
        if (guest_st8(ctx, pa + i, m[i]) != 0) {
            return MIPS_FAULT;
        }
    }
    return 0;
}

/* LWL/LWR merge rules from the E05 tables (M[j] = byte at PA+j): LE LWL
 * fills positions (3-k+i), LE LWR (i-k), BE LWL 3-(i-k), BE LWR (k-i). */
int do_lwl(mips32_ctx_t *ctx, uint32_t addr, unsigned rt)
{
    uint32_t pa = addr & ~3u;
    unsigned k = addr & 3u;
    uint8_t m[4] = { 0u, 0u, 0u, 0u };
    uint32_t v = ctx->gpr[rt];
    unsigned i;

    if (load_bytes(ctx, pa, m) != 0) {
        return MIPS_FAULT;
    }
    if (mips_is_be(ctx)) {
        for (i = k; i < 4u; i++) {
            v = set_pos(v, 3u - (i - k), m[i]);
        }
    } else {
        for (i = 0u; i <= k; i++) {
            v = set_pos(v, 3u - k + i, m[i]);
        }
    }
    interp_set_reg(ctx, rt, v);
    return 0;
}

int do_lwr(mips32_ctx_t *ctx, uint32_t addr, unsigned rt)
{
    uint32_t pa = addr & ~3u;
    unsigned k = addr & 3u;
    uint8_t m[4] = { 0u, 0u, 0u, 0u };
    uint32_t v = ctx->gpr[rt];
    unsigned i;

    if (load_bytes(ctx, pa, m) != 0) {
        return MIPS_FAULT;
    }
    if (mips_is_be(ctx)) {
        for (i = 0u; i <= k; i++) {
            v = set_pos(v, k - i, m[i]);
        }
    } else {
        for (i = k; i < 4u; i++) {
            v = set_pos(v, i - k, m[i]);
        }
    }
    interp_set_reg(ctx, rt, v);
    return 0;
}

/* SWL/SWR store rules mirror the loads (same rt positions). */
int do_swl(mips32_ctx_t *ctx, uint32_t addr, uint32_t rtval)
{
    uint32_t pa = addr & ~3u;
    unsigned k = addr & 3u;
    uint8_t m[4] = { 0u, 0u, 0u, 0u };
    unsigned i;

    if (mips_is_be(ctx)) {
        for (i = k; i < 4u; i++) {
            m[i] = (uint8_t)get_pos(rtval, 3u - (i - k));
        }
        return store_bytes(ctx, pa, m, k, 3u);
    }
    for (i = 0u; i <= k; i++) {
        m[i] = (uint8_t)get_pos(rtval, 3u - k + i);
    }
    return store_bytes(ctx, pa, m, 0u, k);
}

int do_swr(mips32_ctx_t *ctx, uint32_t addr, uint32_t rtval)
{
    uint32_t pa = addr & ~3u;
    unsigned k = addr & 3u;
    uint8_t m[4] = { 0u, 0u, 0u, 0u };
    unsigned i;

    if (mips_is_be(ctx)) {
        for (i = 0u; i <= k; i++) {
            m[i] = (uint8_t)get_pos(rtval, k - i);
        }
        return store_bytes(ctx, pa, m, 0u, k);
    }
    for (i = k; i < 4u; i++) {
        m[i] = (uint8_t)get_pos(rtval, i - k);
    }
    return store_bytes(ctx, pa, m, k, 3u);
}
