/*
 * src/os/mem.c — Guest memory window + endianness-aware accessors (lane L1c)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Phase 1 frozen contracts from src/mips32rt.h: guest_mem_init,
 * guest_ld/st8/16/32, mips_fault.  The 4 GiB window [G, G+4GiB) itself
 * is reserved by the vendored src/rt32/ helpers (rt32_host_probe +
 * rt32_vm_init); this file only adds the MIPS access layer on top.
 *
 * Endianness (mips_is_be, SPEC 2.1): bytes are assembled explicitly so
 * the code is host-endian independent.  LE (mipsel) stores value byte 0
 * at the lowest address; BE (mips) stores the most significant byte at
 * the lowest address.
 *
 * Alignment (SPEC 2.2, phase-1 card): guest_ld/st16/32 are aligned-only
 * and report MIPS_FAULT on a misaligned address (AdEL/AdES); the
 * unaligned LWL/LWR/SWL/SWR pairs compose via guest_ld/st8 (lane L1b).
 * Accesses outside recorded regions (or with insufficient permission)
 * report MIPS_FAULT via mips_fault (EXIT_FAULT + fault addr).
 */

#include "mips32rt.h"

#include "rt32/rt32.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>

int guest_mem_init(mips32_ctx_t *ctx)
{
    if (ctx == NULL) {
        return MIPS_FAULT;
    }
    rt32_host_probe(ctx);
    if (rt32_vm_init(ctx, UINT64_MAX) != 0) {
        return MIPS_FAULT;
    }
    return 0;
}

/*
 * True when every byte of [va, va+len) lies inside recorded regions
 * carrying the needed PROT bits.  Regions mirror the VMA manager
 * (sorted by start); PROT_NONE gaps and unmapped pages fail the walk.
 */
static int range_covered(const mips32_ctx_t *ctx, uint32_t va, uint32_t len,
                         uint32_t need)
{
    uint64_t end64;
    uint32_t cur;
    size_t   i;

    if (ctx == NULL || len == 0U) {
        return ctx != NULL && len == 0U;
    }
    end64 = (uint64_t)va + (uint64_t)len;
    if (end64 > 0x100000000ULL) {
        return 0;
    }
    cur = va;
    for (i = 0; i < ctx->region_count; i++) {
        const mips32_region_t *r = &ctx->regions[i];
        if (r->start > cur || r->end <= cur) {
            continue;
        }
        if ((r->prot & need) != need) {
            return 0;
        }
        cur = r->end;
        if ((uint64_t)cur >= end64) {
            return 1;
        }
    }
    return (uint64_t)cur >= end64;
}

void mips_fault(mips32_ctx_t *ctx, uint32_t addr)
{
    if (ctx == NULL) {
        return;
    }
    ctx->llbit       = 0U; /* SPEC 2.2: any helper exit clears the LL bit */
    ctx->exit_reason = MIPS32_EXIT_FAULT;
    ctx->exit_info   = addr;
}

int guest_ld8(mips32_ctx_t *ctx, uint32_t va, uint32_t *out)
{
    uint8_t b;

    if (ctx == NULL || out == NULL) {
        return MIPS_FAULT;
    }
    if (!range_covered(ctx, va, 1U, (uint32_t)PROT_READ)) {
        mips_fault(ctx, va);
        return MIPS_FAULT;
    }
    memcpy(&b, mips32_guest_ptr(ctx, va), 1U);
    *out = (uint32_t)b;
    return 0;
}

int guest_st8(mips32_ctx_t *ctx, uint32_t va, uint32_t val)
{
    uint8_t b;

    if (ctx == NULL) {
        return MIPS_FAULT;
    }
    if (!range_covered(ctx, va, 1U, (uint32_t)PROT_WRITE)) {
        mips_fault(ctx, va);
        return MIPS_FAULT;
    }
    b = (uint8_t)(val & 0xFFU);
    memcpy(mips32_guest_ptr(ctx, va), &b, 1U);
    return 0;
}

int guest_ld16(mips32_ctx_t *ctx, uint32_t va, uint32_t *out)
{
    uint8_t b[2];

    if (ctx == NULL || out == NULL) {
        return MIPS_FAULT;
    }
    if ((va & 1U) != 0U) {
        mips_fault(ctx, va);
        return MIPS_FAULT;
    }
    if (!range_covered(ctx, va, 2U, (uint32_t)PROT_READ)) {
        mips_fault(ctx, va);
        return MIPS_FAULT;
    }
    memcpy(b, mips32_guest_ptr(ctx, va), 2U);
    if (mips_is_be(ctx)) {
        *out = ((uint32_t)b[0] << 8) | (uint32_t)b[1];
    } else {
        *out = (uint32_t)b[0] | ((uint32_t)b[1] << 8);
    }
    return 0;
}

int guest_st16(mips32_ctx_t *ctx, uint32_t va, uint32_t val)
{
    uint8_t b[2];

    if (ctx == NULL) {
        return MIPS_FAULT;
    }
    if ((va & 1U) != 0U) {
        mips_fault(ctx, va);
        return MIPS_FAULT;
    }
    if (!range_covered(ctx, va, 2U, (uint32_t)PROT_WRITE)) {
        mips_fault(ctx, va);
        return MIPS_FAULT;
    }
    if (mips_is_be(ctx)) {
        b[0] = (uint8_t)((val >> 8) & 0xFFU);
        b[1] = (uint8_t)(val & 0xFFU);
    } else {
        b[0] = (uint8_t)(val & 0xFFU);
        b[1] = (uint8_t)((val >> 8) & 0xFFU);
    }
    memcpy(mips32_guest_ptr(ctx, va), b, 2U);
    return 0;
}

int guest_ld32(mips32_ctx_t *ctx, uint32_t va, uint32_t *out)
{
    uint8_t b[4];

    if (ctx == NULL || out == NULL) {
        return MIPS_FAULT;
    }
    if ((va & 3U) != 0U) {
        mips_fault(ctx, va);
        return MIPS_FAULT;
    }
    if (!range_covered(ctx, va, 4U, (uint32_t)PROT_READ)) {
        mips_fault(ctx, va);
        return MIPS_FAULT;
    }
    memcpy(b, mips32_guest_ptr(ctx, va), 4U);
    if (mips_is_be(ctx)) {
        *out = ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) |
               ((uint32_t)b[2] << 8) | (uint32_t)b[3];
    } else {
        *out = (uint32_t)b[0] | ((uint32_t)b[1] << 8) |
               ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
    }
    return 0;
}

int guest_st32(mips32_ctx_t *ctx, uint32_t va, uint32_t val)
{
    uint8_t b[4];

    if (ctx == NULL) {
        return MIPS_FAULT;
    }
    if ((va & 3U) != 0U) {
        mips_fault(ctx, va);
        return MIPS_FAULT;
    }
    if (!range_covered(ctx, va, 4U, (uint32_t)PROT_WRITE)) {
        mips_fault(ctx, va);
        return MIPS_FAULT;
    }
    if (mips_is_be(ctx)) {
        b[0] = (uint8_t)((val >> 24) & 0xFFU);
        b[1] = (uint8_t)((val >> 16) & 0xFFU);
        b[2] = (uint8_t)((val >> 8) & 0xFFU);
        b[3] = (uint8_t)(val & 0xFFU);
    } else {
        b[0] = (uint8_t)(val & 0xFFU);
        b[1] = (uint8_t)((val >> 8) & 0xFFU);
        b[2] = (uint8_t)((val >> 16) & 0xFFU);
        b[3] = (uint8_t)((val >> 24) & 0xFFU);
    }
    memcpy(mips32_guest_ptr(ctx, va), b, 4U);
    return 0;
}
