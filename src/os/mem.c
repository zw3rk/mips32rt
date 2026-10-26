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
#include "vm/vm32.h"

#include <stddef.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

int guest_mem_init(mips32_ctx_t *ctx)
{
    if (ctx == NULL) {
        return MIPS_FAULT;
    }
    rt32_host_probe(ctx);
    if (rt32_vm_init(ctx, UINT64_MAX) != 0) {
        return MIPS_FAULT;
    }
    /* Wave U3: connect the two-regime VM (FIXADE default-on, A1/A2
     * select, A2 arena/TLB allocation). */
    mips32_fixade_init(ctx);
    if (mips32_vm32_init(ctx) != 0) {
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

/* Lane L4a queries (src/os/signals.c): true when signo has a real
 * guest handler; mips_trap delivers or dies by the signal.  Both are
 * declared by src/mips32rt.h. */
extern int mips_signal_has_handler(int signo);
extern void mips_trap(mips32_ctx_t *ctx, int signo, uint32_t addr);

/* Forward: ordinary stores overlapping the LL word break it (defined
 * below fixade_on, used by guest_st8 first). */
static void note_store(mips32_ctx_t *ctx, uint32_t va, uint32_t len);

void mips_fault(mips32_ctx_t *ctx, uint32_t addr)
{
    int signo;

    if (ctx == NULL) {
        return;
    }
    ctx->llbit       = 0U; /* SPEC 2.2: any helper exit clears the LL bit */
    ctx->exit_reason = MIPS32_EXIT_FAULT;
    ctx->exit_info   = addr;
    if (ctx->trace_enabled) {
        (void)fprintf(stderr, "F %08x fault-addr %08x\n", ctx->pc, addr);
    }
    /* Phase 4 (L4a): reroute to guest delivery when a handler is
     * installed.  Misaligned data addresses fault as AdEL/AdES
     * (SIGBUS); aligned ones as TLB miss/permission faults (SIGSEGV).
     * mips_raise_guest clears exit_reason on delivery so the engine can
     * resume at the handler; without one the process dies by signal
     * (139 for SIGSEGV, matching the Phase-1 exit shape).
     * RC-U3 TIF_FIXADE: with fixade_enabled set, misaligned integer
     * accesses emulate in software and never reach here, so a fault on
     * a misaligned address is a mapping/permission failure (SIGSEGV),
     * not an address error. */
    signo = (ctx->fixade_enabled != 0U || (addr & 3U) == 0U) ? 11 : 10;
    mips_trap(ctx, signo, addr);
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
    note_store(ctx, va, 1U);
    return 0;
}

/* Wave U3 (UNIFICATION-PLAN.md 4.3, fable M5): Linux MIPS TIF_FIXADE.
 * fixade_enabled == 1 (the default) emulates unaligned integer
 * loads/stores byte-wise in software; when cleared via
 * sysmips(MIPS_FIXADE, 0) the next misaligned access faults so the
 * signal layer delivers guest SIGBUS/BUS_ADRALN. */
static int fixade_on(const mips32_ctx_t *ctx)
{
    return ctx != NULL && ctx->fixade_enabled != 0u;
}

/* RC-U3 LL/SC: an ordinary store overlapping the reserved word breaks
 * this thread's reservation (the later SC then fails its checks).
 * Spurious SC failure is architecturally legal; the overlap test keeps
 * reservations for other words alive. */
static void note_store(mips32_ctx_t *ctx, uint32_t va, uint32_t len)
{
    uint64_t end64;

    if (ctx == NULL || ctx->llbit == 0u || len == 0u) {
        return;
    }
    end64 = (uint64_t)va + (uint64_t)len;
    if ((uint64_t)va < (uint64_t)ctx->lladdr + 4u &&
        end64 > (uint64_t)ctx->lladdr) {
        ctx->llbit = 0u;
    }
}

int guest_ld16(mips32_ctx_t *ctx, uint32_t va, uint32_t *out)
{
    uint8_t b[2];

    if (ctx == NULL || out == NULL) {
        return MIPS_FAULT;
    }
    if ((va & 1U) != 0U) {
        uint32_t lo = 0u;
        uint32_t hi = 0u;

        if (!fixade_on(ctx)) {
            mips_fault(ctx, va);
            return MIPS_FAULT;
        }
        if (!range_covered(ctx, va, 2U, (uint32_t)PROT_READ)) {
            mips_fault(ctx, va);
            return MIPS_FAULT;
        }
        memcpy(&lo, mips32_guest_ptr(ctx, va), 1U);
        memcpy(&hi, mips32_guest_ptr(ctx, va + 1U), 1U);
        if (mips_is_be(ctx)) {
            *out = (lo << 8) | hi;
        } else {
            *out = lo | (hi << 8);
        }
        return 0;
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
        uint8_t p[2];

        if (!fixade_on(ctx)) {
            mips_fault(ctx, va);
            return MIPS_FAULT;
        }
        if (!range_covered(ctx, va, 2U, (uint32_t)PROT_WRITE)) {
            mips_fault(ctx, va);
            return MIPS_FAULT;
        }
        if (mips_is_be(ctx)) {
            p[0] = (uint8_t)((val >> 8) & 0xFFU);
            p[1] = (uint8_t)(val & 0xFFU);
        } else {
            p[0] = (uint8_t)(val & 0xFFU);
            p[1] = (uint8_t)((val >> 8) & 0xFFU);
        }
        memcpy(mips32_guest_ptr(ctx, va), p, 2U);
        note_store(ctx, va, 2U);
        return 0;
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
    note_store(ctx, va, 2U);
    return 0;
}

int guest_ld32(mips32_ctx_t *ctx, uint32_t va, uint32_t *out)
{
    uint8_t b[4];

    if (ctx == NULL || out == NULL) {
        return MIPS_FAULT;
    }
    if ((va & 3U) != 0U) {
        uint8_t q[4];

        if (!fixade_on(ctx)) {
            mips_fault(ctx, va);
            return MIPS_FAULT;
        }
        if (!range_covered(ctx, va, 4U, (uint32_t)PROT_READ)) {
            mips_fault(ctx, va);
            return MIPS_FAULT;
        }
        memcpy(q, mips32_guest_ptr(ctx, va), 4U);
        if (mips_is_be(ctx)) {
            *out = ((uint32_t)q[0] << 24) | ((uint32_t)q[1] << 16) |
                   ((uint32_t)q[2] << 8) | (uint32_t)q[3];
        } else {
            *out = (uint32_t)q[0] | ((uint32_t)q[1] << 8) |
                   ((uint32_t)q[2] << 16) | ((uint32_t)q[3] << 24);
        }
        return 0;
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
        uint8_t q[4];

        if (!fixade_on(ctx)) {
            mips_fault(ctx, va);
            return MIPS_FAULT;
        }
        if (!range_covered(ctx, va, 4U, (uint32_t)PROT_WRITE)) {
            mips_fault(ctx, va);
            return MIPS_FAULT;
        }
        if (mips_is_be(ctx)) {
            q[0] = (uint8_t)((val >> 24) & 0xFFU);
            q[1] = (uint8_t)((val >> 16) & 0xFFU);
            q[2] = (uint8_t)((val >> 8) & 0xFFU);
            q[3] = (uint8_t)(val & 0xFFU);
        } else {
            q[0] = (uint8_t)(val & 0xFFU);
            q[1] = (uint8_t)((val >> 8) & 0xFFU);
            q[2] = (uint8_t)((val >> 16) & 0xFFU);
            q[3] = (uint8_t)((val >> 24) & 0xFFU);
        }
        memcpy(mips32_guest_ptr(ctx, va), q, 4U);
        note_store(ctx, va, 4U);
        return 0;
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
    note_store(ctx, va, 4U);
    return 0;
}

int guest_sc32(mips32_ctx_t *ctx, uint32_t va, uint32_t exp_val,
               uint32_t new_val, int *ok)
{
    uint32_t  exp_pat;
    uint32_t  new_pat;
    uint32_t *hp;
    int       swapped;

    if (ctx == NULL || ok == NULL) {
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
    /* Value-domain compare like LL/SC: the host mapping holds the
     * guest-order byte pattern, so swap both sides on BE. */
    if (mips_is_be(ctx)) {
        exp_pat = ((exp_val >> 24) & 0xFFU) | ((exp_val >> 8) & 0xFF00U) |
                  ((exp_val << 8) & 0xFF0000U) | ((exp_val << 24) & 0xFF000000U);
        new_pat = ((new_val >> 24) & 0xFFU) | ((new_val >> 8) & 0xFF00U) |
                  ((new_val << 8) & 0xFF0000U) | ((new_val << 24) & 0xFF000000U);
    } else {
        exp_pat = exp_val;
        new_pat = new_val;
    }
    hp = (uint32_t *)(void *)mips32_guest_ptr(ctx, va);
    swapped = 0;
    if (__atomic_compare_exchange_n(hp, &exp_pat, new_pat, 0,
                                    __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)) {
        swapped = 1;
    }
    *ok = swapped;
    return 0;
}
