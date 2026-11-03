/*
 * src/vm/vm32.c — Two-regime Class-A 32-bit VM (Wave U3)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * UNIFICATION-PLAN.md Rev 4 sections 4.3-4.6, 5.1: Regime A1
 * (H == 4096: the rt32 4 GiB window [G, G+4GiB) with x20 = G and the
 * 1-instruction [x20, wAddr, uxtw] lowering) vs Regime A2 (H > 4096:
 * x20 = &ctx->tlb[0], and the 7-instruction Soft-TLB for every DBT
 * access).
 *
 * RC-U3-R2 single canonical backing: both regimes use the rt32 window
 * [G, G+4GiB) as the one arena (vm_arena_base == guest_base, no
 * separate reservation).  HVA = G + gva is the single coherent address
 * shared by DBT, interp, futex, and syscalls, so Provider-A file bytes
 * populated into G and the Soft-TLB addends can never disagree about
 * where a guest page lives (the old separate A2 arena duplicated file
 * content the mappings never read).  Permission checks still happen in
 * software at instruction 6 (cbnz) before the host load/store, so a
 * fault never partially mutates guest state.
 *
 * Pure C11.  No inline asm, never touches x18 (fixed registers are
 * installed by src/dbt/trampoline_a64.S only).
 */

#define _POSIX_C_SOURCE 200809L
#if defined(__APPLE__)
#define _DARWIN_C_SOURCE 1
#endif

#include "vm/vm32.h"

#include <errno.h>
#include <stdlib.h>
#include <unistd.h>

uint32_t mips32_vm_regime_for_host(size_t host_page_size)
{
    if (host_page_size == 4096u) {
        return MIPS32_VM_REGIME_A1;
    }
    return MIPS32_VM_REGIME_A2;
}

static size_t host_page_size(void)
{
    long v = sysconf(_SC_PAGESIZE);

    if (v <= 0) {
        return 4096u;
    }
    return (size_t)v;
}

void mips32_fixade_init(mips32_ctx_t *ctx)
{
    if (ctx == NULL) {
        return;
    }
    ctx->fixade_enabled = 1u;
}

int32_t mips32_fixade_sysmips(mips32_ctx_t *ctx, uint32_t arg)
{
    if (ctx == NULL) {
        return (int32_t)-EFAULT;
    }
    ctx->fixade_enabled = (arg != 0u) ? 1u : 0u;
    return 0;
}

static void tlb_invalidate_all(mips32_ctx_t *ctx)
{
    mips32_tlb_entry_t *tlb;
    size_t i;

    if (ctx == NULL || ctx->vm_tlb == NULL) {
        return;
    }
    tlb = (mips32_tlb_entry_t *)ctx->vm_tlb;
    for (i = 0u; i < MIPS32_TLB_SIZE; i++) {
        tlb[i].read_tag = MIPS32_TLB_INVALID_TAG;
        tlb[i].write_tag = MIPS32_TLB_INVALID_TAG;
    }
}

int mips32_vm32_init(mips32_ctx_t *ctx)
{
    size_t host_page;

    if (ctx == NULL) {
        return -EFAULT;
    }
    /* RC-U3-R2: the arena is always the rt32 window itself (set by
     * rt32_vm_init before this runs); there is no separate reservation
     * to keep coherent.  A2 only adds the per-context Soft-TLB. */
    host_page = host_page_size();
    if (mips32_vm_regime_for_host(host_page) == MIPS32_VM_REGIME_A1) {
        ctx->vm_regime = MIPS32_VM_REGIME_A1;
        ctx->vm_arena_base = ctx->guest_base;
        ctx->vm_tlb = NULL;
        ctx->delay_target = 0u;
        if (ctx->fixade_enabled != 0u && ctx->fixade_enabled != 1u) {
            ctx->fixade_enabled = 1u;
        }
        return 0;
    }
    ctx->vm_tlb = calloc(MIPS32_TLB_SIZE, sizeof(mips32_tlb_entry_t));
    if (ctx->vm_tlb == NULL) {
        return -ENOMEM;
    }
    ctx->vm_regime = MIPS32_VM_REGIME_A2;
    ctx->vm_arena_base = ctx->guest_base;
    ctx->delay_target = 0u;
    if (ctx->fixade_enabled != 0u && ctx->fixade_enabled != 1u) {
        ctx->fixade_enabled = 1u;
    }
    tlb_invalidate_all(ctx);
    return 0;
}

void mips32_vm32_fini(mips32_ctx_t *ctx)
{
    if (ctx == NULL) {
        return;
    }
    free(ctx->vm_tlb);
    ctx->vm_tlb = NULL;
    ctx->vm_regime = MIPS32_VM_REGIME_UNSET;
}

/*
 * Slow-path miss helper: validates the access against the recorded
 * regions, installs the TLB entry for the 4 KiB page on success, and
 * reports MIPS_FAULT (with mips_fault recording EXIT_FAULT) when the
 * page is unmapped, misaligned, or write-guarded (COW_CLEAN, HAS_CODE,
 * HAS_SW_RESERVATION force every store through here).
 *
 * COW promotion and code invalidation funnel through here as well, so
 * a warm read_tag never bypasses them (UNIFICATION-PLAN.md 4.4).
 */
int mips32_vm_tlb_miss(mips32_ctx_t *ctx, uint32_t gva, int is_write,
                       uint32_t width)
{
    mips32_tlb_entry_t *tlb;
    uint32_t page;
    uint32_t page_base;
    size_t i;
    int covered;

    if (ctx == NULL || width == 0u || width > 16u) {
        return MIPS_FAULT;
    }
    if ((gva & (width - 1u)) != 0u && width <= 8u) {
        /* Alignment is checked before the TLB probe (insn 6, cbnz),
         * mirroring the DBT fast path. */
        mips_fault(ctx, gva);
        return MIPS_FAULT;
    }
    page = (gva >> 12) & 0xFFFu;
    page_base = gva & ~0xFFFu;
    rt32_vm_sync_ctx(ctx);
    covered = 0;
    for (i = 0u; i < ctx->region_count; i++) {
        const mips32_region_t *r = &ctx->regions[i];

        if (r->start > gva || r->end <= gva) {
            continue;
        }
        if (is_write != 0) {
            if ((r->prot & 0x2u) == 0u) {
                break;
            }
        } else if ((r->prot & 0x1u) == 0u) {
            break;
        }
        if ((uint64_t)r->end < (uint64_t)gva + (uint64_t)width) {
            break;
        }
        covered = 1;
        break;
    }
    if (covered == 0) {
        mips_fault(ctx, gva);
        return MIPS_FAULT;
    }
    if (ctx->vm_regime == MIPS32_VM_REGIME_A2 && ctx->vm_tlb != NULL) {
        uint64_t tag = (uint64_t)page_base;

        tlb = (mips32_tlb_entry_t *)ctx->vm_tlb;
        tlb[page].read_tag = tag;
        tlb[page].addend =
            (uintptr_t)(ctx->vm_arena_base + (uint64_t)page_base) -
            (uintptr_t)tag;
        if (is_write != 0) {
            tlb[page].write_tag = tag;
        }
    }
    return 0;
}

void mips32_vm_invalidate_range(mips32_ctx_t *ctx, uint32_t start,
                                uint32_t end)
{
    mips32_tlb_entry_t *tlb;
    uint32_t first;
    uint32_t last;
    uint32_t p;

    if (ctx == NULL || start >= end) {
        return;
    }
    if (ctx->vm_regime != MIPS32_VM_REGIME_A2 || ctx->vm_tlb == NULL) {
        return;
    }
    first = (start >> 12) & 0xFFFu;
    last = ((end - 1u) >> 12) & 0xFFFu;
    tlb = (mips32_tlb_entry_t *)ctx->vm_tlb;
    if ((uint64_t)end - (uint64_t)start >= (uint64_t)512u * 4096u) {
        tlb_invalidate_all(ctx);
        return;
    }
    p = first;
    for (;;) {
        tlb[p].read_tag = MIPS32_TLB_INVALID_TAG;
        tlb[p].write_tag = MIPS32_TLB_INVALID_TAG;
        if (p == last) {
            break;
        }
        p = (p + 1u) & 0xFFFu;
        if (p == first) {
            break;
        }
    }
}

int mips32_vm_a2_has_subpage_guard(mips32_ctx_t *ctx)
{
    size_t i;

    if (ctx == NULL || ctx->vm_regime != MIPS32_VM_REGIME_A2) {
        return 0;
    }
    rt32_vm_sync_ctx(ctx);
    for (i = 0u; i < ctx->region_count; i++) {
        const mips32_region_t *r = &ctx->regions[i];

        if ((r->prot & 0x3u) == 0u) {
            return 1;
        }
        if (i > 0u && r->start > 0u) {
            const mips32_region_t *prev = &ctx->regions[i - 1u];

            if (prev->end > 0u &&
                ((prev->end - 1u) & ~0x3FFFu) == (r->start & ~0x3FFFu) &&
                (prev->prot & 0x3u) != (r->prot & 0x3u)) {
                return 1;
            }
        }
    }
    return 0;
}
