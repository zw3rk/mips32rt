/*
 * src/dbt/dbt.h — Lane-internal DBT dispatcher declarations (Phase 2, lane L2b).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Internal to src/dbt/: block cache, 4096-entry IBTC, 64-entry RAS,
 * page-version (SMC) tracking, and the assembly trampoline contract.
 * Cross-lane interaction stays on the frozen contracts in src/mips32rt.h
 * (dbt_block_t, dbt_lookup/dbt_compile, dbt_emit_int, interp_step,
 * mips_fetch/mips_decode, mips_syscall, mips_fault).
 *
 * Trampoline <-> block code ABI (AArch64, SPEC 2.1):
 * - On entry: x19 = ctx, x20 = G (guest window base). x18 is never
 *   touched. Blocks preserve x19/x20 (fixed registers) and x29.
 * - On exit: w0 = exit reason (MIPS32_EXIT_*), w1 = exit info, and
 *   ctx->pc already advanced past the executed instructions. The
 *   trampoline records reason/info into ctx and returns the reason.
 */

#ifndef MIPS32RT_DBT_H
#define MIPS32RT_DBT_H

#include <stddef.h>
#include <stdint.h>

#include "mips32rt.h"

/* Pool sizes (all counts, never VLAs). */
#define DBT_MAX_BLOCKS 1024U
#define DBT_CODE_POOL_SIZE (4U * 1024U * 1024U)
#define DBT_SMC_TABLE_SIZE 1024U
#define DBT_STAGING_SIZE 4096U

/* One IBTC slot: direct-mapped by guest PC, validated by smc_version. */
typedef struct dbt_ibtc_entry {
    uint32_t guest_pc;
    void    *code;
    uint32_t smc_version;
} dbt_ibtc_entry_t;

/* One RAS slot: guest return PC with its resolved code, if any. */
typedef struct dbt_ras_entry {
    uint32_t guest_pc;
    void    *code;
    uint32_t smc_version;
} dbt_ras_entry_t;

/* One guest-page version slot for SMC invalidation. */
typedef struct dbt_smc_entry {
    uint32_t page;
    uint32_t version;
    uint32_t used;
} dbt_smc_entry_t;

/*
 * dbt_compile return contract (0 ok, 1 interp_step fallback, MIPS_FAULT):
 *  0: block compiled, published, and IBTC-resident; call dbt_lookup.
 *  1: nothing published; caller must run interp_step(ctx) once (cross-page
 *     branch+delay slot start, FP-arithmetic head, SYSCALL/BREAK/trap head,
 *     unknown encoding, or emitter decline) and resume the loop.
 *  MIPS_FAULT: fetch fault; mips_fault already recorded the EXIT_FAULT.
 */
int dbt_compile(mips32_ctx_t *ctx, uint32_t pc);

/* Direct chaining memo + RAS + IBTC + block-pool search, in that order. */
void *dbt_lookup(mips32_ctx_t *ctx, uint32_t pc);

/*
 * Page-version hooks for RC2 SMC wiring (mprotect/munmap/clear_cache and
 * guest writes to translated pages call dbt_smc_bump; the dispatcher
 * drops blocks whose smc_version mismatches).
 */
uint32_t dbt_smc_version(mips32_ctx_t *ctx, uint32_t page);
void dbt_smc_bump(mips32_ctx_t *ctx, uint32_t va);

/* Host entry point (src/dbt/trampoline_a64.S). Never touches x18. */
uint32_t dbt_trampoline_enter(mips32_ctx_t *ctx, void *code);

#endif /* MIPS32RT_DBT_H */
