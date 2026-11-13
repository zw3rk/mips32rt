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

#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>

#include "mips32rt.h"

/* Pool sizes (all counts, never VLAs). */
#define DBT_MAX_BLOCKS 1024U
#define DBT_CODE_POOL_SIZE (16U * 1024U * 1024U)
#define DBT_SMC_TABLE_SIZE 1024U
#define DBT_STAGING_SIZE 65536U

/* One IBTC slot: direct-mapped by guest PC, validated by smc_version. */
typedef struct dbt_ibtc_entry {
    uint32_t guest_pc;
    void    *code;
    uint32_t smc_version;
    size_t   blk_idx; /* index into dbt_cache.blocks (H3: O(1) metadata) */
} dbt_ibtc_entry_t;

/* One RAS slot: guest return PC with its resolved code, if any. */
typedef struct dbt_ras_entry {
    uint32_t guest_pc;
    void    *code;
    uint32_t smc_version;
    size_t   blk_idx; /* index into dbt_cache.blocks (O(1) metadata) */
} dbt_ras_entry_t;

/* One guest-page version slot for SMC invalidation: open-addressed
 * hash entry keyed by page (UINT32_MAX marks an empty slot; valid page
 * bases are 4 KiB-aligned so they never collide with the sentinel). */
typedef struct dbt_smc_entry {
    _Atomic uint32_t page;
    _Atomic uint64_t version;
} dbt_smc_entry_t;

/* Per-host-thread translation cache (owned by src/dbt/dbt.c; shared
 * here so the SMC table TU sees the memo fields). */
typedef struct dbt_cache {
    dbt_block_t blocks[DBT_MAX_BLOCKS];
    uint8_t     block_link[DBT_MAX_BLOCKS];
    size_t      block_count;
    dbt_ibtc_entry_t *ibtc;
    dbt_ras_entry_t ras[MIPS32_RAS_SIZE];
    unsigned    ras_top;
    uint8_t    *pool;
    size_t      pool_used;
    uint32_t    last_pc;
    void       *last_code;
    uint32_t    last_smc;
    int         last_valid;
    size_t      last_bi; /* block index for last_* (H3: O(1) metadata) */
    uint32_t    smc_memo_page; /* H3: last page resolved by dbt_smc_version */
    uint32_t    smc_memo_version;
    int         smc_memo_valid;
    uint64_t    local_flush_epoch;
    uint64_t    local_ver_epoch;
} dbt_cache_t;

extern __thread dbt_cache_t *dbt_cache;
extern _Atomic uint32_t g_smc_lock;
extern _Atomic uint32_t g_smc_used_count;
extern _Atomic uint64_t g_smc_flush_epoch;
void dbt_flush_local(mips32_ctx_t *ctx);
void dbt_smc_reset_for_flush(void);

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
/* Trace replay for --trace/--difftest parity (src/dbt/trace.c). */
void dbt_trace_block(mips32_ctx_t *ctx, const dbt_block_t *b);
/* Wave C2 difftest parity: replay the trace lines for a fault converted
 * by the hostfault guard (src/os/hostfault.c calls this before delivery
 * while ctx->pc still names the faulting insn). The normal dispatcher
 * path skips these blocks (it continues before tracing), so without
 * this hook every converted guest fault diverges interp-vs-dbt. */
void dbt_trace_converted_fault(mips32_ctx_t *ctx);
/* Block table accessor for the trace replay (defined in dbt.c). */
size_t dbt_trace_table(const dbt_block_t **out);
/* In-trampoline chaining step (Wave P lane P4): validated lookup for
 * ctx->pc, NULL to exit the chain (see dbt.c). */
void *dbt_chain_next(mips32_ctx_t *ctx);

/*
 * Page-version hooks for RC2 SMC wiring (mprotect/munmap/clear_cache and
 * guest writes to translated pages call dbt_smc_bump; the dispatcher
 * drops blocks whose smc_version mismatches).
 */
uint32_t dbt_smc_version(mips32_ctx_t *ctx, uint32_t page);
void dbt_smc_bump(mips32_ctx_t *ctx, uint32_t va);
/* M32-R8-5: process-wide SMC version epoch (bumped on every SMC state
 * change); the trampoline probe compares it against ctx->ibtc_epoch. */
extern _Atomic uint64_t dbt_smc_ver_epoch;

/* Host entry point (src/dbt/trampoline_a64.S). Never touches x18. */
uint32_t dbt_trampoline_enter(mips32_ctx_t *ctx, void *code);

#endif /* MIPS32RT_DBT_H */
