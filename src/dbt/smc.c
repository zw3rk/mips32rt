/*
 * src/dbt/smc.c — SMC page-version table (M32-R13-3).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Power-of-two open-addressed hash table indexed by
 * (page >> 12) & (DBT_SMC_TABLE_SIZE - 1).  Updates insert under
 * g_smc_lock with release/relaxed atomics (the version is stored
 * before the page is published on a fresh slot); lookups probe
 * lock-free, stopping at the first UINT32_MAX empty slot after the
 * g_smc_used_count fast-path check.  Zero mutex acquisition on lookup.
 *
 * Pure C11.  Never touches x18.
 */

#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>

#include "mips32rt.h"
#include "dbt/dbt.h"

_Atomic uint32_t g_smc_lock = 0U;
static dbt_smc_entry_t g_smc_table[DBT_SMC_TABLE_SIZE];
static _Atomic uint32_t g_smc_ready = 0U;
_Atomic uint32_t g_smc_used_count = 0U;
_Atomic uint64_t g_smc_flush_epoch = 1U;
_Atomic uint64_t dbt_smc_ver_epoch = 1U;

/* One-time page-sentinel init: zero-init page 0 would alias a real
 * entry, so publish UINT32_MAX to every slot once, under the SMC
 * lock, before the first insert. */
static void dbt_smc_ensure(void)
{
    size_t i;

    if (atomic_load_explicit(&g_smc_ready, memory_order_acquire) != 0U) {
        return;
    }
    mips32_spin_lock(&g_smc_lock);
    if (atomic_load_explicit(&g_smc_ready, memory_order_relaxed) == 0U) {
        for (i = 0U; i < DBT_SMC_TABLE_SIZE; i++) {
            atomic_store_explicit(&g_smc_table[i].page, UINT32_MAX,
                                  memory_order_relaxed);
        }
        atomic_store_explicit(&g_smc_ready, 1U, memory_order_release);
    }
    mips32_spin_unlock(&g_smc_lock);
}

uint32_t dbt_smc_version(mips32_ctx_t *ctx, uint32_t page)
{
    size_t idx;
    size_t k;
    uint32_t v = 1U;
    uint64_t ver_ep;

    (void)ctx;
    if (atomic_load_explicit(&g_smc_used_count, memory_order_acquire) == 0U) {
        return 1U;
    }
    ver_ep = atomic_load_explicit(&dbt_smc_ver_epoch, memory_order_acquire);
    if (dbt_cache != NULL && dbt_cache->smc_memo_valid != 0 &&
        dbt_cache->smc_memo_page == page &&
        dbt_cache->local_ver_epoch == ver_ep) {
        return dbt_cache->smc_memo_version;
    }
    idx = (size_t)((page >> 12U) & (DBT_SMC_TABLE_SIZE - 1U));
    for (k = 0U; k < DBT_SMC_TABLE_SIZE; k++) {
        uint32_t p = atomic_load_explicit(&g_smc_table[idx].page,
                                          memory_order_acquire);
        if (p == page) {
            v = (uint32_t)atomic_load_explicit(&g_smc_table[idx].version,
                                               memory_order_relaxed);
            break;
        }
        if (p == UINT32_MAX) {
            break;
        }
        idx = (idx + 1U) & (DBT_SMC_TABLE_SIZE - 1U);
    }
    if (dbt_cache != NULL) {
        dbt_cache->smc_memo_page = page;
        dbt_cache->smc_memo_version = v;
        dbt_cache->local_ver_epoch = ver_ep;
        dbt_cache->smc_memo_valid = 1;
    }
    return v;
}

void dbt_smc_bump(mips32_ctx_t *ctx, uint32_t va)
{
    uint32_t page = mips32_page_down(va);
    size_t idx = (size_t)((page >> 12U) & (DBT_SMC_TABLE_SIZE - 1U));
    size_t k;

    if (ctx != NULL) {
        ctx->ibtc_ptr = 0U;
    }
    if (dbt_cache != NULL) {
        dbt_cache->smc_memo_valid = 0;
    }
    dbt_smc_ensure();
    mips32_spin_lock(&g_smc_lock);
    for (k = 0U; k < DBT_SMC_TABLE_SIZE; k++) {
        uint32_t p = atomic_load_explicit(&g_smc_table[idx].page,
                                          memory_order_relaxed);
        if (p == page || p == UINT32_MAX) {
            uint64_t v = atomic_load_explicit(&g_smc_table[idx].version,
                                              memory_order_relaxed);
            atomic_store_explicit(&g_smc_table[idx].version,
                                  (p == page) ? v + 1U : 2U,
                                  memory_order_relaxed);
            atomic_store_explicit(&g_smc_table[idx].page, page,
                                  memory_order_release);
            if (p == UINT32_MAX) {
                atomic_fetch_add_explicit(&g_smc_used_count, 1U,
                                          memory_order_release);
            }
            atomic_fetch_add_explicit(&dbt_smc_ver_epoch, 1U,
                                      memory_order_release);
            mips32_spin_unlock(&g_smc_lock);
            return;
        }
        idx = (idx + 1U) & (DBT_SMC_TABLE_SIZE - 1U);
    }
    /* Table full: reset the shared table and flush every thread's
     * cache rather than dropping the invalidation. */
    for (k = 0U; k < DBT_SMC_TABLE_SIZE; k++) {
        atomic_store_explicit(&g_smc_table[k].page, UINT32_MAX,
                              memory_order_relaxed);
    }
    atomic_store_explicit(&g_smc_used_count, 0U, memory_order_relaxed);
    atomic_fetch_add_explicit(&dbt_smc_ver_epoch, 1U, memory_order_relaxed);
    atomic_fetch_add_explicit(&g_smc_flush_epoch, 1U, memory_order_release);
    mips32_spin_unlock(&g_smc_lock);
    dbt_flush_local(ctx);
}

/* Table half of the explicit global SMC flush (the dispatcher follows
 * with a local cache flush). */
void dbt_smc_reset_for_flush(void)
{
    size_t i;

    dbt_smc_ensure();
    mips32_spin_lock(&g_smc_lock);
    for (i = 0U; i < DBT_SMC_TABLE_SIZE; i++) {
        atomic_store_explicit(&g_smc_table[i].page, UINT32_MAX,
                              memory_order_relaxed);
    }
    atomic_store_explicit(&g_smc_used_count, 0U, memory_order_relaxed);
    atomic_fetch_add_explicit(&dbt_smc_ver_epoch, 1U, memory_order_relaxed);
    atomic_fetch_add_explicit(&g_smc_flush_epoch, 1U, memory_order_release);
    mips32_spin_unlock(&g_smc_lock);
}
