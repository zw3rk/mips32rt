/*
 * src/dbt/dbt.c — AArch64 DBT dispatcher: engine loop, block cache, IBTC, RAS.
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Phase 2, lane L2b. Owns the dispatcher side of the frozen DBT contracts:
 * dbt_main, dbt_lookup, dbt_compile. Emission is the frozen dbt_emit_int
 * (sibling lane L2c); this file only calls it, never defines it.
 *
 * Block formation (SPEC 2.2): fetch via mips_fetch, decode via mips_decode,
 * up to MIPS32_DBT_MAX_INSNS (64) instructions, stopping at control
 * transfers (branch+jump with the delay slot emitted as one indivisible
 * unit when both share a 4 KiB page), at 4 KiB page crossings (a branch at
 * (pc & 0xfff) == 0xffc ends the block *before* it; a non-control word at
 * ...0xffc is included and ends the block), and at SYSCALL/BREAK/traps.
 * A block *starting* at (pc & 0xfff) == 0xffc is never compiled: the
 * caller single-steps it with interp_step and resumes. COP1X/COP2 and
 * unknown encodings likewise fall back to interp_step (COP1 proper is
 * natively emitted since Wave P lane P4); the fallback never aborts
 * execution.
 *
 * Single-threaded in Phase 2 (CLONE/threading arrives in Phase 4).
 */

#define _POSIX_C_SOURCE 200809L
#ifdef __APPLE__
#define _DARWIN_C_SOURCE 1
#endif

#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#ifdef __APPLE__
#include <libkern/OSCacheControl.h>
#include <pthread.h>
#endif

#ifndef MAP_ANONYMOUS
#ifdef MAP_ANON
#define MAP_ANONYMOUS MAP_ANON
#else
/* Linux value; this translator runs on AArch64 Linux (mmap path). */
#define MAP_ANONYMOUS 0x20
#endif
#endif

#include "mips32rt.h"
#include "dbt/aot_emit.h"
#include "dbt/dbt.h"

/* MIPS major opcodes needed for block-boundary classification. */
#define DBT_OP_SPECIAL 0x00U
#define DBT_OP_REGIMM  0x01U
#define DBT_OP_J       0x02U
#define DBT_OP_JAL     0x03U
#define DBT_OP_BEQ     0x04U
#define DBT_OP_BNE     0x05U
#define DBT_OP_BLEZ    0x06U
#define DBT_OP_BGTZ    0x07U
#define DBT_OP_COP0    0x10U
#define DBT_OP_COP1    0x11U
#define DBT_OP_COP2    0x12U
#define DBT_OP_COP1X   0x13U
#define DBT_OP_BEQL    0x14U
#define DBT_OP_BNEL    0x15U
#define DBT_OP_BLEZL   0x16U
#define DBT_OP_BGTZL   0x17U

/* COP1 rs classes: moves (Phase 1 fpmove), branch (control), else FP arith. */
#define DBT_COP1_MFC1 0x00U
#define DBT_COP1_CFC1 0x02U
#define DBT_COP1_MTC1 0x04U
#define DBT_COP1_CTC1 0x06U
#define DBT_COP1_BC   0x08U

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

static void dbt_ras_push(uint32_t pc);

/* Process-wide shared SMC page-version table and epochs (M32-5, M32-6):
 * any thread performing SMC / cacheflush / mprotect / munmap / SYNCI
 * updates the shared table or bumps g_smc_flush_epoch, and every thread's
 * local dbt_cache validates against the shared state. */
static _Atomic uint32_t g_smc_lock = 0U;
static dbt_smc_entry_t  g_smc_table[DBT_SMC_TABLE_SIZE];
static _Atomic uint32_t g_smc_used_count = 0U;
static _Atomic uint64_t g_smc_flush_epoch = 1U;
static _Atomic uint64_t g_smc_ver_epoch = 1U;

/* RC4 threads: one cache per host thread.  A shared cache would race
 * concurrent compiles (bump allocator, block/ibtc/ras tables, SMC
 * flush) and corrupt execution; translations are guest-pc-keyed so
 * per-thread duplication stays correct.  Each thread's pool is
 * registered with the (likewise per-thread) hostfault range. */
static __thread dbt_cache_t *dbt_cache;

/* True when the decoded instruction transfers control with a delay slot:
 * J/JAL, integer branches (plain and likely), JR/JALR, and COP1 branches. */
static int dbt_is_control(const mips_dec_t *d)
{
    switch (d->op) {
    case DBT_OP_J:    case DBT_OP_JAL:
    case DBT_OP_BEQ:  case DBT_OP_BNE:  case DBT_OP_BLEZ:  case DBT_OP_BGTZ:
    case DBT_OP_BEQL: case DBT_OP_BNEL: case DBT_OP_BLEZL: case DBT_OP_BGTZL:
        return 1;
    case DBT_OP_REGIMM:
        switch (d->rt) {
        case 0x00U: case 0x01U: case 0x02U: case 0x03U:
        case 0x10U: case 0x11U: case 0x12U: case 0x13U:
            return 1;
        default:
            return 0;
        }
    case DBT_OP_COP1:
        return d->rs == DBT_COP1_BC;
    case DBT_OP_SPECIAL:
        return d->funct == 0x08U || d->funct == 0x09U;
    default:
        return 0;
    }
}

/* True for instructions with link semantics (ra = pc + 8 on the MIPS side). */
static int dbt_is_link(const mips_dec_t *d)
{
    if (d->op == DBT_OP_JAL) {
        return 1;
    }
    if (d->op == DBT_OP_SPECIAL && d->funct == 0x09U &&
        d->rd == MIPS32_REG_RA) {
        return 1;
    }
    if (d->op == DBT_OP_REGIMM &&
        (d->rt == 0x10U || d->rt == 0x11U || d->rt == 0x12U ||
         d->rt == 0x13U)) {
        return 1;
    }
    return 0;
}

/*
 * Still-fallback coprocessor test (Wave P lane P4): COP1 itself is now
 * fully owned by the L2c/L3b emitter (dbt_emit_fp declines unknown forms
 * to UNDEF/SINGLE_STEP exits), so only COP1X/COP2 still force a block
 * break into the interp_step fallback.  COP0 (other than the L2c-owned
 * RDHWR path) and traps remain dispatcher exits.
 */
static int dbt_is_unhandled_coproc(const mips_dec_t *d)
{
    if (d->op == DBT_OP_COP2) {
        return 1;
    }
    if (d->op == DBT_OP_COP1X) {
        return ((d->funct & 0x26U) == 0x20U) ? 0 : 1;
    }
    return 0;
}

/* SYSCALL/BREAK, trap instructions, and ERET end a block before them. */
static int dbt_is_trap_exit(const mips_dec_t *d)
{
    if (d->op == DBT_OP_SPECIAL &&
        (d->funct == 0x0cU || d->funct == 0x0dU || d->funct >= 0x30U)) {
        return 1;
    }
    if (d->op == DBT_OP_REGIMM && d->rt >= 0x08U && d->rt <= 0x0fU) {
        return 1;
    }
    if (d->op == DBT_OP_COP0 && d->rs == 0x10U && d->funct == 0x18U) {
        return 1;
    }
    return 0;
}

static uint32_t dbt_ibtc_index(uint32_t pc)
{
    return ((pc >> 2U) ^ (pc >> 12U)) & (MIPS32_IBTC_SIZE - 1U);
}

static int dbt_pool_ensure(mips32_ctx_t *ctx)
{
    (void)ctx;
    if (dbt_cache->pool != NULL) {
        return 0;
    }
#ifdef __APPLE__
    dbt_cache->pool = (uint8_t *)mmap(NULL, DBT_CODE_POOL_SIZE,
        PROT_READ | PROT_WRITE | PROT_EXEC,
        MAP_PRIVATE | MAP_ANONYMOUS | MAP_JIT, -1, 0);
#else
    dbt_cache->pool = (uint8_t *)mmap(NULL, DBT_CODE_POOL_SIZE,
        PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
#endif
    return dbt_cache->pool == MAP_FAILED ? -1 : 0;
}

/* Flush the calling thread's local translation cache and sync its flush epoch. */
static void dbt_flush_local(mips32_ctx_t *ctx)
{
    size_t i;

    if (ctx != NULL) {
        ctx->ibtc_ptr = 0U;
    }
    if (dbt_cache == NULL) {
        return;
    }
    for (i = 0; i < DBT_MAX_BLOCKS; i++) {
        dbt_cache->blocks[i].code = NULL;
        dbt_cache->blocks[i].code_len = 0;
        dbt_cache->block_link[i] = 0;
    }
    if (dbt_cache->ibtc != NULL) {
        for (i = 0; i < MIPS32_IBTC_SIZE; i++) {
            dbt_cache->ibtc[i].code = NULL;
        }
    }
    for (i = 0; i < MIPS32_RAS_SIZE; i++) {
        dbt_cache->ras[i].code = NULL;
    }
    dbt_cache->block_count = 0;
    dbt_cache->ras_top = 0;
    dbt_cache->pool_used = 0;
    dbt_cache->last_valid = 0;
    dbt_cache->last_bi = 0;
    dbt_cache->smc_memo_valid = 0;
    dbt_cache->local_flush_epoch =
        atomic_load_explicit(&g_smc_flush_epoch, memory_order_acquire);
}

/* Drop every cached translation across all threads (explicit global SMC flush). */
static void dbt_flush_all(mips32_ctx_t *ctx)
{
    size_t i;

    mips32_spin_lock(&g_smc_lock);
    for (i = 0; i < DBT_SMC_TABLE_SIZE; i++) {
        g_smc_table[i].used = 0U;
    }
    atomic_store_explicit(&g_smc_used_count, 0U, memory_order_relaxed);
    atomic_fetch_add_explicit(&g_smc_ver_epoch, 1U, memory_order_relaxed);
    atomic_fetch_add_explicit(&g_smc_flush_epoch, 1U, memory_order_release);
    mips32_spin_unlock(&g_smc_lock);

    dbt_flush_local(ctx);
}

static int dbt_cache_ensure(mips32_ctx_t *ctx)
{
    if (ctx == NULL) {
        return -1;
    }
    if (dbt_cache == NULL) {
        dbt_cache = (dbt_cache_t *)calloc(1, sizeof(*dbt_cache));
        if (dbt_cache == NULL) {
            return -1;
        }
        dbt_cache->local_flush_epoch =
            atomic_load_explicit(&g_smc_flush_epoch, memory_order_acquire);
    }
    if (dbt_cache->ibtc == NULL) {
        dbt_cache->ibtc = (dbt_ibtc_entry_t *)calloc(MIPS32_IBTC_SIZE,
            sizeof(*dbt_cache->ibtc));
        if (dbt_cache->ibtc == NULL) {
            return -1;
        }
        if (atomic_load_explicit(&g_smc_used_count, memory_order_acquire) == 0U &&
            atomic_load_explicit(&g_smc_flush_epoch, memory_order_acquire) == 1U) {
            ctx->ibtc_ptr = (uint64_t)(uintptr_t)dbt_cache->ibtc;
        }
    }
    if (dbt_pool_ensure(ctx) != 0) {
        return -1;
    }
    return 0;
}

uint32_t dbt_smc_version(mips32_ctx_t *ctx, uint32_t page)
{
    size_t i;
    uint32_t v = 1U;
    uint64_t ver_ep;

    (void)ctx;
    if (atomic_load_explicit(&g_smc_used_count, memory_order_acquire) == 0U) {
        return 1U;
    }
    ver_ep = atomic_load_explicit(&g_smc_ver_epoch, memory_order_acquire);
    if (dbt_cache != NULL && dbt_cache->smc_memo_valid != 0 &&
        dbt_cache->smc_memo_page == page &&
        dbt_cache->local_ver_epoch == ver_ep) {
        return dbt_cache->smc_memo_version;
    }
    mips32_spin_lock(&g_smc_lock);
    ver_ep = atomic_load_explicit(&g_smc_ver_epoch, memory_order_relaxed);
    for (i = 0; i < DBT_SMC_TABLE_SIZE; i++) {
        if (g_smc_table[i].used != 0U && g_smc_table[i].page == page) {
            v = g_smc_table[i].version;
            break;
        }
    }
    mips32_spin_unlock(&g_smc_lock);
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
    size_t i;

    if (ctx != NULL) {
        ctx->ibtc_ptr = 0U;
    }
    if (dbt_cache != NULL) {
        dbt_cache->smc_memo_valid = 0;
    }
    mips32_spin_lock(&g_smc_lock);
    for (i = 0; i < DBT_SMC_TABLE_SIZE; i++) {
        if (g_smc_table[i].used != 0U && g_smc_table[i].page == page) {
            g_smc_table[i].version += 1U;
            if (g_smc_table[i].version == 0U) {
                g_smc_table[i].version = 1U;
            }
            atomic_fetch_add_explicit(&g_smc_ver_epoch, 1U,
                memory_order_release);
            mips32_spin_unlock(&g_smc_lock);
            return;
        }
    }
    for (i = 0; i < DBT_SMC_TABLE_SIZE; i++) {
        if (g_smc_table[i].used == 0U) {
            g_smc_table[i].page = page;
            g_smc_table[i].version = 2U;
            g_smc_table[i].used = 1U;
            atomic_fetch_add_explicit(&g_smc_used_count, 1U,
                memory_order_relaxed);
            atomic_fetch_add_explicit(&g_smc_ver_epoch, 1U,
                memory_order_release);
            mips32_spin_unlock(&g_smc_lock);
            return;
        }
    }
    /* M32-6: when all DBT_SMC_TABLE_SIZE slots are occupied, flush all
     * threads' caches and reset the shared SMC table rather than dropping
     * the invalidation. */
    for (i = 0; i < DBT_SMC_TABLE_SIZE; i++) {
        g_smc_table[i].used = 0U;
    }
    atomic_store_explicit(&g_smc_used_count, 0U, memory_order_relaxed);
    atomic_fetch_add_explicit(&g_smc_ver_epoch, 1U, memory_order_relaxed);
    atomic_fetch_add_explicit(&g_smc_flush_epoch, 1U, memory_order_release);
    mips32_spin_unlock(&g_smc_lock);
    dbt_flush_local(ctx);
}

static void dbt_ibtc_fill(uint32_t pc, void *code, uint32_t smc, size_t bi)
{
    uint32_t idx = dbt_ibtc_index(pc);

    dbt_cache->ibtc[idx].guest_pc = pc;
    dbt_cache->ibtc[idx].code = code;
    dbt_cache->ibtc[idx].smc_version = smc;
    dbt_cache->ibtc[idx].blk_idx = bi;
}

/* Strong backend for the rt32 weak hook (SMC): bridge guest mm/cache
 * maintenance onto per-page translation versions. Wide ranges fall back
 * to a full flush instead of a long per-page walk. */
void mips32_dbt_invalidate_range(mips32_ctx_t *ctx, uint32_t start,
                                 uint32_t end)
{
    uint64_t span;
    uint32_t page;

    if (end <= start) {
        if (end != start) {
            dbt_flush_all(ctx);
        }
        return;
    }
    span = (uint64_t)end - (uint64_t)start;
    if (span > (uint64_t)DBT_SMC_TABLE_SIZE * MIPS32_PAGE_SIZE) {
        dbt_flush_all(ctx);
        return;
    }
    for (page = mips32_page_down(start); page < end;
         page += MIPS32_PAGE_SIZE) {
        dbt_smc_bump(ctx, page);
    }
}

static void *dbt_pool_lookup(uint32_t pc, uint32_t smc, size_t *bip)
{
    size_t i;

    for (i = 0; i < dbt_cache->block_count; i++) {
        if (dbt_cache->blocks[i].guest_pc == pc &&
            dbt_cache->blocks[i].code != NULL &&
            dbt_cache->blocks[i].smc_version == smc) {
            dbt_ibtc_fill(pc, dbt_cache->blocks[i].code, smc, i);
            if (bip != NULL) {
                *bip = i;
            }
            return dbt_cache->blocks[i].code;
        }
    }
    return NULL;
}

/* Indexed lookup: same resolution as dbt_lookup, additionally reporting
 * the block-cache index in *bip (H3: lets dbt_main skip its O(n) metadata
 * rescan). Every path that publishes last_* also publishes last_bi. */
static void *dbt_lookup_bi(mips32_ctx_t *ctx, uint32_t pc, size_t *bip)
{
    uint32_t idx;
    dbt_ibtc_entry_t *e;
    uint32_t smc;
    size_t bi = 0;

    if (ctx == NULL || dbt_cache == NULL || dbt_cache->ibtc == NULL) {
        return NULL;
    }
    if (dbt_cache->local_flush_epoch !=
        atomic_load_explicit(&g_smc_flush_epoch, memory_order_acquire)) {
        dbt_flush_local(ctx);
        return NULL;
    }
    if (atomic_load_explicit(&g_smc_used_count, memory_order_acquire) != 0U ||
        atomic_load_explicit(&g_smc_flush_epoch, memory_order_acquire) > 1U) {
        ctx->ibtc_ptr = 0U;
    }
    smc = dbt_smc_version(ctx, mips32_page_down(pc));
    /* Single-entry direct-chaining memo: repeated self-loop dispatch. */
    if (dbt_cache->last_valid != 0 && dbt_cache->last_pc == pc &&
        dbt_cache->last_smc == smc && dbt_cache->last_code != NULL) {
        if (bip != NULL) {
            *bip = dbt_cache->last_bi;
        }
        return dbt_cache->last_code;
    }
    /* RAS fast path: a return to the recorded guest address pops the top.
     * The entry carries its resolved code and block index directly; no
     * O(N) pool rescan (dbt_main revalidates bi before use). */
    if (dbt_cache->ras_top > 0) {
        dbt_ras_entry_t *r = &dbt_cache->ras[dbt_cache->ras_top - 1];
        if (r->guest_pc == pc && r->code != NULL && r->smc_version == smc) {
            void *code = r->code;

            bi = r->blk_idx;
            dbt_cache->ras_top--;
            dbt_cache->last_pc = pc;
            dbt_cache->last_code = code;
            dbt_cache->last_smc = smc;
            dbt_cache->last_valid = 1;
            dbt_cache->last_bi = bi;
            if (bip != NULL) {
                *bip = bi;
            }
            return code;
        }
    }
    /* 4096-entry IBTC keyed by guest PC, validated by smc_version. */
    idx = dbt_ibtc_index(pc);
    e = &dbt_cache->ibtc[idx];
    if (e->code != NULL && e->guest_pc == pc && e->smc_version == smc) {
        dbt_cache->last_pc = pc;
        dbt_cache->last_code = e->code;
        dbt_cache->last_smc = smc;
        dbt_cache->last_valid = 1;
        dbt_cache->last_bi = e->blk_idx;
        if (bip != NULL) {
            *bip = e->blk_idx;
        }
        return e->code;
    }
    return dbt_pool_lookup(pc, smc, bip);
}

void *dbt_lookup(mips32_ctx_t *ctx, uint32_t pc)
{
    return dbt_lookup_bi(ctx, pc, NULL);
}

/* Wave P4 in-trampoline chaining: resolve next block via validated lookup. */
void *dbt_chain_next(mips32_ctx_t *ctx)
{
    void *code;

    if (ctx == NULL || ctx->difftest_enabled || ctx->trace_enabled) {
        return NULL;
    }
    if (dbt_cache != NULL && dbt_cache->local_flush_epoch !=
        atomic_load_explicit(&g_smc_flush_epoch, memory_order_acquire)) {
        dbt_flush_local(ctx);
        return NULL;
    }
    if (dbt_cache != NULL && dbt_cache->last_valid != 0 &&
        dbt_cache->last_bi < dbt_cache->block_count &&
        dbt_cache->block_link[dbt_cache->last_bi] != 0U) {
        dbt_ras_push(dbt_cache->blocks[dbt_cache->last_bi].guest_end);
    }
    code = dbt_lookup(ctx, ctx->pc);
    if (code == NULL) {
        return NULL;
    }
    ctx->blocks_executed++;
    return code;
}

static void dbt_ras_push(uint32_t pc)
{
    uint32_t smc;
    void *code;
    size_t bi = 0;
    dbt_ibtc_entry_t *e;

    if (dbt_cache->ras_top >= MIPS32_RAS_SIZE) {
        memmove(&dbt_cache->ras[0], &dbt_cache->ras[1],
            (MIPS32_RAS_SIZE - 1U) * sizeof(dbt_cache->ras[0]));
        dbt_cache->ras_top = MIPS32_RAS_SIZE - 1U;
    }
    smc = dbt_smc_version(NULL, mips32_page_down(pc));
    e = &dbt_cache->ibtc[dbt_ibtc_index(pc)];
    if (e->code != NULL && e->guest_pc == pc && e->smc_version == smc) {
        code = e->code;
        bi = e->blk_idx;
    } else {
        code = dbt_pool_lookup(pc, smc, &bi);
    }
    dbt_cache->ras[dbt_cache->ras_top].guest_pc = pc;
    dbt_cache->ras[dbt_cache->ras_top].code = code;
    dbt_cache->ras[dbt_cache->ras_top].smc_version = smc;
    dbt_cache->ras[dbt_cache->ras_top].blk_idx = bi;
    dbt_cache->ras_top++;
}

/*
 * Publish emitted bytes with W^X discipline: the pool rests RX, flips to
 * RW for the copy, flips back to RX, then the I-cache is cleared over the
 * new range before the block becomes visible to dbt_lookup.
 */
static void *dbt_publish(mips32_ctx_t *ctx, const uint8_t *bytes, size_t len)
{
    uintptr_t base;
    void *dst;

    (void)ctx;
    len = (len + 3U) & ~(size_t)3U;
    if (len == 0U || len > DBT_CODE_POOL_SIZE) {
        return NULL;
    }
    if (dbt_cache->pool_used + len > DBT_CODE_POOL_SIZE) {
        dbt_flush_local(ctx);
    }
    base = (uintptr_t)dbt_cache->pool;
    dst = (void *)(base + dbt_cache->pool_used);
#ifdef __APPLE__
    pthread_jit_write_protect_np(0);
    memcpy(dst, bytes, len);
    pthread_jit_write_protect_np(1);
    sys_icache_invalidate(dst, len);
#else
    {
        uintptr_t start = base & ~(uintptr_t)4095U;
        uintptr_t end = (base + dbt_cache->pool_used + len + 4095U) & ~(uintptr_t)4095U;
        if (mprotect((void *)start, end - start, PROT_READ | PROT_WRITE) != 0) {
            return NULL;
        }
        memcpy(dst, bytes, len);
        if (mprotect((void *)start, end - start, PROT_READ | PROT_EXEC) != 0) {
            return NULL;
        }
        __builtin___clear_cache((char *)dst, (char *)dst + len);
    }
#endif
    dbt_cache->pool_used += len;
    ctx->wx_transitions++;
    ctx->icache_flushes++;
    return dst;
}

int dbt_compile(mips32_ctx_t *ctx, uint32_t pc)
{
    /* RC4 threads: the staging buffer must be per-thread.  Caches and
     * pools are already __thread, but a shared static buffer let two
     * threads' concurrent compiles interleave bytes, publishing
     * corrupt blocks (observed as host SIGILL in zeroed pool gaps). */
    static __thread uint8_t staging[DBT_STAGING_SIZE];
    mips_dec_t insns[MIPS32_DBT_MAX_INSNS];
    uint32_t cur = pc;
    unsigned count = 0;
    unsigned link = 0;
    uint32_t end = pc;
    uint32_t word = 0;
    uint32_t smc = 0;
    size_t out_len = 0;
    uint32_t out_end = 0;
    void *code = NULL;
    dbt_block_t *b = NULL;

    if (ctx == NULL) {
        return MIPS_FAULT;
    }
    if (dbt_cache_ensure(ctx) != 0) {
        return MIPS_FAULT;
    }
    /* SPEC 2.2: a block starting at the last word of a page always
     * single-steps (the branch+delay-slot pair spans the page). */
    if ((pc & 0xFFFU) == 0xFFCU) {
        return 1;
    }
    smc = dbt_smc_version(ctx, mips32_page_down(pc));
    while (count < MIPS32_DBT_MAX_INSNS) {
        mips_dec_t *d = &insns[count];

        if (mips_fetch(ctx, cur, &word) != 0) {
            if (count == 0U) {
                if (ctx->exit_reason == MIPS32_EXIT_NONE) {
                    mips_fault(ctx, cur);
                }
                return MIPS_FAULT;
            }
            break;
        }
        mips_decode(word, d);
        /* COP1X/COP2 and unknown system classes fall back to interp. */
        if (dbt_is_unhandled_coproc(d)) {
            break;
        }
        if (dbt_is_trap_exit(d)) {
            break;
        }
        if (dbt_is_control(d)) {
            /* SPEC 2.2: a branch at the last word of a page ends the
             * block *before* it; interp_step runs the pair later. */
            if ((cur & 0xFFFU) == 0xFFCU) {
                break;
            }
            /* A control + delay-slot pair needs two decode slots. */
            if (count + 1U >= MIPS32_DBT_MAX_INSNS) {
                break;
            }
            if (mips_fetch(ctx, cur + 4U, &word) != 0) {
                /* Delay slot off the mapped page: stop before the
                 * branch when a prefix exists, else single-step. */
                if (count == 0U) {
                    return 1;
                }
                break;
            }
            mips_decode(word, &insns[count + 1]);
            link = (unsigned)dbt_is_link(d);
            count += 2U;
            end = cur + 8U;
            break;
        }
        count++;
        end = cur + 4U;
        /* A non-control word at the page end closes the block. */
        if ((cur & 0xFFFU) == 0xFFCU) {
            break;
        }
        cur += 4U;
    }
    if (count == 0U) {
        /* Fallback-class, trap, or cross-page head: single-step it. */
        return 1;
    }
    if (dbt_emit_int(ctx, pc, insns, count, staging, sizeof(staging),
            &out_len, &out_end) != 0) {
        return 1;
    }
    if (out_len == 0U || out_len > sizeof(staging)) {
        return 1;
    }
    code = dbt_publish(ctx, staging, out_len);
    if (code == NULL) {
        return 1;
    }
    if (dbt_cache->block_count >= DBT_MAX_BLOCKS) {
        dbt_flush_local(ctx);
        code = dbt_publish(ctx, staging, out_len);
        if (code == NULL) {
            return 1;
        }
    }
    b = &dbt_cache->blocks[dbt_cache->block_count];
    b->guest_pc = pc;
    b->guest_end = (out_end != 0U) ? out_end : end;
    b->code = code;
    b->code_len = out_len;
    b->smc_version = smc;
    /* Wave C2 --cache cold emit: record the published guest range. */
    mips32_aot_note_block(ctx, pc, b->guest_end);
    dbt_cache->block_link[dbt_cache->block_count] = (uint8_t)link;
    dbt_ibtc_fill(pc, code, smc, dbt_cache->block_count);
    dbt_cache->block_count++;
    ctx->blocks_compiled++;
    return 0;
}

/* Wave C2: trace replay lives in src/dbt/trace.c; expose the block table. */
size_t dbt_trace_table(const dbt_block_t **out)
{
    if (out != NULL) {
        *out = (dbt_cache != NULL) ? dbt_cache->blocks : NULL;
    }
    return (dbt_cache != NULL) ? dbt_cache->block_count : 0U;
}

static int dbt_step_fallback(mips32_ctx_t *ctx)
{
    int rc;

    ctx->exit_reason = MIPS32_EXIT_NONE;
    ctx->exit_info = 0;
    rc = interp_step(ctx);
    if (rc == MIPS_FAULT && ctx->exit_reason == MIPS32_EXIT_NONE) {
        return 0;
    }
    if (rc != 0 || ctx->exit_reason != MIPS32_EXIT_NONE) {
        (void)fprintf(stderr, "mips32rt: dbt stopped (reason %u, info 0x%x)\n",
            ctx->exit_reason, ctx->exit_info);
        return 1;
    }
    return 0;
}

int dbt_main(mips32_ctx_t *ctx)
{
    if (ctx == NULL || dbt_cache_ensure(ctx) != 0) {
        return 1;
    }
    mips32_aot_warm(ctx);
    mips_hostfault_install(dbt_cache->pool, DBT_CODE_POOL_SIZE);
    for (;;) {
        uint32_t pc = ctx->pc;
        const dbt_block_t *b = NULL;
        size_t bi = 0;
        int have_b = 0;
        void *code = NULL;
        uint32_t reason = MIPS32_EXIT_NONE;

        if (ctx->exit_reason != MIPS32_EXIT_NONE) {
            (void)fprintf(stderr, "mips32rt: dbt stopped (reason %u, info 0x%x)\n",
                ctx->exit_reason, ctx->exit_info);
            return 1;
        }
        code = dbt_lookup_bi(ctx, pc, &bi);
        if (code == NULL) {
            int cr = dbt_compile(ctx, pc);

            if (cr == MIPS_FAULT) {
                if (ctx->exit_reason == MIPS32_EXIT_NONE) {
                    continue;
                }
                (void)fprintf(stderr,
                    "mips32rt: dbt stopped (reason %u, info 0x%x)\n",
                    ctx->exit_reason, ctx->exit_info);
                return 1;
            }
            if (cr != 0) {
                if (dbt_step_fallback(ctx) != 0) {
                    return 1;
                }
                continue;
            }
            code = dbt_lookup_bi(ctx, pc, &bi);
            if (code == NULL) {
                if (dbt_step_fallback(ctx) != 0) {
                    return 1;
                }
                continue;
            }
        }
        if (bi < dbt_cache->block_count &&
            dbt_cache->blocks[bi].guest_pc == pc &&
            dbt_cache->blocks[bi].code == code) {
            b = &dbt_cache->blocks[bi];
            have_b = 1;
        }
        if (ctx->difftest_enabled || ctx->trace_enabled ||
            atomic_load_explicit(&g_smc_used_count, memory_order_acquire) != 0U ||
            atomic_load_explicit(&g_smc_flush_epoch, memory_order_acquire) > 1U) {
            ctx->ibtc_ptr = 0U;
        } else {
            ctx->ibtc_ptr = (uint64_t)(uintptr_t)dbt_cache->ibtc;
        }
        if (mips_hostfault_run(ctx, code, &reason) != 0) {
            continue;
        }
        ctx->blocks_executed++;
        if (have_b != 0 && ctx->trace_enabled) {
            dbt_trace_block(ctx, b);
        }
        switch (reason) {
        case MIPS32_EXIT_NONE:
        case MIPS32_EXIT_BRANCH:
            if (have_b != 0 && dbt_cache->block_link[bi] != 0U) {
                dbt_ras_push(b->guest_end);
            }
            ctx->exit_reason = MIPS32_EXIT_NONE;
            continue;
        case MIPS32_EXIT_SYSCALL:
            ctx->exit_reason = MIPS32_EXIT_NONE;
            ctx->exit_info = 0;
            ctx->llbit = 0;
            ctx->sc_pc_advanced = 1U;
            (void)mips_syscall(ctx);
            ctx->sc_pc_advanced = 0U;
            ctx->syscalls_executed++;
            if (ctx->exit_reason != MIPS32_EXIT_NONE) {
                (void)fprintf(stderr,
                    "mips32rt: dbt stopped (reason %u, info 0x%x)\n",
                    ctx->exit_reason, ctx->exit_info);
                return 1;
            }
            continue;
        case MIPS32_EXIT_UNDEF:
        case MIPS32_EXIT_SINGLE_STEP:
        case MIPS32_EXIT_TRAP:
            if (dbt_step_fallback(ctx) != 0) {
                return 1;
            }
            continue;
        case MIPS32_EXIT_FAULT: {
            uint32_t info = ctx->exit_info;
            int signo = (ctx->fixade_enabled != 0U ||
                         (info & 3U) == 0U) ? 11 : 10;

            mips_trap(ctx, signo, info);
            if (ctx->exit_reason != MIPS32_EXIT_NONE) {
                return 1;
            }
            continue;
        }
        default:
            (void)fprintf(stderr, "mips32rt: dbt stopped (reason %u, info 0x%x)\n",
                ctx->exit_reason, ctx->exit_info);
            return 1;
        }
    }
}

