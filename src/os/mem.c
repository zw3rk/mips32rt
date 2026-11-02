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

#ifndef MAP_ANONYMOUS
#ifdef MAP_ANON
#define MAP_ANONYMOUS MAP_ANON
#endif
#endif

/* RC-U3-R2/R3 shared LL/SC epoch table: 4096 64-bit generations at the
 * unmappable guest address MIPS32_LL_EPOCH_GVA (above
 * MIPS32_TASK_SIZE_TOP, so no guest mapping can alias it and the
 * region walker never covers it), plus one 64-bit spinlock word right
 * after the table.  Both engines index table[(addr >> 6) & 4095]:
 * every store advances the touched 64-byte lines, LL snapshots the
 * full 64-bit generation into ctx->ll_epoch_snap, and SC verifies the
 * snapshot before committing its write (bumping on success).  A
 * same-value cross-thread store therefore fails the SC even though
 * the value compare alone would succeed.  Full 64-bit generations
 * never wrap in practice, closing the 8-bit wraparound hole. */
#define MIPS32_LL_EPOCH_GVA   0xFFFF0000u
#define MIPS32_LL_EPOCH_WORDS 4096u
#define MIPS32_LL_EPOCH_BYTES (4096u * 8u + 16u)
#define MIPS32_LL_LOCK_OFFSET (4096u * 8u)
#define MIPS32_LL_OWNER_OFFSET (4096u * 8u + 8u)
/* Wave P4 ll_active flag: unused upper 32 bits of tab[4096] (lock word).
 * mips_ll_record sets it to 1 (release); ordinary stores test it and
 * skip all spinlock/epoch traffic when it is 0. */
#define MIPS32_LL_ACTIVE_OFFSET (4096u * 8u + 4u)

static _Atomic uint64_t *ll_epoch_table(mips32_ctx_t *ctx);

/* LL/SC exclusion: the lock word and owning ctx live in the shared
 * epoch mapping itself (lock at table index 4096, owner at 4097), so the
 * C engine and inline DBT sequences serialize on the SAME word
 * (disjoint locks do not mutually exclude). Every store's epoch bump
 * and every SC check-and-store run under it, so an intervening
 * same-value store cannot slip between the SC's verification and its
 * commit. Taken only around short reservation ops, never across
 * syscalls. mips_ll_abandon releases the lock for the faulting ctx
 * when a host fault abandons a block mid-critical-section (the owner
 * slot proves the faulting thread holds it, so a live holder is never
 * disturbed). */
static _Atomic uint32_t *mips_ll_lockword(mips32_ctx_t *ctx)
{
    _Atomic uint64_t *tab;

    if (ctx == NULL) {
        return NULL;
    }
    tab = ll_epoch_table(ctx);
    if (tab == NULL) {
        return NULL;
    }
    return (_Atomic uint32_t *)(void *)&tab[4096u];
}

static _Atomic uint64_t *mips_ll_ownerword(mips32_ctx_t *ctx)
{
    _Atomic uint64_t *tab;

    if (ctx == NULL) {
        return NULL;
    }
    tab = ll_epoch_table(ctx);
    if (tab == NULL) {
        return NULL;
    }
    return &tab[4097u];
}

void mips_ll_lock(mips32_ctx_t *ctx)
{
    _Atomic uint32_t *w = mips_ll_lockword(ctx);
    _Atomic uint64_t *o;

    if (w == NULL) {
        return;
    }
    while (atomic_exchange_explicit(w, 1u, memory_order_acquire) != 0u) {
    }
    o = mips_ll_ownerword(ctx);
    if (o != NULL) {
        atomic_store_explicit(o, (uint64_t)(uintptr_t)ctx,
                              memory_order_relaxed);
    }
}

void mips_ll_unlock(mips32_ctx_t *ctx)
{
    _Atomic uint32_t *w = mips_ll_lockword(ctx);
    _Atomic uint64_t *o = mips_ll_ownerword(ctx);

    if (o != NULL) {
        atomic_store_explicit(o, (uint64_t)0u, memory_order_relaxed);
    }
    if (w != NULL) {
        atomic_store_explicit(w, 0u, memory_order_release);
    }
}

void mips_ll_abandon(mips32_ctx_t *ctx)
{
    _Atomic uint64_t *o = mips_ll_ownerword(ctx);
    _Atomic uint32_t *w;

    if (ctx == NULL || o == NULL) {
        return;
    }
    if (atomic_load_explicit(o, memory_order_relaxed) !=
        (uint64_t)(uintptr_t)ctx) {
        return;
    }
    atomic_store_explicit(o, (uint64_t)0u, memory_order_relaxed);
    w = mips_ll_lockword(ctx);
    if (w != NULL) {
        atomic_store_explicit(w, 0u, memory_order_relaxed);
    }
}

static void mips_store_locked(mips32_ctx_t *ctx, uint32_t va,
    const void *src, uint32_t len);

/* Forward: on-demand epoch mapping (defined below fixade_on). */
int mips_ll_epoch_ensure(mips32_ctx_t *ctx);

int guest_mem_init(mips32_ctx_t *ctx)
{
    if (ctx == NULL) {
        return MIPS_FAULT;
    }
    rt32_host_probe(ctx);
    if (rt32_vm_init(ctx, UINT64_MAX) != 0) {
        return MIPS_FAULT;
    }
    /* Eager epoch mapping for direct guest_mem_init users; the lazy
     * path in ll_epoch_table covers entry points that never call this
     * (production main.c reserves the window itself). */
    if (mips_ll_epoch_ensure(ctx) == 0) {
        return MIPS_FAULT;
    }
    ctx->u3_pad[0] = 0u;
    ctx->u3_pad[1] = 0u;
    ctx->u3_pad[2] = 0u;
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
    return mips32_range_ok(ctx, va, len, need);
}

/* Lane L4a queries (src/os/signals.c): true when signo has a real
 * guest handler; mips_trap delivers or dies by the signal.  Both are
 * declared by src/mips32rt.h. */
extern int mips_signal_has_handler(int signo);
extern void mips_trap(mips32_ctx_t *ctx, int signo, uint32_t addr);

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

/* Regime-A2 access validation (RC-U3-r3 #4): route every byte through
 * the Soft-TLB miss helper so unmapped pages fault, clean COW pages
 * promote on first write, and the TLB entry is installed for the
 * (future) DBT fast path. Byte-granular so spanning and fixade-
 * emulated accesses validate every touched page. Returns 0 when the
 * access may proceed (fault already recorded otherwise). */
static int a2_validate(mips32_ctx_t *ctx, uint32_t va, uint32_t len,
                       int is_write)
{
    uint32_t i;

    for (i = 0u; i < len; i++) {
        if (mips32_vm_tlb_miss(ctx, va + i, is_write, 1u) != 0) {
            return MIPS_FAULT;
        }
    }
    return 0;
}

int guest_ld8(mips32_ctx_t *ctx, uint32_t va, uint32_t *out)
{
    uint8_t b;

    if (ctx == NULL || out == NULL) {
        return MIPS_FAULT;
    }
    if (ctx->vm_regime == MIPS32_VM_REGIME_A2) {
        if (a2_validate(ctx, va, 1U, 0) != 0) {
            return MIPS_FAULT;
        }
    } else if (!range_covered(ctx, va, 1U, (uint32_t)PROT_READ)) {
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
    if (ctx->vm_regime == MIPS32_VM_REGIME_A2) {
        if (a2_validate(ctx, va, 1U, 1) != 0) {
            return MIPS_FAULT;
        }
    } else if (!range_covered(ctx, va, 1U, (uint32_t)PROT_WRITE)) {
        mips_fault(ctx, va);
        return MIPS_FAULT;
    }
    b = (uint8_t)(val & 0xFFU);
    mips_store_locked(ctx, va, &b, 1U);
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

/* The G this process last mapped the epoch page for (idempotent
 * MAP_FIXED remap when the window moves, e.g. re-exec with an explicit
 * --window; concurrent CLONE_VM mappers just repeat the same mapping). */
static _Atomic uint64_t ll_epoch_mapped_base = (uint64_t)UINT64_MAX;

/* Map the shared epoch page at G + MIPS32_LL_EPOCH_GVA on demand (the
 * production entry point in src/main.c reserves the window itself and
 * never calls guest_mem_init, so every live path funnels through here).
 * Returns 1 when the table is usable, 0 when the reservation failed. */
int mips_ll_epoch_ensure(mips32_ctx_t *ctx)
{
    void *tab;
    void *res;
    uint64_t base;

    if (ctx == NULL) {
        return 0;
    }
    base = atomic_load_explicit(&ll_epoch_mapped_base,
                                memory_order_relaxed);
    if (base == ctx->guest_base) {
        return 1;
    }
    tab = (void *)(uintptr_t)(ctx->guest_base +
                              (uint64_t)MIPS32_LL_EPOCH_GVA);
#ifdef __APPLE__
    (void)res;
    if (mprotect(tab, 0xC000u, PROT_READ | PROT_WRITE) != 0) {
        return 0;
    }
#else
    res = mmap(tab, (size_t)MIPS32_LL_EPOCH_BYTES,
               PROT_READ | PROT_WRITE,
               MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (res == MAP_FAILED || res != tab) {
        if (res != MAP_FAILED && res != tab) {
            (void)munmap(res, (size_t)MIPS32_LL_EPOCH_BYTES);
        }
        return 0;
    }
#endif
    memset(tab, 0, (size_t)MIPS32_LL_EPOCH_BYTES);
    atomic_store_explicit(&ll_epoch_mapped_base, ctx->guest_base,
                          memory_order_relaxed);
    return 1;
}

/* The shared epoch table lives at G + MIPS32_LL_EPOCH_GVA (mapped on
 * demand by mips_ll_epoch_ensure); plain host pointer, never a guest
 * range.  NULL when the reservation failed: callers degrade to the
 * value-compare-only protocol instead of faulting. */
static _Atomic uint64_t *ll_epoch_table(mips32_ctx_t *ctx)
{
    if (mips_ll_epoch_ensure(ctx) == 0) {
        return NULL;
    }
    return (_Atomic uint64_t *)(void *)(uintptr_t)(ctx->guest_base +
                                                   (uint64_t)MIPS32_LL_EPOCH_GVA);
}

static uint32_t ll_epoch_idx(uint32_t va)
{
    return (va >> 6) & (MIPS32_LL_EPOCH_WORDS - 1u);
}

/* Advance the epoch for every 64-byte line in [va, va + len): first and
 * last line, which covers all stores up to 4 bytes (a 4-byte access
 * touches at most two lines). Locked variant runs inside the caller's
 * mips_ll_lock critical section; the plain variant takes the lock
 * itself. */
static void ll_epoch_bump_locked(mips32_ctx_t *ctx, uint32_t va,
    uint32_t len)
{
    _Atomic uint64_t *tab;
    uint32_t first;
    uint32_t last;

    if (ctx == NULL || len == 0u) {
        return;
    }
    tab = ll_epoch_table(ctx);
    if (tab == NULL) {
        return;
    }
    first = ll_epoch_idx(va);
    last = ll_epoch_idx(va + len - 1u);
    atomic_fetch_add_explicit(&tab[first], 1u, memory_order_relaxed);
    if (last != first) {
        atomic_fetch_add_explicit(&tab[last], 1u, memory_order_relaxed);
    }
}

/* LL epoch snapshot: the table entry's full 64-bit generation in
 * ctx->ll_epoch_snap (appended at the struct tail, offsets above
 * untouched). Generations never wrap in practice. */
static void ll_seq_save(mips32_ctx_t *ctx, uint64_t seq)
{
    ctx->ll_epoch_snap = seq;
}

static uint64_t ll_seq_saved(const mips32_ctx_t *ctx)
{
    return ctx->ll_epoch_snap;
}

/* RC-U3-R2 LL record (interp LL path): llbit/lladdr/llval plus the
 * epoch snapshot the later SC verifies. Wave P4: also sets the
 * ll_active flag (release) so later ordinary stores take the slow
 * epoch path. */
void mips_ll_record(mips32_ctx_t *ctx, uint32_t addr, uint32_t val)
{
    _Atomic uint64_t *tab;
    _Atomic uint8_t *flag;

    if (ctx == NULL) {
        return;
    }
    ctx->llbit  = 1u;
    ctx->lladdr = addr;
    ctx->llval  = val;
    tab = ll_epoch_table(ctx);
    if (tab == NULL) {
        ll_seq_save(ctx, 0u);
        return;
    }
    ll_seq_save(ctx, atomic_load_explicit(&tab[ll_epoch_idx(addr)],
                                          memory_order_relaxed));
    flag = (_Atomic uint8_t *)(void *)((uint8_t *)(void *)tab +
                                       MIPS32_LL_ACTIVE_OFFSET);
    atomic_store_explicit(flag, (uint8_t)1u, memory_order_release);
}

/* RC-U3 LL/SC: an ordinary store overlapping the reserved word breaks
 * this thread's reservation (the later SC then fails its checks).
 * Spurious SC failure is architecturally legal; the overlap test keeps
 * reservations for other words alive.  Every store also advances the
 * shared epoch (regardless of llbit: another thread may hold a live
 * reservation on the line), so a same-value cross-thread store still
 * fails a later SC via the epoch check.  Locked body: the caller's
 * mips_ll_lock critical section must already cover the data store, so
 * verification and commit stay indivisible (RC-U3-r3). */
static void note_store_locked(mips32_ctx_t *ctx, uint32_t va, uint32_t len)
{
    uint64_t end64;

    if (ctx == NULL || len == 0u) {
        return;
    }
    ll_epoch_bump_locked(ctx, va, len);
    if (ctx->llbit == 0u) {
        return;
    }
    end64 = (uint64_t)va + (uint64_t)len;
    if ((uint64_t)va < (uint64_t)ctx->lladdr + 4u &&
        end64 > (uint64_t)ctx->lladdr) {
        ctx->llbit = 0u;
    }
}

/* Locked guest store: data write plus epoch/reservation update under
 * one mips_ll_lock critical section. All interp stores go through
 * here so an SC's check-and-store can never interleave with them.
 * Wave P4: when the ll_active flag is 0 (no LL ever recorded) run
 * only the plain guest store with zero spinlock/epoch traffic. */
static void mips_store_locked(mips32_ctx_t *ctx, uint32_t va,
    const void *src, uint32_t len)
{
    _Atomic uint64_t *tab;
    _Atomic uint8_t *flag;

    if (ctx == NULL || src == NULL || len == 0u) {
        return;
    }
    tab = ll_epoch_table(ctx);
    if (tab != NULL) {
        flag = (_Atomic uint8_t *)(void *)((uint8_t *)(void *)tab +
                                           MIPS32_LL_ACTIVE_OFFSET);
        if (atomic_load_explicit(flag, memory_order_acquire) == 0u) {
            memcpy(mips32_guest_ptr(ctx, va), src, len);
            return;
        }
    }
    mips_ll_lock(ctx);
    memcpy(mips32_guest_ptr(ctx, va), src, len);
    note_store_locked(ctx, va, len);
    mips_ll_unlock(ctx);
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
        if (ctx->vm_regime == MIPS32_VM_REGIME_A2) {
            if (a2_validate(ctx, va, 2U, 0) != 0) {
                return MIPS_FAULT;
            }
        } else if (!range_covered(ctx, va, 2U, (uint32_t)PROT_READ)) {
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
    if (ctx->vm_regime == MIPS32_VM_REGIME_A2) {
        if (a2_validate(ctx, va, 2U, 0) != 0) {
            return MIPS_FAULT;
        }
    } else if (!range_covered(ctx, va, 2U, (uint32_t)PROT_READ)) {
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
        if (ctx->vm_regime == MIPS32_VM_REGIME_A2) {
            if (a2_validate(ctx, va, 2U, 1) != 0) {
                return MIPS_FAULT;
            }
        } else if (!range_covered(ctx, va, 2U, (uint32_t)PROT_WRITE)) {
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
        mips_store_locked(ctx, va, p, 2U);
        return 0;
    }
    if (ctx->vm_regime == MIPS32_VM_REGIME_A2) {
        if (a2_validate(ctx, va, 2U, 1) != 0) {
            return MIPS_FAULT;
        }
    } else if (!range_covered(ctx, va, 2U, (uint32_t)PROT_WRITE)) {
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
    mips_store_locked(ctx, va, b, 2U);
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
        if (ctx->vm_regime == MIPS32_VM_REGIME_A2) {
            if (a2_validate(ctx, va, 4U, 0) != 0) {
                return MIPS_FAULT;
            }
        } else if (!range_covered(ctx, va, 4U, (uint32_t)PROT_READ)) {
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
    if (ctx->vm_regime == MIPS32_VM_REGIME_A2) {
        if (a2_validate(ctx, va, 4U, 0) != 0) {
            return MIPS_FAULT;
        }
    } else if (!range_covered(ctx, va, 4U, (uint32_t)PROT_READ)) {
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
        if (ctx->vm_regime == MIPS32_VM_REGIME_A2) {
            if (a2_validate(ctx, va, 4U, 1) != 0) {
                return MIPS_FAULT;
            }
        } else if (!range_covered(ctx, va, 4U, (uint32_t)PROT_WRITE)) {
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
        mips_store_locked(ctx, va, q, 4U);
        return 0;
    }
    if (ctx->vm_regime == MIPS32_VM_REGIME_A2) {
        if (a2_validate(ctx, va, 4U, 1) != 0) {
            return MIPS_FAULT;
        }
    } else if (!range_covered(ctx, va, 4U, (uint32_t)PROT_WRITE)) {
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
    mips_store_locked(ctx, va, b, 4U);
    return 0;
}

/* RC-U3-r3 atomic SC: verify the epoch snapshot, then compare-and-store,
 * then bump the epoch, all under mips_ll_lock. Checking the epoch
 * BEFORE the write (rather than after, as before) means a reservation
 * loss fails without touching memory: no committed write can ever
 * outlive a failed SC. The lock serializes against ordinary stores'
 * bumps, closing the same-value race window entirely. */
int guest_sc32(mips32_ctx_t *ctx, uint32_t va, uint32_t exp_val,
               uint32_t new_val, int *ok)
{
    uint32_t  exp_pat;
    uint32_t  new_pat;
    uint32_t *hp;
    int       swapped;
    _Atomic uint64_t *tab;
    uint32_t  idx;
    uint64_t  want;
    uint64_t  s1;

    if (ctx == NULL || ok == NULL) {
        return MIPS_FAULT;
    }
    if ((va & 3U) != 0U) {
        mips_fault(ctx, va);
        return MIPS_FAULT;
    }
    if (ctx->vm_regime == MIPS32_VM_REGIME_A2) {
        if (a2_validate(ctx, va, 4U, 1) != 0) {
            return MIPS_FAULT;
        }
    } else if (!range_covered(ctx, va, 4U, (uint32_t)PROT_WRITE)) {
        mips_fault(ctx, va);
        return MIPS_FAULT;
    }
    /* A dead reservation (or one for another address) fails without
     * touching memory or the lock. */
    if (ctx->llbit == 0u || ctx->lladdr != va) {
        *ok = 0;
        return 0;
    }
    /* Value-domain compare like LL/SC: the host mapping holds the
     * guest-order byte pattern, so swap both sides on BE. Pure
     * computation, no shared state: safe outside the lock. */
    if (mips_is_be(ctx)) {
        exp_pat = ((exp_val >> 24) & 0xFFU) | ((exp_val >> 8) & 0xFF00U) |
                  ((exp_val << 8) & 0xFF0000U) | ((exp_val << 24) & 0xFF000000U);
        new_pat = ((new_val >> 24) & 0xFFU) | ((new_val >> 8) & 0xFF00U) |
                  ((new_val << 8) & 0xFF0000U) | ((new_val << 24) & 0xFF000000U);
    } else {
        exp_pat = exp_val;
        new_pat = new_val;
    }
    mips_ll_lock(ctx);
    tab = ll_epoch_table(ctx);
    if (tab == NULL) {
        idx = 0u;
        s1 = 0u;
        want = 0u;
    } else {
        idx  = ll_epoch_idx(va);
        want = ll_seq_saved(ctx);
        s1   = atomic_load_explicit(&tab[idx], memory_order_relaxed);
        if (s1 != want) {
            mips_ll_unlock(ctx);
            *ok = 0;
            return 0;
        }
    }
    hp = (uint32_t *)(void *)mips32_guest_ptr(ctx, va);
    swapped = 0;
    if (__atomic_compare_exchange_n(hp, &exp_pat, new_pat, 0,
                                    __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)) {
        swapped = 1;
    }
    if (swapped != 0 && tab != NULL) {
        /* Success is itself a store, so it advances the epoch while
         * still holding the lock: no ordinary store can slip between
         * the check above and this bump. */
        atomic_fetch_add_explicit(&tab[idx], 1u, memory_order_relaxed);
    }
    mips_ll_unlock(ctx);
    *ok = swapped;
    return 0;
}
