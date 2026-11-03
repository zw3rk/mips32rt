/*
 * src/os/threads.c — CLONE_VM threads + futex ops.
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 * O32 clone 4120, futex 4238; CLONE_VM threads share [G,G+4GiB) on
 * detached pthreads; futex WAIT/WAKE/BITSET/REQUEUE/WAKE_OP via host.
 */

#if defined(__linux__)
#define _GNU_SOURCE
#endif

#include "mips32rt.h"

#include "os/syscall_nr.h"
#include "os/syscalls_priv.h"

#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>

#if defined(__linux__)
#include <sys/syscall.h>
#endif

/* ---- Linux clone flags (uapi/linux/sched.h, arch-independent) ---- */

#define MIPS_CLONE_VM             0x00000100U
#define MIPS_CLONE_FS             0x00000200U
#define MIPS_CLONE_FILES          0x00000400U
#define MIPS_CLONE_SIGHAND        0x00000800U
#define MIPS_CLONE_PIDFD          0x00001000U
#define MIPS_CLONE_VFORK          0x00004000U
#define MIPS_CLONE_PARENT         0x00008000U
#define MIPS_CLONE_THREAD         0x00010000U
#define MIPS_CLONE_NEWNS          0x00020000U
#define MIPS_CLONE_SYSVSEM        0x00040000U
#define MIPS_CLONE_SETTLS         0x00080000U
#define MIPS_CLONE_PARENT_SETTID  0x00100000U
#define MIPS_CLONE_CHILD_CLEARTID 0x00200000U
#define MIPS_CLONE_UNTRACED       0x00800000U
#define MIPS_CLONE_CHILD_SETTID   0x01000000U
#define MIPS_CLONE_NEWCGROUP      0x02000000U
#define MIPS_CLONE_NEWUTS         0x04000000U
#define MIPS_CLONE_NEWIPC         0x08000000U
#define MIPS_CLONE_NEWUSER        0x10000000U
#define MIPS_CLONE_NEWPID         0x20000000U
#define MIPS_CLONE_NEWNET         0x40000000U
#define MIPS_CLONE_IO             0x80000000U

#define MIPS_CLONE_NEWNS_ALL                                                 \
    (MIPS_CLONE_NEWNS | MIPS_CLONE_NEWCGROUP | MIPS_CLONE_NEWUTS |           \
     MIPS_CLONE_NEWIPC | MIPS_CLONE_NEWUSER | MIPS_CLONE_NEWPID |            \
     MIPS_CLONE_NEWNET)

/* ---- Futex ops (uapi/linux/futex.h, arch-independent) ---- */

#define MIPS_FUTEX_REQUEUE     3
#define MIPS_FUTEX_CMP_REQUEUE 4
#define MIPS_FUTEX_WAKE_OP     5
#define MIPS_FUTEX_WAIT_BITSET 9
#define MIPS_FUTEX_WAKE_BITSET 10
#define MIPS_FUTEX_CLOCK_REALTIME 256

/* ---- Thread record (heap; ownership passes to the L4c wait4 reaper) ---- */

#define MIPS_THREAD_STACK_SIZE (2U * 1024U * 1024U)

#if defined(__linux__)
static void mips_thread_finish(mips32_ctx_t *ctx, uint32_t ctid, int status);
#endif

#define MIPS_FUTEX_OWNER_DIED 0x40000000U
#define MIPS_FUTEX_WAITERS 0x80000000U
#define MIPS_FUTEX_TID_MASK 0x3FFFFFFFU
#define MIPS_ROBUST_LIST_LIMIT 2048U

struct mips_thread {
    mips32_ctx_t ctx;
    void        *host_stack;
    struct mips_thread *next;
    uint32_t     set_ctid;
    uint32_t     clear_ctid;
    /* M32-R4-8/N-2: PARENT_SETTID address the child must write itself
     * when it aliases clear_ctid (0 when the parent writes it). */
    uint32_t     parent_settid;
    /* Parent/child handshake: the child publishes its host tid, then
     * wakes the parent, which needs the tid for the guest clone
     * return value before resuming. */
    _Atomic int  started;
    _Atomic int  child_tid;
};

/* Hosting thread id for --trace attribution: fresh every call (no
 * cache: fork children must attribute to their own tid, and a
 * per-print gettid costs microseconds against millisecond traces).
 * Unconditional (darwin builds trace too); harness-only, never
 * affects guest execution. */
long mips_trace_tid(void)
{
#if defined(__linux__) && defined(SYS_gettid)
    return syscall(SYS_gettid);
#else
    return (long)getpid();
#endif
}

#if defined(__linux__) && defined(SYS_futex) && defined(SYS_clone) && \
    defined(SYS_exit) && defined(SYS_gettid)

/* Live CLONE_VM children; the initial thread is never counted. */
static _Atomic int mips_live_clones = 0;
/* M32-R5-4/R5-10: reaper list of heap records + 2 MiB stacks. Detached
 * children exit via raw SYS_exit, so no pthread_join exists; the parent
 * reaps a record once its host tid is gone (tkill ESRCH), then unmaps
 * the stack and frees the record. Bonded by mips_reap_lock. */
static pthread_mutex_t mips_reap_lock = PTHREAD_MUTEX_INITIALIZER;
static struct mips_thread *mips_reap_head = NULL;

static void mips_reap_done(void)
{
    struct mips_thread *prev = NULL;
    struct mips_thread *t;
    if (pthread_mutex_lock(&mips_reap_lock) != 0) {
        return;
    }
    t = mips_reap_head;
    while (t != NULL) {
        struct mips_thread *nxt = t->next;
        int dead = 0;
        int tid = atomic_load_explicit(&t->child_tid, memory_order_relaxed);
        if (tid != 0) {
            long kr = syscall(SYS_tkill, (int)tid, 0);
            if (kr != 0 && errno == ESRCH) {
                dead = 1;
            }
        }
        if (dead) {
            if (prev == NULL) {
                mips_reap_head = nxt;
            } else {
                prev->next = nxt;
            }
            (void)munmap(t->host_stack, MIPS_THREAD_STACK_SIZE);
            free(t);
        } else {
            prev = t;
        }
        t = nxt;
    }
    (void)pthread_mutex_unlock(&mips_reap_lock);
}

/* M32-R5-5: bounded O32 robust_list wake on thread death. Walks up to
 * LIMIT entries plus the pending slot with checked BE-aware accesses;
 * for each futex at entry+futex_off with (val&TID_MASK)==tid, sets
 * OWNER_DIED and wakes one waiter when WAITERS is set. */
static void mips_robust_wake(mips32_ctx_t *ctx)
{
    uint8_t hb[12];
    uint32_t head, futex_off, pending, cur;
    uint32_t tid;
    unsigned n = 0U;
    int be;
    if (ctx == NULL || ctx->robust_list_head == 0U) {
        return;
    }
    be = mips_is_be(ctx);
    if (mips_sc_copy_from(ctx, hb, ctx->robust_list_head, 12U) != 0) {
        return;
    }
    head = mips_sc_ld32(hb, be);
    futex_off = mips_sc_ld32(hb + 4, be);
    pending = mips_sc_ld32(hb + 8, be);
    tid = ((uint32_t)ctx->host_tid) & MIPS_FUTEX_TID_MASK;
    if (tid == 0U) {
        tid = ((uint32_t)syscall(SYS_gettid)) & MIPS_FUTEX_TID_MASK;
    }
    cur = head;
    for (;;) {
        uint8_t nb[4], fb[4];
        uint32_t nxt, fva, val, nval;
        uint32_t entry_va;
        if (cur == 0U || n >= MIPS_ROBUST_LIST_LIMIT) {
            break;
        }
        entry_va = cur & ~1U;
        if (entry_va == ctx->robust_list_head) {
            break;
        }
        if (entry_va == 0U) {
            break;
        }
        if (mips_sc_copy_from(ctx, nb, entry_va, 4U) != 0) {
            break;
        }
        nxt = mips_sc_ld32(nb, be);
        if (pending != 0U && entry_va == (pending & ~1U)) {
            cur = nxt;
            n++;
            continue;
        }
        fva = entry_va + futex_off;
        if (mips_sc_copy_from(ctx, fb, fva, 4U) == 0) {
            val = mips_sc_ld32(fb, be);
            if ((val & MIPS_FUTEX_TID_MASK) == tid) {
                int need_wake = (val & MIPS_FUTEX_WAITERS) != 0U;
                nval = val | MIPS_FUTEX_OWNER_DIED;
                mips_sc_st32(fb, nval, be);
                (void)mips_sc_copy_to(ctx, fva, fb, 4U);
                if (need_wake) {
                    (void)syscall(SYS_futex, mips32_guest_ptr(ctx, fva),
                        (int)1, (uint32_t)1, NULL, NULL, (uint32_t)0);
                }
            }
        }
        cur = nxt;
        n++;
    }
    if (pending != 0U) {
        uint8_t fb[4];
        uint32_t pva = pending & ~1U;
        uint32_t fva, val, nval;
        if (pva != 0U && pva != ctx->robust_list_head) {
            fva = pva + futex_off;
            if (mips_sc_copy_from(ctx, fb, fva, 4U) == 0) {
                val = mips_sc_ld32(fb, be);
                if ((val & MIPS_FUTEX_TID_MASK) == tid) {
                    int need_wake = (val & MIPS_FUTEX_WAITERS) != 0U;
                    nval = val | MIPS_FUTEX_OWNER_DIED;
                    mips_sc_st32(fb, nval, be);
                    (void)mips_sc_copy_to(ctx, fva, fb, 4U);
                    if (need_wake) {
                        (void)syscall(SYS_futex,
                            mips32_guest_ptr(ctx, fva), (int)1,
                            (uint32_t)1, NULL, NULL, (uint32_t)0);
                    }
                }
            }
        }
    }
}

void mips_threads_fork_prepare(void)
{
    (void)pthread_mutex_lock(&mips_reap_lock);
}
void mips_threads_fork_release(void)
{
    (void)pthread_mutex_unlock(&mips_reap_lock);
}
/* Only forking thread survives; peers gone, records leak, lock reset. */
void mips_threads_fork_child(void)
{
    atomic_store_explicit(&mips_live_clones, 0, memory_order_relaxed);
    (void)pthread_mutex_unlock(&mips_reap_lock);
    (void)pthread_mutex_destroy(&mips_reap_lock);
    (void)pthread_mutex_init(&mips_reap_lock, NULL);
    mips_reap_head = NULL;
}

/* Write a host-known tid to a guest address (BE-aware, range-checked). */
static int thread_write_tid(mips32_ctx_t *ctx, uint32_t va, uint32_t tid)
{
    uint8_t buf[4];

    if (va == 0U) {
        return -EFAULT;
    }
    mips_sc_st32(buf, tid, mips_is_be(ctx));
    return mips_sc_copy_to(ctx, va, buf, 4U);
}

/* Child entry: publish tid, run the guest engine, then exit the thread. */
static int mips_thread_main(void *arg)
{
    struct mips_thread *t = (struct mips_thread *)arg;
    uint32_t            self;
    int                 rc;
    int                 status;

    self           = (uint32_t)syscall(SYS_gettid);
    t->ctx.host_tid = (int)self;
    t->ctx.is_thread_clone = true;
    if (t->ctx.engine == MIPS32_ENGINE_DBT) {
        rc = dbt_main(&t->ctx);
    } else {
        rc = interp_run(&t->ctx);
    }
    /* Engines only return on a stop reason; exit syscalls never return. */
    status = (rc == 0) ? 0 : 1;
    if (t->clear_ctid != 0U) {
        mips_thread_finish(&t->ctx, t->clear_ctid, status);
    } else {
        (void)atomic_fetch_sub_explicit(&mips_live_clones, 1,
                                        memory_order_relaxed);
        (void)syscall(SYS_exit, (int)status);
    }
    return 1; /* unreachable; keeps noreturn-less compilers quiet */
}

/* Shared thread-teardown tail (robust wake + CLEARTID 0-write plus
 * FUTEX_WAKE, live-clone accounting, raw SYS_exit): used by the
 * engine-return path and by guest exit().  Does not return. */
static void mips_thread_finish(mips32_ctx_t *ctx, uint32_t ctid, int status)
{
    mips_robust_wake(ctx);
    if (ctid != 0U) {
        (void)thread_write_tid(ctx, ctid, 0U);
        (void)syscall(SYS_futex, mips32_guest_ptr(ctx, ctid),
                      (int)MIPS_FUTEX_WAKE, (uint32_t)INT_MAX, NULL, NULL,
                      (uint32_t)0);
    }
    (void)atomic_fetch_sub_explicit(&mips_live_clones, 1,
                                    memory_order_relaxed);
    (void)syscall(SYS_exit, status);
    _Exit(status); /* unreachable; raw SYS_exit never returns */
}

/* Guest exit() inside a CLONE_VM thread (RC4): end this host thread
 * alone via the shared teardown tail.  The group stays alive;
 * exit_group still tears everything down.  Does not return. */
void mips_thread_exit(mips32_ctx_t *ctx, int status)
{
    mips_thread_finish(ctx, ctx->clear_child_tid, status);
}

/* Host thread entry for CLONE_VM-family guest threads (RC4): runs on
 * a musl-owned pthread (detached, on the mmap'd stack below) so the
 * child gets a real per-thread TLS block.  An earlier revision used a
 * raw SYS_clone child path without CLONE_SETTLS, which left the child
 * sharing the parent's TLS: the child's __thread guard/cache state
 * (hf_armed, hf_jb, dbt_cache, ...) aliased the parent's, so one
 * thread's disarm/recovery corrupted the other's in-flight block and
 * faulted unarmed pool code.  Guest-visible clone effects (TLS via
 * ulr, ptid/ctid writeback, CLEARTID wake) stay emulated in-band in
 * mips_thread_main; the host thread is only a VM-sharing vehicle and
 * never returns (engines exit the thread via raw SYS_exit). */
static void *mips_host_thread_entry(void *arg)
{
    struct mips_thread *t = (struct mips_thread *)arg;
    uint32_t self;

    self = (uint32_t)syscall(SYS_gettid);
    atomic_store_explicit(&t->child_tid, (int)self, memory_order_relaxed);
    /* Publish the guest tid before waking the parent: the parent returns
     * from clone only after this store, so a joining parent always
     * observes ctid == tid (or 0 after a fast child's clear), never a
     * stale value.  The child performs every startup write (SETTID,
     * plus the PARENT_SETTID-on-clear_ctid alias below); the parent
     * skips its SETTID write for those addresses, so the field stays
     * monotonic tid-then-0 and no resurrection race exists. */
    if (t->set_ctid != 0U) {
        (void)thread_write_tid(&t->ctx, t->set_ctid, self);
    }
    /* M32-R4-8/N-2: when PARENT_SETTID aliases clear_ctid (old musl
     * passes &new->tid for both), the child performs the parent
     * write before publishing started: a fast child that runs to
     * exit clears the word, and a later parent write would resurrect
     * it and hang the join.  The parent skips its own write below. */
    if (t->parent_settid != 0U && t->parent_settid != t->set_ctid) {
        (void)thread_write_tid(&t->ctx, t->parent_settid, self);
    }
    atomic_store_explicit(&t->started, 1, memory_order_release);
    (void)syscall(SYS_futex, &t->started, (int)MIPS_FUTEX_WAKE,
                  (uint32_t)INT_MAX, NULL, NULL, (uint32_t)0);
    (void)mips_thread_main(t);
    return NULL; /* unreachable; mips_thread_main exits the thread */
}

/* CLONE_VM-family clone; called with ctx->pc on the syscall instruction. */
int32_t mips_sc_clone(mips32_ctx_t *ctx, uint32_t sp)
{
    struct mips_thread *t = NULL;
    void               *stack = NULL;
    int                 ok = 1;
    int                 mmap_flags;
    uint32_t            flags;
    uint32_t            child_stack;
    uint32_t            ptid;
    uint32_t            tls;
    uint32_t            ctid;
    long                r;

    flags       = mips_sc_arg(ctx, sp, 0, &ok);
    child_stack = mips_sc_arg(ctx, sp, 1, &ok);
    ptid        = mips_sc_arg(ctx, sp, 2, &ok);
    tls         = mips_sc_arg(ctx, sp, 3, &ok);
    ctid        = mips_sc_arg(ctx, sp, 4, &ok);
    if (!ok) {
        return mips_sc_ret(ctx, -EFAULT);
    }
    ctx->llbit = 0U; /* SPEC 2.2: clone clears the LL reservation */
    flags &= ~MIPS_CLONE_UNTRACED; /* ptrace never attaches: ignored */
    if ((flags & (MIPS_CLONE_NEWNS_ALL | MIPS_CLONE_PIDFD)) != 0U) {
        return mips_sc_ret(ctx, -EINVAL); /* namespaces/pidfd unsupported */
    }
    if ((flags & MIPS_CLONE_VM) == 0U) {
        /* No address space shared: fork semantics (CoW). glibc implements
         * fork() as clone without CLONE_VM; vfork likewise arrives here. */
        extern int32_t mips_proc_fork(mips32_ctx_t *ctx, uint32_t sp);
        return mips_proc_fork(ctx, sp);
    }
    if ((flags & MIPS_CLONE_PARENT_SETTID) != 0U &&
        !mips_sc_range_ok(ctx, ptid, 4U, (uint32_t)PROT_WRITE)) {
        return mips_sc_ret(ctx, -EFAULT);
    }
    if (ctid == 0U &&
        (flags & (MIPS_CLONE_CHILD_SETTID | MIPS_CLONE_CHILD_CLEARTID)) !=
            0U) {
        return mips_sc_ret(ctx, -EINVAL);
    }
    if (ctid != 0U &&
        (flags & (MIPS_CLONE_CHILD_SETTID | MIPS_CLONE_CHILD_CLEARTID)) != 0U &&
        !mips_sc_range_ok(ctx, ctid, 4U, (uint32_t)PROT_WRITE)) {
        return mips_sc_ret(ctx, -EFAULT);
    }

    /* M32-R5-4/R5-10: reclaim dead peers before growing. */
    mips_reap_done();
    t = (struct mips_thread *)calloc(1U, sizeof(*t));
    if (t == NULL) {
        return mips_sc_ret(ctx, -ENOMEM);
    }
    mmap_flags = MAP_PRIVATE | MAP_ANONYMOUS;
#ifdef MAP_STACK
    mmap_flags |= MAP_STACK;
#endif
    stack = mmap(NULL, MIPS_THREAD_STACK_SIZE, PROT_READ | PROT_WRITE,
                 mmap_flags, -1, 0);
    if (stack == MAP_FAILED) {
        int e = errno;

        free(t);
        return mips_sc_ret(ctx, -(int32_t)e);
    }

    t->ctx = *ctx; /* whole window mapping table travels along (CLONE_VM) */
    t->ctx.gpr[MIPS32_REG_SP] = (child_stack != 0U) ? child_stack
                                                   : ctx->gpr[MIPS32_REG_SP];
    /* Child resumes past the syscall with a 0 return (caller advances the
     * parent the same way: syscall insns are non-control insns). */
    t->ctx.pc      = (ctx->sc_pc_advanced != 0U) ? ctx->pc : (ctx->pc + 4U);
    t->ctx.next_pc = t->ctx.pc + 4U;
    t->ctx.gpr[MIPS32_REG_V0] = 0U;
    t->ctx.gpr[MIPS32_REG_A3] = 0U;
    t->ctx.llbit               = 0U;
    t->ctx.in_delay_slot       = 0U;
    t->ctx.exit_reason         = MIPS32_EXIT_NONE;
    t->ctx.exit_info           = 0U;
    t->ctx.host_tid            = 0;
    t->ctx.is_thread_clone     = true;
    t->ctx.robust_list_head = 0U;
    t->ctx.robust_list_len  = 0U;
    if ((flags & MIPS_CLONE_VFORK) == 0U) {
        t->ctx.sigalt_sp = 0U;
        t->ctx.sigalt_size = 0U;
        t->ctx.sigalt_flags = 2U;
    }
    memset(t->ctx.sig_pending, 0, sizeof(t->ctx.sig_pending));
    memset(t->ctx.sig_pending_code, 0, sizeof(t->ctx.sig_pending_code));
    memset(t->ctx.sig_frame_sp, 0, sizeof(t->ctx.sig_frame_sp));
    t->ctx.sig_depth = 0U;
    t->ctx.sig_rt_count = 0U;
    t->ctx.sc_pc_advanced = 0U;
    t->ctx.clear_child_tid =
        ((flags & MIPS_CLONE_CHILD_CLEARTID) != 0U) ? ctid : 0U;
    if ((flags & MIPS_CLONE_SETTLS) != 0U) {
        t->ctx.ulr = tls; /* E06: rdhwr $29 reads ctx->ulr */
    }
    t->host_stack = stack;
    /* M32-R4-8: startup SETTID and exit CLEARTID are independent.  The
     * child writes its TID at startup only for CHILD_SETTID; the
     * clear address is retained only for CHILD_CLEARTID. */
    t->set_ctid   = ((flags & MIPS_CLONE_CHILD_SETTID) != 0U) ? ctid : 0U;
    t->clear_ctid = ((flags & MIPS_CLONE_CHILD_CLEARTID) != 0U) ? ctid : 0U;
    /* M32-R4-8/N-2: PARENT_SETTID aliased onto clear_ctid is written
     * by the child before started (see mips_host_thread_entry), so
     * the parent must not write it after the handshake.  ctid is
     * non-zero whenever CLEARTID is set, so a non-zero parent_settid
     * always equals ptid here. */
    t->parent_settid =
        (((flags & MIPS_CLONE_PARENT_SETTID) != 0U) &&
         ((flags & MIPS_CLONE_CHILD_CLEARTID) != 0U) && (ptid == ctid))
            ? ptid
            : 0U;

    /* Emulate SETTLS/SETTID/CLEARTID in-band; the host thread only
     * carries the sharing (see mips_host_thread_entry). */
    /* Detached musl pthread on the mmap'd stack (see
     * mips_host_thread_entry): real per-thread TLS for the child.
     * The parent waits for the child's tid handshake before
     * returning it to the guest. M32-R5-4: live count before startup
     * with rollback; record joins the reaper list only after the
     * parent handshake (post-SETTID reads) so a fast exiting child
     * cannot be reaped while the parent still reads t. */
    {
        pthread_t      th;
        pthread_attr_t at;
        int            pr;

        atomic_init(&t->started, 0);
        atomic_init(&t->child_tid, 0);
        (void)atomic_fetch_add_explicit(&mips_live_clones, 1,
                                        memory_order_relaxed);
        pr = pthread_attr_init(&at);
        if (pr == 0) {
            pr = pthread_attr_setstack(&at, stack,
                                       MIPS_THREAD_STACK_SIZE);
        }
        if (pr == 0) {
            pr = pthread_attr_setdetachstate(&at,
                                             PTHREAD_CREATE_DETACHED);
        }
        if (pr == 0) {
            pr = pthread_create(&th, &at, mips_host_thread_entry, t);
        }
        (void)pthread_attr_destroy(&at);
        if (pr != 0) {
            (void)atomic_fetch_sub_explicit(&mips_live_clones, 1,
                                            memory_order_relaxed);
            (void)munmap(stack, MIPS_THREAD_STACK_SIZE);
            free(t);
            return mips_sc_ret(ctx, -(int32_t)pr);
        }
        (void)th;
        while (atomic_load_explicit(&t->started,
                                    memory_order_acquire) == 0) {
            (void)syscall(SYS_futex, &t->started, (int)MIPS_FUTEX_WAIT,
                          (uint32_t)0, NULL, NULL, (uint32_t)0);
        }
        r = (long)atomic_load_explicit(&t->child_tid,
                                       memory_order_relaxed);
    }
    /* When ptid aliases the child's startup-write address (NPTL passes
     * pd->tid for both), the child already wrote it before started
     * and will clear it on exit; a parent-side write here would race
     * a fast child and resurrect a cleared tid, hanging the join.
     * Skip the redundant write when the child wrote it (CHILD_SETTID
     * to the same address, or the PARENT_SETTID-on-clear_ctid alias
     * handled above); otherwise the parent must write. */
    if ((flags & MIPS_CLONE_PARENT_SETTID) != 0U &&
        (t->set_ctid == 0U || ptid != t->set_ctid) &&
        (t->parent_settid == 0U || ptid != t->parent_settid) &&
        thread_write_tid(ctx, ptid, (uint32_t)r) != 0) {
        /* The child already runs; its ctid/clear wake still fires on exit.
         * Report the fault to the parent while keeping the thread alive. */
        if (pthread_mutex_lock(&mips_reap_lock) == 0) {
            t->next = mips_reap_head;
            mips_reap_head = t;
            (void)pthread_mutex_unlock(&mips_reap_lock);
        }
        return mips_sc_ret(ctx, -EFAULT);
    }
    /* M32-R5-4: publish to the reaper only after the last parent-side
     * read of t (started/child_tid above, set_ctid/parent_settid here). */
    if (pthread_mutex_lock(&mips_reap_lock) == 0) {
        t->next = mips_reap_head;
        mips_reap_head = t;
        (void)pthread_mutex_unlock(&mips_reap_lock);
    }
    if (r > (long)0x7FFFFFFFL) {
        r = (long)0x7FFFFFFFL;
    }
    return mips_sc_ret(ctx, (int32_t)r);
}

/* BE WAKE_OP emulated in guest value domain. */
static long futex_wake_op_be(mips32_ctx_t *ctx, uint32_t uaddr,
    uint32_t uaddr2, uint32_t val, uint32_t n2, uint32_t val3, int priv)
{
    uint32_t op = (val3 >> 28) & 0xFU, cmp = (val3 >> 24) & 0xFU;
    int32_t oparg = (int32_t)(val3 >> 12 & 0xFFFU);
    int32_t cmparg = (int32_t)(val3 & 0xFFFU);
    uint32_t *hp;
    uint32_t h_old, h_new, g_old, g_new;
    int wop;
    long w = 0L;
    if (!mips_sc_range_ok(ctx, uaddr2, 4U,
            (uint32_t)(PROT_READ | PROT_WRITE))) {
        errno = EFAULT;
        return -1L;
    }
    wop = (int)((uint32_t)MIPS_FUTEX_WAKE |
        (priv ? (uint32_t)MIPS_FUTEX_PRIVATE_FLAG : 0U));
    if ((oparg & 0x800) != 0) {
        oparg |= (int32_t)0xFFFFF000;
    }
    if ((cmparg & 0x800) != 0) {
        cmparg |= (int32_t)0xFFFFF000;
    }
    if ((op & 8U) != 0U) {
        if (oparg < 0 || oparg > 31) {
            errno = EINVAL;
            return -1L;
        }
        oparg = (int32_t)(1u << (uint32_t)oparg);
        op &= ~8U;
    }
    hp = (uint32_t *)(void *)mips32_guest_ptr(ctx, uaddr2);
    h_old = __atomic_load_n(hp, __ATOMIC_SEQ_CST);
    for (;;) {
        uint32_t exp;
        g_old = __builtin_bswap32(h_old);
        switch (op) {
        case 0U: g_new = (uint32_t)oparg; break;
        case 1U: g_new = g_old + (uint32_t)oparg; break;
        case 2U: g_new = g_old | (uint32_t)oparg; break;
        case 3U: g_new = g_old & ~(uint32_t)oparg; break;
        case 4U: g_new = g_old ^ (uint32_t)oparg; break;
        default: errno = EINVAL; return -1L;
        }
        h_new = __builtin_bswap32(g_new);
        exp = h_old;
        if (__atomic_compare_exchange_n(hp, &exp, h_new, 0,
                __ATOMIC_SEQ_CST, __ATOMIC_SEQ_CST)) {
            break;
        }
        h_old = exp;
    }
    mips_guest_store_commit(ctx, uaddr2, (void *)hp, 4U);
    {
        int32_t o = (int32_t)g_old;
        int mo = 0;
        switch (cmp) {
        case 0U: mo = (o == cmparg); break;
        case 1U: mo = (o != cmparg); break;
        case 2U: mo = (o < cmparg); break;
        case 3U: mo = (o <= cmparg); break;
        case 4U: mo = (o > cmparg); break;
        case 5U: mo = (o >= cmparg); break;
        default: errno = EINVAL; return -1L;
        }
        if (val != 0U) {
            long k = syscall(SYS_futex, mips32_guest_ptr(ctx, uaddr),
                wop, val, NULL, NULL, (uint32_t)0);
            if (k > 0) {
                w += k;
            } else if (k < 0 && errno != 0) {
                return -1L;
            }
        }
        if (mo && n2 != 0U) {
            long k = syscall(SYS_futex, mips32_guest_ptr(ctx, uaddr2),
                wop, n2, NULL, NULL, (uint32_t)0);
            if (k > 0) {
                w += k;
            } else if (k < 0 && errno != 0) {
                return (w > 0) ? w : -1L;
            }
        }
    }
    return w;
}

/* uaddr usable by the host futex: aligned and guest-readable. */
static int futex_addr_ok(mips32_ctx_t *ctx, uint32_t va)
{
    if ((va & 3U) != 0U) {
        return -EINVAL;
    }
    if (!mips_sc_range_ok(ctx, va, 4U, (uint32_t)PROT_READ)) {
        return -EFAULT;
    }
    return 0;
}

/* Full futex ops via the host futex on the validated guest uaddr. */
int32_t mips_sc_futex_thread(mips32_ctx_t *ctx, uint32_t sp)
{
    int      ok = 1;
    int      be;
    int      priv;
    int      clk;
    int      rc;
    int      base_op;
    int      host_op;
    uint8_t  cur[4];
    uint32_t uaddr;
    uint32_t op;
    uint32_t val;
    uint32_t to_va;
    uint32_t uaddr2;
    uint32_t val3;
    long     r;

    uaddr = mips_sc_arg(ctx, sp, 0, &ok);
    op    = mips_sc_arg(ctx, sp, 1, &ok);
    val   = mips_sc_arg(ctx, sp, 2, &ok);
    to_va = mips_sc_arg(ctx, sp, 3, &ok);
    if (!ok) {
        return mips_sc_ret(ctx, -EFAULT);
    }
    ctx->llbit = 0U; /* SPEC 2.2: futex ops clear the LL reservation */
    rc = futex_addr_ok(ctx, uaddr);
    if (rc != 0) {
        return mips_sc_ret(ctx, rc);
    }
    priv    = ((op & (uint32_t)MIPS_FUTEX_PRIVATE_FLAG) != 0U);
    clk     = ((op & (uint32_t)MIPS_FUTEX_CLOCK_REALTIME) != 0U);
    base_op = (int)(op & ~((uint32_t)MIPS_FUTEX_PRIVATE_FLAG |
                           (uint32_t)MIPS_FUTEX_CLOCK_REALTIME));
    be      = mips_is_be(ctx);
    /* Host futex numbering is arch-independent: base op, PRIVATE and
     * CLOCK_REALTIME flags map 1:1. */
    host_op = (int)(((priv ? (uint32_t)MIPS_FUTEX_PRIVATE_FLAG : 0U) |
                     (clk ? (uint32_t)MIPS_FUTEX_CLOCK_REALTIME : 0U)) |
                    (uint32_t)base_op);
    switch (base_op) {
    case (int)MIPS_FUTEX_WAIT:
    case MIPS_FUTEX_WAIT_BITSET: {
        struct timespec to;
        struct timespec *top = NULL;

        if (mips_sc_copy_from(ctx, cur, uaddr, 4U) != 0) {
            return mips_sc_ret(ctx, -EFAULT);
        }
        if (mips_sc_ld32(cur, be) != val) {
            return mips_sc_ret(ctx, -EAGAIN);
        }
        if (to_va != 0U) {
            if (mips_sc_read_ts(ctx, to_va, &to) != 0) {
                return mips_sc_ret(ctx, -EFAULT);
            }
            /* WAIT takes a relative timeout; WAIT_BITSET takes an
             * absolute one (CLOCK_REALTIME selects the clock).  Both
             * need a normalized nsec field; the host validates the
             * rest against its own clock. */
            if (to.tv_sec < 0 || to.tv_nsec < 0 ||
                to.tv_nsec >= 1000000000L) {
                return mips_sc_ret(ctx, -EINVAL);
            }
            top = &to;
        }
        /* M32-R5-2: BE kernel compares LE words; swap expected val. */
        if (base_op == (int)MIPS_FUTEX_WAIT) {
            uint32_t hv = be ? __builtin_bswap32(val) : val;
            r = syscall(SYS_futex, mips32_guest_ptr(ctx, uaddr), host_op,
                        hv, top, NULL, (uint32_t)0);
        } else {
            uint32_t hv;
            val3 = mips_sc_arg(ctx, sp, 5, &ok);
            if (!ok) {
                return mips_sc_ret(ctx, -EFAULT);
            }
            hv = be ? __builtin_bswap32(val) : val;
            r = syscall(SYS_futex, mips32_guest_ptr(ctx, uaddr), host_op,
                        hv, top, NULL, (uint32_t)val3);
        }
        break;
    }
    case (int)MIPS_FUTEX_WAKE:
    case MIPS_FUTEX_WAKE_BITSET:
        if (base_op == MIPS_FUTEX_WAKE_BITSET) {
            val3 = mips_sc_arg(ctx, sp, 5, &ok);
            if (!ok) {
                return mips_sc_ret(ctx, -EFAULT);
            }
        } else {
            val3 = 0U;
        }
        r = syscall(SYS_futex, mips32_guest_ptr(ctx, uaddr), host_op,
                    (uint32_t)val, NULL, NULL, (uint32_t)val3);
        break;
    case MIPS_FUTEX_REQUEUE:
    case MIPS_FUTEX_CMP_REQUEUE:
        uaddr2 = mips_sc_arg(ctx, sp, 4, &ok);
        val3   = mips_sc_arg(ctx, sp, 5, &ok);
        if (!ok) {
            return mips_sc_ret(ctx, -EFAULT);
        }
        rc = futex_addr_ok(ctx, uaddr2);
        if (rc != 0) {
            return mips_sc_ret(ctx, rc);
        }
        /* M32-R5-3: 4th arg is nr_requeue count, not a timeout ptr.
         * M32-R5-2: CMP_REQUEUE compares memory; swap expected val3 on BE. */
        {
            const void *nr = (const void *)(uintptr_t)to_va;
            uint32_t hv3 = (base_op == MIPS_FUTEX_CMP_REQUEUE && be)
                ? __builtin_bswap32(val3) : val3;
            r = syscall(SYS_futex, mips32_guest_ptr(ctx, uaddr), host_op,
                        (uint32_t)val, nr, mips32_guest_ptr(ctx, uaddr2), hv3);
        }
        break;
    case MIPS_FUTEX_WAKE_OP:
        uaddr2 = mips_sc_arg(ctx, sp, 4, &ok);
        val3   = mips_sc_arg(ctx, sp, 5, &ok);
        if (!ok) {
            return mips_sc_ret(ctx, -EFAULT);
        }
        rc = futex_addr_ok(ctx, uaddr2);
        if (rc != 0) {
            return mips_sc_ret(ctx, rc);
        }
        if (be) {
            r = futex_wake_op_be(ctx, uaddr, uaddr2, val, to_va, val3,
                priv);
        } else {
            const void *nr2 = (const void *)(uintptr_t)to_va;
            r = syscall(SYS_futex, mips32_guest_ptr(ctx, uaddr), host_op,
                        (uint32_t)val, nr2, mips32_guest_ptr(ctx, uaddr2),
                        (uint32_t)val3);
        }
        break;
    default:
        return mips_sc_ret(ctx, -ENOSYS);
    }
    if (r < 0) {
        return mips_sc_ret(ctx, -(int32_t)errno);
    }
    if (r > (long)0x7FFFFFFFL) {
        r = (long)0x7FFFFFFFL;
    }
    return mips_sc_ret(ctx, (int32_t)r);
}

#else /* Non-Linux or missing raw syscalls: honest -ENOSYS. */

int32_t mips_sc_clone(mips32_ctx_t *ctx, uint32_t sp)
{
    (void)sp;
    ctx->llbit = 0U;
    return mips_sc_ret(ctx, -ENOSYS);
}

int32_t mips_sc_futex_thread(mips32_ctx_t *ctx, uint32_t sp)
{
    (void)sp;
    ctx->llbit = 0U;
    return mips_sc_ret(ctx, -ENOSYS);
}

/* Unreachable off Linux (clone reports -ENOSYS, so no thread ctx exists). */
void mips_thread_exit(mips32_ctx_t *ctx, int status)
{
    (void)ctx;
    _Exit(status);
}

/* No clone peers can exist off Linux: nothing to rebuild after fork. */
void mips_threads_fork_child(void)
{
}
void mips_threads_fork_prepare(void)
{
}
void mips_threads_fork_release(void)
{
}

#endif
