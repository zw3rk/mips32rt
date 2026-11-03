/*
 * src/os/threads.c — Phase 4 CLONE_VM-family guest threads + full futex ops (lane L4b)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * O32 numbers (verified 2026-10-24 against
 * /usr/mipsel-linux-gnu/include/asm/unistd_o32.h from
 * libc6-dev-mipsel-cross 2.36-8cross2, debian:bookworm-slim,
 * linux/arm64; __NR_Linux = 4000):
 *   clone 4120 (+120), futex 4238 (+238), exit_group 4246 (+246),
 *   set_tid_address 4252 (+252), set_robust_list 4309 (+309),
 *   get_robust_list 4310 (+310).  All already live in src/os/syscall_nr.h,
 *   so this lane needs no header extension.
 *
 * Clone (O32 args: flags=$a0, child_stack=$a1, ptid=$a2, tls=$a3,
 * ctid=stack slot 5): CLONE_VM-family guest threads run on detached
 * host pthreads sharing the [G, G + 4 GiB) window (CLONE_VM shares the
 * address space, so mips32_guest_ptr addresses stay valid in every
 * thread), each with its own musl TLS so __thread engine/guard state
 * stays per-thread.  The child gets its own host stack plus a copy of
 * mips32_ctx_t resumed past the syscall (pc = child return, v0 = 0,
 * a3 = 0), guest TLS from CLONE_SETTLS (ctx->ulr), ptid writeback for
 * CLONE_PARENT_SETTID, ctid writeback for CLONE_CHILD_SETTID, and a
 * 0-write plus FUTEX_WAKE for CLONE_CHILD_CLEARTID on thread exit.
 * CLONE_UNTRACED is ignored.
 * Flags without CLONE_VM, namespace flags (NEWNS/NEWCGROUP/NEWUTS/
 * NEWIPC/NEWUSER/NEWPID/NEWNET), and CLONE_PIDFD return -EINVAL.
 *
 * Minimal single-group semantics: threads share one address space and one
 * exit group — exit/exit_group terminate the whole group (existing
 * behaviour), while an ended thread exits alone via raw SYS_exit after
 * its CHILD_CLEARTID wake.  A live-clone counter is kept for the RC4
 * wait4/group-exit wiring; deliberately no group teardown happens when a
 * clone ends while the initial thread still runs.  Thread stacks and ctx
 * copies are retained after thread death for the L4c wait4 reaper.
 *
 * Futex (O32 args: uaddr=$a0, op=$a1, val=$a2, timeout=$a3,
 * uaddr2=slot 5, val3=slot 6): FUTEX_WAIT/WAKE/WAIT_BITSET/WAKE_BITSET
 * with FUTEX_PRIVATE_FLAG and FUTEX_CLOCK_REALTIME, FUTEX_REQUEUE,
 * FUTEX_CMP_REQUEUE, and FUTEX_WAKE_OP pass through to the host futex
 * on the validated guest uaddr (misaligned -> -EINVAL, unmapped ->
 * -EFAULT).  llbit is cleared across every op.  Anything else
 * (PI, fd, NUMA, TRYLOCK variants) returns -ENOSYS.
 *
 * Non-Linux hosts: clone and futex report -ENOSYS (same $a3 convention).
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

struct mips_thread {
    mips32_ctx_t ctx;
    void        *host_stack;
    uint32_t     set_ctid;
    uint32_t     clear_ctid;
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

/* Coordinated fork (cross-RT Round-3 class): only the forking thread
 * survives, so every CLONE_VM peer is gone in the child and the live
 * counter restarts at zero.  Their heap records leak in the child
 * (unreachable by design: no peer thread remains to reap them). */
void mips_threads_fork_child(void)
{
    atomic_store_explicit(&mips_live_clones, 0, memory_order_relaxed);
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

/* Shared thread-teardown tail (CLEARTID 0-write plus FUTEX_WAKE,
 * live-clone accounting, raw SYS_exit): used by the engine-return path
 * and by guest exit().  Does not return. */
static void mips_thread_finish(mips32_ctx_t *ctx, uint32_t ctid, int status)
{
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
     * stale value.  Only CLONE_CHILD_SETTID writes at startup; the
     * parent skips its SETTID write only when the child performs that
     * startup write to the same address, so the field stays monotonic
     * tid-then-0 and no resurrection race exists. */
    if (t->set_ctid != 0U) {
        (void)thread_write_tid(&t->ctx, t->set_ctid, self);
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
    /* A fresh thread starts with no robust list (kernel-side wake of the
     * inherited list is an RC4 follow-up; see header comment). */
    t->ctx.robust_list_head = 0U;
    t->ctx.robust_list_len  = 0U;
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

    /* Emulate SETTLS/SETTID/CLEARTID in-band; the host thread only
     * carries the sharing (see mips_host_thread_entry). */
    /* Detached musl pthread on the mmap'd stack (see
     * mips_host_thread_entry): real per-thread TLS for the child.
     * The parent waits for the child's tid handshake before
     * returning it to the guest. */
    {
        pthread_t      th;
        pthread_attr_t at;
        int            pr;

        atomic_init(&t->started, 0);
        atomic_init(&t->child_tid, 0);
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
     * pd->tid for both) and CHILD_SETTID is set, the child already
     * wrote it at startup and will clear it on exit; a parent-side
     * write here would race a fast child and resurrect a cleared tid,
     * hanging the join.  Skip the redundant write only in that case:
     * without CHILD_SETTID the child never writes, so the parent must. */
    if ((flags & MIPS_CLONE_PARENT_SETTID) != 0U &&
        (t->set_ctid == 0U || ptid != t->set_ctid) &&
        thread_write_tid(ctx, ptid, (uint32_t)r) != 0) {
        /* The child already runs; its ctid/clear wake still fires on exit.
         * Report the fault to the parent while keeping the thread alive. */
        return mips_sc_ret(ctx, -EFAULT);
    }
    (void)atomic_fetch_add_explicit(&mips_live_clones, 1,
                                    memory_order_relaxed);
    if (r > (long)0x7FFFFFFFL) {
        r = (long)0x7FFFFFFFL;
    }
    return mips_sc_ret(ctx, (int32_t)r);
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
        if (base_op == (int)MIPS_FUTEX_WAIT) {
            r = syscall(SYS_futex, mips32_guest_ptr(ctx, uaddr), host_op,
                        (uint32_t)val, top, NULL, (uint32_t)0);
        } else {
            val3 = mips_sc_arg(ctx, sp, 5, &ok);
            if (!ok) {
                return mips_sc_ret(ctx, -EFAULT);
            }
            r = syscall(SYS_futex, mips32_guest_ptr(ctx, uaddr), host_op,
                        (uint32_t)val, top, NULL, (uint32_t)val3);
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
        /* The relative-timeout slot is unused by both requeue ops. */
        r = syscall(SYS_futex, mips32_guest_ptr(ctx, uaddr), host_op,
                    (uint32_t)val, NULL, mips32_guest_ptr(ctx, uaddr2),
                    (uint32_t)val3);
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
        r = syscall(SYS_futex, mips32_guest_ptr(ctx, uaddr), host_op,
                    (uint32_t)val, NULL, mips32_guest_ptr(ctx, uaddr2),
                    (uint32_t)val3);
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

#endif
