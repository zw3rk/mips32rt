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
 * ctid=stack slot 5): CLONE_VM-family guest threads run on host clone(2)
 * sharing the [G, G + 4 GiB) window (CLONE_VM shares the address space,
 * so mips32_guest_ptr addresses stay valid in every thread).  The child
 * gets its own host stack plus a copy of mips32_ctx_t resumed past the
 * syscall (pc = child return, v0 = 0, a3 = 0), TLS from CLONE_SETTLS,
 * ptid writeback for CLONE_PARENT_SETTID, ctid writeback for
 * CLONE_CHILD_SETTID, and a 0-write plus FUTEX_WAKE for
 * CLONE_CHILD_CLEARTID on thread exit.  CLONE_UNTRACED is ignored.
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
 * uaddr2=slot 5, val3=slot 6): FUTEX_WAIT/WAKE with FUTEX_PRIVATE_FLAG,
 * FUTEX_REQUEUE, FUTEX_CMP_REQUEUE, and FUTEX_WAKE_OP pass through to the
 * host futex on the validated guest uaddr (misaligned -> -EINVAL,
 * unmapped -> -EFAULT).  llbit is cleared across every op.  Anything else
 * (bitset, fd, NUMA, TRYLOCK variants) returns -ENOSYS.
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

/* ---- Thread record (heap; ownership passes to the L4c wait4 reaper) ---- */

#define MIPS_THREAD_STACK_SIZE (2U * 1024U * 1024U)

struct mips_thread {
    mips32_ctx_t ctx;
    void        *host_stack;
    uint32_t     ctid;
    int          want_child_set;
    int          want_clear;
};

#if defined(__linux__) && defined(SYS_futex) && defined(SYS_clone) && \
    defined(SYS_exit) && defined(SYS_gettid)

/* Live CLONE_VM children; the initial thread is never counted. */
static _Atomic int mips_live_clones = 0;

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
    if (t->want_child_set) {
        (void)thread_write_tid(&t->ctx, t->ctid, self);
    }
    if (t->ctx.engine == MIPS32_ENGINE_DBT) {
        rc = dbt_main(&t->ctx);
    } else {
        rc = interp_run(&t->ctx);
    }
    /* Engines only return on a stop reason; exit syscalls never return. */
    status = (rc == 0) ? 0 : 1;
    if (t->want_clear) {
        (void)thread_write_tid(&t->ctx, t->ctid, 0U);
        (void)syscall(SYS_futex, mips32_guest_ptr(&t->ctx, t->ctid),
                      (int)MIPS_FUTEX_WAKE, (uint32_t)INT_MAX, NULL, NULL,
                      (uint32_t)0);
    }
    /* The initial thread is never counted, so reaching zero here only
     * accounts clones; group teardown stays with exit/exit_group. */
    (void)atomic_fetch_sub_explicit(&mips_live_clones, 1,
                                    memory_order_relaxed);
    (void)syscall(SYS_exit, (int)status);
    return 1; /* unreachable; keeps noreturn-less compilers quiet */
}

/* CLONE_VM-family clone; called with ctx->pc on the syscall instruction. */
int32_t mips_sc_clone(mips32_ctx_t *ctx, uint32_t sp)
{
    struct mips_thread *t = NULL;
    void               *stack = NULL;
    void               *stack_top;
    int                 ok = 1;
    int                 mmap_flags;
    int                 host_flags;
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
    if ((flags & MIPS_CLONE_VM) == 0U) {
        return mips_sc_ret(ctx, -EINVAL); /* non-VM clone: no address space */
    }
    if ((flags & (MIPS_CLONE_NEWNS_ALL | MIPS_CLONE_PIDFD)) != 0U) {
        return mips_sc_ret(ctx, -EINVAL); /* namespaces/pidfd unsupported */
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
    if (ctid != 0U && (flags & MIPS_CLONE_CHILD_CLEARTID) != 0U &&
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
    t->ctx.pc      = ctx->pc + 4U;
    t->ctx.next_pc = ctx->pc + 8U;
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
    t->ctx.clear_child_tid =
        ((flags & MIPS_CLONE_CHILD_CLEARTID) != 0U) ? ctid : 0U;
    if ((flags & MIPS_CLONE_SETTLS) != 0U) {
        t->ctx.ulr = tls; /* E06: rdhwr $29 reads ctx->ulr */
    }
    t->host_stack      = stack;
    t->ctid            = ctid;
    t->want_child_set  = (ctid != 0U &&
                         (flags & MIPS_CLONE_CHILD_SETTID) != 0U);
    t->want_clear      = (ctid != 0U &&
                         (flags & MIPS_CLONE_CHILD_CLEARTID) != 0U);

    /* Emulate SETTLS/SETTID/CLEARTID in-band; the host clone only carries
     * the sharing and scheduling flags.  CLONE_THREAD groups need a zero
     * exit signal, matching pthread_create. */
    host_flags = (int)(flags & ~(MIPS_CLONE_SETTLS |
                                 MIPS_CLONE_PARENT_SETTID |
                                 MIPS_CLONE_CHILD_SETTID |
                                 MIPS_CLONE_CHILD_CLEARTID));
    if ((flags & MIPS_CLONE_THREAD) != 0U) {
        host_flags &= ~0xFF;
    }
    stack_top = (void *)((uintptr_t)stack + MIPS_THREAD_STACK_SIZE);
    r = (long)clone(mips_thread_main, stack_top, host_flags, t, NULL, NULL,
                    NULL);
    if (r < 0) {
        int e = errno;

        (void)munmap(stack, MIPS_THREAD_STACK_SIZE);
        free(t);
        return mips_sc_ret(ctx, -(int32_t)e);
    }
    if ((flags & MIPS_CLONE_PARENT_SETTID) != 0U &&
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
    int      rc;
    int      base_op;
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
    base_op = (int)(op & ~(uint32_t)MIPS_FUTEX_PRIVATE_FLAG);
    be      = mips_is_be(ctx);
    switch (base_op) {
    case (int)MIPS_FUTEX_WAIT: {
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
            if (to.tv_sec < 0 || to.tv_nsec < 0 ||
                to.tv_nsec >= 1000000000L) {
                return mips_sc_ret(ctx, -EINVAL);
            }
            top = &to;
        }
        r = syscall(SYS_futex, mips32_guest_ptr(ctx, uaddr),
                    (int)(priv ? MIPS_FUTEX_PRIVATE_FLAG : MIPS_FUTEX_WAIT),
                    (uint32_t)val, top, NULL, (uint32_t)0);
        break;
    }
    case (int)MIPS_FUTEX_WAKE:
        r = syscall(SYS_futex, mips32_guest_ptr(ctx, uaddr),
                    (int)((priv ? (uint32_t)MIPS_FUTEX_PRIVATE_FLAG : 0U) |
                          (uint32_t)MIPS_FUTEX_WAKE),
                    (uint32_t)val, NULL, NULL, (uint32_t)0);
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
        r = syscall(SYS_futex, mips32_guest_ptr(ctx, uaddr),
                    (int)((priv ? (uint32_t)MIPS_FUTEX_PRIVATE_FLAG : 0U) |
                          (uint32_t)base_op),
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
        r = syscall(SYS_futex, mips32_guest_ptr(ctx, uaddr),
                    (int)((priv ? (uint32_t)MIPS_FUTEX_PRIVATE_FLAG : 0U) |
                          (uint32_t)MIPS_FUTEX_WAKE_OP),
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

#endif
