/*
 * src/os/fork.c — Coordinated guest fork/vfork (cross-RT Round-3 class)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Split from src/os/proc.c to honor the 900-line file limit.  A raw
 * host fork() duplicates every runtime-owned lock; a peer holding one
 * at the snapshot leaves the child spinning forever, and vanished
 * threads leave stale registry entries behind.  The forking thread
 * therefore quiesces the VM table, signal table, DBT/SMC, and LL/SC
 * locks in a fixed order before forking (it holds none of them on
 * entry: syscall dispatch never takes them, and every holder only
 * spans a short critical section that never blocks on another guest
 * thread).  The parent releases; the child releases the uncontended
 * words and rebuilds sole-survivor state (locks, live-clone count,
 * LL reservation, pending signals, thread identity).
 *
 * MIPS O32 defines no __NR_vfork: glibc vfork(2) lowers to clone(2),
 * so mips_proc_vfork is the documented vfork-as-fork equivalent.
 */

#if defined(__linux__)
#define _GNU_SOURCE /* pipe2(2) */
#endif

#include "mips32rt.h"

#include "os/syscalls_priv.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

/* Cross-file fork stages (weak: standalone harnesses that link this
 * file without the owning subsystem still link; production always
 * provides them). */
__attribute__((weak)) void vm_fork_prepare(void);
__attribute__((weak)) void vm_fork_release(void);
__attribute__((weak)) void mips_sig_fork_prepare(void);
__attribute__((weak)) void mips_sig_fork_release(void);
__attribute__((weak)) void mips_sigqueue_fork_child(void);
__attribute__((weak)) void mips32_dbt_fork_prepare(void);
__attribute__((weak)) void mips32_dbt_fork_release(void);
__attribute__((weak)) void mips_ll_fork_prepare(void);
__attribute__((weak)) void mips_ll_fork_release(void);
__attribute__((weak)) void mips_threads_fork_child(void);
__attribute__((weak)) void mips_threads_fork_prepare(void);
__attribute__((weak)) void mips_threads_fork_release(void);

static int32_t fork_ret(mips32_ctx_t *ctx, int32_t raw)
{
    int32_t err;

    if (raw < 0) {
        err = mips_errno_from_host((int)(-raw));
        ctx->gpr[MIPS32_REG_V0] = (uint32_t)err;
        ctx->gpr[MIPS32_REG_A3] = 1U;
    } else {
        ctx->gpr[MIPS32_REG_V0] = (uint32_t)raw;
        ctx->gpr[MIPS32_REG_A3] = 0U;
    }
    return raw;
}

static void fork_stages_prepare(void)
{
    if (vm_fork_prepare != NULL) {
        vm_fork_prepare();
    }
    if (mips_sig_fork_prepare != NULL) {
        mips_sig_fork_prepare();
    }
    if (mips32_dbt_fork_prepare != NULL) {
        mips32_dbt_fork_prepare();
    }
    if (mips_ll_fork_prepare != NULL) {
        mips_ll_fork_prepare();
    }
    if (mips_threads_fork_prepare != NULL) {
        mips_threads_fork_prepare();
    }
}

static void fork_stages_release(void)
{
    if (mips_threads_fork_release != NULL) {
        mips_threads_fork_release();
    }
    if (mips_ll_fork_release != NULL) {
        mips_ll_fork_release();
    }
    if (mips32_dbt_fork_release != NULL) {
        mips32_dbt_fork_release();
    }
    if (mips_sig_fork_release != NULL) {
        mips_sig_fork_release();
    }
    if (vm_fork_release != NULL) {
        vm_fork_release();
    }
}

/* Sole-survivor fixups shared by the fork and vfork children. */
static void fork_child_common(mips32_ctx_t *ctx)
{
    fork_stages_release();
    if (mips_sigqueue_fork_child != NULL) {
        mips_sigqueue_fork_child();
    }
    if (mips_threads_fork_child != NULL) {
        mips_threads_fork_child();
    }
    (void)unsetenv("MIPS32RT_DUMPSTATE");
    ctx->llbit = 0U; /* SPEC 2.2: LL reservation never crosses fork */
    ctx->lladdr = 0U;
    ctx->ll_epoch_snap = 0U;
    ctx->is_thread_clone = false;
    ctx->host_tid = (int)getpid();
    memset(ctx->sig_pending, 0, sizeof(ctx->sig_pending));
    memset(ctx->sig_pending_code, 0, sizeof(ctx->sig_pending_code));
    ctx->sig_rt_count = 0U;
    ctx->gpr[MIPS32_REG_V0] = 0U;
    ctx->gpr[MIPS32_REG_A3] = 0U;
}

int32_t mips_proc_fork(mips32_ctx_t *ctx, uint32_t sp)
{
    pid_t pid;

    (void)sp;
    if (ctx == NULL) {
        return (int32_t)-EFAULT;
    }
    fork_stages_prepare();
    pid = fork();
    if (pid < 0) {
        int err = errno;

        fork_stages_release();
        return fork_ret(ctx, -(int32_t)err);
    }
    if (pid == 0) {
        /* Child: the host fork() CoW-duplicated the [G, G+4GiB)
         * window, so every guest mapping survives; only translator
         * state changes around the sole surviving thread.  POSIX
         * starts the child with an empty pending set. */
        fork_child_common(ctx);
        return 0;
    }
    fork_stages_release();
    return fork_ret(ctx, (int32_t)pid);
}

/* CLONE_VFORK parent/child handshake.  The pipe is FD_CLOEXEC on both
 * ends: the parent blocks reading 1 byte until the child either execves
 * (the in-process execve path closes every CLOEXEC fd, like a host
 * execve) or exits (closing the write end).  A failed execve leaves the
 * parent blocked until the child exits, which matches the real-vfork
 * contract that the child must exec or _exit (a failed execve still
 * returns an error to the child, it just does not release the parent).
 * Exec-errno propagation is NOT provided: this vfork is a fork (CoW, no
 * shared memory), so a posix_spawn of a missing binary still reports
 * success to the parent while the child exits 127. */
int32_t mips_proc_vfork(mips32_ctx_t *ctx, uint32_t sp)
{
    int   pfd[2];
    pid_t pid;

    (void)sp;
    if (ctx == NULL) {
        return (int32_t)-EFAULT;
    }
#if defined(__linux__)
    if (pipe2(pfd, O_CLOEXEC) != 0) {
        if (pipe(pfd) != 0) {
            return fork_ret(ctx, -(int32_t)errno);
        }
        (void)fcntl(pfd[0], F_SETFD, FD_CLOEXEC);
        (void)fcntl(pfd[1], F_SETFD, FD_CLOEXEC);
    }
#else
    if (pipe(pfd) != 0) {
        return fork_ret(ctx, -(int32_t)errno);
    }
    (void)fcntl(pfd[0], F_SETFD, FD_CLOEXEC);
    (void)fcntl(pfd[1], F_SETFD, FD_CLOEXEC);
#endif
    fork_stages_prepare();
    pid = fork();
    if (pid < 0) {
        int err = errno;

        (void)close(pfd[0]);
        (void)close(pfd[1]);
        fork_stages_release();
        return fork_ret(ctx, -(int32_t)err);
    }
    if (pid == 0) {
        /* Keep pfd[1] open across the child lifetime: the execve path
         * closes it via the CLOEXEC sweep and _exit closes it
         * implicitly. */
        (void)close(pfd[0]);
        fork_child_common(ctx);
        return 0;
    }
    /* Parent: the child inherited its own write-end copy, so closing
     * ours leaves EOF tied to the child's exec/exit. */
    (void)close(pfd[1]);
    fork_stages_release();
    for (;;) {
        char    b;
        ssize_t n = read(pfd[0], &b, 1U);

        if (n == 0 || (n < 0 && errno != EINTR)) {
            break;
        }
        if (n > 0) {
            break;
        }
    }
    (void)close(pfd[0]);
    return fork_ret(ctx, (int32_t)pid);
}

/* Clone without address-space sharing (called from the L4b clone path
 * in threads.c): plain fork when is_vfork == 0, otherwise the
 * pipe-handshake vfork above.  The child takes child_stack so
 * posix_spawn's clone wrapper loads fn/arg from the new sp once the
 * syscall returns 0. */
int32_t mips_clone_no_vm(mips32_ctx_t *ctx, uint32_t sp, int is_vfork,
                         uint32_t child_stack)
{
    int32_t r = (is_vfork != 0) ? mips_proc_vfork(ctx, sp)
                                : mips_proc_fork(ctx, sp);

    if (r == 0 && child_stack != 0U) {
        ctx->gpr[MIPS32_REG_SP] = child_stack;
    }
    return r;
}
