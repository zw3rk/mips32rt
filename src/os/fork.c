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

#include "mips32rt.h"

#include "os/syscalls_priv.h"

#include <errno.h>
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
        fork_stages_release();
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
        return 0;
    }
    fork_stages_release();
    return fork_ret(ctx, (int32_t)pid);
}

int32_t mips_proc_vfork(mips32_ctx_t *ctx, uint32_t sp)
{
    return mips_proc_fork(ctx, sp);
}
