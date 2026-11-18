/*
 * src/os/sigqueue.c — Pending-signal queue and synchronous delivery
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Split from src/os/signals.c to honor the 900-line file limit.  Owns
 * the per-thread pending state on mips32_ctx_t: the 128-bit pending
 * mask, the real-time queue, and the synchronous delivery walk.
 * Dispositions stay in signals.c; default-destination helpers live in
 * kill.c.  All entry points are declared in os/syscalls_priv.h.
 */

#include "mips32rt.h"

#include "os/syscalls_priv.h"

#include <signal.h>
#include <stdatomic.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

/* Local mirrors of the lane-L4a signal range (see signals.c). */
#define SQ_SIGKILL 9U
#define SQ_SIGSTOP 23U
#define SQ_NSIG    128U

/* MIPS SIGCHLD (asm/signal.h) and the asm-generic CLD_* si_codes
 * (shared with every host: EXITED 1, KILLED 2, DUMPED 3). */
#define SQ_SIGCHLD    18
#define SQ_CLD_EXITED 1
#define SQ_CLD_KILLED 2
#define SQ_CLD_DUMPED 3

/* MIPS EAGAIN (arch/mips/include/uapi/asm/errno.h). */
#define SQ_EAGAIN 11

/* Queue-sender si_codes (asm-generic/siginfo.h): plain kill(2) is
 * SI_USER 0 and merges on RT overflow; SI_QUEUE/SI_TKILL observe EAGAIN. */
#define SQ_SI_USER (0)

static int sq_valid_signo(int signo)
{
    return signo >= 1 && signo <= (int)SQ_NSIG;
}

static int sq_uncatchable(int signo)
{
    return signo == (int)SQ_SIGKILL || signo == (int)SQ_SIGSTOP;
}

void mips_sig_purge_signo(mips32_ctx_t *ctx, int signo)
{
    uint32_t r;
    uint32_t w = 0U;
    unsigned bit;

    if (ctx == NULL || !sq_valid_signo(signo)) {
        return;
    }
    bit = (unsigned)(signo - 1);
    ctx->sig_pending[bit / 32U] &= ~(uint32_t)(1U << (bit % 32U));
    for (r = 0U; r < ctx->sig_rt_count && r < MIPS32_RT_SIG_QUEUE_CAP; r++) {
        if (ctx->sig_rt_signo[r] != (uint8_t)signo) {
            ctx->sig_rt_signo[w] = ctx->sig_rt_signo[r];
            ctx->sig_rt_code[w] = ctx->sig_rt_code[r];
            w++;
        }
    }
    ctx->sig_rt_count = w;
}

static int sq_pop_pending(mips32_ctx_t *ctx, unsigned signo, int32_t *out_code)
{
    unsigned bit = signo - 1U;
    uint32_t mask = (uint32_t)(1U << (bit % 32U));

    if ((ctx->sig_pending[bit / 32U] & mask) == 0U ||
        (ctx->sig_blocked[bit / 32U] & mask) != 0U) {
        return 0;
    }
    if (signo >= 32U) {
        uint32_t q;

        for (q = 0U; q < ctx->sig_rt_count && q < MIPS32_RT_SIG_QUEUE_CAP; q++) {
            if (ctx->sig_rt_signo[q] == (uint8_t)signo) {
                uint32_t k;
                int more = 0;

                *out_code = ctx->sig_rt_code[q];
                for (k = q + 1U; k < ctx->sig_rt_count && k < MIPS32_RT_SIG_QUEUE_CAP; k++) {
                    ctx->sig_rt_signo[k - 1U] = ctx->sig_rt_signo[k];
                    ctx->sig_rt_code[k - 1U] = ctx->sig_rt_code[k];
                    if (ctx->sig_rt_signo[k - 1U] == (uint8_t)signo) {
                        more = 1;
                    }
                }
                for (k = 0U; k < q; k++) {
                    if (ctx->sig_rt_signo[k] == (uint8_t)signo) {
                        more = 1;
                    }
                }
                ctx->sig_rt_count--;
                if (!more) {
                    ctx->sig_pending[bit / 32U] &= ~mask;
                }
                return 1;
            }
        }
    }
    ctx->sig_pending[bit / 32U] &= ~mask;
    *out_code = ctx->sig_pending_code[signo];
    return 1;
}

/* M32-R3-5: queueing is observable.  Standard signals merge into
 * the pending bit (no loss possible); a real-time signal whose queue
 * is full reports -EAGAIN without setting the bit for an event that
 * was never stored, so callers (kill) no longer report success for a
 * discarded occurrence -- except plain kill(2) (SI_USER), which takes
 * the Linux __send_signal "silent loss of information" branch: the
 * pending bit is set (merged) and the call returns 0.  Only queued
 * senders (SI_QUEUE/rt_sigqueueinfo, SI_TKILL/tkill/tgkill) see EAGAIN. */
int mips_signal_pend(mips32_ctx_t *ctx, int signo, int32_t si_code)
{
    unsigned bit;

    if (ctx == NULL || !sq_valid_signo(signo) || sq_uncatchable(signo)) {
        return 0;
    }
    bit = (unsigned)(signo - 1);
    if (signo >= 32) {
        if (ctx->sig_rt_count >= MIPS32_RT_SIG_QUEUE_CAP) {
            if (si_code == SQ_SI_USER) {
                ctx->sig_pending[bit / 32U] |= (uint32_t)(1U << (bit % 32U));
                return 0;
            }
            return -SQ_EAGAIN;
        }
        ctx->sig_rt_signo[ctx->sig_rt_count] = (uint8_t)signo;
        ctx->sig_rt_code[ctx->sig_rt_count] = si_code;
        ctx->sig_rt_count++;
    }
    ctx->sig_pending[bit / 32U] |= (uint32_t)(1U << (bit % 32U));
    ctx->sig_pending_code[signo] = si_code;
    return 0;
}

void mips_signal_deliver_pending(mips32_ctx_t *ctx)
{
    unsigned signo;

    if (ctx == NULL) {
        return;
    }
    /* Convert a recorded host SIGCHLD first, so a mask change (or any
     * syscall exit through the common hook) that unblocks SIGCHLD makes
     * an already-exited child visible before the walk below. */
    mips_host_sigchld_poll(ctx);
    for (signo = 1U; signo <= SQ_NSIG; signo++) {
        int32_t code = 0;

        while (sq_pop_pending(ctx, signo, &code)) {
            if (mips_signal_is_ignored((int)signo)) {
                continue;
            }
            if (mips_signal_has_handler((int)signo)) {
                /* Called only on mips_syscall exit paths (sigprocmask,
                 * sigreturn, finish_wait, check_at_syscall_exit), where
                 * sc_pc_advanced was reset to 0 at mips_syscall entry.
                 * Advance past the completed syscall once so the frame
                 * saves the post-syscall EPC (skipped for execve,
                 * sigreturn, and DBT which pre-set sc_pc_advanced = 1). */
                mips_sc_advance_pc_once(ctx);
                if (mips_raise_guest_code(ctx, (int)signo, code, 0U) != 0) {
                    mips_signal_default_die((int)signo);
                }
                return;
            }
            if (mips_signal_default_ignore((int)signo)) {
                continue;
            }
            if (mips_signal_default_stop((int)signo)) {
                (void)kill(getpid(), SIGSTOP);
                continue;
            }
            mips_signal_default_die((int)signo);
        }
    }
}

/* Host SIGCHLD bridge, host half (wait side: src/os/sigchld.c). Guest
 * children are host children; while the guest handles SIGCHLD a host
 * handler records each child exit for the guest-signal queue. */
static _Atomic int sq_host_sigchld = 0;
static volatile sig_atomic_t sq_host_sigchld_armed = 0;

/* Last child-exit snapshot for the SIGCHLD siginfo bridge. Written by
 * the SA_SIGINFO handler under a seqlock (odd seq = writer active) so
 * concurrent pollers never read a torn (pid, uid, status, code)
 * tuple; the pending flag above is claimed with atomic_exchange so
 * two threads never double-pend one child exit. Code and status are
 * MIPS O32 (CLD_EXITED/KILLED/DUMPED; a MIPS signal number for
 * KILLED/DUMPED). */
static _Atomic unsigned sq_chld_seq = 0;
static atomic_flag sq_chld_lock = ATOMIC_FLAG_INIT;
static _Atomic int sq_chld_pid = 0;
static _Atomic int sq_chld_uid = 0;
static _Atomic int sq_chld_status = 0;
static _Atomic int sq_chld_code = 0;

/* Host-to-MIPS O32 numbers (arch/mips asm/signal.h); mirrors
 * proc_host_to_mips_sig (proc.c). Unmapped host signals pass through. */
static int sq_host_to_mips_sig(int host_sig)
{
    switch (host_sig) {
    case SIGHUP: return 1;    case SIGINT: return 2;
    case SIGQUIT: return 3;   case SIGILL: return 4;
    case SIGTRAP: return 5;   case SIGABRT: return 6;
    case SIGBUS: return 10;   case SIGFPE: return 8;
    case SIGKILL: return 9;   case SIGUSR1: return 16;
    case SIGSEGV: return 11;  case SIGUSR2: return 17;
    case SIGPIPE: return 13;  case SIGALRM: return 14;
    case SIGTERM: return 15;  case SIGCHLD: return 18;
    case SIGCONT: return 25;  case SIGSTOP: return 23;
    case SIGTSTP: return 24;  case SIGTTIN: return 26;
    case SIGTTOU: return 27;  case SIGURG: return 21;
    case SIGXCPU: return 30;  case SIGXFSZ: return 31;
    case SIGVTALRM: return 28; case SIGPROF: return 29;
    case SIGWINCH: return 20; case SIGSYS: return 12;
#ifdef SIGPWR
    case SIGPWR: return 19;
#endif
#ifdef SIGPOLL
    case SIGPOLL: return 22;
#elif defined(SIGIO)
    case SIGIO: return 22;
#endif
    default: return host_sig;
    }
}

static void sq_host_sigchld_handler(int signo, siginfo_t *info, void *uc)
{
    unsigned seq;
    int code;
    int status;

    (void)signo;
    (void)uc;
    if (info == NULL ||
        atomic_flag_test_and_set_explicit(&sq_chld_lock,
                                          memory_order_acquire)) {
        atomic_store_explicit(&sq_host_sigchld, 1, memory_order_release);
        return;
    }
    code = info->si_code;
    status = info->si_status;
    if (code == SQ_CLD_KILLED || code == SQ_CLD_DUMPED) {
        status = sq_host_to_mips_sig(status);
    }
    seq = atomic_load_explicit(&sq_chld_seq, memory_order_relaxed);
    atomic_store_explicit(&sq_chld_seq, seq + 1U, memory_order_relaxed);
    atomic_thread_fence(memory_order_seq_cst);
    atomic_store_explicit(&sq_chld_pid, (int)info->si_pid,
        memory_order_relaxed);
    atomic_store_explicit(&sq_chld_uid, (int)info->si_uid,
        memory_order_relaxed);
    atomic_store_explicit(&sq_chld_status, status, memory_order_relaxed);
    atomic_store_explicit(&sq_chld_code, code, memory_order_release);
    atomic_store_explicit(&sq_chld_seq, seq + 2U, memory_order_release);
    atomic_flag_clear_explicit(&sq_chld_lock, memory_order_release);
    atomic_store_explicit(&sq_host_sigchld, 1, memory_order_release);
}

void mips_host_sigchld_arm(void)
{
    struct sigaction sa;

    if (sq_host_sigchld_armed != 0) {
        return;
    }
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = sq_host_sigchld_handler;
    sa.sa_flags = SA_SIGINFO | SA_NOCLDSTOP | SA_RESTART;
    (void)sigemptyset(&sa.sa_mask);
    if (sigaction(SIGCHLD, &sa, NULL) == 0) {
        sq_host_sigchld_armed = 1;
    }
}

int mips_host_sigchld_armed(void)
{
    return sq_host_sigchld_armed != 0;
}

/* Back to the host default once the guest no longer handles SIGCHLD
 * (SIG_DFL/SIG_IGN or exec), so its waits see no spurious EINTR. */
void mips_host_sigchld_disarm(void)
{
    struct sigaction sa;

    if (sq_host_sigchld_armed == 0) {
        return;
    }
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = SIG_DFL;
    (void)sigemptyset(&sa.sa_mask);
    (void)sigaction(SIGCHLD, &sa, NULL);
    sq_host_sigchld_armed = 0;
    atomic_store_explicit(&sq_host_sigchld, 0, memory_order_release);
}

/* Common syscall-exit hook (called from mips_syscall, so both engines
 * are covered): convert a recorded host SIGCHLD, then deliver whatever
 * is pending and unblocked.  The pc stays at the syscall when nothing
 * is delivered (each engine advances it); the advance past the syscall
 * happens inside mips_signal_deliver_pending right before a handled
 * signal is raised.  Skipped once the syscall stopped the thread
 * (exit, execve teardown, fatal signal). */
void mips_sig_check_at_syscall_exit(mips32_ctx_t *ctx)
{
    if (ctx == NULL || ctx->exit_reason != MIPS32_EXIT_NONE) {
        return;
    }
    mips_signal_deliver_pending(ctx);
}

/* Turn a recorded host SIGCHLD into a pending guest SIGCHLD (standard
 * signals merge into the pending bit).  Process-directed routing: a
 * thread that blocks SIGCHLD in its guest mask leaves the flag for a
 * peer that does not (every thread polls on the common syscall-exit
 * hook, so the first willing thread converts promptly). */
void mips_host_sigchld_poll(mips32_ctx_t *ctx)
{
    unsigned bit;
    int code;

    if (ctx == NULL ||
        atomic_load_explicit(&sq_host_sigchld, memory_order_acquire) == 0 ||
        !mips_signal_has_handler(SQ_SIGCHLD)) {
        return;
    }
    bit = (unsigned)(SQ_SIGCHLD - 1);
    if ((ctx->sig_blocked[bit / 32U] &
         (uint32_t)(1U << (bit % 32U))) != 0U) {
        return;
    }
    /* Claim first, snapshot second: code and the last_info tuple then
     * come from the same child exit instead of straddling two exits.
     * The exchange loser returns, so threads never double-pend one. */
    if (atomic_exchange_explicit(&sq_host_sigchld, 0,
            memory_order_acq_rel) == 0) {
        return;
    }
    code = atomic_load_explicit(&sq_chld_code, memory_order_acquire);
    if (code <= 0) {
        code = SQ_CLD_EXITED;
    }
    (void)mips_signal_pend(ctx, SQ_SIGCHLD, code);
}

/* Seqlock snapshot of the last child exit for the SIGCHLD siginfo
 * frame (src/os/signals.c): retries while the handler is writing or
 * the sequence moved, so the tuple is never torn. */
void mips_sigchld_last_info(int32_t *pid, uint32_t *uid, int32_t *status)
{
    unsigned s1;
    unsigned s2;
    int p;
    int u;
    int s;

    if (pid == NULL || uid == NULL || status == NULL) {
        return;
    }
    do {
        s1 = atomic_load_explicit(&sq_chld_seq, memory_order_acquire);
        p = atomic_load_explicit(&sq_chld_pid, memory_order_relaxed);
        u = atomic_load_explicit(&sq_chld_uid, memory_order_relaxed);
        s = atomic_load_explicit(&sq_chld_status, memory_order_relaxed);
        atomic_thread_fence(memory_order_acquire);
        s2 = atomic_load_explicit(&sq_chld_seq, memory_order_relaxed);
    } while (((s1 & 1U) != 0U) || (s1 != s2));
    *pid = (int32_t)p;
    *uid = (uint32_t)u;
    *status = (int32_t)s;
}

/* fork(2) hook (called from the fork-child path in src/os/fork.c): the
 * child never inherits a stale parent SIGCHLD flag. */
void mips_sigqueue_fork_child(void)
{
    atomic_store_explicit(&sq_chld_seq, 0U, memory_order_relaxed);
    atomic_flag_clear_explicit(&sq_chld_lock, memory_order_relaxed);
    atomic_store_explicit(&sq_host_sigchld, 0, memory_order_release);
}
