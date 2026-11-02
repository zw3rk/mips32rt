/*
 * src/os/kill.c — kill/tkill/tgkill self-delivery (Wave C2 lane C2-3).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * glibc raise() on MIPS O32 lowers to tgkill(tgid, tid, sig); kill()
 * and pthread signal paths lower to kill/tkill.  The Phase 4 signal
 * subsystem (signals.c) is synchronous and guest-owned, so these calls
 * deliver synchronously to the calling thread: the frame is built with
 * the kill-family si_code (SI_USER for kill, SI_TKILL for tkill/tgkill,
 * asm-generic/siginfo.h) and the engine resumes at the guest handler.
 *
 * Scope (documented limits, all fail-safe):
 * - Only the calling thread is a delivery target (every raise() site in
 *   the parity matrix is self-directed; no guest uses pthread_kill to a
 *   *different* thread).  Foreign pids/tids report -ESRCH.
 * - pid 0 (own process group) resolves to the caller; negative pids and
 *   foreign groups report -ESRCH (no pgroup iteration support).
 * - signo 0 is the existence check (no delivery, 0 on a live target).
 * - SIGKILL/SIGSTOP are never caught or ignored (Linux semantics);
 *   without async host-signal plumbing the group exits 128+signo, the
 *   same death a default-disposition fault takes in mips_trap.
 * - A recorded SIG_IGN disposition is a no-op success; any other
 *   installed handler delivers; SIG_DFL dies by the signal.
 *
 * O32 numbers (asm/unistd_o32.h, libc6-dev-mipsel-cross 2.36):
 * kill = __NR_Linux+37 (frozen in syscall_nr.h), tkill = +236,
 * tgkill = +266.  Defined locally so the frozen header stays untouched
 * (MIPS32_NR_TID_ADDRESS precedent in syscall_min.c).
 */

#include "mips32rt.h"

#include "os/syscall_nr.h"
#include "os/syscalls_priv.h"

#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>

#if defined(__linux__)
#include <sys/syscall.h>
extern long syscall(long __n, ...);
#endif

/* Locally frozen: __NR_tkill/__NR_tgkill offsets (see above). */
#define MIPS32_NR_TKILL 4236U
#define MIPS32_NR_TGKILL 4266U

/* Kill-family si_codes (include/uapi/asm-generic/siginfo.h). */
#define KILL_SI_USER (-1)
#define KILL_SI_TKILL (-6)

/* MIPS EAGAIN (arch/mips/include/uapi/asm/errno.h): sigqueue overflow. */
#define KILL_EAGAIN 11

/* MIPS signal numbers (arch/mips/include/uapi/asm/signal.h). */
#define KILL_SIGKILL   9
#define KILL_SIGBUS    10
#define KILL_SIGSYS    12
#define KILL_SIGUSR1   16
#define KILL_SIGUSR2   17
#define KILL_SIGCHLD   18
#define KILL_SIGPWR    19
#define KILL_SIGWINCH  20
#define KILL_SIGURG    21
#define KILL_SIGPOLL   22
#define KILL_SIGSTOP   23
#define KILL_SIGTSTP   24
#define KILL_SIGCONT   25
#define KILL_SIGTTIN   26
#define KILL_SIGTTOU   27
#define KILL_SIGVTALRM 28
#define KILL_SIGPROF   29
#define KILL_SIGXCPU   30
#define KILL_SIGXFSZ   31

/* Signals whose Linux default disposition on MIPS is Ignore. */
int mips_signal_default_ignore(int signo)
{
    return signo == KILL_SIGCHLD || signo == KILL_SIGWINCH ||
           signo == KILL_SIGURG  || signo == KILL_SIGCONT;
}

/* Signals whose Linux default disposition on MIPS is Stop. */
int mips_signal_default_stop(int signo)
{
    return signo == KILL_SIGSTOP || signo == KILL_SIGTSTP ||
           signo == KILL_SIGTTIN || signo == KILL_SIGTTOU;
}

static int mips_to_host_fatal_sig(int signo)
{
    switch (signo) {
    case 1:  return SIGHUP;
    case 2:  return SIGINT;
    case 3:  return SIGQUIT;
    case 4:  return SIGILL;
    case 5:  return SIGTRAP;
    case 6:  return SIGABRT;
    case 8:  return SIGFPE;
    case 9:  return SIGKILL;
    case KILL_SIGBUS:    return SIGBUS;
    case 11: return SIGSEGV;
    case KILL_SIGSYS:    return SIGSYS;
    case 13: return SIGPIPE;
    case 14: return SIGALRM;
    case 15: return SIGTERM;
    case KILL_SIGUSR1:   return SIGUSR1;
    case KILL_SIGUSR2:   return SIGUSR2;
#ifdef SIGPWR
    case KILL_SIGPWR:    return SIGPWR;
#endif
#ifdef SIGPOLL
    case KILL_SIGPOLL:   return SIGPOLL;
#endif
    case KILL_SIGVTALRM: return SIGVTALRM;
    case KILL_SIGPROF:   return SIGPROF;
    case KILL_SIGXCPU:   return SIGXCPU;
    case KILL_SIGXFSZ:   return SIGXFSZ;
    default: return 0;
    }
}

/* Die by signo without returning (default-disposition kill/trap target). */
void mips_signal_default_die(int signo)
{
#if defined(__linux__)
    int host_sig = mips_to_host_fatal_sig(signo);
    if (host_sig > 0) {
        (void)raise(host_sig);
    }
#else
    (void)mips_to_host_fatal_sig;
#endif
    _Exit(128 + (signo & 0x7F));
}

int32_t mips_sc_kill(mips32_ctx_t *ctx, uint32_t sp)
{
    uint32_t nr;
    uint32_t a0;
    uint32_t a1;
    uint32_t a2;
    uint32_t pid;
    uint32_t tid;
    int signo;
    int32_t si_code;
    int ok = 1;
    long self_pid;
    long self_tid;

    if (ctx == NULL) {
        return -14; /* EFAULT, matching the mips_sc_* style */
    }
    nr = ctx->gpr[MIPS32_REG_V0];
    a0 = mips_sc_arg(ctx, sp, 0, &ok);
    a1 = mips_sc_arg(ctx, sp, 1, &ok);
    a2 = mips_sc_arg(ctx, sp, 2, &ok);
    if (!ok) {
        return mips_sc_ret(ctx, -14);
    }
    self_pid = (long)getpid();
#if defined(__linux__) && defined(SYS_gettid)
    self_tid = syscall(SYS_gettid);
#else
    self_tid = (long)getpid();
#endif

    pid = a0;
    tid = (uint32_t)self_tid;
    signo = (int)a1;
    si_code = KILL_SI_USER;
    if (nr == MIPS32_NR_TKILL) {
        tid = a0;
        signo = (int)a1;
        si_code = KILL_SI_TKILL;
        pid = (uint32_t)self_pid;
    } else if (nr == MIPS32_NR_TGKILL) {
        pid = a0;
        tid = a1;
        signo = (int)a2;
        si_code = KILL_SI_TKILL;
    }
    if (signo < 0 || signo > 128) {
        return mips_sc_ret(ctx, -22); /* EINVAL */
    }
    if (signo == 0) {
        /* Existence check: pid 0 (own group) and self always live. */
        if (pid == 0U || pid == (uint32_t)self_pid) {
            return mips_sc_ret(ctx, 0);
        }
        return mips_sc_ret(ctx, -3); /* ESRCH */
    }
    if (pid != 0U && pid != (uint32_t)self_pid) {
        return mips_sc_ret(ctx, -3); /* ESRCH: no foreign-pid support */
    }
    if (tid != (uint32_t)self_tid) {
        /* Another live thread of the group: no async cross-thread
         * queue exists, so report ESRCH rather than lose the signal. */
        return mips_sc_ret(ctx, -3); /* ESRCH */
    }
    if (signo == KILL_SIGKILL) {
        mips_signal_default_die(signo);
        return mips_sc_ret(ctx, 0); /* unreachable */
    }
    if (signo == KILL_SIGSTOP) {
        (void)kill(getpid(), SIGSTOP);
        return mips_sc_ret(ctx, 0);
    }
    if (mips_signal_is_ignored(signo)) {
        return mips_sc_ret(ctx, 0);
    }
    if (!mips_signal_has_handler(signo) && mips_signal_default_ignore(signo)) {
        return mips_sc_ret(ctx, 0);
    }
    if (mips_signal_is_blocked(ctx, signo)) {
        /* M32-R3-5: a full real-time queue reports -EAGAIN (Linux
         * sigqueue overflow) instead of losing the occurrence. */
        if (mips_signal_pend(ctx, signo, si_code) != 0) {
            return mips_sc_ret(ctx, -KILL_EAGAIN);
        }
        return mips_sc_ret(ctx, 0);
    }
    if (!mips_signal_has_handler(signo)) {
        if (mips_signal_default_stop(signo)) {
            (void)kill(getpid(), SIGSTOP);
            return mips_sc_ret(ctx, 0);
        }
        mips_signal_default_die(signo);
        return mips_sc_ret(ctx, 0); /* unreachable */
    }
    /* Resume-after semantics: the frame snapshots the post-syscall
     * state (return 0 in $v0/$a3, pc past the trap insn), or sigreturn
     * would re-execute the trap and redeliver forever. */
    mips_sc_advance_pc_once(ctx);
    ctx->gpr[MIPS32_REG_V0] = 0U;
    ctx->gpr[MIPS32_REG_A3] = 0U;
    /* Synchronous self-delivery: the frame redirects ctx->pc at the
     * handler, so the completed $v0/$a3 above are what sigreturn
     * restores. Both engines resume at the moved pc. */
    if (mips_raise_guest_code(ctx, signo, si_code, 0U) != 0) {
        mips_signal_default_die(signo);
        return mips_sc_ret(ctx, 0); /* unreachable */
    }
    return 0;
}
