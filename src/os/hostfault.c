/*
 * src/os/hostfault.c — host SIGSEGV/SIGBUS translation for DBT code.
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * DBT-emitted loads/stores check alignment inline but not mapping, so a
 * guest access to an unmapped page raises a host fault inside emitted
 * code.  mips_hostfault_install records the RX code-pool range once;
 * the dispatcher arms a checkpoint around every trampoline entry.  The
 * handler translates a fault whose faulting host PC lies inside the
 * pool into a guest delivery (SIGSEGV/SIGBUS preserved from the host
 * signal, fault address relocated into guest VA).  Faults anywhere else
 * chain to the previous disposition (translator bugs must crash loudly,
 * never masquerade as guest faults).
 *
 * The faulting host PC comes from the signal ucontext (AArch64 Linux
 * uc_mcontext.pc), never from si_addr: si_addr is the accessed data
 * address, which normally lies outside emitted code.  Emitted code
 * keeps ctx->pc at the faulting guest instruction (fpc, the branch for
 * delay slots) and GPRs flushed, so the delivered frame is precise.
 *
 * Per-thread state is __thread: guest threads run engines on their own
 * host threads.  The handler itself only records and longjmps out; all
 * guest work happens back in normal C context at the checkpoint.
 */

#define _GNU_SOURCE

#include "mips32rt.h"
#include "dbt/dbt.h"

#include <setjmp.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#if defined(__linux__) && defined(__aarch64__)
#include <sys/ucontext.h>
#endif

#define HF_SIGSEGV 11
#define HF_SIGBUS  10

static __thread int          hf_armed;
static __thread mips32_ctx_t *hf_ctx;
static __thread int          hf_signo;
static __thread void         *hf_addr;
static __thread sigjmp_buf   hf_jb;
/* RC4 threads: every DBT thread owns its code pool, so the covered
 * range is per-thread; only the sigaction install itself is once. */
static __thread const void *hf_pool;
static __thread size_t      hf_pool_len;
static int                 hf_installed;

static void hf_chain(int signo, siginfo_t *si)
{
    /* Not ours: restore the default and re-raise so the process dies
     * with the original signal (SA_NODEFER below keeps it unblocked). */
    struct sigaction dfl;

    (void)si;
    memset(&dfl, 0, sizeof dfl);
    dfl.sa_handler = SIG_DFL;
    (void)sigemptyset(&dfl.sa_mask);
    (void)sigaction(signo, &dfl, NULL);
    (void)raise(signo);
    _Exit(128 + (signo & 0x7F)); /* unreachable if raise worked */
}

static const void *hf_fault_pc(void *uc)
{
#if defined(__linux__) && defined(__aarch64__)
    ucontext_t *u = (ucontext_t *)uc;

    if (u == NULL) {
        return NULL;
    }
    return (const void *)(uintptr_t)u->uc_mcontext.pc;
#elif defined(__APPLE__) && defined(__aarch64__)
    ucontext_t *u = (ucontext_t *)uc;

    if (u == NULL) {
        return NULL;
    }
    return (const void *)(uintptr_t)u->uc_mcontext->__ss.__pc;
#else
    (void)uc;
    return NULL;
#endif
}

static void hf_handler(int signo, siginfo_t *si, void *uc)
{
    const void *pc;

    if (!hf_armed || hf_ctx == NULL || si == NULL) {
        hf_chain(signo, si);
        return;
    }
    /* The faulting instruction must live in emitted code; the data
     * address in si_addr is unrelated to the pool range. */
    pc = hf_fault_pc(uc);
    if (pc == NULL || pc < hf_pool ||
        (uintptr_t)pc >= (uintptr_t)hf_pool + hf_pool_len) {
        hf_chain(signo, si);
        return;
    }
    hf_signo = (signo == SIGBUS) ? HF_SIGBUS : HF_SIGSEGV;
    hf_addr = si->si_addr;
    hf_armed = 0;
    siglongjmp(hf_jb, 1);
}

void mips_hostfault_install(const void *pool, size_t len)
{
    struct sigaction sa;

    hf_pool = pool;
    hf_pool_len = len;
    if (hf_installed != 0) {
        return;
    }
    hf_installed = 1;
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = hf_handler;
    (void)sigemptyset(&sa.sa_mask);
    /* NODEFER: re-raise in hf_chain must deliver immediately; the armed
     * window is always exited via longjmp or disarm, never by return. */
    sa.sa_flags = SA_SIGINFO | SA_NODEFER;
    (void)sigaction(SIGSEGV, &sa, NULL);
    (void)sigaction(SIGBUS, &sa, NULL);
}

/* Runs one emitted block under the host-fault guard.  The sigsetjmp
 * frame MUST stay alive across the block: an earlier revision returned
 * to the dispatcher after arming, which freed this frame; the
 * trampoline then reused that stack area for its register saves and
 * destroyed the saved fp/lr, so the longjmp revival returned to a
 * clobbered address.  Calling the trampoline from inside this frame
 * keeps it ancestral (trampoline pushes land below it) and the
 * revival sound.  Returns 0 with *reasonp set (block ran; caller
 * disarms via the normal path below) or 1 (recovered from a host
 * fault and delivered it; the caller must continue dispatching).
 * An undeliverable fault terminates the process; never returns. */
int mips_hostfault_run(mips32_ctx_t *ctx, void *code, uint32_t *reasonp)
{
    hf_ctx = ctx;
    hf_armed = 1;
    /* H3: savemask=0. The checkpoint used to save the signal mask here,
     * costing one rt_sigprocmask syscall per dispatched block (the top
     * syscall in CoreMark profiles). The mask is invariant across the
     * armed window -- this handler is installed with SA_NODEFER and an
     * empty sa_mask so delivery never alters it, and neither the
     * trampoline nor emitted code issues mask-changing calls -- so
     * there is nothing to save or restore; the longjmp revival observes
     * the same mask either way. */
    if (sigsetjmp(hf_jb, 0) != 0) {
        /* Recovered from a host fault inside emitted code.  The ctx
         * parameter is NOT reliable here: longjmp restores machine
         * state to checkpoint time, and the compiler may hold the
         * parameter in a register clobbered by sigsetjmp itself, so
         * re-reading it can yield a stale pointer.  hf_ctx (written
         * to TLS before the setjmp, never a register temporary)
         * always names the armed context. */
        uint32_t         gva;
        int              signo = hf_signo;
        mips32_ctx_t *rc = hf_ctx;

        hf_armed = 0;
        /* A fault inside a locked LL/SC critical section abandons the
         * block without running the unlock epilogue: release the lock
         * for the faulting ctx (no other thread can be inside, since a
         * live holder would have had to acquire it first). */
        mips_ll_abandon(rc);
        if (rc == NULL) {
            _Exit(128 + (signo & 0x7F));
        }
        (void)ctx;
        gva = (uint32_t)((uintptr_t)hf_addr - rc->guest_base);
        /* Wave C2 difftest parity: replay this block's trace lines now,
         * while rc->pc still names the faulting insn (the dispatcher
         * continues before tracing on this path). */
        dbt_trace_converted_fault(rc);
        if (mips_raise_guest(rc, signo, gva) != 0) {
            _Exit(128 + (signo & 0x7F));
        }
        return 1;
    }
    *reasonp = dbt_trampoline_enter(ctx, code);
    mips_hostfault_disarm();
    return 0;
}

void mips_hostfault_disarm(void)
{
    hf_armed = 0;
}
