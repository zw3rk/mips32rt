/*
 * src/os/signals.c — Guest-owned synchronous signal delivery (lane L4a)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

#include "mips32rt.h"

#include "os/sigframe_mips32rt.h"
#include "os/syscall_nr.h"
#include "os/syscalls_priv.h"
#include "rt32/rt32.h"

#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS MAP_ANON
#endif

/* ---- MIPS signal numbers (UAPI asm/signal.h) ---- */
#define L4A_SIGILL  4U
#define L4A_SIGFPE  8U
#define L4A_SIGKILL 9U
#define L4A_SIGBUS  10U
#define L4A_SIGSEGV 11U
#define L4A_SIGSTOP 23U
#define L4A_NSIG    128U

/* ---- MIPS sigaction flags (UAPI asm/signal.h) ---- */
#define L4A_SA_NOCLDSTOP 0x00000001U
#define L4A_SA_SIGINFO   0x00000008U
#define L4A_SA_NOCLDWAIT 0x00010000U
#define L4A_SA_ONSTACK   0x08000000U
#define L4A_SA_RESTART   0x10000000U
#define L4A_SA_NODEFER   0x40000000U
#define L4A_SA_RESETHAND 0x80000000U

/* ---- MIPS mask operations (UAPI asm/signal.h: 1/2/3, not 0/1/2) ---- */
#define L4A_SIG_BLOCK   1U
#define L4A_SIG_UNBLOCK 2U
#define L4A_SIG_SETMASK 3U

/* ---- siginfo codes (asm-generic/siginfo.h) ---- */
#define L4A_SI_KERNEL   128
#define L4A_SEGV_MAPERR 1
#define L4A_SEGV_ACCERR 2
#define L4A_BUS_ADRALN  1
#define L4A_BUS_ADRERR  2
#define L4A_ILL_ILLOPC  1
#define L4A_FPE_FLTINV  7

/* ---- MIPS errnos ---- */
#define L4A_EFAULT 14
#define L4A_EINVAL 22
#define L4A_ENOMEM 12
#define L4A_EPERM  1

/* ---- sigaltstack(2) (asm-generic values, shared by the MIPS O32 UAPI) ---- */
#define L4A_SS_ONSTACK  1U
#define L4A_SS_DISABLE 2U
#define L4A_MINSIGSTKSZ 2048U

/* ---- Nested-delivery bound (lane card: max depth 8, else kill) ---- */
#define L4A_MAX_DEPTH 8U

/* Raw O32 sigaction struct: 24 bytes { flags, handler, mask[4] }. */
#define L4A_KERN_SIGACTION_SIZE 24U

/* Guest handler sentinels. */
#define L4A_SIG_DFL 0U
#define L4A_SIG_IGN 1U

/* Internal trampoline: addiu $v0, $zero, 4193 (rt_sigreturn); syscall. */
#define L4A_TRAMP_INSN0 0x24021061U
#define L4A_TRAMP_INSN1 0x0000000cU

typedef struct {
    uint32_t handler;
    uint32_t flags;
    uint32_t restorer; /* Always 0: MIPS UAPI carries no restorer slot. */
    mips_sigset_t mask;
    int installed;
} l4a_action_t;

/* Process-wide dispositions protected by g_sig_lock; blocked mask,
 * pending mask, and live frame stack live per-thread on mips32_ctx_t. */
static l4a_action_t g_actions[L4A_NSIG + 1U];
static _Atomic uint32_t g_sig_lock = 0U;

static int l4a_valid_signo(int signo)
{
    return signo >= 1 && signo <= (int)L4A_NSIG;
}

static int l4a_uncatchable(int signo)
{
    return signo == (int)L4A_SIGKILL || signo == (int)L4A_SIGSTOP;
}

static void l4a_mask_set(mips_sigset_t *m, int signo)
{
    unsigned bit;

    if (!l4a_valid_signo(signo)) {
        return;
    }
    bit = (unsigned)(signo - 1);
    m->sig[bit / 32U] |= (uint32_t)(1U << (bit % 32U));
}

static void l4a_mask_clear(mips_sigset_t *m, int signo)
{
    unsigned bit;

    if (!l4a_valid_signo(signo)) {
        return;
    }
    bit = (unsigned)(signo - 1);
    m->sig[bit / 32U] &= (uint32_t)~(uint32_t)(1U << (bit % 32U));
}

/* SIGKILL/SIGSTOP can never be blocked: force their bits clear. */
static void l4a_mask_scrub(mips_sigset_t *m)
{
    l4a_mask_clear(m, (int)L4A_SIGKILL);
    l4a_mask_clear(m, (int)L4A_SIGSTOP);
}

static int l4a_range_ok(const mips32_ctx_t *ctx, uint32_t va, uint32_t len,
    uint32_t need)
{
    return mips32_range_ok(ctx, va, len, need);
}

static void l4a_put32(mips32_ctx_t *ctx, uint32_t va, uint32_t v, int be)
{
    uint8_t *p = (uint8_t *)mips32_guest_ptr(ctx, va);

    if (be) {
        p[0] = (uint8_t)((v >> 24) & 0xFFU);
        p[1] = (uint8_t)((v >> 16) & 0xFFU);
        p[2] = (uint8_t)((v >> 8) & 0xFFU);
        p[3] = (uint8_t)(v & 0xFFU);
    } else {
        p[0] = (uint8_t)(v & 0xFFU);
        p[1] = (uint8_t)((v >> 8) & 0xFFU);
        p[2] = (uint8_t)((v >> 16) & 0xFFU);
        p[3] = (uint8_t)((v >> 24) & 0xFFU);
    }
}

static void l4a_put64(mips32_ctx_t *ctx, uint32_t va, uint64_t v, int be)
{
    if (be) {
        l4a_put32(ctx, va, (uint32_t)(v >> 32), be);
        l4a_put32(ctx, va + 4U, (uint32_t)(v & 0xFFFFFFFFULL), be);
    } else {
        l4a_put32(ctx, va, (uint32_t)(v & 0xFFFFFFFFULL), be);
        l4a_put32(ctx, va + 4U, (uint32_t)(v >> 32), be);
    }
}

static uint32_t l4a_get32(const mips32_ctx_t *ctx, uint32_t va, int be)
{
    const uint8_t *p = (const uint8_t *)mips32_guest_ptr(ctx, va);

    if (be) {
        return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
               ((uint32_t)p[2] << 8) | (uint32_t)p[3];
    }
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t l4a_get64(const mips32_ctx_t *ctx, uint32_t va, int be)
{
    uint32_t hi;
    uint32_t lo;

    if (be) {
        hi = l4a_get32(ctx, va, be);
        lo = l4a_get32(ctx, va + 4U, be);
    } else {
        lo = l4a_get32(ctx, va, be);
        hi = l4a_get32(ctx, va + 4U, be);
    }
    return ((uint64_t)hi << 32) | (uint64_t)lo;
}

/* O32 syscall argument fetch: $a0..$a3, then guest stack sp+16/+20... */
static uint32_t l4a_arg(const mips32_ctx_t *ctx, uint32_t sp, unsigned i,
    int *ok)
{
    int be;

    if (ctx == NULL || ok == NULL) {
        if (ok != NULL) {
            *ok = 0;
        }
        return 0;
    }
    be = mips_is_be(ctx);
    if (i < 4U) {
        return ctx->gpr[MIPS32_REG_A0 + i];
    }
    if (!l4a_range_ok(ctx, sp + (uint32_t)(16U + 4U * (i - 4U)), 4U,
            (uint32_t)PROT_READ)) {
        *ok = 0;
        return 0;
    }
    return l4a_get32(ctx, sp + (uint32_t)(16U + 4U * (i - 4U)), be);
}

/* $a3 convention writeback; returns the raw host-style value. */
static int32_t l4a_ret(mips32_ctx_t *ctx, int32_t raw)
{
    if (raw < 0) {
        int32_t e = -raw;

        ctx->gpr[MIPS32_REG_V0] = (uint32_t)(e == 38 ? 89 : e);
        ctx->gpr[MIPS32_REG_A3] = 1U;
    } else {
        ctx->gpr[MIPS32_REG_V0] = (uint32_t)raw;
        ctx->gpr[MIPS32_REG_A3] = 0U;
    }
    return raw;
}

/* mem.c fault hook: true when signo has a real guest handler. */
int mips_signal_has_handler(int signo)
{
    int has;

    if (!l4a_valid_signo(signo)) {
        return 0;
    }
    mips32_spin_lock(&g_sig_lock);
    has = g_actions[(unsigned)signo].installed &&
          g_actions[(unsigned)signo].handler != L4A_SIG_DFL &&
          g_actions[(unsigned)signo].handler != L4A_SIG_IGN;
    mips32_spin_unlock(&g_sig_lock);
    return has;
}

int mips_signal_is_blocked(const mips32_ctx_t *ctx, int signo)
{
    unsigned bit;

    if (ctx == NULL || !l4a_valid_signo(signo) || l4a_uncatchable(signo)) {
        return 0;
    }
    bit = (unsigned)(signo - 1);
    return (ctx->sig_blocked[bit / 32U] & (uint32_t)(1U << (bit % 32U))) != 0U;
}

void mips_signal_pend(mips32_ctx_t *ctx, int signo, int32_t si_code)
{
    unsigned bit;

    if (ctx == NULL || !l4a_valid_signo(signo) || l4a_uncatchable(signo)) {
        return;
    }
    bit = (unsigned)(signo - 1);
    ctx->sig_pending[bit / 32U] |= (uint32_t)(1U << (bit % 32U));
    ctx->sig_pending_code[signo] = si_code;
}

void mips_signal_deliver_pending(mips32_ctx_t *ctx)
{
    unsigned signo;

    if (ctx == NULL) {
        return;
    }
    for (signo = 1U; signo <= L4A_NSIG; signo++) {
        unsigned bit = signo - 1U;
        uint32_t mask = (uint32_t)(1U << (bit % 32U));
        int32_t code;

        if ((ctx->sig_pending[bit / 32U] & mask) == 0U ||
            (ctx->sig_blocked[bit / 32U] & mask) != 0U) {
            continue;
        }
        ctx->sig_pending[bit / 32U] &= ~mask;
        code = ctx->sig_pending_code[signo];
        if (mips_signal_is_ignored((int)signo)) {
            continue;
        }
        if (mips_signal_has_handler((int)signo)) {
            uint32_t word = 0U;

            if (mips_fetch(ctx, ctx->pc, &word) == 0 && word == 0x0000000CU) {
                ctx->pc += 4U;
                ctx->next_pc = ctx->pc + 4U;
                ctx->in_delay_slot = 0U;
            }
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

/* rt_sigaction(sig, act, oact, sigsetsize): record-only. */
int32_t mips_sc_rt_sigaction(mips32_ctx_t *ctx, uint32_t sp)
{
    int ok = 1;
    int be;
    uint32_t sig;
    uint32_t act_va;
    uint32_t oact_va;
    uint32_t setsize;
    l4a_action_t cur;
    uint32_t base;
    unsigned w;

    if (ctx == NULL) {
        return -L4A_EFAULT;
    }
    sig = l4a_arg(ctx, sp, 0, &ok);
    act_va = l4a_arg(ctx, sp, 1, &ok);
    oact_va = l4a_arg(ctx, sp, 2, &ok);
    setsize = l4a_arg(ctx, sp, 3, &ok);
    if (!ok) {
        return l4a_ret(ctx, -L4A_EFAULT);
    }
    if (!l4a_valid_signo((int)sig) || l4a_uncatchable((int)sig)) {
        return l4a_ret(ctx, -L4A_EINVAL);
    }
    if (setsize != 16U) {
        return l4a_ret(ctx, -L4A_EINVAL);
    }
    be = mips_is_be(ctx);
    mips32_spin_lock(&g_sig_lock);
    cur = g_actions[sig];
    mips32_spin_unlock(&g_sig_lock);
    if (oact_va != 0U) {
        if (!l4a_range_ok(ctx, oact_va, L4A_KERN_SIGACTION_SIZE,
                (uint32_t)PROT_WRITE)) {
            return l4a_ret(ctx, -L4A_EFAULT);
        }
        l4a_put32(ctx, oact_va, cur.flags, be);
        l4a_put32(ctx, oact_va + 4U,
            cur.installed ? cur.handler : L4A_SIG_DFL, be);
        for (w = 0; w < 4U; w++) {
            l4a_put32(ctx, oact_va + 8U + 4U * w, cur.mask.sig[w], be);
        }
    }
    if (act_va != 0U) {
        l4a_action_t next;

        if (!l4a_range_ok(ctx, act_va, L4A_KERN_SIGACTION_SIZE,
                (uint32_t)PROT_READ)) {
            return l4a_ret(ctx, -L4A_EFAULT);
        }
        base = act_va;
        next.flags = l4a_get32(ctx, base, be);
        next.handler = l4a_get32(ctx, base + 4U, be);
        for (w = 0; w < 4U; w++) {
            next.mask.sig[w] = l4a_get32(ctx, base + 8U + 4U * w, be);
        }
        next.restorer = 0U;
        l4a_mask_scrub(&next.mask);
        mips32_spin_lock(&g_sig_lock);
        if (next.handler == L4A_SIG_DFL || next.handler == L4A_SIG_IGN) {
            g_actions[sig].installed = (next.handler == L4A_SIG_IGN) ? 1 : 0;
            g_actions[sig].handler = next.handler;
            g_actions[sig].flags = next.flags;
            g_actions[sig].mask = next.mask;
            g_actions[sig].restorer = 0U;
        } else {
            next.installed = 1;
            g_actions[sig] = next;
        }
        mips32_spin_unlock(&g_sig_lock);
        if (next.handler == L4A_SIG_IGN ||
            (next.handler == L4A_SIG_DFL && mips_signal_default_ignore((int)sig))) {
            unsigned bit = sig - 1U;
            ctx->sig_pending[bit / 32U] &= ~(uint32_t)(1U << (bit % 32U));
        }
    }
    return l4a_ret(ctx, 0);
}

/* rt_sigprocmask(how, set, oldset, sigsetsize): record-only; the host
 * mask is never touched so faults stay synchronous. */
int32_t mips_l4a_rt_sigprocmask(mips32_ctx_t *ctx, uint32_t sp)
{
    int ok = 1;
    int be;
    uint32_t how;
    uint32_t set_va;
    uint32_t old_va;
    uint32_t setsize;
    unsigned w;

    if (ctx == NULL) {
        return -L4A_EFAULT;
    }
    how = l4a_arg(ctx, sp, 0, &ok);
    set_va = l4a_arg(ctx, sp, 1, &ok);
    old_va = l4a_arg(ctx, sp, 2, &ok);
    setsize = l4a_arg(ctx, sp, 3, &ok);
    if (!ok) {
        return l4a_ret(ctx, -L4A_EFAULT);
    }
    if (how != L4A_SIG_BLOCK && how != L4A_SIG_UNBLOCK &&
        how != L4A_SIG_SETMASK) {
        return l4a_ret(ctx, -L4A_EINVAL);
    }
    if (setsize != 16U) {
        return l4a_ret(ctx, -L4A_EINVAL);
    }
    be = mips_is_be(ctx);
    if (old_va != 0U) {
        if (!l4a_range_ok(ctx, old_va, 16U, (uint32_t)PROT_WRITE)) {
            return l4a_ret(ctx, -L4A_EFAULT);
        }
        for (w = 0; w < 4U; w++) {
            l4a_put32(ctx, old_va + 4U * w, ctx->sig_blocked[w], be);
        }
    }
    if (set_va != 0U) {
        mips_sigset_t next;

        if (!l4a_range_ok(ctx, set_va, 16U, (uint32_t)PROT_READ)) {
            return l4a_ret(ctx, -L4A_EFAULT);
        }
        for (w = 0; w < 4U; w++) {
            next.sig[w] = l4a_get32(ctx, set_va + 4U * w, be);
        }
        l4a_mask_scrub(&next);
        if (how == L4A_SIG_BLOCK) {
            for (w = 0; w < 4U; w++) {
                ctx->sig_blocked[w] |= next.sig[w];
            }
        } else if (how == L4A_SIG_UNBLOCK) {
            for (w = 0; w < 4U; w++) {
                ctx->sig_blocked[w] &= (uint32_t)~next.sig[w];
            }
        } else {
            for (w = 0; w < 4U; w++) {
                ctx->sig_blocked[w] = next.sig[w];
            }
        }
    }
    (void)l4a_ret(ctx, 0);
    mips_signal_deliver_pending(ctx);
    return 0;
}

/* Lazily install the synthetic sigtramp page: addiu $v0,4193; syscall.
 * Host mapping stays PROT_READ (engines fetch through the window; the
 * host never executes guest bytes, per W^X). */
static int l4a_ensure_sigtramp(mips32_ctx_t *ctx)
{
    void *want;
    void *got;
    uint8_t *h;
    int be;

    if (l4a_range_ok(ctx, MIPS32_SIGTRAMP, 8U, (uint32_t)PROT_READ)) {
        return 0;
    }
    want = (void *)(uintptr_t)(ctx->guest_base + (uint64_t)MIPS32_SIGTRAMP);
#ifdef __APPLE__
    (void)got;
    if (mprotect((void *)((uintptr_t)want & ~0x3FFFull), 0x4000u,
                 PROT_READ | PROT_WRITE) != 0) {
        return -1;
    }
#else
    got = mmap(want, (size_t)MIPS32_PAGE_SIZE,
        PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS,
        -1, 0);
    if (got != want) {
        return -1;
    }
#endif
    be = mips_is_be(ctx);
    h = (uint8_t *)want;
    if (be) {
        h[0] = 0x24U;
        h[1] = 0x02U;
        h[2] = 0x10U;
        h[3] = 0x61U;
        h[4] = 0x00U;
        h[5] = 0x00U;
        h[6] = 0x00U;
        h[7] = 0x0cU;
    } else {
        h[0] = 0x61U;
        h[1] = 0x10U;
        h[2] = 0x02U;
        h[3] = 0x24U;
        h[4] = 0x0cU;
        h[5] = 0x00U;
        h[6] = 0x00U;
        h[7] = 0x00U;
    }
#ifndef __APPLE__
    if (mprotect(want, (size_t)MIPS32_PAGE_SIZE, PROT_READ) != 0) {
        return -1;
    }
#endif
    /* Register in the authoritative VMA table (not the ctx mirror: the
     * next vm op refreshes the mirror from the table and would drop a
     * mirror-only entry, faulting the handler return).  The host
     * mapping stays PROT_READ (engines fetch through the window; the
     * host never executes guest bytes, per W^X). */
    if (rt32_vm_record_region(ctx, MIPS32_SIGTRAMP,
            MIPS32_SIGTRAMP + MIPS32_PAGE_SIZE,
            (uint32_t)(PROT_READ | PROT_EXEC), 0U, "sigtramp") != 0) {
        return -1;
    }
    return 0;
}

static int l4a_range_mapped(const mips32_ctx_t *ctx, uint32_t va,
    uint32_t len)
{
    return mips32_range_mapped(ctx, va, len);
}

static int32_t l4a_fault_code(int signo, uint32_t fault_addr,
    const mips32_ctx_t *ctx)
{
    if (signo == (int)L4A_SIGSEGV) {
        if (!l4a_range_mapped(ctx, fault_addr, 1U)) {
            return L4A_SEGV_MAPERR;
        }
        return L4A_SEGV_ACCERR;
    }
    if (signo == (int)L4A_SIGBUS) {
        if ((fault_addr & 3U) != 0U) {
            return L4A_BUS_ADRALN;
        }
        return L4A_BUS_ADRERR;
    }
    if (signo == (int)L4A_SIGILL) {
        return L4A_ILL_ILLOPC;
    }
    if (signo == (int)L4A_SIGFPE) {
        return L4A_FPE_FLTINV;
    }
    return L4A_SI_KERNEL;
}

/* Frozen contract: build the E04 rt_sigframe on the guest stack and
 * redirect the thread to the handler. Returns 0 on delivery, -1 when
 * the caller must kill the guest (no handler, depth/space failure). */
int mips_raise_guest_code(mips32_ctx_t *ctx, int signo, int32_t si_code,
    uint32_t fault_addr)
{
    l4a_action_t act;
    int be;
    uint32_t newsp;
    uint32_t ra;
    uint32_t branch_pc;
    unsigned i;
    mips_sigset_t entry_mask;

    if (ctx == NULL || !l4a_valid_signo(signo) ||
        !mips_signal_has_handler(signo)) {
        return -1;
    }
    if (ctx->sig_depth >= L4A_MAX_DEPTH) {
        return -1;
    }
    mips32_spin_lock(&g_sig_lock);
    act = g_actions[(unsigned)signo];
    mips32_spin_unlock(&g_sig_lock);
    {
        uint32_t sp = ctx->gpr[MIPS32_REG_SP];
        uint32_t base = sp;

        if ((act.flags & L4A_SA_ONSTACK) != 0U &&
            (ctx->sigalt_flags & L4A_SS_DISABLE) == 0U &&
            ctx->sigalt_size != 0U &&
            (sp < ctx->sigalt_sp ||
             sp >= ctx->sigalt_sp + ctx->sigalt_size)) {
            base = ctx->sigalt_sp + ctx->sigalt_size;
        }
        newsp = (base - (uint32_t)sizeof(mips_rt_sigframe_t)) &
                (uint32_t)~7U;
        if ((ctx->gpr[MIPS32_REG_SP] & 7U) != 0U) {
            ctx->gpr[MIPS32_REG_SP] &= (uint32_t)~7U;
        }
    }
    if (!l4a_range_ok(ctx, newsp, (uint32_t)sizeof(mips_rt_sigframe_t),
            (uint32_t)PROT_WRITE)) {
        return -1;
    }
    if (act.restorer != 0U) {
        ra = act.restorer;
    } else {
        if (l4a_ensure_sigtramp(ctx) != 0) {
            return -1;
        }
        ra = MIPS32_SIGTRAMP;
    }
    be = mips_is_be(ctx);
    memset(mips32_guest_ptr(ctx, newsp), 0, sizeof(mips_rt_sigframe_t));
    /* siginfo: signo@frame+24, code@+28, errno@+32(=0), addr@+36. */
    l4a_put32(ctx, newsp + 24U, (uint32_t)signo, be);
    l4a_put32(ctx, newsp + 28U, (uint32_t)si_code, be);
    l4a_put32(ctx, newsp + 36U, fault_addr, be);
    branch_pc = ctx->in_delay_slot != 0U ? ctx->pc - 4U : ctx->pc;
    l4a_put64(ctx, newsp + 184U, (uint64_t)branch_pc, be);
    for (i = 0; i < 32U; i++) {
        l4a_put64(ctx, newsp + 192U + 8U * i, (uint64_t)ctx->gpr[i], be);
        l4a_put64(ctx, newsp + 448U + 8U * i, ctx->fpr[i], be);
    }
    l4a_put32(ctx, newsp + 704U, 1U, be); /* sc_ownedfp */
    l4a_put32(ctx, newsp + 708U, ctx->fcsr, be); /* sc_fpc_csr */
    l4a_put32(ctx, newsp + 716U, 1U, be); /* sc_used_math */
    l4a_put64(ctx, newsp + 728U, (uint64_t)ctx->hi, be); /* sc_mdhi */
    l4a_put64(ctx, newsp + 736U, (uint64_t)ctx->lo, be); /* sc_mdlo */
    for (i = 0; i < 4U; i++) {
        l4a_put32(ctx, newsp + 768U + 4U * i, ctx->sig_blocked[i], be);
        entry_mask.sig[i] = ctx->sig_blocked[i] | act.mask.sig[i];
    }
    if ((act.flags & L4A_SA_NODEFER) == 0U) {
        l4a_mask_set(&entry_mask, signo);
    }
    l4a_mask_scrub(&entry_mask);
    for (i = 0; i < 4U; i++) {
        ctx->sig_blocked[i] = entry_mask.sig[i];
    }
    if ((act.flags & L4A_SA_RESETHAND) != 0U) {
        mips32_spin_lock(&g_sig_lock);
        g_actions[(unsigned)signo].installed = 0;
        g_actions[(unsigned)signo].handler = L4A_SIG_DFL;
        mips32_spin_unlock(&g_sig_lock);
    }
    ctx->sig_frame_sp[ctx->sig_depth] = newsp;
    ctx->sig_depth++;
    ctx->gpr[MIPS32_REG_A0] = (uint32_t)signo;
    ctx->gpr[MIPS32_REG_A1] = newsp + 24U;
    ctx->gpr[MIPS32_REG_A2] = newsp + 152U;
    ctx->gpr[25] = act.handler;
    ctx->gpr[MIPS32_REG_RA] = ra;
    ctx->gpr[MIPS32_REG_SP] = newsp;
    ctx->gpr[MIPS32_REG_ZERO] = 0U;
    ctx->pc = act.handler;
    ctx->next_pc = act.handler + 4U;
    ctx->in_delay_slot = 0U;
    ctx->llbit = 0U;
    ctx->exit_reason = MIPS32_EXIT_NONE;
    ctx->exit_info = 0U;
    return 0;
}

int mips_raise_guest(mips32_ctx_t *ctx, int signo, uint32_t fault_addr)
{
    return mips_raise_guest_code(ctx, signo,
        l4a_fault_code(signo, fault_addr, ctx), fault_addr);
}

int mips_signal_is_ignored(int signo)
{
    int ign;

    if (!l4a_valid_signo(signo)) {
        return 0;
    }
    mips32_spin_lock(&g_sig_lock);
    ign = g_actions[(unsigned)signo].installed &&
          g_actions[(unsigned)signo].handler == L4A_SIG_IGN;
    mips32_spin_unlock(&g_sig_lock);
    return ign;
}

int32_t mips_rt_sigreturn(mips32_ctx_t *ctx)
{
    uint32_t sp;
    int be;
    unsigned idx;
    unsigned i;
    int found = 0;
    mips_sigset_t saved;

    if (ctx == NULL) {
        return -L4A_EFAULT;
    }
    sp = ctx->gpr[MIPS32_REG_SP];
    if ((sp & 7U) != 0U) {
        ctx->gpr[MIPS32_REG_V0] = (uint32_t)L4A_EFAULT;
        ctx->gpr[MIPS32_REG_A3] = 1U;
        return -L4A_EFAULT;
    }
    for (i = 0; i < ctx->sig_depth; i++) {
        if (ctx->sig_frame_sp[i] == sp) {
            idx = i;
            found = 1;
            break;
        }
    }
    if (!found) {
        ctx->gpr[MIPS32_REG_V0] = (uint32_t)L4A_EFAULT;
        ctx->gpr[MIPS32_REG_A3] = 1U;
        return -L4A_EFAULT;
    }
    if (!l4a_range_ok(ctx, sp, (uint32_t)sizeof(mips_rt_sigframe_t),
            (uint32_t)PROT_READ)) {
        ctx->gpr[MIPS32_REG_V0] = (uint32_t)L4A_EFAULT;
        ctx->gpr[MIPS32_REG_A3] = 1U;
        return -L4A_EFAULT;
    }
    be = mips_is_be(ctx);
    for (i = 1; i < 32U; i++) {
        ctx->gpr[i] =
            (uint32_t)l4a_get64(ctx, sp + 192U + 8U * i, be);
    }
    ctx->gpr[MIPS32_REG_ZERO] = 0U;
    for (i = 0; i < 32U; i++) {
        ctx->fpr[i] = l4a_get64(ctx, sp + 448U + 8U * i, be);
    }
    ctx->pc = (uint32_t)l4a_get64(ctx, sp + 184U, be);
    ctx->next_pc = ctx->pc + 4U;
    ctx->fcsr = l4a_get32(ctx, sp + 708U, be);
    ctx->hi = (uint32_t)l4a_get64(ctx, sp + 728U, be);
    ctx->lo = (uint32_t)l4a_get64(ctx, sp + 736U, be);
    for (i = 0; i < 4U; i++) {
        saved.sig[i] = l4a_get32(ctx, sp + 768U + 4U * i, be);
    }
    l4a_mask_scrub(&saved);
    for (i = 0; i < 4U; i++) {
        ctx->sig_blocked[i] = saved.sig[i];
    }
    ctx->sig_depth = idx;
    ctx->in_delay_slot = 0U;
    ctx->llbit = 0U;
    ctx->exit_reason = MIPS32_EXIT_NONE;
    ctx->exit_info = 0U;
    mips_signal_deliver_pending(ctx);
    return 0;
}

void mips_trap(mips32_ctx_t *ctx, int signo, uint32_t addr)
{
    if (ctx != NULL && mips_signal_has_handler(signo) &&
        mips_raise_guest(ctx, signo, addr) == 0) {
        return;
    }
    (void)raise(signo);
    _Exit(128 + (signo & 0x7F));
}

/* True when the live guest sp runs on the alternate stack. */
static int l4a_on_altstack(const mips32_ctx_t *ctx)
{
    uint32_t sp;

    if (ctx == NULL || ctx->sigalt_size == 0U ||
        (ctx->sigalt_flags & L4A_SS_DISABLE) != 0U) {
        return 0;
    }
    sp = ctx->gpr[MIPS32_REG_SP];
    return sp >= ctx->sigalt_sp &&
           sp < ctx->sigalt_sp + ctx->sigalt_size;
}

/* sigaltstack(ss, oss): O32 stack_t is 12 bytes {sp, size, flags}. */
int32_t mips_sc_sigaltstack(mips32_ctx_t *ctx, uint32_t sp)
{
    int ok = 1;
    int be;
    uint32_t ss_va;
    uint32_t oss_va;

    if (ctx == NULL) {
        return -L4A_EFAULT;
    }
    ss_va = l4a_arg(ctx, sp, 0, &ok);
    oss_va = l4a_arg(ctx, sp, 1, &ok);
    if (!ok) {
        return l4a_ret(ctx, -L4A_EFAULT);
    }
    be = mips_is_be(ctx);
    if (oss_va != 0U) {
        uint32_t flags;

        if (!l4a_range_ok(ctx, oss_va, 12U, (uint32_t)PROT_WRITE)) {
            return l4a_ret(ctx, -L4A_EFAULT);
        }
        flags = ((ctx->sigalt_flags & L4A_SS_DISABLE) != 0U ||
                 ctx->sigalt_size == 0U)
                    ? L4A_SS_DISABLE
                    : (l4a_on_altstack(ctx) ? L4A_SS_ONSTACK : 0U);
        l4a_put32(ctx, oss_va, ctx->sigalt_sp, be);
        l4a_put32(ctx, oss_va + 4U, ctx->sigalt_size, be);
        l4a_put32(ctx, oss_va + 8U, flags, be);
    }
    if (ss_va != 0U) {
        uint32_t nsp;
        uint32_t nflags;
        uint32_t nsize;

        if (!l4a_range_ok(ctx, ss_va, 12U, (uint32_t)PROT_READ)) {
            return l4a_ret(ctx, -L4A_EFAULT);
        }
        nsp = l4a_get32(ctx, ss_va, be);
        nsize = l4a_get32(ctx, ss_va + 4U, be);
        nflags = l4a_get32(ctx, ss_va + 8U, be);
        if (nflags != L4A_SS_DISABLE && nflags != 0U &&
            nflags != L4A_SS_ONSTACK) {
            return l4a_ret(ctx, -L4A_EINVAL);
        }
        if (nflags == L4A_SS_DISABLE) {
            ctx->sigalt_flags = L4A_SS_DISABLE;
            ctx->sigalt_size = 0U;
            ctx->sigalt_sp = 0U;
            return l4a_ret(ctx, 0);
        }
        if (l4a_on_altstack(ctx)) {
            return l4a_ret(ctx, -L4A_EPERM);
        }
        if (nsize < L4A_MINSIGSTKSZ) {
            return l4a_ret(ctx, -L4A_ENOMEM);
        }
        ctx->sigalt_sp = nsp;
        ctx->sigalt_size = nsize;
        ctx->sigalt_flags = 0U;
    }
    return l4a_ret(ctx, 0);
}

/* execve: drop every disposition, mask, live frame and altstack
 * (satisfies the weak reference in src/os/proc.c). */
void mips32_signals_reset_for_exec(mips32_ctx_t *ctx)
{
    size_t i;

    mips32_spin_lock(&g_sig_lock);
    for (i = 0; i <= L4A_NSIG; i++) {
        g_actions[i].installed = 0;
        g_actions[i].handler = L4A_SIG_DFL;
        g_actions[i].flags = 0U;
        g_actions[i].restorer = 0U;
        memset(g_actions[i].mask.sig, 0, sizeof(g_actions[i].mask.sig));
    }
    mips32_spin_unlock(&g_sig_lock);
    if (ctx != NULL) {
        memset(ctx->sig_blocked, 0, sizeof(ctx->sig_blocked));
        memset(ctx->sig_pending, 0, sizeof(ctx->sig_pending));
        memset(ctx->sig_pending_code, 0, sizeof(ctx->sig_pending_code));
        memset(ctx->sig_frame_sp, 0, sizeof(ctx->sig_frame_sp));
        ctx->sig_depth = 0U;
        ctx->sigalt_sp = 0U;
        ctx->sigalt_size = 0U;
        ctx->sigalt_flags = L4A_SS_DISABLE;
    }
}
