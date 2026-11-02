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
#define L4A_EAGAIN 11

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

static void buf_put32(uint8_t *p, size_t off, uint32_t v, int be)
{
    if (be) {
        p[off + 0U] = (uint8_t)((v >> 24) & 0xFFU);
        p[off + 1U] = (uint8_t)((v >> 16) & 0xFFU);
        p[off + 2U] = (uint8_t)((v >> 8) & 0xFFU);
        p[off + 3U] = (uint8_t)(v & 0xFFU);
    } else {
        p[off + 0U] = (uint8_t)(v & 0xFFU);
        p[off + 1U] = (uint8_t)((v >> 8) & 0xFFU);
        p[off + 2U] = (uint8_t)((v >> 16) & 0xFFU);
        p[off + 3U] = (uint8_t)((v >> 24) & 0xFFU);
    }
}

static void buf_put64(uint8_t *p, size_t off, uint64_t v, int be)
{
    if (be) {
        buf_put32(p, off, (uint32_t)(v >> 32), be);
        buf_put32(p, off + 4U, (uint32_t)(v & 0xFFFFFFFFULL), be);
    } else {
        buf_put32(p, off, (uint32_t)(v & 0xFFFFFFFFULL), be);
        buf_put32(p, off + 4U, (uint32_t)(v >> 32), be);
    }
}

static uint32_t buf_get32(const uint8_t *p, size_t off, int be)
{
    if (be) {
        return ((uint32_t)p[off + 0U] << 24) | ((uint32_t)p[off + 1U] << 16) |
               ((uint32_t)p[off + 2U] << 8) | (uint32_t)p[off + 3U];
    }
    return (uint32_t)p[off + 0U] | ((uint32_t)p[off + 1U] << 8) |
           ((uint32_t)p[off + 2U] << 16) | ((uint32_t)p[off + 3U] << 24);
}

static uint64_t buf_get64(const uint8_t *p, size_t off, int be)
{
    uint32_t hi;
    uint32_t lo;

    if (be) {
        hi = buf_get32(p, off, be);
        lo = buf_get32(p, off + 4U, be);
    } else {
        lo = buf_get32(p, off, be);
        hi = buf_get32(p, off + 4U, be);
    }
    return ((uint64_t)hi << 32) | (uint64_t)lo;
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

/* rt_sigaction(sig, act, oact, sigsetsize): record-only. */
int32_t mips_sc_rt_sigaction(mips32_ctx_t *ctx, uint32_t sp)
{
    int ok = 1;
    uint32_t sig;
    uint32_t act_va;
    uint32_t oact_va;
    uint32_t setsize;
    l4a_action_t cur;
    unsigned w;
    uint8_t in_snap[L4A_KERN_SIGACTION_SIZE];
    int have_in = 0;

    if (ctx == NULL) {
        return -L4A_EFAULT;
    }
    sig = mips_sc_arg(ctx, sp, 0, &ok);
    act_va = mips_sc_arg(ctx, sp, 1, &ok);
    oact_va = mips_sc_arg(ctx, sp, 2, &ok);
    setsize = mips_sc_arg(ctx, sp, 3, &ok);
    if (!ok) {
        return mips_sc_ret(ctx, -L4A_EFAULT);
    }
    if (!l4a_valid_signo((int)sig) || l4a_uncatchable((int)sig)) {
        return mips_sc_ret(ctx, -L4A_EINVAL);
    }
    if (setsize != 16U) {
        return mips_sc_ret(ctx, -L4A_EINVAL);
    }
    /* Cross-RT Round-3 class: snapshot the input struct before writing
     * any old output, so aliased/overlapping act/oact pointers apply
     * the requested action instead of the just-written old state. */
    if (act_va != 0U) {
        if (mips_sc_copy_from(ctx, in_snap, act_va, sizeof(in_snap)) != 0) {
            return mips_sc_ret(ctx, -L4A_EFAULT);
        }
        have_in = 1;
    }
    mips32_spin_lock(&g_sig_lock);
    cur = g_actions[sig];
    mips32_spin_unlock(&g_sig_lock);
    if (oact_va != 0U) {
        uint8_t obuf[L4A_KERN_SIGACTION_SIZE];
        int be = mips_is_be(ctx);

        buf_put32(obuf, 0U, cur.flags, be);
        buf_put32(obuf, 4U, cur.installed ? cur.handler : L4A_SIG_DFL, be);
        for (w = 0; w < 4U; w++) {
            buf_put32(obuf, 8U + 4U * w, cur.mask.sig[w], be);
        }
        if (mips_sc_copy_to(ctx, oact_va, obuf, sizeof(obuf)) != 0) {
            return mips_sc_ret(ctx, -L4A_EFAULT);
        }
    }
    if (have_in == 0) {
        return mips_sc_ret(ctx, 0);
    }
    {
        int be = mips_is_be(ctx);
        l4a_action_t next;

        next.flags = buf_get32(in_snap, 0U, be);
        next.handler = buf_get32(in_snap, 4U, be);
        for (w = 0; w < 4U; w++) {
            next.mask.sig[w] = buf_get32(in_snap, 8U + 4U * w, be);
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
            mips_sig_purge_signo(ctx, (int)sig);
        }
    }
    return mips_sc_ret(ctx, 0);
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
    uint8_t in_snap[16];
    int have_in = 0;

    if (ctx == NULL) {
        return -L4A_EFAULT;
    }
    how = mips_sc_arg(ctx, sp, 0, &ok);
    set_va = mips_sc_arg(ctx, sp, 1, &ok);
    old_va = mips_sc_arg(ctx, sp, 2, &ok);
    setsize = mips_sc_arg(ctx, sp, 3, &ok);
    if (!ok) {
        return mips_sc_ret(ctx, -L4A_EFAULT);
    }
    if (how != L4A_SIG_BLOCK && how != L4A_SIG_UNBLOCK &&
        how != L4A_SIG_SETMASK) {
        return mips_sc_ret(ctx, -L4A_EINVAL);
    }
    if (setsize != 16U) {
        return mips_sc_ret(ctx, -L4A_EINVAL);
    }
    /* Same snapshot-first ordering as rt_sigaction above. */
    if (set_va != 0U) {
        if (mips_sc_copy_from(ctx, in_snap, set_va, sizeof(in_snap)) != 0) {
            return mips_sc_ret(ctx, -L4A_EFAULT);
        }
        have_in = 1;
    }
    be = mips_is_be(ctx);
    if (old_va != 0U) {
        uint8_t obuf[16];

        for (w = 0; w < 4U; w++) {
            buf_put32(obuf, 4U * w, ctx->sig_blocked[w], be);
        }
        if (mips_sc_copy_to(ctx, old_va, obuf, sizeof(obuf)) != 0) {
            return mips_sc_ret(ctx, -L4A_EFAULT);
        }
    }
    if (have_in != 0) {
        mips_sigset_t next;

        for (w = 0; w < 4U; w++) {
            next.sig[w] = buf_get32(in_snap, 4U * w, be);
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
    (void)mips_sc_ret(ctx, 0);
    mips_sc_advance_pc_once(ctx);
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

    rt32_vm_sync_ctx(ctx);
    if (mips32_range_ok(ctx, MIPS32_SIGTRAMP, 8U, (uint32_t)PROT_READ)) {
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
    if (ctx != NULL) {
        rt32_vm_sync_ctx((mips32_ctx_t *)ctx);
    }
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
    uint8_t frame[sizeof(mips_rt_sigframe_t)];

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
    memset(frame, 0, sizeof(frame));
    /* siginfo: signo@frame+24, code@+28, errno@+32(=0), addr@+36. */
    buf_put32(frame, 24U, (uint32_t)signo, be);
    buf_put32(frame, 28U, (uint32_t)si_code, be);
    buf_put32(frame, 36U, fault_addr, be);
    branch_pc = ctx->in_delay_slot != 0U ? ctx->pc - 4U : ctx->pc;
    buf_put64(frame, 184U, (uint64_t)branch_pc, be);
    /* M32-R3-7: the frame keeps the exact interrupted $sp; only the
     * new handler frame address (newsp) is aligned.  Rounding the saved
     * register would resume a fault-interrupted sequence with a
     * different stack pointer after rt_sigreturn. */
    for (i = 0; i < 32U; i++) {
        buf_put64(frame, 192U + 8U * i, (uint64_t)ctx->gpr[i], be);
        buf_put64(frame, 448U + 8U * i, ctx->fpr[i], be);
    }
    buf_put32(frame, 704U, 1U, be); /* sc_ownedfp */
    buf_put32(frame, 708U, ctx->fcsr, be); /* sc_fpc_csr */
    buf_put32(frame, 716U, 1U, be); /* sc_used_math */
    buf_put64(frame, 728U, (uint64_t)ctx->hi, be); /* sc_mdhi */
    buf_put64(frame, 736U, (uint64_t)ctx->lo, be); /* sc_mdlo */
    for (i = 0; i < 4U; i++) {
        buf_put32(frame, 768U + 4U * i, ctx->sig_blocked[i], be);
        entry_mask.sig[i] = ctx->sig_blocked[i] | act.mask.sig[i];
    }
    if (mips_sc_copy_to(ctx, newsp, frame, sizeof(frame)) != 0) {
        return -1;
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
    uint8_t frame[sizeof(mips_rt_sigframe_t)];

    if (ctx == NULL) {
        return -L4A_EFAULT;
    }
    sp = ctx->gpr[MIPS32_REG_SP];
    if ((sp & 7U) != 0U) {
        return mips_sc_ret(ctx, -L4A_EFAULT);
    }
    for (i = 0; i < ctx->sig_depth; i++) {
        if (ctx->sig_frame_sp[i] == sp) {
            idx = i;
            found = 1;
            break;
        }
    }
    if (!found) {
        return mips_sc_ret(ctx, -L4A_EFAULT);
    }
    if (mips_sc_copy_from(ctx, frame, sp, sizeof(frame)) != 0) {
        return mips_sc_ret(ctx, -L4A_EFAULT);
    }
    be = mips_is_be(ctx);
    for (i = 1; i < 32U; i++) {
        ctx->gpr[i] = (uint32_t)buf_get64(frame, 192U + 8U * i, be);
    }
    ctx->gpr[MIPS32_REG_ZERO] = 0U;
    for (i = 0; i < 32U; i++) {
        ctx->fpr[i] = buf_get64(frame, 448U + 8U * i, be);
    }
    ctx->pc = (uint32_t)buf_get64(frame, 184U, be);
    ctx->next_pc = ctx->pc + 4U;
    ctx->fcsr = buf_get32(frame, 708U, be);
    ctx->hi = (uint32_t)buf_get64(frame, 728U, be);
    ctx->lo = (uint32_t)buf_get64(frame, 736U, be);
    for (i = 0; i < 4U; i++) {
        saved.sig[i] = buf_get32(frame, 768U + 4U * i, be);
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
    uint8_t in_snap[12];
    int have_in = 0;

    if (ctx == NULL) {
        return -L4A_EFAULT;
    }
    ss_va = mips_sc_arg(ctx, sp, 0, &ok);
    oss_va = mips_sc_arg(ctx, sp, 1, &ok);
    if (!ok) {
        return mips_sc_ret(ctx, -L4A_EFAULT);
    }
    /* Same snapshot-first ordering as rt_sigaction above. */
    if (ss_va != 0U) {
        if (mips_sc_copy_from(ctx, in_snap, ss_va, sizeof(in_snap)) != 0) {
            return mips_sc_ret(ctx, -L4A_EFAULT);
        }
        have_in = 1;
    }
    be = mips_is_be(ctx);
    if (oss_va != 0U) {
        uint8_t obuf[12];
        uint32_t flags;

        flags = ((ctx->sigalt_flags & L4A_SS_DISABLE) != 0U ||
                 ctx->sigalt_size == 0U)
                    ? L4A_SS_DISABLE
                    : (l4a_on_altstack(ctx) ? L4A_SS_ONSTACK : 0U);
        buf_put32(obuf, 0U, ctx->sigalt_sp, be);
        buf_put32(obuf, 4U, ctx->sigalt_size, be);
        buf_put32(obuf, 8U, flags, be);
        if (mips_sc_copy_to(ctx, oss_va, obuf, sizeof(obuf)) != 0) {
            return mips_sc_ret(ctx, -L4A_EFAULT);
        }
    }
    if (have_in != 0) {
        uint32_t nsp;
        uint32_t nflags;
        uint32_t nsize;

        nsp = buf_get32(in_snap, 0U, be);
        nsize = buf_get32(in_snap, 4U, be);
        nflags = buf_get32(in_snap, 8U, be);
        if (nflags != L4A_SS_DISABLE && nflags != 0U &&
            nflags != L4A_SS_ONSTACK) {
            return mips_sc_ret(ctx, -L4A_EINVAL);
        }
        if (nflags == L4A_SS_DISABLE) {
            ctx->sigalt_flags = L4A_SS_DISABLE;
            ctx->sigalt_size = 0U;
            ctx->sigalt_sp = 0U;
            return mips_sc_ret(ctx, 0);
        }
        if (l4a_on_altstack(ctx)) {
            return mips_sc_ret(ctx, -L4A_EPERM);
        }
        if (nsize < L4A_MINSIGSTKSZ) {
            return mips_sc_ret(ctx, -L4A_ENOMEM);
        }
        ctx->sigalt_sp = nsp;
        ctx->sigalt_size = nsize;
        ctx->sigalt_flags = 0U;
    }
    return mips_sc_ret(ctx, 0);
}

/* execve (M32-R3-6, satisfies the weak reference in src/os/proc.c):
 * Linux preserves the blocked mask, pending signals, and ignored
 * dispositions across exec; only caught handlers reset to default.
 * Frame bookkeeping is obsolete (old stacks are gone) and the
 * alternate stack is disabled. */
void mips32_signals_reset_for_exec(mips32_ctx_t *ctx)
{
    size_t i;

    mips32_spin_lock(&g_sig_lock);
    for (i = 0; i <= L4A_NSIG; i++) {
        if (g_actions[i].installed && g_actions[i].handler != L4A_SIG_IGN) {
            g_actions[i].installed = 0;
            g_actions[i].handler = L4A_SIG_DFL;
            g_actions[i].flags = 0U;
            g_actions[i].restorer = 0U;
            memset(g_actions[i].mask.sig, 0, sizeof(g_actions[i].mask.sig));
        }
    }
    mips32_spin_unlock(&g_sig_lock);
    if (ctx != NULL) {
        memset(ctx->sig_frame_sp, 0, sizeof(ctx->sig_frame_sp));
        ctx->sig_depth = 0U;
        ctx->sigalt_sp = 0U;
        ctx->sigalt_size = 0U;
        ctx->sigalt_flags = L4A_SS_DISABLE;
    }
}

/* Coordinated fork stages for g_sig_lock (see src/os/fork.c). */
void mips_sig_fork_prepare(void)
{
    mips32_spin_lock(&g_sig_lock);
}

void mips_sig_fork_release(void)
{
    mips32_spin_unlock(&g_sig_lock);
}
