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
#include <stdint.h>
#include <unistd.h>

/* Local mirrors of the lane-L4a signal range (see signals.c). */
#define SQ_SIGKILL 9U
#define SQ_SIGSTOP 23U
#define SQ_NSIG    128U

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
    for (signo = 1U; signo <= SQ_NSIG; signo++) {
        int32_t code = 0;

        while (sq_pop_pending(ctx, signo, &code)) {
            if (mips_signal_is_ignored((int)signo)) {
                continue;
            }
            if (mips_signal_has_handler((int)signo)) {
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
