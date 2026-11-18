/*
 * src/os/sigchld.c — Host SIGCHLD bridge for sigmask-taking waits
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Guest children are host children, so their exits raise host SIGCHLD.
 * Guest signal state is emulated (ctx->sig_blocked, sig_pending), so
 * without a host handler a child exit never interrupts a blocking host
 * select/poll.  GNU make -jN waits for a jobserver token in
 * pselect6(..., unblock-SIGCHLD mask) and relies on that EINTR plus
 * its SIGCHLD handler to reap finished jobs.
 *
 * Once the guest installs a MIPS SIGCHLD (18) handler, a host handler
 * records the event (sigqueue.c).  pselect6/ppoll keep host SIGCHLD blocked across
 * the pre-check and unblock it only inside the atomic host
 * pselect/ppoll, so an exit landing between check and sleep still
 * wakes the sleep.  SA_RESTART keeps the translator's own blocking
 * calls (and guest read/wait4) transparent; Linux never restarts
 * select/poll after a handler, so those still see EINTR.
 *
 * On EINTR the pending guest signal is delivered under the wait's
 * temporary mask while its frame records the caller's mask, matching
 * Linux restore_saved_sigmask().
 */

#if defined(__linux__)
#define _GNU_SOURCE
#endif

#include "mips32rt.h"

#include "os/syscalls_priv.h"

#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <string.h>

/* MIPS SIGCHLD (asm/signal.h). */
#define SC_MIPS_SIGCHLD 18

/* Whether a pending signal with a guest handler is unblocked under the
 * current guest mask (the wakeup test of a sigmask-taking wait). */
static int sc_deliverable(const mips32_ctx_t *ctx)
{
    unsigned w;
    unsigned b;

    for (w = 0U; w < 4U; w++) {
        uint32_t live = ctx->sig_pending[w] & ~ctx->sig_blocked[w];

        for (b = 0U; live != 0U && b < 32U; b++) {
            if ((live & (1U << b)) != 0U) {
                int sig = (int)(w * 32U + b + 1U);

                /* Linux wakes sigmask-taking waits for any unblocked
                 * pending signal whose disposition is not ignored:
                 * handled signals plus DFL fatal/stop (mips_signal_pend
                 * keeps those queued). */
                if (!mips_signal_is_ignored(sig) &&
                    (mips_signal_has_handler(sig) ||
                     !mips_signal_default_ignore(sig))) {
                    return 1;
                }
            }
        }
    }
    return 0;
}

/* EINTR triage for blocking host waits (poll/select/nanosleep) that do
 * not hold host SIGCHLD blocked: convert the host event, then report
 * whether the guest call must be retried (1: nothing deliverable, the
 * EINTR is spurious while the guest mask blocks SIGCHLD) or reported
 * (0: a handled guest signal is unblocked and pending). */
int mips_sig_should_retry_wait(mips32_ctx_t *ctx)
{
    if (ctx == NULL) {
        return 0;
    }
    mips_host_sigchld_poll(ctx);
    return sc_deliverable(ctx) ? 0 : 1;
}

int mips_chld_wait_begin(mips32_ctx_t *ctx, mips_chld_wait_t *w)
{
    sigset_t chld;
    uint32_t bit = 1U << (SC_MIPS_SIGCHLD - 1);

    w->active = 0;
    if (ctx == NULL) {
        return 0;
    }
    if (!mips_host_sigchld_armed()) {
        return sc_deliverable(ctx);
    }
    (void)sigemptyset(&chld);
    (void)sigaddset(&chld, SIGCHLD);
    if (pthread_sigmask(SIG_BLOCK, &chld, &w->hold) != 0) {
        return 0;
    }
    w->active = 1;
    /* Start from the pre-wait mask with host SIGCHLD blocked: a guest
     * temp mask that keeps SIGCHLD blocked must not see it unblocked
     * here (spurious -EINTR). Unblock only when the guest temp mask
     * leaves SIGCHLD deliverable. */
    w->wait = w->hold;
    (void)sigaddset(&w->wait, SIGCHLD);
    if ((ctx->sig_blocked[0] & bit) == 0U) {
        (void)sigdelset(&w->wait, SIGCHLD);
    }
    mips_host_sigchld_poll(ctx);
    return sc_deliverable(ctx);
}

void mips_chld_wait_end(mips32_ctx_t *ctx, mips_chld_wait_t *w)
{
    if (w->active == 0) {
        return;
    }
    (void)pthread_sigmask(SIG_SETMASK, &w->hold, NULL);
    mips_host_sigchld_poll(ctx);
}

int32_t mips_sig_finish_wait(mips32_ctx_t *ctx, int32_t raw, int swapped,
                             const uint32_t old[4])
{
    unsigned depth0;
    unsigned i;

    (void)mips_sc_ret(ctx, raw);
    if (raw != -EINTR) {
        /* A ready>0/0 return with a signal deliverable under the temp
         * mask (e.g. wait_end just polled a host SIGCHLD unblocked by
         * pselect6/ppoll) still delivers before restoring old[]. */
        if (swapped <= 0 || !sc_deliverable(ctx)) {
            if (swapped > 0) {
                memcpy(ctx->sig_blocked, old, sizeof(ctx->sig_blocked));
            }
            return raw;
        }
    }
    mips_sc_advance_pc_once(ctx);
    depth0 = ctx->sig_depth;
    mips_signal_deliver_pending(ctx);
    if (swapped <= 0) {
        return raw;
    }
    if (ctx->sig_depth > depth0) {
        uint8_t buf[16];
        int be = mips_is_be(ctx);

        for (i = 0U; i < 4U; i++) {
            mips_sc_st32(buf + 4U * i, old[i], be);
        }
        /* The frame was just written at this address, so the store
         * cannot fault. rt_sigreturn now restores the caller's mask.
         * Shared MIPS_RT_SIGFRAME_SIGMASK_OFF (never a magic number). */
        (void)mips_sc_copy_to(ctx,
                              ctx->sig_frame_sp[depth0] +
                              (uint32_t)MIPS_RT_SIGFRAME_SIGMASK_OFF,
                              buf, sizeof(buf));
        return raw;
    }
    memcpy(ctx->sig_blocked, old, sizeof(ctx->sig_blocked));
    return raw;
}
