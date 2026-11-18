/*
 * src/os/syscalls_misc.c — time, poll/select, rlimit and process-group
 * syscalls for the MIPS O32 guest (T1-T4 payload support)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Reached from mips_syscall_more() (syscalls_fs.c); MIPS RLIMIT_* translated here.
 */

#if defined(__linux__)
#define _GNU_SOURCE
#endif

#include "mips32rt.h"

#include "os/syscall_nr.h"
#include "os/syscalls_priv.h"

#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <sched.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/select.h>
#include <sys/time.h>
#include <sys/times.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define NR_TIME       4013U
#define NR_TIMES      4043U
#define NR_GETPGRP    4065U
#define NR_SETSID     4066U
#define NR_SETPGID    4057U
#define NR_GETPGID    4132U
#define NR_GETSID     4151U
#define NR_SETRLIMIT  4075U
#define NR_GETRLIMIT  4076U
#define NR_GETRUSAGE  4077U
#define NR_GETTIMEOFDAY 4078U
#define NR_GETGROUPS  4080U
#define NR_POLL       4188U
#define NR_PPOLL      4302U
#define NR_NEWSELECT  4142U
#define NR_PSELECT6   4301U
#define NR_PSELECT6_T64 4413U
#define NR_SCHED_YIELD 4162U
#define NR_PRLIMIT64  4338U
#define NR_SETUID     4023U
#define NR_SETGID     4046U
#define NR_SETREUID   4070U
#define NR_SETREGID   4071U
#define NR_SETRESUID  4185U
#define NR_SETRESGID  4190U
#define NR_SETGROUPS  4081U
#define NR_GETRESUID  4186U
#define NR_GETRESGID  4191U
#define NR_PRCTL      4192U
#define NR_SCHED_GETAFFINITY 4240U
#define NR_CLOCK_GETRES 4264U
#define NR_CLOCK_NANOSLEEP 4265U
#define NR_PAUSE      4029U
#define NR_ALARM      4027U

#define MIPS_RLIM_INFINITY 0x7fffffffU
#define MIPS_NFDBITS 32U
#define MIPS_FD_SETSIZE 1024U

/* MIPS RLIMIT_* -> host; returns -1 when unsupported. */
static int rlimit_to_host(uint32_t r)
{
    switch (r) {
    case 0U: return RLIMIT_CPU;
    case 1U: return RLIMIT_FSIZE;
    case 2U: return RLIMIT_DATA;
    case 3U: return RLIMIT_STACK;
    case 4U: return RLIMIT_CORE;
    case 5U: return RLIMIT_NOFILE;
#ifdef RLIMIT_AS
    case 6U: return RLIMIT_AS;
#endif
#ifdef RLIMIT_RSS
    case 7U: return RLIMIT_RSS;
#endif
#ifdef RLIMIT_NPROC
    case 8U: return RLIMIT_NPROC;
#endif
#ifdef RLIMIT_MEMLOCK
    case 9U: return RLIMIT_MEMLOCK;
#endif
    default: return -1;
    }
}

static uint32_t rl32(rlim_t v)
{
    if (v == RLIM_INFINITY || v > (rlim_t)MIPS_RLIM_INFINITY) {
        return MIPS_RLIM_INFINITY;
    }
    return (uint32_t)v;
}

static int32_t sc_rlimit(mips32_ctx_t *ctx, uint32_t sp, int set)
{
    struct rlimit rl;
    uint8_t       b[8];
    int           ok = 1;
    uint32_t      res = mips_sc_arg(ctx, sp, 0, &ok);
    uint32_t      va  = mips_sc_arg(ctx, sp, 1, &ok);
    int           hr  = rlimit_to_host(res);
    int           be  = mips_is_be(ctx);

    if (!ok) {
        return mips_sc_ret(ctx, -EFAULT);
    }
    if (hr < 0) {
        return mips_sc_ret(ctx, -EINVAL);
    }
    if (set) {
        /* Limits are advisory for a translated guest: accept and ignore. */
        return mips_sc_ret(ctx, 0);
    }
    if (getrlimit(hr, &rl) != 0) {
        return mips_sc_ret(ctx, -(int32_t)errno);
    }
    mips_sc_st32(b, rl32(rl.rlim_cur), be);
    mips_sc_st32(b + 4, rl32(rl.rlim_max), be);
    return mips_sc_ret(ctx, mips_sc_copy_to(ctx, va, b, 8U) != 0 ? -EFAULT : 0);
}

/* prlimit64(pid, resource, new*, old*): new is ignored. */
static int32_t sc_prlimit64(mips32_ctx_t *ctx, uint32_t sp)
{
    struct rlimit rl;
    uint8_t       b[16];
    int           ok = 1;
    uint32_t      res = mips_sc_arg(ctx, sp, 1, &ok);
    uint32_t      old = mips_sc_arg(ctx, sp, 3, &ok);
    int           hr  = rlimit_to_host(res);
    int           be  = mips_is_be(ctx);

    if (!ok) {
        return mips_sc_ret(ctx, -EFAULT);
    }
    if (hr < 0) {
        return mips_sc_ret(ctx, -EINVAL);
    }
    if (old != 0U) {
        if (getrlimit(hr, &rl) != 0) {
            return mips_sc_ret(ctx, -(int32_t)errno);
        }
        mips_sc_st64(b, rl.rlim_cur == RLIM_INFINITY ? ~0ULL
                                                     : (uint64_t)rl.rlim_cur, be);
        mips_sc_st64(b + 8, rl.rlim_max == RLIM_INFINITY ? ~0ULL
                                                         : (uint64_t)rl.rlim_max, be);
        if (mips_sc_copy_to(ctx, old, b, 16U) != 0) {
            return mips_sc_ret(ctx, -EFAULT);
        }
    }
    return mips_sc_ret(ctx, 0);
}

static int32_t sc_gettimeofday(mips32_ctx_t *ctx, uint32_t sp)
{
    struct timeval tv;
    uint8_t        b[8];
    int            ok = 1;
    uint32_t       va = mips_sc_arg(ctx, sp, 0, &ok);
    int            be = mips_is_be(ctx);

    if (!ok) {
        return mips_sc_ret(ctx, -EFAULT);
    }
    if (gettimeofday(&tv, NULL) != 0) {
        return mips_sc_ret(ctx, -(int32_t)errno);
    }
    if (va != 0U) {
        mips_sc_st32(b, (uint32_t)tv.tv_sec, be);
        mips_sc_st32(b + 4, (uint32_t)tv.tv_usec, be);
        if (mips_sc_copy_to(ctx, va, b, 8U) != 0) {
            return mips_sc_ret(ctx, -EFAULT);
        }
    }
    return mips_sc_ret(ctx, 0);
}

static int32_t sc_time(mips32_ctx_t *ctx, uint32_t sp)
{
    uint8_t  b[4];
    int      ok = 1;
    uint32_t va = mips_sc_arg(ctx, sp, 0, &ok);
    uint32_t t  = (uint32_t)time(NULL);

    if (!ok) {
        return mips_sc_ret(ctx, -EFAULT);
    }
    if (va != 0U) {
        mips_sc_st32(b, t, mips_is_be(ctx));
        if (mips_sc_copy_to(ctx, va, b, 4U) != 0) {
            return mips_sc_ret(ctx, -EFAULT);
        }
    }
    return mips_sc_ret(ctx, (int32_t)t);
}

/* times(struct tms*): four 32-bit clock_t fields; returns ticks. */
static int32_t sc_times(mips32_ctx_t *ctx, uint32_t sp)
{
    struct tms t;
    uint8_t    b[16];
    int        ok = 1;
    uint32_t   va = mips_sc_arg(ctx, sp, 0, &ok);
    clock_t    r;
    int        be = mips_is_be(ctx);

    if (!ok) {
        return mips_sc_ret(ctx, -EFAULT);
    }
    r = times(&t);
    if (r == (clock_t)-1) {
        return mips_sc_ret(ctx, -(int32_t)errno);
    }
    if (va != 0U) {
        mips_sc_st32(b, (uint32_t)t.tms_utime, be);
        mips_sc_st32(b + 4, (uint32_t)t.tms_stime, be);
        mips_sc_st32(b + 8, (uint32_t)t.tms_cutime, be);
        mips_sc_st32(b + 12, (uint32_t)t.tms_cstime, be);
        if (mips_sc_copy_to(ctx, va, b, 16U) != 0) {
            return mips_sc_ret(ctx, -EFAULT);
        }
    }
    /* Keep the result positive: a negative $v0 would look like an error. */
    return mips_sc_ret(ctx, (int32_t)((uint32_t)r & 0x7fffffffU));
}

/* getrusage(who, struct rusage*): 2 timevals + 14 longs (72 bytes). */
static int32_t sc_getrusage(mips32_ctx_t *ctx, uint32_t sp)
{
    struct rusage ru;
    uint8_t       b[72];
    int           ok = 1;
    uint32_t      who = mips_sc_arg(ctx, sp, 0, &ok);
    uint32_t      va  = mips_sc_arg(ctx, sp, 1, &ok);
    int           be  = mips_is_be(ctx);
    int           hw;

    if (!ok) {
        return mips_sc_ret(ctx, -EFAULT);
    }
    /* RUSAGE_SELF 0, RUSAGE_CHILDREN -1, RUSAGE_THREAD 1 */
    hw = ((int32_t)who == -1) ? RUSAGE_CHILDREN : RUSAGE_SELF;
    if (getrusage(hw, &ru) != 0) {
        return mips_sc_ret(ctx, -(int32_t)errno);
    }
    memset(b, 0, sizeof(b));
    mips_sc_st32(b + 0, (uint32_t)ru.ru_utime.tv_sec, be);
    mips_sc_st32(b + 4, (uint32_t)ru.ru_utime.tv_usec, be);
    mips_sc_st32(b + 8, (uint32_t)ru.ru_stime.tv_sec, be);
    mips_sc_st32(b + 12, (uint32_t)ru.ru_stime.tv_usec, be);
    mips_sc_st32(b + 16, (uint32_t)ru.ru_maxrss, be);
    mips_sc_st32(b + 32, (uint32_t)ru.ru_minflt, be);
    mips_sc_st32(b + 36, (uint32_t)ru.ru_majflt, be);
    return mips_sc_ret(ctx, mips_sc_copy_to(ctx, va, b, sizeof(b)) != 0
                                ? -EFAULT : 0);
}

static int32_t sc_getgroups(mips32_ctx_t *ctx, uint32_t sp)
{
    gid_t    g[256];
    uint8_t  b[256 * 4];
    int      ok = 1;
    uint32_t size = mips_sc_arg(ctx, sp, 0, &ok);
    uint32_t va   = mips_sc_arg(ctx, sp, 1, &ok);
    int      n;
    int      i;

    if (!ok) {
        return mips_sc_ret(ctx, -EFAULT);
    }
    n = getgroups(256, g);
    if (n < 0) {
        return mips_sc_ret(ctx, -(int32_t)errno);
    }
    if (size == 0U) {
        return mips_sc_ret(ctx, n);
    }
    if ((uint32_t)n > size) {
        return mips_sc_ret(ctx, -EINVAL);
    }
    for (i = 0; i < n; i++) {
        mips_sc_st32(b + 4 * i, (uint32_t)g[i], mips_is_be(ctx));
    }
    if (n > 0 && mips_sc_copy_to(ctx, va, b, (uint32_t)n * 4U) != 0) {
        return mips_sc_ret(ctx, -EFAULT);
    }
    return mips_sc_ret(ctx, n);
}

/* ---- poll / ppoll ---- */

/* Monotonic milliseconds (CLOCK_MONOTONIC); -1 when unavailable. */
static int64_t mono_ms_now(void)
{
    struct timespec now;

    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
        return -1;
    }
    return (int64_t)now.tv_sec * 1000 + (int64_t)(now.tv_nsec / 1000000L);
}

/* Raw result (count or -errno); the caller sets the syscall return. */
static int32_t do_poll(mips32_ctx_t *ctx, uint32_t va, uint32_t nfds,
                       int timeout_ms)
{
    struct pollfd   *pf;
    uint8_t         *raw;
    uint32_t         i;
    int              n;
    int              be = mips_is_be(ctx);
    mips_chld_wait_t cw;
    int64_t          deadline = 0;
    int              has_deadline = 0;

    if (nfds > 4096U) {
        return -EINVAL;
    }
    pf  = (struct pollfd *)calloc(nfds != 0U ? nfds : 1U, sizeof(*pf));
    raw = (uint8_t *)calloc(nfds != 0U ? nfds : 1U, 8U);
    if (pf == NULL || raw == NULL) {
        free(pf);
        free(raw);
        return -ENOMEM;
    }
    if (nfds != 0U && mips_sc_copy_from(ctx, raw, va, nfds * 8U) != 0) {
        free(pf);
        free(raw);
        return -EFAULT;
    }
    for (i = 0; i < nfds; i++) {
        uint32_t ev = mips_sc_ld32(raw + 8U * i + 4U, be);
        /* halfwords: events at +4, revents at +6 (endian-dependent). */
        uint16_t events = be ? (uint16_t)(ev >> 16) : (uint16_t)(ev & 0xffffU);

        pf[i].fd     = (int)(int32_t)mips_sc_ld32(raw + 8U * i, be);
        pf[i].events = mips_poll_events_to_host(events);
    }
    /* Retry loop: a guest-masked host SIGCHLD must not surface as a spurious -EINTR. */
    if (timeout_ms >= 0) {
        int64_t now = mono_ms_now();

        if (now >= 0) {
            deadline = now + (int64_t)timeout_ms;
            has_deadline = 1;
        }
    }
    for (;;) {
        int cur_ms = timeout_ms;

        if (has_deadline) {
            int64_t now = mono_ms_now();
            int64_t rem = (now >= 0) ? (deadline - now) : 0;

            if (rem <= 0) {
                n = 0;
                break;
            }
            cur_ms = (rem > (int64_t)INT_MAX) ? INT_MAX : (int)rem;
        }
        if (mips_chld_wait_begin(ctx, &cw)) {
            n = -1;
            errno = EINTR;
#if defined(__linux__)
        } else if (cw.active) {
            struct timespec ts;

            ts.tv_sec = cur_ms / 1000;
            ts.tv_nsec = (long)(cur_ms % 1000) * 1000000L;
            n = ppoll(pf, (nfds_t)nfds, cur_ms < 0 ? NULL : &ts, &cw.wait);
#endif
        } else {
            n = poll(pf, (nfds_t)nfds, cur_ms);
        }
        if (n < 0) {
            int e = errno;

            mips_chld_wait_end(ctx, &cw);
            if (e != EINTR || !mips_sig_should_retry_wait(ctx)) {
                free(pf);
                free(raw);
                return -e;
            }
            continue;
        }
        mips_chld_wait_end(ctx, &cw);
        break;
    }
    for (i = 0; i < nfds; i++) {
        uint16_t re = mips_poll_revents_from_host(pf[i].revents);
        uint8_t *p = raw + 8U * i + 6U;

        if (be) {
            p[0] = (uint8_t)(re >> 8);
            p[1] = (uint8_t)re;
        } else {
            p[0] = (uint8_t)re;
            p[1] = (uint8_t)(re >> 8);
        }
    }
    if (nfds != 0U && mips_sc_copy_to(ctx, va, raw, nfds * 8U) != 0) {
        free(pf);
        free(raw);
        return -EFAULT;
    }
    free(pf);
    free(raw);
    return n;
}

static int sel_mask_swap(mips32_ctx_t *ctx, uint32_t set_va, uint32_t setsize,
                         uint32_t old[4]);

static int32_t sc_poll(mips32_ctx_t *ctx, uint32_t sp, int is_ppoll)
{
    int      ok = 1;
    uint32_t va    = mips_sc_arg(ctx, sp, 0, &ok);
    uint32_t nfds  = mips_sc_arg(ctx, sp, 1, &ok);
    uint32_t t     = mips_sc_arg(ctx, sp, 2, &ok);
    uint32_t smask = is_ppoll ? mips_sc_arg(ctx, sp, 3, &ok) : 0U;
    uint32_t ssize = is_ppoll ? mips_sc_arg(ctx, sp, 4, &ok) : 0U;
    uint32_t oldmask[4];
    int      swapped;
    int      ms;

    if (!ok) {
        return mips_sc_ret(ctx, -EFAULT);
    }
    if (!is_ppoll) {
        ms = (int)(int32_t)t;
    } else if (t == 0U) {
        ms = -1;
    } else {
        uint8_t b[8];
        int     be = mips_is_be(ctx);
        int32_t s;
        int32_t ns;

        if (mips_sc_copy_from(ctx, b, t, 8U) != 0) {
            return mips_sc_ret(ctx, -EFAULT);
        }
        s  = (int32_t)mips_sc_ld32(b, be);
        ns = (int32_t)mips_sc_ld32(b + 4, be);
        /* Out-of-range timespecs get EINVAL; saturate the 32-bit ms
         * multiply at INT_MAX instead of wrapping past ~24 days. */
        if (s < 0 || ns < 0 || ns >= 1000000000) {
            return mips_sc_ret(ctx, -EINVAL);
        }
        {
            int64_t ms64 = (int64_t)s * 1000 +
                (int64_t)(ns + 999999) / 1000000;
            ms = (ms64 > (int64_t)INT_MAX) ? INT_MAX : (int)ms64;
        }
    }
    swapped = sel_mask_swap(ctx, smask, ssize, oldmask);
    if (swapped < 0) {
        return mips_sc_ret(ctx, swapped);
    }
    /* M3: temp mask live; the begin pre-check turns pending signals into immediate -EINTR. */
    return mips_sig_finish_wait(ctx, do_poll(ctx, va, nfds, ms), swapped,
                                oldmask);
}

/* ---- select ---- */

static int sel_load(mips32_ctx_t *ctx, uint32_t va, uint32_t n, fd_set *out,
                    fd_set **ptr)
{
    uint8_t  raw[MIPS_FD_SETSIZE / 8U];
    uint32_t words = (n + MIPS_NFDBITS - 1U) / MIPS_NFDBITS;
    uint32_t i;
    int      be = mips_is_be(ctx);

    *ptr = NULL;
    if (va == 0U) {
        return 0;
    }
    if (mips_sc_copy_from(ctx, raw, va, words * 4U) != 0) {
        return -EFAULT;
    }
    FD_ZERO(out);
    for (i = 0; i < n; i++) {
        uint32_t w = mips_sc_ld32(raw + 4U * (i / MIPS_NFDBITS), be);

        if (((w >> (i % MIPS_NFDBITS)) & 1U) != 0U) {
            FD_SET((int)i, out);
        }
    }
    *ptr = out;
    return 0;
}

static int sel_store(mips32_ctx_t *ctx, uint32_t va, uint32_t n,
                     const fd_set *in)
{
    uint8_t  raw[MIPS_FD_SETSIZE / 8U];
    uint32_t words = (n + MIPS_NFDBITS - 1U) / MIPS_NFDBITS;
    uint32_t i;
    int      be = mips_is_be(ctx);

    if (va == 0U) {
        return 0;
    }
    memset(raw, 0, sizeof(raw));
    for (i = 0; i < n; i++) {
        if (FD_ISSET((int)i, in)) {
            uint8_t *p = raw + 4U * (i / MIPS_NFDBITS);
            uint32_t w = mips_sc_ld32(p, be) | (1U << (i % MIPS_NFDBITS));

            mips_sc_st32(p, w, be);
        }
    }
    return mips_sc_copy_to(ctx, va, raw, words * 4U) != 0 ? -EFAULT : 0;
}

/* Temp sigmask of ppoll/pselect6 over ctx->sig_blocked (KILL/STOP
 * stripped). Saves old in old[4]; 1 installed, 0 none, <0 errno. */
static int sel_mask_swap(mips32_ctx_t *ctx, uint32_t set_va, uint32_t setsize,
                         uint32_t old[4])
{
    uint8_t  set[16];
    int      be = mips_is_be(ctx);
    unsigned w;

    if (set_va == 0U) {
        return 0;
    }
    if (setsize != 16U) {
        return -EINVAL;
    }
    if (mips_sc_copy_from(ctx, set, set_va, sizeof(set)) != 0) {
        return -EFAULT;
    }
    for (w = 0; w < 4U; w++) {
        old[w] = ctx->sig_blocked[w];
        ctx->sig_blocked[w] = mips_sc_ld32(set + 4U * w, be);
    }
    ctx->sig_blocked[0] &= ~((1U << 8) | (1U << 22));
    return 1;
}

/* pselect6 sixth argument: {sigset_ptr, sigsetsize}. */
static int sel_mask_swap_p6(mips32_ctx_t *ctx, uint32_t argva,
                            uint32_t old[4])
{
    uint8_t arg[8];
    int     be = mips_is_be(ctx);

    if (argva == 0U) {
        return 0;
    }
    if (mips_sc_copy_from(ctx, arg, argva, sizeof(arg)) != 0) {
        return -EFAULT;
    }
    return sel_mask_swap(ctx, mips_sc_ld32(arg, be), mips_sc_ld32(arg + 4, be),
                         old);
}

/* Monotonic microseconds (CLOCK_MONOTONIC); -1 when unavailable. */
static int64_t mono_us_now(void)
{
    struct timespec now;

    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
        return -1;
    }
    return (int64_t)now.tv_sec * 1000000 + (int64_t)(now.tv_nsec / 1000L);
}

/* _newselect writeback (Linux poll_select_finish): best-effort, {0,0} on timeout. */
static void sel_writeback_tv(mips32_ctx_t *ctx, uint32_t tva, int be,
    int rc, int has_deadline, int64_t deadline_us, int64_t initial_us)
{
    int64_t rem = 0;
    uint8_t ob[8];

    if (rc != 0) {
        int64_t now = has_deadline ? mono_us_now() : -1;

        rem = (now >= 0) ? (deadline_us - now) : initial_us;
        if (rem < 0) {
            rem = 0;
        } else if (rem > initial_us) {
            rem = initial_us;
        }
    }
    mips_sc_st32(ob, (uint32_t)(rem / 1000000), be);
    mips_sc_st32(ob + 4, (uint32_t)(rem % 1000000), be);
    (void)mips_sc_copy_to(ctx, tva, ob, sizeof(ob));
}

/* _newselect(n, in, out, ex, timeval*) and pselect6(.., timespec*, sig). */
static int32_t sc_select(mips32_ctx_t *ctx, uint32_t sp, int is_p6)
{
    fd_set          fr, fw, fe, sfr, sfw, sfe;
    fd_set         *pr, *pw, *pe;
    struct timeval  tv;
    struct timeval *ptv = NULL;
    int             ok = 1;
    uint32_t        n  = mips_sc_arg(ctx, sp, 0, &ok);
    uint32_t        rv = mips_sc_arg(ctx, sp, 1, &ok);
    uint32_t        wv = mips_sc_arg(ctx, sp, 2, &ok);
    uint32_t        ev = mips_sc_arg(ctx, sp, 3, &ok);
    uint32_t        tva = mips_sc_arg(ctx, sp, 4, &ok);
    uint32_t        sigarg = is_p6 ? mips_sc_arg(ctx, sp, 5, &ok) : 0U;
    uint32_t        oldmask[4];
    int             swapped;
    int             be = mips_is_be(ctx);
    int             rc;
    int64_t         deadline_us = 0;
    int64_t         initial_us = 0;
    int             has_deadline = 0;
    mips_chld_wait_t cw;

    if (!ok) {
        return mips_sc_ret(ctx, -EFAULT);
    }
    if (n > MIPS_FD_SETSIZE || n > (uint32_t)FD_SETSIZE) {
        return mips_sc_ret(ctx, -EINVAL);
    }
    rc = sel_load(ctx, rv, n, &fr, &pr);
    if (rc == 0) {
        rc = sel_load(ctx, wv, n, &fw, &pw);
    }
    if (rc == 0) {
        rc = sel_load(ctx, ev, n, &fe, &pe);
    }
    if (rc != 0) {
        return mips_sc_ret(ctx, rc);
    }
    if (pr != NULL) sfr = fr;
    if (pw != NULL) sfw = fw;
    if (pe != NULL) sfe = fe;
    if (tva != 0U) {
        uint8_t b[16];

        if (is_p6 == 2) { /* struct timespec64: two 64-bit words */
            int64_t sec64, nsec64, usec;

            if (mips_sc_copy_from(ctx, b, tva, 16U) != 0) {
                return mips_sc_ret(ctx, -EFAULT);
            }
            sec64 = (int64_t)mips_sc_ld64(b, be);
            /* O32 compat timespec64 masks tv_nsec to 32 bits (pad word). */
            nsec64 = (int64_t)(uint64_t)mips_sc_ld32(b + 8 + (be ? 4 : 0), be);
            if (sec64 < 0 || nsec64 < 0 || nsec64 >= 1000000000LL) {
                return mips_sc_ret(ctx, -EINVAL); /* kernel rejects these */
            }
            if (sec64 > 0x7fffffffLL) { /* saturate: keep sec*1000000 in int64_t */
                sec64 = 0x7fffffffLL;
            }
            usec = (nsec64 + 999LL) / 1000LL;
            if (usec == 1000000LL) {
                sec64 += 1;
                usec = 0;
            }
            tv.tv_sec = (time_t)sec64;
            tv.tv_usec = (suseconds_t)usec;
        } else {
            int32_t sec32, sub32;
            int64_t sec, usec;

            if (mips_sc_copy_from(ctx, b, tva, 8U) != 0) {
                return mips_sc_ret(ctx, -EFAULT);
            }
            sec32 = (int32_t)mips_sc_ld32(b, be);
            sub32 = (int32_t)mips_sc_ld32(b + 4, be);
            if (is_p6 == 1) { /* struct timespec: two 32-bit words */
                if (sec32 < 0 || sub32 < 0 || sub32 >= 1000000000) {
                    return mips_sc_ret(ctx, -EINVAL);
                }
                sec = (int64_t)sec32;
                usec = ((int64_t)sub32 + 999) / 1000;
                if (usec == 1000000LL) {
                    sec += 1;
                    usec = 0;
                }
            } else { /* struct timeval: two 32-bit words */
                if (sec32 < 0 || sub32 < 0) {
                    return mips_sc_ret(ctx, -EINVAL);
                }
                sec = (int64_t)sec32 + (int64_t)sub32 / 1000000;
                usec = (int64_t)sub32 % 1000000;
                if (sec > 0x7fffffffLL) { /* saturate: keep sec*1000000 in int64_t */
                    sec = 0x7fffffffLL;
                }
            }
            tv.tv_sec = (time_t)sec;
            tv.tv_usec = (suseconds_t)usec;
        }
        ptv = &tv;
    }
    swapped = sel_mask_swap_p6(ctx, sigarg, oldmask);
    if (swapped < 0) {
        return mips_sc_ret(ctx, swapped);
    }
    /* M3 (as in sc_poll): temp mask live; begin pre-check turns pending into -EINTR. */
    if (ptv != NULL) {
        int64_t now = mono_us_now();

        initial_us = (int64_t)tv.tv_sec * 1000000 + (int64_t)tv.tv_usec;
        if (now >= 0) {
            deadline_us = now + initial_us;
            has_deadline = 1;
        }
    }
    for (;;) {
        struct timeval cur;
        struct timeval *pcur = NULL;

        if (pr != NULL) fr = sfr;
        if (pw != NULL) fw = sfw;
        if (pe != NULL) fe = sfe;

        if (mips_chld_wait_begin(ctx, &cw)) {
            rc = -1;
            errno = EINTR;
        } else {
            if (has_deadline) {
                int64_t now = mono_us_now();
                int64_t rem = (now >= 0) ? (deadline_us - now) : 0;

                /* A lapsed deadline still polls once with a zero timeout. */
                if (rem <= 0) {
                    rem = 0;
                }
                cur.tv_sec = (time_t)(rem / 1000000);
                cur.tv_usec = (suseconds_t)(rem % 1000000);
                pcur = &cur;
            } else if (ptv != NULL) {
                cur = tv;
                pcur = &cur;
            }
            MIPS_SEL_CAP_CHUNK(pcur);
            if (cw.active) {
                struct timespec ts;

                if (pcur != NULL) {
                    ts.tv_sec = cur.tv_sec;
                    ts.tv_nsec = (long)cur.tv_usec * 1000L;
                }
                rc = pselect((int)n, pr, pw, pe, pcur != NULL ? &ts : NULL,
                             &cw.wait);
            } else {
                rc = select((int)n, pr, pw, pe, pcur);
            }
        }
        if (rc < 0) {
            int e = errno;

            mips_chld_wait_end(ctx, &cw);
            if (e == EINTR && mips_sig_should_retry_wait(ctx)) {
                continue;
            }
            if (e == EINTR && is_p6 == 0 && tva != 0U) {
                sel_writeback_tv(ctx, tva, be, -EINTR, has_deadline,
                                 deadline_us, initial_us);
            }
            return mips_sig_finish_wait(ctx, -(int32_t)e, swapped, oldmask);
        }
        mips_chld_wait_end(ctx, &cw);
        /* A capped-chunk expiry is not the guest deadline: re-wait. */
        if (rc == 0 && has_deadline) {
            int64_t now = mono_us_now();
            if (now >= 0 && now < deadline_us) {
                continue;
            }
        }
        break;
    }
    if (swapped > 0) {
        memcpy(ctx->sig_blocked, oldmask, sizeof(oldmask));
    }
    if (rc == 0) { /* Timeout: the kernel zeroes the output sets. */
        if (pr != NULL) FD_ZERO(pr);
        if (pw != NULL) FD_ZERO(pw);
        if (pe != NULL) FD_ZERO(pe);
    }
    if (is_p6 == 0 && tva != 0U) {
        sel_writeback_tv(ctx, tva, be, rc, has_deadline, deadline_us,
                         initial_us);
    }
    if (pr != NULL) {
        rc = (sel_store(ctx, rv, n, pr) == 0) ? rc : -EFAULT;
    }
    if (rc >= 0 && pw != NULL) {
        rc = (sel_store(ctx, wv, n, pw) == 0) ? rc : -EFAULT;
    }
    if (rc >= 0 && pe != NULL) {
        rc = (sel_store(ctx, ev, n, pe) == 0) ? rc : -EFAULT;
    }
    return mips_sc_ret(ctx, rc);
}

/* setre*id / setres*id: (uint32_t)-1 is unchanged; Darwin lowers setres*id to setre*id. */
static int32_t sc_setid(mips32_ctx_t *ctx, uint32_t sp, uint32_t nr)
{
    int      ok = 1;
    int      is_gid = (nr == NR_SETREGID || nr == NR_SETRESGID);
    uint32_t r = mips_sc_arg(ctx, sp, 0, &ok);
    uint32_t e = mips_sc_arg(ctx, sp, 1, &ok);
    int      rc;

    if (!ok) {
        return mips_sc_ret(ctx, -EFAULT);
    }
    if (nr == NR_SETRESUID || nr == NR_SETRESGID) {
#if defined(__linux__)
        uint32_t sv = mips_sc_arg(ctx, sp, 2, &ok);

        rc = is_gid ? setresgid((gid_t)r, (gid_t)e, (gid_t)sv)
                    : setresuid((uid_t)r, (uid_t)e, (uid_t)sv);
#else
        rc = is_gid ? setregid((gid_t)r, (gid_t)e)
                    : setreuid((uid_t)r, (uid_t)e);
#endif
    } else {
        rc = is_gid ? setregid((gid_t)r, (gid_t)e)
                    : setreuid((uid_t)r, (uid_t)e);
    }
    return mips_sc_ret(ctx, rc != 0 ? -(int32_t)errno : 0);
}

int32_t mips_syscall_misc(mips32_ctx_t *ctx, uint32_t sp, uint32_t nr,
                          int *handled)
{
    int      ok = 1;
    uint32_t a0;

    *handled = 1;
    switch (nr) {
    case NR_TIME:         return sc_time(ctx, sp);
    case NR_TIMES:        return sc_times(ctx, sp);
    case NR_GETTIMEOFDAY: return sc_gettimeofday(ctx, sp);
    case NR_GETRLIMIT:    return sc_rlimit(ctx, sp, 0);
    case NR_SETRLIMIT:    return sc_rlimit(ctx, sp, 1);
    case NR_PRLIMIT64:    return sc_prlimit64(ctx, sp);
    case NR_GETRUSAGE:    return sc_getrusage(ctx, sp);
    case NR_GETGROUPS:    return sc_getgroups(ctx, sp);
    case NR_POLL:         return sc_poll(ctx, sp, 0);
    case NR_PPOLL:        return sc_poll(ctx, sp, 1);
    case NR_NEWSELECT:    return sc_select(ctx, sp, 0);
    case NR_PSELECT6:     return sc_select(ctx, sp, 1);
    case NR_PSELECT6_T64: return sc_select(ctx, sp, 2);
    case NR_SCHED_YIELD:
        (void)sched_yield();
        return mips_sc_ret(ctx, 0);
    case NR_GETPGRP:
        return mips_sc_ret(ctx, (int32_t)getpgrp());
    case NR_SETSID: {
        pid_t r = setsid();
        return mips_sc_ret(ctx, r < 0 ? -(int32_t)errno : (int32_t)r);
    }
    case NR_GETPGID:
    case NR_GETSID: {
        pid_t p = (pid_t)mips_sc_arg(ctx, sp, 0, &ok);
        pid_t r = (nr == NR_GETPGID) ? getpgid(p) : getsid(p);
        return mips_sc_ret(ctx, r < 0 ? -(int32_t)errno : (int32_t)r);
    }
    case NR_SETPGID: {
        pid_t p = (pid_t)mips_sc_arg(ctx, sp, 0, &ok);
        pid_t g = (pid_t)mips_sc_arg(ctx, sp, 1, &ok);
        return mips_sc_ret(ctx, setpgid(p, g) != 0 ? -(int32_t)errno : 0);
    }
    case NR_SETREUID:
    case NR_SETREGID:
    case NR_SETRESUID:
    case NR_SETRESGID:
        return sc_setid(ctx, sp, nr);
    case NR_SETUID:
    case NR_SETGID:
        a0 = mips_sc_arg(ctx, sp, 0, &ok);
        return mips_sc_ret(ctx, (nr == NR_SETUID ? setuid((uid_t)a0)
                                                 : setgid((gid_t)a0)) != 0
                                    ? -(int32_t)errno : 0);
    default:
        break;
    }
    *handled = 0;
    return 0;
}
