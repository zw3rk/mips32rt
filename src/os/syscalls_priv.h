/*
 * src/os/syscalls_priv.h — Shared internals of the Phase 2 syscall layer
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Lane L2a private header (not a frozen contract): MIPS O32 constants
 * plus the cross-file helpers/handlers shared between src/os/syscalls.c
 * (guest helpers, core fd handlers, dispatcher) and
 * src/os/syscalls_meta.c (fcntl/ioctl/stat/time/misc handlers).  Split
 * across two .c files only to honor the 900-line file limit.
 */

#ifndef MIPS32_SYSCALLS_PRIV_H
#define MIPS32_SYSCALLS_PRIV_H

#include "mips32rt.h"

#include "os/syscall_nr.h"

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/stat.h>
#include <time.h>

/* ---- MIPS O32 constants (SPEC 2.3; values from asm/fcntl.h above) ---- */
#define MIPS_O_APPEND    0x0008U
#define MIPS_O_DSYNC     0x0010U
#define MIPS_O_NONBLOCK  0x0080U
#define MIPS_O_CREAT     0x0100U
#define MIPS_O_TRUNC     0x0200U
#define MIPS_O_EXCL      0x0400U
#define MIPS_O_NOCTTY    0x0800U
#define MIPS_O_LARGEFILE 0x2000U
#define MIPS_O_SYNC      0x4010U /* __O_SYNC (0x4000) | O_DSYNC */
#define MIPS_O_DIRECT    0x8000U
#define MIPS_O_DIRECTORY 0x10000U /* 0200000 octal */
#define MIPS_O_NOFOLLOW  0x20000U /* 0400000 octal */
#define MIPS_O_NOATIME   0x40000U /* 01000000 octal */
#define MIPS_O_CLOEXEC   0x80000U /* 02000000 octal */
#define MIPS_O_PATH      0x200000U /* 010000000 octal */

#define MIPS_AT_FDCWD            (-100)
#define MIPS_AT_REMOVEDIR        0x200
#define MIPS_AT_SYMLINK_NOFOLLOW 0x100
#define MIPS_AT_EMPTY_PATH       0x1000

/* fcntl commands shared with asm-generic (bits/fcntl-linux.h). */
#define MIPS_F_DUPFD         0
#define MIPS_F_GETFD         1
#define MIPS_F_SETFD         2
#define MIPS_F_GETFL         3
#define MIPS_F_SETFL         4
#define MIPS_F_DUPFD_CLOEXEC 1030

/* Futex ops (include/uapi/linux/futex.h, arch-independent). */
#define MIPS_FUTEX_WAIT         0
#define MIPS_FUTEX_WAKE         1
#define MIPS_FUTEX_PRIVATE_FLAG 128

/* Ioctl requests (asm/ioctls.h: FIONREAD 0x467f; TIOCGWINSZ is
 * _IOR('t', 104, struct winsize) under the MIPS _IOC layout
 * (DIRSHIFT 29, _IOC_READ 2): (2<<29)|(8<<16)|('t'<<8)|104. */
#define MIPS_FIONREAD    0x467fU
#define MIPS_TIOCGWINSZ  0x40087468U

/* getrandom flags (include/uapi/linux/random.h, arch-independent). */
#define MIPS_GRND_NONBLOCK 0x1U
#define MIPS_GRND_RANDOM   0x2U

/* close_range flags (include/uapi/linux/close_range.h). */
#define MIPS_CLOSE_RANGE_UNSHARE 2U
#define MIPS_CLOSE_RANGE_CLOEXEC 4U

/* MIPS O32 struct stat64 is 104 bytes (asm/stat.h, SPEC 2.3). */
#define MIPS_STAT64_SIZE 104U
#define MIPS_STATX_SIZE  256U
#define MIPS_SIGSET_SIZE 16U /* 128 signals (SPEC 2.3) */
#define MIPS_XIOV_MAX    1024U
#define MIPS_PATH_MAX    4096U

/* Guest helpers (defined in syscalls.c; never fault, -EFAULT style). */
int32_t  mips_sc_ret(mips32_ctx_t *ctx, int32_t raw);
void     mips_sc_advance_pc_once(mips32_ctx_t *ctx);
uint32_t mips_sc_arg(mips32_ctx_t *ctx, uint32_t sp, unsigned i, int *ok);
int      mips_sc_range_ok(const mips32_ctx_t *ctx, uint32_t va, uint32_t len,
                          uint32_t need);
int      mips_sc_copy_from(const mips32_ctx_t *ctx, void *dst, uint32_t va,
                           uint32_t len);
int      mips_sc_copy_to(mips32_ctx_t *ctx, uint32_t va, const void *src,
                         uint32_t len);
uint32_t mips_sc_ld32(const uint8_t *p, int be);
void     mips_sc_st16(uint8_t *p, uint16_t v, int be);
void     mips_sc_st32(uint8_t *p, uint32_t v, int be);
void     mips_sc_st64(uint8_t *p, uint64_t v, int be);
int      mips_sc_read_cstr(const mips32_ctx_t *ctx, uint32_t va,
                           char *host_buf);
#define MIPS_PROC_NONE    0
#define MIPS_PROC_EXE     1
#define MIPS_PROC_MAPS    2
#define MIPS_PROC_CMDLINE 3
#define MIPS_PROC_STAT    4
#define MIPS_PROC_AUXV    5

int      mips_proc_classify(const char *path);
int      mips_proc_open(mips32_ctx_t *ctx, int kind, int flags);
long     mips_proc_readlink(mips32_ctx_t *ctx, int kind, char *buf,
                            unsigned long bufsz);

static inline uint64_t mips_sc_ld64(const uint8_t *p, int be)
{
    uint32_t hi = mips_sc_ld32(be ? p : (p + 4), be);
    uint32_t lo = mips_sc_ld32(be ? (p + 4) : p, be);
    return ((uint64_t)hi << 32) | (uint64_t)lo;
}

/* Authoritative host -> MIPS O32 errno translation (arch/mips/include/uapi/asm/errno.h). */
static inline int32_t mips_errno_from_host(int host_errno)
{
    switch (host_errno) {
    case EAGAIN:
#if defined(EWOULDBLOCK) && EWOULDBLOCK != EAGAIN
    case EWOULDBLOCK:
#endif
        return 11;
    case ENOMSG:          return 35;
    case EIDRM:           return 36;
    case EDEADLK:         return 45;
    case ENOLCK:          return 46;
#ifdef ENOSTR
    case ENOSTR:          return 60;
#endif
#ifdef ENODATA
    case ENODATA:         return 61;
#endif
#ifdef ETIME
    case ETIME:           return 62;
#endif
#ifdef ENOSR
    case ENOSR:           return 63;
#endif
#ifdef ENOLINK
    case ENOLINK:         return 67;
#endif
#ifdef EPROTO
    case EPROTO:          return 71;
#endif
#ifdef EMULTIHOP
    case EMULTIHOP:       return 74;
#endif
    case EBADMSG:         return 77;
#ifdef ENAMETOOLONG
    case ENAMETOOLONG:    return 78;
#endif
    case EOVERFLOW:       return 79;
    case EILSEQ:          return 88;
    case ENOSYS:          return 89;
    case ELOOP:           return 90;
    case ENOTEMPTY:       return 93;
#ifdef EUSERS
    case EUSERS:          return 94;
#endif
    case ENOTSOCK:        return 95;
    case EDESTADDRREQ:    return 96;
    case EMSGSIZE:        return 97;
    case EPROTOTYPE:      return 98;
    case ENOPROTOOPT:     return 99;
    case EPROTONOSUPPORT: return 120;
#ifdef ESOCKTNOSUPPORT
    case ESOCKTNOSUPPORT: return 121;
#endif
    case EOPNOTSUPP:      return 122;
#if defined(ENOTSUP) && (!defined(EOPNOTSUPP) || ENOTSUP != EOPNOTSUPP)
    case ENOTSUP:         return 122;
#endif
#ifdef EPFNOSUPPORT
    case EPFNOSUPPORT:    return 123;
#endif
    case EAFNOSUPPORT:    return 124;
    case EADDRINUSE:      return 125;
    case EADDRNOTAVAIL:   return 126;
    case ENETDOWN:        return 127;
    case ENETUNREACH:     return 128;
    case ENETRESET:       return 129;
    case ECONNABORTED:    return 130;
    case ECONNRESET:      return 131;
    case ENOBUFS:         return 132;
    case EISCONN:         return 133;
    case ENOTCONN:        return 134;
#ifdef ESHUTDOWN
    case ESHUTDOWN:       return 143;
#endif
#ifdef ETOOMANYREFS
    case ETOOMANYREFS:    return 144;
#endif
    case ETIMEDOUT:       return 145;
    case ECONNREFUSED:    return 146;
#ifdef EHOSTDOWN
    case EHOSTDOWN:       return 147;
#endif
    case EHOSTUNREACH:    return 148;
    case EALREADY:        return 149;
    case EINPROGRESS:     return 150;
    case ESTALE:          return 151;
    case ECANCELED:       return 158;
#ifdef EOWNERDEAD
    case EOWNERDEAD:      return 165;
#endif
#ifdef ENOTRECOVERABLE
    case ENOTRECOVERABLE: return 166;
#endif
    case EDQUOT:          return 1133;
    default:
        return (int32_t)host_errno;
    }
}
/* Truncate payload (defined in src/vm/vm_file.c; wired here). */
int32_t mips32_file_sc_truncate(mips32_ctx_t *ctx, uint32_t sp,
                                uint32_t nr);
/* Sysroot-prefixed absolute loads (defined in src/vm/vm_file.c). */
int mips_sysroot_open(const mips32_ctx_t *ctx, int dirfd, const char *path,
                      int host_flags, mode_t mode);
int      mips_sc_read_ts(const mips32_ctx_t *ctx, uint32_t va,
                         struct timespec *out);
int      mips_sc_write_ts(mips32_ctx_t *ctx, uint32_t va,
                          const struct timespec *ts, int wide);
int      mips_sc_flags_to_host(uint32_t mips, int *host_out);

/* Handlers defined in syscalls_meta.c, except access/close_range which
 * live in syscalls.c (called from the dispatcher in syscalls.c). */
int32_t mips_sc_fcntl(mips32_ctx_t *ctx, uint32_t sp);
int32_t mips_sc_ioctl(mips32_ctx_t *ctx, uint32_t sp);
int32_t mips_sc_stat64(mips32_ctx_t *ctx, uint32_t sp, uint32_t nr);
int32_t mips_sc_statx(mips32_ctx_t *ctx, uint32_t sp);
int32_t mips_sc_getdents64(mips32_ctx_t *ctx, uint32_t sp);
int32_t mips_sc_readlinkat(mips32_ctx_t *ctx, uint32_t sp, int is_readlink);
int32_t mips_sc_access(mips32_ctx_t *ctx, uint32_t sp);
int32_t mips_sc_close_range(mips32_ctx_t *ctx, uint32_t sp);
int32_t mips_sc_nanosleep(mips32_ctx_t *ctx, uint32_t sp);
int32_t mips_sc_clock_gettime(mips32_ctx_t *ctx, uint32_t sp, int wide);
int32_t mips_sc_getrandom(mips32_ctx_t *ctx, uint32_t sp);
int32_t mips_sc_futex(mips32_ctx_t *ctx, uint32_t sp);
int32_t mips_sc_getxid(mips32_ctx_t *ctx, uint32_t nr);
int32_t mips_sc_robust(mips32_ctx_t *ctx, uint32_t sp, int is_set);
/* Kill-class delivery (defined in src/os/kill.c): kill/tkill/tgkill to
 * the calling thread complete with 0 in $v0/$a3, advance pc past the
 * trap, then redirect at the guest handler. The engine keeps the moved
 * pc (exec_syscall dispatcher-moved-pc contract); sigreturn restores
 * the post-syscall registers. */
int32_t mips_sc_kill(mips32_ctx_t *ctx, uint32_t sp);
/* Hosting thread id for --trace attribution (defined in threads.c):
 * the raw host gettid on Linux (fresh every call, so fork children
 * attribute correctly), getpid elsewhere. Harness-only; never affects
 * guest execution. */
long mips_trace_tid(void);
/* Explicit-code frame build + signal disposition/mask/pending helpers. */
int  mips_raise_guest_code(mips32_ctx_t *ctx, int signo, int32_t si_code,
                           uint32_t fault_addr);
int  mips_signal_is_ignored(int signo);
int  mips_signal_default_ignore(int signo);
int  mips_signal_default_stop(int signo);
void mips_signal_default_die(int signo);
int  mips_signal_is_blocked(const mips32_ctx_t *ctx, int signo);
int  mips_signal_pend(mips32_ctx_t *ctx, int signo, int32_t si_code);
void mips_signal_deliver_pending(mips32_ctx_t *ctx);
/* Pending-queue maintenance (defined in src/os/sigqueue.c). */
void mips_sig_purge_signo(mips32_ctx_t *ctx, int signo);

#endif /* MIPS32_SYSCALLS_PRIV_H */
