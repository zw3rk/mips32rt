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

#include <stddef.h>
#include <stdint.h>
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
/* Truncate payload (defined in src/vm/vm_file.c; wired here). */
int32_t mips32_file_sc_truncate(mips32_ctx_t *ctx, uint32_t sp,
                                uint32_t nr);
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

#endif /* MIPS32_SYSCALLS_PRIV_H */
