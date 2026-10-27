/*
 * src/os/syscalls_meta.c — Phase 2 syscall handlers, control/metadata/time
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Second half of lane L2a (split from src/os/syscalls.c only to honor
 * the 900-line file limit; shared constants and guest helpers live in
 * src/os/syscalls_priv.h; access/close_range stayed in syscalls.c for
 * balance): fcntl/fcntl64, ioctl (basic), the stat64 family (104-byte
 * MIPS layout), statx, getdents64, readlink/readlinkat, nanosleep,
 * clock_gettime(-64), getrandom, futex (single-threaded), the getxpid
 * identity family, rt_sigprocmask (accepted, not tracked) and
 * set/get_robust_list.  Unknown syscalls keep -ENOSYS with $a3=1 via
 * the dispatcher in syscalls.c.
 */

#if defined(__linux__)
#define _GNU_SOURCE
#endif

#include "mips32rt.h"

#include "os/syscall_nr.h"
#include "os/syscalls_priv.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#if defined(__linux__)
#include <sys/syscall.h>
#endif

/* ---- fcntl/fcntl64 (lock commands arrive with Phase 4; -ENOSYS now) ---- */

/* F_GETFL reports MIPS bits back to the guest. */
static uint32_t host_to_mips_flags(int host)
{
    uint32_t mips = 0U;

    switch (host & 3) {
    case O_WRONLY:
        mips |= 1U;
        break;
    case O_RDWR:
        mips |= 2U;
        break;
    default:
        break; /* O_RDONLY == 0 */
    }
    if ((host & O_APPEND) != 0) {
        mips |= MIPS_O_APPEND;
    }
    if ((host & O_DSYNC) != 0) {
        mips |= MIPS_O_DSYNC;
    }
    if ((host & O_NONBLOCK) != 0) {
        mips |= MIPS_O_NONBLOCK;
    }
#ifdef O_DIRECT
    if ((host & O_DIRECT) != 0) {
        mips |= MIPS_O_DIRECT;
    }
#endif
#ifdef O_DIRECTORY
    if ((host & O_DIRECTORY) != 0) {
        mips |= MIPS_O_DIRECTORY;
    }
#endif
#ifdef O_NOFOLLOW
    if ((host & O_NOFOLLOW) != 0) {
        mips |= MIPS_O_NOFOLLOW;
    }
#endif
#ifdef O_NOATIME
    if ((host & O_NOATIME) != 0) {
        mips |= MIPS_O_NOATIME;
    }
#endif
    return mips;
}

int32_t mips_sc_fcntl(mips32_ctx_t *ctx, uint32_t sp)
{
    int      ok = 1;
    uint32_t fd;
    uint32_t cmd;
    uint32_t arg;
    int      host_flags;
    int      r;

    fd  = mips_sc_arg(ctx, sp, 0, &ok);
    cmd = mips_sc_arg(ctx, sp, 1, &ok);
    arg = mips_sc_arg(ctx, sp, 2, &ok);
    if (!ok) {
        return mips_sc_ret(ctx, -EFAULT);
    }
    switch (cmd) {
    case (uint32_t)MIPS_F_DUPFD:
        r = fcntl((int)fd, F_DUPFD, (int)arg);
        break;
    case (uint32_t)MIPS_F_DUPFD_CLOEXEC:
#ifdef F_DUPFD_CLOEXEC
        r = fcntl((int)fd, F_DUPFD_CLOEXEC, (int)arg);
#else
        r = fcntl((int)fd, F_DUPFD, (int)arg);
        if (r >= 0 && fcntl(r, F_SETFD, FD_CLOEXEC) != 0) {
            int e = errno;

            (void)close(r);
            return mips_sc_ret(ctx, -(int32_t)e);
        }
#endif
        break;
    case (uint32_t)MIPS_F_GETFD:
        r = fcntl((int)fd, F_GETFD, 0);
        break;
    case (uint32_t)MIPS_F_SETFD:
        r = fcntl((int)fd, F_SETFD, (int)(arg & 1U));
        break;
    case (uint32_t)MIPS_F_GETFL:
        r = fcntl((int)fd, F_GETFL, 0);
        if (r >= 0) {
            r = (int)host_to_mips_flags(r);
        }
        break;
    case (uint32_t)MIPS_F_SETFL:
        if (mips_sc_flags_to_host(arg | 2U, &host_flags) != 0) {
            /* arg has no accmode bits; OR in O_RDWR so the
             * converter sees a valid mode while mapping flags. */
            return mips_sc_ret(ctx, -EINVAL);
        }
        host_flags &= ~(O_RDONLY | O_WRONLY | O_RDWR | O_CREAT | O_EXCL |
                        O_NOCTTY | O_TRUNC);
        r = fcntl((int)fd, F_SETFL, host_flags);
        break;
    default:
        return mips_sc_ret(ctx, -ENOSYS); /* F_GETLK/F_SETLK*: Phase 4 */
    }
    if (r < 0) {
        return mips_sc_ret(ctx, -(int32_t)errno);
    }
    return mips_sc_ret(ctx, (int32_t)r);
}

/* ---- ioctl (basic: FIONREAD + TIOCGWINSZ; everything else -ENOSYS) ---- */

int32_t mips_sc_ioctl(mips32_ctx_t *ctx, uint32_t sp)
{
    int      ok = 1;
    int      be;
    uint32_t fd;
    uint32_t req;
    uint32_t arg_va;

    fd     = mips_sc_arg(ctx, sp, 0, &ok);
    req    = mips_sc_arg(ctx, sp, 1, &ok);
    arg_va = mips_sc_arg(ctx, sp, 2, &ok);
    if (!ok) {
        return mips_sc_ret(ctx, -EFAULT);
    }
    be = mips_is_be(ctx);
    if (req == MIPS_FIONREAD) {
        uint8_t out[4];
        int     n = 0;

        if (ioctl((int)fd, FIONREAD, &n) != 0) {
            return mips_sc_ret(ctx, -(int32_t)errno);
        }
        mips_sc_st32(out, (uint32_t)n, be);
        if (mips_sc_copy_to(ctx, arg_va, out, 4U) != 0) {
            return mips_sc_ret(ctx, -EFAULT);
        }
        return mips_sc_ret(ctx, 0);
    }
    if (req == MIPS_TIOCGWINSZ) {
        uint8_t        out[8];
        struct winsize ws;

        memset(&ws, 0, sizeof(ws));
        if (ioctl((int)fd, TIOCGWINSZ, &ws) != 0) {
            return mips_sc_ret(ctx, -(int32_t)errno);
        }
        /* struct winsize is four u16 in the same order on every host. */
        mips_sc_st16(out, ws.ws_row, be);
        mips_sc_st16(out + 2, ws.ws_col, be);
        mips_sc_st16(out + 4, ws.ws_xpixel, be);
        mips_sc_st16(out + 6, ws.ws_ypixel, be);
        if (mips_sc_copy_to(ctx, arg_va, out, 8U) != 0) {
            return mips_sc_ret(ctx, -EFAULT);
        }
        return mips_sc_ret(ctx, 0);
    }
    return mips_sc_ret(ctx, -ENOSYS);
}

/* ---- stat64 family (MIPS 104-byte layout, SPEC 2.3) ----
 * asm/stat.h offsets: st_dev@0, st_ino@16, st_mode@24, st_nlink@28,
 * st_uid@32, st_gid@36, st_rdev@40, st_size@56, st_atime@64/68,
 * st_mtime@72/76, st_ctime@80/84, st_blksize@88, st_blocks@96. */

/* Nanosecond field name differs by host libc (st_atim on glibc/musl,
 * st_atimespec on macOS); seconds (st_atime/...) match everywhere. */
static long xstat_nsec(const struct stat *st, int which)
{
#if defined(__APPLE__)
    if (which == 0) {
        return (long)st->st_atimespec.tv_nsec;
    }
    if (which == 1) {
        return (long)st->st_mtimespec.tv_nsec;
    }
    return (long)st->st_ctimespec.tv_nsec;
#else
    if (which == 0) {
        return (long)st->st_atim.tv_nsec;
    }
    if (which == 1) {
        return (long)st->st_mtim.tv_nsec;
    }
    return (long)st->st_ctim.tv_nsec;
#endif
}

static int write_mips_stat64(mips32_ctx_t *ctx, uint32_t va,
                             const struct stat *st)
{
    uint8_t buf[MIPS_STAT64_SIZE];
    int     be = mips_is_be(ctx);

    memset(buf, 0, sizeof(buf));
    mips_sc_st32(buf + 0, (uint32_t)st->st_dev, be);
    mips_sc_st64(buf + 16, (uint64_t)st->st_ino, be);
    mips_sc_st32(buf + 24, (uint32_t)st->st_mode, be);
    mips_sc_st32(buf + 28, (uint32_t)st->st_nlink, be);
    mips_sc_st32(buf + 32, (uint32_t)st->st_uid, be);
    mips_sc_st32(buf + 36, (uint32_t)st->st_gid, be);
    mips_sc_st32(buf + 40, (uint32_t)st->st_rdev, be);
    mips_sc_st64(buf + 56, (uint64_t)(int64_t)st->st_size, be);
    mips_sc_st32(buf + 64, (uint32_t)(int32_t)st->st_atime, be);
    mips_sc_st32(buf + 68, (uint32_t)(int32_t)xstat_nsec(st, 0), be);
    mips_sc_st32(buf + 72, (uint32_t)(int32_t)st->st_mtime, be);
    mips_sc_st32(buf + 76, (uint32_t)(int32_t)xstat_nsec(st, 1), be);
    mips_sc_st32(buf + 80, (uint32_t)(int32_t)st->st_ctime, be);
    mips_sc_st32(buf + 84, (uint32_t)(int32_t)xstat_nsec(st, 2), be);
    mips_sc_st32(buf + 88, (uint32_t)(int32_t)st->st_blksize, be);
    mips_sc_st64(buf + 96, (uint64_t)(int64_t)st->st_blocks, be);
    if (mips_sc_copy_to(ctx, va, buf, MIPS_STAT64_SIZE) != 0) {
        return -EFAULT;
    }
    return 0;
}

int32_t mips_sc_stat64(mips32_ctx_t *ctx, uint32_t sp, uint32_t nr)
{
    char         path[MIPS_PATH_MAX];
    struct stat  st;
    int          ok = 1;
    uint32_t     a0;
    uint32_t     a1;
    uint32_t     a2;
    uint32_t     a3;
    int          rc;

    a0 = mips_sc_arg(ctx, sp, 0, &ok);
    a1 = mips_sc_arg(ctx, sp, 1, &ok);
    a2 = mips_sc_arg(ctx, sp, 2, &ok);
    a3 = mips_sc_arg(ctx, sp, 3, &ok);
    if (!ok) {
        return mips_sc_ret(ctx, -EFAULT);
    }
    if (nr == (uint32_t)MIPS32_NR_fstat64) {
        if (fstat((int)a0, &st) != 0) {
            return mips_sc_ret(ctx, -(int32_t)errno);
        }
        rc = write_mips_stat64(ctx, a1, &st);
        return mips_sc_ret(ctx, rc);
    }
    if (nr == (uint32_t)MIPS32_NR_fstatat64) {
        uint32_t flags = a3;

        rc = mips_sc_read_cstr(ctx, a1, path);
        if (rc != 0) {
            return mips_sc_ret(ctx, rc);
        }
        if ((flags & ~(uint32_t)MIPS_AT_SYMLINK_NOFOLLOW) != 0U) {
            return mips_sc_ret(ctx, -EINVAL);
        }
        if (fstatat((int)(int32_t)a0, path, &st,
                    (int)flags) != 0) {
            return mips_sc_ret(ctx, -(int32_t)errno);
        }
        rc = write_mips_stat64(ctx, a2, &st);
        return mips_sc_ret(ctx, rc);
    }
    rc = mips_sc_read_cstr(ctx, a0, path);
    if (rc != 0) {
        return mips_sc_ret(ctx, rc);
    }
    if (nr == (uint32_t)MIPS32_NR_lstat64) {
        rc = lstat(path, &st);
    } else {
        rc = stat(path, &st);
    }
    if (rc != 0) {
        return mips_sc_ret(ctx, -(int32_t)errno);
    }
    rc = write_mips_stat64(ctx, a1, &st);
    return mips_sc_ret(ctx, rc);
}

/* ---- statx (fixed-width UAPI layout; byte-swapped for BE guests) ---- */

#if defined(__linux__) && defined(SYS_statx)
#define MIPS_HAVE_STATX 1
/* Local mirror of struct statx (linux/stat.h); host is always LE here
 * so fields are read natively and serialized via xst for the guest. */
struct x_statx {
    uint32_t stx_mask;
    uint32_t stx_blksize;
    uint64_t stx_attributes;
    uint32_t stx_nlink;
    uint32_t stx_uid;
    uint32_t stx_gid;
    uint16_t stx_mode;
    uint16_t spare0;
    uint64_t stx_ino;
    uint64_t stx_size;
    uint64_t stx_blocks;
    uint64_t stx_attributes_mask;
    int64_t  atime_sec;
    uint32_t atime_nsec;
    uint32_t atime_pad;
    int64_t  btime_sec;
    uint32_t btime_nsec;
    uint32_t btime_pad;
    int64_t  ctime_sec;
    uint32_t ctime_nsec;
    uint32_t ctime_pad;
    int64_t  mtime_sec;
    uint32_t mtime_nsec;
    uint32_t mtime_pad;
    uint32_t stx_rdev_major;
    uint32_t stx_rdev_minor;
    uint32_t stx_dev_major;
    uint32_t stx_dev_minor;
    uint64_t stx_mnt_id;
    uint32_t stx_dio_mem_align;
    uint32_t stx_dio_offset_align;
    uint64_t spare3[12];
};
#endif

int32_t mips_sc_statx(mips32_ctx_t *ctx, uint32_t sp)
{
#if !defined(MIPS_HAVE_STATX)
    (void)ctx;
    (void)sp;
    return mips_sc_ret(ctx, -ENOSYS);
#else
    char          path[MIPS_PATH_MAX];
    struct x_statx xs;
    uint8_t       buf[MIPS_STATX_SIZE];
    int           be;
    int           ok = 1;
    uint32_t      dirfd;
    uint32_t      path_va;
    uint32_t      flags;
    uint32_t      mask;
    uint32_t      buf_va;
    long          r;

    dirfd   = mips_sc_arg(ctx, sp, 0, &ok);
    path_va = mips_sc_arg(ctx, sp, 1, &ok);
    flags   = mips_sc_arg(ctx, sp, 2, &ok);
    mask    = mips_sc_arg(ctx, sp, 3, &ok);
    buf_va  = mips_sc_arg(ctx, sp, 4, &ok);
    if (!ok) {
        return mips_sc_ret(ctx, -EFAULT);
    }
    if ((flags & ~(uint32_t)(MIPS_AT_SYMLINK_NOFOLLOW | MIPS_AT_EMPTY_PATH |
                             0x800U /* AT_NO_AUTOMOUNT */)) != 0U) {
        return mips_sc_ret(ctx, -EINVAL);
    }
    if (mips_sc_read_cstr(ctx, path_va, path) != 0) {
        return mips_sc_ret(ctx, -EFAULT);
    }
    memset(&xs, 0, sizeof(xs));
    r = syscall(SYS_statx, (int)(int32_t)dirfd, path, (int)flags,
                (unsigned int)mask, &xs);
    if (r != 0) {
        return mips_sc_ret(ctx, -(int32_t)errno);
    }
    /* Serialize the fixed-width UAPI layout (linux/stat.h offsets). */
    memset(buf, 0, sizeof(buf));
    be = mips_is_be(ctx);
    mips_sc_st32(buf + 0, xs.stx_mask, be);
    mips_sc_st32(buf + 4, xs.stx_blksize, be);
    mips_sc_st64(buf + 8, xs.stx_attributes, be);
    mips_sc_st32(buf + 16, xs.stx_nlink, be);
    mips_sc_st32(buf + 20, xs.stx_uid, be);
    mips_sc_st32(buf + 24, xs.stx_gid, be);
    mips_sc_st16(buf + 28, xs.stx_mode, be);
    mips_sc_st64(buf + 32, xs.stx_ino, be);
    mips_sc_st64(buf + 40, xs.stx_size, be);
    mips_sc_st64(buf + 48, xs.stx_blocks, be);
    mips_sc_st64(buf + 56, xs.stx_attributes_mask, be);
    mips_sc_st64(buf + 64, (uint64_t)xs.atime_sec, be);
    mips_sc_st32(buf + 72, xs.atime_nsec, be);
    mips_sc_st64(buf + 80, (uint64_t)xs.btime_sec, be);
    mips_sc_st32(buf + 88, xs.btime_nsec, be);
    mips_sc_st64(buf + 96, (uint64_t)xs.ctime_sec, be);
    mips_sc_st32(buf + 104, xs.ctime_nsec, be);
    mips_sc_st64(buf + 112, (uint64_t)xs.mtime_sec, be);
    mips_sc_st32(buf + 120, xs.mtime_nsec, be);
    mips_sc_st32(buf + 128, xs.stx_rdev_major, be);
    mips_sc_st32(buf + 132, xs.stx_rdev_minor, be);
    mips_sc_st32(buf + 136, xs.stx_dev_major, be);
    mips_sc_st32(buf + 140, xs.stx_dev_minor, be);
    mips_sc_st64(buf + 144, xs.stx_mnt_id, be);
    mips_sc_st32(buf + 152, xs.stx_dio_mem_align, be);
    mips_sc_st32(buf + 156, xs.stx_dio_offset_align, be);
    if (mips_sc_copy_to(ctx, buf_va, buf, MIPS_STATX_SIZE) != 0) {
        return mips_sc_ret(ctx, -EFAULT);
    }
    return mips_sc_ret(ctx, 0);
#endif
}

/* ---- getdents64 (linux_dirent64 is arch-independent: direct fill) ---- */

int32_t mips_sc_getdents64(mips32_ctx_t *ctx, uint32_t sp)
{
#if defined(__linux__) && defined(SYS_getdents64)
    int      ok = 1;
    uint32_t fd;
    uint32_t dirp;
    uint32_t count;
    long     n;

    fd    = mips_sc_arg(ctx, sp, 0, &ok);
    dirp  = mips_sc_arg(ctx, sp, 1, &ok);
    count = mips_sc_arg(ctx, sp, 2, &ok);
    if (!ok) {
        return mips_sc_ret(ctx, -EFAULT);
    }
    if (!mips_sc_range_ok(ctx, dirp, count,
                   (uint32_t)PROT_WRITE) && count > 0U) {
        return mips_sc_ret(ctx, -EFAULT);
    }
    n = syscall(SYS_getdents64, (int)fd,
                count == 0U ? NULL : mips32_guest_ptr(ctx, dirp),
                (size_t)count);
    if (n < 0) {
        return mips_sc_ret(ctx, -(int32_t)errno);
    }
    if (n > (long)0x7FFFFFFFL) {
        n = (long)0x7FFFFFFFL;
    }
    return mips_sc_ret(ctx, (int32_t)n);
#else
    (void)ctx;
    (void)sp;
    return mips_sc_ret(ctx, -ENOSYS);
#endif
}

/* ---- readlink/readlinkat ---- */

int32_t mips_sc_readlinkat(mips32_ctx_t *ctx, uint32_t sp, int is_readlink)
{
    char     path[MIPS_PATH_MAX];
    char     host_buf[MIPS_PATH_MAX];
    int      ok = 1;
    uint32_t dirfd;
    uint32_t path_va;
    uint32_t buf_va;
    uint32_t bufsiz;
    ssize_t  n;

    if (is_readlink) {
        dirfd   = (uint32_t)MIPS_AT_FDCWD;
        path_va = mips_sc_arg(ctx, sp, 0, &ok);
        buf_va  = mips_sc_arg(ctx, sp, 1, &ok);
        bufsiz  = mips_sc_arg(ctx, sp, 2, &ok);
    } else {
        dirfd   = mips_sc_arg(ctx, sp, 0, &ok);
        path_va = mips_sc_arg(ctx, sp, 1, &ok);
        buf_va  = mips_sc_arg(ctx, sp, 2, &ok);
        bufsiz  = mips_sc_arg(ctx, sp, 3, &ok);
    }
    if (!ok) {
        return mips_sc_ret(ctx, -EFAULT);
    }
    if (bufsiz == 0U || bufsiz > MIPS_PATH_MAX) {
        return mips_sc_ret(ctx, -EINVAL);
    }
    if (mips_sc_read_cstr(ctx, path_va, path) != 0) {
        return mips_sc_ret(ctx, -EFAULT);
    }
    if (!mips_sc_range_ok(ctx, buf_va, bufsiz, (uint32_t)PROT_WRITE)) {
        return mips_sc_ret(ctx, -EFAULT);
    }
    n = readlinkat((int)(int32_t)dirfd, path, host_buf, (size_t)bufsiz);
    if (n < 0) {
        return mips_sc_ret(ctx, -(int32_t)errno);
    }
    if (mips_sc_copy_to(ctx, buf_va, host_buf, (uint32_t)n) != 0) {
        return mips_sc_ret(ctx, -EFAULT);
    }
    return mips_sc_ret(ctx, (int32_t)n);
}

/* ---- nanosleep / clock_gettime(-64) (guest timespec: s32 sec + s32 nsec) ---- */

int mips_sc_read_ts(const mips32_ctx_t *ctx, uint32_t va,
                          struct timespec *out)
{
    uint8_t b[8];

    if (mips_sc_copy_from(ctx, b, va, 8U) != 0) {
        return -EFAULT;
    }
    out->tv_sec  = (time_t)(int32_t)mips_sc_ld32(b, mips_is_be(ctx));
    out->tv_nsec = (long)(int32_t)mips_sc_ld32(b + 4, mips_is_be(ctx));
    return 0;
}

int mips_sc_write_ts(mips32_ctx_t *ctx, uint32_t va,
                           const struct timespec *ts, int wide)
{
    uint8_t b[16];
    int     be = mips_is_be(ctx);

    if (wide) {
        mips_sc_st64(b, (uint64_t)(int64_t)ts->tv_sec, be);
        mips_sc_st64(b + 8, (uint64_t)(int64_t)ts->tv_nsec, be);
        return mips_sc_copy_to(ctx, va, b, 16U);
    }
    mips_sc_st32(b, (uint32_t)(int32_t)ts->tv_sec, be);
    mips_sc_st32(b + 4, (uint32_t)(int32_t)ts->tv_nsec, be);
    return mips_sc_copy_to(ctx, va, b, 8U);
}

int32_t mips_sc_nanosleep(mips32_ctx_t *ctx, uint32_t sp)
{
    struct timespec req;
    struct timespec rem;
    int             ok = 1;
    uint32_t        req_va;
    uint32_t        rem_va;

    req_va = mips_sc_arg(ctx, sp, 0, &ok);
    rem_va = mips_sc_arg(ctx, sp, 1, &ok);
    if (!ok) {
        return mips_sc_ret(ctx, -EFAULT);
    }
    if (mips_sc_read_ts(ctx, req_va, &req) != 0) {
        return mips_sc_ret(ctx, -EFAULT);
    }
    if (req.tv_sec < 0 || req.tv_nsec < 0 || req.tv_nsec >= 1000000000L) {
        return mips_sc_ret(ctx, -EINVAL);
    }
    if (nanosleep(&req, &rem) != 0) {
        if (errno == EINTR && rem_va != 0U) {
            if (mips_sc_write_ts(ctx, rem_va, &rem, 0) != 0) {
                return mips_sc_ret(ctx, -EFAULT);
            }
        }
        return mips_sc_ret(ctx, -(int32_t)errno);
    }
    return mips_sc_ret(ctx, 0);
}

int32_t mips_sc_clock_gettime(mips32_ctx_t *ctx, uint32_t sp, int wide)
{
    struct timespec ts;
    int             ok = 1;
    uint32_t        clk;
    uint32_t        ts_va;
    clockid_t       host_clk;

    clk   = mips_sc_arg(ctx, sp, 0, &ok);
    ts_va = mips_sc_arg(ctx, sp, 1, &ok);
    if (!ok) {
        return mips_sc_ret(ctx, -EFAULT);
    }
#ifdef __APPLE__
    switch (clk) {
    case 0U:
    case 5U:
        host_clk = CLOCK_REALTIME;
        break;
    case 1U:
    case 6U:
    case 7U:
        host_clk = CLOCK_MONOTONIC;
        break;
    case 2U:
        host_clk = CLOCK_PROCESS_CPUTIME_ID;
        break;
    case 3U:
        host_clk = CLOCK_THREAD_CPUTIME_ID;
        break;
    case 4U:
        host_clk = CLOCK_MONOTONIC_RAW;
        break;
    default:
        return mips_sc_ret(ctx, -EINVAL);
    }
#else
    host_clk = (clockid_t)clk;
#endif
    if (clock_gettime(host_clk, &ts) != 0) {
        return mips_sc_ret(ctx, -(int32_t)errno);
    }
    if (mips_sc_write_ts(ctx, ts_va, &ts, wide) != 0) {
        return mips_sc_ret(ctx, -EFAULT);
    }
    return mips_sc_ret(ctx, 0);
}

/* ---- getrandom (Linux only; -ENOSYS elsewhere) ---- */

int32_t mips_sc_getrandom(mips32_ctx_t *ctx, uint32_t sp)
{
#if defined(__linux__) && defined(SYS_getrandom)
    int      ok = 1;
    uint32_t buf_va;
    uint32_t buflen;
    uint32_t flags;
    long     n;

    buf_va = mips_sc_arg(ctx, sp, 0, &ok);
    buflen = mips_sc_arg(ctx, sp, 1, &ok);
    flags  = mips_sc_arg(ctx, sp, 2, &ok);
    if (!ok) {
        return mips_sc_ret(ctx, -EFAULT);
    }
    if ((flags & ~(MIPS_GRND_NONBLOCK | MIPS_GRND_RANDOM)) != 0U) {
        return mips_sc_ret(ctx, -EINVAL);
    }
    if (buflen > 0U &&
        !mips_sc_range_ok(ctx, buf_va, buflen, (uint32_t)PROT_WRITE)) {
        return mips_sc_ret(ctx, -EFAULT);
    }
    n = syscall(SYS_getrandom,
                buflen == 0U ? NULL : mips32_guest_ptr(ctx, buf_va),
                (size_t)buflen, (unsigned int)flags);
    if (n < 0) {
        return mips_sc_ret(ctx, -(int32_t)errno);
    }
    if (n > (long)0x7FFFFFFFL) {
        n = (long)0x7FFFFFFFL;
    }
    return mips_sc_ret(ctx, (int32_t)n);
#else
    (void)ctx;
    (void)sp;
    return mips_sc_ret(ctx, -ENOSYS);
#endif
}

/* ---- futex (single-threaded: WAIT/WAKE via the host futex) ---- */

int32_t mips_sc_futex(mips32_ctx_t *ctx, uint32_t sp)
{
#if defined(__linux__) && defined(SYS_futex)
    uint8_t        cur[4];
    struct timespec to;
    int            be;
    int            ok = 1;
    uint32_t       uaddr;
    uint32_t       op;
    uint32_t       val;
    uint32_t       timeout_va;
    long           r;

    uaddr      = mips_sc_arg(ctx, sp, 0, &ok);
    op         = mips_sc_arg(ctx, sp, 1, &ok);
    val        = mips_sc_arg(ctx, sp, 2, &ok);
    timeout_va = mips_sc_arg(ctx, sp, 3, &ok);
    if (!ok) {
        return mips_sc_ret(ctx, -EFAULT);
    }
    be = mips_is_be(ctx);
    switch (op & ~(uint32_t)MIPS_FUTEX_PRIVATE_FLAG) {
    case (uint32_t)MIPS_FUTEX_WAIT:
        if (mips_sc_copy_from(ctx, cur, uaddr, 4U) != 0) {
            return mips_sc_ret(ctx, -EFAULT);
        }
        if (mips_sc_ld32(cur, be) != val) {
            return mips_sc_ret(ctx, -EAGAIN);
        }
        if (timeout_va != 0U) {
            if (mips_sc_read_ts(ctx, timeout_va, &to) != 0) {
                return mips_sc_ret(ctx, -EFAULT);
            }
            if (to.tv_sec < 0 || to.tv_nsec < 0 ||
                to.tv_nsec >= 1000000000L) {
                return mips_sc_ret(ctx, -EINVAL);
            }
        }
        r = syscall(SYS_futex, mips32_guest_ptr(ctx, uaddr),
                    (int)(op & (uint32_t)MIPS_FUTEX_PRIVATE_FLAG),
                    (uint32_t)val, timeout_va == 0U ? NULL : &to,
                    NULL, 0);
        break;
    case (uint32_t)MIPS_FUTEX_WAKE:
        r = syscall(SYS_futex, mips32_guest_ptr(ctx, uaddr),
                    (int)((op & (uint32_t)MIPS_FUTEX_PRIVATE_FLAG) |
                          (uint32_t)MIPS_FUTEX_WAKE),
                    (uint32_t)val, NULL, NULL, 0);
        if (!mips_sc_range_ok(ctx, uaddr, 4U, (uint32_t)PROT_READ)) {
            return mips_sc_ret(ctx, -EFAULT);
        }
        break;
    default:
        return mips_sc_ret(ctx, -ENOSYS);
    }
    if (r < 0) {
        return mips_sc_ret(ctx, -(int32_t)errno);
    }
    if (r > (long)0x7FFFFFFFL) {
        r = (long)0x7FFFFFFFL;
    }
    return mips_sc_ret(ctx, (int32_t)r);
#else
    (void)ctx;
    (void)sp;
    return mips_sc_ret(ctx, -ENOSYS);
#endif
}

/* ---- identity family ---- */

int32_t mips_sc_getxid(mips32_ctx_t *ctx, uint32_t nr)
{
    uint32_t v = 0U;

    switch (nr) {
    case (uint32_t)MIPS32_NR_getpid:
        v = (uint32_t)getpid();
        break;
    case (uint32_t)MIPS32_NR_getppid:
        v = (uint32_t)getppid();
        break;
    case (uint32_t)MIPS32_NR_getuid:
        v = (uint32_t)getuid();
        break;
    case (uint32_t)MIPS32_NR_geteuid:
        v = (uint32_t)geteuid();
        break;
    case (uint32_t)MIPS32_NR_getgid:
        v = (uint32_t)getgid();
        break;
    case (uint32_t)MIPS32_NR_getegid:
        v = (uint32_t)getegid();
        break;
    default:
        return mips_sc_ret(ctx, -ENOSYS);
    }
    return mips_sc_ret(ctx, (int32_t)v);
}

/* ---- rt_sigprocmask / rt_sigaction (Phase 4, lane L4a) ----
 * The Phase-2 accept-and-ignore stub is retired: the dispatcher routes
 * both calls to the guest-owned 128-bit tables in src/os/signals.c
 * (mips_l4a_rt_sigprocmask / mips_sc_rt_sigaction). */

/* ---- set/get_robust_list (recorded in ctx; woken by Phase 4) ---- */

int32_t mips_sc_robust(mips32_ctx_t *ctx, uint32_t sp, int is_set)
{
    int      be;
    int      ok = 1;
    uint8_t  buf[8];
    uint32_t a0;
    uint32_t a1;
    uint32_t a2;

    a0 = mips_sc_arg(ctx, sp, 0, &ok);
    a1 = mips_sc_arg(ctx, sp, 1, &ok);
    a2 = mips_sc_arg(ctx, sp, 2, &ok);
    if (!ok) {
        return mips_sc_ret(ctx, -EFAULT);
    }
    be = mips_is_be(ctx);
    if (is_set) {
        /* len must equal the O32 head size (3 user pointers = 12). */
        if (a1 != 12U) {
            return mips_sc_ret(ctx, -EINVAL);
        }
        ctx->robust_list_head = a0;
        ctx->robust_list_len  = a1;
        (void)a2;
        return mips_sc_ret(ctx, 0);
    }
    /* get_robust_list(pid, &head, &len): only the current thread exists. */
    if (a0 != 0U) {
        return mips_sc_ret(ctx, -ESRCH);
    }
    mips_sc_st32(buf, ctx->robust_list_head, be);
    mips_sc_st32(buf + 4, ctx->robust_list_len, be);
    if (mips_sc_copy_to(ctx, a1, buf, 4U) != 0 ||
        mips_sc_copy_to(ctx, a2, buf + 4, 4U) != 0) {
        return mips_sc_ret(ctx, -EFAULT);
    }
    return mips_sc_ret(ctx, 0);
}
