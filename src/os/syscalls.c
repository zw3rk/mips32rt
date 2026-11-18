/*
 * src/os/syscalls.c — O32 syscall layer.
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

#if defined(__linux__)
#define _GNU_SOURCE
#endif

#include "mips32rt.h"

#include "os/syscall_nr.h"
#include "os/syscalls_priv.h"
#include "rt32/rt32.h"
#include "rt32/vm_priv.h"

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

#if defined(__linux__)
#include <sys/syscall.h>
#endif

/* Phase 4 thread layer (src/os/threads.c, lane L4b): full futex ops. */
int32_t mips_sc_futex_thread(mips32_ctx_t *ctx, uint32_t sp);


int32_t mips_sc_ret(mips32_ctx_t *ctx, int32_t raw)
{
    if (raw < 0) {
        ctx->gpr[MIPS32_REG_V0] = (uint32_t)mips_errno_from_host(-raw);
        ctx->gpr[MIPS32_REG_A3] = 1U;
    } else {
        ctx->gpr[MIPS32_REG_V0] = (uint32_t)raw;
        ctx->gpr[MIPS32_REG_A3] = 0U;
    }
    return raw;
}

void mips_sc_advance_pc_once(mips32_ctx_t *ctx)
{
    if (ctx != NULL && ctx->sc_pc_advanced == 0U) {
        /* M32-R7-2: a slot syscall resumes at the branch target, so a
         * frame built during delivery saves the destination EPC. */
        if (ctx->in_delay_slot != 0U) {
            ctx->pc = ctx->delay_target;
        } else {
            ctx->pc += 4U;
        }
        ctx->next_pc = ctx->pc + 4U;
        ctx->in_delay_slot = 0U;
        ctx->sc_pc_advanced = 1U;
    }
}

int mips_sc_range_ok(const mips32_ctx_t *ctx, uint32_t va, uint32_t len,
                     uint32_t need)
{
    return mips32_range_ok(ctx, va, len, need);
}

int mips_sc_copy_from(const mips32_ctx_t *ctx, void *dst, uint32_t va,
                      uint32_t len)
{
    return rt32_vm_copy_from(ctx, dst, va, len);
}

int mips_sc_copy_to(mips32_ctx_t *ctx, uint32_t va, const void *src,
                    uint32_t len)
{
    return rt32_vm_copy_to(ctx, va, src, len);
}

uint32_t mips_sc_ld32(const uint8_t *p, int be);
void mips_sc_st32(uint8_t *p, uint32_t v, int be);

uint32_t mips_sc_arg(mips32_ctx_t *ctx, uint32_t sp, unsigned i, int *ok)
{
    uint32_t va;
    uint32_t val = 0U;

    if (i < 4U) {
        *ok = 1;
        return ctx->gpr[MIPS32_REG_A0 + i];
    }
    {
        uint8_t b[4];

        va = sp + 16U + 4U * (i - 4U);
        if ((va & 3U) != 0U || mips_sc_copy_from(ctx, b, va, 4U) != 0) {
            *ok = 0;
            return 0U;
        }
        val = mips_sc_ld32(b, mips_is_be(ctx));
    }
    *ok = 1;
    return val;
}

uint32_t mips_sc_ld32(const uint8_t *p, int be)
{
    if (be) {
        return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
               ((uint32_t)p[2] << 8) | (uint32_t)p[3];
    }
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

void mips_sc_st16(uint8_t *p, uint16_t v, int be)
{
    if (be) {
        p[0] = (uint8_t)(v >> 8);
        p[1] = (uint8_t)v;
    } else {
        p[0] = (uint8_t)v;
        p[1] = (uint8_t)(v >> 8);
    }
}

void mips_sc_st32(uint8_t *p, uint32_t v, int be)
{
    if (be) {
        p[0] = (uint8_t)(v >> 24);
        p[1] = (uint8_t)(v >> 16);
        p[2] = (uint8_t)(v >> 8);
        p[3] = (uint8_t)v;
    } else {
        p[0] = (uint8_t)v;
        p[1] = (uint8_t)(v >> 8);
        p[2] = (uint8_t)(v >> 16);
        p[3] = (uint8_t)(v >> 24);
    }
}

void mips_sc_st64(uint8_t *p, uint64_t v, int be)
{
    if (be) {
        mips_sc_st32(p, (uint32_t)(v >> 32), 1);
        mips_sc_st32(p + 4, (uint32_t)v, 1);
    } else {
        mips_sc_st32(p, (uint32_t)v, 0);
        mips_sc_st32(p + 4, (uint32_t)(v >> 32), 0);
    }
}

int mips_sc_read_cstr(const mips32_ctx_t *ctx, uint32_t va, char *host_buf)
{
    uint32_t i;

    for (i = 0; i < MIPS_PATH_MAX; i++) {
        uint8_t b = 0U;

        if (mips_sc_copy_from(ctx, &b, va + i, 1U) != 0) {
            return -EFAULT;
        }
        host_buf[i] = (char)b;
        if (b == 0U) {
            return 0;
        }
    }
    return -ENAMETOOLONG;
}

int mips_sc_flags_to_host(uint32_t mips, int *host_out)
{
    int host = 0;

    switch (mips & 3U) {
    case 0U:
        host |= O_RDONLY;
        break;
    case 1U:
        host |= O_WRONLY;
        break;
    case 2U:
        host |= O_RDWR;
        break;
    default:
        return -EINVAL; /* O_ACCMODE 3 is invalid */
    }
    if ((mips & MIPS_O_APPEND) != 0U) {
        host |= O_APPEND;
    }
    if ((mips & MIPS_O_DSYNC) != 0U) {
        host |= O_DSYNC;
    }
    if ((mips & MIPS_O_NONBLOCK) != 0U) {
        host |= O_NONBLOCK;
    }
    if ((mips & MIPS_O_CREAT) != 0U) {
        host |= O_CREAT;
    }
    if ((mips & MIPS_O_TRUNC) != 0U) {
        host |= O_TRUNC;
    }
    if ((mips & MIPS_O_EXCL) != 0U) {
        host |= O_EXCL;
    }
    if ((mips & MIPS_O_NOCTTY) != 0U) {
        host |= O_NOCTTY;
    }
#ifdef O_LARGEFILE
    if ((mips & MIPS_O_LARGEFILE) != 0U) {
        host |= O_LARGEFILE;
    }
#else
#endif
    if ((mips & MIPS___O_SYNC) != 0U) {
        host |= O_SYNC;
    }
#ifdef O_DIRECT
    if ((mips & MIPS_O_DIRECT) != 0U) {
        host |= O_DIRECT;
    }
#else
    if ((mips & MIPS_O_DIRECT) != 0U) {
        return -EINVAL;
    }
#endif
#ifdef O_DIRECTORY
    if ((mips & MIPS_O_DIRECTORY) != 0U) {
        host |= O_DIRECTORY;
    }
#else
    if ((mips & MIPS_O_DIRECTORY) != 0U) {
        return -EINVAL;
    }
#endif
#ifdef O_NOFOLLOW
    if ((mips & MIPS_O_NOFOLLOW) != 0U) {
        host |= O_NOFOLLOW;
    }
#else
    if ((mips & MIPS_O_NOFOLLOW) != 0U) {
        return -EINVAL;
    }
#endif
#ifdef O_NOATIME
    if ((mips & MIPS_O_NOATIME) != 0U) {
        host |= O_NOATIME;
    }
#else
    if ((mips & MIPS_O_NOATIME) != 0U) {
        return -EINVAL;
    }
#endif
#ifdef O_CLOEXEC
    if ((mips & MIPS_O_CLOEXEC) != 0U) {
        host |= O_CLOEXEC;
    }
#else
    if ((mips & MIPS_O_CLOEXEC) != 0U) {
        return -EINVAL;
    }
#endif
#ifdef O_PATH
    if ((mips & MIPS_O_PATH) != 0U) {
        host |= O_PATH;
    }
#else
    if ((mips & MIPS_O_PATH) != 0U) {
        return -EINVAL;
    }
#endif
    if ((mips & ~(3U | MIPS_O_APPEND | MIPS_O_DSYNC | MIPS_O_NONBLOCK |
                  MIPS_O_CREAT | MIPS_O_TRUNC | MIPS_O_EXCL |
                  MIPS_O_NOCTTY | MIPS_O_LARGEFILE | MIPS_O_SYNC |
                  MIPS_O_DIRECT | MIPS_O_DIRECTORY | MIPS_O_NOFOLLOW |
                  MIPS_O_NOATIME | MIPS_O_CLOEXEC | MIPS_O_PATH)) != 0U) {
        return -EINVAL;
    }
    *host_out = host;
    return 0;
}

static int32_t sc_openat(mips32_ctx_t *ctx, uint32_t sp, int is_open)
{
    char     path[MIPS_PATH_MAX];
    int      ok = 1;
    int      host_flags;
    uint32_t dirfd;
    uint32_t path_va;
    uint32_t mips_flags;
    uint32_t mode;
    int      fd;
    int      rc;

    dirfd      = (is_open != 0) ? (uint32_t)(int32_t)MIPS_AT_FDCWD
                               : mips_sc_arg(ctx, sp, 0, &ok);
    path_va    = mips_sc_arg(ctx, sp, (unsigned)(is_open != 0 ? 0 : 1), &ok);
    mips_flags = mips_sc_arg(ctx, sp, (unsigned)(is_open != 0 ? 1 : 2), &ok);
    mode       = mips_sc_arg(ctx, sp, (unsigned)(is_open != 0 ? 2 : 3), &ok);
    if (!ok) {
        return mips_sc_ret(ctx, -EFAULT);
    }
    rc = mips_sc_read_cstr(ctx, path_va, path);
    if (rc != 0) {
        return mips_sc_ret(ctx, rc);
    }
    if (mips_sc_flags_to_host(mips_flags, &host_flags) != 0) {
        return mips_sc_ret(ctx, -EINVAL);
    }
    {
        int pkind = mips_proc_classify(path);
        if (pkind != 0) {
            fd = mips_proc_open(ctx, pkind, host_flags);
            return mips_sc_ret(ctx, (int32_t)fd);
        }
    }
    fd = mips_sysroot_open(ctx, (int)(int32_t)dirfd, path, host_flags,
        (mode_t)(mode & 07777U));
    if (fd < 0) {
        fd = openat((int)(int32_t)dirfd, path, host_flags,
            (mode_t)(mode & 07777U));
    }
    if (fd < 0) {
        return mips_sc_ret(ctx, -(int32_t)errno);
    }
    return mips_sc_ret(ctx, (int32_t)fd);
}

static int32_t sc_unlinkat(mips32_ctx_t *ctx, uint32_t sp, int is_unlink)
{
    char     path[MIPS_PATH_MAX];
    char     hpath[MIPS_PATH_MAX];
    int      ok = 1;
    uint32_t dirfd;
    uint32_t path_va;
    uint32_t flags;
    int      rc;

    dirfd  = (is_unlink != 0) ? (uint32_t)(int32_t)MIPS_AT_FDCWD
                             : mips_sc_arg(ctx, sp, 0, &ok);
    path_va = mips_sc_arg(ctx, sp, (unsigned)(is_unlink != 0 ? 0 : 1), &ok);
    flags   = (is_unlink != 0) ? 0U : mips_sc_arg(ctx, sp, 2, &ok);
    if (!ok) {
        return mips_sc_ret(ctx, -EFAULT);
    }
    rc = mips_sc_read_cstr(ctx, path_va, path);
    if (rc != 0) {
        return mips_sc_ret(ctx, rc);
    }
    rc = mips_sysroot_resolve(ctx, path, hpath);
    if (rc != 0) {
        return mips_sc_ret(ctx, rc);
    }
    if ((flags & (uint32_t)MIPS_AT_REMOVEDIR) != 0U) {
        /* The dirfd must travel with the name: coreutils rm unlinks
         * children dirfd-relative (openat O_DIRECTORY + unlinkat), so
         * a bare rmdir(name) resolves against the wrong directory and a
         * recursive rm -rf fails with ENOENT. */
        rc = unlinkat((int)(int32_t)dirfd, hpath, AT_REMOVEDIR);
        if (rc != 0 && mips_sysroot_fallback(ctx, path, errno)) {
            rc = unlinkat((int)(int32_t)dirfd, path, AT_REMOVEDIR);
        }
    } else if (flags == 0U) {
        if (is_unlink != 0) {
            rc = unlink(hpath);
            if (rc != 0 && mips_sysroot_fallback(ctx, path, errno)) {
                rc = unlink(path);
            }
        } else {
            rc = unlinkat((int)(int32_t)dirfd, hpath, 0);
            if (rc != 0 && mips_sysroot_fallback(ctx, path, errno)) {
                rc = unlinkat((int)(int32_t)dirfd, path, 0);
            }
        }
    } else {
        return mips_sc_ret(ctx, -EINVAL);
    }
    if (rc != 0) {
        return mips_sc_ret(ctx, -(int32_t)errno);
    }
    return mips_sc_ret(ctx, 0);
}

static int32_t sc_close(mips32_ctx_t *ctx, uint32_t sp)
{
    int      ok = 1;
    uint32_t fd = mips_sc_arg(ctx, sp, 0, &ok);

    if (!ok) {
        return mips_sc_ret(ctx, -EFAULT);
    }
    if (close((int)fd) != 0) {
        return mips_sc_ret(ctx, -(int32_t)errno);
    }
    return mips_sc_ret(ctx, 0);
}

static int32_t sc_lseek(mips32_ctx_t *ctx, uint32_t sp)
{
    int      ok = 1;
    uint32_t fd;
    int32_t  off;
    uint32_t whence;
    off_t    res;

    fd     = mips_sc_arg(ctx, sp, 0, &ok);
    off    = (int32_t)mips_sc_arg(ctx, sp, 1, &ok);
    whence = mips_sc_arg(ctx, sp, 2, &ok);
    if (!ok) {
        return mips_sc_ret(ctx, -EFAULT);
    }
    if (whence > 2U) {
        return mips_sc_ret(ctx, -EINVAL);
    }
    res = lseek((int)fd, (off_t)off, (int)whence);
    if (res < 0) {
        return mips_sc_ret(ctx, -(int32_t)errno);
    }
    if (res > (off_t)0x7FFFFFFFL) {
        return mips_sc_ret(ctx, -EOVERFLOW);
    }
    return mips_sc_ret(ctx, (int32_t)res);
}

static int32_t sc_llseek(mips32_ctx_t *ctx, uint32_t sp)
{
    int      ok = 1;
    int      be;
    uint8_t  out[8];
    uint32_t fd;
    uint32_t hi;
    uint32_t lo;
    uint32_t res_va;
    uint32_t whence;
    uint64_t off;
    off_t    res;

    fd      = mips_sc_arg(ctx, sp, 0, &ok);
    hi      = mips_sc_arg(ctx, sp, 1, &ok);
    lo      = mips_sc_arg(ctx, sp, 2, &ok);
    res_va  = mips_sc_arg(ctx, sp, 3, &ok);
    whence  = mips_sc_arg(ctx, sp, 4, &ok);
    if (!ok) {
        return mips_sc_ret(ctx, -EFAULT);
    }
    if (whence > 2U) {
        return mips_sc_ret(ctx, -EINVAL);
    }
    off = ((uint64_t)hi << 32) | (uint64_t)lo;
    res = lseek((int)fd, (off_t)(int64_t)off, (int)whence);
    if (res < 0) {
        return mips_sc_ret(ctx, -(int32_t)errno);
    }
    be = mips_is_be(ctx);
    mips_sc_st64(out, (uint64_t)(int64_t)res, be);
    if (mips_sc_copy_to(ctx, res_va, out, 8U) != 0) {
        return mips_sc_ret(ctx, -EFAULT);
    }
    return mips_sc_ret(ctx, 0);
}

static int32_t sc_dup(mips32_ctx_t *ctx, uint32_t sp)
{
    int      ok = 1;
    uint32_t fd = mips_sc_arg(ctx, sp, 0, &ok);
    int      nfd;

    if (!ok) {
        return mips_sc_ret(ctx, -EFAULT);
    }
    nfd = dup((int)fd);
    if (nfd < 0) {
        return mips_sc_ret(ctx, -(int32_t)errno);
    }
    return mips_sc_ret(ctx, (int32_t)nfd);
}

static int32_t sc_dup2(mips32_ctx_t *ctx, uint32_t sp, int is_dup3)
{
    int      ok = 1;
    uint32_t oldfd;
    uint32_t newfd;
    uint32_t flags;
    int      nfd;

    oldfd = mips_sc_arg(ctx, sp, 0, &ok);
    newfd = mips_sc_arg(ctx, sp, 1, &ok);
    flags = is_dup3 ? mips_sc_arg(ctx, sp, 2, &ok) : 0U;
    if (!ok) {
        return mips_sc_ret(ctx, -EFAULT);
    }
    if (is_dup3) {
        if (oldfd == newfd) {
            return mips_sc_ret(ctx, -EINVAL);
        }
        if ((flags & ~MIPS_O_CLOEXEC) != 0U) {
            return mips_sc_ret(ctx, -EINVAL);
        }
    }
    nfd = dup2((int)oldfd, (int)newfd);
    if (nfd < 0) {
        return mips_sc_ret(ctx, -(int32_t)errno);
    }
    if (is_dup3 && (flags & MIPS_O_CLOEXEC) != 0U) {
        if (fcntl(nfd, F_SETFD, FD_CLOEXEC) != 0) {
            return mips_sc_ret(ctx, -(int32_t)errno);
        }
    }
    return mips_sc_ret(ctx, (int32_t)nfd);
}

static int32_t sc_pipe(mips32_ctx_t *ctx, uint32_t sp, int is_pipe2)
{
    int      ok = 1;
    uint32_t fds_va = 0U;
    uint32_t flags = 0U;
    int      fds[2];
    int      i;

    if (is_pipe2) {
        fds_va = mips_sc_arg(ctx, sp, 0, &ok);
        flags = mips_sc_arg(ctx, sp, 1, &ok);
    }
    if (!ok) {
        return mips_sc_ret(ctx, -EFAULT);
    }
    if (is_pipe2 && (flags & ~(MIPS_O_CLOEXEC | MIPS_O_NONBLOCK)) != 0U) {
        return mips_sc_ret(ctx, -EINVAL);
    }
    if (pipe(fds) != 0) {
        return mips_sc_ret(ctx, -(int32_t)errno);
    }
    for (i = 0; i < 2; i++) {
        int fl = 0;

        if ((flags & MIPS_O_CLOEXEC) != 0U) {
            fl |= FD_CLOEXEC;
        }
        if (fl != 0 && fcntl(fds[i], F_SETFD, fl) != 0) {
            int e = errno;

            (void)close(fds[0]);
            (void)close(fds[1]);
            return mips_sc_ret(ctx, -(int32_t)e);
        }
        if ((flags & MIPS_O_NONBLOCK) != 0U) {
            int g = fcntl(fds[i], F_GETFL, 0);

            if (g < 0 || fcntl(fds[i], F_SETFL, g | O_NONBLOCK) != 0) {
                int e = errno;

                (void)close(fds[0]);
                (void)close(fds[1]);
                return mips_sc_ret(ctx, -(int32_t)e);
            }
        }
    }
    if (!is_pipe2) {
        ctx->gpr[MIPS32_REG_V0] = (uint32_t)fds[0];
        ctx->gpr[MIPS32_REG_V1] = (uint32_t)fds[1];
        ctx->gpr[MIPS32_REG_A3] = 0U;
        return fds[0];
    }
    {
        int be = mips_is_be(ctx);
        uint8_t out[8];
        mips_sc_st32(out, (uint32_t)fds[0], be);
        mips_sc_st32(out + 4, (uint32_t)fds[1], be);
        if (mips_sc_copy_to(ctx, fds_va, out, 8U) != 0) {
            (void)close(fds[0]);
            (void)close(fds[1]);
            return mips_sc_ret(ctx, -EFAULT);
        }
    }
    return mips_sc_ret(ctx, 0);
}

static int32_t sc_readv_writev(mips32_ctx_t *ctx, uint32_t sp, int is_write)
{
    struct iovec *vec = NULL;
    uint32_t     *bases = NULL;
    uint8_t     **tmps = NULL;
    int           ok = 1;
    int           be;
    uint32_t      fd;
    uint32_t      iov_va;
    uint32_t      count;
    uint32_t      i;
    ssize_t       n = 0;

    fd     = mips_sc_arg(ctx, sp, 0, &ok);
    iov_va = mips_sc_arg(ctx, sp, 1, &ok);
    count  = mips_sc_arg(ctx, sp, 2, &ok);
    if (!ok) {
        return mips_sc_ret(ctx, -EFAULT);
    }
    if (count > MIPS_XIOV_MAX) {
        return mips_sc_ret(ctx, -EINVAL);
    }
    if (count == 0U) {
        return mips_sc_ret(ctx, 0);
    }
    vec = (struct iovec *)malloc((size_t)count * sizeof(*vec) +
            (size_t)count * (sizeof(*tmps) + sizeof(*bases)));
    if (vec == NULL) {
        return mips_sc_ret(ctx, -ENOMEM);
    }
    tmps = (uint8_t **)(void *)(vec + count);
    bases = (uint32_t *)(void *)(tmps + count);
    for (i = 0; i < count; i++) {
        tmps[i] = NULL;
    }
    be = mips_is_be(ctx);
    for (i = 0; i < count; i++) {
        uint8_t  ent[8];
        uint32_t base;
        uint32_t len;
        uint32_t j;

        if (mips_sc_copy_from(ctx, ent, iov_va + 8U * i, 8U) != 0) {
            for (j = 0; j < count; j++) {
                free(tmps[j]);
            }
            free(vec);
            return mips_sc_ret(ctx, -EFAULT);
        }
        base = mips_sc_ld32(ent, be);
        len  = mips_sc_ld32(ent + 4, be);
        if (len > 0U &&
            !mips_sc_range_ok(ctx, base, len, (uint32_t)(is_write ? PROT_READ
                                                          : PROT_WRITE))) {
            for (j = 0; j < count; j++) {
                free(tmps[j]);
            }
            free(vec);
            return mips_sc_ret(ctx, -EFAULT);
        }
        bases[i] = base;
        /* M32-R5-6: reads stage into host tmps; writes stay direct. */
        if (!is_write && len > 0U) {
            tmps[i] = (uint8_t *)malloc((size_t)len);
            if (tmps[i] == NULL) {
                for (j = 0; j < i; j++) {
                    free(tmps[j]);
                }
                free(vec);
                return mips_sc_ret(ctx, -ENOMEM);
            }
            vec[i].iov_base = tmps[i];
        } else {
            vec[i].iov_base = (len == 0U) ? NULL :
                              mips32_guest_ptr(ctx, base);
        }
        vec[i].iov_len  = (size_t)len;
    }
    if (is_write) {
        int frc = rt32_vm_flush_shared_fd((int)fd);
        if (frc != 0) {
            for (i = 0; i < count; i++) {
                free(tmps[i]);
            }
            free(vec);
            return mips_sc_ret(ctx, frc);
        }
    }
    n = is_write ? writev((int)fd, vec, (int)count)
                 : readv((int)fd, vec, (int)count);
    if (!is_write && n > 0) {
        /* M32-R5-6: commit staged bytes via copy_to under LL/SC lock. */
        uint64_t rem = (uint64_t)n;
        int cfail = 0;

        for (i = 0; i < count && rem > 0U; i++) {
            uint64_t k = (uint64_t)vec[i].iov_len;

            if (k > rem) {
                k = rem;
            }
            if (k > 0U && rt32_vm_copy_to(ctx, bases[i], tmps[i],
                    (uint32_t)k) != 0) {
                cfail = 1;
                break;
            }
            rem -= k;
        }
        for (i = 0; i < count; i++) {
            free(tmps[i]);
        }
        free(vec);
        if (cfail) {
            return mips_sc_ret(ctx, -EFAULT);
        }
    } else {
        for (i = 0; i < count; i++) {
            free(tmps[i]);
        }
        free(vec);
    }
    if (n < 0) {
        return mips_sc_ret(ctx, -(int32_t)errno);
    }
    if (is_write && n > 0) {
        int src = rt32_vm_sync_shared_fd((int)fd);
        if (src != 0) {
            return mips_sc_ret(ctx, src);
        }
    }
    if (n > (ssize_t)0x7FFFFFFFL) {
        n = (ssize_t)0x7FFFFFFFL;
    }
    return mips_sc_ret(ctx, (int32_t)n);
}

int32_t mips_sc_access(mips32_ctx_t *ctx, uint32_t sp)
{
    char     path[MIPS_PATH_MAX];
    int      ok = 1;
    uint32_t path_va;
    uint32_t mode;
    int      rc;

    path_va = mips_sc_arg(ctx, sp, 0, &ok);
    mode    = mips_sc_arg(ctx, sp, 1, &ok);
    if (!ok) {
        return mips_sc_ret(ctx, -EFAULT);
    }
    if ((mode & ~7U) != 0U) {
        return mips_sc_ret(ctx, -EINVAL);
    }
    rc = mips_sc_read_cstr(ctx, path_va, path);
    if (rc != 0) {
        return mips_sc_ret(ctx, rc);
    }
    if (access(path, (int)mode) != 0) {
        return mips_sc_ret(ctx, -(int32_t)errno);
    }
    return mips_sc_ret(ctx, 0);
}

int32_t mips_sc_close_range(mips32_ctx_t *ctx, uint32_t sp)
{
    int      ok = 1;
    uint32_t first;
    uint32_t last;
    uint32_t flags;

    first = mips_sc_arg(ctx, sp, 0, &ok);
    last  = mips_sc_arg(ctx, sp, 1, &ok);
    flags = mips_sc_arg(ctx, sp, 2, &ok);
    if (!ok) {
        return mips_sc_ret(ctx, -EFAULT);
    }
    if ((flags & ~(MIPS_CLOSE_RANGE_CLOEXEC)) != 0U) {
        return mips_sc_ret(ctx, -EINVAL);
    }
#if defined(__linux__) && defined(SYS_close_range)
    {
        long r = syscall(SYS_close_range, (unsigned int)first,
                         (unsigned int)last, (unsigned int)flags);
        if (r != 0) {
            return mips_sc_ret(ctx, -(int32_t)errno);
        }
        return mips_sc_ret(ctx, 0);
    }
#else
    {
        uint64_t fd;

        for (fd = (uint64_t)first; fd <= (uint64_t)last; fd++) {
            if ((flags & MIPS_CLOSE_RANGE_CLOEXEC) != 0U) {
                (void)fcntl((int)fd, F_SETFD, FD_CLOEXEC);
            } else {
                (void)close((int)fd);
            }
            if (fd == (uint64_t)last) {
                break;
            }
        }
        return mips_sc_ret(ctx, 0);
    }
#endif
}

int32_t mips_syscall_more(mips32_ctx_t *ctx, uint32_t sp);

int32_t mips_syscall_extra(mips32_ctx_t *ctx, uint32_t sp)
{
    uint32_t nr;

    if (ctx == NULL) {
        return (int32_t)-EFAULT;
    }
    nr = ctx->gpr[MIPS32_REG_V0];
    switch (nr) {
    case (uint32_t)MIPS32_NR_open:
        return sc_openat(ctx, sp, 1);
    case (uint32_t)MIPS32_NR_openat:
        return sc_openat(ctx, sp, 0);
    case (uint32_t)MIPS32_NR_unlink:
        return sc_unlinkat(ctx, sp, 1);
    case (uint32_t)MIPS32_NR_unlinkat:
        return sc_unlinkat(ctx, sp, 0);
    case (uint32_t)MIPS32_NR_truncate:
    case (uint32_t)MIPS32_NR_ftruncate:
    case (uint32_t)MIPS32_NR_truncate64:
    case (uint32_t)MIPS32_NR_ftruncate64:
        return mips32_file_sc_truncate(ctx, sp, nr);
    case (uint32_t)MIPS32_NR_close:
        return sc_close(ctx, sp);
    case (uint32_t)MIPS32_NR_lseek:
        return sc_lseek(ctx, sp);
    case (uint32_t)MIPS32_NR_llseek:
        return sc_llseek(ctx, sp);
    case (uint32_t)MIPS32_NR_readv:
        return sc_readv_writev(ctx, sp, 0);
    case (uint32_t)MIPS32_NR_writev:
        return sc_readv_writev(ctx, sp, 1);
    case (uint32_t)MIPS32_NR_dup:
        return sc_dup(ctx, sp);
    case (uint32_t)MIPS32_NR_dup2:
        return sc_dup2(ctx, sp, 0);
    case (uint32_t)MIPS32_NR_dup3:
        return sc_dup2(ctx, sp, 1);
    case (uint32_t)MIPS32_NR_pipe:
        return sc_pipe(ctx, sp, 0);
    case (uint32_t)MIPS32_NR_pipe2:
        return sc_pipe(ctx, sp, 1);
    case (uint32_t)MIPS32_NR_fcntl:
    case (uint32_t)MIPS32_NR_fcntl64:
        return mips_sc_fcntl(ctx, sp);
    case (uint32_t)MIPS32_NR_ioctl:
        return mips_sc_ioctl(ctx, sp);
    case (uint32_t)MIPS32_NR_stat64:
    case (uint32_t)MIPS32_NR_lstat64:
    case (uint32_t)MIPS32_NR_fstat64:
    case (uint32_t)MIPS32_NR_fstatat64:
        return mips_sc_stat64(ctx, sp, nr);
    case (uint32_t)MIPS32_NR_statx:
        return mips_sc_statx(ctx, sp);
    case (uint32_t)MIPS32_NR_getdents64:
        return mips_sc_getdents64(ctx, sp);
    case (uint32_t)MIPS32_NR_readlink:
        return mips_sc_readlinkat(ctx, sp, 1);
    case (uint32_t)MIPS32_NR_readlinkat:
        return mips_sc_readlinkat(ctx, sp, 0);
    case (uint32_t)MIPS32_NR_access:
        return mips_sc_access(ctx, sp);
    case (uint32_t)MIPS32_NR_close_range:
        return mips_sc_close_range(ctx, sp);
    case (uint32_t)MIPS32_NR_nanosleep:
        return mips_sc_nanosleep(ctx, sp);
    case (uint32_t)MIPS32_NR_clock_gettime:
        return mips_sc_clock_gettime(ctx, sp, 0);
    case (uint32_t)MIPS32_NR_clock_gettime64:
        return mips_sc_clock_gettime(ctx, sp, 1);
    case (uint32_t)MIPS32_NR_getpid:
    case (uint32_t)MIPS32_NR_getppid:
    case (uint32_t)MIPS32_NR_getuid:
    case (uint32_t)MIPS32_NR_geteuid:
    case (uint32_t)MIPS32_NR_getgid:
    case (uint32_t)MIPS32_NR_getegid:
        return mips_sc_getxid(ctx, nr);
    case (uint32_t)MIPS32_NR_getrandom:
        return mips_sc_getrandom(ctx, sp);
    case (uint32_t)MIPS32_NR_futex:
        return mips_sc_futex_thread(ctx, sp);
    case (uint32_t)MIPS32_NR_rt_sigprocmask:
        return mips_l4a_rt_sigprocmask(ctx, sp);
    case (uint32_t)MIPS32_NR_rt_sigaction:
        return mips_sc_rt_sigaction(ctx, sp);
    case (uint32_t)MIPS32_NR_rt_sigreturn:
        /* Restores $v0/$a3 from the live frame itself: never wrapped. */
        return mips_rt_sigreturn(ctx);
    case (uint32_t)MIPS32_NR_sigaltstack:
        return mips_sc_sigaltstack(ctx, sp);
    case (uint32_t)MIPS32_NR_set_robust_list:
        return mips_sc_robust(ctx, sp, 1);
    case (uint32_t)MIPS32_NR_get_robust_list:
        return mips_sc_robust(ctx, sp, 0);
    default:
        return mips_syscall_more(ctx, sp);
    }
}
