/*
 * src/os/syscalls_fs.c — path / directory / ownership / process-group
 * syscalls needed by the T1-T4 guest payloads (dash, coreutils, tar, ...)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Reached from mips_syscall_extra()'s default arm via mips_syscall_more().
 * Guest fds are host fds, and path arguments are copied out of guest
 * memory (mips_sc_read_cstr) before use.  Errors use the host errno,
 * which mips_sc_ret() maps to the MIPS value ($a3 = 1, $v0 = errno).
 * Numbers verified against asm/unistd_o32.h (libc6-dev, mipsel).
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
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#if defined(__linux__)
#include <sys/syscall.h>
#endif

#define NR_CHDIR     4012U
#define NR_FCHDIR    4133U
#define NR_GETCWD    4203U
#define NR_MKDIR     4039U
#define NR_RMDIR     4040U
#define NR_RENAME    4038U
#define NR_LINK      4009U
#define NR_SYMLINK   4083U
#define NR_CHMOD     4015U
#define NR_FCHMOD    4094U
#define NR_CHOWN     4202U
#define NR_LCHOWN    4016U
#define NR_FCHOWN    4095U
#define NR_UMASK     4060U
#define NR_FSYNC     4118U
#define NR_FDATASYNC 4152U
#define NR_SYNC      4036U
#define NR_FLOCK     4143U
#define NR_MKDIRAT   4289U
#define NR_FCHOWNAT  4291U
#define NR_RENAMEAT  4295U
#define NR_LINKAT    4296U
#define NR_SYMLINKAT 4297U
#define NR_FCHMODAT  4299U
#define NR_FACCESSAT 4300U
#define NR_FACCESSAT2 4439U
#define NR_RENAMEAT2 4351U
#define NR_MKNOD     4014U
#define NR_MKNODAT   4290U
#define NR_CREAT     4008U
#define NR_PREAD64   4200U
#define NR_PWRITE64  4201U
#define NR_MADVISE   4218U
#define NR_MLOCK     4154U
#define NR_MUNLOCK   4155U
#define NR_MSYNC     4144U
#define NR_FADVISE64 4254U
#define NR_UTIMENSAT 4316U

/* Bounce-buffer cap for pread64/pwrite64 (short transfers are legal). */
#define MIPS_IO_CHUNK (1U << 20)

/* ---- sysroot path resolution (declared in syscalls_priv.h) ----
 *
 * Absolute guest paths resolve to sysroot+path when ctx->sysroot is set
 * (the fixture shadows only the absolute paths it contains; callers
 * retry with the raw guest path on ENOENT/ENOTDIR via
 * mips_sysroot_fallback, mirroring mips_sysroot_open).  Relative paths
 * pass through unchanged so dirfd-relative *at calls keep working:
 * fds already encapsulate the guest location.  symlink targets are
 * never resolved by the callers below, only the newpath side. */
int mips_sysroot_resolve(const mips32_ctx_t *ctx, const char *path,
                         char *host_out)
{
    size_t sn;
    size_t pn;

    if (host_out == NULL || path == NULL) {
        return -EFAULT;
    }
    pn = strlen(path);
    if (ctx == NULL || ctx->sysroot == NULL || ctx->sysroot[0] == '\0' ||
        path[0] != '/') {
        if (pn + 1U > MIPS_PATH_MAX) {
            return -ENAMETOOLONG;
        }
        memcpy(host_out, path, pn + 1U);
        return 0;
    }
    sn = strlen(ctx->sysroot);
    if (sn + pn + 1U > MIPS_PATH_MAX) {
        return -ENAMETOOLONG;
    }
    memcpy(host_out, ctx->sysroot, sn);
    memcpy(host_out + sn, path, pn + 1U);
    return 0;
}

int mips_sysroot_fallback(const mips32_ctx_t *ctx, const char *path,
                          int host_errno)
{
    if (ctx == NULL || path == NULL || ctx->sysroot == NULL ||
        ctx->sysroot[0] == '\0' || path[0] != '/') {
        return 0;
    }
    return (host_errno == ENOENT || host_errno == ENOTDIR) ? 1 : 0;
}

static int32_t ret_rc(mips32_ctx_t *ctx, int rc)
{
    return mips_sc_ret(ctx, rc != 0 ? -(int32_t)errno : 0);
}

/* Fetch up to n path args (a0..) as host strings; returns 0 or -errno. */
static int32_t sc_chdir(mips32_ctx_t *ctx, uint32_t sp)
{
    char     path[MIPS_PATH_MAX];
    char     hpath[MIPS_PATH_MAX];
    int      ok = 1;
    uint32_t va = mips_sc_arg(ctx, sp, 0, &ok);
    int      rc;

    if (!ok) {
        return mips_sc_ret(ctx, -EFAULT);
    }
    rc = mips_sc_read_cstr(ctx, va, path);
    if (rc != 0) {
        return mips_sc_ret(ctx, rc);
    }
    rc = mips_sysroot_resolve(ctx, path, hpath);
    if (rc != 0) {
        return mips_sc_ret(ctx, rc);
    }
    rc = chdir(hpath);
    if (rc != 0 && mips_sysroot_fallback(ctx, path, errno)) {
        rc = chdir(path);
    }
    return ret_rc(ctx, rc);
}

static int32_t sc_getcwd(mips32_ctx_t *ctx, uint32_t sp)
{
    char       buf[MIPS_PATH_MAX];
    const char *out = buf;
    int        ok = 1;
    uint32_t   va   = mips_sc_arg(ctx, sp, 0, &ok);
    uint32_t   size = mips_sc_arg(ctx, sp, 1, &ok);
    size_t     len;

    if (!ok) {
        return mips_sc_ret(ctx, -EFAULT);
    }
    if (getcwd(buf, sizeof(buf)) == NULL) {
        return mips_sc_ret(ctx, -(int32_t)errno);
    }
    /* Inside the sysroot the guest sees the sysroot-relative path,
     * matching the openat/readlink resolution above. */
    if (ctx != NULL && ctx->sysroot != NULL && ctx->sysroot[0] != '\0') {
        size_t sn = strlen(ctx->sysroot);

        while (sn > 1U && ctx->sysroot[sn - 1U] == '/') {
            sn--;
        }
        if (strncmp(buf, ctx->sysroot, sn) == 0 &&
            (buf[sn] == '/' || buf[sn] == '\0')) {
            out = buf + sn;
            if (*out == '\0') {
                out = "/";
            }
        }
    }
    len = strlen(out) + 1U;
    if (len > size) {
        return mips_sc_ret(ctx, -ERANGE);
    }
    if (mips_sc_copy_to(ctx, va, out, (uint32_t)len) != 0) {
        return mips_sc_ret(ctx, -EFAULT);
    }
    /* Linux returns the byte count including the NUL. */
    return mips_sc_ret(ctx, (int32_t)len);
}

/*
 * One- and two-path calls.  dirfd args are taken from the guest when the
 * "at" form is used; the plain form uses AT_FDCWD.  Host AT_FDCWD is
 * passed through unchanged (guest -100 == host -100 on Linux; on Darwin
 * the host constant is substituted).
 */
static int host_dirfd(uint32_t g)
{
    if ((int32_t)g == MIPS_AT_FDCWD) {
        return AT_FDCWD;
    }
    return (int)(int32_t)g;
}

static int32_t sc_path1(mips32_ctx_t *ctx, uint32_t sp, uint32_t nr)
{
    char     path[MIPS_PATH_MAX];
    char     hpath[MIPS_PATH_MAX];
    int      ok = 1;
    int      ok2 = 1;
    int      at = (nr == NR_MKDIRAT || nr == NR_FCHMODAT || nr == NR_FCHOWNAT ||
                   nr == NR_FACCESSAT || nr == NR_FACCESSAT2 ||
                   nr == NR_MKNODAT);
    unsigned i = 0;
    int      dirfd = AT_FDCWD;
    uint32_t va;
    uint32_t a1;
    uint32_t a2;
    uint32_t a3;
    int      rc;

    if (at) {
        dirfd = host_dirfd(mips_sc_arg(ctx, sp, i++, &ok));
    }
    va = mips_sc_arg(ctx, sp, i++, &ok);
    a1 = mips_sc_arg(ctx, sp, i++, &ok);
    if (!ok) {
        return mips_sc_ret(ctx, -EFAULT);
    }
    /* Optional trailing args: a spurious stack fault must not fail calls
     * that do not use them, so these reads use their own ok flag. */
    a2 = mips_sc_arg(ctx, sp, i++, &ok2);
    a3 = mips_sc_arg(ctx, sp, i, &ok2);
    rc = mips_sc_read_cstr(ctx, va, path);
    if (rc != 0) {
        return mips_sc_ret(ctx, rc);
    }
    rc = mips_sysroot_resolve(ctx, path, hpath);
    if (rc != 0) {
        return mips_sc_ret(ctx, rc);
    }
    switch (nr) {
    case NR_MKDIR:
    case NR_MKDIRAT:
        rc = mkdirat(dirfd, hpath, (mode_t)a1);
        if (rc != 0 && mips_sysroot_fallback(ctx, path, errno)) {
            rc = mkdirat(dirfd, path, (mode_t)a1);
        }
        return ret_rc(ctx, rc);
    case NR_RMDIR:
        rc = rmdir(hpath);
        if (rc != 0 && mips_sysroot_fallback(ctx, path, errno)) {
            rc = rmdir(path);
        }
        return ret_rc(ctx, rc);
    case NR_CHMOD:
        rc = fchmodat(AT_FDCWD, hpath, (mode_t)a1, 0);
        if (rc != 0 && mips_sysroot_fallback(ctx, path, errno)) {
            rc = fchmodat(AT_FDCWD, path, (mode_t)a1, 0);
        }
        return ret_rc(ctx, rc);
    case NR_FCHMODAT:
        rc = fchmodat(dirfd, hpath, (mode_t)a1, 0);
        if (rc != 0 && mips_sysroot_fallback(ctx, path, errno)) {
            rc = fchmodat(dirfd, path, (mode_t)a1, 0);
        }
        return ret_rc(ctx, rc);
    case NR_CHOWN:
        rc = chown(hpath, (uid_t)a1, (gid_t)a2);
        if (rc != 0 && mips_sysroot_fallback(ctx, path, errno)) {
            rc = chown(path, (uid_t)a1, (gid_t)a2);
        }
        return ret_rc(ctx, rc);
    case NR_LCHOWN:
        rc = lchown(hpath, (uid_t)a1, (gid_t)a2);
        if (rc != 0 && mips_sysroot_fallback(ctx, path, errno)) {
            rc = lchown(path, (uid_t)a1, (gid_t)a2);
        }
        return ret_rc(ctx, rc);
    case NR_FCHOWNAT: {
        int fl = ((a3 & (uint32_t)MIPS_AT_SYMLINK_NOFOLLOW) != 0U)
                     ? AT_SYMLINK_NOFOLLOW : 0;
        rc = fchownat(dirfd, hpath, (uid_t)a1, (gid_t)a2, fl);
        if (rc != 0 && mips_sysroot_fallback(ctx, path, errno)) {
            rc = fchownat(dirfd, path, (uid_t)a1, (gid_t)a2, fl);
        }
        return ret_rc(ctx, rc);
    }
    case NR_FACCESSAT:
    case NR_FACCESSAT2: {
        int fl = 0;
        if (nr == NR_FACCESSAT2) {
            fl = ((a2 & (uint32_t)MIPS_AT_SYMLINK_NOFOLLOW) != 0U)
                     ? AT_SYMLINK_NOFOLLOW : 0;
        }
        if ((a1 & ~7U) != 0U) {
            return mips_sc_ret(ctx, -EINVAL);
        }
        rc = faccessat(dirfd, hpath, (int)a1, fl);
        if (rc != 0 && mips_sysroot_fallback(ctx, path, errno)) {
            rc = faccessat(dirfd, path, (int)a1, fl);
        }
        return ret_rc(ctx, rc);
    }
    case NR_MKNOD:
        /* a2 = dev (MIPS encoding); only FIFO/regular nodes are portable. */
        rc = mknod(hpath, (mode_t)a1, (dev_t)a2);
        if (rc != 0 && mips_sysroot_fallback(ctx, path, errno)) {
            rc = mknod(path, (mode_t)a1, (dev_t)a2);
        }
        return ret_rc(ctx, rc);
    case NR_MKNODAT: {
#if defined(__linux__)
        rc = mknodat(dirfd, hpath, (mode_t)a1, (dev_t)a2);
        if (rc != 0 && mips_sysroot_fallback(ctx, path, errno)) {
            rc = mknodat(dirfd, path, (mode_t)a1, (dev_t)a2);
        }
        return ret_rc(ctx, rc);
#else
        if (dirfd != AT_FDCWD) {
            return mips_sc_ret(ctx, -ENOSYS);
        }
        rc = mknod(hpath, (mode_t)a1, (dev_t)a2);
        if (rc != 0 && mips_sysroot_fallback(ctx, path, errno)) {
            rc = mknod(path, (mode_t)a1, (dev_t)a2);
        }
        return ret_rc(ctx, rc);
#endif
    }
    case NR_CREAT: {
        int fd = open(hpath, O_WRONLY | O_CREAT | O_TRUNC, (mode_t)a1);
        if (fd < 0 && mips_sysroot_fallback(ctx, path, errno)) {
            fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, (mode_t)a1);
        }
        return mips_sc_ret(ctx, fd < 0 ? -(int32_t)errno : fd);
    }
    default:
        return mips_sc_ret(ctx, -ENOSYS);
    }
}

static int32_t sc_path2(mips32_ctx_t *ctx, uint32_t sp, uint32_t nr)
{
    char     p1[MIPS_PATH_MAX];
    char     p2[MIPS_PATH_MAX];
    char     h1[MIPS_PATH_MAX];
    char     h2[MIPS_PATH_MAX];
    int      ok = 1;
    unsigned i = 0;
    int      fd1 = AT_FDCWD;
    int      fd2 = AT_FDCWD;
    uint32_t v1;
    uint32_t v2;
    uint32_t fl = 0U;
    int      rc;
    int      newpath_only;

    switch (nr) {
    case NR_RENAMEAT:
    case NR_RENAMEAT2:
        fd1 = host_dirfd(mips_sc_arg(ctx, sp, i++, &ok));
        v1  = mips_sc_arg(ctx, sp, i++, &ok);
        fd2 = host_dirfd(mips_sc_arg(ctx, sp, i++, &ok));
        v2  = mips_sc_arg(ctx, sp, i++, &ok);
        if (nr == NR_RENAMEAT2) {
            fl = mips_sc_arg(ctx, sp, i, &ok);
        }
        break;
    case NR_LINKAT:
        fd1 = host_dirfd(mips_sc_arg(ctx, sp, i++, &ok));
        v1  = mips_sc_arg(ctx, sp, i++, &ok);
        fd2 = host_dirfd(mips_sc_arg(ctx, sp, i++, &ok));
        v2  = mips_sc_arg(ctx, sp, i++, &ok);
        fl  = mips_sc_arg(ctx, sp, i, &ok);
        break;
    case NR_SYMLINKAT:
        v1  = mips_sc_arg(ctx, sp, i++, &ok);
        fd2 = host_dirfd(mips_sc_arg(ctx, sp, i++, &ok));
        v2  = mips_sc_arg(ctx, sp, i, &ok);
        break;
    default: /* rename, link, symlink */
        v1 = mips_sc_arg(ctx, sp, i++, &ok);
        v2 = mips_sc_arg(ctx, sp, i, &ok);
        break;
    }
    if (!ok) {
        return mips_sc_ret(ctx, -EFAULT);
    }
    rc = mips_sc_read_cstr(ctx, v1, p1);
    if (rc == 0) {
        rc = mips_sc_read_cstr(ctx, v2, p2);
    }
    if (rc != 0) {
        return mips_sc_ret(ctx, rc);
    }
    /* Only the link newpath side resolves: the symlink target is guest
     * content and must pass through verbatim. */
    newpath_only = (nr == NR_SYMLINK || nr == NR_SYMLINKAT);
    if (newpath_only) {
        memcpy(h1, p1, strlen(p1) + 1U);
    } else {
        rc = mips_sysroot_resolve(ctx, p1, h1);
        if (rc != 0) {
            return mips_sc_ret(ctx, rc);
        }
    }
    rc = mips_sysroot_resolve(ctx, p2, h2);
    if (rc != 0) {
        return mips_sc_ret(ctx, rc);
    }
    switch (nr) {
    case NR_RENAME:
        rc = rename(h1, h2);
        if (rc != 0 && (mips_sysroot_fallback(ctx, p1, errno) ||
                        mips_sysroot_fallback(ctx, p2, errno))) {
            rc = rename(p1, p2);
        }
        return ret_rc(ctx, rc);
    case NR_RENAMEAT:
        rc = renameat(fd1, h1, fd2, h2);
        if (rc != 0 && (mips_sysroot_fallback(ctx, p1, errno) ||
                        mips_sysroot_fallback(ctx, p2, errno))) {
            rc = renameat(fd1, p1, fd2, p2);
        }
        return ret_rc(ctx, rc);
    case NR_RENAMEAT2:
        if (fl != 0U) {
#if defined(__linux__) && defined(SYS_renameat2)
            rc = (int)syscall(SYS_renameat2, fd1, h1, fd2, h2, fl);
            if (rc != 0 && (mips_sysroot_fallback(ctx, p1, errno) ||
                            mips_sysroot_fallback(ctx, p2, errno))) {
                rc = (int)syscall(SYS_renameat2, fd1, p1, fd2, p2, fl);
            }
            return ret_rc(ctx, rc);
#else
            return mips_sc_ret(ctx, -EINVAL);
#endif
        }
        rc = renameat(fd1, h1, fd2, h2);
        if (rc != 0 && (mips_sysroot_fallback(ctx, p1, errno) ||
                        mips_sysroot_fallback(ctx, p2, errno))) {
            rc = renameat(fd1, p1, fd2, p2);
        }
        return ret_rc(ctx, rc);
    case NR_LINK:
        rc = link(h1, h2);
        if (rc != 0 && (mips_sysroot_fallback(ctx, p1, errno) ||
                        mips_sysroot_fallback(ctx, p2, errno))) {
            rc = link(p1, p2);
        }
        return ret_rc(ctx, rc);
    case NR_LINKAT: {
        int lfl = (((fl & 0x400U) != 0U) ? AT_SYMLINK_FOLLOW : 0);
        rc = linkat(fd1, h1, fd2, h2, lfl);
        if (rc != 0 && (mips_sysroot_fallback(ctx, p1, errno) ||
                        mips_sysroot_fallback(ctx, p2, errno))) {
            rc = linkat(fd1, p1, fd2, p2, lfl);
        }
        return ret_rc(ctx, rc);
    }
    case NR_SYMLINK:
        rc = symlink(h1, h2);
        if (rc != 0 && mips_sysroot_fallback(ctx, p2, errno)) {
            rc = symlink(p1, p2);
        }
        return ret_rc(ctx, rc);
    case NR_SYMLINKAT:
        rc = symlinkat(h1, fd2, h2);
        if (rc != 0 && mips_sysroot_fallback(ctx, p2, errno)) {
            rc = symlinkat(p1, fd2, p2);
        }
        return ret_rc(ctx, rc);
    default:
        return mips_sc_ret(ctx, -ENOSYS);
    }
}

/* fd-only calls: fchdir, fchmod, fchown, fsync, fdatasync, flock, fadvise. */
static int32_t sc_fd1(mips32_ctx_t *ctx, uint32_t sp, uint32_t nr)
{
    int      ok = 1;
    int      fd = (int)(int32_t)mips_sc_arg(ctx, sp, 0, &ok);
    uint32_t a1 = mips_sc_arg(ctx, sp, 1, &ok);
    uint32_t a2 = mips_sc_arg(ctx, sp, 2, &ok);

    if (!ok) {
        return mips_sc_ret(ctx, -EFAULT);
    }
    switch (nr) {
    case NR_FCHDIR:
        return ret_rc(ctx, fchdir(fd));
    case NR_FCHMOD:
        return ret_rc(ctx, fchmod(fd, (mode_t)a1));
    case NR_FCHOWN:
        return ret_rc(ctx, fchown(fd, (uid_t)a1, (gid_t)a2));
    case NR_FSYNC:
    case NR_FDATASYNC:
        return ret_rc(ctx, fsync(fd));
    case NR_FLOCK:
        /* LOCK_SH 1, LOCK_EX 2, LOCK_NB 4, LOCK_UN 8 on every ABI. */
        return ret_rc(ctx, flock(fd, (int)a1));
    default: /* fadvise64: advisory only */
        return mips_sc_ret(ctx, 0);
    }
}

static int32_t sc_pio(mips32_ctx_t *ctx, uint32_t sp, int is_write)
{
    int      ok = 1;
    int      fd  = (int)(int32_t)mips_sc_arg(ctx, sp, 0, &ok);
    uint32_t va  = mips_sc_arg(ctx, sp, 1, &ok);
    uint32_t cnt = mips_sc_arg(ctx, sp, 2, &ok);
    uint32_t w0  = mips_sc_arg(ctx, sp, 4, &ok); /* a3 is alignment pad */
    uint32_t w1  = mips_sc_arg(ctx, sp, 5, &ok);
    uint64_t off;
    uint8_t *buf;
    ssize_t  n;

    if (!ok) {
        return mips_sc_ret(ctx, -EFAULT);
    }
    off = mips_is_be(ctx) ? (((uint64_t)w0 << 32) | w1)
                          : (((uint64_t)w1 << 32) | w0);
    if (cnt > MIPS_IO_CHUNK) {
        cnt = MIPS_IO_CHUNK;
    }
    if (cnt == 0U) {
        return mips_sc_ret(ctx, 0);
    }
    buf = (uint8_t *)malloc(cnt);
    if (buf == NULL) {
        return mips_sc_ret(ctx, -ENOMEM);
    }
    if (is_write) {
        if (mips_sc_copy_from(ctx, buf, va, cnt) != 0) {
            free(buf);
            return mips_sc_ret(ctx, -EFAULT);
        }
        n = pwrite(fd, buf, cnt, (off_t)off);
    } else {
        n = pread(fd, buf, cnt, (off_t)off);
        if (n > 0 && mips_sc_copy_to(ctx, va, buf, (uint32_t)n) != 0) {
            free(buf);
            return mips_sc_ret(ctx, -EFAULT);
        }
    }
    free(buf);
    return mips_sc_ret(ctx, n < 0 ? -(int32_t)errno : (int32_t)n);
}

/* utimensat(dirfd, path|NULL, struct timespec[2] (32-bit), flags). */
static int32_t sc_utimensat(mips32_ctx_t *ctx, uint32_t sp)
{
    char            path[MIPS_PATH_MAX];
    char            hpath[MIPS_PATH_MAX];
    struct timespec ts[2];
    uint8_t         raw[16];
    int             ok = 1;
    int             dirfd = host_dirfd(mips_sc_arg(ctx, sp, 0, &ok));
    uint32_t        pva = mips_sc_arg(ctx, sp, 1, &ok);
    uint32_t        tva = mips_sc_arg(ctx, sp, 2, &ok);
    uint32_t        fl  = mips_sc_arg(ctx, sp, 3, &ok);
    int             be = mips_is_be(ctx);
    int             hfl = ((fl & (uint32_t)MIPS_AT_SYMLINK_NOFOLLOW) != 0U)
                              ? AT_SYMLINK_NOFOLLOW : 0;
    int             rc;
    int             i;

    if (!ok) {
        return mips_sc_ret(ctx, -EFAULT);
    }
    if (tva != 0U) {
        if (mips_sc_copy_from(ctx, raw, tva, 16U) != 0) {
            return mips_sc_ret(ctx, -EFAULT);
        }
        for (i = 0; i < 2; i++) {
            ts[i].tv_sec  = (time_t)(int32_t)mips_sc_ld32(raw + 8 * i, be);
            ts[i].tv_nsec = (long)(int32_t)mips_sc_ld32(raw + 8 * i + 4, be);
        }
    }
    if (pva == 0U) {
        return ret_rc(ctx, futimens(dirfd, tva != 0U ? ts : NULL));
    }
    rc = mips_sc_read_cstr(ctx, pva, path);
    if (rc != 0) {
        return mips_sc_ret(ctx, rc);
    }
    rc = mips_sysroot_resolve(ctx, path, hpath);
    if (rc != 0) {
        return mips_sc_ret(ctx, rc);
    }
    rc = utimensat(dirfd, hpath, tva != 0U ? ts : NULL, hfl);
    if (rc != 0 && mips_sysroot_fallback(ctx, path, errno)) {
        rc = utimensat(dirfd, path, tva != 0U ? ts : NULL, hfl);
    }
    return ret_rc(ctx, rc);
}

int32_t mips_syscall_misc(mips32_ctx_t *ctx, uint32_t sp, uint32_t nr,
                          int *handled);

int32_t mips_syscall_more(mips32_ctx_t *ctx, uint32_t sp)
{
    uint32_t nr = ctx->gpr[MIPS32_REG_V0];
    int      handled = 0;
    int32_t  r;

    switch (nr) {
    case NR_CHDIR:
        return sc_chdir(ctx, sp);
    case NR_GETCWD:
        return sc_getcwd(ctx, sp);
    case NR_MKDIR: case NR_MKDIRAT: case NR_RMDIR: case NR_CHMOD:
    case NR_FCHMODAT: case NR_CHOWN: case NR_LCHOWN: case NR_FCHOWNAT:
    case NR_FACCESSAT: case NR_FACCESSAT2: case NR_MKNOD: case NR_MKNODAT:
    case NR_CREAT:
        return sc_path1(ctx, sp, nr);
    case NR_RENAME: case NR_RENAMEAT: case NR_RENAMEAT2: case NR_LINK:
    case NR_LINKAT: case NR_SYMLINK: case NR_SYMLINKAT:
        return sc_path2(ctx, sp, nr);
    case NR_FCHDIR: case NR_FCHMOD: case NR_FCHOWN: case NR_FSYNC:
    case NR_FDATASYNC: case NR_FLOCK: case NR_FADVISE64:
        return sc_fd1(ctx, sp, nr);
    case NR_PREAD64:
        return sc_pio(ctx, sp, 0);
    case NR_PWRITE64:
        return sc_pio(ctx, sp, 1);
    case NR_UTIMENSAT:
        return sc_utimensat(ctx, sp);
    case NR_UMASK: {
        int      ok = 1;
        uint32_t m = mips_sc_arg(ctx, sp, 0, &ok);

        if (!ok) {
            return mips_sc_ret(ctx, -EFAULT);
        }
        return mips_sc_ret(ctx, (int32_t)umask((mode_t)(m & 0777U)));
    }
    case NR_SYNC:
        sync();
        return mips_sc_ret(ctx, 0);
    case NR_MADVISE: case NR_MLOCK: case NR_MUNLOCK: case NR_MSYNC:
        return mips_sc_ret(ctx, 0);
    default:
        break;
    }
    r = mips_syscall_misc(ctx, sp, nr, &handled);
    if (handled) {
        return r;
    }
    return mips_sc_ret(ctx, -ENOSYS);
}
