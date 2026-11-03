/*
 * src/vm/vm_file.c — In-place arena file population, truncate, and sysroot helpers
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Every guest page keeps one fixed canonical host address
 * HVA = guest_base + gva across the 4 GiB guest window.
 *
 * - mips32_file_populate_private() copies file bytes in place into
 *   G + gva via pread(2) and zero-fills any tail past EOF while
 *   preserving the existing host arena mapping.
 * - mips32_file_sc_truncate() implements guest truncate/ftruncate and
 *   truncate64/ftruncate64 (O32 4092/4093/4211/4212) with O32
 *   even-register 64-bit length unpacking.
 * - mips_sysroot_open() resolves read-only absolute guest paths
 *   against ctx->sysroot before falling back to the raw host path.
 *
 * Pure C11.  Never touches x18.
 */

#define _POSIX_C_SOURCE 200809L

#include "vm/vm32.h"

#include "os/syscalls_priv.h"
#include "rt32/rt32.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

/*
 * In-place MAP_PRIVATE populate: keep the canonical G + gva arena
 * backing, copy file bytes with pread(2), and zero-fill any bytes past
 * EOF.  The caller must ensure the target host pages are writable
 * while populating before applying final page protections.
 */
int mips32_file_populate_private(mips32_ctx_t *ctx, uint32_t gva,
                                 uint32_t len, int fd, uint64_t file_off)
{
    uint8_t *hva;
    size_t   rem;
    off_t    cur_off;

    if (ctx == NULL || len == 0u) {
        return -EFAULT;
    }
    /* RC-U3-R2 single canonical backing: file bytes land at G + gva
     * (never a separate arena), the same HVA every other path uses. */
    hva     = (uint8_t *)(void *)(uintptr_t)(ctx->guest_base + (uint64_t)gva);
    rem     = (size_t)len;
    cur_off = (off_t)file_off;
    while (rem > 0u) {
        ssize_t got = pread(fd, hva, rem, cur_off);
        if (got < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -errno;
        }
        if (got == 0) {
            memset(hva, 0, rem);
            break;
        }
        hva     += (size_t)got;
        rem     -= (size_t)got;
        cur_off += (off_t)got;
    }
    return 0;
}

static uint64_t o32_trunc64_len(mips32_ctx_t *ctx, uint32_t a2, uint32_t a3)
{
    return mips_is_be(ctx) ? (((uint64_t)a2 << 32) | (uint64_t)a3)
                           : (((uint64_t)a3 << 32) | (uint64_t)a2);
}

static int mips32_file_truncate_at(int fd, uint64_t len)
{
    int frc = rt32_vm_flush_shared_fd(fd);
    int src;
    if (frc != 0) {
        return frc;
    }
    if (ftruncate(fd, (off_t)len) != 0) {
        return -errno;
    }
    src = rt32_vm_sync_shared_fd(fd);
    if (src != 0) {
        return src;
    }
    return 0;
}

/* sys_truncate / sys_ftruncate (O32 4092/4093) and the 64-bit
 * truncate64/ftruncate64 (O32 4211/4212): guest-facing wrappers around
 * mips32_file_truncate_at.  64-bit lengths follow the O32 even-register
 * rule: the 32-bit first argument occupies a0, a1 is padding, and the
 * length arrives in a2/a3 (high word first on BE guests, low word
 * first on LE). */
int32_t mips32_file_sc_truncate(mips32_ctx_t *ctx, uint32_t sp, uint32_t nr)
{
    int ok = 1;

    if (ctx == NULL) {
        return (int32_t)-EFAULT;
    }
    if (nr == (uint32_t)MIPS32_NR_truncate ||
        nr == (uint32_t)MIPS32_NR_truncate64) {
        char     path[MIPS_PATH_MAX];
        uint32_t path_va = mips_sc_arg(ctx, sp, 0, &ok);
        uint64_t len;
        int      fd;
        int      rc;

        if (nr == (uint32_t)MIPS32_NR_truncate) {
            int32_t len32 = (int32_t)mips_sc_arg(ctx, sp, 1, &ok);
            if (!ok) {
                return mips_sc_ret(ctx, -EFAULT);
            }
            if (len32 < 0) {
                return mips_sc_ret(ctx, -EINVAL);
            }
            len = (uint64_t)(int64_t)len32;
        } else {
            /* O32 even-register rule (a2/a3, a1 padding). */
            uint32_t a2 = mips_sc_arg(ctx, sp, 2, &ok);
            uint32_t a3 = mips_sc_arg(ctx, sp, 3, &ok);
            if (!ok) {
                return mips_sc_ret(ctx, -EFAULT);
            }
            len = o32_trunc64_len(ctx, a2, a3);
        }
        rc = mips_sc_read_cstr(ctx, path_va, path);
        if (rc != 0) {
            return mips_sc_ret(ctx, rc);
        }
        fd = open(path, O_WRONLY);
        if (fd < 0) {
            return mips_sc_ret(ctx, -(int32_t)errno);
        }
        rc = mips32_file_truncate_at(fd, len);
        (void)close(fd);
        if (rc != 0) {
            return mips_sc_ret(ctx, rc);
        }
        return mips_sc_ret(ctx, 0);
    }
    if (nr == (uint32_t)MIPS32_NR_ftruncate ||
        nr == (uint32_t)MIPS32_NR_ftruncate64) {
        uint32_t fd = mips_sc_arg(ctx, sp, 0, &ok);
        uint64_t len;
        int      rc;

        if (nr == (uint32_t)MIPS32_NR_ftruncate) {
            int32_t len32 = (int32_t)mips_sc_arg(ctx, sp, 1, &ok);
            if (!ok) {
                return mips_sc_ret(ctx, -EFAULT);
            }
            if (len32 < 0) {
                return mips_sc_ret(ctx, -EINVAL);
            }
            len = (uint64_t)(int64_t)len32;
        } else {
            /* O32 even-register rule (a2/a3, a1 padding). */
            uint32_t a2 = mips_sc_arg(ctx, sp, 2, &ok);
            uint32_t a3 = mips_sc_arg(ctx, sp, 3, &ok);
            if (!ok) {
                return mips_sc_ret(ctx, -EFAULT);
            }
            len = o32_trunc64_len(ctx, a2, a3);
        }
        rc = mips32_file_truncate_at((int)fd, len);
        if (rc != 0) {
            return mips_sc_ret(ctx, rc);
        }
        return mips_sc_ret(ctx, 0);
    }
    return mips_sc_ret(ctx, -ENOSYS);
}

/* Wave C2: sysroot-prefixed absolute loads for the dynamic linker.
 * Read-only, non-creating opens of absolute guest paths (AT_FDCWD)
 * try sysroot+path first, so the committed tests/sysroot fixture can
 * serve PT_INTERP and DT_NEEDED/RPATH libraries.  Any failure falls
 * through to the raw host path (returned -1 here), so /proc, /dev,
 * guest writes, and missing fixture entries behave exactly as before.
 * Returns the sysroot fd, or -1 when the caller must use the raw path.
 * Pure C11.  Never touches x18. */
int mips_sysroot_open(const mips32_ctx_t *ctx, int dirfd, const char *path,
    int host_flags, mode_t mode)
{
    char resolved[MIPS_PATH_MAX];
    int n;
    int fd;

    (void)dirfd; /* openat(2): dirfd is ignored for absolute paths. */
    if (ctx == NULL || path == NULL || path[0] != '/' ||
        ctx->sysroot == NULL || ctx->sysroot[0] == '\0') {
        return -1;
    }
    if ((host_flags & 3) != 0 || (host_flags & O_CREAT) != 0) {
        return -1;
    }
    n = snprintf(resolved, sizeof(resolved), "%s%s", ctx->sysroot, path);
    if (n <= 0 || (size_t)n >= sizeof(resolved)) {
        return -1;
    }
    fd = open(resolved, host_flags, mode);
    if (fd < 0) {
        return -1;
    }
    return fd;
}
