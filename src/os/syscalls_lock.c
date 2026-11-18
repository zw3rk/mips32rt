/*
 * src/os/syscalls_lock.c — fcntl record locks (F_GETLK/F_SETLK/F_SETLKW)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * MIPS O32 has its own lock command numbers and flock layouts (SPEC 2.3,
 * asm/fcntl.h): F_GETLK 14, F_SETLK 6, F_SETLKW 7 with a 36-byte
 * struct flock {short type, whence; off_t start, len; long sysid;
 * pid_t pid; long pad[4]}, and F_GETLK64 33, F_SETLK64 34, F_SETLKW64 35
 * with a 32-byte struct flock64 {short type, whence; (pad) loff_t start,
 * len; pid_t pid}.  l_type values (RDLCK 0, WRLCK 1, UNLCK 2, from
 * asm-generic/fcntl.h) match Linux; Darwin numbers them 1/3/2, so both
 * directions translate there (mips_flock_type_* in syscalls_priv.h).
 * Needed by sqlite3 (and anything using POSIX advisory locks).
 */

#include "mips32rt.h"

#include "os/syscalls_priv.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>

#define MIPS_F_GETLK    14U
#define MIPS_F_SETLK    6U
#define MIPS_F_SETLKW   7U
#define MIPS_F_GETLK64  33U
#define MIPS_F_SETLK64  34U
#define MIPS_F_SETLKW64 35U

#define MIPS_FLOCK_SIZE   36U
#define MIPS_FLOCK64_SIZE 32U

/* Returns 1 when cmd is a record-lock command (handled here). */
int mips_fcntl_is_lock(uint32_t cmd)
{
    return cmd == MIPS_F_GETLK || cmd == MIPS_F_SETLK || cmd == MIPS_F_SETLKW ||
           cmd == MIPS_F_GETLK64 || cmd == MIPS_F_SETLK64 ||
           cmd == MIPS_F_SETLKW64;
}

int32_t mips_sc_fcntl_lock(mips32_ctx_t *ctx, uint32_t fd, uint32_t cmd,
                           uint32_t va)
{
    uint8_t      b[MIPS_FLOCK_SIZE];
    struct flock fl;
    int          wide = (cmd >= MIPS_F_GETLK64);
    uint32_t     sz   = wide ? MIPS_FLOCK64_SIZE : MIPS_FLOCK_SIZE;
    int          be   = mips_is_be(ctx);
    int          hcmd;
    int          is_get = (cmd == MIPS_F_GETLK || cmd == MIPS_F_GETLK64);

    if (mips_sc_copy_from(ctx, b, va, sz) != 0) {
        return mips_sc_ret(ctx, -EFAULT);
    }
    memset(&fl, 0, sizeof(fl));
    /* l_type/l_whence are 16-bit at offsets 0 and 2 in both layouts. */
    {
        uint32_t w = mips_sc_ld32(b, be);
        short    mtype;

        /* word at offset 0 holds both halves; their order is endian-bound */
        mtype = (short)(be ? (w >> 16) : (w & 0xffffU));
        if (mtype != 0 && mtype != 1 && mtype != 2) {
            return mips_sc_ret(ctx, -EINVAL);
        }
        fl.l_type   = mips_flock_type_to_host(mtype);
        fl.l_whence = (short)(be ? (w & 0xffffU) : (w >> 16));
    }
    if (wide) {
        fl.l_start = (off_t)(int64_t)mips_sc_ld64(b + 8, be);
        fl.l_len   = (off_t)(int64_t)mips_sc_ld64(b + 16, be);
    } else {
        fl.l_start = (off_t)(int32_t)mips_sc_ld32(b + 4, be);
        fl.l_len   = (off_t)(int32_t)mips_sc_ld32(b + 8, be);
    }
    hcmd = is_get ? F_GETLK
                  : ((cmd == MIPS_F_SETLKW || cmd == MIPS_F_SETLKW64) ? F_SETLKW
                                                                      : F_SETLK);
    if (fcntl((int)fd, hcmd, &fl) != 0) {
        return mips_sc_ret(ctx, -(int32_t)errno);
    }
    if (is_get) {
        uint32_t w;
        short    mtype = mips_flock_type_from_host(fl.l_type);

        w = be ? (((uint32_t)(uint16_t)mtype << 16) |
                  (uint16_t)fl.l_whence)
               : (((uint32_t)(uint16_t)fl.l_whence << 16) |
                  (uint16_t)mtype);
        mips_sc_st32(b, w, be);
        if (wide) {
            mips_sc_st64(b + 8, (uint64_t)fl.l_start, be);
            mips_sc_st64(b + 16, (uint64_t)fl.l_len, be);
            mips_sc_st32(b + 24, (uint32_t)fl.l_pid, be);
        } else {
            mips_sc_st32(b + 4, (uint32_t)fl.l_start, be);
            mips_sc_st32(b + 8, (uint32_t)fl.l_len, be);
            mips_sc_st32(b + 16, (uint32_t)fl.l_pid, be);
        }
        if (mips_sc_copy_to(ctx, va, b, sz) != 0) {
            return mips_sc_ret(ctx, -EFAULT);
        }
    }
    return mips_sc_ret(ctx, 0);
}
