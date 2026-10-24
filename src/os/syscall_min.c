/*
 * src/os/syscall_min.c — Minimal MIPS O32 syscall dispatcher (lane L1c)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Implements the Phase 1 subset per SPEC 2.3 and the phase-1 lane card:
 * exit, exit_group, read, write, brk, mmap, mmap2, munmap, mprotect,
 * uname, set_tid_address.  Unknown syscalls report -ENOSYS with $a3=1.
 *
 * Syscall numbers (offsets from __NR_Linux = 4000) verified against
 * /usr/mipsel-linux-gnu/include/asm/unistd_o32.h from
 * libc6-dev-mipsel-cross 2.36-8cross2 (debian:bookworm-slim,
 * linux/arm64, 2026-10-24):
 *   __NR_exit +1, __NR_read +3, __NR_write +4, __NR_brk +45,
 *   __NR_mmap +90, __NR_munmap +91, __NR_uname +122, __NR_mprotect +125,
 *   __NR_mmap2 +210, __NR_exit_group +246, __NR_set_tid_address +252.
 * The frozen src/os/syscall_nr.h carries the same values except
 * set_tid_address, which is defined locally below (MIPS32_NR_TID_ADDRESS,
 * 4252) so the frozen header stays untouched.
 *
 * O32 convention (SPEC 2.3, E01 FINDINGS): number in $v0, args 1..4 in
 * $a0..$a3, args 5..8 at guest (sp+16)..(sp+28).  Success: $a3=0 and
 * $v0=(uint32_t)ret; error: $a3=1 and $v0=positive MIPS errno.  The
 * return value of mips_syscall is the raw host-style result (negative
 * errno on error) for the engine; the guest registers always follow
 * the $a3 convention above.
 *
 * 64-bit pairs (E01 section 5: even-pair alignment, lo even/hi odd in
 * mipsel, hi even/lo odd in mips): no Phase 1 syscall takes a 64-bit
 * argument, so no pair assembly is needed yet; it lands with llseek-class
 * syscalls in Phase 2.
 *
 * errno mapping: MIPS shares asm-generic errno values for every error
 * produced here except ENOSYS (MIPS asm/errno.h: ENOSYS 89 vs host 38);
 * mips_errno_from_host maps 38->89 and passes the rest through.
 */

#include "mips32rt.h"

#include "os/syscall_nr.h"
#include "rt32/rt32.h"

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/utsname.h>
#include <unistd.h>

/* Locally frozen: __NR_set_tid_address = __NR_Linux + 252 (see above). */
#define MIPS32_NR_TID_ADDRESS 4252U

/* MIPS new_utsname: 6 fields of 65 bytes (Linux UAPI, all arches). */
#define MIPS_UTS_FIELD 65U
#define MIPS_UTS_SIZE  (6U * MIPS_UTS_FIELD)

/* True when [va, va+len) is fully covered by recorded regions with need. */
static int range_ok(const mips32_ctx_t *ctx, uint32_t va, uint32_t len,
                    uint32_t need)
{
    uint64_t end64;
    uint32_t cur;
    size_t   i;

    if (len == 0U) {
        return 1;
    }
    end64 = (uint64_t)va + (uint64_t)len;
    if (end64 > 0x100000000ULL) {
        return 0;
    }
    cur = va;
    for (i = 0; i < ctx->region_count; i++) {
        const mips32_region_t *r = &ctx->regions[i];
        if (r->start > cur) {
            return 0; /* sorted gap: nothing later can cover cur */
        }
        if (r->end <= cur) {
            continue;
        }
        if ((r->prot & need) != need) {
            return 0;
        }
        cur = r->end;
        if ((uint64_t)cur >= end64) {
            return 1;
        }
    }
    return 0;
}

static int32_t mips_errno_from_host(int host_errno)
{
    if (host_errno == ENOSYS) {
        return 89; /* MIPS ENOSYS (asm/errno.h), not asm-generic 38 */
    }
    return (int32_t)host_errno;
}

/* Record the $a3 convention in the guest regs; return raw host value. */
static int32_t sc_ret(mips32_ctx_t *ctx, int32_t raw)
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

/*
 * Fetch O32 argument i (0-based): $a0..$a3 for i<4, guest stack slot at
 * sp+16+4*(i-4) otherwise.  The readability pre-check keeps a bad stack
 * from recording EXIT_FAULT: failure yields ok=0 for an -EFAULT return.
 */
static uint32_t o32_arg(mips32_ctx_t *ctx, uint32_t sp, unsigned i, int *ok)
{
    uint32_t va;
    uint32_t val = 0U;

    if (i < 4U) {
        *ok = 1;
        return ctx->gpr[MIPS32_REG_A0 + i];
    }
    va = sp + 16U + 4U * (i - 4U);
    if ((va & 3U) != 0U || !range_ok(ctx, va, 4U, (uint32_t)PROT_READ) ||
        guest_ld32(ctx, va, &val) != 0) {
        *ok = 0;
        return 0U;
    }
    *ok = 1;
    return val;
}

static void copy_uts_field(uint8_t *dst, const char *src)
{
    size_t i;

    for (i = 0; i < MIPS_UTS_FIELD; i++) {
        if (src[i] == '\0') {
            break;
        }
        dst[i] = (uint8_t)src[i];
    }
    for (; i < MIPS_UTS_FIELD; i++) {
        dst[i] = 0U;
    }
}

static int32_t sc_read(mips32_ctx_t *ctx, uint32_t sp)
{
    uint8_t  *host_buf;
    int       ok = 1;
    uint32_t  fd;
    uint32_t  buf;
    uint32_t  count;
    ssize_t   n;

    fd    = o32_arg(ctx, sp, 0, &ok);
    buf   = o32_arg(ctx, sp, 1, &ok);
    count = o32_arg(ctx, sp, 2, &ok);
    if (!ok) {
        return sc_ret(ctx, -EFAULT);
    }
    if (count > 0U && !range_ok(ctx, buf, count, (uint32_t)PROT_WRITE)) {
        return sc_ret(ctx, -EFAULT);
    }
    host_buf = (uint8_t *)mips32_guest_ptr(ctx, buf);
    n        = read((int)fd, host_buf, (size_t)count);
    if (n < 0) {
        return sc_ret(ctx, -(int32_t)errno);
    }
    if (n > 0x7FFFFFFFL) {
        n = 0x7FFFFFFFL;
    }
    return sc_ret(ctx, (int32_t)n);
}

static int32_t sc_write(mips32_ctx_t *ctx, uint32_t sp)
{
    const uint8_t *host_buf;
    int            ok = 1;
    uint32_t       fd;
    uint32_t       buf;
    uint32_t       count;
    ssize_t        n;

    fd    = o32_arg(ctx, sp, 0, &ok);
    buf   = o32_arg(ctx, sp, 1, &ok);
    count = o32_arg(ctx, sp, 2, &ok);
    if (!ok) {
        return sc_ret(ctx, -EFAULT);
    }
    if (count > 0U && !range_ok(ctx, buf, count, (uint32_t)PROT_READ)) {
        return sc_ret(ctx, -EFAULT);
    }
    host_buf = (const uint8_t *)mips32_guest_ptr(ctx, buf);
    n        = write((int)fd, host_buf, (size_t)count);
    if (n < 0) {
        return sc_ret(ctx, -(int32_t)errno);
    }
    if (n > 0x7FFFFFFFL) {
        n = 0x7FFFFFFFL;
    }
    return sc_ret(ctx, (int32_t)n);
}

static int32_t sc_mmap(mips32_ctx_t *ctx, uint32_t sp, int is_mmap2)
{
    int      ok = 1;
    uint32_t addr;
    uint32_t len;
    uint32_t prot;
    uint32_t flags;
    uint32_t fd_u;
    uint32_t off;
    uint32_t pgoff;
    uint32_t res;

    addr  = o32_arg(ctx, sp, 0, &ok);
    len   = o32_arg(ctx, sp, 1, &ok);
    prot  = o32_arg(ctx, sp, 2, &ok);
    flags = o32_arg(ctx, sp, 3, &ok);
    fd_u  = o32_arg(ctx, sp, 4, &ok);
    off   = o32_arg(ctx, sp, 5, &ok);
    if (!ok) {
        return sc_ret(ctx, -EFAULT);
    }
    if (is_mmap2) {
        pgoff = off; /* mmap2 offset already in 4 KiB pages */
    } else {
        if ((off & 0xFFFU) != 0U) {
            return sc_ret(ctx, -EINVAL);
        }
        pgoff = off >> 12;
    }
    res = rt32_vm_mmap2(ctx, addr, len, prot, flags, (int)(int32_t)fd_u,
                        pgoff);
    return sc_ret(ctx, (int32_t)res);
}

static int32_t sc_uname(mips32_ctx_t *ctx, uint32_t sp)
{
    uint8_t     *dst;
    int          ok = 1;
    uint32_t     va;
    struct utsname un;

    va = o32_arg(ctx, sp, 0, &ok);
    if (!ok) {
        return sc_ret(ctx, -EFAULT);
    }
    if (!range_ok(ctx, va, MIPS_UTS_SIZE, (uint32_t)PROT_WRITE)) {
        return sc_ret(ctx, -EFAULT);
    }
    if (uname(&un) != 0) {
        return sc_ret(ctx, -(int32_t)errno);
    }
    dst = (uint8_t *)mips32_guest_ptr(ctx, va);
    copy_uts_field(dst + 0U * MIPS_UTS_FIELD, un.sysname);
    copy_uts_field(dst + 1U * MIPS_UTS_FIELD, un.nodename);
    copy_uts_field(dst + 2U * MIPS_UTS_FIELD, un.release);
    copy_uts_field(dst + 3U * MIPS_UTS_FIELD, un.version);
    copy_uts_field(dst + 4U * MIPS_UTS_FIELD, un.machine);
#if defined(__linux__) && !defined(__GLIBC__)
    /* musl spells the sixth utsname field with leading underscores. */
    copy_uts_field(dst + 5U * MIPS_UTS_FIELD, un.__domainname);
#elif defined(__linux__)
    copy_uts_field(dst + 5U * MIPS_UTS_FIELD, un.domainname);
#else
    memset(dst + 5U * MIPS_UTS_FIELD, 0, MIPS_UTS_FIELD);
#endif
    return sc_ret(ctx, 0);
}

/* Phase 2 static-libc layer (src/os/syscalls.c, lane L2a). */
int32_t mips_syscall_extra(mips32_ctx_t *ctx, uint32_t sp);

int32_t mips_syscall(mips32_ctx_t *ctx)
{
    uint32_t nr;
    uint32_t sp;
    int      ok = 1;

    if (ctx == NULL) {
        return (int32_t)-EFAULT;
    }
    ctx->llbit = 0U; /* SPEC 2.2: any syscall clears the LL reservation */
    ctx->syscalls_executed++;
    nr = ctx->gpr[MIPS32_REG_V0];
    sp = ctx->gpr[MIPS32_REG_SP];

    switch (nr) {
    case MIPS32_NR_exit:
    case MIPS32_NR_exit_group: {
        uint32_t status = o32_arg(ctx, sp, 0, &ok);
        (void)ok;
        exit((int)(status & 0xFFU));
        return sc_ret(ctx, 0);
    }
    case MIPS32_NR_read:
        return sc_read(ctx, sp);
    case MIPS32_NR_write:
        return sc_write(ctx, sp);
    case MIPS32_NR_brk: {
        uint32_t new_brk = o32_arg(ctx, sp, 0, &ok);
        uint32_t cur;
        if (!ok) {
            return sc_ret(ctx, -EFAULT);
        }
        cur = rt32_vm_brk(ctx, new_brk);
        return sc_ret(ctx, (int32_t)cur);
    }
    case MIPS32_NR_mmap:
        return sc_mmap(ctx, sp, 0);
    case MIPS32_NR_mmap2:
        return sc_mmap(ctx, sp, 1);
    case MIPS32_NR_munmap: {
        uint32_t addr = o32_arg(ctx, sp, 0, &ok);
        uint32_t len  = o32_arg(ctx, sp, 1, &ok);
        if (!ok) {
            return sc_ret(ctx, -EFAULT);
        }
        return sc_ret(ctx, (int32_t)rt32_vm_munmap(ctx, addr, len));
    }
    case MIPS32_NR_mprotect: {
        uint32_t addr = o32_arg(ctx, sp, 0, &ok);
        uint32_t len  = o32_arg(ctx, sp, 1, &ok);
        uint32_t prot = o32_arg(ctx, sp, 2, &ok);
        if (!ok) {
            return sc_ret(ctx, -EFAULT);
        }
        return sc_ret(ctx, (int32_t)rt32_vm_mprotect(ctx, addr, len, prot));
    }
    case MIPS32_NR_uname:
        return sc_uname(ctx, sp);
    case MIPS32_NR_TID_ADDRESS: {
        uint32_t tidptr = o32_arg(ctx, sp, 0, &ok);
        if (!ok) {
            return sc_ret(ctx, -EFAULT);
        }
        ctx->clear_child_tid = tidptr;
        /* Single-threaded Phase 1: pid is the tid (real tids in Phase 4). */
        return sc_ret(ctx, (int32_t)getpid());
    }
    /* Phase 2 (lane L2a): static-libc numbers handled in syscalls.c. */
    case MIPS32_NR_open:
    case MIPS32_NR_openat:
    case MIPS32_NR_close:
    case MIPS32_NR_lseek:
    case MIPS32_NR_llseek:
    case MIPS32_NR_readv:
    case MIPS32_NR_writev:
    case MIPS32_NR_dup:
    case MIPS32_NR_dup2:
    case MIPS32_NR_dup3:
    case MIPS32_NR_pipe:
    case MIPS32_NR_pipe2:
    case MIPS32_NR_fcntl:
    case MIPS32_NR_fcntl64:
    case MIPS32_NR_ioctl:
    case MIPS32_NR_stat64:
    case MIPS32_NR_lstat64:
    case MIPS32_NR_fstat64:
    case MIPS32_NR_fstatat64:
    case MIPS32_NR_statx:
    case MIPS32_NR_getdents64:
    case MIPS32_NR_readlink:
    case MIPS32_NR_readlinkat:
    case MIPS32_NR_access:
    case MIPS32_NR_close_range:
    case MIPS32_NR_nanosleep:
    case MIPS32_NR_clock_gettime:
    case MIPS32_NR_clock_gettime64:
    case MIPS32_NR_getuid:
    case MIPS32_NR_geteuid:
    case MIPS32_NR_getgid:
    case MIPS32_NR_getegid:
    case MIPS32_NR_getrandom:
    case MIPS32_NR_futex:
    case MIPS32_NR_rt_sigprocmask:
    case MIPS32_NR_rt_sigaction:
    case MIPS32_NR_set_robust_list:
    case MIPS32_NR_get_robust_list:
    case MIPS32_NR_unlink:
    case MIPS32_NR_unlinkat:
        return mips_syscall_extra(ctx, sp);
    case MIPS32_NR_set_thread_area: {
        /* O32 takes the TLS base directly in $a0 (E06); rdhwr $29 reads
         * it back as ctx->ulr.  LL reservations are already clear here. */
        uint32_t tp = o32_arg(ctx, sp, 0, &ok);
        if (!ok) {
            return sc_ret(ctx, -EFAULT);
        }
        ctx->ulr = tp;
        return sc_ret(ctx, 0);
    }
    default:
        break;
    }
    return sc_ret(ctx, -(int32_t)ENOSYS);
}
