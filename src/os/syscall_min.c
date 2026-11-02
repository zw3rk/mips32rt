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
#include "os/syscalls_priv.h"
#include "rt32/rt32.h"

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/utsname.h>
#include <unistd.h>

#if defined(__linux__)
#include <sys/syscall.h>
/* Raw host syscalls without _GNU_SOURCE (which would reshuffle musl's
 * struct utsname spelling above): syscall(2) is a stable ABI. */
extern long syscall(long __n, ...);
#endif

/* Locally frozen: __NR_set_tid_address = __NR_Linux + 252 (see above). */
#define MIPS32_NR_TID_ADDRESS 4252U
/* Wave U3: O32 sysmips = __NR_Linux + 149 (syscall_o32.tbl) and
 * MIPS_FIXADE = 7 (Linux sys/sysmips.h).  Defined locally so the
 * frozen src/os/syscall_nr.h stays untouched (TID_ADDRESS precedent).
 * sysmips(MIPS_FIXADE, 0) disables unaligned emulation (next
 * misaligned access faults -> SIGBUS/BUS_ADRALN); nonzero enables. */
#define MIPS32_NR_SYSMIPS 4149U
#define MIPS32_SYSMIPS_FIXADE 7U

/* Wave C2: O32 tkill = __NR_Linux + 236, tgkill = __NR_Linux + 266,
 * gettid = __NR_Linux + 222 (asm/unistd_o32.h, matching the
 * MIPS32_NR_TID_ADDRESS precedent: defined locally so the frozen
 * src/os/syscall_nr.h stays untouched).  kill (+37) is already frozen.
 * glibc raise() lowers to getpid + gettid + tgkill. */
#define MIPS32_NR_TKILL 4236U
#define MIPS32_NR_TGKILL 4266U
#define MIPS32_NR_GETTID 4222U

/* Kill-class self-delivery (src/os/kill.c, Wave C2). */
int32_t mips_sc_kill(mips32_ctx_t *ctx, uint32_t sp);

/* AOT cache cold emit on guest exit (src/dbt/aot_emit.c, Wave C2). */
void mips32_aot_flush(mips32_ctx_t *ctx);

/* Cross-lane hook (same weak-reference pattern as src/os/proc.c): the
 * Phase 2 DBT provides mips32_dbt_invalidate_range; without it
 * (interp-only link) cacheflush is a successful no-op. */
__attribute__((weak)) void mips32_dbt_invalidate_range(mips32_ctx_t *ctx,
                                                      uint32_t start,
                                                      uint32_t end);

/* MIPS new_utsname: 6 fields of 65 bytes (Linux UAPI, all arches). */
#define MIPS_UTS_FIELD 65U
#define MIPS_UTS_SIZE  (6U * MIPS_UTS_FIELD)

/* True when [va, va+len) is fully covered by recorded regions with need. */
static int range_ok(const mips32_ctx_t *ctx, uint32_t va, uint32_t len,
                    uint32_t need)
{
    return mips32_range_ok(ctx, va, len, need);
}

/* Record the $a3 convention in the guest regs; return raw host value. */
static int32_t sc_ret(mips32_ctx_t *ctx, int32_t raw)
{
    return mips_sc_ret(ctx, raw);
}

/* Fetch O32 argument i (0-based) via shared lock-held syscall helper. */
static uint32_t o32_arg(mips32_ctx_t *ctx, uint32_t sp, unsigned i, int *ok)
{
    return mips_sc_arg(ctx, sp, i, ok);
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
    if (n > 0) {
        rt32_vm_sync_shared_fd((int)fd);
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
    /* MIPS MAP_ANONYMOUS is 0x800 (classic MAP_ANON, UAPI
     * arch/mips/include/uapi/asm/mman.h), not the asm-generic 0x20
     * the RT32 VMA layer matches; normalize at the O32 boundary so
     * the window layer stays in host form.  SHARED/PRIVATE/FIXED and
     * FIXED_NOREPLACE already match. */
    if ((flags & 0x800U) != 0U) {
        flags = (flags & ~0x800U) | 0x20U;
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

/* Phase 4 process lifecycle (src/os/proc.c, lane L4c). */
int32_t mips_proc_fork(mips32_ctx_t *ctx, uint32_t sp);
int32_t mips_proc_execve(mips32_ctx_t *ctx, uint32_t sp);
int32_t mips_proc_wait4(mips32_ctx_t *ctx, uint32_t sp);
int32_t mips_proc_waitpid(mips32_ctx_t *ctx, uint32_t sp);

/* Phase 4 thread layer (src/os/threads.c, lane L4b). */
int32_t mips_sc_clone(mips32_ctx_t *ctx, uint32_t sp);

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
        /* RC4: a CLONE_VM thread ending via plain exit() leaves the
         * group alive (raw SYS_exit + CLEARTID wake in threads.c);
         * exit_group always tears the whole group down.  Group
         * teardown is a raw SYS_exit_group, never libc exit(): clone
         * children die via raw SYS_exit while possibly holding libc
         * locks (malloc arena, stdio), so running the translator's
         * own atexit/flush teardown hangs or crashes intermittently.
         * The guest already ran its own exit handlers; the translator
         * holds no buffered guest output. */
        if (nr == (uint32_t)MIPS32_NR_exit && ctx->is_thread_clone) {
            mips_thread_exit(ctx, (int)(status & 0xFFU));
            return sc_ret(ctx, 0); /* unreachable */
        }
        /* Wave C2 --cache cold emit: persist noted DBT blocks before
         * the group teardown (silent best-effort; CLONE_VM threads
         * took the mips_thread_exit path above). */
        mips32_aot_flush(ctx);
#if defined(__linux__) && defined(SYS_exit_group)
        (void)syscall(SYS_exit_group, (int)(status & 0xFFU));
#else
        _Exit((int)(status & 0xFFU));
#endif
        return sc_ret(ctx, 0); /* unreachable */
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
    case MIPS32_NR_cacheflush: {
        uint32_t addr = o32_arg(ctx, sp, 0, &ok);
        uint32_t len  = o32_arg(ctx, sp, 1, &ok);
        if (!ok) {
            return sc_ret(ctx, -EFAULT);
        }
        if (len != 0U && mips32_dbt_invalidate_range != NULL) {
            uint64_t end64 = (uint64_t)addr + (uint64_t)len;

            if (end64 > 0xFFFFFFFFULL) {
                mips32_dbt_invalidate_range(ctx, addr, 0U);
            } else {
                mips32_dbt_invalidate_range(ctx, addr, (uint32_t)end64);
            }
        }
        return sc_ret(ctx, 0);
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
    /* Phase 4 (lane L4c): process lifecycle in proc.c (vfork has no
     * O32 number; it arrives via the L4b clone path). */
    case MIPS32_NR_fork:
        return mips_proc_fork(ctx, sp);
    case MIPS32_NR_execve:
        return mips_proc_execve(ctx, sp);
    case MIPS32_NR_wait4:
        return mips_proc_wait4(ctx, sp);
    case MIPS32_NR_waitpid:
        return mips_proc_waitpid(ctx, sp);
    /* Phase 4 (lane L4b): CLONE_VM-family threads live in threads.c. */
    case MIPS32_NR_clone:
        return mips_sc_clone(ctx, sp);
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
    case MIPS32_NR_getpid:
    case MIPS32_NR_getppid:
    case MIPS32_NR_getuid:
    case MIPS32_NR_geteuid:
    case MIPS32_NR_getgid:
    case MIPS32_NR_getegid:
    case MIPS32_NR_getrandom:
    case MIPS32_NR_futex:
    case MIPS32_NR_rt_sigprocmask:
    case MIPS32_NR_rt_sigaction:
    case MIPS32_NR_rt_sigreturn:
    case MIPS32_NR_sigaltstack:
    case MIPS32_NR_set_robust_list:
    case MIPS32_NR_get_robust_list:
    case MIPS32_NR_unlink:
    case MIPS32_NR_unlinkat:
    case MIPS32_NR_truncate:
    case MIPS32_NR_ftruncate:
    case MIPS32_NR_truncate64:
    case MIPS32_NR_ftruncate64:
        return mips_syscall_extra(ctx, sp);
    case MIPS32_NR_SYSMIPS: {
        /* sysmips(cmd, arg): only MIPS_FIXADE is emulated. */
        uint32_t cmd = o32_arg(ctx, sp, 0, &ok);
        uint32_t arg = o32_arg(ctx, sp, 1, &ok);

        if (!ok) {
            return sc_ret(ctx, -EFAULT);
        }
        if (cmd != (uint32_t)MIPS32_SYSMIPS_FIXADE) {
            return sc_ret(ctx, -(int32_t)ENOSYS);
        }
        ctx->fixade_enabled = (arg != 0U) ? 1u : 0u;
        return sc_ret(ctx, 0);
    }
    /* Wave C2: kill-class self-delivery (raise/tgkill path). */
    case (uint32_t)MIPS32_NR_kill:
    case (uint32_t)MIPS32_NR_TKILL:
    case (uint32_t)MIPS32_NR_TGKILL:
        return mips_sc_kill(ctx, sp);
    case (uint32_t)MIPS32_NR_GETTID: {
        /* O32 gettid: the main thread is the group leader (host gettid
         * == host getpid); clone threads cached their host tid at
         * spawn (threads.c). glibc raise() needs this for tgkill. */
        long tid;
#if defined(__linux__) && defined(SYS_gettid)
        if (ctx->is_thread_clone && ctx->host_tid != 0) {
            tid = (long)ctx->host_tid;
        } else {
            tid = syscall(SYS_gettid);
        }
#else
        tid = (long)getpid();
#endif
        return sc_ret(ctx, (int32_t)tid);
    }
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
