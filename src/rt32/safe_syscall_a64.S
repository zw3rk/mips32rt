/* src/rt32/safe_syscall_a64.S — D18 signal-window host syscall gate (Linux AArch64)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Race-free commit point for host syscalls issued on behalf of the guest:
 * the generation counter is checked with an acquire load immediately
 * before the SVC, so a host signal handler can tell "interrupted before
 * the commit" (PC in [window_begin, post_svc) -> redirect to abort,
 * returning -EINTR) from "interrupted after" (completed result wins and
 * is never replaced).  Frameless: a redirect to the abort label returns
 * through the caller's LR.  Do not move either post-SVC label into a
 * recovery interval, and never read or write x18 here.
 */

.text
.p2align 2
.globl mips32_safe_syscall6
.globl mips32_safe_syscall_window_begin
.globl mips32_safe_syscall_post_svc
.globl mips32_safe_syscall_abort

/* long mips32_safe_syscall6(long nr, const long args[6],
 *                           const _Atomic uint32_t *gen, uint32_t expected);
 * x0 = nr, x1 = args, x2 = gen, x3 = expected (w).  Returns the raw
 * kernel result (negative errno style, as from SVC). */
mips32_safe_syscall6:
mips32_safe_syscall_window_begin:
    ldar w9, [x2]
    cmp w9, w3
    b.ne mips32_safe_syscall_abort
    mov x8, x0                  /* syscall number */
    mov x9, x1                  /* args pointer (gen value no longer needed) */
    ldp x0, x1, [x9, #0]
    ldp x2, x3, [x9, #16]
    ldp x4, x5, [x9, #32]
    svc #0
mips32_safe_syscall_post_svc:
    ret
mips32_safe_syscall_abort:
    mov x0, #-4                 /* -EINTR: interrupted before the commit */
    ret
