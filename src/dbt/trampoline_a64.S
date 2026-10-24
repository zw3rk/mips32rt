/* src/dbt/trampoline_a64.S — DBT host entry/exit gate (AArch64, Phase 2 L2b)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Host entry point for translated blocks.  Saves the callee-saved
 * registers it repurposes, installs the SPEC 2.1 fixed registers
 * (x19 = ctx, x20 = G), calls the block, then records the block's exit
 * reason/info into ctx and returns the reason.  Never reads or writes
 * x18 (platform-reserved).
 */

.text
.p2align 2
.globl dbt_trampoline_enter

/* uint32_t dbt_trampoline_enter(mips32_ctx_t *ctx, void *code);
 * x0 = ctx, x1 = block entry.
 * Block ABI: entry with x19 = ctx, x20 = G; exit with w0 = exit reason
 * (MIPS32_EXIT_*), w1 = exit info, ctx->pc already advanced.  The block
 * preserves x19/x20/x29; all other AAPCS callee-saved state is owned
 * here. */
dbt_trampoline_enter:
    stp x29, x30, [sp, #-16]!
    stp x19, x20, [sp, #-16]!
    stp x21, x22, [sp, #-16]!
    stp x23, x24, [sp, #-16]!
    stp x25, x26, [sp, #-16]!
    stp x27, x28, [sp, #-16]!
    mov x19, x0
    ldr x20, [x0, #0x0a8]       /* ctx->guest_base (SPEC 2.1 xG) */
    blr x1
    str w0, [x19, #0x0b8]       /* ctx->exit_reason */
    str w1, [x19, #0x0bc]       /* ctx->exit_info */
    ldp x27, x28, [sp], #16
    ldp x25, x26, [sp], #16
    ldp x23, x24, [sp], #16
    ldp x21, x22, [sp], #16
    ldp x19, x20, [sp], #16
    ldp x29, x30, [sp], #16
    ret
