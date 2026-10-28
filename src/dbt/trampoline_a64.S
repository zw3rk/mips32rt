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
 *
 * Wave P lane P4: in-trampoline block chaining.  After each block
 * returns (its epilogue already flushed cached GPRs w0-w15 to ctx->r[]
 * and advanced ctx->pc), the trampoline chains directly to the next
 * block without returning to mips_hostfault_run: callee-saved x23
 * carries the current/next block entry across the loop (including
 * across the validated C lookup, which preserves it), and w24 is the
 * 4096-block chain budget.  w24 is reloaded from a trampoline stack
 * slot every iteration because emitted blocks freely clobber it; the
 * slot itself survives (blocks and the lookup never touch trampoline
 * stack memory).  Only EXIT_NONE/EXIT_BRANCH chain; the validated
 * lookup exits the chain under --difftest/--trace (block-lockstep
 * parity) and on uncompiled targets.  The budget bounds async-signal
 * and quiescence latency.
 */

.text
.p2align 2
#ifdef __APPLE__
.globl _dbt_trampoline_enter
#endif
.globl dbt_trampoline_enter

/* uint32_t dbt_trampoline_enter(mips32_ctx_t *ctx, void *code);
 * x0 = ctx, x1 = block entry.
 * Block ABI: entry with x19 = ctx, x20 = G; exit with w0 = exit reason
 * (MIPS32_EXIT_*), w1 = exit info, ctx->pc already advanced.  The block
 * preserves x19/x20/x29; all other AAPCS callee-saved state is owned
 * here. */
#ifdef __APPLE__
_dbt_trampoline_enter:
#endif
dbt_trampoline_enter:
    stp x29, x30, [sp, #-16]!
    stp x19, x20, [sp, #-16]!
    stp x21, x22, [sp, #-16]!
    stp x23, x24, [sp, #-16]!
    stp x25, x26, [sp, #-16]!
    stp x27, x28, [sp, #-16]!
    sub sp, sp, #16
    mov x19, x0
    ldr x20, [x0, #0x0a8]       /* ctx->guest_base (SPEC 2.1 xG) */
    mov x23, x1                 /* x23 = current block entry */
    movz w24, #4096
    str w24, [sp]               /* chain budget slot */
    b .Lchain_enter
.Lchain_next:
    ldr w24, [sp]
    cbz w24, .Lchain_done       /* budget exhausted: w0 holds reason */
    sub w24, w24, #1
    str w24, [sp]
    mov x0, x19                 /* ctx (x19/x20 survive the call) */
#ifdef __APPLE__
    bl _dbt_chain_next
#else
    bl dbt_chain_next
#endif
    cbz x0, .Lchain_done_reload /* NULL: reason already stored; reload */
    mov x23, x0                 /* x23 = next block entry */
.Lchain_enter:
    blr x23
    str w0, [x19, #0x0b8]       /* ctx->exit_reason */
    str w1, [x19, #0x0bc]       /* ctx->exit_info */
    cmp w0, #1
    b.ls .Lchain_next           /* chain EXIT_NONE(0)/EXIT_BRANCH(1) */
.Lchain_done:
    add sp, sp, #16
    ldp x27, x28, [sp], #16
    ldp x25, x26, [sp], #16
    ldp x23, x24, [sp], #16
    ldp x21, x22, [sp], #16
    ldp x19, x20, [sp], #16
    ldp x29, x30, [sp], #16
    ret
.Lchain_done_reload:
    ldr w0, [x19, #0x0b8]       /* last stored reason (call clobbered w0) */
    b .Lchain_done
