/*
 * src/dbt/trace.c — --trace/--difftest block-trace replay (Wave C2).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Split out of src/dbt/dbt.c (file-size discipline): replays the
 * "I <tid> %08x %08x" fetch lines the interpreter prints, so
 * interp-vs-dbt traces compare equal instruction by instruction
 * (the harness demultiplexes the hosting-tid field per thread).
 *
 * Blocks normally run to their exit, so replaying [start, end) prints
 * exactly the interpreter's fetches.  Mid-block redirects need a
 * tighter bound, anchored at ctx->pc (every redirect stub records
 * the fault site there: emit_sync_pc, emit_align_fault,
 * emit_cond_fault, emit_exit_imm, the FP trap):
 *
 * - FAULT/TRAP (delivery, no re-execution): replay through the
 *   faulting fetch (what the interpreter printed before faulting).
 *   A delayed-branch fault site covers its slot too.
 * - SINGLE_STEP/UNDEF (interp_step fallback): replay up to but not
 *   including the declined insn; the fallback prints it itself via
 *   fetch_decode (branch and slot for a delayed decline).
 * - Converted host faults (dbt_trace_converted_fault, called from
 *   mips_hostfault_run before delivery) take the FAULT bound; the
 *   dispatcher skips these blocks (it continues before tracing), so
 *   without the hook every converted guest fault diverges.
 *
 * Pure C11.  Never touches x18.
 */

#include "mips32rt.h"

#include "dbt/dbt.h"
#include "os/syscalls_priv.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

/* Range replay with fetch-break (unmapped words stop the replay). */
static void trace_range(mips32_ctx_t *ctx, uint32_t start, uint32_t limit)
{
    uint32_t p;

    for (p = start; p < limit; p += 4U) {
        uint32_t word = 0U;

        if (mips_fetch(ctx, p, &word) != 0) {
            break;
        }
        /* Wave C2: hosting-tid attribution lets the difftest harness
         * compare per-thread streams (scheduling order varies). */
        (void)fprintf(stderr, "I %08lx %08x %08x\n",
                      (unsigned long)mips_trace_tid(), p, word);
    }
}

/* True when the word is a control transfer with a delay slot (the slot
 * executes before any redirect takes effect, so the interpreter prints
 * both fetches).  J/JAL, Bcond/BcondL, REGIMM branches (rt 0-3 and
 * 0x10-0x13; trap immediates have no delay slot), JR/JALR, BCzF/BCzT. */
static int has_delay_slot(uint32_t word)
{
    uint32_t op = word >> 26;

    if (op == 2U || op == 3U) {
        return 1;
    }
    if (op == 4U || op == 5U || op == 6U || op == 7U) {
        return 1;
    }
    if (op == 20U || op == 21U || op == 22U || op == 23U) {
        return 1;
    }
    if (op == 1U) {
        /* M32-R8-6: REGIMM links (BLTZAL/BGEZAL/BLTZALL/BGEZALL,
         * rt 0x10-0x13) have delay slots, like rt 0-3. */
        uint32_t rt = (word >> 16) & 31U;

        return rt <= 3U || (rt >= 0x10U && rt <= 0x13U);
    }
    if (op == 0U) {
        uint32_t funct = word & 63U;

        return funct == 8U || funct == 9U;
    }
    if (op == 16U || op == 17U) {
        uint32_t rs = (word >> 21) & 31U;

        return rs >= 8U && rs <= 11U;
    }
    return 0;
}

/* Replay bound for a mid-block redirect: [start, bound). Inclusion
 * covers the redirecting fetch (fault/trap delivery prints nothing
 * itself); exclusion leaves it to the interp_step fallback. Falls
 * back to the block end when pc is not anchored inside the block. */
static uint32_t replay_bound(mips32_ctx_t *ctx, uint32_t start,
    uint32_t end, int include_site)
{
    uint32_t pc = ctx->pc;
    uint32_t bound;

    if (pc < start || pc >= end) {
        return end;
    }
    if (!include_site) {
        return pc;
    }
    bound = pc + 4U;
    {
        uint32_t word = 0U;

        if (mips_fetch(ctx, pc, &word) == 0 && has_delay_slot(word)) {
            bound = pc + 8U;
        }
    }
    return (bound > end) ? end : bound;
}

void dbt_trace_block(mips32_ctx_t *ctx, const dbt_block_t *b)
{
    uint32_t start;
    uint32_t end;

    if (ctx == NULL || b == NULL) {
        return;
    }
    start = b->guest_pc;
    end = b->guest_end;
    switch (ctx->exit_reason) {
    case MIPS32_EXIT_FAULT:
    case MIPS32_EXIT_TRAP:
        trace_range(ctx, start, replay_bound(ctx, start, end, 1));
        return;
    case MIPS32_EXIT_SINGLE_STEP:
    case MIPS32_EXIT_UNDEF:
        trace_range(ctx, start, replay_bound(ctx, start, end, 0));
        return;
    case MIPS32_EXIT_BRANCH:
        if (ctx->exit_info == 1U && end >= start + 4U) {
            trace_range(ctx, start, end - 4U);
            return;
        }
        break;
    default:
        break;
    }
    trace_range(ctx, start, end);
}

void dbt_trace_converted_fault(mips32_ctx_t *ctx)
{
    const dbt_block_t *blocks = NULL;
    size_t count;
    uint32_t fpc;
    size_t i;

    if (ctx == NULL || ctx->trace_enabled == 0) {
        return;
    }
    count = dbt_trace_table(&blocks);
    if (blocks == NULL) {
        return;
    }
    fpc = ctx->pc;
    for (i = 0; i < count; i++) {
        uint32_t start = blocks[i].guest_pc;
        uint32_t end = blocks[i].guest_end;

        if (fpc < start || fpc >= end) {
            continue;
        }
        trace_range(ctx, start, replay_bound(ctx, start, end, 1));
        return;
    }
}
