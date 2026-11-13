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
#include "interp/decode.h"
#include "os/syscalls_priv.h"

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

int mips_trace_insn(uint32_t pc, uint32_t word)
{
    static __thread long last_tid = 0;
    static __thread uint32_t emitted = 0U;
    static int cap_init = 0;
    static int cap_on = 0;
    long tid = mips_trace_tid();

    if (!cap_init) {
        cap_on = (getenv("MIPS32RT_DUMPSTATE") != NULL) ? 1 : 0;
        cap_init = 1;
    }
    if (tid != last_tid) {
        last_tid = tid;
        emitted = 0U;
    }
    if (cap_on && emitted >= 250000U) {
        return 1;
    }
    emitted++;
    (void)fprintf(stderr, "I %08lx %08x %08x\n",
                  (unsigned long)tid, pc, word);
    return 0;
}

/* Range replay with fetch-break (unmapped words stop the replay). */
static void trace_range(mips32_ctx_t *ctx, uint32_t start, uint32_t limit)
{
    uint32_t p;

    for (p = start; p < limit; p += 4U) {
        uint32_t word = 0U;

        if (mips_fetch(ctx, p, &word) != 0) {
            break;
        }
        if (mips_trace_insn(p, word) != 0) {
            break;
        }
    }
}

/* Delay-slot predicate, unified with the interp classifier
 * (M32-R13-7): decode once and ask mips_has_delay_slot instead of
 * maintaining a duplicate opcode switch. */
static int has_delay_slot(uint32_t word)
{
    mips_dec_t d;

    mips_decode(word, &d);
    return mips_has_delay_slot(&d);
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
        trace_range(ctx, start, replay_bound(ctx, start, end, 1));
        return;
    case MIPS32_EXIT_SINGLE_STEP:
    case MIPS32_EXIT_UNDEF:
    case MIPS32_EXIT_TRAP:
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
