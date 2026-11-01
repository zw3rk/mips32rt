/*
 * src/dbt/aot_emit.c — guest-run AOT cache emit/reload hooks (Wave C2).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Implements src/dbt/aot_emit.h on top of the file-cache writer/reader
 * (src/dbt/aot/aot.c).  The note buffer records guest ranges only (no
 * host code addresses: the file survives process restart and PIE/ASLR
 * rebasing by construction).  Records are metadata-only (code_len 0;
 * the writer persists header + block records, never host code bytes),
 * so warm reload revalidates the file and re-executes through the
 * normal JIT path — output identity, not a translation counter, is
 * the observable cache contract.
 *
 * Threading: one note buffer per host thread (CLONE_VM threads compile
 * into their own DBT caches); the exit_group flush persists the
 * calling thread's buffer, which owns the main-thread blocks.  Every
 * hook is silent: failures behave exactly like --cache not passed.
 *
 * Pure C11.  Never touches x18.
 */

#include "dbt/aot_emit.h"

#include "dbt/aot/aot.h"

#include <stddef.h>
#include <stdio.h>

/* Cap: the file writer holds MIPS32_AOT_MAX_BLOCKS records. */
#define AOT_NOTE_MAX 4096u

static __thread uint32_t aot_note_pc[AOT_NOTE_MAX];
static __thread uint32_t aot_note_end[AOT_NOTE_MAX];
static __thread uint32_t aot_note_count;

void mips32_aot_note_block(mips32_ctx_t *ctx, uint32_t guest_pc,
    uint32_t guest_end)
{
    uint32_t n;

    if (ctx == NULL || ctx->cache_dir == NULL ||
        ctx->cache_dir[0] == '\0') {
        return;
    }
    n = aot_note_count;
    if (n >= AOT_NOTE_MAX) {
        return;
    }
    aot_note_pc[n] = guest_pc;
    aot_note_end[n] = guest_end;
    aot_note_count = n + 1u;
}

void mips32_aot_flush(mips32_ctx_t *ctx)
{
    mips32_aot_writer_t *w = NULL;
    uint32_t is_be;
    uint32_t i;

    if (ctx == NULL || ctx->cache_dir == NULL ||
        ctx->cache_dir[0] == '\0') {
        return;
    }
    if (ctx->engine != MIPS32_ENGINE_DBT || aot_note_count == 0u) {
        return;
    }
    is_be = (uint32_t)mips_is_be(ctx);
    if (mips32_aot_writer_open(ctx->cache_dir, is_be, &w) != 0 ||
        w == NULL) {
        return;
    }
    for (i = 0u; i < aot_note_count; i++) {
        /* Metadata-only record: guest range with no host payload
         * (code_len 0).  The writer persists the record, never code. */
        if (mips32_aot_writer_add_block(w, aot_note_pc[i],
                aot_note_end[i], NULL, 0u, NULL, 0u, 0u) != 0) {
            break;
        }
    }
    {
        char path[MIPS32_AOT_MAX_PATH];

        (void)mips32_aot_writer_finish(w, path, sizeof(path));
    }
}

void mips32_aot_warm(mips32_ctx_t *ctx)
{
    char path[MIPS32_AOT_MAX_PATH];
    mips32_aot_block_rec_t rec;
    int n;

    if (ctx == NULL || ctx->cache_dir == NULL ||
        ctx->cache_dir[0] == '\0') {
        return;
    }
    if (ctx->engine != MIPS32_ENGINE_DBT) {
        return;
    }
    n = snprintf(path, sizeof(path), "%s/mips32rt-aot-v1-%s.bin",
        ctx->cache_dir, (mips_is_be(ctx) != 0) ? "be" : "le");
    if (n <= 0 || (size_t)n >= sizeof(path)) {
        return;
    }
    /* Best-effort validation (magic, version, entry block present):
     * any failure silently runs the guest cold. */
    (void)mips32_aot_lookup(path, ctx->elf_entry, &rec);
}
