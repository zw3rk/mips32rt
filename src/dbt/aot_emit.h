/*
 * src/dbt/aot_emit.h — guest-run AOT cache emit/reload hooks (Wave C2).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Lane-internal header (not a frozen contract): connects the DBT
 * dispatcher (src/dbt/dbt.c) and the guest exit path
 * (src/os/syscall_min.c) to the file-cache writer/reader
 * (src/dbt/aot/aot.c) behind the user-visible --cache DIR option
 * (ctx->cache_dir, --cache / MIPS32RT_CACHE).
 *
 * Cold emit: dbt_compile records every published block's guest range;
 * the exit/exit_group path flushes the note buffer to
 * <dir>/mips32rt-aot-v1-{le,be}.bin (magic MIPS32_AOT_MAGIC).
 * Warm reload: dbt_main validates the cache file (magic, version,
 * entry block) and runs the guest; execution stays JIT-correct by
 * construction, so the parity gate compares cold vs warm guest stdout
 * for byte identity (same contract as ppc64rt's aot_reload row).
 *
 * All three hooks are silent best-effort: any failure (missing dir,
 * corrupt file, interp engine, empty note buffer) runs the guest
 * exactly as if --cache had not been passed.  Pure C11.
 */

#ifndef MIPS32RT_DBT_AOT_EMIT_H
#define MIPS32RT_DBT_AOT_EMIT_H

#include <stdint.h>

#include "mips32rt.h"

/* Record one published DBT block (called from dbt_compile). */
void mips32_aot_note_block(mips32_ctx_t *ctx, uint32_t guest_pc,
    uint32_t guest_end);

/* Flush noted blocks to the cache file (called on guest exit_group). */
void mips32_aot_flush(mips32_ctx_t *ctx);

/* Validate an existing cache file (called at dbt_main entry). */
void mips32_aot_warm(mips32_ctx_t *ctx);

#endif /* MIPS32RT_DBT_AOT_EMIT_H */
