/*
 * src/dbt/emit_priv.h — Shared internals of the AArch64 integer emitter.
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Split from src/dbt/emit_int.c (line-limit split, no behavior change):
 * the memory subsystem lives in src/dbt/emit_mem.c while ALU/branch
 * emission stays in src/dbt/emit_int.c.  Both translation units share
 * the register-cache helpers and the C-tail field accessors below.
 */

#ifndef MIPS32RT_EMIT_PRIV_H
#define MIPS32RT_EMIT_PRIV_H

#include <stddef.h>
#include <stdint.h>

#include "mips32rt.h"
#include "rt32/a64_emit.h"
#include "interp/decode.h"

/* C-tail ctx fields beyond the LDR/STR imm12 reach (see mips32rt.h):
 * emitters materialize the offset and add it to x19 (xCtx). */
#define EMIT_FIXADE_OFFSET ((uint32_t)offsetof(mips32_ctx_t, fixade_enabled))
#define EMIT_DELAY_TARGET_OFFSET \
    ((uint32_t)offsetof(mips32_ctx_t, delay_target))
/* RC-U3-R2/R3 LL epoch snapshot: the full 64-bit generation in
 * ctx->ll_epoch_snap (struct tail; see src/os/mem.c). */
#define EMIT_LL_SEQ_OFFSET ((uint32_t)offsetof(mips32_ctx_t, ll_epoch_snap))
_Static_assert(offsetof(mips32_ctx_t, ll_epoch_snap) % 8u == 0u,
    "ll_epoch_snap must be 8-byte aligned for LDR Xt");
/* NOTE: the offset exceeds the 12-bit unsigned LDR range; emitters
 * materialize it with mov_imm32 + base add (see emit_epoch_record),
 * never as an immediate offset. */
/* Guest VA of the shared 32 KiB epoch table (G-relative, unmappable:
 * above MIPS32_TASK_SIZE_TOP).  JIT forms Xtab = x20 + (OFF + idx*8). */
#define EMIT_LL_EPOCH_OFFSET 0xFFFF0000u
/* Guest VA of the 64-bit LL exclusion spinlock: the first word after
 * the epoch table. JIT forms Xlock = x20 + LOCK_OFF. */
#define EMIT_LL_LOCK_OFFSET (0xFFFF0000u + 4096u * 8u)

/* Register-cache core (src/dbt/emit_int.c). */
int      gpr_host(unsigned g);
unsigned op_val(a64_buf_t *b, unsigned g, unsigned tmp);
unsigned op_sp(a64_buf_t *b, unsigned g, unsigned tmp);
void     put_rd(a64_buf_t *b, unsigned g, unsigned src);
void     emit_flush(a64_buf_t *b);
/* Load ctx->delay_target (JR/JALR recovery) into dst. */
void     emit_load_delay_target(a64_buf_t *b, unsigned dst);

/* Memory subsystem (src/dbt/emit_mem.c).  EA lands in w22 (A64_ADDR);
 * ind_slot is nonzero for JR/JALR delay slots (next_pc recovers from
 * ctx->delay_target instead of fpc + 4 on fault exits). */
void emit_ea(a64_buf_t *b, unsigned rs, int32_t simm);
void emit_mem_aligned(a64_buf_t *b, const mips_dec_t *d, uint32_t fpc,
                      int be, int ind_slot);
void emit_mem_unaligned(a64_buf_t *b, const mips_dec_t *d, uint32_t fpc,
                        int be, int ind_slot);
void emit_ll(a64_buf_t *b, const mips_dec_t *d, uint32_t fpc, int be,
             int ind_slot);
void emit_sc(a64_buf_t *b, const mips_dec_t *d, uint32_t fpc, int be,
             int ind_slot);

#endif /* MIPS32RT_EMIT_PRIV_H */
