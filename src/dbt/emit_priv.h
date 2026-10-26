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
                        int be);
void emit_ll(a64_buf_t *b, const mips_dec_t *d, uint32_t fpc, int be,
             int ind_slot);
void emit_sc(a64_buf_t *b, const mips_dec_t *d, uint32_t fpc, int be,
             int ind_slot);

#endif /* MIPS32RT_EMIT_PRIV_H */
