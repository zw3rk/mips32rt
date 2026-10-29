/*
 * src/dbt/emit_fp_priv.h — Shared internals of the AArch64 FPU emitter.
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Split from src/dbt/emit_fp.c (line-limit split, no behavior change):
 * float<->integer conversions live in src/dbt/emit_fp_cvt.c while
 * arithmetic/compare/move emission stays in src/dbt/emit_fp.c.  Both
 * translation units share the helpers declared below.
 */

#ifndef MIPS32RT_EMIT_FP_PRIV_H
#define MIPS32RT_EMIT_FP_PRIV_H

#include <stddef.h>
#include <stdint.h>

#include "mips32rt.h"
#include "rt32/a64_emit.h"
#include "interp/decode.h"

/* COP1 fmt (rs) selectors. */
#define FP_FMT_S 16U
#define FP_FMT_D 17U
#define FP_FMT_W 18U
#define FP_FMT_L 19U

/* COP1 move/branch (rs) selectors. */
#define FP_RS_MFC1 0U
#define FP_RS_DMFC1 1U
#define FP_RS_CFC1 2U
#define FP_RS_MFHC1 3U
#define FP_RS_MTC1 4U
#define FP_RS_DMTC1 5U
#define FP_RS_CTC1 6U
#define FP_RS_MTHC1 7U

/* COP1 arithmetic funct selectors (fmt S/D). */
#define FP_FUNCT_ADD 0x00U
#define FP_FUNCT_SUB 0x01U
#define FP_FUNCT_MUL 0x02U
#define FP_FUNCT_DIV 0x03U
#define FP_FUNCT_SQRT 0x04U
#define FP_FUNCT_ABS 0x05U
#define FP_FUNCT_MOV 0x06U
#define FP_FUNCT_NEG 0x07U
#define FP_FUNCT_ROUND 0x0CU
#define FP_FUNCT_TRUNC 0x0DU
#define FP_FUNCT_CEIL 0x0EU
#define FP_FUNCT_FLOOR 0x0FU
#define FP_FUNCT_CVT_S 0x20U
#define FP_FUNCT_CVT_D 0x21U
#define FP_FUNCT_CVT_W 0x24U
#define FP_FUNCT_CVT_L 0x25U

/* FCSR field positions (SPEC 2.1, E03 6). */
#define FP_FCSR_CAUSE_MASK 0x1F000U
#define FP_FCSR_ENABLE_SHIFT 7U
#define FP_FCSR_E_BIT (1U << 17)

/* FCSR fast-path mask (Wave P lane P4): FS (bit 24), Enable (11:7) and
 * RM (1:0).  Sticky Cause/Flags bits are deliberately EXCLUDED: masking
 * them in would pin the slow path after the first inexact operation. */
#define FP_FCSR_FAST_MASK 0x01000F83U

/* Scratch for the pre-quiet sNaN sticky bit (Wave P lane P4): W25.
 * W15 is NOT usable here: it caches guest $ra (kFpGprHost[31]). */
#define FP_STICKY 25U

/* Raw op emitters (src/dbt/emit_fp.c). */
void fp_emit1(a64_buf_t *b, unsigned ptype, unsigned op5, unsigned opc6,
              unsigned vd, unsigned vn);
void fp_cvt(a64_buf_t *b, unsigned sf, unsigned ptype, unsigned sub,
            unsigned rd, unsigned rn);

/* FPR file access (src/dbt/emit_fp.c). */
uint32_t fp_slot(unsigned fs);
unsigned fp_get(a64_buf_t *b, unsigned g, unsigned tmp);
void fp_ld(a64_buf_t *b, unsigned vd, unsigned fs, int be, unsigned is_d);
void fp_st(a64_buf_t *b, unsigned vd, unsigned fs, int be, unsigned is_d);
/* Single-precision FPR writes (src/dbt/emit_fp_cvt.c): fp_store_w
 * stores a W conversion result to an FPR low half, and
 * fp_invalidate_single drops the cached copies a single-precision
 * write to fs invalidates (the same-reg entry plus the pair double
 * (fs & ~1u), covering odd/even aliasing). */
void fp_store_w(a64_buf_t *b, unsigned wsrc, uint32_t off, int be);
void fp_invalidate_single(a64_buf_t *b, unsigned fs);

/* FPCR/FPSR sync + finish (src/dbt/emit_fp.c). */
void fp_fpcr_sync(a64_buf_t *b);
void fp_fpcr_restore(a64_buf_t *b);
void fp_fpsr_clear(a64_buf_t *b);
void fp_fpsr_read(a64_buf_t *b, unsigned wdst);
void fp_finish(a64_buf_t *b, unsigned wfpsr5, uint32_t cur);

/* Legacy-NaN pre/post steps (src/dbt/emit_fp.c). */
void fp_quiet(a64_buf_t *b, unsigned vd, unsigned wsticky, unsigned is_d);
void fp_quiet_reg(a64_buf_t *b, unsigned vd, unsigned greg, unsigned wsticky,
                  unsigned is_d);
void fp_fix(a64_buf_t *b, unsigned vd, unsigned is_d);

/* Conversion ops (src/dbt/emit_fp_cvt.c). */
int fp_to_int_op(a64_buf_t *b, const mips_dec_t *d, uint32_t cur, int be);
int fp_cvt_float_op(a64_buf_t *b, const mips_dec_t *d, uint32_t cur, int be,
                    int nan2008, unsigned is_d);
int fp_from_int_op(a64_buf_t *b, const mips_dec_t *d, uint32_t cur, int be,
                   unsigned is_d);

#endif /* MIPS32RT_EMIT_FP_PRIV_H */
