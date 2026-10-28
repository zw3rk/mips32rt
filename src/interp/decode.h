/*
 * src/interp/decode.h — MIPS32r2 instruction decoder interface (lane L1a).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Re-exports the frozen decoder contract from src/mips32rt.h
 * (mips_dec_t, mips_decode, mips_fetch) and adds pure instruction
 * classifiers used by the interpreter (lane L1b) and later the DBT.
 * All classifiers are pure: they inspect only the decoded fields.
 */

#ifndef MIPS32RT_INTERP_DECODE_H
#define MIPS32RT_INTERP_DECODE_H

#include "mips32rt.h"

/* Major opcodes (bits 31..26). */
#define MIPS_OP_SPECIAL 0x00U
#define MIPS_OP_REGIMM  0x01U
#define MIPS_OP_J       0x02U
#define MIPS_OP_JAL     0x03U
#define MIPS_OP_BEQ     0x04U
#define MIPS_OP_BNE     0x05U
#define MIPS_OP_BLEZ    0x06U
#define MIPS_OP_BGTZ    0x07U
#define MIPS_OP_ADDI    0x08U
#define MIPS_OP_ADDIU   0x09U
#define MIPS_OP_SLTI    0x0aU
#define MIPS_OP_SLTIU   0x0bU
#define MIPS_OP_ANDI    0x0cU
#define MIPS_OP_ORI     0x0dU
#define MIPS_OP_XORI    0x0eU
#define MIPS_OP_LUI     0x0fU
#define MIPS_OP_COP0    0x10U
#define MIPS_OP_COP1    0x11U
#define MIPS_OP_BEQL    0x14U
#define MIPS_OP_BNEL    0x15U
#define MIPS_OP_BLEZL   0x16U
#define MIPS_OP_BGTZL   0x17U
#define MIPS_OP_SPECIAL2 0x1cU
#define MIPS_OP_SPECIAL3 0x1fU /* RDHWR lives here (funct 0x3b) */
#define MIPS_OP_LB      0x20U
#define MIPS_OP_LH      0x21U
#define MIPS_OP_LWL     0x22U
#define MIPS_OP_LW      0x23U
#define MIPS_OP_LBU     0x24U
#define MIPS_OP_LHU     0x25U
#define MIPS_OP_LWR     0x26U
#define MIPS_OP_SB      0x28U
#define MIPS_OP_SH      0x29U
#define MIPS_OP_SWL     0x2aU
#define MIPS_OP_SW      0x2bU
#define MIPS_OP_SWR     0x2eU
#define MIPS_OP_LL      0x30U
#define MIPS_OP_SC      0x38U

/* REGIMM rt selectors (op == MIPS_OP_REGIMM). */
#define MIPS_REGIMM_BLTZ   0x00U
#define MIPS_REGIMM_BGEZ   0x01U
#define MIPS_REGIMM_BLTZL  0x02U
#define MIPS_REGIMM_BGEZL  0x03U
#define MIPS_REGIMM_BLTZAL 0x10U
#define MIPS_REGIMM_BGEZAL 0x11U

/* SPECIAL funct selectors (op == MIPS_OP_SPECIAL). */
#define MIPS_FUNCT_SLL   0x00U
#define MIPS_FUNCT_SRL   0x02U
#define MIPS_FUNCT_SRA   0x03U
#define MIPS_FUNCT_JR    0x08U
#define MIPS_FUNCT_JALR  0x09U
#define MIPS_FUNCT_SYSCALL 0x0cU
#define MIPS_FUNCT_BREAK 0x0dU
#define MIPS_FUNCT_MFHI  0x10U
#define MIPS_FUNCT_MTHI  0x11U
#define MIPS_FUNCT_MFLO  0x12U
#define MIPS_FUNCT_MTLO  0x13U
#define MIPS_FUNCT_MULT  0x18U
#define MIPS_FUNCT_MULTU 0x19U
#define MIPS_FUNCT_DIV   0x1aU
#define MIPS_FUNCT_DIVU  0x1bU
#define MIPS_FUNCT_ADD   0x20U
#define MIPS_FUNCT_ADDU  0x21U
#define MIPS_FUNCT_SUB   0x22U
#define MIPS_FUNCT_AND   0x24U
#define MIPS_FUNCT_OR    0x25U
#define MIPS_FUNCT_XOR   0x26U
#define MIPS_FUNCT_NOR   0x27U
#define MIPS_FUNCT_SLT   0x2aU
#define MIPS_FUNCT_SLTU  0x2bU

/* COP1 branch sub-opcodes: op == MIPS_OP_COP1, rs == 8 (BC).
 * Values are raw rt bits: bit0 = tf (T/F), bit1 = nd (likely),
 * bits[4:2] = cc (GAS: bc1t -> rt=1, bc1fl -> rt=2). */
#define MIPS_COP1_RS_BC  8U
#define MIPS_COP1_BC1F   0x00U
#define MIPS_COP1_BC1T   0x01U
#define MIPS_COP1_BC1FL  0x02U
#define MIPS_COP1_BC1TL  0x03U

/*
 * Pure classifiers.  Each returns nonzero when the decoded instruction
 * belongs to the named class, zero otherwise (including a null pointer).
 */
int mips_is_branch(const mips_dec_t *d);
int mips_is_branch_likely(const mips_dec_t *d);
int mips_is_jump(const mips_dec_t *d);
int mips_is_link(const mips_dec_t *d);
int mips_has_delay_slot(const mips_dec_t *d);

#endif /* MIPS32RT_INTERP_DECODE_H */
