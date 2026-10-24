/*
 * src/interp/interp.c — MIPS32r2 integer reference interpreter (Phase 1).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Step-by-step oracle for the SPEC 2 integer subset: ALU/shifts, MULT/DIV
 * via hi/lo, branches with delay slots and likely-annul, J/JAL/JR/JALR
 * (ra = pc+8), SYSCALL via the L1c dispatcher, BREAK/traps via mips_fault,
 * aligned loads/stores, LWL/LWR/SWL/SWR per E05, LL/SC, RDHWR $29 and
 * MFC0/DMFC0 ulr alias, CACHE/PREF/SYNCI as NOP.  FP/COP1/COP2 and unknown
 * encodings fault; $0 stays 0; syscall exits clear llbit.
 */

#include <stdint.h>
#include <stdio.h>

#include "mips32rt.h"
#include "interp/fp.h"
#include "interp/interp.h"

static int exec_branch(mips32_ctx_t *ctx, uint32_t pc, const mips_dec_t *d);

static int fault_at(mips32_ctx_t *ctx, uint32_t addr)
{
    if (ctx->trace_enabled) {
        (void)fprintf(stderr, "F %08x at %08x\n", ctx->pc, addr);
    }
    mips_fault(ctx, addr);
    return MIPS_FAULT;
}

/* Fetch and decode the word at pc; fault when the fetcher did not. */
static int fetch_decode(mips32_ctx_t *ctx, uint32_t pc, mips_dec_t *d)
{
    uint32_t word = 0u;

    if (mips_fetch(ctx, pc, &word) != 0) {
        if (ctx->exit_reason == MIPS32_EXIT_NONE) {
            mips_fault(ctx, pc);
        }
        return MIPS_FAULT;
    }
    if (ctx->trace_enabled) {
        (void)fprintf(stderr, "I %08x %08x\n", pc, word);
    }
    mips_decode(word, d);
    return 0;
}

static uint32_t clz32(uint32_t x)
{
    uint32_t n = 0u;
    uint32_t bit = 0x80000000u;

    while (bit != 0u && (x & bit) == 0u) {
        n++;
        bit >>= 1;
    }
    return n;
}

static uint32_t rot_right(uint32_t v, unsigned n)
{
    n &= 31u;
    if (n == 0u) {
        return v;
    }
    return (v >> n) | (v << ((32u - n) & 31u));
}

/* SYSCALL: clears llbit; dispatcher owns $v0/$a3 writeback (including
 * legitimate nonzero guest results like brk addresses and byte counts).
 * The dispatcher's int32 return is opaque here: guest-visible errors are
 * already in $v0/$a3.  Returns 0 (caller advances pc), 2 (dispatcher
 * moved pc: keep it), 1 (stop). */
static int exec_syscall(mips32_ctx_t *ctx)
{
    uint32_t before = ctx->pc;

    ctx->llbit = 0;
    (void)mips_syscall(ctx);
    if (ctx->exit_reason != MIPS32_EXIT_NONE) {
        return 1;
    }
    return (ctx->pc != before) ? 2 : 0;
}

/* Signed ADD/SUB overflow probes without signed UB (uint32 arithmetic). */
static int add_overflows(uint32_t a, uint32_t b, uint32_t s)
{
    return (((a ^ s) & (b ^ s)) & 0x80000000u) != 0u;
}

static int sub_overflows(uint32_t a, uint32_t b, uint32_t d)
{
    return (((a ^ b) & (a ^ d)) & 0x80000000u) != 0u;
}

/* Execute one non-control instruction; callers advance ctx->pc except
 * for exec_syscall's dispatcher-moved-pc case (returns 2). */
static int exec_special(mips32_ctx_t *ctx, uint32_t cur_pc, const mips_dec_t *d)
{
    uint32_t rs = ctx->gpr[d->rs];
    uint32_t rt = ctx->gpr[d->rt];
    uint32_t out;

    switch (d->funct) {
    case 0x00u: /* SLL */
        interp_set_reg(ctx, d->rd, rt << (d->sa & 31u));
        return 0;
    case 0x02u: /* SRL / ROR (rs == 1 selects ROR) */
        if (d->rs == 1u) {
            interp_set_reg(ctx, d->rd, rot_right(rt, d->sa));
        } else {
            interp_set_reg(ctx, d->rd, rt >> (d->sa & 31u));
        }
        return 0;
    case 0x03u: /* SRA */
        interp_set_reg(ctx, d->rd,
                       (uint32_t)((int32_t)rt >> (d->sa & 31u)));
        return 0;
    case 0x04u: /* SLLV */
        interp_set_reg(ctx, d->rd, rt << (rs & 31u));
        return 0;
    case 0x06u: /* SRLV / RORV (sa == 1 selects RORV) */
        if (d->sa == 1u) {
            interp_set_reg(ctx, d->rd, rot_right(rt, rs));
        } else {
            interp_set_reg(ctx, d->rd, rt >> (rs & 31u));
        }
        return 0;
    case 0x07u: /* SRAV */
        interp_set_reg(ctx, d->rd, (uint32_t)((int32_t)rt >> (rs & 31u)));
        return 0;
    case 0x08u: /* JR */
    case 0x09u: /* JALR */
        return exec_branch(ctx, cur_pc, d);
    case 0x0Au: /* MOVZ */
        if (rt == 0u) {
            interp_set_reg(ctx, d->rd, rs);
        }
        return 0;
    case 0x0Bu: /* MOVN */
        if (rt != 0u) {
            interp_set_reg(ctx, d->rd, rs);
        }
        return 0;
    case 0x0Cu: /* SYSCALL */
        return exec_syscall(ctx);
    case 0x0Du: /* BREAK */
    case 0x3Fu: /* SDBBP */
        return fault_at(ctx, cur_pc);
    case 0x0Fu: /* SYNC */
        return 0;
    case 0x10u: /* MFHI */
        interp_set_reg(ctx, d->rd, ctx->hi);
        return 0;
    case 0x11u: /* MTHI */
        ctx->hi = rs;
        return 0;
    case 0x12u: /* MFLO */
        interp_set_reg(ctx, d->rd, ctx->lo);
        return 0;
    case 0x13u: /* MTLO */
        ctx->lo = rs;
        return 0;
    case 0x18u: /* MULT */
        {
            int64_t p = (int64_t)(int32_t)rs * (int64_t)(int32_t)rt;
            ctx->lo = (uint32_t)p;
            ctx->hi = (uint32_t)((uint64_t)p >> 32);
        }
        return 0;
    case 0x19u: /* MULTU */
        {
            uint64_t p = (uint64_t)rs * (uint64_t)rt;
            ctx->lo = (uint32_t)p;
            ctx->hi = (uint32_t)(p >> 32);
        }
        return 0;
    case 0x1Au: /* DIV: divide-by-zero leaves hi/lo unchanged */
        if (rt != 0u) {
            int64_t q = (int64_t)(int32_t)rs / (int64_t)(int32_t)rt;
            int64_t r = (int64_t)(int32_t)rs % (int64_t)(int32_t)rt;
            ctx->lo = (uint32_t)(int32_t)q;
            ctx->hi = (uint32_t)(int32_t)r;
        }
        return 0;
    case 0x1Bu: /* DIVU: divide-by-zero leaves hi/lo unchanged */
        if (rt != 0u) {
            ctx->lo = rs / rt;
            ctx->hi = rs % rt;
        }
        return 0;
    case 0x20u: /* ADD */
        out = rs + rt;
        if (add_overflows(rs, rt, out)) {
            return fault_at(ctx, cur_pc);
        }
        interp_set_reg(ctx, d->rd, out);
        return 0;
    case 0x21u: /* ADDU */
        interp_set_reg(ctx, d->rd, rs + rt);
        return 0;
    case 0x22u: /* SUB */
        out = rs - rt;
        if (sub_overflows(rs, rt, out)) {
            return fault_at(ctx, cur_pc);
        }
        interp_set_reg(ctx, d->rd, out);
        return 0;
    case 0x23u: /* SUBU */
        interp_set_reg(ctx, d->rd, rs - rt);
        return 0;
    case 0x24u: /* AND */
        interp_set_reg(ctx, d->rd, rs & rt);
        return 0;
    case 0x25u: /* OR */
        interp_set_reg(ctx, d->rd, rs | rt);
        return 0;
    case 0x26u: /* XOR */
        interp_set_reg(ctx, d->rd, rs ^ rt);
        return 0;
    case 0x27u: /* NOR */
        interp_set_reg(ctx, d->rd, ~(rs | rt));
        return 0;
    case 0x2Au: /* SLT */
        interp_set_reg(ctx, d->rd, (int32_t)rs < (int32_t)rt ? 1u : 0u);
        return 0;
    case 0x2Bu: /* SLTU */
        interp_set_reg(ctx, d->rd, rs < rt ? 1u : 0u);
        return 0;
    case 0x30u: /* TGE */
        return (int32_t)rs >= (int32_t)rt ? fault_at(ctx, cur_pc) : 0;
    case 0x31u: /* TGEU */
        return rs >= rt ? fault_at(ctx, cur_pc) : 0;
    case 0x32u: /* TLT */
        return (int32_t)rs < (int32_t)rt ? fault_at(ctx, cur_pc) : 0;
    case 0x33u: /* TLTU */
        return rs < rt ? fault_at(ctx, cur_pc) : 0;
    case 0x34u: /* TEQ */
        return rs == rt ? fault_at(ctx, cur_pc) : 0;
    case 0x36u: /* TNE */
        return rs != rt ? fault_at(ctx, cur_pc) : 0;
    default:
        return fault_at(ctx, cur_pc);
    }
}

static int exec_special2(mips32_ctx_t *ctx, uint32_t cur_pc,
                         const mips_dec_t *d)
{
    uint32_t rs = ctx->gpr[d->rs];
    uint32_t rt = ctx->gpr[d->rt];

    switch (d->funct) {
    case 0x00u: /* MADD */
        {
            int64_t acc = (int64_t)(((uint64_t)ctx->hi << 32) | ctx->lo);
            acc += (int64_t)(int32_t)rs * (int64_t)(int32_t)rt;
            ctx->lo = (uint32_t)(uint64_t)acc;
            ctx->hi = (uint32_t)((uint64_t)acc >> 32);
        }
        return 0;
    case 0x01u: /* MADDU */
        {
            uint64_t acc = ((uint64_t)ctx->hi << 32) | ctx->lo;
            acc += (uint64_t)rs * (uint64_t)rt;
            ctx->lo = (uint32_t)acc;
            ctx->hi = (uint32_t)(acc >> 32);
        }
        return 0;
    case 0x02u: /* MUL */
        {
            uint64_t p = (uint64_t)rs * (uint64_t)rt;
            interp_set_reg(ctx, d->rd, (uint32_t)p);
        }
        return 0;
    case 0x04u: /* MSUB */
        {
            int64_t acc = (int64_t)(((uint64_t)ctx->hi << 32) | ctx->lo);
            acc -= (int64_t)(int32_t)rs * (int64_t)(int32_t)rt;
            ctx->lo = (uint32_t)(uint64_t)acc;
            ctx->hi = (uint32_t)((uint64_t)acc >> 32);
        }
        return 0;
    case 0x05u: /* MSUBU */
        {
            uint64_t acc = ((uint64_t)ctx->hi << 32) | ctx->lo;
            acc -= (uint64_t)rs * (uint64_t)rt;
            ctx->lo = (uint32_t)acc;
            ctx->hi = (uint32_t)(acc >> 32);
        }
        return 0;
    case 0x20u: /* CLZ */
        interp_set_reg(ctx, d->rd, clz32(rs));
        return 0;
    case 0x21u: /* CLO */
        interp_set_reg(ctx, d->rd, clz32(~rs));
        return 0;
    default:
        return fault_at(ctx, cur_pc);
    }
}

/* EXT/INS/BSHFL/RDHWR (SPECIAL3, major opcode 0x1F). */
static int exec_special3(mips32_ctx_t *ctx, uint32_t cur_pc,
                         const mips_dec_t *d)
{
    uint32_t rs = ctx->gpr[d->rs];
    uint32_t rt = ctx->gpr[d->rt];

    switch (d->funct) {
    case 0x00u: /* EXT rt, rs: size = rd + 1 bits from lsb (rd holds
        * size-1, unlike INS where rd holds msb). */
        {
            unsigned lsb = d->sa & 31u;
            unsigned size = (unsigned)d->rd + 1u;
            uint64_t mask = (size >= 32u) ? (uint64_t)0xFFFFFFFFu :
                                            (((uint64_t)1u << size) - 1u);
            interp_set_reg(ctx, d->rt, (uint32_t)(((uint64_t)(rs >> lsb)) & mask));
        }
        return 0;
    case 0x04u: /* INS rt, rs, lsb, msb */
        {
            unsigned lsb = d->sa & 31u;
            unsigned msb = d->rd & 31u;
            unsigned size = (msb >= lsb) ? (msb - lsb + 1u) : 0u;
            uint64_t mask = (size >= 32u) ? (uint64_t)0xFFFFFFFFu :
                                            (((uint64_t)1u << size) - 1u);
            uint32_t field = (uint32_t)(((uint64_t)rs << lsb) & (mask << lsb));
            interp_set_reg(ctx, d->rt,
                           (uint32_t)((rt & ~((uint32_t)(mask << lsb))) | field));
        }
        return 0;
    case 0x20u: /* BSHFL: source is rt (rs is unused, always $0). */
        switch (d->sa) {
        case 2u: /* WSBH */
            interp_set_reg(ctx, d->rd,
                           ((rt & 0x00FF00FFu) << 8) | ((rt & 0xFF00FF00u) >> 8));
            return 0;
        case 16u: /* SEB */
            interp_set_reg(ctx, d->rd, (uint32_t)(int32_t)(int8_t)(rt & 0xFFu));
            return 0;
        case 24u: /* SEH */
            interp_set_reg(ctx, d->rd,
                           (uint32_t)(int32_t)(int16_t)(rt & 0xFFFFu));
            return 0;
        default:
            return fault_at(ctx, cur_pc);
        }
    case 0x3Bu: /* RDHWR rt, rd: rd selects, rt receives (MIPS32r2). */
        if (d->rd != MIPS32_RDHWR_ULR) {
            return fault_at(ctx, cur_pc);
        }
        interp_set_reg(ctx, d->rt, ctx->ulr);
        return 0;
    default:
        return fault_at(ctx, cur_pc);
    }
}

/* COP0: only MFC0/DMFC0 of the ulr alias (rd 4, sel 2) are wired. */
static int exec_cop0(mips32_ctx_t *ctx, uint32_t cur_pc, const mips_dec_t *d)
{
    if ((d->rs == 0u || d->rs == 1u) && d->rd == 4u &&
        (d->funct & 7u) == 2u) {
        interp_set_reg(ctx, d->rt, ctx->ulr);
        return 0;
    }
    return fault_at(ctx, cur_pc);
}

static int exec_regimm_trap(mips32_ctx_t *ctx, uint32_t cur_pc,
                            const mips_dec_t *d)
{
    uint32_t rs = ctx->gpr[d->rs];
    int32_t fire = 0;

    switch (d->rt) {
    case 0x08u: /* TGEI */
        fire = (int32_t)rs >= d->simm;
        break;
    case 0x09u: /* TGEIU */
        fire = rs >= (uint32_t)d->simm;
        break;
    case 0x0Au: /* TLTI */
        fire = (int32_t)rs < d->simm;
        break;
    case 0x0Bu: /* TLTIU */
        fire = rs < (uint32_t)d->simm;
        break;
    case 0x0Cu: /* TEQI */
        fire = (int32_t)rs == d->simm;
        break;
    case 0x0Eu: /* TNEI */
        fire = (int32_t)rs != d->simm;
        break;
    case 0x1Fu: /* SYNCI: cache maintenance hint, NOP here */
        return 0;
    default:
        return fault_at(ctx, cur_pc);
    }
    return fire ? fault_at(ctx, cur_pc) : 0;
}

static int exec_mem(mips32_ctx_t *ctx, uint32_t cur_pc, const mips_dec_t *d)
{
    uint32_t addr = ctx->gpr[d->rs] + (uint32_t)d->simm;
    uint32_t v = 0u;

    switch (d->op) {
    case 0x20u: /* LB */
        if (guest_ld8(ctx, addr, &v) != 0) {
            return fault_at(ctx, addr);
        }
        interp_set_reg(ctx, d->rt, (uint32_t)(int32_t)(int8_t)(v & 0xFFu));
        return 0;
    case 0x21u: /* LH */
        if ((addr & 1u) != 0u) {
            return fault_at(ctx, addr);
        }
        if (guest_ld16(ctx, addr, &v) != 0) {
            return fault_at(ctx, addr);
        }
        interp_set_reg(ctx, d->rt, (uint32_t)(int32_t)(int16_t)(v & 0xFFFFu));
        return 0;
    case 0x22u: /* LWL */
        return do_lwl(ctx, addr, d->rt);
    case 0x23u: /* LW */
        if ((addr & 3u) != 0u) {
            return fault_at(ctx, addr);
        }
        if (guest_ld32(ctx, addr, &v) != 0) {
            return fault_at(ctx, addr);
        }
        interp_set_reg(ctx, d->rt, v);
        return 0;
    case 0x24u: /* LBU */
        if (guest_ld8(ctx, addr, &v) != 0) {
            return fault_at(ctx, addr);
        }
        interp_set_reg(ctx, d->rt, v & 0xFFu);
        return 0;
    case 0x25u: /* LHU */
        if ((addr & 1u) != 0u) {
            return fault_at(ctx, addr);
        }
        if (guest_ld16(ctx, addr, &v) != 0) {
            return fault_at(ctx, addr);
        }
        interp_set_reg(ctx, d->rt, v & 0xFFFFu);
        return 0;
    case 0x26u: /* LWR */
        return do_lwr(ctx, addr, d->rt);
    case 0x28u: /* SB */
        if (guest_st8(ctx, addr, ctx->gpr[d->rt] & 0xFFu) != 0) {
            return fault_at(ctx, addr);
        }
        return 0;
    case 0x29u: /* SH */
        if ((addr & 1u) != 0u) {
            return fault_at(ctx, addr);
        }
        if (guest_st16(ctx, addr, ctx->gpr[d->rt] & 0xFFFFu) != 0) {
            return fault_at(ctx, addr);
        }
        return 0;
    case 0x2Au: /* SWL */
        return do_swl(ctx, addr, ctx->gpr[d->rt]);
    case 0x2Bu: /* SW */
        if ((addr & 3u) != 0u) {
            return fault_at(ctx, addr);
        }
        if (guest_st32(ctx, addr, ctx->gpr[d->rt]) != 0) {
            return fault_at(ctx, addr);
        }
        return 0;
    case 0x2Eu: /* SWR */
        return do_swr(ctx, addr, ctx->gpr[d->rt]);
    case 0x30u: /* LL */
        if ((addr & 3u) != 0u) {
            return fault_at(ctx, addr);
        }
        if (guest_ld32(ctx, addr, &v) != 0) {
            return fault_at(ctx, addr);
        }
        ctx->llbit = 1;
        ctx->lladdr = addr;
        ctx->llval = v;
        interp_set_reg(ctx, d->rt, v);
        return 0;
    case 0x38u: /* SC */
        if ((addr & 3u) != 0u) {
            return fault_at(ctx, addr);
        }
        if (guest_ld32(ctx, addr, &v) != 0) {
            return fault_at(ctx, addr);
        }
        if (ctx->llbit != 0u && ctx->lladdr == addr && v == ctx->llval) {
            if (guest_st32(ctx, addr, ctx->gpr[d->rt]) != 0) {
                return fault_at(ctx, addr);
            }
            interp_set_reg(ctx, d->rt, 1u);
        } else {
            interp_set_reg(ctx, d->rt, 0u);
        }
        ctx->llbit = 0;
        return 0;
    default:
        return fault_at(ctx, cur_pc);
    }
}

static int exec_simple(mips32_ctx_t *ctx, uint32_t cur_pc, const mips_dec_t *d)
{
    uint32_t rs;
    uint32_t out;

    switch (d->op) {
    case 0x00u: /* SPECIAL */
        return exec_special(ctx, cur_pc, d);
    case 0x01u: /* REGIMM traps / SYNCI (branches never reach here) */
        return exec_regimm_trap(ctx, cur_pc, d);
    case 0x08u: /* ADDI */
        rs = ctx->gpr[d->rs];
        out = rs + (uint32_t)d->simm;
        if (add_overflows(rs, (uint32_t)d->simm, out)) {
            return fault_at(ctx, cur_pc);
        }
        interp_set_reg(ctx, d->rt, out);
        return 0;
    case 0x09u: /* ADDIU */
        interp_set_reg(ctx, d->rt, ctx->gpr[d->rs] + (uint32_t)d->simm);
        return 0;
    case 0x0Au: /* SLTI */
        interp_set_reg(ctx, d->rt,
                       (int32_t)ctx->gpr[d->rs] < d->simm ? 1u : 0u);
        return 0;
    case 0x0Bu: /* SLTIU */
        interp_set_reg(ctx, d->rt,
                       ctx->gpr[d->rs] < (uint32_t)d->simm ? 1u : 0u);
        return 0;
    case 0x0Cu: /* ANDI */
        interp_set_reg(ctx, d->rt, ctx->gpr[d->rs] & d->uimm);
        return 0;
    case 0x0Du: /* ORI */
        interp_set_reg(ctx, d->rt, ctx->gpr[d->rs] | d->uimm);
        return 0;
    case 0x0Eu: /* XORI */
        interp_set_reg(ctx, d->rt, ctx->gpr[d->rs] ^ d->uimm);
        return 0;
    case 0x0Fu: /* LUI */
        interp_set_reg(ctx, d->rt, d->uimm << 16);
        return 0;
    case 0x10u: /* COP0 */
        return exec_cop0(ctx, cur_pc, d);
    case 0x1Cu: /* SPECIAL2 */
        return exec_special2(ctx, cur_pc, d);
    case 0x1Fu: /* SPECIAL3 */
        return exec_special3(ctx, cur_pc, d);
    case 0x20u: /* LB */
    case 0x21u: /* LH */
    case 0x22u: /* LWL */
    case 0x23u: /* LW */
    case 0x24u: /* LBU */
    case 0x25u: /* LHU */
    case 0x26u: /* LWR */
    case 0x28u: /* SB */
    case 0x29u: /* SH */
    case 0x2Au: /* SWL */
    case 0x2Bu: /* SW */
    case 0x2Eu: /* SWR */
    case 0x30u: /* LL */
    case 0x38u: /* SC */
        return exec_mem(ctx, cur_pc, d);
    case 0x31u: /* LWC1 */
    case 0x35u: /* LDC1 */
    case 0x39u: /* SWC1 */
    case 0x3Du: /* SDC1 */
        if (fpmove_mem(ctx, d) != 0) {
            return fault_at(ctx, cur_pc);
        }
        return 0;
    case 0x11u: /* COP1: moves via fpmove.c, arithmetic/BC1 via fp.c (L3a) */
        if (fpmove_cop1(ctx, d) != 0) {
            return fp_exec(ctx, cur_pc, d);
        }
        return 0;
    case 0x2Fu: /* CACHE */
    case 0x33u: /* PREF */
        return 0;
    default: /* COP2/COP1X, MIPS64, reserved */
        return fault_at(ctx, cur_pc);
    }
}

/* Control transfer with delay slot: link (ra = pc+8) first; likely
 * not-taken annuls the slot with no fetch of pc+4; otherwise the slot
 * runs with in_delay_slot = 1 and a fault there keeps pc at the branch
 * (SPEC 2.2).  A branch in the slot is undefined; the inner one wins. */
static int exec_branch(mips32_ctx_t *ctx, uint32_t pc, const mips_dec_t *d)
{
    uint32_t rs = ctx->gpr[d->rs];
    uint32_t rt = ctx->gpr[d->rt];
    uint32_t target = pc + 8u;
    unsigned link_rd = MIPS32_REG_RA;
    int link = 0;
    int likely = 0;
    int taken = 0;

    switch (d->op) {
    case 0x02u: /* J */
        taken = 1;
        target = ((pc + 4u) & 0xF0000000u) | (d->target << 2);
        break;
    case 0x03u: /* JAL */
        taken = 1;
        link = 1;
        target = ((pc + 4u) & 0xF0000000u) | (d->target << 2);
        break;
    case 0x04u: /* BEQ */
        taken = (rs == rt);
        target = pc + 4u + (uint32_t)(d->simm * 4);
        break;
    case 0x05u: /* BNE */
        taken = (rs != rt);
        target = pc + 4u + (uint32_t)(d->simm * 4);
        break;
    case 0x06u: /* BLEZ */
        taken = (int32_t)rs <= 0;
        target = pc + 4u + (uint32_t)(d->simm * 4);
        break;
    case 0x07u: /* BGTZ */
        taken = (int32_t)rs > 0;
        target = pc + 4u + (uint32_t)(d->simm * 4);
        break;
    case 0x14u: /* BEQL */
        likely = 1;
        taken = (rs == rt);
        target = pc + 4u + (uint32_t)(d->simm * 4);
        break;
    case 0x15u: /* BNEL */
        likely = 1;
        taken = (rs != rt);
        target = pc + 4u + (uint32_t)(d->simm * 4);
        break;
    case 0x16u: /* BLEZL */
        likely = 1;
        taken = (int32_t)rs <= 0;
        target = pc + 4u + (uint32_t)(d->simm * 4);
        break;
    case 0x17u: /* BGTZL */
        likely = 1;
        taken = (int32_t)rs > 0;
        target = pc + 4u + (uint32_t)(d->simm * 4);
        break;
    case 0x01u: /* REGIMM */
        target = pc + 4u + (uint32_t)(d->simm * 4);
        switch (d->rt) {
        case 0x00u: /* BLTZ */
            taken = (int32_t)rs < 0;
            break;
        case 0x01u: /* BGEZ */
            taken = (int32_t)rs >= 0;
            break;
        case 0x02u: /* BLTZL */
            likely = 1;
            taken = (int32_t)rs < 0;
            break;
        case 0x03u: /* BGEZL */
            likely = 1;
            taken = (int32_t)rs >= 0;
            break;
        case 0x10u: /* BLTZAL */
            link = 1;
            taken = (int32_t)rs < 0;
            break;
        case 0x11u: /* BGEZAL (BAL) */
            link = 1;
            taken = (int32_t)rs >= 0;
            break;
        case 0x12u: /* BLTZALL */
            link = 1;
            likely = 1;
            taken = (int32_t)rs < 0;
            break;
        case 0x13u: /* BGEZALL */
            link = 1;
            likely = 1;
            taken = (int32_t)rs >= 0;
            break;
        default:
            return fault_at(ctx, pc);
        }
        break;
    case 0x00u: /* JR / JALR */
        taken = 1;
        target = rs;
        if (d->funct == 0x09u) {
            link = 1;
            link_rd = d->rd;
        } else if (d->funct != 0x08u) {
            return fault_at(ctx, pc);
        }
        break;
    default:
        return fault_at(ctx, pc);
    }

    if (link) {
        interp_set_reg(ctx, link_rd, pc + 8u);
    }
    if (likely && !taken) {
        ctx->pc = pc + 8u;
        ctx->next_pc = pc + 12u;
        return 0;
    }
    ctx->in_delay_slot = 1;
    {
        mips_dec_t s;
        int rc;

        if (fetch_decode(ctx, pc + 4u, &s) != 0) {
            return MIPS_FAULT;
        }
        if (interp_is_control(&s)) {
            return exec_branch(ctx, pc + 4u, &s);
        }
        rc = exec_simple(ctx, pc + 4u, &s);
        if (rc == 0) {
            ctx->in_delay_slot = 0;
            ctx->pc = taken ? target : pc + 8u;
            ctx->next_pc = ctx->pc + 4u;
        } else if (rc == 2) {
            ctx->in_delay_slot = 0;
            rc = 0;
        }
        return rc;
    }
}

int interp_step(mips32_ctx_t *ctx)
{
    uint32_t pc = ctx->pc;
    mips_dec_t d;
    int rc;

    if (fetch_decode(ctx, pc, &d) != 0) {
        return MIPS_FAULT;
    }
    if (interp_is_control(&d)) {
        rc = exec_branch(ctx, pc, &d);
    } else {
        rc = exec_simple(ctx, pc, &d);
        if (rc == 0) {
            ctx->pc = pc + 4u;
            ctx->next_pc = pc + 8u;
        } else if (rc == 2) {
            ctx->next_pc = ctx->pc + 4u;
            rc = 0;
        }
    }
    if (rc == 0 && ctx->exit_reason != MIPS32_EXIT_NONE) {
        rc = 1;
    }
    return rc;
}

int interp_run(mips32_ctx_t *ctx)
{
    for (;;) {
        int rc = interp_step(ctx);
        if (rc != 0) {
            return rc;
        }
    }
}
