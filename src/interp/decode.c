/*
 * src/interp/decode.c — MIPS32r2 instruction decoder (lane L1a).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * mips_decode is a pure field splitter: it fills every mips_dec_t field
 * from the raw word and touches no other state.  mips_fetch loads the
 * word at guest pc through the frozen guest_ld32 contract (lane L1c owns
 * the memory window) and reports MIPS_FAULT on a bad pc.
 */

#include "interp/decode.h"

#include <sys/mman.h>

void mips_decode(uint32_t word, mips_dec_t *d)
{
    uint16_t imm;

    if (d == NULL) {
        return;
    }
    imm = (uint16_t)(word & 0xffffU);
    d->word = word;
    d->op = (uint8_t)((word >> 26) & 0x3fU);
    d->rs = (uint8_t)((word >> 21) & 0x1fU);
    d->rt = (uint8_t)((word >> 16) & 0x1fU);
    d->rd = (uint8_t)((word >> 11) & 0x1fU);
    d->sa = (uint8_t)((word >> 6) & 0x1fU);
    d->funct = (uint8_t)(word & 0x3fU);
    d->imm = imm;
    d->target = word & 0x03ffffffU;
    d->simm = (int32_t)(int16_t)imm;
    d->uimm = (uint32_t)imm;
}

/*
 * Pending lane L1c fallback: guest_ld32 is declared by the frozen header
 * but defined by src/os/mem.c, which is not on master yet.  This weak
 * definition keeps translation units that call mips_fetch linkable until
 * L1c lands; the strong L1c definition overrides it at RC1 merge time.
 * Fetch self-tests stay deferred until then (see tests/test_decode.c).
 */
int __attribute__((weak)) guest_ld32(mips32_ctx_t *ctx, uint32_t va,
    uint32_t *out)
{
    (void)ctx;
    (void)va;
    (void)out;
    return MIPS_FAULT;
}

/* Range check lives in src/os/syscalls.c (declared in
 * src/os/syscalls_priv.h); interp/ never includes os-private headers,
 * so declare it here like the guest_ld32 fallback above. */
extern int mips_sc_range_ok(const mips32_ctx_t *ctx, uint32_t va,
    uint32_t len, uint32_t need);

int mips_fetch(mips32_ctx_t *ctx, uint32_t pc, uint32_t *word)
{
    if (ctx == NULL || word == NULL) {
        return MIPS_FAULT;
    }
    if ((pc & 3U) != 0U) {
        return MIPS_FAULT;
    }
    /* W^X: the host never executes guest bytes, but executing from a
     * non-executable guest page must still fault (PROT_EXEC required;
     * PROT_NONE and RW pages trap here, reported as ACCERR). */
    if (!mips_sc_range_ok(ctx, pc, 4U, (uint32_t)PROT_EXEC)) {
        return MIPS_FAULT;
    }
    return guest_ld32(ctx, pc, word);
}

static int is_regimm_branch(uint8_t rt)
{
    return rt == MIPS_REGIMM_BLTZ || rt == MIPS_REGIMM_BGEZ ||
        rt == MIPS_REGIMM_BLTZL || rt == MIPS_REGIMM_BGEZL ||
        rt == MIPS_REGIMM_BLTZAL || rt == MIPS_REGIMM_BGEZAL ||
        rt == MIPS_REGIMM_BLTZALL || rt == MIPS_REGIMM_BGEZALL;
}

int mips_is_branch(const mips_dec_t *d)
{
    if (d == NULL) {
        return 0;
    }
    switch (d->op) {
    case MIPS_OP_BEQ:
    case MIPS_OP_BNE:
    case MIPS_OP_BLEZ:
    case MIPS_OP_BGTZ:
    case MIPS_OP_BEQL:
    case MIPS_OP_BNEL:
    case MIPS_OP_BLEZL:
    case MIPS_OP_BGTZL:
        return 1;
    case MIPS_OP_REGIMM:
        return is_regimm_branch(d->rt);
    case MIPS_OP_COP1:
        return d->rs == MIPS_COP1_RS_BC && d->rt <= MIPS_COP1_BC1TL;
    default:
        return 0;
    }
}

int mips_is_branch_likely(const mips_dec_t *d)
{
    if (d == NULL) {
        return 0;
    }
    switch (d->op) {
    case MIPS_OP_BEQL:
    case MIPS_OP_BNEL:
    case MIPS_OP_BLEZL:
    case MIPS_OP_BGTZL:
        return 1;
    case MIPS_OP_REGIMM:
        return d->rt == MIPS_REGIMM_BLTZL || d->rt == MIPS_REGIMM_BGEZL ||
            d->rt == MIPS_REGIMM_BLTZALL || d->rt == MIPS_REGIMM_BGEZALL;
    case MIPS_OP_COP1:
        return d->rs == MIPS_COP1_RS_BC &&
            (d->rt == MIPS_COP1_BC1FL || d->rt == MIPS_COP1_BC1TL);
    default:
        return 0;
    }
}

int mips_is_jump(const mips_dec_t *d)
{
    if (d == NULL) {
        return 0;
    }
    if (d->op == MIPS_OP_J || d->op == MIPS_OP_JAL) {
        return 1;
    }
    return d->op == MIPS_OP_SPECIAL &&
        (d->funct == MIPS_FUNCT_JR || d->funct == MIPS_FUNCT_JALR);
}

int mips_is_link(const mips_dec_t *d)
{
    if (d == NULL) {
        return 0;
    }
    if (d->op == MIPS_OP_JAL) {
        return 1;
    }
    if (d->op == MIPS_OP_SPECIAL && d->funct == MIPS_FUNCT_JALR) {
        return 1;
    }
    return d->op == MIPS_OP_REGIMM &&
        (d->rt == MIPS_REGIMM_BLTZAL || d->rt == MIPS_REGIMM_BGEZAL ||
         d->rt == MIPS_REGIMM_BLTZALL || d->rt == MIPS_REGIMM_BGEZALL);
}

int mips_is_ras_call(const mips_dec_t *d)
{
    if (d == NULL) {
        return 0;
    }
    if (d->op == MIPS_OP_JAL) {
        return 1;
    }
    if (d->op == MIPS_OP_SPECIAL && d->funct == MIPS_FUNCT_JALR &&
        d->rd == MIPS32_REG_RA) {
        return 1;
    }
    return d->op == MIPS_OP_REGIMM &&
        (d->rt == MIPS_REGIMM_BLTZAL || d->rt == MIPS_REGIMM_BGEZAL ||
         d->rt == MIPS_REGIMM_BLTZALL || d->rt == MIPS_REGIMM_BGEZALL);
}

int mips_has_delay_slot(const mips_dec_t *d)
{
    if (d == NULL) {
        return 0;
    }
    return mips_is_branch(d) || mips_is_jump(d);
}
