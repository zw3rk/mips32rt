/*
 * tests/test_decode.c — Table-driven self-test for mips_decode (lane L1a).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Host-native test: fixed instruction words map to expected decoded
 * fields.  Every field of mips_dec_t is asserted for every case.
 * mips_fetch is NOT exercised here: the guest window (guest_mem_init,
 * guest_ld32) is owned by lane L1c and not on master yet, so fetch
 * checks stay deferred to the RC1 gate.
 */

#include <stdio.h>

#include "mips32rt.h"
#include "interp/decode.h"

/* Link stub: this self-test only exercises mips_decode (pure); the
 * mips_fetch range check lives in the syscall layer (src/os/syscalls.c)
 * and is covered by the run_p6 parity gates, not here. */
int mips_sc_range_ok(const mips32_ctx_t *ctx, uint32_t va, uint32_t len,
                     uint32_t need)
{
    (void)ctx;
    (void)va;
    (void)len;
    (void)need;
    return 1;
}

typedef struct {
    const char *name;
    uint32_t word;
    uint8_t op;
    uint8_t rs;
    uint8_t rt;
    uint8_t rd;
    uint8_t sa;
    uint8_t funct;
    uint16_t imm;
    uint32_t target;
    int32_t simm;
    uint32_t uimm;
} decode_case_t;

static const decode_case_t cases[] = {
    /* SPECIAL (op 0). */
    { "nop", 0x00000000U, 0, 0, 0, 0, 0, 0x00, 0x0000, 0x0000000U, 0, 0U },
    { "sll", 0x00094100U, 0, 0, 9, 8, 4, 0x00, 0x4100, 0x0094100U, 16640, 16640U },
    { "add", 0x012a4020U, 0, 9, 10, 8, 0, 0x20, 0x4020, 0x012a4020U, 16416, 16416U },
    { "jr", 0x03e00008U, 0, 31, 0, 0, 0, 0x08, 0x0008, 0x03e00008U, 8, 8U },
    { "syscall", 0x0000000cU, 0, 0, 0, 0, 0, 0x0c, 0x000c, 0x000000cU, 12, 12U },
    { "mult", 0x00220018U, 0, 1, 2, 0, 0, 0x18, 0x0018, 0x0220018U, 24, 24U },
    { "mfhi", 0x00004010U, 0, 0, 0, 8, 0, 0x10, 0x4010, 0x0004010U, 16400, 16400U },
    { "break", 0x0000000dU, 0, 0, 0, 0, 0, 0x0d, 0x000d, 0x000000dU, 13, 13U },
    { "addu", 0x00430821U, 0, 2, 3, 1, 0, 0x21, 0x0821, 0x0430821U, 2081, 2081U },
    { "srl", 0x000521c2U, 0, 0, 5, 4, 7, 0x02, 0x21c2, 0x00521c2U, 8642, 8642U },
    /* REGIMM (op 1). */
    { "bltz", 0x04800010U, 1, 4, 0, 0, 0, 0x10, 0x0010, 0x0800010U, 16, 16U },
    { "bgez", 0x04a1fffcU, 1, 5, 1, 31, 31, 0x3c, 0xfffc, 0x00a1fffcU, -4, 65532U },
    { "bltzal", 0x04d01234U, 1, 6, 16, 2, 8, 0x34, 0x1234, 0x0d01234U, 4660, 4660U },
    { "bgezl-regimm", 0x04e3ffffU, 1, 7, 3, 31, 31, 0x3f, 0xffff, 0x00e3ffffU, -1, 65535U },
    /* Jumps. */
    { "j", 0x08100000U, 2, 0, 16, 0, 0, 0x00, 0x0000, 0x0100000U, 0, 0U },
    { "jal", 0x0fffffffU, 3, 31, 31, 31, 31, 0x3f, 0xffff, 0x3ffffffU, -1, 65535U },
    /* Branches. */
    { "beq", 0x10850064U, 4, 4, 5, 0, 1, 0x24, 0x0064, 0x0850064U, 100, 100U },
    { "bne", 0x14c7ff9cU, 5, 6, 7, 31, 30, 0x1c, 0xff9c, 0x00c7ff9cU, -100, 65436U },
    { "blez", 0x19007fffU, 6, 8, 0, 15, 31, 0x3f, 0x7fff, 0x1007fffU, 32767, 32767U },
    { "bgtz", 0x1d208000U, 7, 9, 0, 16, 0, 0x00, 0x8000, 0x1208000U, -32768, 32768U },
    { "beql", 0x514b0001U, 20, 10, 11, 0, 0, 0x01, 0x0001, 0x14b0001U, 1, 1U },
    { "bnel", 0x558dfffeU, 21, 12, 13, 31, 31, 0x3e, 0xfffe, 0x018dfffeU, -2, 65534U },
    { "blezl", 0x59c0abcdU, 22, 14, 0, 21, 15, 0x0d, 0xabcd, 0x1c0abcdU, -21555, 43981U },
    { "bgtzl", 0x5de00000U, 23, 15, 0, 0, 0, 0x00, 0x0000, 0x1e00000U, 0, 0U },
    /* Immediates. */
    { "addi", 0x20a4ffffU, 8, 5, 4, 31, 31, 0x3f, 0xffff, 0x00a4ffffU, -1, 65535U },
    { "addiu", 0x24e67fffU, 9, 7, 6, 15, 31, 0x3f, 0x7fff, 0x00e67fffU, 32767, 32767U },
    { "slti", 0x29288000U, 10, 9, 8, 16, 0, 0x00, 0x8000, 0x01288000U, -32768, 32768U },
    { "andi", 0x316aabcdU, 12, 11, 10, 21, 15, 0x0d, 0xabcd, 0x016aabcdU, -21555, 43981U },
    { "ori", 0x35ac1234U, 13, 13, 12, 2, 8, 0x34, 0x1234, 0x01ac1234U, 4660, 4660U },
    { "xori", 0x39ee0000U, 14, 15, 14, 0, 0, 0x00, 0x0000, 0x01ee0000U, 0, 0U },
    { "lui", 0x3c041234U, 15, 0, 4, 2, 8, 0x34, 0x1234, 0x00041234U, 4660, 4660U },
    /* Loads/stores. */
    { "lw", 0x8d28fff8U, 35, 9, 8, 31, 31, 0x38, 0xfff8, 0x0128fff8U, -8, 65528U },
    { "sw", 0xad6a0010U, 43, 11, 10, 0, 0, 0x10, 0x0010, 0x016a0010U, 16, 16U },
    { "lb", 0x81ac0001U, 32, 13, 12, 0, 0, 0x01, 0x0001, 0x01ac0001U, 1, 1U },
    { "lbu", 0x91ee00ffU, 36, 15, 14, 0, 3, 0x3f, 0x00ff, 0x01ee00ffU, 255, 255U },
    { "sb", 0xa0410000U, 40, 2, 1, 0, 0, 0x00, 0x0000, 0x00410000U, 0, 0U },
    { "lwl", 0x88a40003U, 34, 5, 4, 0, 0, 0x03, 0x0003, 0x00a40003U, 3, 3U },
    { "lwr", 0x98e60007U, 38, 7, 6, 0, 0, 0x07, 0x0007, 0x00e60007U, 7, 7U },
    { "ll", 0xc1280000U, 48, 9, 8, 0, 0, 0x00, 0x0000, 0x01280000U, 0, 0U },
    { "sc", 0xe16a0000U, 56, 11, 10, 0, 0, 0x00, 0x0000, 0x016a0000U, 0, 0U },
    /* COP0 / RDHWR. */
    { "mfc0", 0x40086000U, 16, 0, 8, 12, 0, 0x00, 0x6000, 0x00086000U, 24576, 24576U },
    { "rdhwr", 0x7c08e83bU, 31, 0, 8, 29, 0, 0x3b, 0xe83b, 0x008e83bU, -6085, 59451U },
    /* COP1. */
    { "mfc1", 0x44084800U, 17, 0, 8, 9, 0, 0x00, 0x4800, 0x00084800U, 18432, 18432U },
    { "bc1t", 0x45020005U, 17, 8, 2, 0, 0, 0x05, 0x0005, 0x01020005U, 5, 5U },
    { "bc1fl", 0x4501fff8U, 17, 8, 1, 31, 31, 0x38, 0xfff8, 0x0101fff8U, -8, 65528U }
};

#define N_CASES (sizeof(cases) / sizeof(cases[0]))

typedef struct {
    const char *name;
    size_t index;
    int is_branch;
    int is_likely;
    int is_jump;
    int is_link;
} class_case_t;

static const class_case_t class_cases[] = {
    { "nop", 0, 0, 0, 0, 0 },
    { "add", 2, 0, 0, 0, 0 },
    { "jr", 3, 0, 0, 1, 0 },
    { "bltz", 10, 1, 0, 0, 0 },
    { "bltzal", 12, 1, 0, 0, 1 },
    { "j", 14, 0, 0, 1, 0 },
    { "jal", 15, 0, 0, 1, 1 },
    { "beq", 16, 1, 0, 0, 0 },
    { "bne", 17, 1, 0, 0, 0 },
    { "beql", 20, 1, 1, 0, 0 },
    { "blezl", 22, 1, 1, 0, 0 },
    { "addi", 24, 0, 0, 0, 0 },
    { "lw", 31, 0, 0, 0, 0 },
    { "mfc0", 40, 0, 0, 0, 0 },
    { "rdhwr", 41, 0, 0, 0, 0 },
    { "mfc1", 42, 0, 0, 0, 0 },
    { "bc1t", 43, 1, 0, 0, 0 },
    { "bc1fl", 44, 1, 1, 0, 0 }
};

#define N_CLASS (sizeof(class_cases) / sizeof(class_cases[0]))

static int failures;

static void check_field(const char *name, const char *field,
    unsigned long got, unsigned long want)
{
    if (got != want) {
        printf("FAIL %s: %s got %lu want %lu\n", name, field, got, want);
        failures++;
    }
}

static void check_case(const decode_case_t *c)
{
    mips_dec_t d;

    mips_decode(c->word, &d);
    check_field(c->name, "word", (unsigned long)d.word, (unsigned long)c->word);
    check_field(c->name, "op", (unsigned long)d.op, (unsigned long)c->op);
    check_field(c->name, "rs", (unsigned long)d.rs, (unsigned long)c->rs);
    check_field(c->name, "rt", (unsigned long)d.rt, (unsigned long)c->rt);
    check_field(c->name, "rd", (unsigned long)d.rd, (unsigned long)c->rd);
    check_field(c->name, "sa", (unsigned long)d.sa, (unsigned long)c->sa);
    check_field(c->name, "funct", (unsigned long)d.funct, (unsigned long)c->funct);
    check_field(c->name, "imm", (unsigned long)d.imm, (unsigned long)c->imm);
    check_field(c->name, "target", (unsigned long)d.target, (unsigned long)c->target);
    if (d.simm != c->simm) {
        printf("FAIL %s: simm got %d want %d\n", c->name, (int)d.simm, (int)c->simm);
        failures++;
    }
    check_field(c->name, "uimm", (unsigned long)d.uimm, (unsigned long)c->uimm);
}

int main(void)
{
    size_t i;

    failures = 0;
    for (i = 0; i < N_CASES; i++) {
        check_case(&cases[i]);
    }
    for (i = 0; i < N_CLASS; i++) {
        const class_case_t *c = &class_cases[i];
        mips_dec_t d;
        int want_slot;

        mips_decode(cases[c->index].word, &d);
        if (!!mips_is_branch(&d) != c->is_branch) {
            printf("FAIL %s: is_branch got %d want %d\n",
                c->name, !!mips_is_branch(&d), c->is_branch);
            failures++;
        }
        if (!!mips_is_branch_likely(&d) != c->is_likely) {
            printf("FAIL %s: is_branch_likely got %d want %d\n",
                c->name, !!mips_is_branch_likely(&d), c->is_likely);
            failures++;
        }
        if (!!mips_is_jump(&d) != c->is_jump) {
            printf("FAIL %s: is_jump got %d want %d\n",
                c->name, !!mips_is_jump(&d), c->is_jump);
            failures++;
        }
        if (!!mips_is_link(&d) != c->is_link) {
            printf("FAIL %s: is_link got %d want %d\n",
                c->name, !!mips_is_link(&d), c->is_link);
            failures++;
        }
        want_slot = (c->is_branch || c->is_jump) ? 1 : 0;
        if (!!mips_has_delay_slot(&d) != want_slot) {
            printf("FAIL %s: has_delay_slot got %d want %d\n",
                c->name, !!mips_has_delay_slot(&d), want_slot);
            failures++;
        }
    }
    /* Null-pointer safety: decoders and classifiers must not crash. */
    mips_decode(0x00000000U, NULL);
    if (mips_is_branch(NULL) != 0 || mips_is_branch_likely(NULL) != 0 ||
        mips_is_jump(NULL) != 0 || mips_is_link(NULL) != 0 ||
        mips_has_delay_slot(NULL) != 0) {
        printf("FAIL null: classifier on NULL did not return 0\n");
        failures++;
    }

    if (failures != 0) {
        printf("DECODE: %d failure(s)\n", failures);
        return 1;
    }
    printf("DECODE: all %lu cases + %lu classifier checks passed\n",
        (unsigned long)N_CASES, (unsigned long)N_CLASS);
    printf("FETCH: DEFERRED (guest window owned by lane L1c, not on master)\n");
    return 0;
}
