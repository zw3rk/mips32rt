/*
 * tests/test_p1_isa.h — Shared declarations for Phase 1 ISA test suite
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef MIPS32_TEST_P1_ISA_H
#define MIPS32_TEST_P1_ISA_H

#define PAGE 4096u

/* O32 syscall numbers (arch/mips, __NR_Linux base 4000). */
#define NR_EXIT 4001
#define NR_WRITE 4004
#define NR_SET_THREAD_AREA 4283

void p1_check(const char *name, int cond, const char *detail);
long p1_raw_sys3(long num, long a0, long a1, long a2, int *pa3);

void t_llsc(void);
void t_unaligned(void);
void t_rdhwr(void);
void t_unaligned_child(void);
void t_raw_write(void);

#endif /* MIPS32_TEST_P1_ISA_H */
