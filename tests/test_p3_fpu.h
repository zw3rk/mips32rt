/*
 * tests/test_p3_fpu.h — Shared declarations for Phase 3 FPU test suite
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef MIPS32_TEST_P3_FPU_H
#define MIPS32_TEST_P3_FPU_H

#include <stdint.h>
#include <string.h>

extern int g_nan2008;
extern uint32_t g_fcsr_reset;
extern int g_have_fpe;

void p3_check(const char *name, int cond, const char *detail);
int add_s_trap_test(uint32_t bits, uint32_t *res, uint32_t *fcsr);
int abs_s_trap_test(uint32_t bits, uint32_t *res, uint32_t *fcsr);

void t_trapctl(void);
void t_excepts(void);
void t_round_cvt(void);
void t_branch(void);
void t_moves(void);
void t_fcsr(void);
void t_mem(void);

static inline uint32_t f_bits(float f)
{
    uint32_t u;
    memcpy(&u, &f, sizeof u);
    return u;
}

static inline float u_float(uint32_t u)
{
    float f;
    memcpy(&f, &u, sizeof f);
    return f;
}

static inline uint64_t d_bits(double d)
{
    uint64_t u;
    memcpy(&u, &d, sizeof u);
    return u;
}

static inline double u_double(uint64_t u)
{
    double d;
    memcpy(&d, &u, sizeof d);
    return d;
}

static inline uint32_t read_fcsr(void)
{
    uint32_t v;
    __asm__ volatile("cfc1 %0, $31" : "=r"(v));
    return v;
}

static inline void write_fcsr(uint32_t v)
{
    __asm__ volatile("ctc1 %0, $31" : : "r"(v));
}

static inline uint32_t read_fir(void)
{
    uint32_t v;
    __asm__ volatile("cfc1 %0, $0" : "=r"(v));
    return v;
}

static inline float op_div_s(float a, float b)
{
    float r;
    __asm__ volatile("div.s %0, %1, %2" : "=f"(r) : "f"(a), "f"(b));
    return r;
}

static inline float op_mul_s(float a, float b)
{
    float r;
    __asm__ volatile("mul.s %0, %1, %2" : "=f"(r) : "f"(a), "f"(b));
    return r;
}

static inline double op_div_d(double a, double b)
{
    double r;
    __asm__ volatile("div.d %0, %1, %2" : "=f"(r) : "f"(a), "f"(b));
    return r;
}

static inline double op_mul_d(double a, double b)
{
    double r;
    __asm__ volatile("mul.d %0, %1, %2" : "=f"(r) : "f"(a), "f"(b));
    return r;
}

static inline uint32_t qnan_s(void)
{
    return g_nan2008 ? 0x7fc00000u : 0x7fbfffffu;
}

static inline uint32_t snan_s(void)
{
    return g_nan2008 ? 0x7fa00000u : 0x7fffffffu;
}

static inline uint64_t qnan_d(void)
{
    return g_nan2008 ? 0x7ff8000000000000ull : 0x7ff7ffffffffffffull;
}

static inline uint64_t snan_d(void)
{
    return g_nan2008 ? 0x7ff4000000000000ull : 0x7ffffffffffbffffull;
}

#endif /* MIPS32_TEST_P3_FPU_H */
