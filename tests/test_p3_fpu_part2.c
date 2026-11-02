/*
 * tests/test_p3_fpu_part2.c — Phase 3 FPU coverage suite part 2
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

#define _GNU_SOURCE
#include "test_p3_fpu.h"

#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define check p3_check

static int32_t op_round_w_s(float a)
{
    int32_t r;
    __asm__ volatile("round.w.s %0, %1" : "=f"(r) : "f"(a));
    return r;
}

static int32_t op_trunc_w_s(float a)
{
    int32_t r;
    __asm__ volatile("trunc.w.s %0, %1" : "=f"(r) : "f"(a));
    return r;
}

static int32_t op_ceil_w_s(float a)
{
    int32_t r;
    __asm__ volatile("ceil.w.s %0, %1" : "=f"(r) : "f"(a));
    return r;
}

static int32_t op_floor_w_s(float a)
{
    int32_t r;
    __asm__ volatile("floor.w.s %0, %1" : "=f"(r) : "f"(a));
    return r;
}

static int32_t op_cvt_w_s(float a)
{
    int32_t r;
    __asm__ volatile("cvt.w.s %0, %1" : "=f"(r) : "f"(a));
    return r;
}

static int32_t op_cvt_w_d(double a)
{
    int32_t r;
    __asm__ volatile("cvt.w.d %0, %1" : "=f"(r) : "f"(a));
    return r;
}

static double op_cvt_d_s(float a)
{
    double r;
    __asm__ volatile("cvt.d.s %0, %1" : "=f"(r) : "f"(a));
    return r;
}

static float op_cvt_s_d(double a)
{
    float r;
    __asm__ volatile("cvt.s.d %0, %1" : "=f"(r) : "f"(a));
    return r;
}

static float op_cvt_s_w(int32_t a)
{
    float r;
    __asm__ volatile("cvt.s.w %0, %1" : "=f"(r) : "f"(a));
    return r;
}

static double op_cvt_d_w(int32_t a)
{
    double r;
    __asm__ volatile("cvt.d.w %0, %1" : "=f"(r) : "f"(a));
    return r;
}

static uint32_t mtc1_mfc1(uint32_t in)
{
    uint32_t out;
    __asm__ volatile("mtc1 %1, $f0\n\tmfc1 %0, $f0" : "=r"(out) : "r"(in));
    return out;
}

static void mthc1_pair(uint32_t lo, uint32_t hi, uint32_t *rlo, uint32_t *rhi)
{
    uint32_t o0, o1;
    __asm__ volatile("mtc1 %2, $f0\n\t"
                     "mthc1 %3, $f0\n\t"
                     "mfc1 %0, $f0\n\t"
                     "mfhc1 %1, $f0\n\t"
                     : "=r"(o0), "=r"(o1)
                     : "r"(lo), "r"(hi));
    *rlo = o0;
    *rhi = o1;
}

static void swc1_set(float *p, float v)
{
    __asm__ volatile("swc1 %1, %0" : "=m"(*p) : "f"(v) : "memory");
}

static float lwc1_get(const float *p)
{
    float r;
    __asm__ volatile("lwc1 %0, %1" : "=f"(r) : "m"(*p) : "memory");
    return r;
}

static void sdc1_set(double *p, double v)
{
    __asm__ volatile("sdc1 %1, %0" : "=m"(*p) : "f"(v) : "memory");
}

static double ldc1_get(const double *p)
{
    double r;
    __asm__ volatile("ldc1 %0, %1" : "=f"(r) : "m"(*p) : "memory");
    return r;
}

static int fcc0_eq_s(float a, float b)
{
    int r;
    __asm__ volatile("c.eq.s %1, %2\n\tcfc1 %0, $31\n\t" : "=r"(r) : "f"(a), "f"(b));
    return (r >> 23) & 1;
}

static int fcc0_lt_s(float a, float b)
{
    int r;
    __asm__ volatile("c.lt.s %1, %2\n\tcfc1 %0, $31\n\t" : "=r"(r) : "f"(a), "f"(b));
    return (r >> 23) & 1;
}

static int fcc0_le_s(float a, float b)
{
    int r;
    __asm__ volatile("c.le.s %1, %2\n\tcfc1 %0, $31\n\t" : "=r"(r) : "f"(a), "f"(b));
    return (r >> 23) & 1;
}

static int fcc0_un_d(double a, double b)
{
    int r;
    __asm__ volatile("c.un.d %1, %2\n\tcfc1 %0, $31\n\t" : "=r"(r) : "f"(a), "f"(b));
    return (r >> 23) & 1;
}

static int bc1t_path(float a, float b)
{
    int cnt = 0;
    __asm__ volatile("c.eq.s %1, %2\n\t.set noreorder\n\tbc1t 1f\n\taddiu %0, %0, 1\n\tj 2f\n\tnop\n1:\n\taddiu %0, %0, 10\n2:\n\t.set reorder\n\t"
                     : "+r"(cnt) : "f"(a), "f"(b) : "memory");
    return cnt;
}

static int bc1f_path(float a, float b)
{
    int cnt = 0;
    __asm__ volatile("c.eq.s %1, %2\n\t.set noreorder\n\tbc1f 1f\n\taddiu %0, %0, 1\n\tj 2f\n\tnop\n1:\n\taddiu %0, %0, 10\n2:\n\t.set reorder\n\t"
                     : "+r"(cnt) : "f"(a), "f"(b) : "memory");
    return cnt;
}

static int bc1tl_path(float a, float b)
{
    int cnt = 0;
    __asm__ volatile("c.eq.s %1, %2\n\t.set noreorder\n\tbc1tl 1f\n\taddiu %0, %0, 1\n\tj 2f\n\tnop\n1:\n\taddiu %0, %0, 10\n2:\n\t.set reorder\n\t"
                     : "+r"(cnt) : "f"(a), "f"(b) : "memory");
    return cnt;
}

static int bc1fl_path(float a, float b)
{
    int cnt = 0;
    __asm__ volatile("c.eq.s %1, %2\n\t.set noreorder\n\tbc1fl 1f\n\taddiu %0, %0, 1\n\tj 2f\n\tnop\n1:\n\taddiu %0, %0, 10\n2:\n\t.set reorder\n\t"
                     : "+r"(cnt) : "f"(a), "f"(b) : "memory");
    return cnt;
}

void t_trapctl(void)
{
    char db[128];
    uint32_t res, fc;
    int trapped;

    if (!g_have_fpe) {
        printf("P3 trap-snan: SKIP no signal delivery\n");
        printf("P3 trap-qnan-silent: SKIP no signal delivery\n");
        printf("P3 trap-abs-snan-silent: SKIP no signal delivery\n");
        printf("P3 trap-abs-qnan-silent: SKIP no signal delivery\n");
        return;
    }

    trapped = add_s_trap_test(snan_s(), &res, &fc);
    snprintf(db, sizeof db, "add(snan)+trap trapped=%d fcsr=0x%08x", trapped,
             fc);
    check("trap-snan", trapped == 1, db);

    trapped = add_s_trap_test(qnan_s(), &res, &fc);
    snprintf(db, sizeof db, "add(qnan)+trap trapped=%d res=0x%08x", trapped,
             res);
    check("trap-qnan-silent", trapped == 0 && res == qnan_s(), db);

    trapped = abs_s_trap_test(snan_s(), &res, &fc);
    snprintf(db, sizeof db, "abs(snan)+trap trapped=%d res=0x%08x", trapped,
             res);
    check("trap-abs-snan-silent",
          trapped == 0 && res == (snan_s() & 0x7fffffffu), db);
    trapped = abs_s_trap_test(qnan_s(), &res, &fc);
    snprintf(db, sizeof db, "abs(qnan)+trap trapped=%d res=0x%08x", trapped,
             res);
    check("trap-abs-qnan-silent",
          trapped == 0 && res == (qnan_s() & 0x7fffffffu), db);
}

void t_excepts(void)
{
    char db[128];
    uint32_t r, fc;
    uint64_t rd;

    write_fcsr(g_fcsr_reset);
    r = f_bits(op_div_s(1.0f, 0.0f));
    fc = read_fcsr();
    snprintf(db, sizeof db, "1/0=0x%08x fcsr=0x%08x", r, fc);
    check("divz-pos", r == 0x7f800000u && (fc & 0x20u) != 0 &&
                          (fc & 0x8000u) != 0 && (fc & 0x40u) == 0,
          db);
    write_fcsr(g_fcsr_reset);
    r = f_bits(op_div_s(-1.0f, 0.0f));
    snprintf(db, sizeof db, "-1/0=0x%08x", r);
    check("divz-neg", r == 0xff800000u && (read_fcsr() & 0x20u) != 0, db);
    write_fcsr(g_fcsr_reset);
    rd = d_bits(op_div_d(1.0, 0.0));
    snprintf(db, sizeof db, "1.0/0.0=0x%016llx",
             (unsigned long long)rd);
    check("divz-d", rd == 0x7ff0000000000000ull, db);
    write_fcsr(g_fcsr_reset);

    r = f_bits(op_mul_s(3.4028235e38f, 2.0f));
    fc = read_fcsr();
    snprintf(db, sizeof db, "max*2=0x%08x fcsr=0x%08x", r, fc);
    check("ovf-s", r == 0x7f800000u && (fc & 0x10u) != 0 &&
                       (fc & 0x4000u) != 0,
          db);
    write_fcsr(g_fcsr_reset);
    rd = d_bits(op_mul_d(1.7976931348623157e308, 2.0));
    snprintf(db, sizeof db, "dmax*2=0x%016llx",
             (unsigned long long)rd);
    check("ovf-d", rd == 0x7ff0000000000000ull &&
                       (read_fcsr() & 0x10u) != 0,
          db);
    write_fcsr(g_fcsr_reset);

    {
        int32_t w = op_cvt_w_s(1.0e20f);

        fc = read_fcsr();
        snprintf(db, sizeof db, "cvt.w.s(1e20)=0x%08x fcsr=0x%08x",
                 (uint32_t)w, fc);
        check("cvt-ovf", w == (int32_t)0x7fffffff && (fc & 0x40u) != 0, db);
        write_fcsr(g_fcsr_reset);
    }
}

void t_round_cvt(void)
{
    char db[96];

    check("round.w.s", op_round_w_s(1.5f) == 2 && op_round_w_s(2.5f) == 2 &&
                           op_round_w_s(-2.5f) == -2,
          "half-even 1.5->2 2.5->2 -2.5->-2");
    check("trunc.w.s", op_trunc_w_s(1.9f) == 1 && op_trunc_w_s(-1.9f) == -1,
          "toward-zero");
    check("ceil.w.s", op_ceil_w_s(1.1f) == 2 && op_ceil_w_s(-1.1f) == -1,
          "toward+inf");
    check("floor.w.s", op_floor_w_s(1.9f) == 1 && op_floor_w_s(-1.1f) == -2,
          "toward-inf");

    write_fcsr((g_fcsr_reset & ~3u) | 1u);
    check("rm-rz", op_cvt_w_s(1.9f) == 1 && op_cvt_w_s(-1.9f) == -1, "rz");
    write_fcsr((g_fcsr_reset & ~3u) | 2u);
    check("rm-rp", op_cvt_w_s(1.1f) == 2 && op_cvt_w_s(-1.1f) == -1, "rp");
    write_fcsr((g_fcsr_reset & ~3u) | 3u);
    check("rm-rm", op_cvt_w_s(1.9f) == 1 && op_cvt_w_s(-1.1f) == -2, "rm");
    write_fcsr(g_fcsr_reset & ~3u);
    check("rm-rn", op_cvt_w_s(1.5f) == 2 && op_cvt_w_s(2.5f) == 2, "rn");
    write_fcsr(g_fcsr_reset);

    check("cvt.d.s", d_bits(op_cvt_d_s(3.25f)) == d_bits(3.25), "3.25f->d");
    check("cvt.s.d", f_bits(op_cvt_s_d(3.25)) == f_bits(3.25f), "3.25d->s");
    check("cvt.s.w", f_bits(op_cvt_s_w(12345)) == f_bits(12345.0f), "12345");
    check("cvt.d.w",
          d_bits(op_cvt_d_w(-7)) == d_bits(-7.0), "-7");
    snprintf(db, sizeof db, "cvt.w.s(cvt.s.w(12345))=%d",
             op_cvt_w_s(op_cvt_s_w(12345)));
    check("cvt-chain-w", op_cvt_w_s(op_cvt_s_w(12345)) == 12345, db);
    snprintf(db, sizeof db, "cvt.w.d(-7.0)=%d", op_cvt_w_d(-7.0));
    check("cvt-w-d", op_cvt_w_d(-7.0) == -7, db);
}

void t_branch(void)
{
    check("cmp-eq", fcc0_eq_s(1.0f, 1.0f) == 1 && fcc0_eq_s(1.0f, 2.0f) == 0,
          "eq t/f");
    check("cmp-lt", fcc0_lt_s(1.0f, 2.0f) == 1 && fcc0_lt_s(2.0f, 1.0f) == 0 &&
                        fcc0_lt_s(1.0f, 1.0f) == 0,
          "lt");
    check("cmp-le", fcc0_le_s(1.0f, 1.0f) == 1 && fcc0_le_s(1.0f, 2.0f) == 1 &&
                        fcc0_le_s(2.0f, 1.0f) == 0,
          "le");
    check("cmp-un-d",
          fcc0_un_d(u_double(qnan_d()), 1.0) == 1 &&
              fcc0_un_d(1.0, 2.0) == 0,
          "un");
    {
        char cb[64];
        int c;

        c = bc1t_path(1.0f, 1.0f);
        snprintf(cb, sizeof cb, "cnt=%d", c);
        check("bc1t-taken", c == 11, cb);
        c = bc1t_path(1.0f, 2.0f);
        snprintf(cb, sizeof cb, "cnt=%d", c);
        check("bc1t-nottaken", c == 1, cb);
        c = bc1f_path(1.0f, 2.0f);
        snprintf(cb, sizeof cb, "cnt=%d", c);
        check("bc1f-taken", c == 11, cb);
        c = bc1f_path(1.0f, 1.0f);
        snprintf(cb, sizeof cb, "cnt=%d", c);
        check("bc1f-nottaken", c == 1, cb);
        c = bc1tl_path(1.0f, 1.0f);
        snprintf(cb, sizeof cb, "delay runs cnt=%d", c);
        check("bc1tl-taken", c == 11, cb);
        c = bc1tl_path(1.0f, 2.0f);
        snprintf(cb, sizeof cb, "delay annulled cnt=%d", c);
        check("bc1tl-annul", c == 0, cb);
        c = bc1fl_path(1.0f, 2.0f);
        snprintf(cb, sizeof cb, "delay runs cnt=%d", c);
        check("bc1fl-taken", c == 11, cb);
        c = bc1fl_path(1.0f, 1.0f);
        snprintf(cb, sizeof cb, "delay annulled cnt=%d", c);
        check("bc1fl-annul", c == 0, cb);
    }
}

void t_moves(void)
{
    char db[96];
    const uint32_t pats[3] = { 0x12345678u, 0x00000000u, 0xffffffffu };
    int i;
    uint32_t rlo, rhi;

    for (i = 0; i < 3; i++) {
        uint32_t back = mtc1_mfc1(pats[i]);

        snprintf(db, sizeof db, "in=0x%08x out=0x%08x", pats[i], back);
        check(i == 0 ? "mtc1-mfc1-a" : (i == 1 ? "mtc1-mfc1-b" : "mtc1-mfc1-c"),
              back == pats[i], db);
    }
    mthc1_pair(0xdeadbeefu, 0x12345678u, &rlo, &rhi);
    snprintf(db, sizeof db, "lo=0x%08x hi=0x%08x", rlo, rhi);
    check("mthc1-mfhc1", rlo == 0xdeadbeefu && rhi == 0x12345678u, db);
}

void t_fcsr(void)
{
    char db[64];
    uint32_t save = g_fcsr_reset;
    int rm;

    for (rm = 0; rm < 4; rm++) {
        uint32_t w = (save & ~3u) | (uint32_t)rm;
        uint32_t back;

        write_fcsr(w);
        back = read_fcsr();
        snprintf(db, sizeof db, "rm=%d back=0x%08x", rm, back);
        check(rm == 0 ? "fcsr-rm0" : (rm == 1 ? "fcsr-rm1" : (rm == 2 ? "fcsr-rm2" : "fcsr-rm3")),
              (back & 3u) == (uint32_t)rm &&
                  (back & 0x000c0000u) == (save & 0x000c0000u),
              db);
    }
    write_fcsr(save);
    (void)op_div_s(0.0f, 0.0f);
    check("fcsr-flag-set", (read_fcsr() & 0x40u) != 0, "Flags.V after 0/0");
    write_fcsr(save);
    check("fcsr-flag-clear", (read_fcsr() & 0x7cu) == (save & 0x7cu),
          "flags cleared");
    write_fcsr(save);
}

__attribute__((noinline)) static void fixade_off(void)
{
    register unsigned long r_v0 __asm__("$2") = 4149u;
    register unsigned long r_a0 __asm__("$4") = 7u;
    register unsigned long r_a1 __asm__("$5") = 0u;
    register unsigned long r_a3 __asm__("$7");
    __asm__ volatile("syscall"
                     : "+r"(r_v0), "=r"(r_a3)
                     : "r"(r_a0), "r"(r_a1)
                     : "memory");
    (void)r_v0;
    (void)r_a3;
}

void t_mem(void)
{
    char db[96];
    static float sf[4] __attribute__((aligned(8)));
    static double sd[2] __attribute__((aligned(8)));
    static unsigned char buf[16] __attribute__((aligned(8)));

    swc1_set(&sf[0], 1.25f);
    swc1_set(&sf[1], -2.5f);
    check("swc1-lwc1",
          f_bits(lwc1_get(&sf[0])) == f_bits(1.25f) &&
              f_bits(lwc1_get(&sf[1])) == f_bits(-2.5f),
          "aligned word round-trip");
    sdc1_set(&sd[0], 3.75);
    snprintf(db, sizeof db, "ldc1=0x%016llx",
             (unsigned long long)d_bits(ldc1_get(&sd[0])));
    check("sdc1-ldc1", d_bits(ldc1_get(&sd[0])) == d_bits(3.75), db);

    {
        pid_t pid = fork();
        int st;

        if (pid == 0) {
            static volatile int dummy;

            (void)dummy;
            fixade_off();
            {
                const float *up = (const float *)(buf + 1);
                float v;

                __asm__ volatile("lwc1 %0, %1"
                                 : "=f"(v)
                                 : "m"(*up)
                                 : "memory");
                _exit(v == 0.0f ? 43 : 44);
            }
        }
        if (pid < 0) {
            if (errno == ENOSYS) {
                printf("P3 unaligned-lwc1: SKIP fork unimplemented\n");
            } else {
                check("unaligned-lwc1", 0, "fork failed");
            }
        } else {
            pid_t w = waitpid(pid, &st, 0);

            if (w != pid) {
                check("unaligned-lwc1", 0, "waitpid failed");
            } else if (WIFSIGNALED(st) &&
                       (WTERMSIG(st) == SIGBUS || WTERMSIG(st) == SIGSEGV)) {
                snprintf(db, sizeof db, "child sig=%d (AdEL fault)",
                         WTERMSIG(st));
                check("unaligned-lwc1", 1, db);
            } else if (WIFEXITED(st) && WEXITSTATUS(st) == 42) {
                check("unaligned-lwc1", 0, "unreachable");
            } else if (WIFEXITED(st) &&
                       (WEXITSTATUS(st) == 43 || WEXITSTATUS(st) == 44)) {
                snprintf(db, sizeof db, "child exit=%d (emulated)",
                         WEXITSTATUS(st));
                check("unaligned-lwc1", 1, db);
            } else {
                snprintf(db, sizeof db, "child st=0x%x (unexpected)", st);
                check("unaligned-lwc1", 0, db);
            }
        }
    }
}
