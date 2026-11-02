/* tests/test_p3_fpu.c — Phase 3 FPU coverage suite + qemu goldens (Lane L3c).
 *
 * Guest-side C (libc allowed: this is the test, not the translator) with
 * MIPS32r2 inline asm. Built `-static` for mipsel (LE, default Legacy-NaN)
 * and mips (BE), executed under qemu-mipsel / qemu-mips; stdout + exit code
 * are captured into tests/p3_golden_le.txt / tests/p3_golden_be.txt.
 *
 * Covers: S/D add/sub/mul/div/sqrt vs host-computed references, abs/neg/mov
 * (incl. sNaN non-trapping per E03-corrected ground truth), round/trunc/
 * ceil/floor + FCSR rounding modes, cvt S/D/W/L chains, comparisons +
 * BC1T/BC1F taken/not-taken + BC1TL/BC1FL taken/annulled, MFC1/MTC1 and
 * MFHC1/MTHC1 round-trips, CTC1/CFC1 FCSR round-trip, div-by-zero (+-Inf),
 * overflow (+-Inf), invalid (mode default NaN + FCSR Cause.V/Flags.V),
 * Legacy-vs-2008 quiet/signaling BIT PATTERNS per E03 tables (never `==`
 * on raw NaN values — all NaN checks compare memcpy'd bit patterns), and
 * aligned LWC1/SWC1/LDC1/SDC1 round-trips plus an unaligned-LWC1 spot check
 * isolated in a forked child.
 *
 * stdout is deterministic by construction: no absolute addresses are
 * printed (only hex bit patterns, flags, and counts). Prints per-check
 * `P3 <name>: PASS/FAIL` lines plus a final `P3-RESULT: PASS` line; exit
 * code is 0 iff every check passes.
 *
 * Ground-truth notes (experiments/E03/FINDINGS.md, qemu-mipsel 7.2):
 * - Legacy NaN: quiet bit = frac MSB CLEAR (S: 0x7fbfffff, D:
 *   0x7ff7ffffffffffff); signaling bit patterns have MSB SET (S:
 *   0x7fffffff, D: 0x7ffffffffffbffff).
 * - 2008 NaN: meaning inverted (S QNaN 0x7fc00000, SNaN exemplar
 *   0x7fa00000; D QNaN 0x7ff8000000000000).
 * - sNaN quieting through arithmetic preserves the payload and sets the
 *   mode's quiet bit; legacy 0x7fffffff->0x7fbfffff, 2008
 *   0x7fbfffff->0x7fffffff, both with Cause.V + Flags.V.
 * - ABS.S/ABS.D are NON-ARITHMETIC: they never signal, even on sNaN, in
 *   EITHER NaN mode (E03 corrected the SPEC-2.2 "Legacy traps" premise
 *   against qemu 7.2 and real MIPS: ABS/NEG/MOV never raise Invalid).
 *   Arithmetic add.s on sNaN is the signaling case.
 * - FCSR: Flags V/Z/O/U/I = bits 6/5/4/3/2; Enables = bits 11..7;
 *   Cause = bits 17:12 (V=16 Z=15 O=14 U=13 I=12); RM = bits 1:0.
 *   2008 mode reset FCSR = 0x000c0000 (read-only mode bits survive ctc1).
 */
#define _GNU_SOURCE /* sigjmp_buf/sigsetjmp under strict -std=c11 */
#include <errno.h>
#include <math.h>
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include "test_p3_fpu.h"

static int g_pass = 0, g_fail = 0;

void p3_check(const char *name, int cond, const char *detail)
{
    if (cond) {
        g_pass++;
        printf("P3 %s: PASS %s\n", name, detail);
    } else {
        g_fail++;
        printf("P3 %s: FAIL %s\n", name, detail);
    }
}

#define check p3_check

/* ---- single-precision arithmetic (one guest op each; no host folding) ---- */
static float op_add_s(float a, float b)
{
    float r;

    __asm__ volatile("add.s %0, %1, %2" : "=f"(r) : "f"(a), "f"(b));
    return r;
}

static float op_sub_s(float a, float b)
{
    float r;

    __asm__ volatile("sub.s %0, %1, %2" : "=f"(r) : "f"(a), "f"(b));
    return r;
}

static float op_sqrt_s(float a)
{
    float r;

    __asm__ volatile("sqrt.s %0, %1" : "=f"(r) : "f"(a));
    return r;
}

/* ---- double-precision arithmetic ---- */
static double op_add_d(double a, double b)
{
    double r;

    __asm__ volatile("add.d %0, %1, %2" : "=f"(r) : "f"(a), "f"(b));
    return r;
}

static double op_sub_d(double a, double b)
{
    double r;

    __asm__ volatile("sub.d %0, %1, %2" : "=f"(r) : "f"(a), "f"(b));
    return r;
}

static double op_sqrt_d(double a)
{
    double r;

    __asm__ volatile("sqrt.d %0, %1" : "=f"(r) : "f"(a));
    return r;
}

/* ---- sign-bit moves (non-arithmetic: never trap, even on sNaN) ---- */
static float op_abs_s(float a)
{
    float r;

    __asm__ volatile("abs.s %0, %1" : "=f"(r) : "f"(a));
    return r;
}

static double op_abs_d(double a)
{
    double r;

    __asm__ volatile("abs.d %0, %1" : "=f"(r) : "f"(a));
    return r;
}

static float op_neg_s(float a)
{
    float r;

    __asm__ volatile("neg.s %0, %1" : "=f"(r) : "f"(a));
    return r;
}

static double op_neg_d(double a)
{
    double r;

    __asm__ volatile("neg.d %0, %1" : "=f"(r) : "f"(a));
    return r;
}

static float op_mov_s(float a)
{
    float r;

    __asm__ volatile("mov.s %0, %1" : "=f"(r) : "f"(a));
    return r;
}

static double op_mov_d(double a)
{
    double r;

    __asm__ volatile("mov.d %0, %1" : "=f"(r) : "f"(a));
    return r;
}

/* ================= NaN-mode tables (E03 §6) ================= */

int g_nan2008;          /* 1 when FCSR reset shows 2008 mode bits */
uint32_t g_fcsr_reset;  /* FCSR at entry (mode bits preserved) */

/* Mode's quieting of an sNaN through arithmetic: payload preserved,
 * mode quiet bit set (float MSB 0x00400000, double MSB 0x0008000000000000). */
static uint32_t quieted_s(uint32_t snan)
{
    return g_nan2008 ? (snan | 0x00400000u) : (snan & ~0x00400000u);
}

/* ================= SIGFPE trap control (Invalid enable, like E03 §6) ==== */

static sigjmp_buf g_sj;
static volatile sig_atomic_t g_got_fpe;
int g_have_fpe;

static void on_fpe(int s)
{
    (void)s;
    g_got_fpe = 1;
    siglongjmp(g_sj, 1);
}

/* add.s(pattern, 1.0) with the Invalid trap enabled. Returns 1 on SIGFPE. */
int add_s_trap_test(uint32_t bits, uint32_t *res, uint32_t *fcsr)
{
    float f = u_float(bits);

    g_got_fpe = 0;
    write_fcsr(g_fcsr_reset | (1u << 11)); /* enable Invalid only */
    if (sigsetjmp(g_sj, 1) == 0) {
        float r = op_add_s(f, 1.0f);

        *res = f_bits(r);
        *fcsr = read_fcsr();
        write_fcsr(g_fcsr_reset);
        return 0;
    }
    *res = 0xdead0000u;
    *fcsr = read_fcsr();
    write_fcsr(g_fcsr_reset);
    return 1;
}

/* abs.s on a NaN pattern with the Invalid trap enabled (E03: silent). */
int abs_s_trap_test(uint32_t bits, uint32_t *res, uint32_t *fcsr)
{
    float f = u_float(bits);

    g_got_fpe = 0;
    write_fcsr(g_fcsr_reset | (1u << 11));
    if (sigsetjmp(g_sj, 1) == 0) {
        float r = op_abs_s(f);

        *res = f_bits(r);
        *fcsr = read_fcsr();
        write_fcsr(g_fcsr_reset);
        return 0;
    }
    *res = 0xdead0000u;
    *fcsr = read_fcsr();
    write_fcsr(g_fcsr_reset);
    return 1;
}

/* ================= test groups ================= */

static void t_id(void)
{
    char db[96];
    uint32_t fir = read_fir();

    snprintf(db, sizeof db, "FIR=0x%08x FCSR(reset)=0x%08x mode=%s", fir,
             g_fcsr_reset, g_nan2008 ? "2008" : "legacy");
    check("fpuid", fir != 0, db);
}

static void t_arith_s(void)
{
    char db[96];
    volatile float va = 1.5f, vb = 2.25f;
    volatile float vc = -4.0f;
    float e, r;

    e = va + vb;
    r = op_add_s(va, vb);
    snprintf(db, sizeof db, "1.5+2.25=0x%08x", f_bits(r));
    check("add.s", f_bits(r) == f_bits(e), db);

    e = va - vb;
    r = op_sub_s(va, vb);
    snprintf(db, sizeof db, "1.5-2.25=0x%08x", f_bits(r));
    check("sub.s", f_bits(r) == f_bits(e), db);

    e = va * vb;
    r = op_mul_s(va, vb);
    snprintf(db, sizeof db, "1.5*2.25=0x%08x", f_bits(r));
    check("mul.s", f_bits(r) == f_bits(e), db);

    e = vb / va;
    r = op_div_s(vb, va);
    snprintf(db, sizeof db, "2.25/1.5=0x%08x", f_bits(r));
    check("div.s", f_bits(r) == f_bits(e), db);

    e = sqrtf(2.0f);
    r = op_sqrt_s(2.0f);
    snprintf(db, sizeof db, "sqrt(2)=0x%08x", f_bits(r));
    check("sqrt.s", f_bits(r) == f_bits(e), db);

    r = op_sqrt_s(vc);
    snprintf(db, sizeof db, "sqrt(-4)=0x%08x fcsr=0x%08x", f_bits(r),
             read_fcsr());
    check("sqrt.s-neg", f_bits(r) == qnan_s() && (read_fcsr() & 0x40u) != 0,
          db);
    write_fcsr(g_fcsr_reset);
}

static void t_arith_d(void)
{
    char db[96];
    volatile double va = 1.5, vb = 2.25;
    double e, r;

    e = va + vb;
    r = op_add_d(va, vb);
    snprintf(db, sizeof db, "1.5+2.25=0x%016llx",
             (unsigned long long)d_bits(r));
    check("add.d", d_bits(r) == d_bits(e), db);

    e = va - vb;
    r = op_sub_d(va, vb);
    snprintf(db, sizeof db, "1.5-2.25=0x%016llx",
             (unsigned long long)d_bits(r));
    check("sub.d", d_bits(r) == d_bits(e), db);

    e = va * vb;
    r = op_mul_d(va, vb);
    snprintf(db, sizeof db, "1.5*2.25=0x%016llx",
             (unsigned long long)d_bits(r));
    check("mul.d", d_bits(r) == d_bits(e), db);

    e = vb / va;
    r = op_div_d(vb, va);
    snprintf(db, sizeof db, "2.25/1.5=0x%016llx",
             (unsigned long long)d_bits(r));
    check("div.d", d_bits(r) == d_bits(e), db);

    e = sqrt(2.0);
    r = op_sqrt_d(2.0);
    snprintf(db, sizeof db, "sqrt(2)=0x%016llx",
             (unsigned long long)d_bits(r));
    check("sqrt.d", d_bits(r) == d_bits(e), db);
}

static void t_signops(void)
{
    char db[96];
    uint32_t qs = qnan_s(), ss = snan_s();
    uint64_t qd = qnan_d(), sd = snan_d();

    check("abs.s", f_bits(op_abs_s(-1.0f)) == 0x3f800000u, "abs(-1)=1");
    check("abs.d",
          d_bits(op_abs_d(-1.0)) == 0x3ff0000000000000ull, "abs(-1)=1");
    check("neg.s", f_bits(op_neg_s(1.5f)) == f_bits(-1.5f), "neg(1.5)");
    check("neg.d", d_bits(op_neg_d(-1.5)) == d_bits(1.5), "neg(-1.5)");
    check("mov.s", f_bits(op_mov_s(2.5f)) == f_bits(2.5f), "mov(2.5)");
    check("mov.d", d_bits(op_mov_d(2.5)) == d_bits(2.5), "mov(2.5)");

    /* sNaN through abs/neg/mov: sign-bit op only, no Invalid, bits kept. */
    write_fcsr(g_fcsr_reset);
    snprintf(db, sizeof db, "abs(snan)=0x%08x", f_bits(op_abs_s(u_float(ss))));
    check("abs.s-snan",
          f_bits(op_abs_s(u_float(ss))) == (ss & 0x7fffffffu) &&
              read_fcsr() == g_fcsr_reset,
          db);
    write_fcsr(g_fcsr_reset);
    snprintf(db, sizeof db, "neg(qnan)=0x%08x", f_bits(op_neg_s(u_float(qs))));
    check("neg.s-qnan",
          f_bits(op_neg_s(u_float(qs))) == (qs ^ 0x80000000u) &&
              read_fcsr() == g_fcsr_reset,
          db);
    write_fcsr(g_fcsr_reset);
    snprintf(db, sizeof db, "mov(snan)=0x%08x", f_bits(op_mov_s(u_float(ss))));
    check("mov.s-snan",
          f_bits(op_mov_s(u_float(ss))) == ss &&
              read_fcsr() == g_fcsr_reset,
          db);
    write_fcsr(g_fcsr_reset);
    snprintf(db, sizeof db, "abs.d(snan)=0x%016llx",
             (unsigned long long)d_bits(op_abs_d(u_double(sd))));
    check("abs.d-snan",
          d_bits(op_abs_d(u_double(sd))) == (sd & 0x7fffffffffffffffull) &&
              read_fcsr() == g_fcsr_reset,
          db);
    write_fcsr(g_fcsr_reset);
    check("mov.d-qnan", d_bits(op_mov_d(u_double(qd))) == qd, "payload kept");
}

static void t_nanbits(void)
{
    char db[128];
    float z = 0.0f;
    double dz = 0.0;
    uint32_t r0, fc0;
    uint64_t rd0;

    /* Default NaN from 0.0/0.0 is the mode's quiet NaN (E03 table). */
    write_fcsr(g_fcsr_reset);
    r0 = f_bits(op_div_s(z, z));
    fc0 = read_fcsr();
    snprintf(db, sizeof db, "0.0f/0.0f=0x%08x fcsr=0x%08x", r0, fc0);
    check("nan-default-s",
          r0 == qnan_s() && (fc0 & 0x40u) != 0 && (fc0 & 0x10000u) != 0, db);
    write_fcsr(g_fcsr_reset);
    rd0 = d_bits(op_div_d(dz, dz));
    snprintf(db, sizeof db, "0.0/0.0=0x%016llx",
             (unsigned long long)rd0);
    check("nan-default-d", rd0 == qnan_d(), db);
    write_fcsr(g_fcsr_reset);

    /* Quiet input passes through arithmetic silently. */
    r0 = f_bits(op_add_s(u_float(qnan_s()), 1.0f));
    fc0 = read_fcsr();
    snprintf(db, sizeof db, "add(qnan,1)=0x%08x fcsr=0x%08x", r0, fc0);
    check("nan-quiet-passthru",
          r0 == qnan_s() && (fc0 & ~0x000c0000u) == (g_fcsr_reset & ~0x000c0000u),
          db);
    write_fcsr(g_fcsr_reset);

    /* sNaN input quiets with payload preserved + Cause.V + Flags.V. */
    r0 = f_bits(op_add_s(u_float(snan_s()), 1.0f));
    fc0 = read_fcsr();
    snprintf(db, sizeof db, "add(snan,1)=0x%08x fcsr=0x%08x", r0, fc0);
    check("nan-snan-quiet",
          r0 == quieted_s(snan_s()) && (fc0 & 0x40u) != 0 &&
              (fc0 & 0x10000u) != 0,
          db);
    write_fcsr(g_fcsr_reset);

    /* Double sNaN through arithmetic: qemu returns a quiet NaN in the
     * mode sense (frac MSB clear in Legacy, set in 2008) with Cause.V +
     * Flags.V. No exact payload is asserted: E03 tables cover float
     * payloads exactly, while for double qemu 7.2 returns the default
     * quiet NaN (observed 0x7ff7ffffffffffff for a partial payload). */
    rd0 = d_bits(op_add_d(u_double(snan_d()), 1.0));
    fc0 = read_fcsr();
    snprintf(db, sizeof db, "add.d(snan,1)=0x%016llx fcsr=0x%08x",
             (unsigned long long)rd0, fc0);
    {
        uint64_t frac = rd0 & 0x000fffffffffffffull;
        int is_qnan = g_nan2008 ? ((rd0 & 0x0008000000000000ull) != 0 &&
                                   (rd0 & 0x7ff0000000000000ull) ==
                                       0x7ff0000000000000ull && frac != 0)
                                : ((rd0 & 0x0008000000000000ull) == 0 &&
                                   (rd0 & 0x7ff0000000000000ull) ==
                                       0x7ff0000000000000ull && frac != 0);

        check("nan-snan-quiet-d",
              is_qnan && (fc0 & 0x40u) != 0 && (fc0 & 0x10000u) != 0, db);
    }
    write_fcsr(g_fcsr_reset);
}

int main(void)
{
    uint32_t div0bits;
    double dz = 0.0;

    if (signal(SIGFPE, on_fpe) == SIG_ERR) {
        printf("P3 signals: SKIP sigaction-SIGFPE errno=%d\n", errno);
        g_have_fpe = 0;
    } else {
        g_have_fpe = 1;
    }
    g_fcsr_reset = read_fcsr();
    g_nan2008 = (g_fcsr_reset & 0x000c0000u) == 0x000c0000u;

    /* Sanity: 0.0/0.0 bit pattern must agree with the FCSR mode bits. */
    write_fcsr(g_fcsr_reset);
    div0bits = f_bits(op_div_s(0.0f, 0.0f));
    write_fcsr(g_fcsr_reset);
    {
        uint32_t expect = g_nan2008 ? 0x7fc00000u : 0x7fbfffffu;
        char db[64];

        snprintf(db, sizeof db, "mode=%s div0=0x%08x",
                 g_nan2008 ? "2008" : "legacy", div0bits);
        check("nan-mode", div0bits == expect, db);
    }
    (void)dz;

    t_id();
    t_arith_s();
    t_arith_d();
    t_signops();
    t_nanbits();
    t_trapctl();
    t_excepts();
    t_round_cvt();
    t_branch();
    t_moves();
    t_fcsr();
    t_mem();

    write_fcsr(g_fcsr_reset);
    printf("P3 checks: %d pass, %d fail\n", g_pass, g_fail);
    if (g_fail == 0) {
        printf("P3-RESULT: PASS\n");
        return 0;
    }
    printf("P3-RESULT: FAIL\n");
    return 1;
}
