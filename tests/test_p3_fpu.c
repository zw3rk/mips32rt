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

static int g_pass = 0, g_fail = 0;

static void check(const char *name, int cond, const char *detail)
{
    if (cond) {
        g_pass++;
        printf("P3 %s: PASS %s\n", name, detail);
    } else {
        g_fail++;
        printf("P3 %s: FAIL %s\n", name, detail);
    }
}

/* ---- bit helpers (never == on raw NaN values) ---- */
static uint32_t f_bits(float f)
{
    uint32_t u;

    memcpy(&u, &f, sizeof u);
    return u;
}

static float u_float(uint32_t u)
{
    float f;

    memcpy(&f, &u, sizeof f);
    return f;
}

static uint64_t d_bits(double d)
{
    uint64_t u;

    memcpy(&u, &d, sizeof u);
    return u;
}

static double u_double(uint64_t u)
{
    double d;

    memcpy(&d, &u, sizeof d);
    return d;
}

/* ---- FCSR/FIR access ---- */
static uint32_t read_fcsr(void)
{
    uint32_t v;

    __asm__ volatile("cfc1 %0, $31" : "=r"(v));
    return v;
}

static void write_fcsr(uint32_t v)
{
    __asm__ volatile("ctc1 %0, $31" : : "r"(v));
}

static uint32_t read_fir(void)
{
    uint32_t v;

    __asm__ volatile("cfc1 %0, $0" : "=r"(v));
    return v;
}

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

static float op_mul_s(float a, float b)
{
    float r;

    __asm__ volatile("mul.s %0, %1, %2" : "=f"(r) : "f"(a), "f"(b));
    return r;
}

static float op_div_s(float a, float b)
{
    float r;

    __asm__ volatile("div.s %0, %1, %2" : "=f"(r) : "f"(a), "f"(b));
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

static double op_mul_d(double a, double b)
{
    double r;

    __asm__ volatile("mul.d %0, %1, %2" : "=f"(r) : "f"(a), "f"(b));
    return r;
}

static double op_div_d(double a, double b)
{
    double r;

    __asm__ volatile("div.d %0, %1, %2" : "=f"(r) : "f"(a), "f"(b));
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

/* ---- rounding / conversion (integer result observes FCSR.RM) ---- */
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

/* ---- GPR<->FPR moves ---- */
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

/* ---- explicit FP memory traffic ---- */
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

/* ================= NaN-mode tables (E03 §6) ================= */

static int g_nan2008;          /* 1 when FCSR reset shows 2008 mode bits */
static uint32_t g_fcsr_reset;  /* FCSR at entry (mode bits preserved) */

static uint32_t qnan_s(void)
{
    return g_nan2008 ? 0x7fc00000u : 0x7fbfffffu;
}

static uint32_t snan_s(void)
{
    return g_nan2008 ? 0x7fa00000u : 0x7fffffffu;
}

static uint64_t qnan_d(void)
{
    return g_nan2008 ? 0x7ff8000000000000ull : 0x7ff7ffffffffffffull;
}

static uint64_t snan_d(void)
{
    return g_nan2008 ? 0x7ff4000000000000ull : 0x7ffffffffffbffffull;
}

/* Mode's quieting of an sNaN through arithmetic: payload preserved,
 * mode quiet bit set (float MSB 0x00400000, double MSB 0x0008000000000000). */
static uint32_t quieted_s(uint32_t snan)
{
    return g_nan2008 ? (snan | 0x00400000u) : (snan & ~0x00400000u);
}

/* ================= comparisons + BC1 branches ================= */

/* FCC0 (FCSR bit 23) after a comparison. */
static int fcc0_eq_s(float a, float b)
{
    int r;

    __asm__ volatile("c.eq.s %1, %2\n\t"
                     "cfc1 %0, $31\n\t"
                     : "=r"(r)
                     : "f"(a), "f"(b));
    return (r >> 23) & 1;
}

static int fcc0_lt_s(float a, float b)
{
    int r;

    __asm__ volatile("c.lt.s %1, %2\n\t"
                     "cfc1 %0, $31\n\t"
                     : "=r"(r)
                     : "f"(a), "f"(b));
    return (r >> 23) & 1;
}

static int fcc0_le_s(float a, float b)
{
    int r;

    __asm__ volatile("c.le.s %1, %2\n\t"
                     "cfc1 %0, $31\n\t"
                     : "=r"(r)
                     : "f"(a), "f"(b));
    return (r >> 23) & 1;
}

/* Unordered: true iff either operand is NaN (bit compare, never ==). */
static int fcc0_un_d(double a, double b)
{
    int r;

    __asm__ volatile("c.un.d %1, %2\n\t"
                     "cfc1 %0, $31\n\t"
                     : "=r"(r)
                     : "f"(a), "f"(b));
    return (r >> 23) & 1;
}

/* bc1t/bc1f with a counting delay slot: taken -> 11, not taken -> 1. */
static int bc1t_path(float a, float b)
{
    int cnt = 0;

    __asm__ volatile("c.eq.s %1, %2\n\t"
                     ".set noreorder\n\t"
                     "bc1t 1f\n\t"
                     "addiu %0, %0, 1\n\t"
                     "j 2f\n\t"
                     "nop\n"
                     "1:\n\t"
                     "addiu %0, %0, 10\n"
                     "2:\n\t"
                     ".set reorder\n\t"
                     : "+r"(cnt)
                     : "f"(a), "f"(b)
                     : "memory");
    return cnt;
}

static int bc1f_path(float a, float b)
{
    int cnt = 0;

    __asm__ volatile("c.eq.s %1, %2\n\t"
                     ".set noreorder\n\t"
                     "bc1f 1f\n\t"
                     "addiu %0, %0, 1\n\t"
                     "j 2f\n\t"
                     "nop\n"
                     "1:\n\t"
                     "addiu %0, %0, 10\n"
                     "2:\n\t"
                     ".set reorder\n\t"
                     : "+r"(cnt)
                     : "f"(a), "f"(b)
                     : "memory");
    return cnt;
}

/* bc1tl/bc1fl likely: taken executes delay (cnt=11), not-taken annuls (0). */
static int bc1tl_path(float a, float b)
{
    int cnt = 0;

    __asm__ volatile("c.eq.s %1, %2\n\t"
                     ".set noreorder\n\t"
                     "bc1tl 1f\n\t"
                     "addiu %0, %0, 1\n\t"
                     "j 2f\n\t"
                     "nop\n"
                     "1:\n\t"
                     "addiu %0, %0, 10\n"
                     "2:\n\t"
                     ".set reorder\n\t"
                     : "+r"(cnt)
                     : "f"(a), "f"(b)
                     : "memory");
    return cnt;
}

static int bc1fl_path(float a, float b)
{
    int cnt = 0;

    __asm__ volatile("c.eq.s %1, %2\n\t"
                     ".set noreorder\n\t"
                     "bc1fl 1f\n\t"
                     "addiu %0, %0, 1\n\t"
                     "j 2f\n\t"
                     "nop\n"
                     "1:\n\t"
                     "addiu %0, %0, 10\n"
                     "2:\n\t"
                     ".set reorder\n\t"
                     : "+r"(cnt)
                     : "f"(a), "f"(b)
                     : "memory");
    return cnt;
}

/* ================= SIGFPE trap control (Invalid enable, like E03 §6) ==== */

static sigjmp_buf g_sj;
static volatile sig_atomic_t g_got_fpe;
/* 1 when synchronous SIGFPE delivery works (qemu, Phase-4 translator);
 * 0 under the Phase-1..3 interp (no sigaction yet): trap tests SKIP. */
static int g_have_fpe;

static void on_fpe(int s)
{
    (void)s;
    g_got_fpe = 1;
    siglongjmp(g_sj, 1);
}

/* add.s(pattern, 1.0) with the Invalid trap enabled. Returns 1 on SIGFPE. */
static int add_s_trap_test(uint32_t bits, uint32_t *res, uint32_t *fcsr)
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
static int abs_s_trap_test(uint32_t bits, uint32_t *res, uint32_t *fcsr)
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

static void t_trapctl(void)
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

    /* Mode sNaN + Invalid trap enabled -> SIGFPE (E03 control). */
    trapped = add_s_trap_test(snan_s(), &res, &fc);
    snprintf(db, sizeof db, "add(snan)+trap trapped=%d fcsr=0x%08x", trapped,
             fc);
    check("trap-snan", trapped == 1, db);

    /* Mode qNaN + trap enabled -> silent. */
    trapped = add_s_trap_test(qnan_s(), &res, &fc);
    snprintf(db, sizeof db, "add(qnan)+trap trapped=%d res=0x%08x", trapped,
             res);
    check("trap-qnan-silent", trapped == 0 && res == qnan_s(), db);

    /* abs.s on both NaN patterns with trap enabled -> silent (E03 §6). */
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

static void t_excepts(void)
{
    char db[128];
    uint32_t r, fc;
    uint64_t rd;

    /* Division by zero -> +-Inf + Flags.Z + Cause.Z, no Invalid. */
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

    /* Overflow -> +-Inf + Flags.O + Cause.O. */
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

    /* Invalid cvt: huge float -> int saturates + Flags.V. */
    {
        int32_t w = op_cvt_w_s(1.0e20f);

        fc = read_fcsr();
        snprintf(db, sizeof db, "cvt.w.s(1e20)=0x%08x fcsr=0x%08x",
                 (uint32_t)w, fc);
        check("cvt-ovf", w == (int32_t)0x7fffffff && (fc & 0x40u) != 0, db);
        write_fcsr(g_fcsr_reset);
    }
}

static void t_round_cvt(void)
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

    /* FCSR rounding modes steer cvt.w.s (directed cases, exact). */
    write_fcsr((g_fcsr_reset & ~3u) | 1u); /* RZ */
    check("rm-rz", op_cvt_w_s(1.9f) == 1 && op_cvt_w_s(-1.9f) == -1, "rz");
    write_fcsr((g_fcsr_reset & ~3u) | 2u); /* RP */
    check("rm-rp", op_cvt_w_s(1.1f) == 2 && op_cvt_w_s(-1.1f) == -1, "rp");
    write_fcsr((g_fcsr_reset & ~3u) | 3u); /* RM */
    check("rm-rm", op_cvt_w_s(1.9f) == 1 && op_cvt_w_s(-1.1f) == -2, "rm");
    write_fcsr(g_fcsr_reset & ~3u); /* RN */
    check("rm-rn", op_cvt_w_s(1.5f) == 2 && op_cvt_w_s(2.5f) == 2, "rn");
    write_fcsr(g_fcsr_reset);

    /* Conversion chains preserve exact values. */
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

static void t_branch(void)
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

static void t_moves(void)
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

static void t_fcsr(void)
{
    char db[64];
    uint32_t save = g_fcsr_reset;
    int rm;

    /* RM field round-trips through ctc1/cfc1 (mode bits untouched). */
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
    /* Flags set by an invalid op clear with a flag-less write. */
    write_fcsr(save);
    (void)op_div_s(0.0f, 0.0f);
    check("fcsr-flag-set", (read_fcsr() & 0x40u) != 0, "Flags.V after 0/0");
    write_fcsr(save);
    check("fcsr-flag-clear", (read_fcsr() & 0x7cu) == (save & 0x7cu),
          "flags cleared");
    write_fcsr(save);
}

static void t_mem(void)
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

    /* Unaligned LWC1 spot check in a forked child: under qemu-user the
     * unaligned address faults (AdEL -> SIGBUS on MIPS); the parent
     * records the outcome honestly. No addresses are printed. */
    {
        pid_t pid = fork();
        int st;

        if (pid == 0) {
            /* Child: trap unaligned access, exit 42 on fault. */
            static volatile int dummy;

            (void)dummy;
            {
                const float *up =
                    (const float *)(buf + 1); /* misaligned */
                float v;

                __asm__ volatile("lwc1 %0, %1"
                                 : "=f"(v)
                                 : "m"(*up)
                                 : "memory");
                _exit(v == 0.0f ? 43 : 44); /* emulated: record */
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
