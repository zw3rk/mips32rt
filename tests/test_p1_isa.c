/* tests/test_p1_isa.c — Phase 1 ISA coverage suite + qemu goldens (Lane L1d).
 *
 * Guest-side C (libc allowed: this is the test, not the translator) with
 * MIPS32r2 inline asm. Built `-static` for mipsel (LE) and mips (BE),
 * executed under qemu-mipsel / qemu-mips; stdout + exit code are captured
 * into tests/p1_golden_le.txt / tests/p1_golden_be.txt.
 *
 * Covers: ALU/shifts, MULT/MULTU/DIV/DIVU hi-lo, every branch type
 * taken + not-taken with delay slots, branch-likely annulment (counting
 * check in mapped memory plus the page_end-4-before-PROT_NONE pattern),
 * J/JALR/JR, LL/SC success + interference failure, LWL/LWR/SWL/SWR at all
 * alignments, RDHWR/set_thread_area, an unaligned-LW fault isolated in a
 * forked child, and a raw write + raw exit path.
 *
 * stdout is deterministic by construction: no absolute addresses are
 * printed (only diffs/flags/counts), so the interp/dbt RC1 comparison is
 * meaningful. Prints per-check `P1 <name>: PASS/FAIL` lines plus a final
 * `P1-RESULT: PASS` line; exit code is 0 iff every check passes (via a
 * raw O32 exit syscall).
 *
 * Ground-truth notes reused from Phase E probes:
 * - E02: branch delay slots, BEQL annulment counting test, bal-not-jal
 *   for local subroutine calls, "+r" (not "=r") for skippable writes,
 *   delay-slot fault reports the branch pc, qemu translate-time fetch
 *   of the delay word at page end (SIGSEGV, sc_pc == branch).
 * - E05: LWL/LWR/SWL/SWR merge tables for LE and BE, plain unaligned
 *   LW/SW faults under qemu-user (AdEL/AdES -> SIGBUS == signal 10 on
 *   MIPS, NOT emulated).
 * - E06: rdhwr $29 mnemonic + fixed word 0x7c03e83b, set_thread_area
 *   4283 round-trip (no libc calls while a foreign ULR is installed),
 *   LL/SC retry loop and store-interference failure.
 * - E01: raw O32 syscall convention ($v0 = number, $a3 = error flag),
 *   MIPS ENOSYS = 89; O32 __NR_exit = 4001, __NR_write = 4004.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <setjmp.h>
#include <errno.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <ucontext.h>
#include "test_p1_isa.h"

static int g_pass = 0, g_fail = 0;

void p1_check(const char *name, int cond, const char *detail)
{
    if (cond) {
        g_pass++;
        printf("P1 %s: PASS %s\n", name, detail);
    } else {
        g_fail++;
        printf("P1 %s: FAIL %s\n", name, detail);
    }
}

#define check p1_check

/* ---- raw O32 syscall (number in $v0, error flag out via $a3) ---- */
long p1_raw_sys3(long num, long a0, long a1, long a2, int *pa3)
{
    register long r_v0 __asm__("v0") = num;
    register long r_a0 __asm__("a0") = a0;
    register long r_a1 __asm__("a1") = a1;
    register long r_a2 __asm__("a2") = a2;
    register long r_a3 __asm__("a3") = 0;
    __asm__ volatile(
        "syscall"
        : "+r"(r_v0), "+r"(r_a3)
        : "r"(r_a0), "r"(r_a1), "r"(r_a2)
        : "memory");
    if (pa3)
        *pa3 = (int)r_a3;
    return r_v0;
}

#define raw_sys3 p1_raw_sys3

__attribute__((noreturn)) static void raw_exit(long code)
{
    raw_sys3(NR_EXIT, code, 0, 0, NULL);
    for (;;) {
    }
}

/* ================= ALU (compiler-generated + volatile operands) ================= */

__attribute__((noinline)) static void t_alu(void)
{
    char db[128];
    volatile int va = 100, vb = 27;
    volatile unsigned ua = 0xFFFFFFFFu, ub = 1u;
    volatile int vs = -100;
    int r_add = va + vb;
    int r_sub = va - vb;
    unsigned r_addu = ua + ub;               /* wraps to 0 */
    unsigned r_subu = ub - ua;               /* 1 - 0xFFFFFFFF = 2 */
    unsigned r_and = 0xF0F0F0F0u & 0x0FF00FF0u;
    unsigned r_or = 0xF0F0F0F0u | 0x0FF00FF0u;
    unsigned r_xor = 0xFFFFFFFFu ^ 0x12345678u;
    unsigned r_nor = ~(0xF0F0F0F0u | 0x0FF00FF0u);
    int r_slt1 = (vs < va);                  /* -100 < 100 */
    int r_slt2 = (va < vs);
    unsigned r_sltu = (ub < ua);             /* 1 < 0xFFFFFFFF */
    int r_slti = (va < 200) ? 1 : 0;
    unsigned r_lui = 0x1234u << 16;
    snprintf(db, sizeof db, "add=%d sub=%d addu=0x%x subu=0x%x",
             r_add, r_sub, r_addu, r_subu);
    check("alu-addsub", r_add == 127 && r_sub == 73 &&
          r_addu == 0u && r_subu == 2u, db);
    snprintf(db, sizeof db,
             "and=0x%x or=0x%x xor=0x%x nor=0x%x",
             r_and, r_or, r_xor, r_nor);
    check("alu-logic", r_and == 0x00F000F0u && r_or == 0xFFF0FFF0u &&
          r_xor == 0xEDCBA987u && r_nor == 0x000F000Fu, db);
    snprintf(db, sizeof db, "slt=%d/%d sltu=%u slti=%d lui=0x%x",
             r_slt1, r_slt2, r_sltu, r_slti, r_lui);
    check("alu-slt-lui", r_slt1 == 1 && r_slt2 == 0 && r_sltu == 1 &&
          r_slti == 1 && r_lui == 0x12340000u, db);
}

/* ================= shifts (explicit asm) ================= */

__attribute__((noinline)) static void t_shifts(void)
{
    char db[128];
    uint32_t r;
    __asm__ volatile("sll %0,%1,8" : "=r"(r) : "r"(0x12345678u));
    uint32_t r_sll = r;
    __asm__ volatile("srl %0,%1,4" : "=r"(r) : "r"(0x80000001u));
    uint32_t r_srl = r;
    __asm__ volatile("sra %0,%1,4" : "=r"(r) : "r"(0x80000001u));
    uint32_t r_sra = r;
    __asm__ volatile("sllv %0,%1,%2" : "=r"(r) : "r"(0x00000003u), "r"(10));
    uint32_t r_sllv = r;
    __asm__ volatile("srlv %0,%1,%2" : "=r"(r) : "r"(0x80000000u), "r"(4));
    uint32_t r_srlv = r;
    __asm__ volatile("srav %0,%1,%2" : "=r"(r) : "r"(0x80000000u), "r"(4));
    uint32_t r_srav = r;
    snprintf(db, sizeof db,
             "sll=0x%x srl=0x%x sra=0x%x", r_sll, r_srl, r_sra);
    check("shift-imm", r_sll == 0x34567800u && r_srl == 0x08000000u &&
          r_sra == 0xF8000000u, db);
    snprintf(db, sizeof db,
             "sllv=0x%x srlv=0x%x srav=0x%x", r_sllv, r_srlv, r_srav);
    check("shift-var", r_sllv == 0x00000C00u && r_srlv == 0x08000000u &&
          r_srav == 0xF8000000u, db);
}

/* ================= MULT/DIV hi-lo ================= */

__attribute__((noinline)) static void t_muldiv(void)
{
    char db[128];
    uint32_t lo = 0, hi = 0;
    __asm__ volatile("mult %2,%3\n\tmflo %0\n\tmfhi %1"
                     : "=&r"(lo), "=&r"(hi)
                     : "r"(12345u), "r"(6789u));
    snprintf(db, sizeof db, "mult lo=%u hi=%u", lo, hi);
    check("mult", lo == 83810205u && hi == 0u, db);
    __asm__ volatile("multu %2,%3\n\tmflo %0\n\tmfhi %1"
                     : "=&r"(lo), "=&r"(hi)
                     : "r"(0xFFFFFFFFu), "r"(0xFFFFFFFFu));
    snprintf(db, sizeof db, "multu lo=0x%x hi=0x%x", lo, hi);
    check("multu", lo == 1u && hi == 0xFFFFFFFEu, db);
    {
        int q = 0, rem = 0;
        __asm__ volatile("div %2,%3\n\tmflo %0\n\tmfhi %1"
                         : "=&r"(q), "=&r"(rem)
                         : "r"(100), "r"(7));
        snprintf(db, sizeof db, "div q=%d r=%d", q, rem);
        check("div", q == 14 && rem == 2, db);
    }
    {
        unsigned q = 0, rem = 0;
        __asm__ volatile("divu %2,%3\n\tmflo %0\n\tmfhi %1"
                         : "=&r"(q), "=&r"(rem)
                         : "r"(0xFFFFFFFFu), "r"(16u));
        snprintf(db, sizeof db, "divu q=0x%x r=0x%x", q, rem);
        check("divu", q == 0x0FFFFFFFu && rem == 0xFu, db);
    }
    {
        uint32_t back_lo = 0, back_hi = 0;
        __asm__ volatile("mtlo %2\n\tmthi %3\n\tmflo %0\n\tmfhi %1"
                         : "=&r"(back_lo), "=&r"(back_hi)
                         : "r"(0xAABBCCDDu), "r"(0x11223344u));
        snprintf(db, sizeof db, "mthi/mtlo lo=0x%x hi=0x%x",
                 back_lo, back_hi);
        check("mthi-mtlo", back_lo == 0xAABBCCDDu &&
              back_hi == 0x11223344u, db);
    }
}

/* BSHFL/EXT/INS (SPECIAL3): source registers are rt for BSHFL and rs for
 * EXT/INS.  The BSHFL-from-$0 mixup (interp + emitter) printed lowercase
 * %X in glibc; these checks pin the encoding (regression collateral). */
__attribute__((noinline)) static void t_bshfl(void)
{
    char db[160];
    uint32_t r;
    __asm__ volatile("seb %0,%1" : "=r"(r) : "r"(0x00000082u));
    uint32_t r_seb_lo = r;
    __asm__ volatile("seb %0,%1" : "=r"(r) : "r"(0x0000007Fu));
    uint32_t r_seb_hi = r;
    __asm__ volatile("seh %0,%1" : "=r"(r) : "r"(0x0000ABCDu));
    uint32_t r_seh = r;
    snprintf(db, sizeof db, "seb=0x%x/0x%x seh=0x%x",
             r_seb_lo, r_seb_hi, r_seh);
    check("sign-extend", r_seb_lo == 0xFFFFFF82u && r_seb_hi == 0x7Fu &&
          r_seh == 0xFFFFABCDu, db);
    __asm__ volatile("wsbh %0,%1" : "=r"(r) : "r"(0x12345678u));
    uint32_t r_wsbh = r;
    snprintf(db, sizeof db, "wsbh=0x%x", r_wsbh);
    check("wsbh", r_wsbh == 0x34127856u, db);
    __asm__ volatile("ext %0,%1,4,6" : "=r"(r) : "r"(0xABCDEF12u));
    uint32_t r_ext = r;
    snprintf(db, sizeof db, "ext=0x%x", r_ext);
    check("ext", r_ext == 0x31u, db);
    r = 0x12345678u;
    __asm__ volatile("ins %0,%1,8,8" : "+r"(r) : "r"(0x000000F0u));
    snprintf(db, sizeof db, "ins=0x%x", r);
    check("ins", r == 0x1234F078u, db);
}

/* ================= branches with delay slots =================
 * TBR2/TBR1: normal branches (delay slot always executes).
 * TBL2/TBL1: branch-likely (delay slot annulled when not taken).
 * Taken:    delay=1 fall=0/100-skipped targ=7.
 * NotTaken: delay=1 (0 if likely) fall=200 targ=0/300-skipped. */

/* One macro for every branch shape. FRAG is the branch instruction with
 * its operands (%3,%4 two-reg or %3 one-reg); ANNUL_D is the expected
 * not-taken delay-slot count (1 normal, 0 branch-likely annulled). */
#define TBRANCH(NAME, FRAG, TA, TB, NA, NB, ANNUL_D)                       \
    __attribute__((noinline)) static void t_##NAME(void)                  \
    {                                                                     \
        char db[96];                                                      \
        int dt = 0, ft = 0, tt = 0, dn = 0, fn = 0, tn = 0;               \
        int a = (TA), b = (TB), c = (NA), d = (NB);                      \
        __asm__ volatile(                                                 \
            ".set noreorder\n" FRAG                                        \
            "addiu %0,$0,1\n" "addiu %1,$0,100\n"                          \
            "1:\n" "addiu %2,$0,7\n" ".set reorder\n"                      \
            : "+r"(dt), "+r"(ft), "+r"(tt) : "r"(a), "r"(b));              \
        __asm__ volatile(                                                 \
            ".set noreorder\n" FRAG                                        \
            "addiu %0,$0,1\n" "addiu %1,$0,200\n"                          \
            "j 2f\n" "nop\n" "1:\n" "addiu %2,$0,300\n" "2:\n"              \
            ".set reorder\n"                                              \
            : "+r"(dn), "+r"(fn), "+r"(tn) : "r"(c), "r"(d));              \
        snprintf(db, sizeof db, "d=%d f=%d t=%d", dt, ft, tt);            \
        check(#NAME "-taken", dt == 1 && ft == 0 && tt == 7, db);          \
        snprintf(db, sizeof db, "d=%d f=%d t=%d", dn, fn, tn);            \
        check(#NAME "-nottaken", dn == (ANNUL_D) && fn == 200 &&          \
              tn == 0, db);                                               \
    }

TBRANCH(beq, "beq %3,%4,1f\n", 0, 0, 0, 1, 1)
TBRANCH(bne, "bne %3,%4,1f\n", 0, 1, 0, 0, 1)
TBRANCH(blez, "blez %3,1f\n", 0, 0, 5, 0, 1)
TBRANCH(bgtz, "bgtz %3,1f\n", 5, 0, 0, 0, 1)
TBRANCH(bltz, "bltz %3,1f\n", -5, 0, 0, 0, 1)
TBRANCH(bgez, "bgez %3,1f\n", 0, 0, -5, 0, 1)
TBRANCH(beql, "beql %3,%4,1f\n", 0, 0, 0, 1, 0)
TBRANCH(bnel, "bnel %3,%4,1f\n", 0, 1, 0, 0, 0)
TBRANCH(blezl, "blezl %3,1f\n", 0, 0, 5, 0, 0)
TBRANCH(bgtzl, "bgtzl %3,1f\n", 5, 0, 0, 0, 0)
TBRANCH(bltzl, "bltzl %3,1f\n", -5, 0, 0, 0, 0)
TBRANCH(bgezl, "bgezl %3,1f\n", 0, 0, -5, 0, 0)

/* Explicit annulment trio (E02 T2c shape): normal BEQ counts the delay
 * slot, not-taken BEQL must not, taken BEQL must. */
__attribute__((noinline)) static void t_annul_trio(void)
{
    char db[96];
    int c_beq = 0, c_beql_nt = 0, c_beql_t = 0;
    int one = 1, zero = 0;
    __asm__ volatile(
        ".set noreorder\n"
        "beq $0,%3,1f\n"
        "addiu %0,%0,1\n"
        "j 2f\n" "nop\n" "1:\n" "nop\n" "2:\n"
        ".set reorder\n"
        : "+r"(c_beq) : "r"(zero), "r"(zero), "r"(one) : "memory");
    __asm__ volatile(
        ".set noreorder\n"
        "beql $0,%3,1f\n"
        "addiu %0,%0,1\n"
        "j 2f\n" "nop\n" "1:\n" "nop\n" "2:\n"
        ".set reorder\n"
        : "+r"(c_beql_nt) : "r"(zero), "r"(zero), "r"(one) : "memory");
    __asm__ volatile(
        ".set noreorder\n"
        "beql $0,%2,1f\n"
        "addiu %0,%0,1\n"
        "j 2f\n" "nop\n" "1:\n" "nop\n" "2:\n"
        ".set reorder\n"
        : "+r"(c_beql_t) : "r"(zero), "r"(zero), "r"(zero) : "memory");
    (void)zero;
    snprintf(db, sizeof db, "beq-nt=%d beql-nt=%d beql-t=%d",
             c_beq, c_beql_nt, c_beql_t);
    check("annul-trio", c_beq == 1 && c_beql_nt == 0 && c_beql_t == 1, db);
}

/* ================= jumps: J, BAL-link, JALR, JR ================= */

__attribute__((noinline)) static void t_j(void)
{
    char db[96];
    int d = 0, f = 0, t = 0;
    __asm__ volatile(
        ".set noreorder\n"
        "j 1f\n"
        "addiu %0,$0,1\n"
        "addiu %1,$0,100\n"
        "1:\n"
        "addiu %2,$0,7\n"
        ".set reorder\n"
        : "+r"(d), "+r"(f), "+r"(t));
    snprintf(db, sizeof db, "d=%d f=%d t=%d", d, f, t);
    check("j", d == 1 && f == 0 && t == 7, db);
}

/* BAL as the local-call link op (GAS PIC-expands jal; E02 note). */
__attribute__((noinline)) static void t_jlink(void)
{
    char db[96];
    int marker = 0;
    void *captured = NULL, *land = NULL, *saved = NULL;
    __asm__ volatile(
        "move %3,$31\n"
        ".set noreorder\n"
        "bal 1f\n"
        "addiu %0,$0,0x51\n"
        "2:\n"
        "move %1,$31\n"
        "j 3f\n"
        "nop\n"
        "1:\n"
        "jr $31\n"
        "nop\n"
        "3:\n"
        ".set reorder\n"
        "la %2,2b\n"
        "move $31,%3\n"
        : "=r"(marker), "=r"(captured), "=r"(land), "=r"(saved));
    (void)saved;
    snprintf(db, sizeof db, "marker=0x%x ra==land=%d",
             marker, captured == land);
    check("jal-link", marker == 0x51 && captured == land, db);
}

__attribute__((noinline)) static void t_jalr(void)
{
    char db[96];
    int marker = 0;
    void *captured = NULL, *land = NULL, *tmp = NULL, *saved = NULL;
    __asm__ volatile(
        "move %4,$31\n"
        ".set noreorder\n"
        "la %3,1f\n"
        "jalr %3\n"
        "addiu %0,$0,0x33\n"
        "2:\n"
        "move %1,$31\n"
        "j 3f\n"
        "nop\n"
        "1:\n"
        "jr $31\n"
        "nop\n"
        "3:\n"
        ".set reorder\n"
        "la %2,2b\n"
        "move $31,%4\n"
        : "=r"(marker), "=r"(captured), "=r"(land), "=&r"(tmp),
          "=&r"(saved));
    (void)saved;
    (void)tmp;
    snprintf(db, sizeof db, "marker=0x%x ra==land=%d",
             marker, captured == land);
    check("jalr", marker == 0x33 && captured == land, db);
}

__attribute__((noinline)) static void t_jr(void)
{
    char db[96];
    int d = 0, f = 0, t = 0;
    void *tmp = NULL;
    __asm__ volatile(
        ".set noreorder\n"
        "la %3,1f\n"
        "jr %3\n"
        "addiu %0,$0,1\n"
        "addiu %1,$0,100\n"
        "1:\n"
        "addiu %2,$0,7\n"
        ".set reorder\n"
        : "+r"(d), "+r"(f), "+r"(t), "=&r"(tmp));
    snprintf(db, sizeof db, "d=%d f=%d t=%d", d, f, t);
    check("jr", d == 1 && f == 0 && t == 7, db);
}

/* FP op in a JR delay slot (Wave P3 astra): the slot op spills FPCR
 * through w23, which also carries the indirect target; the indirect
 * exit must reload w23 from ctx->delay_target. */
__attribute__((noinline)) static void t_jr_fp_slot(void)
{
    char db[96];
    int landed = 0;
    uint32_t back = 0u;
    uint32_t a = 0x3fc00000u; /* 1.5f */
    uint32_t b = 0x40200000u; /* 2.5f */
    void *tgt = NULL;
    __asm__ volatile(
        "mtc1 %3, $f2\n"
        "mtc1 %4, $f4\n"
        ".set noreorder\n"
        "la %2, 1f\n"
        "jr %2\n"
        "add.s $f0, $f2, $f4\n" /* slot: must not divert the jump */
        "addiu %0, $0, 99\n"    /* trap pad: never executes */
        "j 2f\n"
        "nop\n"
        "1:\n"
        "addiu %0, %0, 1\n"
        "mfc1 %1, $f0\n"
        "2:\n"
        ".set reorder\n"
        : "+r"(landed), "=&r"(back), "=&r"(tgt)
        : "r"(a), "r"(b)
        : "memory", "$f0", "$f2", "$f4");
    snprintf(db, sizeof db, "landed=%d bits=0x%08x", landed, back);
    check("jr-fp-slot", landed == 1 && back == 0x40800000u, db);
}

/* Declined COP1 op in a branch delay slot (Wave P3 astra): cfc1 $0
 * (FIR) is not natively emitted, so the DBT must rewind the branch
 * and single-step the pair instead of silently skipping the slot. */
__attribute__((noinline)) static void t_cfc1_slot(void)
{
    char db[96];
    uint32_t v = 0u;
    int f = 0;
    int t = 0;
    __asm__ volatile(
        ".set noreorder\n"
        "beq %2, %3, 1f\n"
        "cfc1 %0, $0\n" /* declined slot: must still execute */
        "addiu %1, $0, 100\n"
        "1:\n"
        "addiu %1, %1, 7\n"
        ".set reorder\n"
        : "=&r"(v), "+r"(f)
        : "r"(t), "r"(t)
        : "memory");
    snprintf(db, sizeof db, "fir=0x%08x f=%d", v, f);
    check("cfc1-slot", v == 0x00739300u && f == 7, db);
}

/* ================= fault capture (page-end + delay-slot) ================= */

static volatile int g_sig;
static volatile uintptr_t g_siaddr;
static volatile uintptr_t g_scpc;
static sigjmp_buf g_jb;
static volatile int g_armed;
/* 1 when synchronous fault delivery works (qemu, Phase-4 translator);
 * 0 when sigaltstack/sigaction are unimplemented (Phase-1 interp): the
 * signal-dependent tests below report SKIP instead of dying. */
static int g_have_signals = 0;

static void fault_handler(int sig, siginfo_t *si, void *ctx)
{
    ucontext_t *uc = (ucontext_t *)ctx;
    g_sig = sig;
    g_siaddr = si ? (uintptr_t)si->si_addr : 0;
    g_scpc = (uintptr_t)uc->uc_mcontext.pc; /* O32: branch pc on DSlot */
    if (g_armed)
        siglongjmp(g_jb, 1);
    _exit(99);
}

static void install_fault_handlers(void)
{
    static uint8_t altstack[8192];
    stack_t ss;
    struct sigaction sa;
    ss.ss_sp = altstack;
    ss.ss_size = sizeof altstack;
    ss.ss_flags = 0;
    if (sigaltstack(&ss, NULL) != 0) {
        printf("P1 signals: SKIP sigaltstack errno=%d\n", errno);
        return;
    }
    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = fault_handler;
    sa.sa_flags = SA_SIGINFO | SA_ONSTACK;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGSEGV, &sa, NULL) != 0) {
        printf("P1 signals: SKIP sigaction-SEGV errno=%d\n", errno);
        return;
    }
    if (sigaction(SIGBUS, &sa, NULL) != 0) {
        printf("P1 signals: SKIP sigaction-BUS errno=%d\n", errno);
        return;
    }
    g_have_signals = 1;
}

/* Branch-likely at page_end-4 before a PROT_NONE page (E02 pattern).
 * qemu-user ground truth: BOTH taken and not-taken SIGSEGV with
 * sc_pc == the BEQL itself (translate-time fetch of the delay word);
 * the architectural annulment is proven by t_annul_trio above. */
#define OP_BEQL 0x50000000u
#define OP_J 0x08000000u
#define INSN_NOP 0x00000000u
#define INSN_JR_RA 0x03E00008u

static uint32_t enc_beql(int rs, int rt, int32_t off)
{
    return OP_BEQL | ((uint32_t)rs << 21) | ((uint32_t)rt << 16) |
           ((uint32_t)off & 0xFFFFu);
}

static uint32_t enc_j(uintptr_t target)
{
    return OP_J | (((uint32_t)target >> 2) & 0x03FFFFFFu);
}

__attribute__((noinline)) static void t_beql_pageend(void)
{
    char db[160];

    if (!g_have_signals) {
        printf("P1 beql-pageend-nottaken: SKIP no signal delivery\n");
        printf("P1 beql-pageend-taken: SKIP no signal delivery\n");
        return;
    }
    uint8_t *base = mmap(NULL, 2 * PAGE, PROT_READ | PROT_WRITE | PROT_EXEC,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (base == MAP_FAILED) {
        check("beql-pageend-setup", 0, "mmap failed");
        return;
    }
    {
        uint8_t *p1 = base, *p2 = base + PAGE;
        uintptr_t B = (uintptr_t)(p1 + PAGE - 4);
        uintptr_t SAFE = (uintptr_t)(p1 + 0x300);
        uintptr_t PRO = (uintptr_t)(p1 + 0x100);
        int32_t off = (int32_t)((int64_t)SAFE - (int64_t)(B + 4)) >> 2;
        typedef int (*stub_t)(int, int);
        stub_t stub = (stub_t)(void *)PRO;
        volatile int got_nt = 0, got_t = 0;
        volatile int sig_nt = 0, sig_t = 0;
        volatile int pcok_nt = 0, pcok_t = 0;
        volatile int adok_nt = 0, adok_t = 0;
        ((uint32_t *)(p1 + 0x100))[0] = enc_j(B);
        ((uint32_t *)(p1 + 0x100))[1] = INSN_NOP;
        ((uint32_t *)(p1 + 0x300))[0] = 0x24021111u;
        ((uint32_t *)(p1 + 0x300))[1] = INSN_JR_RA;
        ((uint32_t *)(p1 + 0x300))[2] = INSN_NOP;
        ((uint32_t *)(p1 + PAGE - 4))[0] = enc_beql(4, 5, off);
        ((uint32_t *)p2)[0] = INSN_NOP;
        ((uint32_t *)p2)[1] = INSN_NOP;
        __builtin___clear_cache((char *)base, (char *)(base + 2 * PAGE));
        if (mprotect(p2, PAGE, PROT_NONE) != 0) {
            check("beql-pageend-setup", 0, "mprotect failed");
            munmap(base, 2 * PAGE);
            return;
        }
        g_armed = 1;
        if (sigsetjmp(g_jb, 1) == 0) {
            stub(1, 2); /* not taken: a0 != a1 */
        } else {
            got_nt = 1;
            sig_nt = g_sig;
            pcok_nt = (g_scpc == B || g_scpc == B + 8);
            adok_nt = ((g_siaddr & ~(uintptr_t)0xFFFu) ==
                       (uintptr_t)p2);
        }
        g_armed = 0;
        g_armed = 1;
        if (sigsetjmp(g_jb, 1) == 0) {
            stub(7, 7); /* taken: a0 == a1 */
        } else {
            got_t = 1;
            sig_t = g_sig;
            pcok_t = (g_scpc == B);
            adok_t = ((g_siaddr & ~(uintptr_t)0xFFFu) ==
                      (uintptr_t)p2);
        }
        g_armed = 0;
        snprintf(db, sizeof db,
                 "qemu-fetch sig=%d branch-pc=%d p2base=%d",
                 sig_nt, pcok_nt, adok_nt);
        check("beql-pageend-nottaken",
              got_nt && sig_nt == 11 && pcok_nt && adok_nt, db);
        snprintf(db, sizeof db,
                 "qemu-fetch sig=%d branch-pc=%d p2base=%d",
                 sig_t, pcok_t, adok_t);
        check("beql-pageend-taken",
              got_t && sig_t == 11 && pcok_t && adok_t, db);
        mprotect(p2, PAGE, PROT_READ | PROT_WRITE);
        munmap(base, 2 * PAGE);
    }
}

/* Fault in a delay slot: signal pc must be the branch (pc - 4). */
__attribute__((noinline)) static void t_delayslot_sigpc(void)
{
    char db[160];

    if (!g_have_signals) {
        printf("P1 delayslot-sigpc: SKIP no signal delivery\n");
        return;
    }
    volatile int loaded = -1;
    volatile int got = 0, sig = 0, adok = 0;
    int rs = 0, rt = 0;
    g_armed = 1;
    if (sigsetjmp(g_jb, 1) == 0) {
        __asm__ volatile(
            ".set noreorder\n"
            "beq %1,%2,2f\n"
            "lw %0,0($0)\n" /* delay slot: load from NULL */
            "nop\n"
            "2:\n"
            "nop\n"
            ".set reorder\n"
            : "+r"(loaded)
            : "r"(rs), "r"(rt)
            : "memory");
    } else {
        got = 1;
        sig = g_sig;
        adok = (g_siaddr == 0);
    }
    g_armed = 0;
    snprintf(db, sizeof db, "sig=%d null-addr=%d loaded=%d",
             sig, adok, loaded);
    check("delayslot-sigpc",
          got && sig == 11 && adok && loaded == -1, db);
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    printf("P1 endian: LE\n");
#else
    printf("P1 endian: BE\n");
#endif
    install_fault_handlers();
    t_alu();
    t_shifts();
    t_muldiv();
    t_bshfl();
    t_beq();
    t_bne();
    t_blez();
    t_bgtz();
    t_bltz();
    t_bgez();
    t_beql();
    t_bnel();
    t_blezl();
    t_bgtzl();
    t_bltzl();
    t_bgezl();
    t_annul_trio();
    t_j();
    t_jlink();
    t_jalr();
    t_jr();
    t_jr_fp_slot();
    t_cfc1_slot();
    t_beql_pageend();
    t_delayslot_sigpc();
    t_llsc();
    t_unaligned();
    t_rdhwr();
    t_unaligned_child();
    t_raw_write();
    printf("P1 checks: %d pass, %d fail\n", g_pass, g_fail);
    if (g_fail == 0)
        printf("P1-RESULT: PASS\n");
    else
        printf("P1-RESULT: FAIL\n");
    fflush(stdout);
    raw_exit(g_fail == 0 ? 0 : 1);
}

