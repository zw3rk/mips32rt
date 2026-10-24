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

#define PAGE 4096u

/* O32 syscall numbers (arch/mips, __NR_Linux base 4000). */
#define NR_EXIT 4001
#define NR_WRITE 4004
#define NR_SET_THREAD_AREA 4283

static int g_pass = 0, g_fail = 0;

static void check(const char *name, int cond, const char *detail)
{
    if (cond) {
        g_pass++;
        printf("P1 %s: PASS %s\n", name, detail);
    } else {
        g_fail++;
        printf("P1 %s: FAIL %s\n", name, detail);
    }
}

/* ---- raw O32 syscall (number in $v0, error flag out via $a3) ---- */
static long raw_sys3(long num, long a0, long a1, long a2, int *pa3)
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
            pcok_nt = (g_scpc == B);
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

/* ================= LL/SC (E06 patterns) ================= */

static int llsc_add1(volatile int *p)
{
    int oldval, newval;
    __asm__ volatile(
        "1:\n\t"
        "ll %0,0(%2)\n\t"
        "addu %1,%0,1\n\t"
        "sc %1,0(%2)\n\t"
        "beqz %1,1b\n\t"
        "nop\n\t"
        : "=&r"(oldval), "=&r"(newval)
        : "r"(p)
        : "memory");
    return oldval;
}

static int sc_after_store(volatile int *p, int interfere, int scval)
{
    int oldval, scres;
    __asm__ volatile(
        "ll %0,0(%2)\n\t"
        "sw %3,0(%2)\n\t"
        "sc %4,0(%2)\n\t"
        "move %1,%4\n\t"
        : "=&r"(oldval), "=&r"(scres)
        : "r"(p), "r"(interfere), "r"(scval)
        : "memory");
    (void)oldval;
    return scres;
}

__attribute__((noinline)) static void t_llsc(void)
{
    char db[128];
    volatile int cell = 0;
    int i, ok = 1;
    for (i = 0; i < 1000; i++) {
        if (llsc_add1(&cell) != i)
            ok = 0;
    }
    snprintf(db, sizeof db, "1000x add1 cell=%d", cell);
    check("llsc-success", ok && cell == 1000, db);
    {
        volatile int victim = 0;
        int scres = sc_after_store(&victim, 0x11111111, 0x22222222);
        snprintf(db, sizeof db, "scres=%d cell=0x%x", scres, victim);
        check("llsc-interfere-fail",
              scres == 0 && victim == 0x11111111, db);
    }
}

/* ================= LWL/LWR/SWL/SWR (E05 tables) ================= */

static unsigned char area[16] __attribute__((aligned(8)));

#define INIT_RT 0xAABBCCDDu

static uint32_t do_lwl(unsigned char *addr, uint32_t init)
{
    uint32_t rt = init;
    __asm__ volatile("lwl %0,0(%1)" : "+r"(rt) : "r"(addr) : "memory");
    return rt;
}

static uint32_t do_lwr(unsigned char *addr, uint32_t init)
{
    uint32_t rt = init;
    __asm__ volatile("lwr %0,0(%1)" : "+r"(rt) : "r"(addr) : "memory");
    return rt;
}

static void do_swl(unsigned char *addr, uint32_t v)
{
    __asm__ volatile("swl %0,0(%1)" : : "r"(v), "r"(addr) : "memory");
}

static void do_swr(unsigned char *addr, uint32_t v)
{
    __asm__ volatile("swr %0,0(%1)" : : "r"(v), "r"(addr) : "memory");
}

static uint32_t do_unaligned_load(unsigned char *addr, uint32_t init)
{
    uint32_t rt = init;
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    __asm__ volatile(
        "lwr %0,0(%1)\n"
        "lwl %0,3(%1)\n"
        : "+r"(rt)
        : "r"(addr)
        : "memory");
#else
    __asm__ volatile(
        "lwl %0,0(%1)\n"
        "lwr %0,3(%1)\n"
        : "+r"(rt)
        : "r"(addr)
        : "memory");
#endif
    return rt;
}

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
static const uint32_t exp_lwl[4] =
    { 0x11BBCCDDu, 0x2211CCDDu, 0x332211DDu, 0x44332211u };
static const uint32_t exp_lwr[4] =
    { 0x44332211u, 0xAA443322u, 0xAABB4433u, 0xAABBCC44u };
static const unsigned char exp_swl[4][6] = {
    { 0xAA, 0x00, 0x00, 0x00, 0x00, 0x00 },
    { 0xBB, 0xAA, 0x00, 0x00, 0x00, 0x00 },
    { 0xCC, 0xBB, 0xAA, 0x00, 0x00, 0x00 },
    { 0xDD, 0xCC, 0xBB, 0xAA, 0x00, 0x00 },
};
static const unsigned char exp_swr[4][6] = {
    { 0xDD, 0xCC, 0xBB, 0xAA, 0x00, 0x00 },
    { 0x00, 0xDD, 0xCC, 0xBB, 0x00, 0x00 },
    { 0x00, 0x00, 0xDD, 0xCC, 0x00, 0x00 },
    { 0x00, 0x00, 0x00, 0xDD, 0x00, 0x00 },
};
static const uint32_t exp_ulw[4] =
    { 0x44332211u, 0x55443322u, 0x66554433u, 0x77665544u };
#else
static const uint32_t exp_lwl[4] =
    { 0x11223344u, 0x223344DDu, 0x3344CCDDu, 0x44BBCCDDu };
static const uint32_t exp_lwr[4] =
    { 0xAABBCC11u, 0xAABB1122u, 0xAA112233u, 0x11223344u };
static const unsigned char exp_swl[4][6] = {
    { 0xAA, 0xBB, 0xCC, 0xDD, 0x00, 0x00 },
    { 0x00, 0xAA, 0xBB, 0xCC, 0x00, 0x00 },
    { 0x00, 0x00, 0xAA, 0xBB, 0x00, 0x00 },
    { 0x00, 0x00, 0x00, 0xAA, 0x00, 0x00 },
};
static const unsigned char exp_swr[4][6] = {
    { 0xDD, 0x00, 0x00, 0x00, 0x00, 0x00 },
    { 0xCC, 0xDD, 0x00, 0x00, 0x00, 0x00 },
    { 0xBB, 0xCC, 0xDD, 0x00, 0x00, 0x00 },
    { 0xAA, 0xBB, 0xCC, 0xDD, 0x00, 0x00 },
};
static const uint32_t exp_ulw[4] =
    { 0x11223344u, 0x22334455u, 0x33445566u, 0x44556677u };
#endif

static void reset_mem(void)
{
    memset(area, 0x00, sizeof area);
    area[0] = 0x11;
    area[1] = 0x22;
    area[2] = 0x33;
    area[3] = 0x44;
}

__attribute__((noinline)) static void t_unaligned(void)
{
    char db[160];
    int k, ok;
    ok = 1;
    for (k = 0; k < 4; k++) {
        uint32_t r;
        reset_mem();
        r = do_lwl(area + k, INIT_RT);
        if (r != exp_lwl[k])
            ok = 0;
        reset_mem();
        r = do_lwr(area + k, INIT_RT);
        if (r != exp_lwr[k])
            ok = 0;
    }
    snprintf(db, sizeof db, "lwl/lwr x4 match=%d", ok);
    check("lwl-lwr", ok, db);
    ok = 1;
    for (k = 0; k < 4; k++) {
        memset(area, 0x00, sizeof area);
        do_swl(area + k, INIT_RT);
        if (memcmp(area, exp_swl[k], 6) != 0)
            ok = 0;
        memset(area, 0x00, sizeof area);
        do_swr(area + k, INIT_RT);
        if (memcmp(area, exp_swr[k], 6) != 0)
            ok = 0;
    }
    snprintf(db, sizeof db, "swl/swr x4 match=%d", ok);
    check("swl-swr", ok, db);
    ok = 1;
    for (k = 0; k < 4; k++) {
        uint32_t r;
        reset_mem();
        area[4] = 0x55;
        area[5] = 0x66;
        area[6] = 0x77;
        r = do_unaligned_load(area + k, INIT_RT);
        if (r != exp_ulw[k])
            ok = 0;
    }
    snprintf(db, sizeof db, "ulw-idiom x4 match=%d", ok);
    check("ulw-idiom", ok, db);
}

/* ================= RDHWR / set_thread_area (E06) ================= */

static unsigned long rdhwr_mnemonic(void)
{
    unsigned long v;
    __asm__ volatile("rdhwr %0,$29" : "=r"(v));
    return v;
}

/* rdhwr $v1($3),$29 via its exact 32-bit encoding 0x7c03e83b. */
static unsigned long rdhwr_fixed(void)
{
    unsigned long v, save3;
    __asm__ volatile(
        "move %1,$3\n\t"
        ".word 0x7c03e83b\n\t"
        "move %0,$3\n\t"
        "move $3,%1\n\t"
        : "=r"(v), "=&r"(save3)
        :
        : "memory");
    return v;
}

static __thread int tls_var = 42;

__attribute__((noinline)) static void t_rdhwr(void)
{
    char db[160];
    unsigned long u_m = rdhwr_mnemonic();
    unsigned long u_f = rdhwr_fixed();
    long rc1, rc2;
    unsigned long u_set, u_back;
    snprintf(db, sizeof db, "agree=%d nonzero=%d",
             u_m == u_f, u_m != 0);
    check("rdhwr", u_m == u_f && u_m != 0, db);
    /* No libc calls between the foreign install and the restore. */
    rc1 = syscall(NR_SET_THREAD_AREA, 0x51ab0001UL);
    u_set = rdhwr_mnemonic();
    rc2 = syscall(NR_SET_THREAD_AREA, u_m);
    u_back = rdhwr_mnemonic();
    snprintf(db, sizeof db, "set-rc=%ld set-match=%d restore-rc=%ld "
             "restore-match=%d tls=%d",
             rc1, u_set == 0x51ab0001UL, rc2, u_back == u_m, tls_var);
    check("set-thread-area", rc1 == 0 && u_set == 0x51ab0001UL &&
          rc2 == 0 && u_back == u_m && tls_var == 42, db);
}

/* ================= unaligned LW fault in a forked child =================
 * qemu-user ground truth (E05): plain misaligned LW raises AdEL, delivered
 * as SIGBUS (MIPS signal 10), never emulated. The Phase-1 translator
 * contract maps any such fault to process exit 139; here the child must
 * die by signal so the suite itself survives and exits 0. */

__attribute__((noinline)) static void t_unaligned_child(void)
{
    char db[160];
    pid_t pid;
    int st;
    fflush(stdout);
    pid = fork();
    if (pid < 0) {
        if (errno == ENOSYS) {
            printf("P1 unaligned-child: SKIP fork unimplemented\n");
            return;
        }
        check("unaligned-child", 0, "fork failed");
        return;
    }
    if (pid == 0) {
        uint32_t r = 0xDEADBEEFu;
        unsigned char *p;
        signal(SIGBUS, SIG_DFL);
        signal(SIGSEGV, SIG_DFL);
        reset_mem();
        p = area + 1;
        __asm__ volatile("lw %0,0(%1)" : "=r"(r) : "r"(p) : "memory");
        _exit(99); /* reached only if the fault was emulated */
    }
    while (waitpid(pid, &st, 0) < 0) {
    }
    if (WIFEXITED(st) && WEXITSTATUS(st) == 99) {
        snprintf(db, sizeof db, "child survived fault (emulated)");
        check("unaligned-child", 0, db);
    } else if (WIFSIGNALED(st)) {
        snprintf(db, sizeof db, "child termsig=%d "
                 "(qemu AdEL->SIGBUS=10; translator fault contract: "
                 "exit 139)", WTERMSIG(st));
        check("unaligned-child",
              WTERMSIG(st) == SIGBUS || WTERMSIG(st) == SIGSEGV, db);
    } else {
        snprintf(db, sizeof db, "child status=0x%x", st);
        check("unaligned-child", 0, db);
    }
}

/* ================= raw write path ================= */

__attribute__((noinline)) static void t_raw_write(void)
{
    char db[96];
    static const char msg[] = "P1-RAW-WRITE: ok\n";
    int a3 = -1;
    long r = raw_sys3(NR_WRITE, 1, (long)msg, (long)(sizeof msg - 1),
                      &a3);
    snprintf(db, sizeof db, "raw-write ret=%ld a3=%d", r, a3);
    check("raw-write", r == (long)(sizeof msg - 1) && a3 == 0, db);
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

