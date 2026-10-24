/* E02: branch delay slots, BEQL annulment vs page-end faults, delay-slot signals.
 *
 * MIPS O32, runs under qemu-mipsel (LE) and qemu-mips (BE).
 * All verdicts are qemu-observed ground truth unless marked UNVERIFIED.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <setjmp.h>
#include <sys/mman.h>
#include <ucontext.h>
#include <unistd.h>

#define PAGE 4096u

/* ---- shared signal capture ---- */
static volatile int g_sig;
static volatile uintptr_t g_siaddr;
static volatile uintptr_t g_scpc;
static sigjmp_buf g_jb;
static volatile int g_jb_armed;

static void handler(int sig, siginfo_t *si, void *ctx)
{
    ucontext_t *uc = (ucontext_t *)ctx;
    g_sig = sig;
    g_siaddr = si ? (uintptr_t)si->si_addr : 0;
    g_scpc = (uintptr_t)uc->uc_mcontext.pc; /* O32 mcontext_t pc field */
    if (g_jb_armed)
        siglongjmp(g_jb, 1);
    _exit(99);
}

/* ---- (1a) normal BEQ taken: delay slot runs, fallthrough skipped ---- */
__attribute__((noinline)) static void t_beq_taken(void)
{
    int delay = 0, fall = 0, targ = 0;
    __asm__ volatile (
        ".set noreorder\n"
        "beq $0, $0, 1f\n"        /* always taken */
        "addiu %0, $0, 1\n"       /* delay slot: executes */
        "addiu %1, $0, 100\n"     /* fallthrough: skipped */
        "1:\n"
        "addiu %2, $0, 7\n"       /* target: executes */
        ".set reorder\n"
        : "+r" (delay), "+r" (fall), "+r" (targ));
    printf("T1a beq-taken: delay=%d fall=%d targ=%d (expect 1 0 7) %s\n",
           delay, fall, targ,
           (delay == 1 && fall == 0 && targ == 7) ? "MATCH" : "MISMATCH");
}

/* ---- (1b) normal BEQ not taken: delay slot still runs, target skipped ---- */
__attribute__((noinline)) static void t_beq_nottaken(void)
{
    int delay = 0, fall = 0, targ = 0;
    int one = 1;
    __asm__ volatile (
        ".set noreorder\n"
        "beq $0, %3, 1f\n"        /* 0 == 1 false: not taken */
        "addiu %0, $0, 1\n"       /* delay slot: executes */
        "addiu %1, $0, 200\n"     /* fallthrough: executes */
        "j 2f\n"
        "nop\n"
        "1:\n"
        "addiu %2, $0, 300\n"     /* target: skipped */
        "2:\n"
        ".set reorder\n"
        : "+r" (delay), "+r" (fall), "+r" (targ)
        : "r" (one));
    printf("T1b beq-nottaken: delay=%d fall=%d targ=%d (expect 1 200 0) %s\n",
           delay, fall, targ,
           (delay == 1 && fall == 200 && targ == 0) ? "MATCH" : "MISMATCH");
}

/* ---- (1c) JAL: delay slot runs, ra = address of insn after delay (pc+8) ---- */
__attribute__((noinline)) static void t_jal_link(void)
{
    int marker = 0;
    void *captured = NULL, *land = NULL, *saved = NULL;
    __asm__ volatile (
        "move %3, $31\n"          /* save entry ra */
        ".set noreorder\n"
        "bal 1f\n"                /* NOTE: bal, not jal: GAS PIC-expands jal */
        "addiu %0, $0, 0x51\n"    /* delay slot marker */
        "2:\n"
        "move %1, $31\n"          /* ra captured here */
        "j 3f\n"
        "nop\n"
        "1:\n"
        "jr $31\n"                /* subroutine returns to 2: */
        "nop\n"
        "3:\n"
        ".set reorder\n"
        "la %2, 2b\n"             /* addr of insn after delay slot */
        "move $31, %3\n"          /* restore entry ra */
        : "=r" (marker), "=r" (captured), "=r" (land), "=r" (saved));
    (void)saved;
    printf("T1c bal-link: marker=0x%x ra=%p land=%p diff=%ld (expect marker 0x51 diff 0) %s\n",
           marker, captured, land, (long)((char *)captured - (char *)land),
           (marker == 0x51 && captured == land) ? "MATCH" : "MISMATCH");
}

/* ---- (2) BEQL at page end: annulment vs fault address ---- */
#define OP_BEQL 0x50000000u
#define OP_J    0x08000000u
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

__attribute__((noinline)) static void t_beql_page(void)
{
    uint8_t *base = mmap(NULL, 2 * PAGE, PROT_READ | PROT_WRITE | PROT_EXEC,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (base == MAP_FAILED) { perror("mmap"); exit(1); }
    uint8_t *p1 = base, *p2 = base + PAGE;
    uintptr_t B = (uintptr_t)(p1 + PAGE - 4);   /* BEQL site: last word of p1 */
    uintptr_t SAFE = (uintptr_t)(p1 + 0x300);   /* taken-target landing pad */
    uintptr_t PRO = (uintptr_t)(p1 + 0x100);    /* prologue entry */

    /* prologue: j B; nop */
    ((uint32_t *)(p1 + 0x100))[0] = enc_j(B);
    ((uint32_t *)(p1 + 0x100))[1] = INSN_NOP;
    /* SAFE pad (unreachable in practice): v0=0x1111; jr ra; nop */
    ((uint32_t *)(p1 + 0x300))[0] = 0x24021111u;
    ((uint32_t *)(p1 + 0x300))[1] = INSN_JR_RA;
    ((uint32_t *)(p1 + 0x300))[2] = INSN_NOP;
    /* BEQL a0,a1 -> SAFE ; delay slot word lives at p2+0 */
    int32_t off = (int32_t)((int64_t)SAFE - (int64_t)(B + 4)) >> 2;
    uint32_t beql = enc_beql(4, 5, off);
    ((uint32_t *)(p1 + PAGE - 4))[0] = beql;
    /* delay-slot placeholder word on p2 (about to become PROT_NONE) */
    ((uint32_t *)p2)[0] = INSN_NOP;
    ((uint32_t *)p2)[1] = INSN_NOP;

    __builtin___clear_cache((char *)base, (char *)(base + 2 * PAGE));
    if (mprotect(p2, PAGE, PROT_NONE) != 0) { perror("mprotect"); exit(1); }

    printf("T2 layout: p1=%p p2=%p(none) PRO@%p=J(0x%08x) BEQL@%p=0x%08x off=%d delay@%p cont@%p safe@%p\n",
           (void *)p1, (void *)p2, (void *)PRO, ((uint32_t *)(p1 + 0x100))[0],
           (void *)B, beql, off,
           (void *)(B + 4), (void *)(B + 8), (void *)SAFE);

    typedef int (*stub_t)(int, int);
    stub_t stub = (stub_t)(void *)PRO;

    /* Case A: not taken (a0=1,a1=2). Annulment => delay word never fetched;
     * continuation fetch at B+8 must fault instead. */
    g_jb_armed = 1;
    if (sigsetjmp(g_jb, 1) == 0) {
        stub(1, 2);
        g_jb_armed = 0;
        printf("T2a beql-nottaken: NO SIGNAL (unexpected)\n");
    } else {
        g_jb_armed = 0;
        printf("T2a beql-nottaken: sig=%d si_addr=%p sc_pc=%p (cont=%p delay=%p)\n",
               g_sig, (void *)g_siaddr, (void *)g_scpc,
               (void *)(B + 8), (void *)(B + 4));
    }

    /* Case B: taken (a0=7,a1=7). Delay slot executes => fetch at B+4 faults. */
    g_jb_armed = 1;
    if (sigsetjmp(g_jb, 1) == 0) {
        stub(7, 7);
        g_jb_armed = 0;
        printf("T2b beql-taken: NO SIGNAL (unexpected)\n");
    } else {
        g_jb_armed = 0;
        printf("T2b beql-taken: sig=%d si_addr=%p sc_pc=%p (cont=%p delay=%p)\n",
               g_sig, (void *)g_siaddr, (void *)g_scpc,
               (void *)(B + 8), (void *)(B + 4));
    }

    mprotect(p2, PAGE, PROT_READ | PROT_WRITE);
    munmap(base, 2 * PAGE);
}

/* ---- (2c) true annulment check: counting delay slot, BEQ vs BEQL ---- */
__attribute__((noinline)) static void t_beql_annul(void)
{
    int c_beq = 0, c_beql_nt = 0, c_beql_t = 0;
    int one = 1, zero = 0;
    /* normal BEQ not taken: delay slot MUST execute */
    __asm__ volatile (
        ".set noreorder\n"
        "beq $0, %3, 1f\n"
        "addiu %0, %0, 1\n"
        "j 2f\n"
        "nop\n"
        "1:\n"
        "nop\n"
        "2:\n"
        ".set reorder\n"
        : "+r" (c_beq) : "r" (zero), "r" (zero), "r" (one) : "memory");
    /* BEQL not taken: delay slot must be ANNULLED (no increment) */
    __asm__ volatile (
        ".set noreorder\n"
        "beql $0, %3, 1f\n"
        "addiu %0, %0, 1\n"
        "j 2f\n"
        "nop\n"
        "1:\n"
        "nop\n"
        "2:\n"
        ".set reorder\n"
        : "+r" (c_beql_nt) : "r" (zero), "r" (zero), "r" (one) : "memory");
    /* BEQL taken: delay slot MUST execute */
    __asm__ volatile (
        ".set noreorder\n"
        "beql $0, %2, 1f\n"
        "addiu %0, %0, 1\n"
        "j 2f\n"
        "nop\n"
        "1:\n"
        "nop\n"
        "2:\n"
        ".set reorder\n"
        : "+r" (c_beql_t) : "r" (zero), "r" (zero), "r" (zero) : "memory");
    (void)zero;
    printf("T2c annul: beq-nt=%d beql-nt=%d beql-t=%d (expect 1 0 1) %s\n",
           c_beq, c_beql_nt, c_beql_t,
           (c_beq == 1 && c_beql_nt == 0 && c_beql_t == 1)
           ? "MATCH" : "MISMATCH");
}

/* ---- (3) fault in delay slot: ucontext pc == branch pc ----
 * branch address verified against objdump (branch label self-measurement
 * via la is unreliable under PIC codegen); sc_pc is the ground truth. */
__attribute__((noinline)) static void t_delayslot_sigpc(void)
{
    int loaded = -1, rs = 0, rt = 0;
    g_jb_armed = 1;
    if (sigsetjmp(g_jb, 1) == 0) {
        __asm__ volatile (
            ".set noreorder\n"
            "beq %1, %2, 2f\n"    /* taken (0==0); delay slot faults */
            "lw %0, 0($0)\n"      /* delay slot: load from NULL */
            "nop\n"
            "2:\n"
            "nop\n"
            ".set reorder\n"
            : "+r" (loaded)
            : "r" (rs), "r" (rt)
            : "memory");
        g_jb_armed = 0;
        printf("T3 delayslot-fault: NO SIGNAL (unexpected)\n");
    } else {
        g_jb_armed = 0;
        printf("T3 delayslot-fault: sig=%d si_addr=%p sc_pc=%p loaded=%d\n",
               g_sig, (void *)g_siaddr, (void *)g_scpc, loaded);
    }
}

int main(void)
{
    stack_t ss;
    static uint8_t altstack[8192];
    struct sigaction sa;
    ss.ss_sp = altstack;
    ss.ss_size = sizeof(altstack);
    ss.ss_flags = 0;
    if (sigaltstack(&ss, NULL) != 0) { perror("sigaltstack"); return 1; }
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = handler;
    sa.sa_flags = SA_SIGINFO | SA_ONSTACK;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGSEGV, &sa, NULL) != 0) { perror("sigaction"); return 1; }

    printf("E02 probe start (sizeof void*=%zu)\n", sizeof(void *));
    t_beq_taken();
    t_beq_nottaken();
    t_jal_link();
    t_beql_page();
    t_beql_annul();
    t_delayslot_sigpc();
    printf("E02 probe done\n");
    return 0;
}
