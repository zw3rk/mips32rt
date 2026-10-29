/*
 * tests/test_p4_threads_signals.c — Phase 4 guest test (RC4 gate).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Synchronous signal delivery, threads, and process lifecycle for
 * MIPS32r2 O32 guests, identical under qemu-mipsel (and qemu-mips BE)
 * and under mips32rt --interp / --dbt (LE+BE):
 *
 *  - t_sigreturn_recover: SIGSEGV on a PROT_NONE page; the handler
 *    inspects si_signo/si_addr and the ucontext fault pc, repairs the
 *    mapping with mprotect, and returns.  Execution resumes through
 *    rt_sigreturn with registers intact (frame restoration).
 *  - t_frame_modify_skip: a second fault where the handler instead
 *    advances the saved pc past the faulting store (frame
 *    modification); the store is skipped and execution continues.
 *  - t_sigbus_misaligned: misaligned LW delivers SIGBUS in-process.
 *  - t_threads: two pthreads share one counter (mutex/futex), one
 *    lock-free LL/SC counter, and a __thread TLS accumulator.
 *  - t_fork_exec_wait: fork + execve(self) + wait4 round-trip.
 *
 * Build (static, inside the debian container like run_p1_isa.sh):
 *   mipsel-linux-gnu-gcc -march=mips32r2 -static -pthread -O1 \
 *       -o /tmp/p4-le tests/test_p4_threads_signals.c
 */

#define _GNU_SOURCE /* wait4/sigaction/ucontext under strict -std=c11 */

#include <errno.h>
#include <pthread.h>
#include <sched.h>
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <ucontext.h>
#include <unistd.h>

static int g_pass = 0;
static int g_fail = 0;

static void check(const char *name, int ok, const char *detail)
{
    if (ok) {
        g_pass++;
        printf("P4 %s: ok %s\n", name, detail);
    } else {
        g_fail++;
        printf("P4 %s: FAIL %s\n", name, detail);
    }
}

/* ================= SIGSEGV recover + frame modify ================= */

static volatile uintptr_t g_segv_addr;
static volatile uintptr_t g_segv_pc;
static volatile int g_segv_sig;
static volatile int g_segv_count;
static volatile int g_segv_fix_map; /* 1: mprotect; 0: advance saved pc */

static void sev_handler(int sig, siginfo_t *si, void *ctx)
{
    ucontext_t *uc = (ucontext_t *)ctx;

    g_segv_sig = sig;
    g_segv_addr = si ? (uintptr_t)si->si_addr : 0;
    g_segv_pc = (uintptr_t)uc->uc_mcontext.pc;
    g_segv_count++;
    if (g_segv_fix_map) {
        /* Repair the mapping and re-execute the faulting store. */
        uintptr_t base = g_segv_addr & ~(uintptr_t)0xFFFu;

        if (mprotect((void *)base, 4096, PROT_READ | PROT_WRITE) != 0) {
            _exit(91);
        }
    } else {
        /* Skip the 4-byte faulting store (frame modification). */
        uc->uc_mcontext.pc += 4;
    }
}

__attribute__((noinline)) static void t_sigreturn_recover(void)
{
    char db[160];
    static uint8_t * volatile page;
    struct sigaction sa;
    void *want;
    void *got;

    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = sev_handler;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGSEGV, &sa, NULL) != 0) {
        printf("P4 sigreturn-recover: SKIP sigaction errno=%d\n", errno);
        printf("P4 frame-modify-skip: SKIP sigaction errno=%d\n", errno);
        return;
    }
    want = NULL;
    got = mmap(want, 8192, PROT_READ | PROT_WRITE,
               MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (got == MAP_FAILED) {
        check("sigreturn-setup", 0, "mmap failed");
        return;
    }
    page = (uint8_t *)got;
    if (mprotect(page, 4096, PROT_NONE) != 0) {
        check("sigreturn-setup", 0, "mprotect failed");
        munmap(got, 8192);
        return;
    }
    /* Fault 1: store to the guarded page; handler repairs, store lands. */
    g_segv_count = 0;
    g_segv_fix_map = 1;
    __asm__ volatile(
        "sw $0,0(%0)\n"
        : /* no outputs */
        : "r"(page)
        : "memory");
    snprintf(db, sizeof db, "sig=%d count=%d addr-ok=%d val=%u",
             g_segv_sig, g_segv_count,
             g_segv_addr == (uintptr_t)page,
             *(volatile unsigned *)page);
    check("sigreturn-recover",
          g_segv_sig == SIGSEGV && g_segv_count == 1 &&
              g_segv_addr == (uintptr_t)page &&
              *(volatile unsigned *)page == 0u,
          db);
    /* Fault 2: fresh guarded page; handler skips the store instead. */
    *(volatile unsigned *)(page + 4096) = 0xA5A5A5A5u;
    if (mprotect(page + 4096, 4096, PROT_NONE) != 0) {
        check("skip-setup", 0, "mprotect failed");
        munmap(got, 8192);
        return;
    }
    g_segv_count = 0;
    g_segv_fix_map = 0;
    {
        volatile unsigned *p = (volatile unsigned *)(page + 4096);

        __asm__ volatile(
            "sw $0,0(%0)\n"
            : /* no outputs */
            : "r"(p)
            : "memory");
    }
    /* Restore readability to inspect the (un)written word. */
    if (mprotect(page + 4096, 4096, PROT_READ | PROT_WRITE) != 0) {
        check("skip-setup", 0, "mprotect failed");
        munmap(got, 8192);
        return;
    }
    snprintf(db, sizeof db, "sig=%d count=%d addr-ok=%d kept=%x",
             g_segv_sig, g_segv_count,
             g_segv_addr == (uintptr_t)(page + 4096),
             *(volatile unsigned *)(page + 4096));
    check("frame-modify-skip",
          g_segv_sig == SIGSEGV && g_segv_count == 1 &&
              g_segv_addr == (uintptr_t)(page + 4096) &&
              *(volatile unsigned *)(page + 4096) == 0xA5A5A5A5u,
          db);
    munmap(got, 8192);
}

/* ================= SIGBUS misaligned LW (in-process) ================= */

static volatile int g_bus_sig;
static volatile uintptr_t g_bus_addr;
static sigjmp_buf g_bus_jb;
static volatile int g_bus_armed;

static void bus_handler(int sig, siginfo_t *si, void *ctx)
{
    (void)ctx;
    g_bus_sig = sig;
    g_bus_addr = si ? (uintptr_t)si->si_addr : 0;
    if (g_bus_armed) {
        siglongjmp(g_bus_jb, 1);
    }
    _exit(92);
}

/* Wave U3 FIXADE control: the translator emulates unaligned integer
 * accesses by default (fixade_enabled = 1, mirroring Linux MIPS
 * TIF_FIXADE). This fault-behavior test opts out explicitly with raw
 * O32 sysmips(MIPS_FIXADE = 7, arg) (nr 4149 = __NR_Linux + 149) and
 * restores the default afterwards; the result is ignored because
 * qemu-user has no FIXADE state and keeps faulting. */
__attribute__((noinline)) static void fixade_set(unsigned arg)
{
    register unsigned long r_v0 __asm__("$2") = 4149u;
    register unsigned long r_a0 __asm__("$4") = 7u;
    register unsigned long r_a1 __asm__("$5") = (unsigned long)arg;
    register unsigned long r_a3 __asm__("$7");
    __asm__ volatile("syscall"
                     : "+r"(r_v0), "=r"(r_a3)
                     : "r"(r_a0), "r"(r_a1)
                     : "memory");
    (void)r_v0;
    (void)r_a3;
}

__attribute__((noinline)) static void t_sigbus_misaligned(void)
{
    char db[160];
    static unsigned area[8];
    struct sigaction sa;
    volatile unsigned *p;
    unsigned v = 0xDEADBEEFu;
    volatile int got = 0;

    memset(&sa, 0, sizeof sa);
    sa.sa_sigaction = bus_handler;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGBUS, &sa, NULL) != 0 ||
        sigaction(SIGSEGV, &sa, NULL) != 0) {
        printf("P4 sigbus-misaligned: SKIP sigaction errno=%d\n", errno);
        return;
    }
    area[0] = 0x11223344u;
    area[1] = 0x55667788u;
    p = (volatile unsigned *)((uintptr_t)&area[0] + 1);
    g_bus_armed = 1;
    fixade_set(0u); /* fault, don't emulate (Wave U3 default-on) */
    if (sigsetjmp(g_bus_jb, 1) == 0) {
        __asm__ volatile("lw %0,0(%1)" : "=r"(v) : "r"(p) : "memory");
    } else {
        got = 1;
    }
    g_bus_armed = 0;
    fixade_set(1u); /* restore translator default for later tests */
    snprintf(db, sizeof db, "sig=%d addr-ok=%d kept=%x", g_bus_sig,
             g_bus_addr == (uintptr_t)p, v);
    check("sigbus-misaligned",
          got && (g_bus_sig == SIGBUS || g_bus_sig == SIGSEGV) &&
              g_bus_addr == (uintptr_t)p,
          db);
}

/* ================= threads: mutex + LL/SC + TLS ================= */

#define THR_ITERS 2000

static pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;
static volatile int g_shared;
static volatile int g_llsc_shared;
static __thread int t_local;

/* LL/SC add-1 with the retry inside one asm block (P1 llsc_add1
 * shape).  A C-level retry loop around separate ll/sc asm statements
 * is NOT qemu-user compatible (observed: single-threaded counter
 * stuck at 1 / garbage); the in-asm beqz retry is exact on qemu,
 * interp and dbt. */
static void llsc_add1(volatile int *p)
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
}

static void *thr_main(void *arg)
{
    int i;
    int n = *(int *)arg;

    for (i = 0; i < n; i++) {
        pthread_mutex_lock(&g_mu);
        g_shared++;
        pthread_mutex_unlock(&g_mu);
        t_local++;
    }
    /* Lock-free LL/SC increments: reservation invalidation across
     * threads is what makes the shared final sum exact. */
    for (i = 0; i < n; i++) {
        llsc_add1(&g_llsc_shared);
    }
    return (void *)(intptr_t)t_local;
}

static void t_threads(void)
{
    char db[160];
    pthread_t t1;
    pthread_t t2;
    int n = THR_ITERS;
    void *r1 = NULL;
    void *r2 = NULL;

    g_shared = 0;
    g_llsc_shared = 0;
    {
        char d2[64];
        int rc = pthread_create(&t1, NULL, thr_main, &n);

        if (rc != 0) {
            snprintf(d2, sizeof d2, "pthread_create t1 errno=%d", rc);
            check("threads", 0, d2);
            return;
        }
    }
    {
        char d2[64];
        int rc = pthread_create(&t2, NULL, thr_main, &n);

        if (rc != 0) {
            snprintf(d2, sizeof d2, "pthread_create t2 errno=%d", rc);
            check("threads", 0, d2);
            return;
        }
    }
    if (pthread_join(t1, &r1) != 0 || pthread_join(t2, &r2) != 0) {
        check("threads", 0, "pthread_join failed");
        return;
    }
    snprintf(db, sizeof db, "shared=%d llsc=%d loc=%ld+%ld",
             g_shared, g_llsc_shared, (long)(intptr_t)r1,
             (long)(intptr_t)r2);
    check("threads",
          g_shared == 2 * THR_ITERS &&
              g_llsc_shared == 2 * THR_ITERS &&
              (long)(intptr_t)r1 == THR_ITERS &&
              (long)(intptr_t)r2 == THR_ITERS,
          db);
}

/* ================= fork + wait4 =================
 *
 * qemu-user cannot execve a MIPS binary (host ENOEXEC), so the golden
 * comparison covers fork + wait4 plus the execve ENOENT dispatch path
 * only.  Successful fork + execve(self) + wait4 runs as the
 * translator-only "p4-exec-probe" mode (see main + run_p4.sh). */

static void t_fork_wait(void)
{
    char db[160];
    pid_t pid;
    int st;
    struct rusage ru;

    fflush(stdout);
    pid = fork();
    if (pid < 0) {
        if (errno == ENOSYS) {
            printf("P4 fork-wait: SKIP fork unimplemented\n");
        } else {
            check("fork-wait", 0, "fork failed");
        }
        return;
    }
    if (pid == 0) {
        _exit(43);
    }
    memset(&ru, 0, sizeof ru);
    if (wait4(pid, &st, 0, &ru) != pid) {
        check("fork-wait", 0, "wait4 failed");
        return;
    }
    snprintf(db, sizeof db, "exited=%d code=%d",
             WIFEXITED(st), WIFEXITED(st) ? WEXITSTATUS(st) : -1);
    check("fork-wait", WIFEXITED(st) && WEXITSTATUS(st) == 43, db);
}

/* execve dispatch validation with identical qemu behavior. */
static void t_execve_enoent(void)
{
    char db[160];
    char *args[2];

    args[0] = (char *)"nope";
    args[1] = NULL;
    errno = 0;
    if (execve("/nonexistent-p4-guest", args, NULL) == 0) {
        check("execve-enoent", 0, "execve unexpectedly succeeded");
        return;
    }
    snprintf(db, sizeof db, "errno=%d", errno);
    check("execve-enoent", errno == ENOENT, db);
}

/* Translator-only probe (no qemu golden): fork + execve(self as the
 * exec-child marker) + wait4 success path, exercising in-process ELF
 * reload, signal-disposition reset and O_CLOEXEC handling. */
static int t_exec_probe(char **argv, char **envp)
{
    pid_t pid;
    int st;
    struct rusage ru;

    fflush(stdout);
    pid = fork();
    if (pid < 0) {
        printf("P4-EXEC-PROBE: SKIP fork errno=%d\n", errno);
        return 2;
    }
    if (pid == 0) {
        char *args[3];

        args[0] = argv[0];
        args[1] = (char *)"p4-exec-child";
        args[2] = NULL;
        execve(argv[0], args, envp);
        _exit(93); /* execve failed */
    }
    memset(&ru, 0, sizeof ru);
    if (wait4(pid, &st, 0, &ru) != pid) {
        printf("P4-EXEC-PROBE: FAIL wait4\n");
        return 1;
    }
    printf("P4-EXEC-PROBE: exited=%d code=%d\n",
           WIFEXITED(st), WIFEXITED(st) ? WEXITSTATUS(st) : -1);
    if (WIFEXITED(st) && WEXITSTATUS(st) == 42) {
        printf("P4-RESULT: PASS\n");
        return 0;
    }
    printf("P4-RESULT: FAIL\n");
    return 1;
}

int main(int argc, char **argv, char **envp)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    if (argc == 2 && strcmp(argv[1], "p4-exec-child") == 0) {
        printf("P4-EXEC-CHILD: ok\n");
        return 42;
    }
    if (argc == 2 && strcmp(argv[1], "p4-exec-probe") == 0) {
        return t_exec_probe(argv, envp);
    }
    t_sigreturn_recover();
    t_sigbus_misaligned();
    t_threads();
    t_fork_wait();
    t_execve_enoent();

    printf("P4 checks: %d pass, %d fail\n", g_pass, g_fail);
    if (g_fail == 0) {
        printf("P4-RESULT: PASS\n");
        return 0;
    }
    printf("P4-RESULT: FAIL\n");
    return 1;
}
