/*
 * tests/test_p6_perms.c — Phase 6 adjacent-page permission parity (lane L6b).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Guest-side C (libc allowed: this is the test, not the translator).
 * Built `-static` for mipsel (LE) and mips (BE), executed under
 * qemu-mipsel / qemu-mips (golden) and under mips32rt --interp / --dbt
 * (LE+BE, byte-identical stdout+exit, 0 difftest divergences).
 *
 * Covers adjacent 4 KiB pages with distinct permissions:
 *  - RX next to RW (write to the RX page faults, RW page stays writable);
 *  - RW next to RX (fault lands exactly on the second page);
 *  - RELRO-style RX-then-RW split over one 3-page mapping (fault on the
 *    second RX page, RW tail stays writable);
 *  - PROT_NONE guard page (read and write fault with SEGV_ACCERR on the
 *    guarded page — the VMA exists but carries no permissions — while
 *    the neighbour page stays usable);
 *  - execute from an RX page returns, execute from an RW page faults.
 *
 * Every faulting access runs in a forked child with a SA_SIGINFO SIGSEGV
 * handler that records si_code/si_addr and siglongjmps back; the child
 * prints the verdict and _exits. stdout is deterministic by construction:
 * only page-relative offsets (si_addr - mapping base), si_code numbers,
 * and return values are printed — never absolute addresses.
 *
 * Build (inside the debian lane container, see tests/run_p6.sh):
 *   mipsel-linux-gnu-gcc -march=mips32r2 -static -O1 -std=c11 -Wall -Wextra \
 *       -o /tmp/p6perms-le tests/test_p6_perms.c
 *   mips-linux-gnu-gcc -march=mips32r2 -EB -static -O1 -std=c11 -Wall -Wextra \
 *       -o /tmp/p6perms-be tests/test_p6_perms.c
 */
#define _GNU_SOURCE
#include <errno.h>
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define PAGE 4096UL

static int g_pass = 0;
static int g_fail = 0;

static void check(const char *name, int cond, const char *detail)
{
    if (cond != 0) {
        g_pass++;
        printf("P6 %s: PASS %s\n", name, detail);
    } else {
        g_fail++;
        printf("P6 %s: FAIL %s\n", name, detail);
    }
}

/* ---- fault capture (one attempt per forked child) ---- */

static sigjmp_buf g_jb;
static volatile int g_fcode;
static volatile const void *g_faddr;
static const char *g_fbase; /* mapping base for offset computation */

static void on_segv(int sig, siginfo_t *si, void *uc)
{
    (void)sig;
    (void)uc;
    if (si != NULL) {
        g_fcode = si->si_code;
        g_faddr = si->si_addr;
    }
    siglongjmp(g_jb, 1);
}

static void install_segv(void)
{
    struct sigaction sa;

    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = on_segv;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGSEGV, &sa, NULL) != 0) {
        printf("P6 setup: FAIL sigaction errno=%d\n", errno);
        exit(1);
    }
}

/* Returns 1 on SIGSEGV (fills code_out and off_out), 0 when the access
 * completes without faulting. */
static int attempt_rw(volatile unsigned char *p, int is_write, int *code_out,
                      unsigned long *off_out)
{
    if (sigsetjmp(g_jb, 1) == 0) {
        if (is_write != 0) {
            *p = (unsigned char)0xAA;
        } else {
            volatile unsigned char c = *p;
            (void)c;
        }
        return 0;
    }
    *code_out = g_fcode;
    *off_out = (unsigned long)((const char *)g_faddr - g_fbase);
    return 1;
}

/* Call the code at addr. Returns 1 on SIGSEGV (fills code_out and
 * off_out), 0 when the call returns (fills ret_out). */
static int attempt_exec(void *addr, int *code_out, unsigned long *off_out,
                        int *ret_out)
{
    int (* volatile f)(void) = (int (*)(void))addr;

    if (sigsetjmp(g_jb, 1) == 0) {
        *ret_out = f();
        return 0;
    }
    *code_out = g_fcode;
    *off_out = (unsigned long)((const char *)g_faddr - g_fbase);
    return 1;
}

static void *xmap(unsigned long bytes)
{
    void *p = mmap(NULL, (size_t)bytes, PROT_READ | PROT_WRITE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if (p == MAP_FAILED) {
        printf("P6 setup: FAIL mmap errno=%d\n", errno);
        exit(1);
    }
    return p;
}

/* Fork a child that performs one access; the child prints the verdict
 * line. want_fault/want_code/want_off describe the expected outcome. */
static void child_probe(const char *name, void *addr, int is_write,
                        int want_fault, int want_code, unsigned long want_off)
{
    pid_t pid;
    int st;

    fflush(stdout);
    pid = fork();
    if (pid < 0) {
        check(name, 0, "fork failed");
        return;
    }
    if (pid == 0) {
        int code = 0;
        unsigned long off = 0UL;
        int faulted = attempt_rw((volatile unsigned char *)addr, is_write,
                                 &code, &off);

        if (faulted == want_fault &&
            (want_fault == 0 ||
             (code == want_code && off == want_off))) {
            printf("P6 %s: PASS code=%d off=%lu\n", name, code, off);
            _exit(0);
        }
        printf("P6 %s: FAIL fault=%d code=%d off=%lu\n", name, faulted,
               code, off);
        _exit(1);
    }
    if (waitpid(pid, &st, 0) != pid) {
        check(name, 0, "wait failed");
        return;
    }
    if (WIFEXITED(st) != 0 && WEXITSTATUS(st) == 0) {
        g_pass++;
    } else {
        g_fail++;
        printf("P6 %s: FAIL child-status=%d\n", name, st);
    }
}

static void child_exec_probe(const char *name, void *addr, int want_code,
                             unsigned long want_off)
{
    pid_t pid;
    int st;

    fflush(stdout);
    pid = fork();
    if (pid < 0) {
        check(name, 0, "fork failed");
        return;
    }
    if (pid == 0) {
        int code = 0;
        unsigned long off = 0UL;
        int ret = 0;
        int faulted = attempt_exec(addr, &code, &off, &ret);

        if (faulted == 1 && code == want_code && off == want_off) {
            printf("P6 %s: PASS code=%d off=%lu\n", name, code, off);
            _exit(0);
        }
        printf("P6 %s: FAIL fault=%d code=%d off=%lu ret=%d\n", name,
               faulted, code, off, ret);
        _exit(1);
    }
    if (waitpid(pid, &st, 0) != pid) {
        check(name, 0, "wait failed");
        return;
    }
    if (WIFEXITED(st) != 0 && WEXITSTATUS(st) == 0) {
        g_pass++;
    } else {
        g_fail++;
        printf("P6 %s: FAIL child-status=%d\n", name, st);
    }
}

/* ---- scenarios ---- */

/* Layout [RX][RW]: write to the RX page faults on page 0. */
static void t_rx_next_rw(void)
{
    char *base = (char *)xmap(2UL * PAGE);
    char detail[64];
    volatile unsigned char v;

    memset(base, 0x5A, 2UL * (size_t)PAGE);
    if (mprotect(base, (size_t)PAGE, PROT_READ | PROT_EXEC) != 0) {
        check("rx-next-rw-protect", 0, "mprotect failed");
        return;
    }
    check("rx-next-rw-protect", 1, "rx-rw");
    g_fbase = base;
    child_probe("rx-write", base + 0x10, 1, 1, SEGV_ACCERR, 0x10UL);
    v = *(volatile unsigned char *)(base + 0x10);
    snprintf(detail, sizeof(detail), "val=0x%02x",
             (unsigned int)(unsigned char)v);
    check("rx-read", v == (volatile unsigned char)0x5A, detail);
    *(volatile unsigned char *)(base + PAGE + 0x20) = (unsigned char)0xAA;
    v = *(volatile unsigned char *)(base + PAGE + 0x20);
    snprintf(detail, sizeof(detail), "val=0x%02x",
             (unsigned int)(unsigned char)v);
    check("rw-write", v == (volatile unsigned char)0xAA, detail);
}

/* Layout [RW][RX]: the fault lands exactly on the second page. */
static void t_rw_next_rx(void)
{
    char *base = (char *)xmap(2UL * PAGE);
    volatile unsigned char v;

    memset(base, 0x5A, 2UL * (size_t)PAGE);
    if (mprotect(base + PAGE, (size_t)PAGE, PROT_READ | PROT_EXEC) != 0) {
        check("rw-next-rx-protect", 0, "mprotect failed");
        return;
    }
    check("rw-next-rx-protect", 1, "rw-rx");
    g_fbase = base;
    child_probe("rx2-write", base + PAGE + 0x20, 1, 1, SEGV_ACCERR,
                PAGE + 0x20UL);
    *(volatile unsigned char *)(base + 0x10) = (unsigned char)0xAA;
    v = *(volatile unsigned char *)(base + 0x10);
    check("rw1-write", v == (volatile unsigned char)0xAA, "val=0xaa");
}

/* RELRO-style split over one mapping: [RX][RX][RW]. */
static void t_relro(void)
{
    char *base = (char *)xmap(3UL * PAGE);
    char detail[64];
    volatile unsigned char v;

    memset(base, 0x5A, 3UL * (size_t)PAGE);
    if (mprotect(base, (size_t)(2UL * PAGE), PROT_READ | PROT_EXEC) != 0) {
        check("relro-protect", 0, "mprotect failed");
        return;
    }
    check("relro-protect", 1, "rx-rx-rw");
    g_fbase = base;
    child_probe("relro-rx2-write", base + PAGE + 0x30, 1, 1, SEGV_ACCERR,
                PAGE + 0x30UL);
    *(volatile unsigned char *)(base + 2UL * PAGE + 0x40) =
        (unsigned char)0xAA;
    v = *(volatile unsigned char *)(base + 2UL * PAGE + 0x40);
    snprintf(detail, sizeof(detail), "val=0x%02x",
             (unsigned int)(unsigned char)v);
    check("relro-rw-write", v == (volatile unsigned char)0xAA, detail);
    v = *(volatile unsigned char *)(base + 0x50);
    snprintf(detail, sizeof(detail), "val=0x%02x",
             (unsigned int)(unsigned char)v);
    check("relro-rx1-read", v == (volatile unsigned char)0x5A, detail);
}

/* Layout [RW][NONE]: the guarded VMA exists but carries no permissions,
 * so both read and write fault with SEGV_ACCERR (never SEGV_MAPERR). */
static void t_prot_none(void)
{
    char *base = (char *)xmap(2UL * PAGE);
    volatile unsigned char v;

    memset(base, 0x5A, 2UL * (size_t)PAGE);
    if (mprotect(base + PAGE, (size_t)PAGE, PROT_NONE) != 0) {
        check("none-protect", 0, "mprotect failed");
        return;
    }
    check("none-protect", 1, "rw-none");
    g_fbase = base;
    child_probe("none-read", base + PAGE + 0x10, 0, 1, SEGV_ACCERR,
                PAGE + 0x10UL);
    child_probe("none-write", base + PAGE + 0x18, 1, 1, SEGV_ACCERR,
                PAGE + 0x18UL);
    *(volatile unsigned char *)(base + 0x10) = (unsigned char)0xAA;
    v = *(volatile unsigned char *)(base + 0x10);
    check("none-rw-write", v == (volatile unsigned char)0xAA, "val=0xaa");
}

/* Tiny MIPS32r2 leaf: addiu $v0,$zero,42; jr $ra; nop. */
#ifdef __MIPSEL__
static const unsigned char g_func[12] = {
    0x2A, 0x00, 0x02, 0x24, 0x08, 0x00, 0xE0, 0x03, 0x00, 0x00, 0x00, 0x00
};
#else
static const unsigned char g_func[12] = {
    0x24, 0x02, 0x00, 0x2A, 0x03, 0xE0, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00
};
#endif

/* RX page executes; RW page must not execute (SIGSEGV on the RW page). */
static void t_exec(void)
{
    char *base = (char *)xmap(2UL * PAGE);
    int (* volatile f)(void);
    char detail[64];
    int r = 0;

    memcpy(base, g_func, sizeof(g_func));
    memcpy(base + PAGE, g_func, sizeof(g_func));
    if (mprotect(base, (size_t)PAGE, PROT_READ | PROT_EXEC) != 0) {
        check("exec-protect", 0, "mprotect failed");
        return;
    }
    check("exec-protect", 1, "rx-rw");
    __builtin___clear_cache(base, base + sizeof(g_func));
    __builtin___clear_cache(base + PAGE, base + PAGE + sizeof(g_func));
    f = (int (*)(void))(void *)base;
    r = f();
    snprintf(detail, sizeof(detail), "ret=%d", r);
    check("exec-rx", r == 42, detail);
    g_fbase = base;
    child_exec_probe("exec-rw", base + PAGE, SEGV_ACCERR, PAGE);
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    install_segv();
    printf("P6-PERMS: start\n");
    t_rx_next_rw();
    t_rw_next_rx();
    t_relro();
    t_prot_none();
    t_exec();
    printf("P6-SUMMARY: pass=%d fail=%d\n", g_pass, g_fail);
    if (g_fail == 0) {
        printf("P6-PERMS-RESULT: PASS\n");
        return 0;
    }
    printf("P6-PERMS-RESULT: FAIL\n");
    return 1;
}
