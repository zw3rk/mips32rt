/*
 * tests/test_p1_isa_part2.c — Phase 1 ISA coverage suite part 2 (LL/SC, LWL/LWR, RDHWR, syscalls)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 */

#define _GNU_SOURCE
#include "test_p1_isa.h"

#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define check    p1_check
#define raw_sys3 p1_raw_sys3

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

__attribute__((noinline)) void t_llsc(void)
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

__attribute__((noinline)) void t_unaligned(void)
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

__attribute__((noinline)) void t_rdhwr(void)
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

/* ================= unaligned LW fault in a forked child ================= */

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

__attribute__((noinline)) void t_unaligned_child(void)
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
        fixade_off(); /* fault, don't emulate (Wave U3 default-on) */
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

__attribute__((noinline)) void t_raw_write(void)
{
    char db[96];
    static const char msg[] = "P1-RAW-WRITE: ok\n";
    int a3 = -1;
    long r = raw_sys3(NR_WRITE, 1, (long)msg, (long)(sizeof msg - 1),
                      &a3);
    snprintf(db, sizeof db, "raw-write ret=%ld a3=%d", r, a3);
    check("raw-write", r == (long)(sizeof msg - 1) && a3 == 0, db);
}
