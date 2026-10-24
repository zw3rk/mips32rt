/*
 * tests/test_p5_dyn.c — Phase 5 dynamic-linking guest test (lane L5b).
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Dynamically linked MIPS32r2 O32 guest, identical under qemu-mipsel
 * (and qemu-mips BE) and under mips32rt --interp / --dbt (LE+BE):
 *
 *  - t_shared_libc: shared-libc calls (printf/qsort/malloc/strcmp).
 *  - t_tls: __thread storage, main thread plus a pthread (isolation).
 *  - t_dlopen: dlopen/dlsym of the companion helper shared object
 *    built from this same file with -DP5_HELPER -shared -fPIC.
 *  - t_argv_env_auxv: argv/envp/auxv self-check, including
 *    getauxval(AT_ENTRY) == load-base + e_entry (the _start entry).
 *
 * Build (inside the debian lane container, see tests/run_p5_busybox.sh):
 *   mipsel-linux-gnu-gcc -march=mips32r2 -O1 -std=c11 -Wall -Wextra \
 *       -fPIC -shared -DP5_HELPER -o /tmp/p5helper-le.so tests/test_p5_dyn.c
 *   mipsel-linux-gnu-gcc -march=mips32r2 -O1 -std=c11 -Wall -Wextra \
 *       -o /tmp/p5dyn-le tests/test_p5_dyn.c -ldl -pthread \
 *       -Wl,-rpath,/usr/mipsel-linux-gnu/lib
 *
 * Run: P5_MARKER=p5-lane-l5b <qemu|mips32rt> /tmp/p5dyn-le ./p5helper-le.so
 * (helper path defaults per-endian when argv[1] is absent).
 */

#ifdef P5_HELPER

/* ================= companion helper shared object ================= */

static __thread int helper_tls_accum = 0;

int p5_helper_add(int a, int b)
{
    return a + b;
}

const char *p5_helper_name(void)
{
    return "p5-helper-v1";
}

int p5_helper_tls_bump(void)
{
    helper_tls_accum += 7;
    return helper_tls_accum;
}

#else /* ================= main test binary ================= */

#define _GNU_SOURCE /* getauxval/dlsym/RTLD_* under strict -std=c11 */

#include <dlfcn.h>
#include <elf.h>
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/auxv.h>
#include <unistd.h>

static int g_pass = 0;
static int g_fail = 0;

static void check(const char *name, int ok, const char *detail)
{
    if (ok) {
        g_pass++;
        printf("P5 %s: ok %s\n", name, detail);
    } else {
        g_fail++;
        printf("P5 %s: FAIL %s\n", name, detail);
    }
}

/* ================= shared-libc calls ================= */

static int cmp_int(const void *a, const void *b)
{
    int x = *(const int *)a;
    int y = *(const int *)b;

    if (x < y) {
        return -1;
    }
    if (x > y) {
        return 1;
    }
    return 0;
}

static void t_shared_libc(void)
{
    int nums[] = { 5, -1, 9, 0, -1, 42 };
    static const int want[] = { -1, -1, 0, 5, 9, 42 };
    unsigned i;
    int ok = 1;
    int *heap;
    char msg[64];
    int n;

    qsort(nums, sizeof(nums) / sizeof(nums[0]), sizeof(nums[0]), cmp_int);
    for (i = 0u; i < sizeof(nums) / sizeof(nums[0]); i++) {
        if (nums[i] != want[i]) {
            ok = 0;
        }
    }
    heap = (int *)malloc(4u * sizeof(int));
    if (heap == NULL) {
        ok = 0;
    } else {
        heap[0] = 1;
        heap[1] = 2;
        heap[2] = 3;
        heap[3] = 4;
        if (heap[0] + heap[1] + heap[2] + heap[3] != 10) {
            ok = 0;
        }
        if (strcmp("libc", "libc") != 0 || strcmp("libc", "libd") >= 0) {
            ok = 0;
        }
        free(heap);
    }
    n = snprintf(msg, sizeof(msg), "qsort+malloc+strcmp n=%d", 3);
    if (n <= 0 || msg[0] == '\0') {
        ok = 0;
    }
    check("shared-libc", ok, msg);
}

/* ================= __thread TLS ================= */

static __thread long tls_accum = 0L;
static volatile int child_tls_first = -1;
static volatile int child_tls_second = -1;

static void *tls_child(void *arg)
{
    (void)arg;
    tls_accum += 100L;
    child_tls_first = (int)tls_accum;
    tls_accum += 100L;
    child_tls_second = (int)tls_accum;
    return NULL;
}

static void t_tls(void)
{
    pthread_t th;
    int rc;
    long before;

    tls_accum = 0L;
    tls_accum += 1L;
    before = tls_accum;
    rc = pthread_create(&th, NULL, tls_child, NULL);
    if (rc != 0) {
        check("tls", 0, "pthread_create failed");
        return;
    }
    pthread_join(th, NULL);
    check("tls", before == 1L && tls_accum == 1L &&
          child_tls_first == 100 && child_tls_second == 200,
          "main=1 child=100,200 isolated");
}

/* ================= dlopen/dlsym ================= */

static void t_dlopen(const char *helper_path)
{
    void *h;
    int (*add_fn)(int, int);
    const char *(*name_fn)(void);
    int (*bump_fn)(void);
    int v0;
    int v1;
    int ok = 1;
    char detail[96];
    int n;

    h = dlopen(helper_path, RTLD_NOW);
    if (h == NULL) {
        n = snprintf(detail, sizeof(detail), "dlopen(%s): %s", helper_path,
                     dlerror());
        (void)n;
        check("dlopen", 0, detail);
        return;
    }
    dlerror();
    add_fn = (int (*)(int, int))dlsym(h, "p5_helper_add");
    name_fn = (const char *(*)(void))dlsym(h, "p5_helper_name");
    bump_fn = (int (*)(void))dlsym(h, "p5_helper_tls_bump");
    if (add_fn == NULL || name_fn == NULL || bump_fn == NULL) {
        check("dlopen", 0, "dlsym missing symbol");
        dlclose(h);
        return;
    }
    if (add_fn(40, 2) != 42) {
        ok = 0;
    }
    if (strcmp(name_fn(), "p5-helper-v1") != 0) {
        ok = 0;
    }
    v0 = bump_fn();
    v1 = bump_fn();
    if (v0 != 7 || v1 != 14) {
        ok = 0;
    }
    n = snprintf(detail, sizeof(detail), "%s add=42 tls=%d,%d",
                 helper_path, v0, v1);
    (void)n;
    check("dlopen", ok, detail);
    dlclose(h);
}

/* ================= argv/envp/auxv ================= */

/*
 * Derive the executable's entry address the way the loader sees it:
 * dladdr(main) gives the load base; the ELF header at the base gives
 * e_type/e_entry. For ET_DYN the kernel reports AT_ENTRY = base + e_entry,
 * for ET_EXEC it reports AT_ENTRY = e_entry. This checks the same
 * "_start-adjacent main entry" identity as &_start without referencing
 * the _start symbol (which the cross linker does not always provide).
 */
int main(int argc, char **argv);

static int auxv_entry_ok(unsigned long at_entry, unsigned long *expect_out)
{
    Dl_info info;
    Elf32_Ehdr eh;
    unsigned long expect = 0UL;

    memset(&info, 0, sizeof info);
    if (dladdr((const void *)(uintptr_t)main, &info) == 0 ||
        info.dli_fbase == NULL ||
        ((uintptr_t)info.dli_fbase & 0xFFFu) != 0u) {
        return 0;
    }
    memcpy(&eh, info.dli_fbase, sizeof eh);
    if (eh.e_ident[EI_MAG0] != ELFMAG0 || eh.e_ident[EI_MAG1] != ELFMAG1 ||
        eh.e_ident[EI_MAG2] != ELFMAG2 || eh.e_ident[EI_MAG3] != ELFMAG3 ||
        eh.e_ident[EI_CLASS] != ELFCLASS32) {
        return 0;
    }
    if (eh.e_type == ET_DYN) {
        expect = (unsigned long)(uintptr_t)info.dli_fbase +
            (unsigned long)eh.e_entry;
    } else if (eh.e_type == ET_EXEC) {
        expect = (unsigned long)eh.e_entry;
    } else {
        return 0;
    }
    if (expect_out != NULL) {
        *expect_out = expect;
    }
    return at_entry == expect;
}

static void t_argv_env_auxv(int argc, char **argv)
{
    unsigned long at_entry;
    unsigned long at_phdr;
    unsigned long at_random;
    unsigned long at_pagesz;
    unsigned long at_uid;
    const char *marker;
    int ok = 1;
    char detail[96];
    int n;

    if (argc < 1 || argv[0] == NULL || argv[0][0] == '\0') {
        ok = 0;
    }
    marker = getenv("P5_MARKER");
    if (marker == NULL || strcmp(marker, "p5-lane-l5b") != 0) {
        ok = 0;
    }
    at_entry = getauxval(AT_ENTRY);
    at_phdr = getauxval(AT_PHDR);
    at_random = getauxval(AT_RANDOM);
    at_pagesz = getauxval(AT_PAGESZ);
    at_uid = getauxval(AT_UID);
    if (at_entry == 0UL || !auxv_entry_ok(at_entry, NULL)) {
        ok = 0;
    }
    if (at_phdr == 0UL || at_random == 0UL) {
        ok = 0;
    }
    if (at_pagesz != 4096UL) {
        ok = 0;
    }
    if (at_uid != (unsigned long)getuid()) {
        ok = 0;
    }
    n = snprintf(detail, sizeof(detail),
                 "argc=%d entry=0x%lx marker=%s", argc, at_entry,
                 marker != NULL ? marker : "(null)");
    (void)n;
    check("argv-env-auxv", ok, detail);
}

int main(int argc, char **argv)
{
    const char *helper;
#ifdef __MIPSEL__
    helper = "p5helper-le.so";
#else
    helper = "p5helper-be.so";
#endif

    if (argc >= 2 && argv[1] != NULL && argv[1][0] != '\0') {
        helper = argv[1];
    }
    t_shared_libc();
    t_tls();
    t_dlopen(helper);
    t_argv_env_auxv(argc, argv);
    printf("P5-SUMMARY: pass=%d fail=%d\n", g_pass, g_fail);
    if (g_fail == 0 && g_pass == 4) {
        printf("P5-RESULT: PASS\n");
        return 0;
    }
    printf("P5-RESULT: FAIL\n");
    return 1;
}

#endif
