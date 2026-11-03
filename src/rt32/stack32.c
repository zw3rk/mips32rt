/*
 * src/rt32/stack32.c — MIPS O32 initial stack, argv, envp, and auxv builder
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Vendored from ../i686rt/src/rt32/rt32_stack32.c: retyped on mips32_ctx_t
 * with the O32 stack top (SPEC 1.1, 0x7fff0000).  Phase 5 (lane L5a) builds
 * the complete O32 auxv: PHDR/PHENT/PHNUM, PAGESZ, BASE (dynamic only),
 * FLAGS, ENTRY, UID/EUID/GID/EGID, HWCAP, CLKTCK, RANDOM (16 stack bytes),
 * SECURE, HWCAP2, EXECFN, AT_NULL.  The .MIPS.abiflags-derived entries
 * (FR mode, FP ABI) stay Phase 6+ work; there is no vdso on this target.
 */

#define _GNU_SOURCE
#include "rt32.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#ifdef __linux__
#include <sys/random.h>
#endif
#include <unistd.h>

#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS MAP_ANON
#endif

#define RT32_STACK_TOP  0x7FFF0000U
#define RT32_STACK_SIZE (8U * 1024U * 1024U)

/* AT_* keys (Linux generic + MIPS O32; values match asm-generic auxvec). */
#define RT32_AT_NULL    0U
#define RT32_AT_PHDR    3U
#define RT32_AT_PHENT   4U
#define RT32_AT_PHNUM   5U
#define RT32_AT_PAGESZ  6U
#define RT32_AT_BASE    7U
#define RT32_AT_FLAGS   8U
#define RT32_AT_ENTRY   9U
#define RT32_AT_UID     11U
#define RT32_AT_EUID    12U
#define RT32_AT_GID     13U
#define RT32_AT_EGID    14U
#define RT32_AT_HWCAP   16U
#define RT32_AT_CLKTCK  17U
#define RT32_AT_SECURE  23U
#define RT32_AT_RANDOM  25U
#define RT32_AT_HWCAP2  26U
#define RT32_AT_EXECFN  31U

/* Guest byte order for stack words: the host is LE, so BE (mips)
 * guests need every 32-bit stack word byte-swapped (E05). */
static uint32_t guest_swap32(uint32_t v)
{
    return ((v & 0x000000FFU) << 24) | ((v & 0x0000FF00U) << 8) |
           ((v & 0x00FF0000U) >> 8) | ((v & 0xFF000000U) >> 24);
}

static uint32_t guest_word(const rt32_elf_info_t *info, uint32_t v)
{
    return (info->is_be != 0U) ? guest_swap32(v) : v;
}

static uint32_t push_bytes(mips32_ctx_t *ctx, uint32_t *sp, const void *data, size_t len)
{
    if (*sp < ctx->stack_base || len > (size_t)(*sp - ctx->stack_base)) {
        return 0U;
    }
    *sp -= (uint32_t)len;
    memcpy(mips32_guest_ptr(ctx, *sp), data, len);
    return *sp;
}

static uint32_t push_cstring(mips32_ctx_t *ctx, uint32_t *sp, const char *s)
{
    size_t len = strlen(s) + 1U;
    return push_bytes(ctx, sp, s, len);
}

static int push_string_table(mips32_ctx_t *ctx, uint32_t *sp, char **strs,
                             int max_count, uint32_t *out_ptrs, int *out_count)
{
    int count = 0;
    if (strs) {
        while (count < max_count && count < 511 && strs[count] != NULL) {
            count++;
        }
        for (int i = count - 1; i >= 0; i--) {
            out_ptrs[i] = push_cstring(ctx, sp, strs[i]);
            if (out_ptrs[i] == 0U) {
                return -1;
            }
        }
    }
    *out_count = count;
    return 0;
}

int rt32_stack_setup(mips32_ctx_t *ctx, const rt32_elf_info_t *elf_info,
                    int guest_argc, char **guest_argv, char **host_envp,
                    uint32_t *out_sp)
{
    if (!ctx || !elf_info || !out_sp || guest_argc < 1 || !guest_argv || !guest_argv[0]) {
        return -1;
    }

    uint32_t stack_base = RT32_STACK_TOP - RT32_STACK_SIZE;
    void *host_stack = mips32_guest_ptr(ctx, stack_base);
    void *res = mmap(host_stack, RT32_STACK_SIZE, PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (res == MAP_FAILED) {
        fprintf(stderr, "mips32rt: failed to map guest stack: %s\n", strerror(errno));
        return -1;
    }
    ctx->stack_top  = RT32_STACK_TOP;
    ctx->stack_base = stack_base;
    rt32_vm_record_region(ctx, stack_base, RT32_STACK_TOP,
                         (uint32_t)(PROT_READ | PROT_WRITE), 0x12U, "[stack]");

    uint32_t sp = RT32_STACK_TOP - 64U;

    uint8_t rand_bytes[16];
    if (getenv("MIPS32RT_DUMPSTATE") != NULL) {
        for (size_t i = 0; i < sizeof(rand_bytes); i++) {
            rand_bytes[i] = (uint8_t)(0xA5U ^ (uint8_t)(i * 17U));
        }
    } else {
#ifdef __APPLE__
        arc4random_buf(rand_bytes, sizeof(rand_bytes));
#elif defined(__linux__)
        if (getrandom(rand_bytes, sizeof(rand_bytes), 0) != (ssize_t)sizeof(rand_bytes)) {
            for (size_t i = 0; i < sizeof(rand_bytes); i++) {
                rand_bytes[i] = (uint8_t)(0xA5U ^ (uint8_t)(i * 17U));
            }
        }
#else
        for (size_t i = 0; i < sizeof(rand_bytes); i++) {
            rand_bytes[i] = (uint8_t)(0xA5U ^ (uint8_t)(i * 17U));
        }
#endif
    }
    uint32_t at_random_va = push_bytes(ctx, &sp, rand_bytes, sizeof(rand_bytes));
    const char *execfn_str = (ctx->exec_path && ctx->exec_path[0]) ? ctx->exec_path : guest_argv[0];
    uint32_t at_execfn_va = push_cstring(ctx, &sp, execfn_str);
    if (at_random_va == 0U || at_execfn_va == 0U) {
        return -1;
    }

    uint32_t env_ptrs[512];
    uint32_t arg_ptrs[512];
    int envc = 0;
    int argc = 0;
    if (push_string_table(ctx, &sp, host_envp, 511, env_ptrs, &envc) != 0 ||
        push_string_table(ctx, &sp, guest_argv, guest_argc, arg_ptrs, &argc) != 0) {
        return -1;
    }

    sp &= ~0xFU;

    /* Phase 5 complete O32 auxv (kernel order: PHDR..ENTRY, ids, HWCAP,
     * CLKTCK, RANDOM, SECURE, HWCAP2, EXECFN, AT_NULL).  AT_BASE is present
     * only for dynamic binaries (interp_base != 0); AT_ENTRY is always the
     * exe entry even when control starts at the interpreter.  Values are
     * host-order here; the frame writer swaps them for BE (mips) guests
     * while ctx->auxv_data keeps the host-order copy for /proc/self/auxv
     * (src/os/proc.c swaps on read for BE).  18 pairs fit in auxv[40]. */
    uint32_t auxv[40];
    size_t aux_idx = 0;
#define RT32_PUT_AT(k, v) do { auxv[aux_idx++] = (uint32_t)(k); auxv[aux_idx++] = (uint32_t)(v); } while (0)
    RT32_PUT_AT(RT32_AT_PHDR, elf_info->phdr_vaddr);
    RT32_PUT_AT(RT32_AT_PHENT, elf_info->phent);
    RT32_PUT_AT(RT32_AT_PHNUM, elf_info->phnum);
    RT32_PUT_AT(RT32_AT_PAGESZ, 4096U);
    if (elf_info->interp_base != 0U) {
        RT32_PUT_AT(RT32_AT_BASE, elf_info->interp_base);
    }
    RT32_PUT_AT(RT32_AT_FLAGS, 0U);
    RT32_PUT_AT(RT32_AT_ENTRY, elf_info->entry);
    RT32_PUT_AT(RT32_AT_UID, (uint32_t)getuid());
    RT32_PUT_AT(RT32_AT_EUID, (uint32_t)geteuid());
    RT32_PUT_AT(RT32_AT_GID, (uint32_t)getgid());
    RT32_PUT_AT(RT32_AT_EGID, (uint32_t)getegid());
    RT32_PUT_AT(RT32_AT_HWCAP, 0U);
    RT32_PUT_AT(RT32_AT_CLKTCK, 100U);
    RT32_PUT_AT(RT32_AT_RANDOM, at_random_va);
    RT32_PUT_AT(RT32_AT_SECURE, 0U);
    RT32_PUT_AT(RT32_AT_HWCAP2, 0U);
    RT32_PUT_AT(RT32_AT_EXECFN, at_execfn_va);
    RT32_PUT_AT(RT32_AT_NULL, 0U);
#undef RT32_PUT_AT
    if (aux_idx > sizeof(auxv) / sizeof(auxv[0])) {
        return -1;
    }

    /* Frame layout: argc, argv[0..argc-1], NULL, envp[0..envc-1], NULL, auxv[] */
    size_t total_words   = 1U + ((size_t)argc + 1U) + ((size_t)envc + 1U) + aux_idx;
    uint32_t frame_bytes = (uint32_t)(total_words * sizeof(uint32_t));
    if (sp < ctx->stack_base || (sp - ctx->stack_base) < frame_bytes + 16U) {
        return -1;
    }
    uint32_t final_sp = (sp - frame_bytes) & ~0xFU;

    uint32_t *w = (uint32_t *)mips32_guest_ptr(ctx, final_sp);
    size_t pos = 0;
    size_t i;
    w[pos++] = guest_word(elf_info, (uint32_t)argc);
    for (i = 0u; i < (size_t)argc; i++) {
        w[pos++] = guest_word(elf_info, arg_ptrs[i]);
    }
    w[pos++] = 0U;
    for (i = 0u; i < (size_t)envc; i++) {
        w[pos++] = guest_word(elf_info, env_ptrs[i]);
    }
    w[pos++] = 0U;
    for (i = 0u; i < aux_idx; i++) {
        w[pos++] = guest_word(elf_info, auxv[i]);
    }

    ctx->guest_argc = argc;
    ctx->guest_argv = guest_argv;
    ctx->host_envp  = host_envp;

    size_t copy_words = aux_idx;
    if (copy_words > (sizeof(ctx->auxv_data) / sizeof(ctx->auxv_data[0]))) {
        copy_words = sizeof(ctx->auxv_data) / sizeof(ctx->auxv_data[0]);
    }
    memcpy(ctx->auxv_data, auxv, copy_words * sizeof(uint32_t));
    ctx->auxv_bytes = copy_words * sizeof(uint32_t);

    *out_sp = final_sp;
    return 0;
}
