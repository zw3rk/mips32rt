/*
 * src/rt32/vm_init.c — Guest 4 GiB window [G, G+4GiB) reservation and init
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Split from src/rt32/vm.c to honor the 900-line file limit.  Owns the
 * host-side window reservation (try_reserve_window) and rt32_vm_init;
 * the VMA table itself stays in vm.c.  All shared state is declared in
 * rt32/vm_priv.h and serialized on the D19 CLONE_VM lock (g_vm_lock).
 */

#define _GNU_SOURCE
#include "vm_priv.h"

#include "vm/vm32.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS MAP_ANON
#endif
#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif

static int try_reserve_window(uint64_t base)
{
    if ((base & (MIPS32_PAGE_SIZE - 1ULL)) != 0ULL || base > UINT64_MAX - RT32_WINDOW_SIZE) {
        return -1;
    }
#ifdef __APPLE__
    if (base == 0ULL || (base & 0x3FFFULL) != 0ULL) {
        return -1;
    }
    void *res = mmap((void *)(uintptr_t)base, (size_t)RT32_WINDOW_SIZE, PROT_NONE,
                     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (res == MAP_FAILED) {
        return -1;
    }
    if ((uint64_t)(uintptr_t)res != base) {
        munmap(res, (size_t)RT32_WINDOW_SIZE);
        return -1;
    }
    return 0;
#else
    uint64_t map_start = (base == 0ULL) ? (uint64_t)MIPS32_LOW_GUARD_SIZE : base;
    uint64_t map_len   = (base == 0ULL) ? (RT32_WINDOW_SIZE - (uint64_t)MIPS32_LOW_GUARD_SIZE)
                                        : RT32_WINDOW_SIZE;

    void *res = mmap((void *)(uintptr_t)map_start, (size_t)map_len, PROT_NONE,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
    if (res == MAP_FAILED && (errno == EINVAL || errno == EOPNOTSUPP)) {
        res = mmap((void *)(uintptr_t)map_start, (size_t)map_len, PROT_NONE,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    }
    if (res == MAP_FAILED) {
        return -1;
    }
    if ((uint64_t)(uintptr_t)res != map_start) {
        munmap(res, (size_t)map_len);
        return -1;
    }
    return 0;
#endif
}

int rt32_vm_init(mips32_ctx_t *ctx, uint64_t requested_window)
{
    if (!ctx) {
        return -1;
    }

    uint64_t base = requested_window;
    bool     has_explicit = (requested_window != UINT64_MAX);

    if (!has_explicit) {
        const char *env_win = getenv("MIPS32RT_WINDOW");
        if (env_win && env_win[0] != '\0') {
            char *endp = NULL;
            errno = 0;
            unsigned long long val = strtoull(env_win, &endp, 0);
            if (strchr(env_win, '-') != NULL || errno == ERANGE || !endp ||
                endp == env_win || *endp != '\0' || (uint64_t)val == UINT64_MAX) {
                fprintf(stderr, "mips32rt: invalid MIPS32RT_WINDOW '%s'\n", env_win);
                return -1;
            }
            base = (uint64_t)val;
            has_explicit = true;
        }
    }

    if (has_explicit) {
        if (try_reserve_window(base) != 0) {
            fprintf(stderr, "mips32rt: failed to reserve guest window at 0x%llx\n",
                    (unsigned long long)base);
            return -1;
        }
        ctx->guest_base = base;
    } else if (ctx->has_host_info && ctx->host_info.window_hint != 0ULL &&
               try_reserve_window(ctx->host_info.window_hint) == 0) {
        ctx->guest_base = ctx->host_info.window_hint;
    } else {
        /* Try G = 0 first; if occupied, scan 4 GiB-aligned windows [4G, 64G). */
        if (try_reserve_window(0ULL) == 0) {
            ctx->guest_base = 0ULL;
        } else {
            bool found = false;
            for (uint64_t cand = 0x100000000ULL; cand < 0x1000000000ULL; cand += 0x100000000ULL) {
                if (try_reserve_window(cand) == 0) {
                    ctx->guest_base = cand;
                    found = true;
                    break;
                }
            }
            if (!found) {
#ifdef __APPLE__
                void *any = mmap(NULL, (size_t)RT32_WINDOW_SIZE, PROT_NONE,
                                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
                if (any != MAP_FAILED) {
                    ctx->guest_base = (uint64_t)(uintptr_t)any;
                    found = true;
                }
#endif
                if (!found) {
                    fprintf(stderr, "mips32rt: unable to find free 4 GiB guest window\n");
                    return -1;
                }
            }
        }
    }

    /* M32-R9-1: connect the two-regime VM here so every production
     * path gets a regime (run_guest via this call; execve inherits it
     * across rt32_vm_reset_for_exec, which preserves it): FIXADE
     * default-on plus the A1/A2 select for this host's page size. */
    mips32_fixade_init(ctx);
    if (mips32_vm32_init(ctx) != 0) {
        return -1;
    }

    vm_lock_acquire();
    g_vm_root_ctx     = ctx;
    g_vm_brk_base     = 0U;
    g_vm_brk_curr     = 0U;
    g_vm_mmap_cursor  = RT32_MMAP_BASE_32;
    g_vm_region_count = 0U;
    for (size_t i = 0U; i < MIPS32_MAX_REGIONS; i++) {
        g_vm_backing[i] = (vm_backing_t){ -1, 0U, 0U, 0U, 0U };
    }
    atomic_store_explicit(&g_vm_gen, 1U, memory_order_release);
    ctx->mmap_cursor  = RT32_MMAP_BASE_32;
    ctx->region_count = 0U;
    ctx->vm_gen       = 1U;
    vm_lock_release();
    return 0;
}
