/*
 * src/rt32/vm.c — Guest 4 GiB window [G, G+4GiB) reservation and VMA manager
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Vendored from ../i686rt/src/rt32/rt32_vm.c: retyped on mips32_ctx_t,
 * guest VA ceiling MIPS32_TASK_SIZE_TOP (0x7fff8000, SPEC 1.1).  The
 * page-table lock below is the D19 CLONE_VM behavior: every VMA mutation
 * serializes on g_vm_lock and mirrors into the calling ctx.
 */

#define _GNU_SOURCE
#include "vm_priv.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS MAP_ANON
#endif
#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif

_Atomic uint32_t g_vm_lock = 0U;
static _Atomic uint64_t    g_vm_gen = 0U;
mips32_ctx_t              *g_vm_root_ctx = NULL;
static uint32_t            g_vm_brk_base = 0U;
static uint32_t            g_vm_brk_curr = 0U;
uint32_t                   g_vm_mmap_cursor = RT32_MMAP_BASE_32;
mips32_region_t            g_vm_regions[MIPS32_MAX_REGIONS];
vm_backing_t               g_vm_backing[MIPS32_MAX_REGIONS];
size_t                     g_vm_region_count = 0U;

void vm_lock_acquire(void)
{
    mips32_spin_lock(&g_vm_lock);
}

void vm_lock_release(void)
{
    mips32_spin_unlock(&g_vm_lock);
}

uint64_t vm_page_align_up(uint64_t v)
{
    return (v + 0xFFFULL) & ~0xFFFULL;
}

int vm_reserve_prot_none(mips32_ctx_t *ctx, uint32_t start, uint32_t len)
{
#ifdef __APPLE__
    uint32_t h_start = (start + 0x3FFFU) & ~0x3FFFU;
    uint32_t h_end   = (start + len) & ~0x3FFFU;
    if (h_end > h_start) {
        if (mprotect(mips32_guest_ptr(ctx, h_start), (size_t)(h_end - h_start), PROT_NONE) != 0) {
            return -errno;
        }
    }
    return 0;
#else
    void *res = mmap(mips32_guest_ptr(ctx, start), (size_t)len, PROT_NONE,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    if (res == MAP_FAILED) {
        return -errno;
    }
    return 0;
#endif
}

/* Translation-cache invalidation on guest mm ops (SMC): the Phase 2 DBT
 * provides mips32_dbt_invalidate_range; the weak reference keeps Phase 0/1
 * (interp only, no code cache) linked and running without it. */
__attribute__((weak)) void mips32_dbt_invalidate_range(mips32_ctx_t *ctx,
                                                      uint32_t start,
                                                      uint32_t end);
void vm_invalidate_jit(mips32_ctx_t *ctx, uint32_t start, uint32_t end)
{
    if (mips32_dbt_invalidate_range != NULL) {
        mips32_dbt_invalidate_range(ctx, start, end);
    }
}

void vm_sync_from_ctx(mips32_ctx_t *ctx)
{
    if (ctx->brk_base != 0U && g_vm_brk_base != ctx->brk_base) {
        g_vm_brk_base = ctx->brk_base;
        g_vm_brk_curr = ctx->brk_curr;
    }
}

void vm_sync_brk_to_ctx(mips32_ctx_t *ctx)
{
    (void)atomic_fetch_add_explicit(&g_vm_gen, 1U, memory_order_release);
    if (g_vm_brk_base != 0U) {
        ctx->brk_base = g_vm_brk_base;
        ctx->brk_curr = g_vm_brk_curr;
    }
    ctx->vm_gen = atomic_load_explicit(&g_vm_gen, memory_order_relaxed);
}

void vm_copy_state_to_ctx(mips32_ctx_t *dst)
{
    if (g_vm_brk_base != 0U) {
        dst->brk_base = g_vm_brk_base;
        dst->brk_curr = g_vm_brk_curr;
    }
    size_t count = (g_vm_region_count <= MIPS32_MAX_REGIONS) ? g_vm_region_count : MIPS32_MAX_REGIONS;
    dst->mmap_cursor  = g_vm_mmap_cursor;
    dst->region_count = count;
    if (count > 0U) {
        memcpy(dst->regions, g_vm_regions, count * sizeof(mips32_region_t));
    }
    dst->vm_gen = atomic_load_explicit(&g_vm_gen, memory_order_relaxed);
}

void vm_sync_to_ctx(mips32_ctx_t *ctx)
{
    (void)atomic_fetch_add_explicit(&g_vm_gen, 1U, memory_order_release);
    vm_copy_state_to_ctx(ctx);
}

static void vm_maybe_close_fd_locked(int fd)
{
    if (fd < 0) {
        return;
    }
    for (size_t i = 0U; i < g_vm_region_count; i++) {
        if (g_vm_backing[i].fd == fd) {
            return;
        }
    }
    (void)close(fd);
}

void vm_remove_region_at(size_t idx)
{
    if (idx >= g_vm_region_count) {
        return;
    }
    vm_backing_t old_b = g_vm_backing[idx];
    if (idx + 1U < g_vm_region_count) {
        memmove(&g_vm_regions[idx], &g_vm_regions[idx + 1U],
                (g_vm_region_count - idx - 1U) * sizeof(mips32_region_t));
        memmove(&g_vm_backing[idx], &g_vm_backing[idx + 1U],
                (g_vm_region_count - idx - 1U) * sizeof(vm_backing_t));
    }
    g_vm_region_count--;
    vm_maybe_close_fd_locked(old_b.fd);
}

int vm_insert_region_backed(uint32_t start, uint32_t end, uint32_t prot,
                            uint32_t flags, const char *name, vm_backing_t back)
{
    if (start >= end || g_vm_region_count >= MIPS32_MAX_REGIONS) {
        return -1;
    }
    size_t pos = 0U;
    while (pos < g_vm_region_count && g_vm_regions[pos].start < start) {
        pos++;
    }
    if (pos < g_vm_region_count) {
        memmove(&g_vm_regions[pos + 1U], &g_vm_regions[pos],
                (g_vm_region_count - pos) * sizeof(mips32_region_t));
        memmove(&g_vm_backing[pos + 1U], &g_vm_backing[pos],
                (g_vm_region_count - pos) * sizeof(vm_backing_t));
    }
    g_vm_region_count++;
    mips32_region_t *r = &g_vm_regions[pos];
    r->start = start;
    r->end   = end;
    r->prot  = prot;
    r->flags = flags;
    if (name) {
        snprintf(r->name, sizeof(r->name), "%s", name);
    } else {
        r->name[0] = '\0';
    }
    g_vm_backing[pos] = back;
    return 0;
}

int vm_insert_region_raw(uint32_t start, uint32_t end,
                         uint32_t prot, uint32_t flags, const char *name)
{
    vm_backing_t none = { -1, 0U, 0U, 0U, 0U };
    return vm_insert_region_backed(start, end, prot, flags, name, none);
}

void vm_coalesce_regions_locked(void)
{
    if (g_vm_region_count < 2U) {
        return;
    }
    size_t dst = 0U;
    for (size_t src = 1U; src < g_vm_region_count; src++) {
        mips32_region_t *prev = &g_vm_regions[dst];
        const mips32_region_t *curr = &g_vm_regions[src];
        const vm_backing_t *pb = &g_vm_backing[dst];
        const vm_backing_t *cb = &g_vm_backing[src];
        bool back_match = (pb->fd == cb->fd && pb->dev == cb->dev &&
                           pb->ino == cb->ino && pb->darw_sync == cb->darw_sync &&
                           (pb->fd < 0 ||
                            pb->file_off + (uint64_t)(prev->end - prev->start) == cb->file_off));
        if (prev->end == curr->start && prev->prot == curr->prot &&
            prev->flags == curr->flags && strcmp(prev->name, curr->name) == 0 &&
            back_match) {
            prev->end = curr->end;
        } else {
            dst++;
            if (dst != src) {
                g_vm_regions[dst] = *curr;
                g_vm_backing[dst] = *cb;
            }
        }
    }
    g_vm_region_count = dst + 1U;
}

int vm_can_unmap_regions_locked(uint32_t unmap_start, uint32_t unmap_end,
                                size_t extra_insert)
{
    vm_coalesce_regions_locked();
    size_t cur  = g_vm_region_count;
    size_t peak = cur;
    for (size_t i = 0U; i < g_vm_region_count; i++) {
        const mips32_region_t *r = &g_vm_regions[i];
        if (r->end <= unmap_start || r->start >= unmap_end) {
            continue;
        }
        if (r->start >= unmap_start && r->end <= unmap_end) {
            if (cur > 0U) {
                cur--;
            }
        } else if (r->start < unmap_start && r->end > unmap_end) {
            cur++;
            if (cur > peak) {
                peak = cur;
            }
        }
    }
    if (cur + extra_insert > peak) {
        peak = cur + extra_insert;
    }
    return (peak <= MIPS32_MAX_REGIONS) ? 0 : -ENOMEM;
}

void vm_unmap_regions_locked(uint32_t unmap_start, uint32_t unmap_end)
{
    size_t i = 0U;
    while (i < g_vm_region_count) {
        mips32_region_t *r = &g_vm_regions[i];
        if (r->end <= unmap_start || r->start >= unmap_end) {
            i++;
            continue;
        }
        if (r->start >= unmap_start && r->end <= unmap_end) {
            vm_remove_region_at(i);
            continue;
        }
        if (r->start < unmap_start && r->end > unmap_end) {
            if (g_vm_region_count + 1U >= MIPS32_MAX_REGIONS) {
                size_t before = g_vm_region_count;
                vm_coalesce_regions_locked();
                if (g_vm_region_count != before) {
                    i = 0U;
                    continue;
                }
            }
            mips32_region_t orig   = *r;
            vm_backing_t    orig_b = g_vm_backing[i];
            vm_backing_t tail_b = {
                orig_b.fd,
                orig_b.file_off + (uint64_t)(unmap_end - orig.start),
                orig_b.dev, orig_b.ino, orig_b.darw_sync
            };
            if (vm_insert_region_backed(unmap_end, orig.end,
                                        orig.prot, orig.flags, orig.name, tail_b) == 0) {
                g_vm_regions[i].end = unmap_start;
                i += 2U;
            } else {
                i++;
            }
            continue;
        }
        if (r->start < unmap_start) {
            r->end = unmap_start;
        } else {
            vm_backing_t *b = &g_vm_backing[i];
            if (b->fd >= 0) {
                b->file_off += (uint64_t)(unmap_end - r->start);
            }
            r->start = unmap_end;
        }
        i++;
    }
}

int vm_record_region_backed_locked(uint32_t start, uint32_t end,
                                   uint32_t prot, uint32_t flags, const char *name,
                                   vm_backing_t back)
{
    if (start >= end) {
        return -1;
    }
    char name_copy[64];
    if (name) {
        snprintf(name_copy, sizeof(name_copy), "%s", name);
    } else {
        name_copy[0] = '\0';
    }
    uint32_t clean_flags = flags & ~(RT32_MAP_FIXED | RT32_MAP_FIXED_NOREPLACE);
    vm_unmap_regions_locked(start, end);
    int rc = vm_insert_region_backed(start, end, prot, clean_flags, name_copy, back);
    if (rc < 0) {
        vm_coalesce_regions_locked();
        rc = vm_insert_region_backed(start, end, prot, clean_flags, name_copy, back);
    }
    vm_coalesce_regions_locked();
    return rc;
}

int vm_record_region_locked(uint32_t start, uint32_t end,
                            uint32_t prot, uint32_t flags, const char *name)
{
    vm_backing_t none = { -1, 0U, 0U, 0U, 0U };
    return vm_record_region_backed_locked(start, end, prot, flags, name, none);
}

int vm_can_mprotect_regions_locked(uint32_t mp_start, uint32_t mp_end, uint32_t prot)
{
    vm_coalesce_regions_locked();
    size_t extra = 0U;
    for (size_t i = 0U; i < g_vm_region_count; i++) {
        const mips32_region_t *r = &g_vm_regions[i];
        if (r->end <= mp_start || r->start >= mp_end || r->prot == prot) {
            continue;
        }
        if (r->start < mp_start && r->end > mp_end) {
            extra += 2U;
        } else if (r->start < mp_start || r->end > mp_end) {
            extra += 1U;
        }
    }
    return (g_vm_region_count + extra <= MIPS32_MAX_REGIONS) ? 0 : -ENOMEM;
}

void vm_mprotect_regions_locked(uint32_t mp_start, uint32_t mp_end, uint32_t prot)
{
    size_t i = 0U;
    while (i < g_vm_region_count) {
        mips32_region_t *r = &g_vm_regions[i];
        if (r->end <= mp_start || r->start >= mp_end || r->prot == prot) {
            i++;
            continue;
        }
        if (r->start >= mp_start && r->end <= mp_end) {
            r->prot = prot;
            i++;
            continue;
        }
        mips32_region_t orig   = *r;
        vm_backing_t    orig_b = g_vm_backing[i];
        if (orig.start < mp_start && orig.end > mp_end) {
            vm_backing_t mid_b  = { orig_b.fd, orig_b.file_off + (uint64_t)(mp_start - orig.start), orig_b.dev, orig_b.ino, orig_b.darw_sync };
            vm_backing_t tail_b = { orig_b.fd, orig_b.file_off + (uint64_t)(mp_end - orig.start), orig_b.dev, orig_b.ino, orig_b.darw_sync };
            r->end = mp_start;
            (void)vm_insert_region_backed(mp_start, mp_end, prot, orig.flags, orig.name, mid_b);
            (void)vm_insert_region_backed(mp_end, orig.end, orig.prot, orig.flags, orig.name, tail_b);
            i += 3U;
        } else if (orig.start < mp_start) {
            vm_backing_t tail_b = { orig_b.fd, orig_b.file_off + (uint64_t)(mp_start - orig.start), orig_b.dev, orig_b.ino, orig_b.darw_sync };
            g_vm_regions[i].end = mp_start;
            (void)vm_insert_region_backed(mp_start, orig.end, prot, orig.flags, orig.name, tail_b);
            i += 2U;
        } else {
            r->start = mp_end;
            if (orig_b.fd >= 0) {
                g_vm_backing[i].file_off = orig_b.file_off + (uint64_t)(mp_end - orig.start);
            }
            (void)vm_insert_region_backed(orig.start, mp_end, prot, orig.flags, orig.name, orig_b);
            i += 2U;
        }
    }
    vm_coalesce_regions_locked();
}

bool vm_range_overlaps_locked(uint32_t start, uint32_t end)
{
    for (size_t i = 0U; i < g_vm_region_count && g_vm_regions[i].start < end; i++) {
        if (g_vm_regions[i].end > start) {
            return true;
        }
    }
    return false;
}

bool vm_check_mapped_range_locked(uint32_t start, uint32_t end,
                                  uint32_t *out_prot, uint32_t *out_flags,
                                  char *out_name, size_t name_sz,
                                  vm_backing_t *out_back)
{
    if (start >= end) {
        return false;
    }
    uint32_t cur = start;
    bool     first = true;
    uint32_t first_prot  = 0U;
    uint32_t first_flags = 0U;
    if (out_back != NULL) {
        out_back->fd        = -1;
        out_back->file_off  = 0U;
        out_back->dev       = 0U;
        out_back->ino       = 0U;
        out_back->darw_sync = 0U;
    }
    for (size_t i = 0U; i < g_vm_region_count; i++) {
        const mips32_region_t *r = &g_vm_regions[i];
        if (r->end <= cur) {
            continue;
        }
        if (r->start > cur) {
            return false;
        }
        if (first) {
            first_prot  = r->prot;
            first_flags = r->flags & 0x23U;
            if (out_prot) {
                *out_prot = r->prot;
            }
            if (out_flags) {
                *out_flags = r->flags;
            }
            if (out_name && name_sz > 0U) {
                snprintf(out_name, name_sz, "%s", r->name);
            }
            if (out_back != NULL) {
                out_back->fd        = g_vm_backing[i].fd;
                out_back->file_off  = g_vm_backing[i].file_off + (uint64_t)(start - r->start);
                out_back->dev       = g_vm_backing[i].dev;
                out_back->ino       = g_vm_backing[i].ino;
                out_back->darw_sync = g_vm_backing[i].darw_sync;
            }
            first = false;
        } else if ((out_prot != NULL && r->prot != first_prot) ||
                   (out_flags != NULL && (r->flags & 0x23U) != first_flags)) {
            return false;
        }
        if (r->end >= end) {
            return true;
        }
        cur = r->end;
    }
    return false;
}

int vm_find_free_gap_locked(uint64_t aligned_len, uint32_t *out_va)
{
    if (aligned_len == 0ULL ||
        aligned_len > (uint64_t)(RT32_MMAP_TOP_32 - RT32_MMAP_BASE_32)) {
        return -1;
    }

    uint64_t cursor_cand = vm_page_align_up((uint64_t)g_vm_mmap_cursor);
    if (cursor_cand < (uint64_t)RT32_MMAP_BASE_32) {
        cursor_cand = (uint64_t)RT32_MMAP_BASE_32;
    }
    if (cursor_cand + aligned_len <= (uint64_t)RT32_MMAP_TOP_32 &&
        !vm_range_overlaps_locked((uint32_t)cursor_cand, (uint32_t)(cursor_cand + aligned_len))) {
        *out_va = (uint32_t)cursor_cand;
        return 0;
    }

    uint64_t cand = (uint64_t)RT32_MMAP_BASE_32;
    for (size_t i = 0U; i < g_vm_region_count; i++) {
        uint64_t r_start = (uint64_t)g_vm_regions[i].start;
        uint64_t r_end   = vm_page_align_up((uint64_t)g_vm_regions[i].end);
        if (r_end <= cand) {
            continue;
        }
        if (cand + aligned_len <= r_start) {
            break;
        }
        cand = r_end;
    }

    if (cand + aligned_len > (uint64_t)RT32_MMAP_TOP_32) {
        return -1;
    }

    *out_va = (uint32_t)cand;
    return 0;
}

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

int rt32_vm_record_region(mips32_ctx_t *ctx, uint32_t start, uint32_t end,
                         uint32_t prot, uint32_t flags, const char *name)
{
    if (!ctx || start >= end) {
        return -1;
    }
    vm_lock_acquire();
    vm_sync_from_ctx(ctx);
    int rc = vm_record_region_locked(start, end, prot, flags, name);
    vm_sync_to_ctx(ctx);
    vm_lock_release();
    return rc;
}


/* Exec teardown: drop every region from the AUTHORITATIVE global list
 * (ctx->regions is a mirror; vm_sync_from_ctx never copies it back, so a
 * ctx-only clear is undone by the next vm_sync_to_ctx).  No region
 * survives: linux execve destroys the whole old address space, and the
 * Phase 0/1 stack setup re-maps the stack while the loader maps the new
 * image fresh (a synthetic sigtramp/vdso page arrives in a later phase). */
void rt32_vm_reset_for_exec(mips32_ctx_t *ctx)
{
    vm_lock_acquire();
    (void)vm_flush_darw_range_locked(0U, MIPS32_TASK_SIZE_TOP);
    while (g_vm_region_count > 0U) {
        vm_remove_region_at(g_vm_region_count - 1U);
    }
    g_vm_brk_base    = 0U;
    g_vm_brk_curr    = 0U;
    g_vm_mmap_cursor = RT32_MMAP_BASE_32;
    (void)atomic_fetch_add_explicit(&g_vm_gen, 1U, memory_order_release);
    if (ctx != NULL) {
        (void)vm_reserve_prot_none(ctx, MIPS32_LOW_GUARD_SIZE,
            (uint32_t)(0xFFFF0000ULL - (uint64_t)MIPS32_LOW_GUARD_SIZE));
        ctx->brk_base     = 0U;
        ctx->brk_curr     = 0U;
        ctx->mmap_cursor  = RT32_MMAP_BASE_32;
        ctx->region_count = 0U;
        ctx->vm_gen       = atomic_load_explicit(&g_vm_gen, memory_order_relaxed);
    }
    vm_lock_release();
}

uint32_t rt32_vm_brk(mips32_ctx_t *ctx, uint32_t new_brk)
{
    if (!ctx) {
        return 0U;
    }
    vm_lock_acquire();
    vm_sync_from_ctx(ctx);

    uint32_t brk_limit = (g_vm_brk_base < RT32_MMAP_BASE_32) ? RT32_MMAP_BASE_32 : RT32_MMAP_TOP_32;
    if (new_brk == 0U || new_brk < g_vm_brk_base || new_brk > brk_limit) {
        uint32_t curr = g_vm_brk_curr;
        vm_sync_brk_to_ctx(ctx);
        vm_lock_release();
        return curr;
    }

    uint64_t old_page64 = vm_page_align_up((uint64_t)g_vm_brk_curr);
    uint64_t new_page64 = vm_page_align_up((uint64_t)new_brk);
    if (new_page64 > (uint64_t)brk_limit) {
        uint32_t curr = g_vm_brk_curr;
        vm_sync_brk_to_ctx(ctx);
        vm_lock_release();
        return curr;
    }

    uint32_t old_page = (uint32_t)old_page64;
    uint32_t new_page = (uint32_t)new_page64;

    if (new_page > old_page) {
        if (vm_range_overlaps_locked(old_page, new_page) ||
            vm_can_unmap_regions_locked(old_page, new_page, 1U) != 0) {
            uint32_t curr = g_vm_brk_curr;
            vm_sync_brk_to_ctx(ctx);
            vm_lock_release();
            return curr;
        }
        uint32_t len = new_page - old_page;
        void *host_addr = mips32_guest_ptr(ctx, old_page);
#ifdef __APPLE__
        uint32_t h_start = old_page & ~0x3FFFU;
        uint32_t h_end   = (new_page + 0x3FFFU) & ~0x3FFFU;
        if (mprotect(mips32_guest_ptr(ctx, h_start), (size_t)(h_end - h_start),
                     PROT_READ | PROT_WRITE) != 0) {
            uint32_t curr = g_vm_brk_curr;
            vm_sync_brk_to_ctx(ctx);
            vm_lock_release();
            return curr;
        }
        memset(host_addr, 0, len);
#else
        void *res = mmap(host_addr, len, PROT_READ | PROT_WRITE,
                         MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
        if (res == MAP_FAILED) {
            uint32_t curr = g_vm_brk_curr;
            vm_sync_brk_to_ctx(ctx);
            vm_lock_release();
            return curr;
        }
#endif
        (void)vm_record_region_locked(old_page, new_page,
                                      (uint32_t)(PROT_READ | PROT_WRITE), 0x22U, "[heap]");
    } else if (new_page < old_page) {
        if (vm_can_unmap_regions_locked(new_page, old_page, 0U) != 0) {
            uint32_t curr = g_vm_brk_curr;
            vm_sync_brk_to_ctx(ctx);
            vm_lock_release();
            return curr;
        }
        uint32_t len = old_page - new_page;
        (void)vm_flush_darw_range_locked(new_page, old_page);
        /* Re-reserve shrunk brk pages with PROT_NONE inside the guest window */
        (void)vm_reserve_prot_none(ctx, new_page, len);
        vm_unmap_regions_locked(new_page, old_page);
    }

    g_vm_brk_curr = new_brk;
    if (new_page != old_page) {
        vm_sync_to_ctx(ctx);
    } else {
        vm_sync_brk_to_ctx(ctx);
    }
    vm_lock_release();

    if (new_page < old_page) {
        vm_invalidate_jit(ctx, new_page, old_page);
    }
    return new_brk;
}

void rt32_vm_sync_ctx(mips32_ctx_t *ctx)
{
    uint64_t gen;

    if (!ctx) {
        return;
    }
    gen = atomic_load_explicit(&g_vm_gen, memory_order_acquire);
    if (gen == 0U || ctx->vm_gen == gen) {
        return;
    }
    vm_lock_acquire();
    vm_sync_from_ctx(ctx);
    vm_copy_state_to_ctx(ctx);
    vm_lock_release();
}

static bool vm_range_ok_locked(uint32_t va, uint32_t len, uint32_t need)
{
    if (len == 0U) {
        return true;
    }
    uint64_t end = (uint64_t)va + (uint64_t)len;
    if (end > 0x100000000ULL) {
        return false;
    }
    uint64_t cur = (uint64_t)va;
    for (size_t i = 0U; i < g_vm_region_count; i++) {
        const mips32_region_t *r = &g_vm_regions[i];
        if ((uint64_t)r->end <= cur) {
            continue;
        }
        if ((uint64_t)r->start > cur || (r->prot & need) != need) {
            return false;
        }
        cur = (uint64_t)r->end;
        if (cur >= end) {
            return true;
        }
    }
    return false;
}

int rt32_vm_copy_from(const mips32_ctx_t *ctx, void *dst, uint32_t va, uint32_t len)
{
    if (!ctx || (!dst && len > 0U)) {
        return -EFAULT;
    }
    if (len == 0U) {
        return 0;
    }
    vm_lock_acquire();
    bool ok = (atomic_load_explicit(&g_vm_gen, memory_order_relaxed) != 0U)
        ? vm_range_ok_locked(va, len, (uint32_t)PROT_READ)
        : mips32_range_ok(ctx, va, len, (uint32_t)PROT_READ);
    if (!ok) {
        vm_lock_release();
        return -EFAULT;
    }
    memcpy(dst, mips32_guest_ptr(ctx, va), (size_t)len);
    vm_lock_release();
    return 0;
}

int rt32_vm_copy_to(mips32_ctx_t *ctx, uint32_t va, const void *src, uint32_t len)
{
    if (!ctx || (!src && len > 0U)) {
        return -EFAULT;
    }
    if (len == 0U) {
        return 0;
    }
    vm_lock_acquire();
    bool ok = (atomic_load_explicit(&g_vm_gen, memory_order_relaxed) != 0U)
        ? vm_range_ok_locked(va, len, (uint32_t)PROT_WRITE)
        : mips32_range_ok(ctx, va, len, (uint32_t)PROT_WRITE);
    if (!ok) {
        vm_lock_release();
        return -EFAULT;
    }
    memcpy(mips32_guest_ptr(ctx, va), src, (size_t)len);
    vm_lock_release();
    return 0;
}
