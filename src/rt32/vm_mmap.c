/*
 * src/rt32/vm_mmap.c — Guest mmap/mprotect/munmap/mremap on the 4 GiB window
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Split from src/rt32/vm.c (vendored from ../i686rt/src/rt32/rt32_vm.c)
 * to honor the 900-line file limit.  All mutations serialize on the
 * D19 CLONE_VM page-table lock (g_vm_lock) and invalidate the DBT range
 * on success (SMC).
 */

#define _GNU_SOURCE
#include "vm_priv.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>

static uint32_t vm_mmap2_locked(mips32_ctx_t *ctx, uint32_t addr, uint32_t len, uint32_t prot,
                                uint32_t flags, int fd, uint32_t pgoffset)
{
    if (!ctx || len == 0U || (flags & 0x03U) == 0U || (flags & 0x03U) == 0x03U) {
        return (uint32_t)(-EINVAL);
    }

    uint64_t aligned_len = vm_page_align_up((uint64_t)len);
    if (aligned_len == 0ULL || aligned_len > (uint64_t)MIPS32_TASK_SIZE_TOP) {
        return (uint32_t)(-ENOMEM);
    }

    int host_flags = 0;
    if (flags & 0x01U) {
        host_flags |= MAP_SHARED;
    }
    if (flags & 0x02U) {
        host_flags |= MAP_PRIVATE;
    }
    if (flags & RT32_MAP_ANONYMOUS) {
        host_flags |= MAP_ANONYMOUS;
    }

    uint32_t target_va     = 0U;
    bool     update_cursor = false;
    if ((flags & (RT32_MAP_FIXED | RT32_MAP_FIXED_NOREPLACE)) != 0U) {
        if ((addr & (MIPS32_PAGE_SIZE - 1U)) != 0U || addr < MIPS32_LOW_GUARD_SIZE) {
            return (uint32_t)(-EINVAL);
        }
        if ((uint64_t)addr + aligned_len > (uint64_t)MIPS32_TASK_SIZE_TOP) {
            return (uint32_t)(-ENOMEM);
        }
        if ((flags & RT32_MAP_FIXED_NOREPLACE) != 0U &&
            vm_range_overlaps_locked(addr, (uint32_t)((uint64_t)addr + aligned_len))) {
            return (uint32_t)(-EEXIST);
        }
        target_va = addr;
    } else {
        uint32_t hint_va = mips32_page_down(addr);
        if (addr != 0U &&
            hint_va >= RT32_MMAP_BASE_32 &&
            (uint64_t)hint_va + aligned_len <= (uint64_t)RT32_MMAP_TOP_32 &&
            !vm_range_overlaps_locked(hint_va, (uint32_t)((uint64_t)hint_va + aligned_len))) {
            target_va = hint_va;
        } else if (vm_find_free_gap_locked(aligned_len, &target_va) != 0) {
            return (uint32_t)(-ENOMEM);
        } else {
            update_cursor = true;
        }
    }

    int   host_prot   = mips32_host_prot(ctx, prot);
    void *host_target = mips32_guest_ptr(ctx, target_va);
    off_t host_off    = (off_t)pgoffset * (off_t)MIPS32_PAGE_SIZE;
    void *res = mmap(host_target, (size_t)aligned_len, host_prot,
                     host_flags | MAP_FIXED, (host_flags & MAP_ANONYMOUS) ? -1 : fd,
                     (host_flags & MAP_ANONYMOUS) ? 0 : host_off);
    if (res == MAP_FAILED) {
        return (uint32_t)(-errno);
    }

    if (update_cursor) {
        g_vm_mmap_cursor = (uint32_t)((uint64_t)target_va + aligned_len);
    }
    (void)vm_record_region_locked(target_va, (uint32_t)((uint64_t)target_va + aligned_len),
                                  prot & 0x7U, flags, "[mmap]");
    return target_va;
}

uint32_t rt32_vm_mmap2(mips32_ctx_t *ctx, uint32_t addr, uint32_t len, uint32_t prot,
                      uint32_t flags, int fd, uint32_t pgoffset)
{
    if (!ctx) {
        return (uint32_t)(-EINVAL);
    }

    vm_lock_acquire();
    vm_sync_from_ctx(ctx);
    uint32_t res = vm_mmap2_locked(ctx, addr, len, prot, flags, fd, pgoffset);
    vm_sync_to_ctx(ctx);
    vm_lock_release();

    if (res <= 0xFFFFF000U &&
        ((flags & (RT32_MAP_FIXED | RT32_MAP_FIXED_NOREPLACE)) != 0U ||
         (prot & (uint32_t)PROT_EXEC) != 0U)) {
        vm_invalidate_jit(ctx, res, (uint32_t)((uint64_t)res + vm_page_align_up((uint64_t)len)));
    }

    /* No AOT pre-translator exists: the Phase 2 DBT compiles lazily. */

    return res;
}

static int vm_mprotect_locked(mips32_ctx_t *ctx, uint32_t addr, uint32_t len, uint32_t prot)
{
    if (!ctx || (addr & (MIPS32_PAGE_SIZE - 1U)) != 0U || addr < 0x1000U || (prot & ~0x7U) != 0U) {
        return -EINVAL;
    }
    if (len == 0U) {
        return 0;
    }
    uint64_t aligned_len = vm_page_align_up((uint64_t)len);
    uint64_t end64       = (uint64_t)addr + aligned_len;
    if (addr < MIPS32_LOW_GUARD_SIZE ||
        aligned_len == 0ULL ||
        end64 > (uint64_t)MIPS32_TASK_SIZE_TOP ||
        !vm_check_mapped_range_locked(addr, (uint32_t)end64, NULL, NULL, NULL, 0U)) {
        return -ENOMEM;
    }

    if (mprotect(mips32_guest_ptr(ctx, addr), (size_t)aligned_len, mips32_host_prot(ctx, prot)) != 0) {
        return -errno;
    }

    vm_mprotect_regions_locked(addr, (uint32_t)end64, prot & 0x7U);
    return 0;
}

int rt32_vm_mprotect(mips32_ctx_t *ctx, uint32_t addr, uint32_t len, uint32_t prot)
{
    if (!ctx) {
        return -EINVAL;
    }

    vm_lock_acquire();
    vm_sync_from_ctx(ctx);
    int rc = vm_mprotect_locked(ctx, addr, len, prot);
    vm_sync_to_ctx(ctx);
    vm_lock_release();

    if (rc == 0 && len > 0U) {
        vm_invalidate_jit(ctx, addr, (uint32_t)((uint64_t)addr + vm_page_align_up((uint64_t)len)));
    }
    return rc;
}

static int vm_munmap_locked(mips32_ctx_t *ctx, uint32_t addr, uint32_t len)
{
    if (!ctx || (addr & (MIPS32_PAGE_SIZE - 1U)) != 0U || len == 0U) {
        return -EINVAL;
    }
    uint64_t aligned_len = vm_page_align_up((uint64_t)len);
    if (addr < MIPS32_LOW_GUARD_SIZE ||
        (uint64_t)addr + aligned_len > (uint64_t)MIPS32_TASK_SIZE_TOP) {
        return -EINVAL;
    }

    uint32_t start = mips32_page_down(addr);
    /* Keep the [G, G+4GiB) reservation intact by replacing unmapped pages with PROT_NONE */
    int rc = vm_reserve_prot_none(ctx, start, (uint32_t)aligned_len);
    if (rc != 0) {
        return rc;
    }

    uint32_t end = (uint32_t)((uint64_t)start + aligned_len);
    vm_unmap_regions_locked(start, end);
    if (g_vm_mmap_cursor == end && start >= RT32_MMAP_BASE_32) {
        g_vm_mmap_cursor = start;
    }
    return 0;
}

int rt32_vm_munmap(mips32_ctx_t *ctx, uint32_t addr, uint32_t len)
{
    if (!ctx) {
        return -EINVAL;
    }

    vm_lock_acquire();
    vm_sync_from_ctx(ctx);
    int rc = vm_munmap_locked(ctx, addr, len);
    vm_sync_to_ctx(ctx);
    vm_lock_release();

    if (rc == 0) {
        vm_invalidate_jit(ctx, addr, (uint32_t)((uint64_t)addr + vm_page_align_up((uint64_t)len)));
    }
    return rc;
}

uint32_t rt32_vm_mremap(mips32_ctx_t *ctx, uint32_t old_addr, uint32_t old_len,
                       uint32_t new_len, uint32_t flags, uint32_t new_addr)
{
    if (!ctx || (old_addr & (MIPS32_PAGE_SIZE - 1U)) != 0U ||
        old_len == 0U || new_len == 0U) {
        return (uint32_t)(-EINVAL);
    }
    if ((flags & ~(RT32_MREMAP_MAYMOVE | RT32_MREMAP_FIXED)) != 0U ||
        ((flags & RT32_MREMAP_FIXED) != 0U && (flags & RT32_MREMAP_MAYMOVE) == 0U)) {
        return (uint32_t)(-EINVAL);
    }

    uint64_t old_aligned = vm_page_align_up((uint64_t)old_len);
    uint64_t new_aligned = vm_page_align_up((uint64_t)new_len);
    if (old_addr < MIPS32_LOW_GUARD_SIZE ||
        (uint64_t)old_addr + old_aligned > (uint64_t)MIPS32_TASK_SIZE_TOP) {
        return (uint32_t)(-EINVAL);
    }
    if (new_aligned == 0ULL || new_aligned > (uint64_t)MIPS32_TASK_SIZE_TOP) {
        return (uint32_t)(-ENOMEM);
    }

    vm_lock_acquire();
    vm_sync_from_ctx(ctx);

    uint32_t prot       = 0x3U;
    uint32_t orig_flags = 0x22U;
    char     orig_name[64];
    orig_name[0] = '\0';
    if (!vm_check_mapped_range_locked(old_addr, (uint32_t)((uint64_t)old_addr + old_aligned),
                                      &prot, &orig_flags, orig_name, sizeof(orig_name))) {
        vm_sync_to_ctx(ctx);
        vm_lock_release();
        return (uint32_t)(-EFAULT);
    }
    uint32_t    keep_flags  = orig_flags & 0x23U;
    uint32_t    map_flags   = (((keep_flags & 0x01U) != 0U) ? 0x01U : 0x02U) | RT32_MAP_ANONYMOUS;
    const char *region_name = (orig_name[0] != '\0') ? orig_name : "[mmap]";

    if ((flags & RT32_MREMAP_FIXED) == 0U) {
        if (new_aligned == old_aligned) {
            vm_sync_to_ctx(ctx);
            vm_lock_release();
            return old_addr;
        }
        if (new_aligned < old_aligned) {
            uint32_t unmap_addr = old_addr + (uint32_t)new_aligned;
            uint32_t unmap_len  = (uint32_t)(old_aligned - new_aligned);
            int rc = vm_munmap_locked(ctx, unmap_addr, unmap_len);
            vm_sync_to_ctx(ctx);
            vm_lock_release();
            if (rc != 0) {
                return (uint32_t)rc;
            }
            vm_invalidate_jit(ctx, unmap_addr, unmap_addr + unmap_len);
            return old_addr;
        }

        uint32_t old_end = (uint32_t)((uint64_t)old_addr + old_aligned);
        uint64_t new_end = (uint64_t)old_addr + new_aligned;
        if (new_end <= (uint64_t)MIPS32_TASK_SIZE_TOP &&
            !vm_range_overlaps_locked(old_end, (uint32_t)new_end)) {
            uint32_t ext = vm_mmap2_locked(ctx, old_end, (uint32_t)(new_aligned - old_aligned),
                                           prot, map_flags | RT32_MAP_FIXED, -1, 0U);
            if (ext <= 0xFFFFF000U) {
                (void)vm_record_region_locked(old_end, (uint32_t)new_end,
                                              prot, keep_flags, region_name);
                uint32_t ext_end = (uint32_t)new_end;
                if (g_vm_mmap_cursor >= old_addr && g_vm_mmap_cursor < ext_end &&
                    ext_end <= RT32_MMAP_TOP_32) {
                    g_vm_mmap_cursor = ext_end;
                }
                vm_sync_to_ctx(ctx);
                vm_lock_release();
                if ((prot & (uint32_t)PROT_EXEC) != 0U) {
                    vm_invalidate_jit(ctx, old_end, ext_end);
                }
                return old_addr;
            }
        }

        if ((flags & RT32_MREMAP_MAYMOVE) == 0U) {
            vm_sync_to_ctx(ctx);
            vm_lock_release();
            return (uint32_t)(-ENOMEM);
        }
    } else {
        if ((new_addr & (MIPS32_PAGE_SIZE - 1U)) != 0U || new_addr < MIPS32_LOW_GUARD_SIZE ||
            (uint64_t)new_addr + new_aligned > (uint64_t)MIPS32_TASK_SIZE_TOP ||
            ((uint64_t)new_addr < (uint64_t)old_addr + old_aligned &&
             (uint64_t)old_addr < (uint64_t)new_addr + new_aligned)) {
            vm_sync_to_ctx(ctx);
            vm_lock_release();
            return (uint32_t)(-EINVAL);
        }
    }

    bool     is_fixed = (flags & RT32_MREMAP_FIXED) != 0U;
    uint32_t rw_prot  = (prot & ~((uint32_t)PROT_EXEC)) | (uint32_t)(PROT_READ | PROT_WRITE);
    uint32_t new_va   = vm_mmap2_locked(ctx, is_fixed ? new_addr : 0U, (uint32_t)new_aligned,
                                        rw_prot, map_flags | (is_fixed ? RT32_MAP_FIXED : 0U),
                                        -1, 0U);
    if (new_va > 0xFFFFF000U) {
        vm_sync_to_ctx(ctx);
        vm_lock_release();
        return new_va;
    }

    if ((prot & 0x1U) == 0U) {
        (void)mprotect(mips32_guest_ptr(ctx, old_addr), (size_t)old_aligned, PROT_READ);
    }
    size_t copy_bytes = (size_t)((old_aligned < new_aligned) ? old_aligned : new_aligned);
    memcpy(mips32_guest_ptr(ctx, new_va), mips32_guest_ptr(ctx, old_addr), copy_bytes);
    if (prot != 0x3U) {
        (void)vm_mprotect_locked(ctx, new_va, (uint32_t)new_aligned, prot);
    }
    (void)vm_record_region_locked(new_va, (uint32_t)((uint64_t)new_va + new_aligned),
                                  prot, keep_flags, region_name);
    (void)vm_munmap_locked(ctx, old_addr, (uint32_t)old_aligned);
    vm_sync_to_ctx(ctx);
    vm_lock_release();

    vm_invalidate_jit(ctx, old_addr, (uint32_t)((uint64_t)old_addr + old_aligned));
    if (is_fixed || (prot & (uint32_t)PROT_EXEC) != 0U) {
        vm_invalidate_jit(ctx, new_va, (uint32_t)((uint64_t)new_va + new_aligned));
    }
    return new_va;
}

