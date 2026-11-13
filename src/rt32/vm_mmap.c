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

#include "vm/vm32.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS MAP_ANON
#endif

/* Keep the A2 Soft-TLB coherent wherever the DBT range is invalidated. */
static void vm_invalidate_all(mips32_ctx_t *ctx, uint32_t start,
                              uint32_t end)
{
    vm_invalidate_jit(ctx, start, end);
    mips32_vm_invalidate_range(ctx, start, end);
}

static int pread_full(int fd, uint8_t *dst, size_t rem, off_t cur_off)
{
    while (rem > 0U) {
        ssize_t n = pread(fd, dst, rem, cur_off);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -errno;
        }
        if (n == 0) {
            break;
        }
        dst += (size_t)n;
        rem -= (size_t)n;
        cur_off += (off_t)n;
    }
    return 0;
}

static uint32_t vm_mmap2_ext_locked(mips32_ctx_t *ctx, uint32_t addr, uint32_t len, uint32_t prot,
                                    uint32_t flags, int fd, uint32_t pgoffset, bool dup_backing,
                                    const char *rname)
{
    if (!ctx || len == 0U || (flags & 0x03U) == 0U || (flags & 0x03U) == 0x03U) {
        return (uint32_t)(-EINVAL);
    }
    /* M32-R9-4: reject unknown prot bits like mprotect does below instead
     * of silently masking them into the VMA record. */
    if ((prot & ~0x7U) != 0U) {
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
    } else if (fd < 0) {
        return (uint32_t)(-EBADF);
    }

    uint32_t target_va     = 0U;
    bool     update_cursor = false;
#ifdef __APPLE__
    bool     shadow_elevated = false;
#endif
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

    uint32_t target_end = (uint32_t)((uint64_t)target_va + aligned_len);
    if (vm_can_unmap_regions_locked(target_va, target_end, 1U) != 0) {
        return (uint32_t)(-ENOMEM);
    }

    off_t        host_off = (off_t)pgoffset * (off_t)MIPS32_PAGE_SIZE;
    vm_backing_t back     = { -1, 0U, 0U, 0U, 0U };
    if ((host_flags & MAP_ANONYMOUS) == 0 && fd >= 0) {
        struct stat st;
        int fl = fcntl(fd, F_GETFL);
        if (fl < 0 || fstat(fd, &st) != 0) {
            return (uint32_t)(-errno);
        }
        if ((fl & O_ACCMODE) == O_WRONLY ||
            ((flags & 0x01U) != 0U && (prot & (uint32_t)PROT_WRITE) != 0U &&
             (fl & O_ACCMODE) != O_RDWR)) {
            return (uint32_t)(-EACCES);
        }
        int bfd = dup_backing ? fcntl(fd, F_DUPFD_CLOEXEC, 0) : fd;
        if (bfd < 0) {
            return (uint32_t)(-errno);
        }
        back.fd       = bfd;
        back.file_off = (uint64_t)host_off;
        back.dev      = (uint64_t)st.st_dev;
        back.ino      = (uint64_t)st.st_ino;
        if ((flags & 0x01U) != 0U) {
            /* M32-R4-9: a failed same-inode flush must fail the mmap
             * instead of leaving stale shadows behind. */
            int frc = vm_flush_darw_inode_locked(back.dev, back.ino);
            if (frc != 0) {
                if (dup_backing && back.fd >= 0) {
                    (void)close(back.fd);
                }
                return (uint32_t)frc;
            }
        }
    }
    /* M32-R4-9: a failed pre-replacement flush must fail the mmap
     * instead of silently dropping dirty bytes on replace. */
    {
        int frc = vm_flush_darw_range_locked(target_va, target_end);
        if (frc != 0) {
            if (dup_backing && back.fd >= 0) {
                (void)close(back.fd);
            }
            return (uint32_t)frc;
        }
    }

    int   host_prot   = mips32_host_prot(ctx, prot);
    void *host_target = mips32_guest_ptr(ctx, target_va);
#ifdef __APPLE__
    uint32_t h_start = target_va & ~0x3FFFU;
    uint32_t h_end   = (target_end + 0x3FFFU) & ~0x3FFFU;
    /* M32-R4-5/M32-R4-10: on Darwin every file mapping is shadow-backed
     * (anonymous host pages populated from the file, MAP_SHARED tracked
     * via darw_sync alias propagation) instead of mixing direct
     * MAP_SHARED host pages with shadow aliases: replacing a 4 KiB
     * sub-page of a direct shared page would zero the underlying file,
     * and baseline-diff flushes cannot tell a stale shadow from newer
     * direct writes.  Anonymous mappings keep the direct path. */
    if ((host_flags & MAP_ANONYMOUS) != 0U &&
        (target_va & 0x3FFFU) == 0U && (aligned_len & 0x3FFFULL) == 0ULL) {
        void *res = mmap(host_target, (size_t)aligned_len, host_prot,
                         host_flags | MAP_FIXED, -1, 0);
        if (res == MAP_FAILED) {
            int err = errno;
            if (dup_backing && back.fd >= 0) {
                (void)close(back.fd);
            }
            return (uint32_t)(-err);
        }
    } else {
        /* M32-R4-7: stage the fallible file population before touching
         * live mappings: pread into a zeroed staging buffer first, so a
         * read error returns with no modified bytes and no elevated
         * protection.  Zero-fill plus pread_full is byte-identical to
         * the old in-place memset plus populate_private/pread sequence
         * (mips32_guest_ptr is G + gva, the same HVA the A2 private
         * helper uses), so the A2 private path stages the same way. */
        uint8_t *stage = NULL;

        shadow_elevated = true;
        if ((host_flags & MAP_ANONYMOUS) == 0 && fd >= 0) {
            int prc;

            stage = (uint8_t *)malloc((size_t)aligned_len);
            if (stage == NULL) {
                if (dup_backing && back.fd >= 0) {
                    (void)close(back.fd);
                }
                return (uint32_t)(-ENOMEM);
            }
            memset(stage, 0, (size_t)aligned_len);
            prc = pread_full(fd, stage, (size_t)aligned_len, host_off);
            if (prc != 0) {
                free(stage);
                if (dup_backing && back.fd >= 0) {
                    (void)close(back.fd);
                }
                return (uint32_t)prc;
            }
        }
        if (mprotect(mips32_guest_ptr(ctx, h_start), (size_t)(h_end - h_start),
                     PROT_READ | PROT_WRITE) != 0) {
            int err = errno;
            free(stage);
            if (dup_backing && back.fd >= 0) {
                (void)close(back.fd);
            }
            return (uint32_t)(-err);
        }
        if (stage != NULL) {
            memcpy(host_target, stage, (size_t)aligned_len);
            free(stage);
        } else {
            memset(host_target, 0, (size_t)aligned_len);
        }
        if ((host_flags & MAP_ANONYMOUS) == 0 && fd >= 0 &&
            (flags & 0x01U) != 0U) {
            back.darw_sync = 1U;
        }
    }
#else
    void *res = mmap(host_target, (size_t)aligned_len, host_prot,
                     host_flags | MAP_FIXED, (host_flags & MAP_ANONYMOUS) ? -1 : fd,
                     (host_flags & MAP_ANONYMOUS) ? 0 : host_off);
    if (res == MAP_FAILED) {
        int err = errno;
        if (dup_backing && back.fd >= 0) {
            (void)close(back.fd);
        }
        return (uint32_t)(-err);
    }
#endif

    if (vm_record_region_backed_locked(target_va, target_end,
                                       prot & 0x7U, flags, rname ? rname : "[mmap]", back) != 0) {
        if (dup_backing && back.fd >= 0) {
            (void)close(back.fd);
        }
        /* Transactional unwind (cross-RT Round-3 class): the host
         * mapping is live but has no VMA record, so later permission
         * checks and file hooks would observe a different model.
         * The union restore drops exactly this range back to PROT_NONE
         * (plus live neighbors) on every host. */
        vm_host_restore_locked(target_va, target_end);
        return (uint32_t)(-ENOMEM);
    }
#ifdef __APPLE__
    /* The shadow populate above left the host-rounded range RW: fold
     * it back to the union so read-only mappings (and neighbors that
     * merely share the edge page) regain their host protection. */
    if (shadow_elevated) {
        vm_host_restore_locked(target_va, target_end);
    }
#endif
    if (update_cursor) {
        g_vm_mmap_cursor = target_end;
    }
    return target_va;
}

static uint32_t vm_mmap2_locked(mips32_ctx_t *ctx, uint32_t addr, uint32_t len, uint32_t prot,
                                uint32_t flags, int fd, uint32_t pgoffset)
{
    return vm_mmap2_ext_locked(ctx, addr, len, prot, flags, fd, pgoffset, true, "[mmap]");
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
        vm_invalidate_all(ctx, res, (uint32_t)((uint64_t)res + vm_page_align_up((uint64_t)len)));
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
        !vm_check_mapped_range_locked(addr, (uint32_t)end64, NULL, NULL, NULL, 0U, NULL) ||
        vm_can_mprotect_regions_locked(addr, (uint32_t)end64, prot & 0x7U) != 0) {
        return -ENOMEM;
    }

#ifdef __APPLE__
    /* M32-R3-3: one mprotect covers whole host pages, so the new
     * protection must already include every surviving neighbor piece:
     * regions fully inside [addr, end) take the new prot, anything
     * reaching outside keeps its old prot in the union.  The outside
     * contribution is exactly the union over the two host-rounded
     * slivers, reused from vm_union_host_prot_locked instead of a
     * second open-coded scan. */
    {
        uint32_t h_start = addr & ~0x3FFFU;
        uint32_t h_end   = ((uint32_t)end64 + 0x3FFFU) & ~0x3FFFU;
        uint32_t m_end   = (uint32_t)end64;
        int      h_prot  = mips32_host_prot(ctx, prot);

        if (h_start < addr) {
            h_prot |= vm_union_host_prot_locked(h_start, addr);
        }
        if (m_end < h_end) {
            h_prot |= vm_union_host_prot_locked(m_end, h_end);
        }
        if (mprotect(mips32_guest_ptr(ctx, h_start), (size_t)(h_end - h_start), h_prot) != 0) {
            return -errno;
        }
    }
#else
    if (mprotect(mips32_guest_ptr(ctx, addr), (size_t)aligned_len, mips32_host_prot(ctx, prot)) != 0) {
        return -errno;
    }
#endif

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
        vm_invalidate_all(ctx, addr, (uint32_t)((uint64_t)addr + vm_page_align_up((uint64_t)len)));
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
    uint32_t end   = (uint32_t)((uint64_t)start + aligned_len);
    if (vm_can_unmap_regions_locked(start, end, 0U) != 0) {
        return -ENOMEM;
    }
    /* M32-R4-9: a failed flush must fail the munmap instead of
     * silently dropping dirty bytes on unmap. */
    {
        int frc = vm_flush_darw_range_locked(start, end);
        if (frc != 0) {
            return frc;
        }
    }
#ifdef __APPLE__
    /* M32-R3-3: unmap first, then restore the union.  A blanket
     * PROT_NONE over the host-rounded range would disable a live
     * neighbor sharing an edge page, while the union keeps the
     * reservation PROT_NONE exactly where nothing remains. */
    vm_unmap_regions_locked(start, end);
    vm_host_restore_locked(start, end);
#else
    /* Keep the [G, G+4GiB) reservation intact by replacing unmapped pages with PROT_NONE */
    int rc = vm_reserve_prot_none(ctx, start, (uint32_t)aligned_len);
    if (rc != 0) {
        return rc;
    }

    vm_unmap_regions_locked(start, end);
#endif
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
        vm_invalidate_all(ctx, addr, (uint32_t)((uint64_t)addr + vm_page_align_up((uint64_t)len)));
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

    uint32_t     prot       = 0x3U;
    uint32_t     orig_flags = 0x22U;
    char         orig_name[64];
    vm_backing_t orig_back  = { -1, 0U, 0U, 0U, 0U };
    orig_name[0] = '\0';
    if (!vm_check_mapped_range_locked(old_addr, (uint32_t)((uint64_t)old_addr + old_aligned),
                                      &prot, &orig_flags, orig_name, sizeof(orig_name),
                                      &orig_back)) {
        vm_sync_to_ctx(ctx);
        vm_lock_release();
        return (uint32_t)(-EFAULT);
    }
    uint32_t    keep_flags  = orig_flags & 0x23U;
    uint32_t    anon_flags  = (((keep_flags & 0x01U) != 0U) ? 0x01U : 0x02U) | RT32_MAP_ANONYMOUS;
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
            vm_invalidate_all(ctx, unmap_addr, unmap_addr + unmap_len);
            return old_addr;
        }

        uint32_t old_end = (uint32_t)((uint64_t)old_addr + old_aligned);
        uint64_t new_end = (uint64_t)old_addr + new_aligned;
        if (new_end <= (uint64_t)MIPS32_TASK_SIZE_TOP &&
            !vm_range_overlaps_locked(old_end, (uint32_t)new_end)) {
            uint32_t ext_flags = (orig_back.fd >= 0) ? keep_flags : anon_flags;
            uint32_t ext_pgoff = (orig_back.fd >= 0)
                ? (uint32_t)((orig_back.file_off + old_aligned) / (uint64_t)MIPS32_PAGE_SIZE)
                : 0U;
            uint32_t ext = vm_mmap2_ext_locked(ctx, old_end,
                                               (uint32_t)(new_aligned - old_aligned),
                                               prot, ext_flags | RT32_MAP_FIXED,
                                               orig_back.fd, ext_pgoff, false, region_name);
            if (ext <= 0xFFFFF000U) {
                uint32_t ext_end = (uint32_t)new_end;
                if (g_vm_mmap_cursor >= old_addr && g_vm_mmap_cursor < ext_end &&
                    ext_end <= RT32_MMAP_TOP_32) {
                    g_vm_mmap_cursor = ext_end;
                }
                vm_sync_to_ctx(ctx);
                vm_lock_release();
                if ((prot & (uint32_t)PROT_EXEC) != 0U) {
                    vm_invalidate_all(ctx, old_end, ext_end);
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
    uint32_t new_va   = 0U;
    if (orig_back.fd >= 0 && (keep_flags & 0x01U) != 0U) {
        /* File-backed MAP_SHARED move: map the backing fd directly at new_va. */
        uint32_t map_prot = (orig_back.darw_sync != 0U)
            ? ((prot & ~((uint32_t)PROT_EXEC)) | (uint32_t)(PROT_READ | PROT_WRITE))
            : prot;
        uint32_t pgoff = (uint32_t)(orig_back.file_off / (uint64_t)MIPS32_PAGE_SIZE);
        new_va = vm_mmap2_ext_locked(ctx, is_fixed ? new_addr : 0U, (uint32_t)new_aligned,
                                     map_prot, keep_flags | (is_fixed ? RT32_MAP_FIXED : 0U),
                                     orig_back.fd, pgoff, false, region_name);
        if (new_va > 0xFFFFF000U) {
            vm_sync_to_ctx(ctx);
            vm_lock_release();
            return new_va;
        }
        if (orig_back.darw_sync != 0U) {
            /* M32-R3-4: the destination may recycle an address a live
             * LL reservation names, so the move participates in epoch
             * tracking like every other bulk store. */
            uint32_t copy_len = (uint32_t)((old_aligned < new_aligned) ? old_aligned : new_aligned);
            mips_guest_store_commit(ctx, new_va,
                                    mips32_guest_ptr(ctx, old_addr), copy_len);
            if (prot != map_prot) {
                int mrc = vm_mprotect_locked(ctx, new_va,
                                             (uint32_t)new_aligned, prot);
                if (mrc != 0) {
                    (void)vm_munmap_locked(ctx, new_va,
                                           (uint32_t)new_aligned);
                    vm_sync_to_ctx(ctx);
                    vm_lock_release();
                    return (uint32_t)mrc;
                }
            }
        }
    } else {
        uint32_t rw_prot = (prot & ~((uint32_t)PROT_EXEC)) | (uint32_t)(PROT_READ | PROT_WRITE);
        new_va = vm_mmap2_ext_locked(ctx, is_fixed ? new_addr : 0U, (uint32_t)new_aligned,
                                     rw_prot, anon_flags | (is_fixed ? RT32_MAP_FIXED : 0U),
                                     -1, 0U, false, region_name);
        if (new_va > 0xFFFFF000U) {
            vm_sync_to_ctx(ctx);
            vm_lock_release();
            return new_va;
        }
#ifdef __linux__
        if (orig_back.fd < 0 && (keep_flags & 0x01U) != 0U) {
            /* Anonymous MAP_SHARED move on Linux: preserve shared pages via host mremap. */
            void *mres = mremap(mips32_guest_ptr(ctx, old_addr), (size_t)old_aligned,
                                (size_t)new_aligned, MREMAP_MAYMOVE | MREMAP_FIXED,
                                mips32_guest_ptr(ctx, new_va));
            if (mres != MAP_FAILED) {
                if (prot != rw_prot) {
                    if (mprotect(mips32_guest_ptr(ctx, new_va),
                                 (size_t)new_aligned,
                                 mips32_host_prot(ctx, prot)) != 0) {
                        int e = errno;
                        (void)vm_munmap_locked(ctx, new_va,
                                               (uint32_t)new_aligned);
                        vm_sync_to_ctx(ctx);
                        vm_lock_release();
                        return (uint32_t)-(int32_t)e;
                    }
                }
                (void)vm_record_region_backed_locked(new_va,
                    (uint32_t)((uint64_t)new_va + new_aligned),
                    prot, keep_flags, region_name, orig_back);
                (void)vm_munmap_locked(ctx, old_addr, (uint32_t)old_aligned);
                vm_sync_to_ctx(ctx);
                vm_lock_release();
                vm_invalidate_all(ctx, old_addr, (uint32_t)((uint64_t)old_addr + old_aligned));
                if (is_fixed || (prot & (uint32_t)PROT_EXEC) != 0U) {
                    vm_invalidate_all(ctx, new_va, (uint32_t)((uint64_t)new_va + new_aligned));
                }
                return new_va;
            }
            /* I686-R3-9 class: a copying fallback would silently stop
             * sharing the pages with fork peers, so fail instead and
             * drop the provisional destination. */
            (void)vm_munmap_locked(ctx, new_va, (uint32_t)new_aligned);
            vm_sync_to_ctx(ctx);
            vm_lock_release();
            return (uint32_t)(-ENOMEM);
        }
#endif
        if ((prot & 0x1U) == 0U) {
            (void)mprotect(mips32_guest_ptr(ctx, old_addr), (size_t)old_aligned, PROT_READ);
        }
        /* M32-R3-4: epoch-tracked move like the shared path above. */
        mips_guest_store_commit(ctx, new_va, mips32_guest_ptr(ctx, old_addr),
                                (uint32_t)((old_aligned < new_aligned) ? old_aligned : new_aligned));
        if (orig_back.fd >= 0 && new_aligned > old_aligned) {
            /* Private file-backed growth: populate the exposed tail
             * from the retained backing fd (pread shortfall past EOF
             * leaves the fresh zero pages intact). */
            (void)pread_full(orig_back.fd,
                             (uint8_t *)mips32_guest_ptr(ctx, new_va) + old_aligned,
                             (size_t)(new_aligned - old_aligned),
                             (off_t)(orig_back.file_off + old_aligned));
        }
        if (prot != 0x3U) {
            int mrc = vm_mprotect_locked(ctx, new_va, (uint32_t)new_aligned,
                                         prot);
            if (mrc != 0) {
                (void)vm_munmap_locked(ctx, new_va, (uint32_t)new_aligned);
                vm_sync_to_ctx(ctx);
                vm_lock_release();
                return (uint32_t)mrc;
            }
        }
        vm_backing_t new_back = { orig_back.fd, orig_back.file_off, orig_back.dev, orig_back.ino, 0U };
        (void)vm_record_region_backed_locked(new_va, (uint32_t)((uint64_t)new_va + new_aligned),
                                             prot, keep_flags, region_name, new_back);
    }
    (void)vm_munmap_locked(ctx, old_addr, (uint32_t)old_aligned);
    vm_sync_to_ctx(ctx);
    vm_lock_release();

    vm_invalidate_all(ctx, old_addr, (uint32_t)((uint64_t)old_addr + old_aligned));
    if (is_fixed || (prot & (uint32_t)PROT_EXEC) != 0U) {
        vm_invalidate_all(ctx, new_va, (uint32_t)((uint64_t)new_va + new_aligned));
    }
    return new_va;
}

int rt32_vm_msync_shared(const mips32_ctx_t *ctx, uint32_t addr, uint32_t len)
{
    if (!ctx || len == 0U) {
        return 0;
    }
    uint64_t end64 = (uint64_t)addr + vm_page_align_up((uint64_t)len);
    if (end64 > (uint64_t)MIPS32_TASK_SIZE_TOP) {
        return -ENOMEM;
    }
    vm_lock_acquire();
    int rc = vm_flush_darw_range_locked(addr, (uint32_t)end64);
    vm_lock_release();
    return rc;
}

int rt32_vm_flush_shared_fd(int fd)
{
#ifdef __APPLE__
    struct stat st;
    int rc;
    if (fd < 0) {
        return -EBADF;
    }
    if (fstat(fd, &st) != 0) {
        return -errno;
    }
    vm_lock_acquire();
    rc = vm_flush_darw_inode_locked((uint64_t)st.st_dev, (uint64_t)st.st_ino);
    vm_lock_release();
    return rc;
#else
    (void)fd;
    return 0;
#endif
}

int rt32_vm_sync_shared_fd(int fd)
{
#ifdef __APPLE__
    struct stat st;
    int rc = 0;
    if (fd < 0) {
        return -EBADF;
    }
    if (fstat(fd, &st) != 0) {
        return -errno;
    }
    vm_lock_acquire();
    if (g_vm_root_ctx != NULL) {
        for (size_t i = 0U; i < g_vm_region_count; i++) {
            const mips32_region_t *r = &g_vm_regions[i];
            const vm_backing_t    *b = &g_vm_backing[i];
            uint8_t *stage = NULL;
            uint8_t *dst;
            size_t   len;
            if (b->darw_sync == 0U || b->fd < 0 ||
                b->dev != (uint64_t)st.st_dev || b->ino != (uint64_t)st.st_ino) {
                continue;
            }
            /* M32-R5-7: stage with EINTR/short-read loop; zero only the
             * verified beyond-EOF tail, never on error. */
            len = (size_t)(r->end - r->start);
            stage = (uint8_t *)malloc(len ? len : 1U);
            if (stage == NULL) {
                rc = -ENOMEM;
                break;
            }
            memset(stage, 0, len);
            {
                size_t off = 0U;
                off_t cur = (off_t)b->file_off;
                while (off < len) {
                    ssize_t got = pread(b->fd, stage + off, len - off, cur);
                    if (got < 0) {
                        if (errno == EINTR) {
                            continue;
                        }
                        rc = -errno;
                        break;
                    }
                    if (got == 0) {
                        break;
                    }
                    off += (size_t)got;
                    cur += (off_t)got;
                }
            }
            if (rc != 0) {
                free(stage);
                break;
            }
            if ((r->prot & (uint32_t)PROT_WRITE) == 0U) {
                vm_host_temp_prot(r->start, r->end, PROT_READ | PROT_WRITE);
            }
            dst = (uint8_t *)mips32_guest_ptr(g_vm_root_ctx, r->start);
            memcpy(dst, stage, len);
            free(stage);
            /* M32-R3-3: union restore, never the single VMA's prot. */
            vm_host_restore_locked(r->start, r->end);
        }
    }
    vm_lock_release();
    return rc;
#else
    (void)fd;
    return 0;
#endif
}

