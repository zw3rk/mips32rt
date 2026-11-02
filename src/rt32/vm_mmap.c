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
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#ifndef MAP_ANONYMOUS
#define MAP_ANONYMOUS MAP_ANON
#endif

/* Provider A hook (src/vm/vm_file.c): declared locally so vm32.h stays
 * untouched.  Mirrors private file bytes into the A2 arena. */
extern int mips32_file_populate_private(mips32_ctx_t *ctx, uint32_t gva,
                                        uint32_t len, int fd,
                                        uint64_t file_off);
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

static void vm_host_temp_prot(uint32_t start, uint32_t end, int prot)
{
    if (g_vm_root_ctx == NULL || start >= end) {
        return;
    }
#ifdef __APPLE__
    uint32_t h_s = start & ~0x3FFFU;
    uint32_t h_e = (end + 0x3FFFU) & ~0x3FFFU;
    (void)mprotect(mips32_guest_ptr(g_vm_root_ctx, h_s), (size_t)(h_e - h_s), prot);
#else
    (void)mprotect(mips32_guest_ptr(g_vm_root_ctx, start), (size_t)(end - start), prot);
#endif
}

static int vm_writeback_darw_locked(size_t idx, uint32_t start, uint32_t end)
{
    struct stat st;
    const mips32_region_t *r = &g_vm_regions[idx];
    vm_backing_t back = g_vm_backing[idx];
    if (back.darw_sync == 0U || back.fd < 0 || g_vm_root_ctx == NULL || start >= end) {
        return 0;
    }
    uint64_t foff = back.file_off + (uint64_t)(start - r->start);
    uint64_t span = (uint64_t)(end - start);
    if ((r->prot & (uint32_t)PROT_READ) == 0U) {
        vm_host_temp_prot(start, end, PROT_READ | PROT_WRITE);
    }
    const uint8_t *base_src = (const uint8_t *)mips32_guest_ptr(g_vm_root_ctx, start);
    for (size_t j = 0U; j < g_vm_region_count; j++) {
        const mips32_region_t *rj = &g_vm_regions[j];
        const vm_backing_t *bj = &g_vm_backing[j];
        if (j == idx || bj->fd < 0 || (rj->flags & 0x01U) == 0U ||
            bj->dev != back.dev || bj->ino != back.ino) {
            continue;
        }
        uint64_t j_foff = bj->file_off;
        uint64_t j_fend = j_foff + (uint64_t)(rj->end - rj->start);
        uint64_t ov_s = (foff > j_foff) ? foff : j_foff;
        uint64_t ov_e = (foff + span < j_fend) ? (foff + span) : j_fend;
        if (ov_s < ov_e) {
            uint32_t d_va = rj->start + (uint32_t)(ov_s - j_foff);
            uint32_t d_end = d_va + (uint32_t)(ov_e - ov_s);
            if ((rj->prot & (uint32_t)PROT_WRITE) == 0U) {
                vm_host_temp_prot(d_va, d_end, PROT_READ | PROT_WRITE);
            }
            memcpy(mips32_guest_ptr(g_vm_root_ctx, d_va),
                   base_src + (size_t)(ov_s - foff), (size_t)(ov_e - ov_s));
            if ((rj->prot & (uint32_t)PROT_WRITE) == 0U) {
                vm_host_temp_prot(d_va, d_end, mips32_host_prot(g_vm_root_ctx, rj->prot));
            }
        }
    }
    int rc = 0;
    if (fstat(back.fd, &st) == 0 && (uint64_t)st.st_size > foff) {
        uint64_t avail = (uint64_t)st.st_size - foff;
        size_t   rem   = (size_t)((span < avail) ? span : avail);
        const uint8_t *src = base_src;
        off_t cur_off = (off_t)foff;
        while (rem > 0U) {
            ssize_t n = pwrite(back.fd, src, rem, cur_off);
            if (n < 0) {
                if (errno == EINTR) {
                    continue;
                }
                rc = -errno;
                break;
            }
            if (n == 0) {
                break;
            }
            src += (size_t)n;
            rem -= (size_t)n;
            cur_off += (off_t)n;
        }
    }
    if ((r->prot & (uint32_t)PROT_READ) == 0U) {
        vm_host_temp_prot(start, end, mips32_host_prot(g_vm_root_ctx, r->prot));
    }
    return rc;
}

int vm_flush_darw_range_locked(uint32_t start, uint32_t end)
{
    int rc = 0;
    for (size_t i = 0U; i < g_vm_region_count; i++) {
        const mips32_region_t *r = &g_vm_regions[i];
        const vm_backing_t    *b = &g_vm_backing[i];
        if (r->end <= start || r->start >= end || b->darw_sync == 0U || b->fd < 0) {
            continue;
        }
        uint32_t s = (r->start > start) ? r->start : start;
        uint32_t e = (r->end < end) ? r->end : end;
        int wrc = vm_writeback_darw_locked(i, s, e);
        if (wrc != 0 && rc == 0) {
            rc = wrc;
        }
    }
    return rc;
}

void vm_flush_darw_inode_locked(uint64_t dev, uint64_t ino)
{
    for (size_t i = 0U; i < g_vm_region_count; i++) {
        const mips32_region_t *r = &g_vm_regions[i];
        const vm_backing_t    *b = &g_vm_backing[i];
        if (b->darw_sync != 0U && b->fd >= 0 && b->dev == dev && b->ino == ino) {
            (void)vm_writeback_darw_locked(i, r->start, r->end);
        }
    }
}

static uint32_t vm_mmap2_ext_locked(mips32_ctx_t *ctx, uint32_t addr, uint32_t len, uint32_t prot,
                                    uint32_t flags, int fd, uint32_t pgoffset, bool dup_backing,
                                    const char *rname)
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
    } else if (fd < 0) {
        return (uint32_t)(-EBADF);
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
            vm_flush_darw_inode_locked(back.dev, back.ino);
        }
    }
    (void)vm_flush_darw_range_locked(target_va, target_end);

    int   host_prot   = mips32_host_prot(ctx, prot);
    void *host_target = mips32_guest_ptr(ctx, target_va);
#ifdef __APPLE__
    uint32_t h_start = target_va & ~0x3FFFU;
    uint32_t h_end   = (target_end + 0x3FFFU) & ~0x3FFFU;
    if ((target_va & 0x3FFFU) == 0U && (aligned_len & 0x3FFFULL) == 0ULL &&
        ((host_flags & MAP_ANONYMOUS) != 0 || (host_off & 0x3FFF) == 0)) {
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
    } else {
        if (mprotect(mips32_guest_ptr(ctx, h_start), (size_t)(h_end - h_start),
                     PROT_READ | PROT_WRITE) != 0) {
            int err = errno;
            if (dup_backing && back.fd >= 0) {
                (void)close(back.fd);
            }
            return (uint32_t)(-err);
        }
        memset(host_target, 0, (size_t)aligned_len);
        if ((host_flags & MAP_ANONYMOUS) == 0 && fd >= 0) {
            int prc = ((flags & 0x01U) == 0U && ctx->vm_regime == MIPS32_VM_REGIME_A2)
                ? mips32_file_populate_private(ctx, target_va, (uint32_t)aligned_len,
                                               fd, (uint64_t)host_off)
                : pread_full(fd, (uint8_t *)host_target, (size_t)aligned_len, host_off);
            if (prc != 0) {
                if (dup_backing && back.fd >= 0) {
                    (void)close(back.fd);
                }
                return (uint32_t)prc;
            }
            if ((flags & 0x01U) != 0U) {
                back.darw_sync = 1U;
            }
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
        return (uint32_t)(-ENOMEM);
    }
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
    uint32_t h_start = addr & ~0x3FFFU;
    uint32_t h_end   = ((uint32_t)end64 + 0x3FFFU) & ~0x3FFFU;
    int      h_prot  = mips32_host_prot(ctx, prot);
    if ((addr & 0x3FFFU) != 0U || (end64 & 0x3FFFULL) != 0ULL) {
        h_prot |= PROT_READ | PROT_WRITE;
    }
    if (mprotect(mips32_guest_ptr(ctx, h_start), (size_t)(h_end - h_start), h_prot) != 0) {
        return -errno;
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
    (void)vm_flush_darw_range_locked(start, end);
    /* Keep the [G, G+4GiB) reservation intact by replacing unmapped pages with PROT_NONE */
    int rc = vm_reserve_prot_none(ctx, start, (uint32_t)aligned_len);
    if (rc != 0) {
        return rc;
    }

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
            size_t copy_bytes = (size_t)((old_aligned < new_aligned) ? old_aligned : new_aligned);
            memcpy(mips32_guest_ptr(ctx, new_va), mips32_guest_ptr(ctx, old_addr), copy_bytes);
            if (prot != map_prot) {
                (void)vm_mprotect_locked(ctx, new_va, (uint32_t)new_aligned, prot);
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
                    (void)mprotect(mips32_guest_ptr(ctx, new_va), (size_t)new_aligned,
                                   mips32_host_prot(ctx, prot));
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
        }
#endif
        if ((prot & 0x1U) == 0U) {
            (void)mprotect(mips32_guest_ptr(ctx, old_addr), (size_t)old_aligned, PROT_READ);
        }
        size_t copy_bytes = (size_t)((old_aligned < new_aligned) ? old_aligned : new_aligned);
        memcpy(mips32_guest_ptr(ctx, new_va), mips32_guest_ptr(ctx, old_addr), copy_bytes);
        if (orig_back.fd >= 0 && new_aligned > old_aligned) {
            (void)pread_full(orig_back.fd,
                             (uint8_t *)mips32_guest_ptr(ctx, new_va) + old_aligned,
                             (size_t)(new_aligned - old_aligned),
                             (off_t)(orig_back.file_off + old_aligned));
        }
        if (prot != 0x3U) {
            (void)vm_mprotect_locked(ctx, new_va, (uint32_t)new_aligned, prot);
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

void rt32_vm_flush_shared_fd(int fd)
{
#ifdef __APPLE__
    struct stat st;
    if (fd < 0 || fstat(fd, &st) != 0) {
        return;
    }
    vm_lock_acquire();
    vm_flush_darw_inode_locked((uint64_t)st.st_dev, (uint64_t)st.st_ino);
    vm_lock_release();
#else
    (void)fd;
#endif
}

void rt32_vm_sync_shared_fd(int fd)
{
#ifdef __APPLE__
    struct stat st;
    if (fd < 0 || fstat(fd, &st) != 0) {
        return;
    }
    vm_lock_acquire();
    if (g_vm_root_ctx != NULL) {
        for (size_t i = 0U; i < g_vm_region_count; i++) {
            const mips32_region_t *r = &g_vm_regions[i];
            const vm_backing_t    *b = &g_vm_backing[i];
            if (b->darw_sync == 0U || b->fd < 0 ||
                b->dev != (uint64_t)st.st_dev || b->ino != (uint64_t)st.st_ino) {
                continue;
            }
            if ((r->prot & (uint32_t)PROT_WRITE) == 0U) {
                vm_host_temp_prot(r->start, r->end, PROT_READ | PROT_WRITE);
            }
            uint8_t *dst = (uint8_t *)mips32_guest_ptr(g_vm_root_ctx, r->start);
            size_t   len = (size_t)(r->end - r->start);
            memset(dst, 0, len);
            (void)pread(b->fd, dst, len, (off_t)b->file_off);
            if ((r->prot & (uint32_t)PROT_WRITE) == 0U) {
                vm_host_temp_prot(r->start, r->end, mips32_host_prot(g_vm_root_ctx, r->prot));
            }
        }
    }
    vm_lock_release();
#else
    (void)fd;
#endif
}

