/*
 * src/rt32/vm_darw.c - Darwin shadow MAP_SHARED writeback and coherency
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Split from src/rt32/vm_mmap.c to honor the 900-line file limit.
 * On hosts with 16 KiB pages a 4 KiB guest MAP_SHARED file mapping
 * cannot be a direct host shared mapping, so the mapper keeps
 * anonymous shadow pages (darw_sync backing) and this file writes
 * them back: merged, dirty-aware writeback plus the inode/range
 * flush entry points.  Every mutation serializes on the D19 CLONE_VM
 * lock (g_vm_lock); restores use the protection union from vm.c.
 */

#define _GNU_SOURCE
#include "vm_priv.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

void vm_host_temp_prot(uint32_t start, uint32_t end, int prot)
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

/* M32-R3-2: merged, dirty-aware Darwin writeback.
 *
 * Shadow aliases of one file range have no dirty-byte tracking, so a
 * whole-range copy from an arbitrary alias cannot tell which data is
 * current: flushing a stale alias first used to overwrite a newer one
 * and then write the stale bytes to the file.  This version compares
 * the source against the file baseline chunk by chunk and only
 * propagates bytes that actually differ from the file: a stale alias
 * contributes nothing, so flush order no longer destroys newer data.
 * Bytes from disjoint writers merge; a true same-byte conflict keeps
 * first-flushed-wins (no tracking exists to do better).  Writes stay
 * clamped to st_size (Linux MAP_SHARED never extends the file), while
 * in-memory alias coherence covers the full shadow range. */
#define VM_DARW_FLUSH_CHUNK 65536U

static uint64_t vm_u64_min(uint64_t a, uint64_t b)
{
    return (a < b) ? a : b;
}

/* File-offset overlap of region j with [foff, foff + span): guest
 * destination range in out_va/out_end, source offset in out_soff.
 * Returns 0 when there is no overlap. */
static int vm_alias_overlap_locked(size_t j, uint64_t foff, uint64_t span,
                                   uint32_t *out_va, uint32_t *out_end,
                                   uint64_t *out_soff)
{
    const mips32_region_t *rj = &g_vm_regions[j];
    const vm_backing_t    *bj = &g_vm_backing[j];
    uint64_t j_foff;
    uint64_t j_fend;
    uint64_t ov_s;
    uint64_t ov_e;

    j_foff = bj->file_off;
    j_fend = j_foff + (uint64_t)(rj->end - rj->start);
    ov_s = (foff > j_foff) ? foff : j_foff;
    ov_e = (foff + span < j_fend) ? (foff + span) : j_fend;
    if (ov_s >= ov_e) {
        return 0;
    }
    *out_va   = rj->start + (uint32_t)(ov_s - j_foff);
    *out_end  = *out_va + (uint32_t)(ov_e - ov_s);
    *out_soff = ov_s - foff;
    return 1;
}

static int vm_alias_of_locked(size_t j, size_t idx, const vm_backing_t *back)
{
    const mips32_region_t *rj = &g_vm_regions[j];
    const vm_backing_t    *bj = &g_vm_backing[j];

    return j != idx && bj->fd >= 0 && (rj->flags & 0x01U) != 0U &&
           bj->dev == back->dev && bj->ino == back->ino;
}

static int vm_writeback_darw_locked(size_t idx, uint32_t start, uint32_t end)
{
    struct stat st;
    const mips32_region_t *r;
    vm_backing_t back;
    uint64_t foff;
    uint64_t span;
    uint64_t file_size;
    const uint8_t *base_src;
    uint8_t *filebuf;
    uint64_t done;
    int rc;
    size_t j;

    if (idx >= g_vm_region_count || g_vm_root_ctx == NULL || start >= end) {
        return 0;
    }
    r = &g_vm_regions[idx];
    back = g_vm_backing[idx];
    if (back.darw_sync == 0U || back.fd < 0) {
        return 0;
    }
    foff = back.file_off + (uint64_t)(start - r->start);
    span = (uint64_t)(end - start);
    file_size = 0U;
    if (fstat(back.fd, &st) == 0 && st.st_size > 0) {
        file_size = (uint64_t)st.st_size;
    }
    /* Elevate every participant once: the source plus all same-file
     * shared aliases overlapping this file range. */
    if ((r->prot & (uint32_t)PROT_WRITE) == 0U) {
        vm_host_temp_prot(start, end, PROT_READ | PROT_WRITE);
    }
    for (j = 0U; j < g_vm_region_count; j++) {
        uint32_t d_va;
        uint32_t d_end;
        uint64_t dummy;

        if (!vm_alias_of_locked(j, idx, &back)) {
            continue;
        }
        if (vm_alias_overlap_locked(j, foff, span, &d_va, &d_end, &dummy) != 0 &&
            (g_vm_regions[j].prot & (uint32_t)PROT_WRITE) == 0U) {
            vm_host_temp_prot(d_va, d_end, PROT_READ | PROT_WRITE);
        }
    }
    filebuf = (uint8_t *)malloc(VM_DARW_FLUSH_CHUNK);
    if (filebuf == NULL) {
        vm_host_restore_locked(start, end);
        for (j = 0U; j < g_vm_region_count; j++) {
            uint32_t d_va;
            uint32_t d_end;
            uint64_t dummy;

            if (vm_alias_of_locked(j, idx, &back) &&
                vm_alias_overlap_locked(j, foff, span, &d_va, &d_end, &dummy) != 0) {
                vm_host_restore_locked(d_va, d_end);
            }
        }
        return -ENOMEM;
    }
    base_src = (const uint8_t *)mips32_guest_ptr(g_vm_root_ctx, start);
    rc = 0;
    done = 0U;
    while (done < span) {
        uint64_t coff = foff + done;
        size_t   n    = (size_t)vm_u64_min(span - done, (uint64_t)VM_DARW_FLUSH_CHUNK);
        size_t   got  = 0U;
        int      wfile = 0;
        size_t   i;

        /* Baseline: current file bytes, zeros past EOF. */
        memset(filebuf, 0, n);
        while (got < n) {
            ssize_t k = pread(back.fd, filebuf + got, n - got, (off_t)(coff + (uint64_t)got));
            if (k < 0) {
                if (errno == EINTR) {
                    continue;
                }
                break;
            }
            if (k == 0) {
                break;
            }
            got += (size_t)k;
        }
        /* Propagate first, against the pristine baseline: every byte
         * where the source differs from the file is dirty and moves
         * to overlapping aliases (stale bytes equal the baseline and
         * contribute nothing).  The merge below must not run first:
         * it overwrites the baseline the comparison needs. */
        for (j = 0U; j < g_vm_region_count; j++) {
            uint32_t d_va;
            uint32_t d_end;
            uint64_t soff;
            uint64_t rel;
            uint8_t *dst;
            size_t k;

            if (!vm_alias_of_locked(j, idx, &back)) {
                continue;
            }
            if (vm_alias_overlap_locked(j, coff, (uint64_t)n, &d_va, &d_end, &rel) == 0) {
                continue;
            }
            soff = rel + (coff - foff);
            dst = (uint8_t *)mips32_guest_ptr(g_vm_root_ctx, d_va);
            for (k = 0U; k < (size_t)(d_end - d_va); k++) {
                uint8_t s = base_src[soff + k];

                if (s != filebuf[rel + k]) {
                    dst[k] = s;
                }
            }
        }
        /* Merge dirty bytes into the baseline (in-file only) for the
         * file write. */
        for (i = 0U; i < n; i++) {
            uint8_t s = base_src[done + i];

            if (s == filebuf[i]) {
                continue;
            }
            if (coff + (uint64_t)i < file_size) {
                filebuf[i] = s;
                wfile = 1;
            }
        }
        if (wfile != 0) {
            uint64_t wend = vm_u64_min(coff + (uint64_t)n, file_size);
            const uint8_t *src = filebuf;
            size_t rem = (size_t)(wend - coff);
            off_t cur_off = (off_t)coff;

            while (rem > 0U) {
                ssize_t k = pwrite(back.fd, src, rem, cur_off);
                if (k < 0) {
                    if (errno == EINTR) {
                        continue;
                    }
                    rc = -errno;
                    break;
                }
                if (k == 0) {
                    break;
                }
                src += (size_t)k;
                rem -= (size_t)k;
                cur_off += (off_t)k;
            }
        }
        done += (uint64_t)n;
    }
    free(filebuf);
    /* M32-R3-3: restore from the protection union, never a single VMA. */
    vm_host_restore_locked(start, end);
    for (j = 0U; j < g_vm_region_count; j++) {
        uint32_t d_va;
        uint32_t d_end;
        uint64_t dummy;

        if (vm_alias_of_locked(j, idx, &back) &&
            vm_alias_overlap_locked(j, foff, span, &d_va, &d_end, &dummy) != 0) {
            vm_host_restore_locked(d_va, d_end);
        }
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
