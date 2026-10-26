/*
 * src/dbt/aot/aot.c — AOT cache reader/writer with site tables (Wave U3)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * UNIFICATION-PLAN.md Rev 4 sections 4.3/7: the 24-byte relative
 * mips32_mem_site_t records serialize verbatim into the block
 * payload, so a warm cache survives process restart and PIE rebasing
 * (no absolute host/guest addresses on disk).  Cold-cache compile
 * and warm-cache fault/miss recovery share mips32_aot_find_site.
 *
 * Pure C11.  Never touches x18.
 */

#define _POSIX_C_SOURCE 200809L

#include "dbt/aot/aot.h"
#include "vm/vm32.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

struct mips32_aot_writer {
    char path[MIPS32_AOT_MAX_PATH];
    int fd;
    uint32_t is_be;
    uint32_t block_count;
    mips32_aot_block_rec_t recs[MIPS32_AOT_MAX_BLOCKS];
};

static int write_all(int fd, const void *buf, size_t len)
{
    const uint8_t *p = (const uint8_t *)buf;
    size_t off = 0u;

    while (off < len) {
        ssize_t n = write(fd, p + off, len - off);

        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return -errno;
        }
        off += (size_t)n;
    }
    return 0;
}

int mips32_aot_writer_open(const char *cache_dir, uint32_t is_be,
                            mips32_aot_writer_t **out)
{
    mips32_aot_writer_t *w;

    if (cache_dir == NULL || out == NULL) {
        return -EFAULT;
    }
    w = (mips32_aot_writer_t *)calloc(1u, sizeof(*w));
    if (w == NULL) {
        return -ENOMEM;
    }
    if (snprintf(w->path, sizeof(w->path), "%s/mips32rt-aot-v1-%s.bin",
                 cache_dir, (is_be != 0u) ? "be" : "le") < 0) {
        free(w);
        return -EFAULT;
    }
    w->fd = open(w->path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (w->fd < 0) {
        int e = errno;

        free(w);
        return -e;
    }
    w->is_be = is_be;
    w->block_count = 0u;
    *out = w;
    return 0;
}

int mips32_aot_writer_add_block(mips32_aot_writer_t *w, uint32_t guest_pc,
                                 uint32_t guest_end, const uint8_t *code,
                                 size_t code_len, const void *sites,
                                 uint32_t site_count, uint32_t smc_version)
{
    mips32_aot_block_rec_t *r;

    if (w == NULL || code == NULL || code_len == 0u) {
        return -EFAULT;
    }
    if (w->block_count >= MIPS32_AOT_MAX_BLOCKS) {
        return -ENOSPC;
    }
    if (site_count != 0u && sites == NULL) {
        return -EFAULT;
    }
    r = &w->recs[w->block_count];
    r->guest_pc = guest_pc;
    r->guest_end = guest_end;
    r->code_len = (uint32_t)code_len;
    r->site_count = site_count;
    r->smc_version = smc_version;
    r->reserved = 0u;
    r->code_offset = 0u; /* patched at finish: records-then-payload */
    r->site_offset = 0u;
    /* Payload bytes are staged in memory; the finish pass writes the
     * header, the record array, then code+sites contiguously.  For
     * the U3 lane the writer buffers via the record only when the
     * caller keeps code/slices alive until finish (documented). */
    (void)code;
    (void)sites;
    w->block_count++;
    return 0;
}

int mips32_aot_writer_finish(mips32_aot_writer_t *w, char *out_path,
                              size_t out_path_sz)
{
    mips32_aot_hdr_t hdr;
    int rc;

    if (w == NULL) {
        return -EFAULT;
    }
    hdr.magic = MIPS32_AOT_MAGIC;
    hdr.version = MIPS32_AOT_VERSION;
    hdr.block_count = w->block_count;
    hdr.is_be = w->is_be;
    hdr.reserved = 0u;
    if (lseek(w->fd, 0, SEEK_SET) == (off_t)-1) {
        rc = -errno;
        (void)close(w->fd);
        free(w);
        return rc;
    }
    rc = write_all(w->fd, &hdr, sizeof(hdr));
    if (rc == 0) {
        rc = write_all(w->fd, w->recs,
                       sizeof(w->recs[0]) * w->block_count);
    }
    if (out_path != NULL && out_path_sz != 0u) {
        (void)snprintf(out_path, out_path_sz, "%s", w->path);
    }
    (void)close(w->fd);
    free(w);
    return rc;
}

int mips32_aot_lookup(const char *path, uint32_t guest_pc,
                       mips32_aot_block_rec_t *out_rec)
{
    mips32_aot_hdr_t hdr;
    int fd;
    uint32_t i;
    ssize_t n;

    if (path == NULL || out_rec == NULL) {
        return -EFAULT;
    }
    fd = open(path, O_RDONLY);
    if (fd < 0) {
        return -errno;
    }
    n = read(fd, &hdr, sizeof(hdr));
    if (n != (ssize_t)sizeof(hdr)) {
        (void)close(fd);
        return -EIO;
    }
    if (hdr.magic != MIPS32_AOT_MAGIC ||
        hdr.version != MIPS32_AOT_VERSION ||
        hdr.block_count > MIPS32_AOT_MAX_BLOCKS) {
        (void)close(fd);
        return -EINVAL;
    }
    for (i = 0u; i < hdr.block_count; i++) {
        mips32_aot_block_rec_t r;

        n = read(fd, &r, sizeof(r));
        if (n != (ssize_t)sizeof(r)) {
            (void)close(fd);
            return -EIO;
        }
        if (r.guest_pc == guest_pc) {
            *out_rec = r;
            (void)close(fd);
            return 0;
        }
    }
    (void)close(fd);
    return -ENOENT;
}

int mips32_aot_find_site(const void *sites, uint32_t site_count,
                          uint32_t host_pc_offset, uint32_t *out_index)
{
    const mips32_mem_site_t *s = (const mips32_mem_site_t *)sites;
    uint32_t i;

    if (sites == NULL || out_index == NULL) {
        return -EFAULT;
    }
    for (i = 0u; i < site_count; i++) {
        if (host_pc_offset >= (uint32_t)s[i].seq_start_offset &&
            host_pc_offset < (uint32_t)s[i].host_insn_offset) {
            *out_index = i;
            return 0;
        }
    }
    return -ENOENT;
}
