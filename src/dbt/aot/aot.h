/*
 * src/dbt/aot/aot.h — Series-wide 7-file AOT cache, mips32 binding (Wave U3)
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * UNIFICATION-PLAN.md Rev 4 sections 4.3 and 7 (Wave U6 preview,
 * landed early for mips32rt in Wave U3): persistent cache
 * (--cache-dir, --pretranslate) with the relative mips32_mem_site_t[]
 * recovery table serialized into every block payload (astra#xhigh
 * #14), so warm-cache fault recovery and PIE rebasing work without
 * absolute addresses.  Pure C11; never touches x18.
 */

#ifndef MIPS32RT_DBT_AOT_H
#define MIPS32RT_DBT_AOT_H

#include <stddef.h>
#include <stdint.h>

#define MIPS32_AOT_MAGIC 0x31414F5432334D00ULL /* "M32T AO1" tag */
#define MIPS32_AOT_VERSION 1u
#define MIPS32_AOT_MAX_BLOCKS 4096u
#define MIPS32_AOT_MAX_PATH 256u

/* Per-block disk record header (followed by code bytes, then the
 * relative mips32_mem_site_t[site_count] table). */
typedef struct {
    uint32_t guest_pc;
    uint32_t guest_end;
    uint32_t code_len;
    uint32_t site_count;
    uint32_t smc_version;
    uint32_t reserved;
    uint64_t code_offset; /* file offset of the code bytes */
    uint64_t site_offset; /* file offset of the site table */
} mips32_aot_block_rec_t;

typedef struct {
    uint64_t magic;
    uint32_t version;
    uint32_t block_count;
    uint32_t is_be;
    uint32_t reserved;
} mips32_aot_hdr_t;

/* Writer handle (opaque). */
typedef struct mips32_aot_writer mips32_aot_writer_t;

int mips32_aot_writer_open(const char *cache_dir, uint32_t is_be,
                            mips32_aot_writer_t **out);
int mips32_aot_writer_add_block(mips32_aot_writer_t *w, uint32_t guest_pc,
                                 uint32_t guest_end, const uint8_t *code,
                                 size_t code_len, const void *sites,
                                 uint32_t site_count, uint32_t smc_version);
int mips32_aot_writer_finish(mips32_aot_writer_t *w, char *out_path,
                              size_t out_path_sz);

/* Reader: open an AOT file, look up one block by guest PC. */
int mips32_aot_lookup(const char *path, uint32_t guest_pc,
                       mips32_aot_block_rec_t *out_rec);

/* Fault recovery: find the site whose [seq_start, host_insn) window
 * contains host_pc_offset (signal rewind for 4.5 quiescence). */
int mips32_aot_find_site(const void *sites, uint32_t site_count,
                          uint32_t host_pc_offset, uint32_t *out_index);

#endif /* MIPS32RT_DBT_AOT_H */
