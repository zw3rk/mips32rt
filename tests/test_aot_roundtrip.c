/*
 * tests/test_aot_roundtrip.c — host-native AOT file-cache round-trip check.
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Exercises the persistent AOT block cache (src/dbt/aot/aot.c) through
 * its public API only: writer_open -> add_block x2 -> finish emits a
 * file carrying MIPS32_AOT_MAGIC; lookup hits both blocks by guest PC
 * with matching record fields and misses cleanly (-ENOENT); a
 * magic-corrupted copy is rejected (-EINVAL) and a truncated copy is
 * rejected (-EIO); find_site resolves a fault offset to the covering
 * site record. Prints AOT-ROUNDTRIP: PASS and exits 0 on success.
 *
 * Build & run (host-native):
 *   cc -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror \
 *     -Iinclude -Isrc tests/test_aot_roundtrip.c src/dbt/aot/aot.c \
 *     -o /tmp/test_aot_roundtrip && /tmp/test_aot_roundtrip
 */

#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "dbt/aot/aot.h"
#include "vm/vm32.h"

static int failures = 0;

static void expect(int cond, const char *what)
{
    if (cond == 0) {
        printf("AOT-ROUNDTRIP FAIL: %s\n", what);
        failures++;
    }
}

int main(void)
{
    char dir[64];
    char path[288];
    char bad_path[288];
    char short_path[288];
    mips32_aot_writer_t *w = NULL;
    mips32_aot_block_rec_t rec;
    mips32_mem_site_t sites[2];
    uint32_t index = 0u;
    struct stat st;
    int fd;
    static const uint8_t code_a[16] = {
        1u, 2u, 3u, 4u, 5u, 6u, 7u, 8u,
        9u, 10u, 11u, 12u, 13u, 14u, 15u, 16u
    };
    static const uint8_t code_b[8] = {
        17u, 18u, 19u, 20u, 21u, 22u, 23u, 24u
    };
    uint64_t magic = 0u;

    (void)snprintf(dir, sizeof dir, "/tmp/mips32-aot-%ld", (long)getpid());
    (void)mkdir(dir, 0700);
    expect(mips32_aot_writer_open(dir, 0u, &w) == 0 && w != NULL,
        "writer_open le");
    expect(mips32_aot_writer_add_block(w, 0x1000u, 0x1040u, code_a,
        sizeof code_a, NULL, 0u, 1u) == 0, "add_block pc=0x1000");
    expect(mips32_aot_writer_add_block(w, 0x2000u, 0x2010u, code_b,
        sizeof code_b, NULL, 0u, 1u) == 0, "add_block pc=0x2000");
    expect(mips32_aot_writer_finish(w, path, sizeof path) == 0,
        "writer_finish");
    w = NULL;
    expect(stat(path, &st) == 0 && st.st_size > 0, "cache file non-empty");

    fd = open(path, O_RDONLY);
    expect(fd >= 0, "reopen cache file");
    expect(read(fd, &magic, sizeof magic) == (ssize_t)sizeof magic &&
        magic == MIPS32_AOT_MAGIC, "file magic is M32T AO1");
    (void)close(fd);

    (void)memset(&rec, 0, sizeof rec);
    expect(mips32_aot_lookup(path, 0x1000u, &rec) == 0 &&
        rec.guest_pc == 0x1000u && rec.guest_end == 0x1040u &&
        rec.code_len == sizeof code_a, "lookup hit pc=0x1000");
    (void)memset(&rec, 0, sizeof rec);
    expect(mips32_aot_lookup(path, 0x2000u, &rec) == 0 &&
        rec.guest_pc == 0x2000u && rec.code_len == sizeof code_b,
        "lookup hit pc=0x2000");
    expect(mips32_aot_lookup(path, 0x3000u, &rec) == -ENOENT,
        "lookup miss -> -ENOENT");

    (void)memset(sites, 0, sizeof sites);
    sites[0].seq_start_offset = 0u;
    sites[0].host_insn_offset = 8u;
    sites[1].seq_start_offset = 8u;
    sites[1].host_insn_offset = 16u;
    expect(mips32_aot_find_site(sites, 2u, 5u, &index) == 0 && index == 0u,
        "find_site offset 5 -> site 0");
    expect(mips32_aot_find_site(sites, 2u, 10u, &index) == 0 && index == 1u,
        "find_site offset 10 -> site 1");
    expect(mips32_aot_find_site(sites, 2u, 20u, &index) == -ENOENT,
        "find_site past end -> -ENOENT");
    expect(mips32_aot_find_site(NULL, 2u, 5u, &index) == -EFAULT,
        "find_site NULL -> -EFAULT");

    (void)snprintf(bad_path, sizeof bad_path, "%s-bad.bin", dir);
    (void)snprintf(short_path, sizeof short_path, "%s-short.bin", dir);
    {
        uint8_t buf[512];
        ssize_t n;
        int src = open(path, O_RDONLY);
        int dst;
        expect(src >= 0, "reopen for corrupt copies");
        n = read(src, buf, sizeof buf);
        (void)close(src);
        expect(n > 16, "cache file big enough to corrupt");
        dst = open(bad_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        buf[0] ^= 0xFFu;
        expect(dst >= 0 &&
            write(dst, buf, (size_t)n) == n, "write bad-magic copy");
        if (dst >= 0) {
            (void)close(dst);
        }
        dst = open(short_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        expect(dst >= 0 &&
            write(dst, buf, 8) == 8, "write truncated copy");
        if (dst >= 0) {
            (void)close(dst);
        }
    }
    expect(mips32_aot_lookup(bad_path, 0x1000u, &rec) == -EINVAL,
        "bad magic rejected (-EINVAL)");
    expect(mips32_aot_lookup(short_path, 0x1000u, &rec) == -EIO,
        "truncated file rejected (-EIO)");

    (void)unlink(path);
    (void)unlink(bad_path);
    (void)unlink(short_path);
    (void)snprintf(path, sizeof path, "%s/mips32rt-aot-v1-le.bin", dir);
    (void)unlink(path);
    (void)rmdir(dir);

    if (failures == 0) {
        printf("AOT-ROUNDTRIP: PASS\n");
        return 0;
    }
    printf("AOT-ROUNDTRIP: FAIL (%d)\n", failures);
    return 1;
}
