/*
 * tests/difftest/test_d2_malloc.c — allocator + brk/mmap guest.
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Allocates, fills, checksums, and frees several blocks of different
 * sizes (exercising brk growth and mmap-backed large blocks), then
 * prints only the deterministic checksums — never addresses.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static unsigned checksum(const unsigned char *p, unsigned n)
{
    unsigned sum = 0u;
    unsigned i;

    for (i = 0u; i < n; i++) {
        sum = sum * 31u + p[i];
    }
    return sum;
}

int main(void)
{
    static const unsigned sizes[] = { 1u, 7u, 64u, 1000u, 65536u, 300000u };
    unsigned i;

    for (i = 0u; i < sizeof(sizes) / sizeof(sizes[0]); i++) {
        unsigned char *p;
        unsigned j;
        unsigned n = sizes[i];

        p = malloc(n);
        if (p == NULL) {
            printf("malloc %u: FAILED\n", n);
            return 1;
        }
        for (j = 0u; j < n; j++) {
            p[j] = (unsigned char)((j * 37u + 11u) & 0xffu);
        }
        printf("block %u sum=%u\n", n, checksum(p, n));
        memset(p, 0, n);
        printf("block %u zero=%u\n", n, checksum(p, n));
        free(p);
    }
    printf("realloc: ");
    {
        char *r = malloc(16);
        unsigned k;

        if (r == NULL) {
            printf("FAILED\n");
            return 1;
        }
        for (k = 0u; k < 16u; k++) {
            r[k] = (char)('a' + (int)(k % 26u));
        }
        r = realloc(r, 4096);
        if (r == NULL) {
            printf("FAILED\n");
            return 1;
        }
        printf("sum=%u\n", checksum((unsigned char *)r, 16));
        free(r);
    }
    printf("calloc: ");
    {
        unsigned *z = calloc(128, sizeof(unsigned));
        unsigned k;
        unsigned long long total = 0ull;

        if (z == NULL) {
            printf("FAILED\n");
            return 1;
        }
        for (k = 0u; k < 128u; k++) {
            total += z[k];
        }
        printf("total=%llu\n", total);
        free(z);
    }
    return 0;
}
