/*
 * tests/difftest/test_d2_qsort.c — qsort + string/memory ops guest.
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Sorts a fixed array with qsort, checks the result against the known
 * order, and exercises strcmp/memcpy/memmove. Output is fully
 * deterministic.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int cmp_int(const void *a, const void *b)
{
    int x = *(const int *)a;
    int y = *(const int *)b;

    if (x < y) {
        return -1;
    }
    if (x > y) {
        return 1;
    }
    return 0;
}

static int cmp_str(const void *a, const void *b)
{
    return strcmp(*(const char *const *)a, *(const char *const *)b);
}

int main(void)
{
    int nums[] = { 9, -3, 42, 0, 17, -3, 1001, 8, -2147483647 - 1, 2147483647 };
    static const int want[] = { -2147483647 - 1, -3, -3, 0, 8, 9, 17, 42,
                                1001, 2147483647 };
    const char *words[] = { "delta", "alpha", "charlie", "bravo" };
    static const char *wwant[] = { "alpha", "bravo", "charlie", "delta" };
    unsigned i;
    int ok = 1;

    qsort(nums, sizeof(nums) / sizeof(nums[0]), sizeof(nums[0]), cmp_int);
    for (i = 0u; i < sizeof(nums) / sizeof(nums[0]); i++) {
        printf("int[%u]=%d\n", i, nums[i]);
        if (nums[i] != want[i]) {
            ok = 0;
        }
    }
    qsort((void *)words, 4u, sizeof(words[0]), cmp_str);
    for (i = 0u; i < 4u; i++) {
        printf("str[%u]=%s\n", i, words[i]);
        if (strcmp(words[i], wwant[i]) != 0) {
            ok = 0;
        }
    }
    {
        char buf[32];

        memcpy(buf, "hello world", 12);
        memmove(buf + 6, buf, 5);
        printf("mem=%s cmp=%d len=%u\n", buf, strcmp(buf, "hello hello"),
               (unsigned)strlen(buf));
        if (strcmp(buf, "hello hello") != 0) {
            ok = 0;
        }
    }
    printf("qsort %s\n", ok ? "OK" : "MISMATCH");
    return ok ? 0 : 1;
}
