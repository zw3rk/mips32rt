/*
 * tests/difftest/test_d2_printf.c — formatted-output guest.
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Deterministic printf coverage: signed/unsigned decimal, hex, octal,
 * char, string, field width, precision, and 64-bit values. No addresses
 * are printed, so the output is stable across runs and engines.
 */
#include <stdio.h>

int main(void)
{
    printf("dec=%d neg=%d zero=%d\n", 42, -7, 0);
    printf("uns=%u big=%u\n", 42u, 4294967295u);
    printf("hex=%x HEX=%X oct=%o\n", 3735928559u, 3735928559u, 511u);
    printf("chr=%c str=%s empty=[%s]\n", 'Q', "mips32", "");
    printf("width=[%8d] zero=[%08d] left=[%-8d]\n", 123, 123, 123);
    printf("prec=[%.3d] strprec=[%.2s]\n", 5, "abcdef");
    printf("u64=%llu neg64=%lld\n", 18446744073709551615ull, -1ll);
    printf("mix: %s=%d (0x%x)\n", "answer", 42, 42);
    return 0;
}
