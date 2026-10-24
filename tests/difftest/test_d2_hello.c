/*
 * tests/difftest/test_d2_hello.c — minimal static-libc smoke guest.
 *
 * Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
 * SPDX-License-Identifier: Apache-2.0
 *
 * Prints one deterministic line and exits 0. Exercises the write(2)
 * path through buffered stdio.
 */
#include <stdio.h>

int main(void)
{
    puts("hello mips32rt");
    return 0;
}
