#!/bin/sh
# E05 run script: cross-compile probe.c for mipsel (LE) and mips (BE),
# dump instruction encodings, run both under qemu-user with timeouts.
# Usage: sh run.sh   (expects mips toolchains + qemu-user in PATH)
set -eu
cd "$(dirname "$0")"

echo "=== compiler identities ==="
mipsel-linux-gnu-gcc --version | head -1
mips-linux-gnu-gcc --version | head -1
echo "=== qemu identities ==="
qemu-mipsel --version | head -1
qemu-mips --version | head -1

echo "=== build LE (static: qemu-user has no dynamic loader sysroot) ==="
mipsel-linux-gnu-gcc -march=mips32r2 -O1 -static -Wall -Wextra -o probe-le probe.c
echo "=== build BE (static) ==="
mips-linux-gnu-gcc -march=mips32r2 -EB -O1 -static -Wall -Wextra -o probe-be probe.c
mipsel-linux-gnu-readelf -h probe-le | grep -E 'Class|Machine|Data'; mips-linux-gnu-readelf -h probe-be | grep -E 'Class|Machine|Data'

echo "=== encodings LE: all lwl/lwr/swl/swr sites ==="
mipsel-linux-gnu-objdump -d --show-raw-insn probe-le \
  | grep -E '[[:space:]]+(lwl|lwr|swl|swr)[[:space:]]'
echo "=== encodings BE: all lwl/lwr/swl/swr sites ==="
mips-linux-gnu-objdump -d --show-raw-insn probe-be \
  | grep -E '[[:space:]]+(lwl|lwr|swl|swr)[[:space:]]'
echo "=== encodings LE: plain lw/sw fault-test sites (do_* excluded above) ==="
mipsel-linux-gnu-objdump -d --show-raw-insn probe-le \
  | grep -E '[[:space:]]+(lw|sw)[[:space:]]' | grep -E 'a0,0\(a1\)|v0,0\(' | head -5

echo "=== run LE under qemu-mipsel ==="
timeout --kill-after=30s 60s qemu-mipsel ./probe-le > out-le.txt; echo "LE exit=$?"
cat out-le.txt

echo "=== run BE under qemu-mips ==="
timeout --kill-after=30s 60s qemu-mips ./probe-be > out-be.txt; echo "BE exit=$?"
cat out-be.txt

echo "=== diff LE vs BE (expected: differ) ==="
diff out-le.txt out-be.txt && echo IDENTICAL || echo DIFFER-as-expected
