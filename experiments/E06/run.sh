#!/bin/sh
# E06 run script: cross-compile probe.c for mipsel O32 and run under qemu-mipsel.
# Usage: ./run.sh [mipsel|mips]   (default: mipsel; mips build/run is best-effort)
set -eu
cd "$(dirname "$0")"

ARCH="${1:-mipsel}"
case "$ARCH" in
mipsel) CC=mipsel-linux-gnu-gcc; QEMU=qemu-mipsel ;;
mips)   CC=mips-linux-gnu-gcc;   QEMU=qemu-mips ;;
*) echo "unknown arch: $ARCH" >&2; exit 2 ;;
esac
OBJDUMP="${CC%-gcc}-objdump"

echo "== compiler: $($CC --version | head -1)"
echo "== qemu: $($QEMU --version | head -1)"

$CC -static -O2 -mabi=32 -o "probe_${ARCH}" probe.c -pthread
file "probe_${ARCH}"
$CC -O2 -mabi=32 -c -o "/tmp/e06_probe_${ARCH}.o" probe.c
echo "== rdhwr/ll/sc disassembly (objdump -d):"
$OBJDUMP -d "/tmp/e06_probe_${ARCH}.o" 2>/dev/null | grep -E 'rdhwr|ll |sc ' | head -20 || true
echo "== fixed-encoding word check (expect 7c03e83b for rdhwr \$3,\$29):"
$OBJDUMP -d "/tmp/e06_probe_${ARCH}.o" 2>/dev/null | grep -i '7c03e83b' | head -5 || true

echo "== run under $QEMU:"
timeout --kill-after=30s 60s $QEMU "./probe_${ARCH}"
echo "exit=$?"
