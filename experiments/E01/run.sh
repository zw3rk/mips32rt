#!/bin/sh
# E01 build + run driver.
# Runs where a MIPS O32 cross toolchain and qemu-user exist
# (Debian container per lane instructions). BE section is skipped
# gracefully if the mips (BE) toolchain is absent.
set -eu
cd "$(dirname "$0")"

LE_CC=${LE_CC:-mipsel-linux-gnu-gcc}
BE_CC=${BE_CC:-mips-linux-gnu-gcc}
CFLAGS="-march=mips32r2 -static -no-pie -fno-PIC -mno-shared -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror -O1"

echo "== LE build =="
$LE_CC $CFLAGS -o probe-le probe.c
ls -l probe-le
mipsel-linux-gnu-readelf -h probe-le | grep -E 'Class|Machine|Flags'
echo "== LE disasm: every 'syscall' site and its encoding =="
mipsel-linux-gnu-objdump -d probe-le | grep -B2 'syscall' | head -48
echo "count of 0000000c words in disassembly:"
mipsel-linux-gnu-objdump -d probe-le | grep -c '0000000c'
echo "== LE versions =="
$LE_CC -dumpversion
qemu-mipsel --version | head -1
echo "== LE run =="
timeout --kill-after=30s 60s qemu-mipsel ./probe-le

if command -v "$BE_CC" >/dev/null 2>&1 && command -v qemu-mips >/dev/null 2>&1; then
	echo "== BE build =="
	$BE_CC $CFLAGS -o probe-be probe.c
	mips-linux-gnu-readelf -h probe-be | grep -E 'Class|Machine|Flags'
	echo "== BE versions =="
	$BE_CC -dumpversion
	qemu-mips --version | head -1
	echo "== BE run =="
	timeout --kill-after=30s 60s qemu-mips ./probe-be
else
	echo "BE toolchain absent: BE UNVERIFIED"
fi
