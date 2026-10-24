#!/bin/sh
# E02 runner: cross-compile LE+BE, run under qemu, dump encodings.
set -u
cd "$(dirname "$0")"
LE_CC=${LE_CC:-mipsel-linux-gnu-gcc}
BE_CC=${BE_CC:-mips-linux-gnu-gcc}
echo "== compiler identities =="
$LE_CC --version | head -1
$BE_CC --version | head -1
echo "== qemu identities =="
qemu-mipsel --version | head -1
qemu-mips --version | head -1
echo "== build LE =="
$LE_CC -O2 -static -o probe-le probe.c || exit 1
echo "== build BE =="
$BE_CC -O2 -static -o probe-be probe.c || exit 1
echo "== run LE under qemu-mipsel =="
timeout --kill-after=30s 60s qemu-mipsel ./probe-le
echo "rc-le=$?"
echo "== run BE under qemu-mips =="
timeout --kill-after=30s 60s qemu-mips ./probe-be
echo "rc-be=$?"
echo "== ELF type (ET_EXEC => fixed addresses) =="
mipsel-linux-gnu-readelf -h probe-le | grep -i "type\|machine"
echo "== encodings: disassembly of branch tests (LE) =="
for f in t_beq_taken t_beq_nottaken t_jal_link t_beql_annul t_delayslot_sigpc; do
  mipsel-linux-gnu-objdump -d --disassemble=$f probe-le | grep -v "^$\|file format\|Disassembly of section"
done
echo "== encodings: disassembly of branch tests (BE) =="
for f in t_beq_taken t_beq_nottaken t_jal_link t_beql_annul t_delayslot_sigpc; do
  mips-linux-gnu-objdump -d --disassemble=$f probe-be | grep -v "^$\|file format\|Disassembly of section"
done
