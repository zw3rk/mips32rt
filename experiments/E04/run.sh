#!/bin/sh
# E04 runner: cross-compile probe.c for mipsel O32 (LE) and mips (BE),
# run each under qemu-user, plus a native-contrast build where possible.
# Usage: ./run.sh [outdir]   (default outdir: ./out)
set -eu
cd "$(dirname "$0")"

OUT="${1:-out}"
mkdir -p "$OUT"

LE_CC="${LE_CC:-mipsel-linux-gnu-gcc}"
BE_CC="${BE_CC:-mips-linux-gnu-gcc}"
NATIVE_CC="${NATIVE_CC:-cc}"

{
echo "=== toolchain ==="
"$LE_CC" --version | head -1
"$BE_CC" --version | head -1
qemu-mipsel --version | head -1
qemu-mips --version | head -1
} | tee "$OUT/versions.txt"

echo "=== LE build ==="
$LE_CC -std=c11 -Wall -Wextra -static -O1 probe.c -o "$OUT/probe-le"
echo "=== LE run (qemu-mipsel) ==="
qemu-mipsel "$OUT/probe-le" | tee "$OUT/output-le.txt"
test "$(grep -c '^RESULT=PASS$' "$OUT/output-le.txt")" = 1

if [ "${SKIP_BE:-0}" != "1" ]; then
echo "=== BE build ==="
$BE_CC -std=c11 -Wall -Wextra -static -O1 probe.c -o "$OUT/probe-be"
echo "=== BE run (qemu-mips) ==="
qemu-mips "$OUT/probe-be" | tee "$OUT/output-be.txt"
test "$(grep -c '^RESULT=PASS$' "$OUT/output-be.txt")" = 1
fi

if command -v "$NATIVE_CC" >/dev/null 2>&1; then
echo "=== native build+run ==="
$NATIVE_CC -std=c11 -Wall -Wextra -O1 probe.c -o "$OUT/probe-native" \
  && ./"$OUT/probe-native" | tee "$OUT/output-native.txt" || true
fi

echo "E04 run.sh: ALL DONE"
