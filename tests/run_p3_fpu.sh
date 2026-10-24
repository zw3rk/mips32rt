#!/bin/sh
# L3c: cross-compile tests/test_p3_fpu.c for mipsel (LE, default
# Legacy-NaN) + mips (BE), run each under qemu-user, capture stdout +
# exit code into tests/p3_golden_le.txt / tests/p3_golden_be.txt.
# BE is best-effort: any toolchain gap is recorded honestly in the golden.
# A -mnan=2008 LE variant is attempted as INFORMATIONAL only (Debian cross
# sysroot is legacy-NaN-only per experiments/E03/FINDINGS.md §3, so the
# link is expected to fail); its outcome goes to tests/p3_golden_le2008.txt
# and never gates acceptance.
set -eu
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
T="$ROOT/tests"
NAME="mips32rt-l3c-$$"
IMG="debian:bookworm-slim"

cleanup() {
    docker rm -f "$NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

echo "=== L3c container setup ($IMG) ==="
docker run -d --name "$NAME" --memory 2g --cpus 2 \
    --platform linux/arm64 -v "$ROOT:/w" -w /w "$IMG" sleep 1200
docker exec "$NAME" sh -c \
    'apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq qemu-user gcc-mipsel-linux-gnu gcc-mips-linux-gnu libc6-dev-mipsel-cross libc6-dev-mips-cross binutils-mipsel-linux-gnu binutils-mips-linux-gnu'

echo "=== build + run LE (mipsel, default Legacy-NaN) ==="
docker exec "$NAME" sh -c '
    set -eu
    echo "--- toolchain ---"
    mipsel-linux-gnu-gcc --version | head -1
    qemu-mipsel --version | head -1
    echo "--- build LE ---"
    mipsel-linux-gnu-gcc -march=mips32r2 -static -O1 -std=c11 -Wall -Wextra \
        -o /tmp/p3-le /w/tests/test_p3_fpu.c -lm
    mipsel-linux-gnu-readelf -h /tmp/p3-le | grep -E "Class|Machine|Data"
    echo "--- run LE under qemu-mipsel ---"
    timeout --kill-after=30s 60s qemu-mipsel /tmp/p3-le || rc=$?
    echo "LE-EXIT=${rc:-0}"
    ' > "$T/p3_golden_le.txt" 2>&1 || {
    echo "LE-FAILED rc=$? (see above)" >> "$T/p3_golden_le.txt"
}

echo "=== build + run BE (mips, best-effort) ==="
docker exec "$NAME" sh -c '
    set -eu
    echo "--- toolchain ---"
    mips-linux-gnu-gcc --version | head -1
    qemu-mips --version | head -1
    echo "--- build BE ---"
    mips-linux-gnu-gcc -march=mips32r2 -EB -static -O1 -std=c11 -Wall -Wextra \
        -o /tmp/p3-be /w/tests/test_p3_fpu.c -lm
    mips-linux-gnu-readelf -h /tmp/p3-be | grep -E "Class|Machine|Data"
    echo "--- run BE under qemu-mips ---"
    timeout --kill-after=30s 60s qemu-mips /tmp/p3-be || rc=$?
    echo "BE-EXIT=${rc:-0}"
    ' > "$T/p3_golden_be.txt" 2>&1 || {
    {
        echo "BE-BUILD/RUN FAILED (best-effort; toolchain gap, see above)"
    } >> "$T/p3_golden_be.txt"
}

echo "=== LE -mnan=2008 variant (informational, not gated) ==="
docker exec "$NAME" sh -c '
    set -eu
    echo "--- build LE -mnan=2008 (expected to fail: legacy-only sysroot) ---"
    mipsel-linux-gnu-gcc -march=mips32r2 -mnan=2008 -static -O1 -std=c11 \
        -Wall -Wextra -o /tmp/p3-le2008 /w/tests/test_p3_fpu.c -lm
    echo "--- run LE-2008 under qemu-mipsel ---"
    timeout --kill-after=30s 60s qemu-mipsel /tmp/p3-le2008 || rc=$?
    echo "LE2008-EXIT=${rc:-0}"
    ' > "$T/p3_golden_le2008.txt" 2>&1 || {
    {
        echo "LE2008-BUILD/RUN FAILED (informational only; legacy-only sysroot per E03 FINDINGS.md section 3, see above)"
    } >> "$T/p3_golden_le2008.txt"
}

echo "=== goldens ==="
ls -l "$T/p3_golden_le.txt" "$T/p3_golden_be.txt" "$T/p3_golden_le2008.txt"
tail -3 "$T/p3_golden_le.txt"
tail -3 "$T/p3_golden_be.txt"
tail -3 "$T/p3_golden_le2008.txt"
echo "=== container cleanup ==="
docker rm -f "$NAME" >/dev/null 2>&1 || true
docker ps
trap - EXIT INT TERM
