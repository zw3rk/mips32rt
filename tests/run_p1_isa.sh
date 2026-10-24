#!/bin/sh
# L1d: cross-compile test_p1_isa.c for mipsel (LE) + mips (BE), run each
# under qemu-user, capture stdout+exit code into p1_golden_le/be.txt.
# BE is best-effort: any toolchain gap is recorded honestly in the golden.
set -eu
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
T="$ROOT/tests"
NAME="mips32rt-l1d-$$"
IMG="debian:bookworm-slim"

cleanup() {
    docker rm -f "$NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

echo "=== L1d container setup ($IMG) ==="
docker run -d --name "$NAME" --memory 2g --cpus 2 \
    --platform linux/arm64 -v "$ROOT:/w" -w /w "$IMG" sleep 1200
docker exec "$NAME" sh -c \
    'apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq qemu-user gcc-mipsel-linux-gnu gcc-mips-linux-gnu libc6-dev-mipsel-cross libc6-dev-mips-cross binutils-mipsel-linux-gnu binutils-mips-linux-gnu'

echo "=== build + run LE (mipsel) ==="
docker exec "$NAME" sh -c '
    set -eu
    echo "--- toolchain ---"
    mipsel-linux-gnu-gcc --version | head -1
    qemu-mipsel --version | head -1
    echo "--- build LE ---"
    mipsel-linux-gnu-gcc -march=mips32r2 -static -O1 -std=c11 -Wall -Wextra \
        -o /tmp/p1-le /w/tests/test_p1_isa.c
    mipsel-linux-gnu-readelf -h /tmp/p1-le | grep -E "Class|Machine|Data"
    echo "--- run LE under qemu-mipsel ---"
    timeout --kill-after=30s 60s qemu-mipsel /tmp/p1-le
    echo "LE-EXIT=$?"
    ' > "$T/p1_golden_le.txt" 2>&1 || {
    echo "LE-FAILED rc=$? (see above)" >> "$T/p1_golden_le.txt"
}

echo "=== build + run BE (mips, best-effort) ==="
docker exec "$NAME" sh -c '
    set -eu
    echo "--- toolchain ---"
    mips-linux-gnu-gcc --version | head -1
    qemu-mips --version | head -1
    echo "--- build BE ---"
    mips-linux-gnu-gcc -march=mips32r2 -EB -static -O1 -std=c11 -Wall -Wextra \
        -o /tmp/p1-be /w/tests/test_p1_isa.c
    mips-linux-gnu-readelf -h /tmp/p1-be | grep -E "Class|Machine|Data"
    echo "--- run BE under qemu-mips ---"
    timeout --kill-after=30s 60s qemu-mips /tmp/p1-be
    echo "BE-EXIT=$?"
    ' > "$T/p1_golden_be.txt" 2>&1 || {
    {
        echo "BE-BUILD/RUN FAILED (best-effort; toolchain gap, see above)"
    } >> "$T/p1_golden_be.txt"
}

echo "=== goldens ==="
ls -l "$T/p1_golden_le.txt" "$T/p1_golden_be.txt"
tail -3 "$T/p1_golden_le.txt"
tail -3 "$T/p1_golden_be.txt"
echo "=== container cleanup ==="
docker rm -f "$NAME" >/dev/null 2>&1 || true
docker ps
trap - EXIT INT TERM
