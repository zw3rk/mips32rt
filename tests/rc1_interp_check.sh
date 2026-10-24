#!/bin/sh
# RC1 gate: test_p1_isa LE+BE under MIPS32RT_ENGINE=interp must exit 0
# with P1-RESULT: PASS and byte-identical output to the qemu goldens
# except for the documented Phase-1 gaps (no signal delivery, no fork):
#   - "P1 signals: SKIP ..." instead of silent handler install,
#   - beql-pageend x2 + delayslot-sigpc SKIP (need handlers; the not-taken
#     pageend line additionally encodes qemu's translate-time over-fetch,
#     which SPEC 2.2 forbids the translator to replicate),
#   - unaligned-child SKIP (needs fork; arrives Phase 4),
#   - summary "47 pass" instead of "51 pass" (4 checks skipped).
# Any FAIL line, any missing golden PASS line, or any extra PASS line
# fails the gate. Container discipline mirrors tests/run_p1_isa.sh.
set -eu
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
T="$ROOT/tests"
NAME="mips32rt-rc1-$$"
IMG="debian:bookworm-slim"

fail() {
    echo "RC1 FAIL: $1"
    exit 1
}

cleanup() {
    docker rm -f "$NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

echo "=== RC1 rebuild translator ==="
nix shell nixpkgs#pkgsCross.aarch64-multiplatform-musl.stdenv.cc -c \
    make -C "$ROOT" clean build CC=aarch64-unknown-linux-musl-gcc
test -x "$ROOT/_build/mips32rt"

echo "=== RC1 container setup ($IMG) ==="
docker run -d --name "$NAME" --memory 2g --cpus 2 \
    --platform linux/arm64 -v "$ROOT:/w" -w /w "$IMG" sleep 1200
docker exec "$NAME" sh -c \
    'apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq gcc-mipsel-linux-gnu gcc-mips-linux-gnu libc6-dev-mipsel-cross libc6-dev-mips-cross'

docker exec "$NAME" sh -c '
    set -eu
    mipsel-linux-gnu-gcc -march=mips32r2 -static -O1 -o /tmp/p1-le /w/tests/test_p1_isa.c
    mips-linux-gnu-gcc -march=mips32r2 -EB -static -O1 -o /tmp/p1-be /w/tests/test_p1_isa.c
    # NB: the "|| xxx=$?" guards are load-bearing: without them set -eu
    # would abort before the EXIT trailer is recorded on a guest failure.
    timeout --kill-after=30s 120s /w/_build/mips32rt --interp -- /tmp/p1-le > /tmp/rc1-le.txt 2>&1 || le_rc=$?
    echo "LE-EXIT=${le_rc:-0}" >> /tmp/rc1-le.txt
    timeout --kill-after=30s 120s /w/_build/mips32rt --interp -- /tmp/p1-be > /tmp/rc1-be.txt 2>&1 || be_rc=$?
    echo "BE-EXIT=${be_rc:-0}" >> /tmp/rc1-be.txt
    cp /tmp/rc1-le.txt /tmp/rc1-be.txt /w/tests/
'

check_one() {
    tag="$1"
    up="$2"
    out="$T/rc1-$tag.txt"
    golden="$T/p1_golden_$tag.txt"
    test -s "$out" || fail "$tag: no interp output"
    grep -q "^$up-EXIT=0$" "$out" || fail "$tag: bad exit"
    grep -q "^P1-RESULT: PASS$" "$out" || fail "$tag: no P1-RESULT PASS"
    grep -q ": FAIL" "$out" && fail "$tag: FAIL line present"
    grep -q "^P1 checks: 51 pass, 0 fail$" "$out" || fail "$tag: bad summary"
    for skip in "P1 signals: SKIP" \
                "P1 beql-pageend-nottaken: SKIP" \
                "P1 beql-pageend-taken: SKIP" \
                "P1 delayslot-sigpc: SKIP" \
                "P1 unaligned-child: SKIP"; do
        grep -q "^$skip" "$out" || fail "$tag: missing [$skip]"
    done
    # Every golden PASS line except the 4 signal/fork ones must be present.
    grep ": PASS" "$golden" | grep -v -e beql-pageend -e delayslot-sigpc -e unaligned-child > /tmp/want.txt
    n_want=$(wc -l < /tmp/want.txt | tr -d ' ')
    n_have=0
    while IFS= read -r line; do
        grep -qF -- "$line" "$out" || fail "$tag: missing golden line [$line]"
        n_have=$((n_have + 1))
    done < /tmp/want.txt
    # No extra PASS lines beyond golden-minus-4 plus nothing else.
    n_got=$(grep -c ": PASS" "$out" || true)
    [ "$n_got" = "$n_want" ] || fail "$tag: PASS count $n_got != golden $n_want"
    echo "RC1 $tag ok ($n_got shared PASS lines, 5 documented SKIPs)"
    rm -f "$out"
}

check_one "le" "LE"
check_one "be" "BE"
echo "RC1 PASS: interp matches qemu goldens on both endians (documented SKIPs only)"
