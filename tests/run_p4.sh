#!/bin/sh
# run_p4.sh — RC4 gate: test_p4_threads_signals LE+BE under qemu goldens
# and both translator engines.
#
# Builds tests/test_p4_threads_signals.c for mipsel (LE) + mips (BE)
# with the Debian cross toolchains, runs each under qemu-mipsel/qemu-mips
# capturing stdout+exit, then runs each under --interp and --dbt and
# requires stdout+exit identical to the golden (0 divergences: signals,
# threads, fork+execve+wait4 all execute live at RC4).
#
# Container discipline mirrors tests/difftest/run_d2.sh (unique --name,
# --memory 2g --cpus 2, per-command timeouts, docker ps cleanup check).
#
# Acceptance: sh tests/run_p4.sh (exits nonzero on any mismatch).
set -eu
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
T="$ROOT/tests"
NAME="mips32rt-p4-$$"
IMG="debian:bookworm-slim"
ENGINES="interp dbt"

fail() {
    echo "P4 FAIL: $1"
    exit 1
}

cleanup() {
    docker rm -f "$NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

echo "=== P4 rebuild translator (host nix cross CC) ==="
nix shell nixpkgs#pkgsCross.aarch64-multiplatform-musl.stdenv.cc -c \
    make -C "$ROOT" clean build CC=aarch64-unknown-linux-musl-gcc
test -x "$ROOT/_build/mips32rt" || fail "no translator binary"

echo "=== P4 container setup ($IMG) ==="
docker run -d --name "$NAME" --memory 2g --cpus 2 \
    --platform linux/arm64 -v "$ROOT:/w" -w /w "$IMG" sleep 1200

echo "=== P4 build guest + qemu goldens + engine checks ==="
docker exec -e ENGINES="$ENGINES" "$NAME" sh -c '
    set -eu
    apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
        qemu-user gcc-mipsel-linux-gnu gcc-mips-linux-gnu \
        libc6-dev-mipsel-cross libc6-dev-mips-cross
    fails=0
    mipsel-linux-gnu-gcc -march=mips32r2 -static -pthread -O1 -std=c11 -Wall -Wextra \
        -o /tmp/p4-le /w/tests/test_p4_threads_signals.c
    mips-linux-gnu-gcc -march=mips32r2 -EB -static -pthread -O1 -std=c11 -Wall -Wextra \
        -o /tmp/p4-be /w/tests/test_p4_threads_signals.c
    for endian in le be; do
        case $endian in
            le) qemu=qemu-mipsel ;;
            be) qemu=qemu-mips ;;
        esac
        qrc=""
        timeout --kill-after=30s 120s $qemu /tmp/p4-$endian \
            >/tmp/p4-$endian.stdout 2>/tmp/p4-$endian.stderr || qrc=$?
        { cat /tmp/p4-$endian.stdout; echo "P4-EXIT=${qrc:-0}"; } \
            >/w/tests/p4_golden_$endian.txt
        echo "golden $endian: exit=${qrc:-0} bytes=$(wc -c </tmp/p4-$endian.stdout | tr -d " ")"
        grep -q "P4-RESULT: PASS" /tmp/p4-$endian.stdout || {
            echo "P4 GOLDEN FAIL: $endian qemu run did not PASS"
            cat /tmp/p4-$endian.stdout
            fails=$((fails + 1))
            continue
        }
        for eng in $ENGINES; do
            erc=""
            timeout --kill-after=30s 120s /w/_build/mips32rt --$eng -- /tmp/p4-$endian \
                >/tmp/p4-$endian.$eng.stdout 2>/tmp/p4-$endian.$eng.stderr || erc=$?
            { cat /tmp/p4-$endian.$eng.stdout; echo "P4-EXIT=${erc:-0}"; } \
                >/tmp/p4-$endian.$eng.got
            if cmp -s /tmp/p4-$endian.$eng.got /w/tests/p4_golden_$endian.txt; then
                echo "P4 PASS: $endian ($eng matches qemu golden)"
            else
                echo "P4 MISMATCH: $endian ($eng vs qemu golden)"
                diff /w/tests/p4_golden_$endian.txt /tmp/p4-$endian.$eng.got | head -30 || true
                echo "--- $eng stderr (first lines) ---"
                head -10 /tmp/p4-$endian.$eng.stderr || true
                fails=$((fails + 1))
            fi
        done
    done
    echo "=== P4 translator-only fork+execve probe (no qemu golden: qemu-user cannot execve a MIPS binary) ==="
    for endian in le be; do
        for eng in $ENGINES; do
            erc=""
            timeout --kill-after=30s 120s /w/_build/mips32rt --$eng -- /tmp/p4-$endian p4-exec-probe \
                >/tmp/p4-$endian.$eng.probe.stdout 2>/tmp/p4-$endian.$eng.probe.stderr || erc=$?
            { cat /tmp/p4-$endian.$eng.probe.stdout; echo "P4-EXIT=${erc:-0}"; } \
                >/tmp/p4-$endian.$eng.probe.got
            { echo "P4-EXEC-CHILD: ok"; echo "P4-EXEC-PROBE: exited=1 code=42"; echo "P4-RESULT: PASS"; } > /tmp/p4-probe.expect
            {
                grep -v "^P4-EXIT=" /tmp/p4-$endian.$eng.probe.got | grep -v "^$" || true
                echo "P4-EXIT=${erc:-0}"
            } > /tmp/p4-$endian.$eng.probe.norm
            {
                cat /tmp/p4-probe.expect
                echo "P4-EXIT=0"
            } > /tmp/p4-probe-expect-full.txt
            if cmp -s /tmp/p4-$endian.$eng.probe.norm /tmp/p4-probe-expect-full.txt; then
                echo "P4 PASS: $endian exec-probe ($eng fork+execve+wait4)"
            else
                echo "P4 MISMATCH: $endian exec-probe ($eng)"
                diff /tmp/p4-probe-expect-full.txt /tmp/p4-$endian.$eng.probe.norm | head -20 || true
                echo "--- $eng probe stderr (first lines) ---"
                head -10 /tmp/p4-$endian.$eng.probe.stderr || true
                fails=$((fails + 1))
            fi
        done
    done
    echo "=== P4 difftest (interp vs dbt, LE+BE) ==="
    for endian in le be; do
        sh /w/tests/difftest/run_difftest.sh /tmp/p4-$endian interp dbt || fails=$((fails + 1))
    done
    [ "$fails" -eq 0 ] || { echo "P4: $fails failures"; exit 1; }
    echo "P4: guest matches qemu goldens on engines: $ENGINES (LE+BE)"
'

echo "=== P4 container cleanup ==="
docker rm -f "$NAME" >/dev/null 2>&1 || true
docker ps
trap - EXIT INT TERM
echo "P4 PASS: test_p4_threads_signals matches qemu on interp+dbt LE+BE"
