#!/bin/sh
# run_p6.sh — Phase 6 lane-L6b parity gate: full P1/P3/P4/P5 re-run plus the
# adjacent-page permission suite, LE+BE, interp+dbt, vs qemu goldens.
#
# For each static suite (test_p1_isa, test_p3_fpu, test_p4_threads_signals,
# test_p6_perms) the gate builds LE+BE static guests, captures a
# qemu-mipsel/qemu-mips golden (stdout + EXIT line), and requires
# byte-identical stdout+exit under --interp and --dbt plus 0 divergences
# from tests/difftest/run_difftest.sh (interp vs dbt). test_p4 also runs
# the translator-only fork+execve(self)+wait4 probe (qemu-user cannot
# execve a MIPS binary), mirroring tests/run_p4.sh. The dynamic
# test_p5_dyn section (helper .so, P5_MARKER env, --sysroot) mirrors
# tests/run_p5_busybox.sh. A quick BusyBox probe (LE static only; the full
# 4-combo qualification lives in run_p5_busybox.sh) is best-effort: any
# failure there prints P6-BUSYBOX: DEFERRED and never fails the gate.
# L6a's tests/p6_host_check.sh is invoked read-only when present; L6a has
# not landed in this worktree, so the host-check currently reports
# DEFERRED and only the suites owned by this lane gate acceptance.
#
# Container discipline mirrors tests/run_p4.sh (unique --name,
# --memory 2g --cpus 2, per-command timeouts, docker ps cleanup check).
#
# Acceptance: sh tests/run_p6.sh (exits nonzero on any mismatch).
set -eu
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
T="$ROOT/tests"
SRC="$ROOT/_build/p6src"
NAME="mips32rt-l6b-$$"
IMG="debian:bookworm-slim"
ENGINES="interp dbt"

fail() {
    echo "P6 FAIL: $1"
    exit 1
}

cleanup() {
    docker rm -f "$NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

echo "=== P6 rebuild translator (host nix cross CC) ==="
nix shell nixpkgs#pkgsCross.aarch64-multiplatform-musl.stdenv.cc -c \
    make -C "$ROOT" clean build CC=aarch64-unknown-linux-musl-gcc
test -x "$ROOT/_build/mips32rt" || fail "no translator binary"

if [ -f "$T/p6_host_check.sh" ]; then
    echo "=== P6 host-contract check (L6a, read-only invoke) ==="
    sh "$T/p6_host_check.sh" || fail "p6_host_check.sh failed"
else
    echo "P6-HOST-CHECK: DEFERRED (L6a tests/p6_host_check.sh not present)"
fi

echo "=== P6 stage gate script (gitignored _build scratch) ==="
mkdir -p "$SRC"
cat > "$SRC/gate.sh" <<'GATEEOF'
#!/bin/sh
# gate.sh — runs inside the linux/arm64 container (generated scratch).
set -eu
fails=0
ENGINES="interp dbt"

p6fail() {
    echo "P6 FAIL: $1"
    fails=$((fails + 1))
}

echo "=== P6 container setup ==="
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
    qemu-user gcc-mipsel-linux-gnu gcc-mips-linux-gnu \
    libc6-dev-mipsel-cross libc6-dev-mips-cross
test -x /w/_build/mips32rt || { echo "P6 FAIL: no translator binary"; exit 1; }

echo "=== P6 build static guests (LE+BE) ==="
mipsel-linux-gnu-gcc -march=mips32r2 -static -O1 -std=c11 -Wall -Wextra \
    -o /tmp/p1-le /w/tests/test_p1_isa.c
mips-linux-gnu-gcc -march=mips32r2 -EB -static -O1 -std=c11 -Wall -Wextra \
    -o /tmp/p1-be /w/tests/test_p1_isa.c
mipsel-linux-gnu-gcc -march=mips32r2 -static -O1 -std=c11 -Wall -Wextra \
    -o /tmp/p3-le /w/tests/test_p3_fpu.c -lm
mips-linux-gnu-gcc -march=mips32r2 -EB -static -O1 -std=c11 -Wall -Wextra \
    -o /tmp/p3-be /w/tests/test_p3_fpu.c -lm
mipsel-linux-gnu-gcc -march=mips32r2 -static -pthread -O1 -std=c11 -Wall -Wextra \
    -o /tmp/p4-le /w/tests/test_p4_threads_signals.c
mips-linux-gnu-gcc -march=mips32r2 -EB -static -pthread -O1 -std=c11 -Wall -Wextra \
    -o /tmp/p4-be /w/tests/test_p4_threads_signals.c
mipsel-linux-gnu-gcc -march=mips32r2 -static -O1 -std=c11 -Wall -Wextra \
    -o /tmp/p6perms-le /w/tests/test_p6_perms.c
mips-linux-gnu-gcc -march=mips32r2 -EB -static -O1 -std=c11 -Wall -Wextra \
    -o /tmp/p6perms-be /w/tests/test_p6_perms.c

# run_suite TAG PREFIX MARK: qemu golden + interp/dbt compare + difftest
# for one static suite. Golden/got files stay in /tmp (never repo files).
run_suite() {
    tag="$1"
    prefix="$2"
    mark="$3"
    for endian in le be; do
        case $endian in
            le) qemu=qemu-mipsel ;;
            be) qemu=qemu-mips ;;
        esac
        guest="$prefix-$endian"
        qrc=""
        timeout --kill-after=30s 120s $qemu "$guest" \
            >/tmp/$tag-$endian.stdout 2>/tmp/$tag-$endian.stderr || qrc=$?
        { cat /tmp/$tag-$endian.stdout; echo "$tag-EXIT=${qrc:-0}"; } \
            >/tmp/$tag-$endian.golden
        grep -q "$mark" /tmp/$tag-$endian.stdout || {
            p6fail "$tag $endian qemu run did not PASS"
            cat /tmp/$tag-$endian.stdout
            continue
        }
        for eng in $ENGINES; do
            erc=""
            timeout --kill-after=30s 120s /w/_build/mips32rt --$eng -- "$guest" \
                >/tmp/$tag-$endian.$eng.stdout 2>/tmp/$tag-$endian.$eng.stderr || erc=$?
            { cat /tmp/$tag-$endian.$eng.stdout; echo "$tag-EXIT=${erc:-0}"; } \
                >/tmp/$tag-$endian.$eng.got
            if cmp -s /tmp/$tag-$endian.$eng.got /tmp/$tag-$endian.golden; then
                echo "P6 PASS: $tag $endian ($eng matches qemu golden)"
            else
                p6fail "$tag $endian ($eng vs qemu golden)"
                diff /tmp/$tag-$endian.golden /tmp/$tag-$endian.$eng.got | head -30 || true
                echo "--- $eng stderr (first lines) ---"
                head -10 /tmp/$tag-$endian.$eng.stderr || true
            fi
        done
        sh /w/tests/difftest/run_difftest.sh "$guest" interp dbt \
            || p6fail "$tag $endian difftest"
    done
}

echo "=== P6 suite: test_p1_isa ==="
run_suite P1 /tmp/p1 "P1-RESULT: PASS"

echo "=== P6 suite: test_p3_fpu ==="
run_suite P3 /tmp/p3 "P3-RESULT: PASS"

echo "=== P6 suite: test_p4_threads_signals ==="
run_suite P4 /tmp/p4 "P4-RESULT: PASS"

echo "=== P6 translator-only fork+execve probe (no qemu golden) ==="
for endian in le be; do
    for eng in $ENGINES; do
        erc=""
        timeout --kill-after=30s 120s /w/_build/mips32rt --$eng -- /tmp/p4-$endian p4-exec-probe \
            >/tmp/p4-$endian.$eng.probe.stdout 2>/tmp/p4-$endian.$eng.probe.stderr || erc=$?
        { cat /tmp/p4-$endian.$eng.probe.stdout; echo "P4-EXIT=${erc:-0}"; } \
            >/tmp/p4-$endian.$eng.probe.got
        {
            grep -v "^P4-EXIT=" /tmp/p4-$endian.$eng.probe.got | grep -v "^$" || true
            echo "P4-EXIT=${erc:-0}"
        } > /tmp/p4-$endian.$eng.probe.norm
        {
            echo "P4-EXEC-CHILD: ok"
            echo "P4-EXEC-PROBE: exited=1 code=42"
            echo "P4-RESULT: PASS"
            echo "P4-EXIT=0"
        } > /tmp/p4-probe-expect-full.txt
        if cmp -s /tmp/p4-$endian.$eng.probe.norm /tmp/p4-probe-expect-full.txt; then
            echo "P6 PASS: P4 $endian exec-probe ($eng fork+execve+wait4)"
        else
            p6fail "P4 $endian exec-probe ($eng)"
            diff /tmp/p4-probe-expect-full.txt /tmp/p4-$endian.$eng.probe.norm | head -20 || true
        fi
    done
done

echo "=== P6 suite: test_p6_perms (adjacent 4 KiB page permissions) ==="
run_suite P6 /tmp/p6perms "P6-PERMS-RESULT: PASS"

echo "=== P6 suite: test_p5_dyn (dynamic, mirrors run_p5_busybox.sh) ==="
LE_SYS=/usr/mipsel-linux-gnu
BE_SYS=/usr/mips-linux-gnu
mkdir -p /tmp/p5work-le /tmp/p5work-be
mipsel-linux-gnu-gcc -march=mips32r2 -O1 -std=c11 -Wall -Wextra \
    -fPIC -shared -DP5_HELPER \
    -o /tmp/p5helper-le.so /w/tests/test_p5_dyn.c
mipsel-linux-gnu-gcc -march=mips32r2 -O1 -std=c11 -Wall -Wextra \
    -o /tmp/p5dyn-le /w/tests/test_p5_dyn.c -ldl -pthread \
    -Wl,-rpath,/usr/mipsel-linux-gnu/lib
mips-linux-gnu-gcc -march=mips32r2 -EB -O1 -std=c11 -Wall -Wextra \
    -fPIC -shared -DP5_HELPER \
    -o /tmp/p5helper-be.so /w/tests/test_p5_dyn.c
mips-linux-gnu-gcc -march=mips32r2 -EB -O1 -std=c11 -Wall -Wextra \
    -o /tmp/p5dyn-be /w/tests/test_p5_dyn.c -ldl -pthread \
    -Wl,-rpath,/usr/mips-linux-gnu/lib
cd /tmp
for endian in le be; do
    case $endian in
        le) qemu=qemu-mipsel; sysroot=/usr/mipsel-linux-gnu ;;
        be) qemu=qemu-mips; sysroot=/usr/mips-linux-gnu ;;
    esac
    qrc=""
    P5_MARKER=p5-lane-l5b LD_LIBRARY_PATH=$sysroot/lib \
        timeout --kill-after=30s 120s $qemu -L $sysroot \
        /tmp/p5dyn-$endian ./p5helper-$endian.so \
        >/tmp/p5dyn-$endian.stdout 2>/tmp/p5dyn-$endian.stderr || qrc=$?
    { cat /tmp/p5dyn-$endian.stdout; echo "P5-EXIT=${qrc:-0}"; } \
        >/tmp/p5dyn-$endian.golden
    grep -q "P5-RESULT: PASS" /tmp/p5dyn-$endian.stdout || {
        p6fail "P5 $endian qemu run did not PASS"
        cat /tmp/p5dyn-$endian.stderr | head -20
        continue
    }
    for eng in $ENGINES; do
        erc=""
        P5_MARKER=p5-lane-l5b LD_LIBRARY_PATH=$sysroot/lib \
            timeout --kill-after=30s 180s /w/_build/mips32rt --$eng \
            --sysroot $sysroot -- /tmp/p5dyn-$endian ./p5helper-$endian.so \
            >/tmp/p5dyn-$endian.$eng.stdout 2>/tmp/p5dyn-$endian.$eng.stderr || erc=$?
        { cat /tmp/p5dyn-$endian.$eng.stdout; echo "P5-EXIT=${erc:-0}"; } \
            >/tmp/p5dyn-$endian.$eng.got
        if cmp -s /tmp/p5dyn-$endian.$eng.got /tmp/p5dyn-$endian.golden; then
            echo "P6 PASS: P5 $endian ($eng matches qemu golden)"
        else
            p6fail "P5 $endian ($eng vs qemu golden)"
            diff /tmp/p5dyn-$endian.golden /tmp/p5dyn-$endian.$eng.got | head -30 || true
            head -10 /tmp/p5dyn-$endian.$eng.stderr || true
        fi
    done
    ( MIPS32RT_SYSROOT=$sysroot LD_LIBRARY_PATH=$sysroot/lib \
        P5_MARKER=p5-lane-l5b \
        sh /w/tests/difftest/run_difftest.sh /tmp/p5dyn-$endian interp dbt ) \
        || p6fail "P5 $endian difftest"
done

echo "=== P6 BusyBox quick probe (best-effort; DEFERRED on any failure) ==="
BB_VER="1.36.1"
bb_note=""
if apt-get install -y -qq make wget bzip2 bc gcc file ca-certificates \
        >/tmp/bb-apt.log 2>&1; then
    cd /tmp
    if [ ! -f busybox-$BB_VER.tar.bz2 ] && \
        ! wget -q https://busybox.net/downloads/busybox-$BB_VER.tar.bz2; then
        bb_note="BusyBox tarball download failed"
    fi
fi
if [ -z "$bb_note" ] && [ ! -x /tmp/bb-le-static ]; then
    if [ -f /tmp/busybox-$BB_VER.tar.bz2 ]; then
        rm -rf /tmp/bb-src /tmp/bb-obj-le-static
        mkdir /tmp/bb-src
        if tar -xjf /tmp/busybox-$BB_VER.tar.bz2 -C /tmp/bb-src \
                --strip-components=1 2>/tmp/bb-build.log && \
            (make -C /tmp/bb-src O=/tmp/bb-obj-le-static ARCH=mips \
                allnoconfig >>/tmp/bb-build.log 2>&1) && \
            sed -i -e "s/^# CONFIG_ASH is not set$/CONFIG_ASH=y/" \
                -e "s/^# CONFIG_SH_IS_ASH is not set$/CONFIG_SH_IS_ASH=y/" \
                -e "s/^# CONFIG_LS is not set$/CONFIG_LS=y/" \
                -e "s/^# CONFIG_ECHO is not set$/CONFIG_ECHO=y/" \
                -e "s/^# CONFIG_WC is not set$/CONFIG_WC=y/" \
                -e "s/^# CONFIG_STATIC is not set$/CONFIG_STATIC=y/" \
                /tmp/bb-obj-le-static/.config && \
            (yes "" | make -C /tmp/bb-src O=/tmp/bb-obj-le-static ARCH=mips \
                oldconfig >>/tmp/bb-build.log 2>&1) && \
            (timeout --kill-after=30s 600s make -C /tmp/bb-src \
                O=/tmp/bb-obj-le-static ARCH=mips -j2 \
                CROSS_COMPILE="mipsel-linux-gnu-" \
                >>/tmp/bb-build.log 2>&1) && \
            cp /tmp/bb-obj-le-static/busybox /tmp/bb-le-static; then
            echo "P6 BusyBox built: le/static"
        else
            bb_note="BusyBox le/static build failed (see /tmp/bb-build.log)"
        fi
    else
        bb_note="BusyBox sources unavailable"
    fi
fi
if [ -z "$bb_note" ] && [ -x /tmp/bb-le-static ]; then
    qrc=""
    timeout --kill-after=30s 120s qemu-mipsel /tmp/bb-le-static \
        sh -c 'ls / && echo ok | wc -c' \
        >/tmp/bb-le-static.stdout 2>/tmp/bb-le-static.stderr || qrc=$?
    { cat /tmp/bb-le-static.stdout; echo "BB-EXIT=${qrc:-0}"; } \
        >/tmp/bb-le-static.golden
    for eng in $ENGINES; do
        erc=""
        timeout --kill-after=30s 180s /w/_build/mips32rt --$eng -- \
            /tmp/bb-le-static sh -c 'ls / && echo ok | wc -c' \
            >/tmp/bb-le-static.$eng.stdout 2>/tmp/bb-le-static.$eng.stderr || erc=$?
        { cat /tmp/bb-le-static.$eng.stdout; echo "BB-EXIT=${erc:-0}"; } \
            >/tmp/bb-le-static.$eng.got
        if cmp -s /tmp/bb-le-static.$eng.got /tmp/bb-le-static.golden; then
            echo "P6 PASS: BusyBox le/static ($eng matches qemu golden)"
        else
            bb_note="BusyBox le/static $eng mismatch (see /tmp/bb-le-static.$eng.stderr)"
            diff /tmp/bb-le-static.golden /tmp/bb-le-static.$eng.got | head -30 || true
            break
        fi
    done
fi
if [ -n "$bb_note" ]; then
    echo "P6-BUSYBOX: DEFERRED ($bb_note; full 4-combo gate is tests/run_p5_busybox.sh)"
else
    echo "P6-BUSYBOX: PASS (le/static matches qemu on interp+dbt)"
fi

if [ "$fails" -eq 0 ]; then
    echo "P6: all suites match qemu goldens on engines: $ENGINES (LE+BE)"
else
    echo "P6: $fails failures"
    exit 1
fi
GATEEOF

echo "=== P6 container run ($IMG) ==="
docker run -d --name "$NAME" --memory 2g --cpus 2 \
    --platform linux/arm64 -v "$ROOT:/w" -w /w "$IMG" sleep 3600
docker exec "$NAME" sh /w/_build/p6src/gate.sh

echo "=== P6 container cleanup ==="
docker rm -f "$NAME" >/dev/null 2>&1 || true
if docker ps --filter "name=$NAME" --format "{{.Names}}" | grep -q "$NAME"; then
    echo "P6 FAIL: container $NAME still running"
    exit 1
fi
docker ps
trap - EXIT INT TERM
echo "P6 PASS: parity suite matches qemu on interp+dbt LE+BE"
