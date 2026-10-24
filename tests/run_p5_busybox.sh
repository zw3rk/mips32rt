#!/bin/sh
# run_p5_busybox.sh — L5b: dynamic test_p5_dyn + target BusyBox qualification.
#
# Builds tests/test_p5_dyn.c (LE+BE, dynamic) plus its companion helper
# .so (from the same file, -DP5_HELPER), runs each under qemu-mipsel /
# qemu-mips capturing stdout+exit as the golden, then runs each under
# --interp and --dbt and requires stdout+exit byte-identical to golden
# (0 divergences), plus an interp-vs-dbt --difftest check.
#
# Then builds static + dynamic MIPS BusyBox (LE+BE) from source with the
# lane container toolchain and runs `sh -c 'ls / && echo ok | wc -c'`
# under qemu (golden), interp, and dbt; stdout must be byte-identical.
#
# Container discipline mirrors tests/run_p4.sh (unique --name,
# --memory 2g --cpus 2, per-command timeouts, docker ps cleanup check).
#
# Acceptance: sh tests/run_p5_busybox.sh (exits nonzero on any mismatch).
set -eu
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
T="$ROOT/tests"
NAME="mips32rt-l5b-$$"
IMG="debian:bookworm-slim"
ENGINES="interp dbt"
BB_VER="1.36.1"

fail() {
    echo "P5B FAIL: $1"
    exit 1
}

cleanup() {
    docker rm -f "$NAME" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

echo "=== P5B rebuild translator (host nix cross CC) ==="
nix shell nixpkgs#pkgsCross.aarch64-multiplatform-musl.stdenv.cc -c \
    make -C "$ROOT" clean build CC=aarch64-unknown-linux-musl-gcc
test -x "$ROOT/_build/mips32rt" || fail "no translator binary"

echo "=== P5B container setup ($IMG) ==="
docker run -d --name "$NAME" --memory 2g --cpus 2 \
    --platform linux/arm64 -v "$ROOT:/w" -w /w "$IMG" sleep 1500

echo "=== P5B dynamic test + BusyBox checks ==="
docker exec -e ENGINES="$ENGINES" -e BB_VER="$BB_VER" "$NAME" sh -c '
    set -eu
    apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
        qemu-user gcc-mipsel-linux-gnu gcc-mips-linux-gnu \
        libc6-dev-mipsel-cross libc6-dev-mips-cross \
        make wget bzip2 bc file ca-certificates
    fails=0

    echo "--- P5B build dynamic test_p5_dyn + helper .so (LE+BE) ---"
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
    mipsel-linux-gnu-readelf -h /tmp/p5dyn-le | grep -E "Class|Machine|Data|Type"
    mips-linux-gnu-readelf -h /tmp/p5dyn-be | grep -E "Class|Machine|Data|Type"
    mipsel-linux-gnu-readelf -d /tmp/p5dyn-le | grep -E "NEEDED|INTERP"
    ls -l /usr/mipsel-linux-gnu/lib/ld.so.1 /usr/mips-linux-gnu/lib/ld.so.1

    cd /tmp
    for endian in le be; do
        case $endian in
            le) qemu=qemu-mipsel; sysroot=/usr/mipsel-linux-gnu ;;
            be) qemu=qemu-mips; sysroot=/usr/mips-linux-gnu ;;
        esac
        echo "--- P5B dynamic golden ($endian, $qemu -L $sysroot) ---"
        qrc=""
        P5_MARKER=p5-lane-l5b LD_LIBRARY_PATH=$sysroot/lib \
            timeout --kill-after=30s 120s $qemu -L $sysroot \
            /tmp/p5dyn-$endian ./p5helper-$endian.so \
            >/tmp/p5dyn-$endian.stdout 2>/tmp/p5dyn-$endian.stderr || qrc=$?
        { cat /tmp/p5dyn-$endian.stdout; echo "P5-EXIT=${qrc:-0}"; } \
            >/tmp/p5dyn-$endian.golden
        cat /tmp/p5dyn-$endian.golden
        grep -q "P5-RESULT: PASS" /tmp/p5dyn-$endian.stdout || {
            echo "P5B GOLDEN FAIL: $endian qemu run did not PASS"
            cat /tmp/p5dyn-$endian.stderr | head -20
            fails=$((fails + 1))
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
                echo "P5B PASS: dynamic $endian ($eng matches qemu golden)"
            else
                echo "P5B MISMATCH: dynamic $endian ($eng vs qemu golden)"
                diff /tmp/p5dyn-$endian.golden /tmp/p5dyn-$endian.$eng.got | head -30 || true
                echo "--- $eng stderr (first lines) ---"
                head -10 /tmp/p5dyn-$endian.$eng.stderr || true
                fails=$((fails + 1))
            fi
        done
    done

    echo "--- P5B difftest dynamic (interp vs dbt, LE+BE) ---"
    for endian in le be; do
        case $endian in
            le) sysroot=/usr/mipsel-linux-gnu ;;
            be) sysroot=/usr/mips-linux-gnu ;;
        esac
        (cd /tmp && MIPS32RT_SYSROOT=$sysroot LD_LIBRARY_PATH=$sysroot/lib \
            P5_MARKER=p5-lane-l5b \
            sh /w/tests/difftest/run_difftest.sh /tmp/p5dyn-$endian interp dbt) \
            || fails=$((fails + 1))
    done

    echo "--- P5B fetch BusyBox $BB_VER ---"
    cd /tmp
    [ -f busybox-$BB_VER.tar.bz2 ] || \
        wget -q https://busybox.net/downloads/busybox-$BB_VER.tar.bz2
    rm -rf bb-src bb-obj-le-static bb-obj-le-dynamic bb-obj-be-static bb-obj-be-dynamic
    mkdir bb-src && tar -xjf busybox-$BB_VER.tar.bz2 -C bb-src --strip-components=1

    for endian in le be; do
        case $endian in
            le) qemu=qemu-mipsel; sysroot=/usr/mipsel-linux-gnu; cross=mipsel-linux-gnu- ;;
            be) qemu=qemu-mips; sysroot=/usr/mips-linux-gnu; cross=mips-linux-gnu- ;;
        esac
        for flavor in static dynamic; do
            echo "--- P5B build BusyBox $endian/$flavor ---"
            obj=/tmp/bb-obj-$endian-$flavor
            mkdir -p $obj
            (make -C /tmp/bb-src O=$obj ARCH=mips defconfig >/tmp/bb-$endian-$flavor.conf.log 2>&1) || {
                echo "P5B BUSYBOX FAIL: $endian/$flavor defconfig"
                tail -20 /tmp/bb-$endian-$flavor.conf.log
                fails=$((fails + 1))
                continue
            }
            /tmp/bb-src/scripts/config --file $obj/.config \
                --set-str CONFIG_CROSS_COMPILER_PREFIX "$cross" \
                --set-str CONFIG_EXTRA_CFLAGS "-march=mips32r2" \
                $([ "$flavor" = static ] && echo --enable || echo --disable) CONFIG_STATIC \
                >>/tmp/bb-$endian-$flavor.conf.log 2>&1
            (make -C /tmp/bb-src O=$obj ARCH=mips olddefconfig >>/tmp/bb-$endian-$flavor.conf.log 2>&1) || {
                echo "P5B BUSYBOX FAIL: $endian/$flavor olddefconfig"
                tail -20 /tmp/bb-$endian-$flavor.conf.log
                fails=$((fails + 1))
                continue
            }
            (timeout --kill-after=30s 600s make -C /tmp/bb-src O=$obj ARCH=mips -j2 \
                CROSS_COMPILE="$cross" >>/tmp/bb-$endian-$flavor.build.log 2>&1) || {
                echo "P5B BUSYBOX FAIL: $endian/$flavor build"
                tail -20 /tmp/bb-$endian-$flavor.build.log
                fails=$((fails + 1))
                continue
            }
            cp $obj/busybox /tmp/bb-$endian-$flavor
            ${cross}readelf -h /tmp/bb-$endian-$flavor | grep -E "Class|Machine|Data|Type"
            ${cross}readelf -d /tmp/bb-$endian-$flavor 2>/dev/null | grep -E "NEEDED" || echo "(static: no dynamic section)"
        done
    done

    echo "--- P5B BusyBox probe: sh -c '\''ls / && echo ok | wc -c'\'' ---"
    for endian in le be; do
        case $endian in
            le) qemu=qemu-mipsel; sysroot=/usr/mipsel-linux-gnu ;;
            be) qemu=qemu-mips; sysroot=/usr/mips-linux-gnu ;;
        esac
        for flavor in static dynamic; do
            [ -x /tmp/bb-$endian-$flavor ] || {
                echo "P5B SKIP: bb-$endian-$flavor missing (build failed above)"
                continue
            }
            if [ "$flavor" = static ]; then lflag=""; else lflag="-L $sysroot"; fi
            qrc=""
            timeout --kill-after=30s 120s $qemu $lflag /tmp/bb-$endian-$flavor \
                sh -c '"'"'ls / && echo ok | wc -c'"'"' \
                >/tmp/bb-$endian-$flavor.stdout 2>/tmp/bb-$endian-$flavor.stderr || qrc=$?
            { cat /tmp/bb-$endian-$flavor.stdout; echo "BB-EXIT=${qrc:-0}"; } \
                >/tmp/bb-$endian-$flavor.golden
            echo "golden bb-$endian-$flavor: exit=${qrc:-0}"
            cat /tmp/bb-$endian-$flavor.golden
            for eng in $ENGINES; do
                erc=""
                LD_LIBRARY_PATH=$sysroot/lib \
                    timeout --kill-after=30s 180s /w/_build/mips32rt --$eng \
                    --sysroot $sysroot -- /tmp/bb-$endian-$flavor \
                    sh -c '"'"'ls / && echo ok | wc -c'"'"' \
                    >/tmp/bb-$endian-$flavor.$eng.stdout 2>/tmp/bb-$endian-$flavor.$eng.stderr || erc=$?
                { cat /tmp/bb-$endian-$flavor.$eng.stdout; echo "BB-EXIT=${erc:-0}"; } \
                    >/tmp/bb-$endian-$flavor.$eng.got
                if cmp -s /tmp/bb-$endian-$flavor.$eng.got /tmp/bb-$endian-$flavor.golden; then
                    echo "P5B PASS: busybox $endian/$flavor ($eng matches qemu golden)"
                else
                    echo "P5B MISMATCH: busybox $endian/$flavor ($eng vs qemu golden)"
                    diff /tmp/bb-$endian-$flavor.golden /tmp/bb-$endian-$flavor.$eng.got | head -30 || true
                    echo "--- $eng stderr (first lines) ---"
                    head -10 /tmp/bb-$endian-$flavor.$eng.stderr || true
                    fails=$((fails + 1))
                fi
            done
        done
    done
    [ "$fails" -eq 0 ] || { echo "P5B: $fails failures"; exit 1; }
    echo "P5B: dynamic test_p5_dyn + BusyBox static/dynamic match qemu goldens on: $ENGINES (LE+BE)"
'

echo "=== P5B container cleanup ==="
docker rm -f "$NAME" >/dev/null 2>&1 || true
if docker ps --filter "name=$NAME" --format "{{.Names}}" | grep -q "$NAME"; then
    echo "P5B FAIL: container $NAME still running"
    exit 1
fi
docker ps
trap - EXIT INT TERM
echo "P5B: done (exit 0)"
