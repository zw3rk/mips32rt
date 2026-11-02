#!/bin/sh
# tests/parity_suite.sh — Wave C2 uniform 10-category guest matrix gate.
#
# Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
# SPDX-License-Identifier: Apache-2.0
#
# Runs the full uniform guest matrix from
# ../../rt-series/docs/lanes/wave-c2-uniform-catalogue.md (§2) for
# mipsel (LE) + mips (BE) with 0 FAIL, 0 GAP, 0 SKIP
# (PARITY_ALLOW_SKIP defaults to 0 and is never raised here):
#
#   p1_isa      integer/branch/unaligned/trap torture (--interp, --dbt, --difftest)
#   p2_libc     static libc hello/printf/malloc/qsort/fileio (--interp, --dbt, --difftest)
#   p3_fp       FP/SIMD torture (--interp, --dbt, --difftest)
#   p3_torture  portable FP/signal/VM/atomics torture, compiled from
#               ../../rt-series/tests/p3_torture.c (--interp, --dbt, --difftest)
#   tcg_smoke   portable ALU/signal/mmap/thread torture, compiled from
#               ../../rt-series/tests/tcg/smoke_tcg.c (--interp, --dbt, --difftest)
#   p4_threads  threads/signals/pipe/fork-wait (--interp, --dbt, --difftest)
#   p5_dyn      dynamic PT_INTERP/ld.so + shared libc via the committed
#               minimal tests/sysroot/ fixture (--interp, --dbt, --difftest)
#   h1_smc      self-modifying code + I-cache invalidation (--interp, --dbt, --difftest)
#   h4_cxx      C++17 exceptions/RTTI/threads (--interp, --dbt, --difftest)
#   bench_smoke bench-mipsel --smoke (ALL_PASS, no FAIL) on interp+dbt
#   aot_reload  real guest ELF cold-emit (-> --cache DIR, magic check) +
#               warm-reload (byte-identical stdout); the sole AOT row.
#
# Sources the frozen cross-repo contract
# ../../rt-series/tools/parity_contract.sh and emits one structured
# PARITY_ROW per executed check, finishing with parity_summary (non-zero
# exit on any FAIL/GAP/SKIP).
#
# Golden comparison is stdout-plus-exit: the committed goldens in tests/
# bundle the Docker toolchain header ("--- toolchain ---" through
# "--- run ... ---"), the qemu stderr line ("qemu: uncaught target
# signal ..."), and an EXIT trailer; golden_split() strips exactly those
# harness lines and the suite additionally requires the translator exit
# code to equal the golden's trailer code.
#
# Backend order for guest legs: a Linux _build/mips32rt runs natively on
# Linux CI, else inside one Debian bookworm container (which also builds
# the guests and runs the qemu-mipsel/qemu-mips oracle, so the whole
# Linux leg is a single audited environment), else GAP. The darwin
# translator runs the bench-smoke rows only: backend_darwin implements
# neither fork nor clone, so signal/thread guests cannot match the
# goldens there by construction.
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT" || exit 1
CONTRACT="$ROOT/../rt-series/tools/parity_contract.sh"
if [ ! -f "$CONTRACT" ]; then
    echo "parity_suite: frozen contract missing: $CONTRACT" >&2
    exit 2
fi
. "$CONTRACT"
parity_init "mips32rt"

OUT="$ROOT/_build/parity"
mkdir -p "$OUT"
HOST="$(uname -s 2>/dev/null || echo unknown)"
BENCH="$ROOT/../rt-series/_build/bench/bench-mipsel"
RT_LINUX="$ROOT/_build/mips32rt"
RT_DARWIN="$ROOT/_build/mips32rt-darwin"
SYSROOT="$ROOT/tests/sysroot"

RT_MODE="none"
if [ -x "$RT_LINUX" ] && "$RT_LINUX" --version >/dev/null 2>&1; then
    RT_MODE="native"
elif command -v docker >/dev/null 2>&1; then
    RT_MODE="docker"
fi

have_docker() { command -v docker >/dev/null 2>&1; }

DOCKER_NAME="mips32rt-c2-$$"
docker_cleanup() { docker rm -f "$DOCKER_NAME" >/dev/null 2>&1 || true; }

# Inner guest root: $ROOT natively, /w inside the container.
GROOT="$ROOT"
ZMOUNT=""
if [ "$RT_MODE" = "docker" ]; then
    GROOT="/w"
    ZMOUNT="-v $ROOT/..:/z"
fi
SYSROOT_INNER="$GROOT/tests/sysroot"

# abi_of <guest>: mipsel for *-le, mips for *-be.
abi_of() {
    case "$1" in
        *-be) echo "mips" ;;
        *) echo "mipsel" ;;
    esac
}

qemu_of() {
    case "$1" in
        *-be) echo "qemu-mips" ;;
        *) echo "qemu-mipsel" ;;
    esac
}

# case_of <guest>: the 10-category case name.
case_of() {
    case "$1" in
        p1-*) echo "p1_isa" ;;
        p2-*) echo "p2_libc" ;;
        p3-*) echo "p3_fp" ;;
        p3t-*) echo "p3_torture" ;;
        tcg-*) echo "tcg_smoke" ;;
        p4-*) echo "p4_threads" ;;
        p5-*) echo "p5_dyn" ;;
        h1-*) echo "h1_smc" ;;
        h4-*) echo "h4_cxx" ;;
        *) echo "unknown" ;;
    esac
}

# golden_of <guest>: committed golden path for the guest.
golden_of() {
    case "$1" in
        p1-le) echo "tests/p1_golden_le.txt" ;;
        p1-be) echo "tests/p1_golden_be.txt" ;;
        p2-hello-le) echo "tests/difftest/golden_le_hello.txt" ;;
        p2-hello-be) echo "tests/difftest/golden_be_hello.txt" ;;
        p2-printf-le) echo "tests/difftest/golden_le_printf.txt" ;;
        p2-printf-be) echo "tests/difftest/golden_be_printf.txt" ;;
        p2-malloc-le) echo "tests/difftest/golden_le_malloc.txt" ;;
        p2-malloc-be) echo "tests/difftest/golden_be_malloc.txt" ;;
        p2-qsort-le) echo "tests/difftest/golden_le_qsort.txt" ;;
        p2-qsort-be) echo "tests/difftest/golden_be_qsort.txt" ;;
        p2-fileio-le) echo "tests/difftest/golden_le_fileio.txt" ;;
        p2-fileio-be) echo "tests/difftest/golden_be_fileio.txt" ;;
        p3-le) echo "tests/p3_golden_le.txt" ;;
        p3-be) echo "tests/p3_golden_be.txt" ;;
        p3t-le) echo "tests/p3t_golden_le.txt" ;;
        p3t-be) echo "tests/p3t_golden_be.txt" ;;
        tcg-le) echo "tests/tcg_golden_le.txt" ;;
        tcg-be) echo "tests/tcg_golden_be.txt" ;;
        p4-le) echo "tests/p4_golden_le.txt" ;;
        p4-be) echo "tests/p4_golden_be.txt" ;;
        p5-le) echo "tests/p5_golden_le.txt" ;;
        p5-be) echo "tests/p5_golden_be.txt" ;;
        h1-le) echo "tests/h1_golden_le.txt" ;;
        h1-be) echo "tests/h1_golden_be.txt" ;;
        h4-le) echo "tests/h4_golden_le.txt" ;;
        h4-be) echo "tests/h4_golden_be.txt" ;;
        *) echo "" ;;
    esac
}

# golden_split <golden> <stdout-out>: write the guest-stdout section of
# the golden (harness header, qemu chatter, and EXIT trailer stripped)
# and echo the trailer exit code on stdout.
golden_split() {
    local _golden="$1" _out="$2" _last _code
    if grep -q '^--- run ' "$_golden"; then
        sed -n '/^--- run /,$p' "$_golden" | tail -n +2 | \
            grep -v '^qemu: uncaught target signal' >"$OUT/.gs.tmp" || true
    else
        grep -v '^qemu: uncaught target signal' "$_golden" \
            >"$OUT/.gs.tmp" || true
    fi
    _last="$(tail -n 1 "$OUT/.gs.tmp")"
    _code="$(printf '%s' "$_last" | sed -n 's/.*-EXIT=\([0-9][0-9]*\)$/\1/p')"
    if [ -n "$_code" ]; then
        sed -e '$d' "$OUT/.gs.tmp" >"$_out"
        printf '%s' "$_code"
    else
        cp "$OUT/.gs.tmp" "$_out"
        printf '0'
    fi
    rm -f "$OUT/.gs.tmp"
}

# golden_row <abi> <host> <case> <engine> <golden> <actual> <exit>
golden_row() {
    local _t0 _abi _host _case _eng _golden _actual _exit _ms
    local _gg _ga _exp
    _t0="$(parity_now_ms)"
    _abi="$1"; _host="$2"; _case="$3"; _eng="$4"
    _golden="$5"; _actual="$6"; _exit="$7"
    _ms=0
    if [ ! -f "$_golden" ]; then
        parity_row "$_abi" "$_host" "$_case" "$_eng" "GAP" "$_ms" \
            "golden missing: $_golden"
        return
    fi
    _gg="$OUT/.golden-guest.tmp"
    _ga="$OUT/.actual-norm.tmp"
    _exp="$(golden_split "$_golden" "$_gg")"
    grep -v '^qemu: uncaught target signal' "$_actual" >"$_ga" || true
    if [ "$_exit" != "$_exp" ]; then
        parity_row "$_abi" "$_host" "$_case" "$_eng" "FAIL" "$_ms" \
            "exit=$_exit golden wants $_exp"
        rm -f "$_gg" "$_ga"
        return
    fi
    if parity_check_golden "$_gg" "$_ga"; then
        _ms=$(( $(parity_now_ms) - _t0 ))
        parity_row "$_abi" "$_host" "$_case" "$_eng" "PASS" "$_ms" \
            "guest stdout identical, exit $_exit"
    else
        parity_row "$_abi" "$_host" "$_case" "$_eng" "FAIL" "$_ms" \
            "guest stdout differs from golden"
    fi
    rm -f "$_gg" "$_ga"
}

# ---- structural + host unit rows --------------------------------------
_t0="$(parity_now_ms)"
if make check-line-limits >/dev/null 2>&1; then
    parity_row "struct" "$HOST" "check-line-limits" "host" "PASS" \
        "$(( $(parity_now_ms) - _t0 ))" "every .c/.h/.S <= 900 lines"
else
    parity_row "struct" "$HOST" "check-line-limits" "host" "FAIL" "0" \
        "see make check-line-limits"
fi

_t0="$(parity_now_ms)"
if make check-abi-invariants >"$OUT/host-abi.log" 2>&1; then
    parity_row "struct" "$HOST" "check-abi-invariants" "host" "PASS" \
        "$(( $(parity_now_ms) - _t0 ))" "ALL OK"
else
    parity_row "struct" "$HOST" "check-abi-invariants" "host" "FAIL" "0" \
        "see $OUT/host-abi.log"
fi

_t0="$(parity_now_ms)"
if cc -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror \
        -Iinclude -Isrc tests/test_decode.c src/interp/decode.c \
        -o "$OUT/test_decode" 2>"$OUT/host-decode.log" \
    && "$OUT/test_decode" >"$OUT/host-decode.out" 2>&1 \
    && grep -q "DECODE: all 45 cases" "$OUT/host-decode.out"; then
    parity_row "struct" "$HOST" "test-decode" "host" "PASS" \
        "$(( $(parity_now_ms) - _t0 ))" "45 cases + 18 classifier checks"
else
    parity_row "struct" "$HOST" "test-decode" "host" "FAIL" "0" \
        "see $OUT/host-decode.log"
fi

if [ ! -x "$RT_DARWIN" ]; then
    echo "note: building missing $RT_DARWIN (make build-darwin)"
    make build-darwin >/dev/null 2>&1 || true
fi

# ---- guest matrix ------------------------------------------------------
# guest_spec <g>: "rel|cflags|cc|libs" (rel is relative to $ROOT/..).
UP="$(cd "$ROOT/.." && pwd)"
GUESTS="p1-le p1-be p2-hello-le p2-hello-be p2-printf-le p2-printf-be p2-malloc-le p2-malloc-be p2-qsort-le p2-qsort-be p2-fileio-le p2-fileio-be p3-le p3-be p3t-le p3t-be tcg-le tcg-be p4-le p4-be p5-le p5-be h1-le h1-be h4-le h4-be"

guest_spec() {
    local _g="$1" _e="" _m=""
    case "$_g" in *-be) _e="-EB" ;; esac
    case "$_g" in
        p1-*)      _m="mips32rt/tests/test_p1_isa.c|-march=mips32r2 $_e -static -O1 -std=c11 -Wall -Wextra|CC|";;
        p2-hello-*) _m="mips32rt/tests/difftest/test_d2_hello.c|-march=mips32r2 $_e -static -O1 -std=c11 -Wall -Wextra|CC|";;
        p2-printf-*) _m="mips32rt/tests/difftest/test_d2_printf.c|-march=mips32r2 $_e -static -O1 -std=c11 -Wall -Wextra|CC|";;
        p2-malloc-*) _m="mips32rt/tests/difftest/test_d2_malloc.c|-march=mips32r2 $_e -static -O1 -std=c11 -Wall -Wextra|CC|";;
        p2-qsort-*) _m="mips32rt/tests/difftest/test_d2_qsort.c|-march=mips32r2 $_e -static -O1 -std=c11 -Wall -Wextra|CC|";;
        p2-fileio-*) _m="mips32rt/tests/difftest/test_d2_fileio.c|-march=mips32r2 $_e -static -O1 -std=c11 -Wall -Wextra|CC|";;
        p3-*)      _m="mips32rt/tests/test_p3_fpu.c|-march=mips32r2 $_e -static -O1 -std=c11 -Wall -Wextra|CC|";;
        p3t-*)     _m="rt-series/tests/p3_torture.c|-march=mips32r2 $_e -static -pthread -O1 -std=c11 -D_GNU_SOURCE -Wall -Wextra|CC|-lm";;
        tcg-*)     _m="rt-series/tests/tcg/smoke_tcg.c|-march=mips32r2 $_e -static -pthread -O1 -std=c11 -D_GNU_SOURCE -Wall -Wextra|CC|";;
        p4-*)      _m="mips32rt/tests/test_p4_threads_signals.c|-march=mips32r2 $_e -static -pthread -O1 -std=c11 -Wall -Wextra|CC|";;
        h1-*)      _m="mips32rt/tests/test_h1_smc.c|-march=mips32r2 $_e -static -O1 -std=c11 -Wall -Wextra|CC|";;
        h4-*)      _m="mips32rt/tests/test_h4_cxx17.cc|-march=mips32r2 $_e -static -pthread -O1 -std=c++17 -Wall -Wextra|CXX|";;
        p5-le)     _m="mips32rt/tests/test_p5_dyn.c|-march=mips32r2 -O1 -std=c11 -Wall -Wextra -Wl,--dynamic-linker=/mipsel/lib/ld.so.1 -Wl,-rpath,/mipsel/lib|CC|-ldl -pthread";;
        p5-be)     _m="mips32rt/tests/test_p5_dyn.c|-march=mips32r2 -EB -O1 -std=c11 -Wall -Wextra -Wl,--dynamic-linker=/mips/lib/ld.so.1 -Wl,-rpath,/mips/lib|CC|-ldl -pthread";;
        *) echo ""; return ;;
    esac
    case "$_g" in
        *-be) _m="$(printf '%s' "$_m" | sed 's/|CC|/|mips-linux-gnu-gcc|/;s/|CXX|/|mips-linux-gnu-g++|/')" ;;
        *)    _m="$(printf '%s' "$_m" | sed 's/|CC|/|mipsel-linux-gnu-gcc|/;s/|CXX|/|mipsel-linux-gnu-g++|/')" ;;
    esac
    printf '%s' "$_m"
}

# p5 helper objects (built alongside p5-le/p5-be, run via guest argv[1]).
p5_helper_of() {
    case "$1" in p5-le) echo "p5helper-le.so" ;; p5-be) echo "p5helper-be.so" ;; *) echo "" ;; esac
}

need_build=""
for _g in $GUESTS; do
    _spec="$(guest_spec "$_g")"
    _rel="${_spec%%|*}"
    _fresh=1
    if [ ! -x "$OUT/$_g" ] || [ "$UP/$_rel" -nt "$OUT/$_g" ]; then
        _fresh=0
    fi
    case "$_g" in
        p5-*)
            _h="$(p5_helper_of "$_g")"
            if [ ! -x "$OUT/$_h" ] || [ "$UP/$_rel" -nt "$OUT/$_h" ]; then
                _fresh=0
            fi
            ;;
    esac
    if [ "$_fresh" -eq 1 ]; then
        parity_row "$(abi_of "$_g")" "$HOST" "$(case_of "$_g")-guest-build" \
            "host" "PASS" "0" "cached, newer than $_rel"
    else
        need_build="$need_build $_g"
    fi
done

build_one_native() { # <guest>: compile with the native cross toolchain.
    local _g="$1" _spec _rel _rest _flags _cc _libs _h
    _spec="$(guest_spec "$_g")"
    _rel="${_spec%%|*}"; _rest="${_spec#*|}"
    _flags="${_rest%%|*}"; _rest="${_rest#*|}"
    _cc="${_rest%%|*}"; _libs="${_rest##*|}"
    # shellcheck disable=SC2086
    if ! $_cc $_flags -o "$OUT/$_g" "$UP/$_rel" $_libs \
            >"$OUT/build-$_g.log" 2>&1; then
        return 1
    fi
    case "$_g" in
        p5-*)
            _h="$(p5_helper_of "$_g")"
            # shellcheck disable=SC2086
            $_cc $_flags -fPIC -shared -DP5_HELPER -o "$OUT/$_h" \
                "$UP/$_rel" >"$OUT/build-$_h.log" 2>&1 || return 1
            ;;
    esac
    return 0
}

if [ -n "$need_build" ]; then
    if command -v mipsel-linux-gnu-gcc >/dev/null 2>&1 && \
            command -v mips-linux-gnu-gcc >/dev/null 2>&1 && \
            command -v mipsel-linux-gnu-g++ >/dev/null 2>&1 && \
            command -v mips-linux-gnu-g++ >/dev/null 2>&1; then
        for _g in $need_build; do
            _t0="$(parity_now_ms)"
            if build_one_native "$_g"; then
                parity_row "$(abi_of "$_g")" "$HOST" "$(case_of "$_g")-guest-build" \
                    "host" "PASS" "$(( $(parity_now_ms) - _t0 ))" "native cross build"
            else
                parity_row "$(abi_of "$_g")" "$HOST" "$(case_of "$_g")-guest-build" \
                    "host" "GAP" "0" "native build failed, see $OUT/build-$_g.log"
            fi
        done
    elif have_docker; then
        {
            echo "set -eu"
            echo "export DEBIAN_FRONTEND=noninteractive"
            echo "apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq qemu-user gcc-mipsel-linux-gnu gcc-mips-linux-gnu g++-mipsel-linux-gnu g++-mips-linux-gnu libc6-dev-mipsel-cross libc6-dev-mips-cross binutils-mipsel-linux-gnu binutils-mips-linux-gnu >/dev/null 2>&1"
            for _g in $need_build; do
                _spec="$(guest_spec "$_g")"
                _rel="${_spec%%|*}"; _rest="${_spec#*|}"
                _flags="${_rest%%|*}"; _rest="${_rest#*|}"
                _cc="${_rest%%|*}"; _libs="${_rest##*|}"
                # shellcheck disable=SC2086
                echo "{ $_cc $_flags -o /w/_build/parity/$_g /z/$_rel $_libs; } || true"
                case "$_g" in
                    p5-*)
                        _h="$(p5_helper_of "$_g")"
                        echo "{ $_cc $_flags -fPIC -shared -DP5_HELPER -o /w/_build/parity/$_h /z/$_rel; } || true"
                        ;;
                esac
            done
            # Live 2008-NaN probe (expected to fail on legacy-NaN-only
            # sysroots; the log feeds the p3-2008nan row below).
            echo "rm -f /w/_build/parity/.docker-2008-fresh"
            echo "mipsel-linux-gnu-gcc -march=mips32r2 -mnan=2008 -static -O1 -std=c11 -o /tmp/p3-le2008 /z/mips32rt/tests/test_p3_fpu.c >/w/_build/parity/le2008-build.log 2>&1 && echo LE2008-UNEXPECTED-OK >>/w/_build/parity/le2008-build.log || true"
            echo "touch /w/_build/parity/.docker-2008-fresh"
        } >"$OUT/.build-inner.sh"
        rm -f "$OUT/.docker-2008-fresh"
        _t0="$(parity_now_ms)"
        trap docker_cleanup EXIT INT TERM
        if timeout --kill-after=30s 500s docker run --rm \
                --name "$DOCKER_NAME" --memory 2g --cpus 2 \
                --platform linux/arm64 -v "$ROOT:/w" $ZMOUNT -w /w \
                debian:bookworm-slim \
                bash /w/_build/parity/.build-inner.sh \
                >"$OUT/docker-build.log" 2>&1; then
            for _g in $need_build; do
                if [ -x "$OUT/$_g" ]; then
                    parity_row "$(abi_of "$_g")" "$HOST" "$(case_of "$_g")-guest-build" \
                        "host" "PASS" "$(( $(parity_now_ms) - _t0 ))" "bookworm container build"
                else
                    parity_row "$(abi_of "$_g")" "$HOST" "$(case_of "$_g")-guest-build" \
                        "host" "GAP" "0" "container build missed $_g"
                fi
            done
        else
            for _g in $need_build; do
                parity_row "$(abi_of "$_g")" "$HOST" "$(case_of "$_g")-guest-build" \
                    "host" "GAP" "0" "container build failed"
            done
        fi
        trap - EXIT INT TERM
        docker_cleanup
    else
        for _g in $need_build; do
            parity_row "$(abi_of "$_g")" "$HOST" "$(case_of "$_g")-guest-build" "host" \
                "GAP" "0" "no mips cross gcc and no docker"
        done
    fi
fi
rm -f "$OUT/.build-inner.sh"

# ---- oracle vs golden ---------------------------------------------------
# qemu-mipsel (LE) / qemu-mips (BE). Native qemu when present, else the
# bookworm container (qemu-user). p5 runs with -L $SYSROOT, P5_MARKER,
# and CWD=$OUT so the relative helper path matches the golden.
export P5_MARKER="p5-lane-l5b"

or_run_native() { # <guest> <outfile>: run under the native qemu oracle.
    local _g="$1" _ofile="$2"
    case "$_g" in
        p5-*)
            (cd "$OUT" && timeout --kill-after=10s 90s "$(qemu_of "$_g")" \
                -L "$SYSROOT" "./$_g" "./$(p5_helper_of "$_g")" \
                >"$_ofile" 2>&1)
            ;;
        *)
            timeout --kill-after=10s 90s "$(qemu_of "$_g")" "$OUT/$_g" \
                >"$_ofile" 2>&1
            ;;
    esac
}

ORACLE_MODE="none"
if command -v qemu-mipsel >/dev/null 2>&1 && \
        command -v qemu-mips >/dev/null 2>&1; then
    ORACLE_MODE="native"
elif have_docker; then
    ORACLE_MODE="docker"
fi

need_oracle=""
for _g in $GUESTS; do
    if [ ! -f "$OUT/oracle-$_g.txt" ] || [ ! -f "$OUT/oracle-$_g.code" ] || \
            [ "$OUT/$_g" -nt "$OUT/oracle-$_g.txt" ]; then
        need_oracle="$need_oracle $_g"
    fi
done

if [ "$ORACLE_MODE" = "docker" ] && [ -n "$need_oracle" ]; then
    {
        echo "set -eu"
        echo "export DEBIAN_FRONTEND=noninteractive"
        echo "export P5_MARKER=p5-lane-l5b"
        echo "apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq qemu-user >/dev/null 2>&1"
        echo "cd /w/_build/parity"
        for _g in $GUESTS; do
            case "$_g" in
                p5-*) echo "{ timeout --kill-after=10s 90s $(qemu_of "$_g") -L /w/tests/sysroot ./$_g ./$(p5_helper_of "$_g") >/w/_build/parity/oracle-$_g.txt 2>&1; echo \"\$?\" >/w/_build/parity/oracle-$_g.code; } || true" ;;
                *) echo "{ timeout --kill-after=10s 90s $(qemu_of "$_g") /w/_build/parity/$_g >/w/_build/parity/oracle-$_g.txt 2>&1; echo \"\$?\" >/w/_build/parity/oracle-$_g.code; } || true" ;;
            esac
        done
    } >"$OUT/.oracle-inner.sh"
    trap docker_cleanup EXIT INT TERM
    if ! timeout --kill-after=30s 500s docker run --rm \
            --name "$DOCKER_NAME" --memory 2g --cpus 2 \
            --platform linux/arm64 -v "$ROOT:/w" -w /w \
            debian:bookworm-slim \
            bash /w/_build/parity/.oracle-inner.sh \
            >"$OUT/docker-oracle.log" 2>&1; then
        echo "note: oracle container failed, see $OUT/docker-oracle.log"
        ORACLE_MODE="none"
    fi
    trap - EXIT INT TERM
    docker_cleanup
    rm -f "$OUT/.oracle-inner.sh"
fi

for _g in $GUESTS; do
    _case="$(case_of "$_g")"
    _golden="$(golden_of "$_g")"
    case "$ORACLE_MODE" in
        native)
            _rc=0
            or_run_native "$_g" "$OUT/oracle-$_g.txt" || _rc=$?
            printf '%s' "$_rc" >"$OUT/oracle-$_g.code"
            ;;
        docker)
            if [ ! -f "$OUT/oracle-$_g.txt" ] || \
                    [ ! -f "$OUT/oracle-$_g.code" ]; then
                parity_row "$(abi_of "$_g")" "$HOST" "$_case" "oracle" \
                    "GAP" "0" "oracle output missing for $_g"
                continue
            fi
            _rc="$(cat "$OUT/oracle-$_g.code")"
            ;;
        *)
            parity_row "$(abi_of "$_g")" "$HOST" "$_case" "oracle" \
                "GAP" "0" "no qemu oracle and no docker"
            continue
            ;;
    esac
    golden_row "$(abi_of "$_g")" "$HOST/$ORACLE_MODE" "$_case" "oracle" \
        "$ROOT/$_golden" "$OUT/oracle-$_g.txt" "$_rc"
done

# ---- translator vs golden -----------------------------------------------
# rt_run <guest> <outfile> <engine-flag...>: run under the Linux
# translator (natively on Linux CI, else in the base bookworm container
# with no extra packages). p5 runs with CWD=$OUT, relative guest and
# helper paths, P5_MARKER, and --sysroot $SYSROOT_INNER.
rt_run() {
    local _guest="$1" _ofile="$2" _rc
    shift 2
    case "$_guest" in
        */p5-*)
            _h="./$(p5_helper_of "$(basename "$_guest")")"
            case "$RT_MODE" in
                native)
                    (cd "$OUT" && timeout --kill-after=10s 120s \
                        "$RT_LINUX" "$@" --sysroot "$SYSROOT" \
                        "./$(basename "$_guest")" "$_h" \
                        >"$_ofile" 2>&1)
                    ;;
                docker)
                    trap docker_cleanup EXIT INT TERM
                    timeout --kill-after=30s 300s docker run --rm \
                        --name "$DOCKER_NAME" --memory 2g --cpus 2 \
                        --platform linux/arm64 -v "$ROOT:/w" \
                        -e P5_MARKER=p5-lane-l5b \
                        -w /w/_build/parity debian:bookworm-slim \
                        /w/_build/mips32rt "$@" --sysroot \
                        "$SYSROOT_INNER" "./$(basename "$_guest")" \
                        "$_h" >"$_ofile" 2>&1
                    _rc=$?
                    trap - EXIT INT TERM
                    docker_cleanup
                    return $_rc
                    ;;
                *) return 127 ;;
            esac
            ;;
        *)
            case "$RT_MODE" in
                native)
                    timeout --kill-after=10s 120s "$RT_LINUX" "$@" -- \
                        "$_guest" >"$_ofile" 2>&1
                    ;;
                docker)
                    _crel="_build/parity/$(basename "$_guest")"
                    trap docker_cleanup EXIT INT TERM
                    timeout --kill-after=30s 300s docker run --rm \
                        --name "$DOCKER_NAME" --memory 2g --cpus 2 \
                        --platform linux/arm64 -v "$ROOT:/w" -w /w \
                        debian:bookworm-slim \
                        /w/_build/mips32rt "$@" -- "/w/$_crel" \
                        >"$_ofile" 2>&1
                    _rc=$?
                    trap - EXIT INT TERM
                    docker_cleanup
                    return $_rc
                    ;;
                *) return 127 ;;
            esac
            ;;
    esac
}

if [ "$RT_MODE" = "none" ]; then
    for _g in $GUESTS; do
        for _eng in interp dbt difftest; do
            parity_row "$(abi_of "$_g")" "$HOST" "$(case_of "$_g")" \
                "$_eng" "GAP" "0" "no translator runner"
        done
    done
else
    if [ "$RT_MODE" = "docker" ]; then
        {
            echo "set -u"
            echo "export P5_MARKER=p5-lane-l5b"
            echo "export RT_SYSROOT=$SYSROOT_INNER"
            for _g in $GUESTS; do
                [ -x "$OUT/$_g" ] || continue
                for _eng in interp dbt; do
                    case "$_g" in
                        p5-*)
                            echo "(cd /w/_build/parity && timeout --kill-after=10s 90s /w/_build/mips32rt --$_eng --sysroot $SYSROOT_INNER ./$_g ./$(p5_helper_of "$_g") >/w/_build/parity/rt-$_eng-$_g.txt 2>&1); echo \"\$?\" >/w/_build/parity/rt-$_eng-$_g.code"
                            ;;
                        *)
                            echo "timeout --kill-after=10s 90s /w/_build/mips32rt --$_eng -- /w/_build/parity/$_g >/w/_build/parity/rt-$_eng-$_g.txt 2>&1; echo \"\$?\" >/w/_build/parity/rt-$_eng-$_g.code"
                            ;;
                    esac
                done
                case "$_g" in
                    p5-*)
                        echo "(cd /w/_build/parity && sh /w/tests/difftest/run_difftest.sh ./$_g interp dbt ./$(p5_helper_of "$_g") >/w/_build/parity/rt-difftest-$_g.txt 2>&1); echo \"\$?\" >/w/_build/parity/rt-difftest-$_g.code"
                        ;;
                    *)
                        echo "sh /w/tests/difftest/run_difftest.sh /w/_build/parity/$_g interp dbt >/w/_build/parity/rt-difftest-$_g.txt 2>&1; echo \"\$?\" >/w/_build/parity/rt-difftest-$_g.code"
                        ;;
                esac
            done
        } >"$OUT/.rt-batch.sh"
        trap docker_cleanup EXIT INT TERM
        timeout --kill-after=30s 500s docker run --rm \
            --name "$DOCKER_NAME" --memory 2g --cpus 2 \
            --platform linux/arm64 -v "$ROOT:/w" -w /w \
            debian:bookworm-slim \
            bash /w/_build/parity/.rt-batch.sh \
            >"$OUT/docker-rt-batch.log" 2>&1 || true
        trap - EXIT INT TERM
        docker_cleanup
        rm -f "$OUT/.rt-batch.sh"
    fi
    for _g in $GUESTS; do
        _case="$(case_of "$_g")"
        _golden="$(golden_of "$_g")"
        if [ ! -x "$OUT/$_g" ]; then
            for _eng in interp dbt difftest; do
                parity_row "$(abi_of "$_g")" "$HOST" "$_case" "$_eng" \
                    "GAP" "0" "guest missing"
            done
            continue
        fi
        for _eng in interp dbt; do
            _rc=0
            if [ "$RT_MODE" = "docker" ]; then
                _rc="$(cat "$OUT/rt-$_eng-$_g.code" 2>/dev/null || echo 127)"
            else
                rt_run "$OUT/$_g" "$OUT/rt-$_eng-$_g.txt" "--$_eng" || _rc=$?
            fi
            golden_row "$(abi_of "$_g")" "$HOST/$RT_MODE" "$_case" \
                "$_eng" "$ROOT/$_golden" "$OUT/rt-$_eng-$_g.txt" "$_rc"
        done
    done

    # ---- difftest (interp vs dbt, 0 divergences) -------------------------
    for _g in $GUESTS; do
        _case="$(case_of "$_g")"
        if [ ! -x "$OUT/$_g" ]; then
            parity_row "$(abi_of "$_g")" "$HOST" "$_case" \
                "difftest" "GAP" "0" "guest missing"
            continue
        fi
        _t0="$(parity_now_ms)"
        _dout="$OUT/rt-difftest-$_g.txt"
        _drc=0
        case "$RT_MODE" in
            native)
                case "$_g" in
                    p5-*)
                        (cd "$OUT" && RT_SYSROOT="$SYSROOT" sh \
                            "$ROOT/tests/difftest/run_difftest.sh" \
                            "./$_g" interp dbt \
                            "./$(p5_helper_of "$_g")" \
                            >"$_dout" 2>&1) || _drc=$?
                        ;;
                    *)
                        if ! sh tests/difftest/run_difftest.sh \
                                "$OUT/$_g" interp dbt \
                                >"$_dout" 2>&1; then
                            _drc=$?
                        fi
                        ;;
                esac
                ;;
            docker)
                _drc="$(cat "$OUT/rt-difftest-$_g.code" 2>/dev/null || echo 127)"
                ;;
        esac
        if [ "$_drc" -eq 0 ] && grep -q "0 divergences" "$_dout"; then
            parity_row "$(abi_of "$_g")" "$HOST/$RT_MODE" "$_case" \
                "difftest" "PASS" "$(( $(parity_now_ms) - _t0 ))" \
                "$(grep -m1 -o '0 divergences[^)]*)' "$_dout" || echo '0 divergences')"
        else
            parity_row "$(abi_of "$_g")" "$HOST/$RT_MODE" "$_case" \
                "difftest" "FAIL" "0" "exit=$_drc, see $_dout"
        fi
    done
fi

# ---- p3 2008-NaN documented toolchain gap --------------------------------
# The committed p3_golden_le2008.txt records that Debian cross sysroots
# are legacy-NaN-only (-mnan=2008 fails on gnu/stubs-o32_hard_2008.h).
# The static row pins the committed record; the live row reproduces
# that failure (native mipsel gcc or the bookworm build container).
# Any other outcome fails the gate.
_t0="$(parity_now_ms)"
if grep -q "LE2008-BUILD/RUN FAILED" tests/p3_golden_le2008.txt 2>/dev/null \
    && grep -q "stubs-o32_hard_2008" tests/p3_golden_le2008.txt \
        2>/dev/null; then
    parity_row "mipsel" "$HOST" "p3-2008nan-golden" "host" "PASS" \
        "$(( $(parity_now_ms) - _t0 ))" "committed gap record intact"
else
    parity_row "mipsel" "$HOST" "p3-2008nan-golden" "host" "FAIL" "0" \
        "p3_golden_le2008.txt record changed"
fi

if command -v mipsel-linux-gnu-gcc >/dev/null 2>&1; then
    _t0="$(parity_now_ms)"
    if mipsel-linux-gnu-gcc -march=mips32r2 -mnan=2008 -static -O1 \
            -std=c11 -o "$OUT/p3-le2008" tests/test_p3_fpu.c \
            >"$OUT/le2008-build.log" 2>&1; then
        parity_row "mipsel" "$HOST" "p3-2008nan" "host" "FAIL" "0" \
            "2008 build unexpectedly succeeded (sysroot changed?)"
    elif grep -q "stubs-o32_hard_2008" "$OUT/le2008-build.log"; then
        parity_row "mipsel" "$HOST" "p3-2008nan" "host" "PASS" \
            "$(( $(parity_now_ms) - _t0 ))" "documented gap reproduced"
    else
        parity_row "mipsel" "$HOST" "p3-2008nan" "host" "FAIL" "0" \
            "build failed differently, see $OUT/le2008-build.log"
    fi
elif [ -x "$OUT/p3-le2008" ]; then
    parity_row "mipsel" "$HOST" "p3-2008nan" "host" "FAIL" "0" \
        "2008 build unexpectedly succeeded (sysroot changed?)"
elif [ -f "$OUT/.docker-2008-fresh" ] && \
        grep -q "stubs-o32_hard_2008" "$OUT/le2008-build.log" 2>/dev/null; then
    parity_row "mipsel" "$HOST" "p3-2008nan" "host" "PASS" "0" \
        "documented gap (this-run container log)"
else
    echo "note: p3-2008nan skipped (no fresh 2008 build evidence this run)"
fi
rm -f "$OUT/.docker-2008-fresh"

# ---- bench smoke (linux + darwin legs) -----------------------------------
# bench-mipsel --smoke must exit 0 with ALL_PASS and no FAIL line on
# both engines. Output carries timings, so the check is the CRC verdict,
# not a golden byte-compare.
bench_check() { # <outfile>: 0 when ALL_PASS, no FAIL, exit was 0.
    grep -q "ALL_PASS" "$1" 2>/dev/null && ! grep -q "FAIL" "$1" 2>/dev/null
}

if [ -x "$RT_LINUX" ] && [ "$RT_MODE" = "native" ] && [ -x "$BENCH" ]; then
    for _eng in interp dbt; do
        _t0="$(parity_now_ms)"
        _rc=0
        timeout --kill-after=10s 60s "$RT_LINUX" "--$_eng" -- "$BENCH" \
            --smoke >"$OUT/bench-linux-$_eng.txt" 2>&1 || _rc=$?
        if [ "$_rc" -eq 0 ] && bench_check "$OUT/bench-linux-$_eng.txt"; then
            parity_row "mipsel" "$HOST/native" "bench_smoke" "$_eng" \
                "PASS" "$(( $(parity_now_ms) - _t0 ))" "ALL_PASS, no FAIL"
        else
            parity_row "mipsel" "$HOST/native" "bench_smoke" "$_eng" \
                "FAIL" "0" "exit=$_rc, see $OUT/bench-linux-$_eng.txt"
        fi
    done
elif [ -x "$BENCH" ] && have_docker; then
    trap docker_cleanup EXIT INT TERM
    for _eng in interp dbt; do
        _t0="$(parity_now_ms)"
        _rc=0
        timeout --kill-after=30s 300s docker run --rm \
            --name "$DOCKER_NAME" --memory 2g --cpus 2 \
            --platform linux/arm64 -v "$ROOT:/w" \
            -v "$UP:/z" -w /w debian:bookworm-slim \
            /w/_build/mips32rt "--$_eng" -- \
            /z/rt-series/_build/bench/bench-mipsel --smoke \
            >"$OUT/bench-docker-$_eng.txt" 2>&1 || _rc=$?
        if [ "$_rc" -eq 0 ] && bench_check "$OUT/bench-docker-$_eng.txt"; then
            parity_row "mipsel" "$HOST/docker" "bench_smoke" "$_eng" \
                "PASS" "$(( $(parity_now_ms) - _t0 ))" "ALL_PASS, no FAIL"
        else
            parity_row "mipsel" "$HOST/docker" "bench_smoke" "$_eng" \
                "FAIL" "0" "exit=$_rc, see $OUT/bench-docker-$_eng.txt"
        fi
    done
    trap - EXIT INT TERM
    docker_cleanup
else
    for _eng in interp dbt; do
        parity_row "mipsel" "$HOST" "bench_smoke" "$_eng" "GAP" "0" \
            "no bench binary or no linux runner"
    done
fi

if [ -x "$RT_DARWIN" ] && [ -x "$BENCH" ]; then
    for _eng in interp dbt; do
        _t0="$(parity_now_ms)"
        _rc=0
        timeout --kill-after=10s 60s "$RT_DARWIN" "--$_eng" -- "$BENCH" \
            --smoke >"$OUT/bench-darwin-$_eng.txt" 2>&1 || _rc=$?
        if [ "$_rc" -eq 0 ] && bench_check "$OUT/bench-darwin-$_eng.txt"; then
            parity_row "mipsel" "$HOST/darwin" "bench_smoke" "$_eng" \
                "PASS" "$(( $(parity_now_ms) - _t0 ))" "ALL_PASS, no FAIL"
        else
            parity_row "mipsel" "$HOST/darwin" "bench_smoke" "$_eng" \
                "FAIL" "0" "exit=$_rc, see $OUT/bench-darwin-$_eng.txt"
        fi
    done
else
    for _eng in interp dbt; do
        parity_row "mipsel" "$HOST" "bench_smoke" "$_eng" "GAP" "0" \
            "no darwin translator or no bench binary"
    done
fi

# ---- aot_reload (real guest cold-emit -> warm-reload) ---------------------
# The sole AOT row: a cold --dbt --cache run over the cleanly-exiting
# p3 guest emits <dir>/mips32rt-aot-v1-{le,be}.bin (magic MIPS32_AOT_MAGIC
# verified by od); a warm run with the same cache must produce
# byte-identical guest stdout. Execution stays JIT-correct by
# construction, so output identity is the reload contract.
aot_reload_one() { # <guest>: cold emit + warm reload, PASS/GAP/FAIL rows.
    local _g="$1" _le _cache _cold _warm _m _rc
    case "$_g" in *-be) _le="be" ;; *) _le="le" ;; esac
    _cache="$OUT/aot-cache-$_le"
    rm -rf "$_cache"
    mkdir -p "$_cache"
    _cold="$OUT/aot-cold-$_g.txt"
    _warm="$OUT/aot-warm-$_g.txt"
    case "$RT_MODE" in
        native)
            _rc=0
            timeout --kill-after=10s 120s "$RT_LINUX" --dbt --cache \
                "$_cache" -- "$OUT/$_g" >"$_cold" 2>&1 || _rc=$?
            ;;
        docker)
            trap docker_cleanup EXIT INT TERM
            _rc=0
            timeout --kill-after=30s 300s docker run --rm \
                --name "$DOCKER_NAME" --memory 2g --cpus 2 \
                --platform linux/arm64 -v "$ROOT:/w" -w /w \
                debian:bookworm-slim \
                /w/_build/mips32rt --dbt --cache \
                "/w/_build/parity/aot-cache-$_le" -- \
                "/w/_build/parity/$_g" >"$_cold" 2>&1 || _rc=$?
            trap - EXIT INT TERM
            docker_cleanup
            ;;
        *)
            parity_row "$(abi_of "$_g")" "$HOST" "aot_reload" "dbt" \
                "GAP" "0" "no translator runner"
            parity_row "$(abi_of "$_g")" "$HOST" "aot_reload" "dbt" \
                "GAP" "0" "no translator runner"
            return
            ;;
    esac
    _m=""
    if [ -f "$_cache/mips32rt-aot-v1-$_le.bin" ]; then
        _m="$(od -A n -t x1 -N 8 "$_cache/mips32rt-aot-v1-$_le.bin" \
            2>/dev/null | tr -d ' \t\n')"
    fi
    _t0="$(parity_now_ms)"
    if [ "$_rc" -eq 0 ] && [ "$_m" = "004d3332544f4131" ]; then
        parity_row "$(abi_of "$_g")" "$HOST/$RT_MODE" "aot_reload" \
            "dbt" "PASS" "$(( $(parity_now_ms) - _t0 ))" \
            "cold emit magic ok exit=$_rc"
    else
        parity_row "$(abi_of "$_g")" "$HOST/$RT_MODE" "aot_reload" \
            "dbt" "FAIL" "0" \
            "cold emit rc=$_rc magic=${_m:-missing} (want 004d3332544f4131)"
        parity_row "$(abi_of "$_g")" "$HOST/$RT_MODE" "aot_reload" \
            "dbt" "GAP" "0" "emit failed"
        return
    fi
    case "$RT_MODE" in
        native)
            _rc=0
            timeout --kill-after=10s 120s "$RT_LINUX" --dbt --cache \
                "$_cache" -- "$OUT/$_g" >"$_warm" 2>&1 || _rc=$?
            ;;
        docker)
            trap docker_cleanup EXIT INT TERM
            _rc=0
            timeout --kill-after=30s 300s docker run --rm \
                --name "$DOCKER_NAME" --memory 2g --cpus 2 \
                --platform linux/arm64 -v "$ROOT:/w" -w /w \
                debian:bookworm-slim \
                /w/_build/mips32rt --dbt --cache \
                "/w/_build/parity/aot-cache-$_le" -- \
                "/w/_build/parity/$_g" >"$_warm" 2>&1 || _rc=$?
            trap - EXIT INT TERM
            docker_cleanup
            ;;
    esac
    _t0="$(parity_now_ms)"
    if [ "$_rc" -eq 0 ] && cmp -s "$_cold" "$_warm"; then
        parity_row "$(abi_of "$_g")" "$HOST/$RT_MODE" "aot_reload" \
            "dbt" "PASS" "$(( $(parity_now_ms) - _t0 ))" \
            "warm reload output identical"
    else
        parity_row "$(abi_of "$_g")" "$HOST/$RT_MODE" "aot_reload" \
            "dbt" "FAIL" "0" "reload exit=$_rc, outputs differ"
    fi
}

aot_reload_one "p3-le"
aot_reload_one "p3-be"

parity_summary
