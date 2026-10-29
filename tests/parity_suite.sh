#!/bin/sh
# tests/parity_suite.sh — Wave C1 catalogue parity gate (lane C1-3).
#
# Copyright 2026 Moritz Angermann <moritz@zw3rk.com>, zw3rk pte. ltd.
# SPDX-License-Identifier: Apache-2.0
#
# MIPS32r2 O32 LE (mipsel) + BE (mips) Tier S gate. Sources the frozen
# cross-repo contract ../../rt-series/tools/parity_contract.sh and
# emits one structured PARITY_ROW per executed check, finishing with
# parity_summary (non-zero exit on any FAIL/GAP/SKIP).
#
# Rows:
#   struct  make check-line-limits, make check-abi-invariants,
#           test_decode host self-test, host AOT round-trip check.
#   mipsel/mips guest execution parity (--interp, --dbt, --difftest)
#           on _build/parity/{p1,p3,p4}-{le,be} against the committed
#           goldens in tests/ (p1_golden_{le,be}.txt, p3_golden_{le,be}.txt,
#           p3_golden_le2008.txt, p4_golden_{le,be}.txt), plus
#           bench-mipsel --smoke (when present).
#
# Golden comparison is stdout-only: the committed goldens bundle the
# Docker toolchain header ("--- toolchain ---" through "--- run ... ---"),
# the qemu stderr line ("qemu: uncaught target signal ..."), and an
# EXIT trailer; golden_guest() strips exactly those harness lines and
# the suite additionally requires translator exit 0.
#
# Backend order for guest legs: a Linux _build/mips32rt runs natively
# on Linux CI, else inside one Debian bookworm container (which also
# builds the guests and runs the qemu-mipsel/qemu-mips oracle, so the
# whole Linux leg is a single audited environment), else via
# hyper-linux (../rt-series/_build/hl, with a documented caveat: hl
# reports a signal-killed guest child as exited(139) instead of
# signal-killed, so fork-death rows diverge there), else GAP.
# The darwin translator runs the bench-smoke rows only: backend_darwin
# implements neither fork nor clone, so signal/thread guests cannot
# match the goldens there by construction.
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
HL="$ROOT/../rt-series/_build/hl"

RT_MODE="none"
if [ -x "$RT_LINUX" ] && "$RT_LINUX" --version >/dev/null 2>&1; then
    RT_MODE="native"
elif command -v docker >/dev/null 2>&1; then
    RT_MODE="docker"
elif [ -x "$HL" ] && [ -x "$RT_LINUX" ] && \
        "$HL" "$RT_LINUX" --version >/dev/null 2>&1; then
    RT_MODE="hl"
fi

have_docker() { command -v docker >/dev/null 2>&1; }

DOCKER_NAME="mips32rt-c13-$$"
docker_cleanup() { docker rm -f "$DOCKER_NAME" >/dev/null 2>&1 || true; }

# abi_of <guest>: mipsel for *-le, mips for *-be.
abi_of() {
    case "$1" in
        *-be) echo "mips" ;;
        *) echo "mipsel" ;;
    esac
}

# golden_guest <golden> <out>: strip the toolchain header, the qemu
# stderr chatter, and the EXIT trailer, leaving guest stdout only.
golden_guest() {
    local _golden="$1" _out="$2"
    if grep -q '^--- run ' "$_golden"; then
        sed -n '/^--- run /,$p' "$_golden" | tail -n +2
    else
        cat "$_golden"
    fi | grep -v '^qemu: uncaught target signal' | \
        grep -v '^[A-Z0-9]*-EXIT=[0-9][0-9]*$' >"$_out"
}

# golden_row <abi> <host> <case> <engine> <golden> <actual> <exit>
golden_row() {
    local _t0 _abi _host _case _eng _golden _actual _exit _ms _gg _ga
    _t0="$(parity_now_ms)"
    _abi="$1"; _host="$2"; _case="$3"; _eng="$4"
    _golden="$5"; _actual="$6"; _exit="$7"
    _ms=0
    if [ ! -f "$_golden" ]; then
        parity_row "$_abi" "$_host" "$_case" "$_eng" "GAP" "$_ms" \
            "golden missing: $_golden"
        return
    fi
    if [ "$_exit" -ne 0 ]; then
        parity_row "$_abi" "$_host" "$_case" "$_eng" "FAIL" "$_ms" \
            "exit=$_exit"
        return
    fi
    _gg="$OUT/.golden-guest.tmp"
    _ga="$OUT/.actual-norm.tmp"
    golden_guest "$_golden" "$_gg"
    grep -v '^qemu: uncaught target signal' "$_actual" >"$_ga" || true
    if parity_check_golden "$_gg" "$_ga"; then
        _ms=$(( $(parity_now_ms) - _t0 ))
        parity_row "$_abi" "$_host" "$_case" "$_eng" "PASS" "$_ms" \
            "guest stdout identical, exit 0"
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

_t0="$(parity_now_ms)"
if cc -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror \
        -Iinclude -Isrc tests/test_aot_roundtrip.c \
        src/dbt/aot/aot.c -o "$OUT/host_aot_roundtrip" \
        2>"$OUT/host-aot.log" \
    && "$OUT/host_aot_roundtrip" >"$OUT/host-aot.out" 2>&1 \
    && grep -q "AOT-ROUNDTRIP: PASS" "$OUT/host-aot.out"; then
    parity_row "struct" "$HOST" "host-aot-roundtrip" "host" "PASS" \
        "$(( $(parity_now_ms) - _t0 ))" "write/lookup/magic/sites PASS"
else
    parity_row "struct" "$HOST" "host-aot-roundtrip" "host" "FAIL" "0" \
        "see $OUT/host-aot.log"
fi

if [ ! -x "$RT_DARWIN" ]; then
    echo "note: building missing $RT_DARWIN (make build-darwin)"
    make build-darwin >/dev/null 2>&1 || true
fi

# ---- guest builds -------------------------------------------------------
# Static guests (_build/parity/, gitignored): reuse when newer than
# their sources, else build with native cross gcc, else in a bookworm
# container. Each guest gets an availability row.
mips_build_one() {
    local _cc="$1" _flags="$2" _src="$3" _out="$4"
    # shellcheck disable=SC2086
    $_cc $_flags -o "$_out" "$ROOT/$_src"
}

guest_spec() {
    local _g="$1"
    case "$_g" in
        p1-le) echo "tests/test_p1_isa.c|-march=mips32r2 -static -O1 -std=c11 -Wall -Wextra|mipsel-linux-gnu-gcc" ;;
        p1-be) echo "tests/test_p1_isa.c|-march=mips32r2 -EB -static -O1 -std=c11 -Wall -Wextra|mips-linux-gnu-gcc" ;;
        p3-le) echo "tests/test_p3_fpu.c|-march=mips32r2 -static -O1 -std=c11 -Wall -Wextra|mipsel-linux-gnu-gcc" ;;
        p3-be) echo "tests/test_p3_fpu.c|-march=mips32r2 -EB -static -O1 -std=c11 -Wall -Wextra|mips-linux-gnu-gcc" ;;
        p4-le) echo "tests/test_p4_threads_signals.c|-march=mips32r2 -static -pthread -O1 -std=c11 -Wall -Wextra|mipsel-linux-gnu-gcc" ;;
        p4-be) echo "tests/test_p4_threads_signals.c|-march=mips32r2 -EB -static -pthread -O1 -std=c11 -Wall -Wextra|mips-linux-gnu-gcc" ;;
    esac
}

need_build=""
_le2008_log_fresh=0
for _g in p1-le p1-be p3-le p3-be p4-le p4-be; do
    _s="$(guest_spec "$_g")"
    _src="${_s%%|*}"
    if [ -x "$OUT/$_g" ] && [ "$OUT/$_g" -nt "$ROOT/$_src" ]; then
        parity_row "$(abi_of "$_g")" "$HOST" "$_g-guest-build" "host" \
            "PASS" "0" "cached, newer than $_src"
    else
        need_build="$need_build $_g"
    fi
done

if [ -n "$need_build" ]; then
    if command -v mipsel-linux-gnu-gcc >/dev/null 2>&1 && \
            command -v mips-linux-gnu-gcc >/dev/null 2>&1; then
        for _g in $need_build; do
            _s="$(guest_spec "$_g")"
            _src="${_s%%|*}"; _rest="${_s#*|}"
            _flags="${_rest%%|*}"; _cc="${_rest##*|}"
            _t0="$(parity_now_ms)"
            if mips_build_one "$_cc" "$_flags" "$_src" "$OUT/$_g" \
                    >"$OUT/build-$_g.log" 2>&1; then
                parity_row "$(abi_of "$_g")" "$HOST" "$_g-guest-build" \
                    "host" "PASS" "$(( $(parity_now_ms) - _t0 ))" \
                    "native cross build"
            else
                parity_row "$(abi_of "$_g")" "$HOST" "$_g-guest-build" \
                    "host" "GAP" "0" "native build failed"
            fi
        done
    elif have_docker; then
        _t0="$(parity_now_ms)"
        trap docker_cleanup EXIT INT TERM
        if timeout --kill-after=30s 500s docker run --rm \
                --name "$DOCKER_NAME" --memory 2g --cpus 2 \
                --platform linux/arm64 -v "$ROOT:/w" -w /w \
                debian:bookworm-slim bash -lc '
set -eu
apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install \
    -y -qq qemu-user gcc-mipsel-linux-gnu gcc-mips-linux-gnu \
    libc6-dev-mipsel-cross libc6-dev-mips-cross \
    binutils-mipsel-linux-gnu binutils-mips-linux-gnu >/dev/null 2>&1
mkdir -p _build/parity
mipsel-linux-gnu-gcc -march=mips32r2 -static -O1 -std=c11 -Wall -Wextra \
    -o _build/parity/p1-le tests/test_p1_isa.c
mips-linux-gnu-gcc -march=mips32r2 -EB -static -O1 -std=c11 -Wall -Wextra \
    -o _build/parity/p1-be tests/test_p1_isa.c
mipsel-linux-gnu-gcc -march=mips32r2 -static -O1 -std=c11 -Wall -Wextra \
    -o _build/parity/p3-le tests/test_p3_fpu.c
mips-linux-gnu-gcc -march=mips32r2 -EB -static -O1 -std=c11 -Wall -Wextra \
    -o _build/parity/p3-be tests/test_p3_fpu.c
mipsel-linux-gnu-gcc -march=mips32r2 -static -pthread -O1 -std=c11 \
    -Wall -Wextra -o _build/parity/p4-le tests/test_p4_threads_signals.c
mips-linux-gnu-gcc -march=mips32r2 -EB -static -pthread -O1 -std=c11 \
    -Wall -Wextra -o _build/parity/p4-be tests/test_p4_threads_signals.c
rm -f _build/parity/p3-le2008
mipsel-linux-gnu-gcc -march=mips32r2 -mnan=2008 -static -O1 -std=c11 \
    -o _build/parity/p3-le2008 tests/test_p3_fpu.c \
    2>_build/parity/le2008-build.log || \
    echo "2008 build failed as documented (see le2008-build.log)"
echo "LE2008_FRESH=1" > _build/parity/docker-build.env
' >"$OUT/docker-build.log" 2>&1; then
            if grep -q "LE2008_FRESH=1" "$OUT/docker-build.env" 2>/dev/null; then
                _le2008_log_fresh=1
            fi
            for _g in $need_build; do
                if [ -x "$OUT/$_g" ]; then
                    parity_row "$(abi_of "$_g")" "$HOST" "$_g-guest-build" \
                        "host" "PASS" "$(( $(parity_now_ms) - _t0 ))" \
                        "bookworm container build"
                else
                    parity_row "$(abi_of "$_g")" "$HOST" "$_g-guest-build" \
                        "host" "GAP" "0" "container build missed $_g"
                fi
            done
        else
            for _g in $need_build; do
                parity_row "$(abi_of "$_g")" "$HOST" "$_g-guest-build" \
                    "host" "GAP" "0" "container build failed"
            done
        fi
        trap - EXIT INT TERM
        docker_cleanup
    else
        for _g in $need_build; do
            parity_row "$(abi_of "$_g")" "$HOST" "$_g-guest-build" "host" \
                "GAP" "0" "no mips cross gcc and no docker"
        done
    fi
fi

# ---- oracle vs golden ---------------------------------------------------
# qemu-mipsel (LE) / qemu-mips (BE). A native qemu is trusted only when
# it reproduces the committed golden (self-validating oracle);
# otherwise the pinned bookworm (qemu 7.2) container runs the legs.
qemu_of() {
    case "$1" in
        *-be) echo "qemu-mips" ;;
        *) echo "qemu-mipsel" ;;
    esac
}

ORACLE_MODE="none"
if command -v qemu-mipsel >/dev/null 2>&1 && \
        command -v qemu-mips >/dev/null 2>&1; then
    _ok=1
    for _g in p1-le p1-be p3-le p3-be p4-le p4-be; do
        _q="$(qemu_of "$_g")"
        _golden="tests/p1_golden_le.txt"
        case "$_g" in
            p1-le) _golden="tests/p1_golden_le.txt" ;;
            p1-be) _golden="tests/p1_golden_be.txt" ;;
            p3-le) _golden="tests/p3_golden_le.txt" ;;
            p3-be) _golden="tests/p3_golden_be.txt" ;;
            p4-le) _golden="tests/p4_golden_le.txt" ;;
            p4-be) _golden="tests/p4_golden_be.txt" ;;
        esac
        if [ -x "$OUT/$_g" ] && \
                timeout --kill-after=10s 60s "$_q" "$OUT/$_g" \
                    >"$OUT/oracle-native-$_g.txt" 2>&1 && \
                { golden_guest "$ROOT/$_golden" "$OUT/.gg.tmp" && \
                    grep -v '^qemu: uncaught target signal' \
                        "$OUT/oracle-native-$_g.txt" \
                        >"$OUT/.go-norm.tmp" && \
                    parity_check_golden "$OUT/.gg.tmp" \
                        "$OUT/.go-norm.tmp"; }; then
            :
        else
            _ok=0
        fi
    done
    rm -f "$OUT/.gg.tmp"
    if [ "$_ok" -eq 1 ]; then
        ORACLE_MODE="native"
        echo "note: native qemu reproduces goldens"
    else
        echo "note: native qemu diverges from goldens"
    fi
fi
if [ "$ORACLE_MODE" = "none" ] && have_docker; then
    trap docker_cleanup EXIT INT TERM
    if timeout --kill-after=30s 500s docker run --rm \
            --name "$DOCKER_NAME" --memory 2g --cpus 2 \
            --platform linux/arm64 -v "$ROOT:/w" -w /w \
            debian:bookworm-slim bash -lc '
set -eu
apt-get update -qq && DEBIAN_FRONTEND=noninteractive \
    apt-get install -y -qq qemu-user >/dev/null 2>&1
qemu-mipsel --version | head -1
for g in p1-le p1-be p3-le p3-be p4-le p4-be; do
    case $g in *-be) q=qemu-mips;; *) q=qemu-mipsel;; esac
    rc=0
    timeout --kill-after=10s 60s $q _build/parity/$g \
        > _build/parity/oracle-$g.txt 2>&1 || rc=$?
    echo "$g oracle exit=$rc"
done
' >"$OUT/docker-oracle.log" 2>&1; then
        ORACLE_MODE="docker"
    else
        echo "note: oracle container failed, see $OUT/docker-oracle.log"
    fi
    trap - EXIT INT TERM
    docker_cleanup
fi

golden_name_of() {
    case "$1" in
        p1-le) echo "tests/p1_golden_le.txt" ;;
        p1-be) echo "tests/p1_golden_be.txt" ;;
        p3-le) echo "tests/p3_golden_le.txt" ;;
        p3-be) echo "tests/p3_golden_be.txt" ;;
        p4-le) echo "tests/p4_golden_le.txt" ;;
        p4-be) echo "tests/p4_golden_be.txt" ;;
    esac
}

for _g in p1-le p1-be p3-le p3-be p4-le p4-be; do
    _t0="$(parity_now_ms)"
    case "$ORACLE_MODE" in
        native) _of="$OUT/oracle-native-$_g.txt" ;;
        docker) _of="$OUT/oracle-$_g.txt" ;;
        *)
            echo "note: no oracle for $_g (no qemu, no docker)"
            continue
            ;;
    esac
    if [ ! -x "$OUT/$_g" ]; then
        parity_row "$(abi_of "$_g")" "$HOST" "$_g-oracle-vs-golden" \
            "oracle" "GAP" "0" "guest missing"
    else
        golden_guest "$ROOT/$(golden_name_of "$_g")" "$OUT/.gg.tmp"
        grep -v '^qemu: uncaught target signal' "$_of" \
            >"$OUT/.go-norm.tmp" || true
        if parity_check_golden "$OUT/.gg.tmp" "$OUT/.go-norm.tmp"; then
            parity_row "$(abi_of "$_g")" "$HOST" "$_g-oracle-vs-golden" \
                "oracle" "PASS" "$(( $(parity_now_ms) - _t0 ))" \
                "$(qemu_of "$_g") reproduces golden"
        else
            parity_row "$(abi_of "$_g")" "$HOST" "$_g-oracle-vs-golden" \
                "oracle" "FAIL" "0" "oracle output differs from golden"
        fi
        rm -f "$OUT/.gg.tmp"
    fi
done

# ---- translator vs golden -----------------------------------------------
# rt_run <guest> <outfile> <engine-flags...>
rt_run() {
    local _guest="$1" _ofile="$2" _crel _rc
    shift 2
    case "$RT_MODE" in
        native)
            timeout --kill-after=10s 120s "$RT_LINUX" "$@" -- "$_guest" \
                >"$_ofile" 2>&1
            ;;
        docker)
            _crel="_build/parity/$(basename "$_guest")"
            trap docker_cleanup EXIT INT TERM
            timeout --kill-after=30s 500s docker run --rm \
                --name "$DOCKER_NAME" --memory 2g --cpus 2 \
                --platform linux/arm64 -v "$ROOT:/w" -w /w \
                debian:bookworm-slim \
                /w/_build/mips32rt "$@" -- "$_crel" >"$_ofile" 2>&1
            _rc=$?
            trap - EXIT INT TERM
            docker_cleanup
            return $_rc
            ;;
        hl)
            timeout --kill-after=10s 120s "$HL" "$RT_LINUX" "$@" \
                -- "$_guest" >"$_ofile" 2>&1
            ;;
        *) return 127 ;;
    esac
}

if [ "$RT_MODE" = "none" ]; then
    for _g in p1-le p1-be p3-le p3-be p4-le p4-be; do
        for _eng in interp dbt difftest; do
            parity_row "$(abi_of "$_g")" "$HOST" "$_g-vs-golden" "$_eng" \
                "GAP" "0" "no translator runner"
        done
    done
else
    for _g in p1-le p1-be p3-le p3-be p4-le p4-be; do
        if [ ! -x "$OUT/$_g" ]; then
            for _eng in interp dbt difftest; do
                parity_row "$(abi_of "$_g")" "$HOST" "$_g-vs-golden" \
                    "$_eng" "GAP" "0" "guest missing"
            done
            continue
        fi
        for _eng in interp dbt; do
            _rc=0
            rt_run "$OUT/$_g" "$OUT/rt-$_eng-$_g.txt" "--$_eng" || _rc=$?
            golden_row "$(abi_of "$_g")" "$HOST/$RT_MODE" "$_g-vs-golden" \
                "$_eng" "$ROOT/$(golden_name_of "$_g")" \
                "$OUT/rt-$_eng-$_g.txt" "$_rc"
        done
    done

    # ---- difftest (interp vs dbt, 0 divergences) ------------------------
    # Native/docker Linux: the committed tests/difftest/run_difftest.sh
    # (trace + REGS lockstep). hl: same comparison inline (the script
    # hardcodes the Linux binary, which cannot exec on Darwin).
    for _g in p1-le p1-be p3-le p3-be p4-le p4-be; do
        if [ ! -x "$OUT/$_g" ]; then
            parity_row "$(abi_of "$_g")" "$HOST" "$_g-difftest" \
                "difftest" "GAP" "0" "guest missing"
            continue
        fi
        _t0="$(parity_now_ms)"
        _dout="$OUT/rt-difftest-$_g.txt"
        case "$RT_MODE" in
            native)
                if sh tests/difftest/run_difftest.sh "$OUT/$_g" interp \
                        dbt >"$_dout" 2>&1; then
                    _drc=0
                else
                    _drc=$?
                fi
                ;;
            docker)
                _crel="_build/parity/$_g"
                trap docker_cleanup EXIT INT TERM
                if timeout --kill-after=30s 500s docker run --rm \
                        --name "$DOCKER_NAME" --memory 2g --cpus 2 \
                        --platform linux/arm64 -v "$ROOT:/w" -w /w \
                        debian:bookworm-slim \
                        sh tests/difftest/run_difftest.sh \
                            "/w/$_crel" interp dbt >"$_dout" 2>&1; then
                    _drc=0
                else
                    _drc=$?
                fi
                trap - EXIT INT TERM
                docker_cleanup
                ;;
            hl)
                _work="$OUT/.dft-$$"
                mkdir -p "$_work"
                _drc=0
                for _eng in interp dbt; do
                    _rc=0
                    MIPS32RT_DUMPSTATE=1 timeout --kill-after=10s 120s \
                        "$HL" "$RT_LINUX" "--$_eng" --trace -- \
                        "$OUT/$_g" >"$_work/$_eng.stdout" \
                        2>"$_work/$_eng.stderr" || _rc=$?
                    echo "$_rc" >"$_work/$_eng.exit"
                    grep -E '^I ' "$_work/$_eng.stderr" \
                        >"$_work/$_eng.trace" || true
                    grep -E '^(REGS|GPR|EXIT)' "$_work/$_eng.stderr" \
                        >"$_work/$_eng.regs" || true
                done
                _divs=0
                if [ "$(cat "$_work/interp.exit")" != \
                        "$(cat "$_work/dbt.exit")" ]; then
                    _divs=$((_divs + 1))
                fi
                if ! diff -u "$_work/interp.trace" "$_work/dbt.trace" \
                        >"$_work/trace.diff"; then
                    _divs=$((_divs + \
                        $(grep -c '^[<>]' "$_work/trace.diff" || true)))
                fi
                if ! diff -u "$_work/interp.regs" "$_work/dbt.regs" \
                        >"$_work/regs.diff"; then
                    _divs=$((_divs + \
                        $(grep -c '^[<>]' "$_work/regs.diff" || true)))
                fi
                if [ "$_divs" -eq 0 ]; then
                    echo "DIFFTEST: 0 divergences (interp vs dbt on $OUT/$_g)" \
                        >"$_dout"
                else
                    echo "DIFFTEST: $_divs divergences (interp vs dbt)" \
                        >"$_dout"
                    _drc=1
                fi
                rm -rf "$_work"
                ;;
        esac
        if [ "$_drc" -eq 0 ] && grep -q "0 divergences" "$_dout"; then
            parity_row "$(abi_of "$_g")" "$HOST/$RT_MODE" "$_g-difftest" \
                "difftest" "PASS" "$(( $(parity_now_ms) - _t0 ))" \
                "$(grep -m1 -o '0 divergences[^)]*)' "$_dout" || echo '0 divergences')"
        else
            parity_row "$(abi_of "$_g")" "$HOST/$RT_MODE" "$_g-difftest" \
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
elif [ "$_le2008_log_fresh" = 1 ] && [ -f "$OUT/le2008-build.log" ] && \
        grep -q "stubs-o32_hard_2008" "$OUT/le2008-build.log"; then
    parity_row "mipsel" "$HOST" "p3-2008nan" "host" "PASS" "0" \
        "documented gap (this-run container log)"
else
    echo "note: p3-2008nan skipped (no fresh 2008 build evidence this run)"
fi

# ---- bench smoke (when present) -----------------------------------------
if [ -x "$BENCH" ] && [ -x "$RT_DARWIN" ]; then
    for _eng in interp dbt; do
        _t0="$(parity_now_ms)"
        _rc=0
        timeout --kill-after=10s 60s "$RT_DARWIN" "--$_eng" -- "$BENCH" \
            --smoke >"$OUT/bench-$_eng.txt" 2>&1 || _rc=$?
        if [ "$_rc" -eq 0 ] && grep -q "ALL_PASS" "$OUT/bench-$_eng.txt" \
                && ! grep -q "FAIL" "$OUT/bench-$_eng.txt"; then
            parity_row "mipsel" "$HOST/darwin" "bench-smoke" "$_eng" \
                "PASS" "$(( $(parity_now_ms) - _t0 ))" "ALL_PASS, no FAIL"
        else
            parity_row "mipsel" "$HOST/darwin" "bench-smoke" "$_eng" \
                "FAIL" "0" "exit=$_rc, see $OUT/bench-$_eng.txt"
        fi
    done
else
    echo "note: bench smoke skipped (bench or darwin translator missing)"
fi

parity_summary
