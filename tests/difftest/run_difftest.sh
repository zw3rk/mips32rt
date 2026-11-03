#!/bin/sh
# run_difftest.sh — engine-vs-engine differential check for one guest.
#
# Usage: sh run_difftest.sh GUEST [ENGINE_A] [ENGINE_B]
#   GUEST     path to a MIPS32r2 static guest binary
#   ENGINE_A  first engine (default: interp)
#   ENGINE_B  second engine (default: interp)
#
# Runs GUEST twice (once per engine) with --trace and MIPS32RT_DUMPSTATE=1,
# then diffs the per-thread "pc+word" instruction streams and the REGS
# exit-state dumps. Prints "DIFFTEST: 0 divergences" on a match or the
# first divergence otherwise.
#
# Two scheduling dimensions are normalized so the gate is stable:
# setarch -R (when available) pins guest mappings against host ASLR,
# and the hosting-tid trace field demultiplexes threads (first-appearance
# order) so each thread's own stream compares verbatim.
#
# The default interp-vs-interp run is the self-consistency gate;
# interp-vs-dbt went live at RC2 (both must report 0 divergences).
# Run this script where _build/mips32rt executes (AArch64 Linux host or
# the bounded debian container used by run_d2.sh).
set -eu
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BIN="$ROOT/_build/mips32rt"

fail() {
    echo "DIFFTEST FAIL: $1"
    exit 1
}

[ $# -ge 1 ] || fail "usage: sh run_difftest.sh GUEST [ENGINE_A] [ENGINE_B]"
GUEST="$1"
ENGA="${2:-interp}"
ENGB="${3:-interp}"
[ -x "$BIN" ] || fail "translator not executable: $BIN"
[ -f "$GUEST" ] || fail "guest not found: $GUEST"
# Extra operands after ENGINE_B pass through as guest argv; RT_SYSROOT
# (when set) adds `--sysroot DIR` for dynamic guests. The caller picks
# the CWD so relative helper paths resolve identically on both legs.
shift 3 2>/dev/null || shift $#
GUESTARGS="$*"

WORK="$(mktemp -d /tmp/difftest.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT INT TERM

# demux <trace> <dir>: split "I tid pc word" lines into one file per
# hosting thread (named 0,1,2... in first-appearance order), dropping
# the tid field so per-thread streams compare verbatim.
demux() {
    mkdir -p "$2"
    : >"$2/order"
    awk -v d="$2" 'BEGIN { n=0 } {
        t=$2
        if (!(t in m)) { m[t]=n; print n > (d"/order"); n++ }
        print "I " $3 " " $4 > (d"/"m[t])
    }' "$1"
}

if setarch -R true >/dev/null 2>&1; then
    SETARCH="setarch -R"
else
    SETARCH=""
fi

run_one() {
    tag="$1"
    eng="$2"
    rc=""
    # shellcheck disable=SC2086
    MIPS32RT_DUMPSTATE=1 timeout --kill-after=30s 120s $SETARCH "$BIN" \
        "--$eng" ${RT_SYSROOT:+--sysroot "$RT_SYSROOT"} --trace -- \
        "$GUEST" $GUESTARGS \
        >"$WORK/$tag.stdout" 2>"$WORK/$tag.stderr" || rc=$?
    echo "${rc:-0}" >"$WORK/$tag.exit"
    grep -E '^I ' "$WORK/$tag.stderr" >"$WORK/$tag.trace" || true
    grep -E '^(REGS|GPR|EXIT)' "$WORK/$tag.stderr" >"$WORK/$tag.regs" || true
}

run_one a "$ENGA"
run_one b "$ENGB"

# M32-R5-9: timeout/infra exits (>=124) and empty outputs never pass.
for _t in a b; do
    _c="$(cat "$WORK/$_t.exit")"
    case "$_c" in
        ''|*[!0-9]*) fail "infrastructure: non-numeric exit in leg $_t: $_c" ;;
    esac
    if [ "$_c" -ge 124 ]; then
        fail "infrastructure exit $_c in leg $_t (>=124 timeout/signal)"
    fi
    if [ ! -s "$WORK/$_t.trace" ]; then
        fail "empty instruction trace in leg $_t (exit $_c)"
    fi
    if [ ! -s "$WORK/$_t.regs" ]; then
        fail "empty register dump in leg $_t (exit $_c)"
    fi
done

divs=0
if [ "$(cat "$WORK/a.exit")" != "$(cat "$WORK/b.exit")" ]; then
    echo "--- exit-code divergence ($ENGA vs $ENGB) ---"
    echo "A($ENGA): exit=$(cat "$WORK/a.exit")"
    echo "B($ENGB): exit=$(cat "$WORK/b.exit")"
    divs=$((divs + 1))
fi
demux "$WORK/a.trace" "$WORK/a.d"
demux "$WORK/b.trace" "$WORK/b.d"
if ! diff -q "$WORK/a.d/order" "$WORK/b.d/order" >/dev/null 2>&1; then
    echo "--- thread-count divergence ($ENGA vs $ENGB) ---"
    echo "A threads: $(wc -l <"$WORK/a.d/order" | tr -d ' ')"
    echo "B threads: $(wc -l <"$WORK/b.d/order" | tr -d ' ')"
    divs=$((divs + 1))
else
    : >"$WORK/trace.diff"
    for _t in $(cat "$WORK/a.d/order"); do
        if ! diff -u "$WORK/a.d/$_t" "$WORK/b.d/$_t" \
                >"$WORK/trace.diff.$_t" 2>/dev/null; then
            echo "--- trace divergence ($ENGA vs $ENGB) thread T$_t: first lines ---"
            head -10 "$WORK/trace.diff.$_t"
            # Unified change lines start with -/+, file headers ---/+++.
            divs=$((divs + $(grep -c -E '^[-+][^-+]' "$WORK/trace.diff.$_t" || true)))
            cat "$WORK/trace.diff.$_t" >>"$WORK/trace.diff"
        fi
    done
fi
if ! diff -u "$WORK/a.regs" "$WORK/b.regs" >"$WORK/regs.diff"; then
    echo "--- REGS divergence ($ENGA vs $ENGB): first lines ---"
    head -20 "$WORK/regs.diff"
    divs=$((divs + $(grep -c -E '^[-+][^-+]' "$WORK/regs.diff" || true)))
fi
if [ "$divs" -eq 0 ]; then
    echo "DIFFTEST: 0 divergences ($ENGA vs $ENGB on $GUEST)"
else
    echo "DIFFTEST: $divs divergences ($ENGA vs $ENGB on $GUEST)"
    exit 1
fi
