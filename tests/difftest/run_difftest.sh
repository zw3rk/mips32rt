#!/bin/sh
# run_difftest.sh — engine-vs-engine differential check for one guest.
#
# Usage: sh run_difftest.sh GUEST [ENGINE_A] [ENGINE_B]
#   GUEST     path to a MIPS32r2 static guest binary
#   ENGINE_A  first engine (default: interp)
#   ENGINE_B  second engine (default: interp)
#
# Runs GUEST twice (once per engine) with --trace and MIPS32RT_DUMPSTATE=1,
# then diffs the "pc+word" instruction streams and the REGS exit-state
# dumps. Prints "DIFFTEST: 0 divergences" on a match or the first
# divergence otherwise.
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

WORK="$(mktemp -d /tmp/difftest.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT INT TERM

run_one() {
    tag="$1"
    eng="$2"
    rc=""
    MIPS32RT_DUMPSTATE=1 timeout --kill-after=30s 120s "$BIN" \
        "--$eng" --trace -- "$GUEST" \
        >"$WORK/$tag.stdout" 2>"$WORK/$tag.stderr" || rc=$?
    echo "${rc:-0}" >"$WORK/$tag.exit"
    grep -E '^I ' "$WORK/$tag.stderr" >"$WORK/$tag.trace" || true
    grep -E '^(REGS|GPR|EXIT)' "$WORK/$tag.stderr" >"$WORK/$tag.regs" || true
}

run_one a "$ENGA"
run_one b "$ENGB"

divs=0
if [ "$(cat "$WORK/a.exit")" != "$(cat "$WORK/b.exit")" ]; then
    echo "--- exit-code divergence ($ENGA vs $ENGB) ---"
    echo "A($ENGA): exit=$(cat "$WORK/a.exit")"
    echo "B($ENGB): exit=$(cat "$WORK/b.exit")"
    divs=$((divs + 1))
fi
if ! diff -u "$WORK/a.trace" "$WORK/b.trace" >"$WORK/trace.diff"; then
    echo "--- trace divergence ($ENGA vs $ENGB): first lines ---"
    head -20 "$WORK/trace.diff"
    divs=$((divs + $(grep -c '^[<>]' "$WORK/trace.diff" || true)))
fi
if ! diff -u "$WORK/a.regs" "$WORK/b.regs" >"$WORK/regs.diff"; then
    echo "--- REGS divergence ($ENGA vs $ENGB): first lines ---"
    head -20 "$WORK/regs.diff"
    divs=$((divs + $(grep -c '^[<>]' "$WORK/regs.diff" || true)))
fi
if [ "$divs" -eq 0 ]; then
    echo "DIFFTEST: 0 divergences ($ENGA vs $ENGB on $GUEST)"
else
    echo "DIFFTEST: $divs divergences ($ENGA vs $ENGB on $GUEST)"
    exit 1
fi
