#!/bin/sh
# E03 runner: FR=0 vs FR=1, Legacy vs 2008 NaN / ABS FPU semantics.
#
# Host usage (macOS Apple Silicon, no local toolchain):
#   sh experiments/E03/run.sh
# which re-executes this same file with --inner inside a unique
# debian:bookworm-slim container (--platform linux/arm64).
# Inner usage (already inside debian):
#   sh experiments/E03/run.sh --inner
set -eu

E03=experiments/E03
IMG=debian:bookworm-slim

if [ "${1:-}" != "--inner" ]; then
	NAME="mips32rt-e03-$$"
	docker run --rm --name "$NAME" --memory 2g --cpus 2 \
		--platform linux/arm64 -v "$PWD:/w" -w /w \
		"$IMG" sh "$E03/run.sh" --inner
	rc=$?
	docker ps | head -5
	exit $rc
fi

# ---- inner (debian) ----
echo "== toolchain setup =="
if ! command -v mipsel-linux-gnu-gcc >/dev/null 2>&1; then
	apt-get update
	apt-get install -y --no-install-recommends \
		qemu-user \
		gcc-mipsel-linux-gnu libc6-dev-mipsel-cross \
		gcc-mips-linux-gnu libc6-dev-mips-cross \
		file
fi
echo "== identities =="
mipsel-linux-gnu-gcc --version | head -1
mips-linux-gnu-gcc --version | head -1 || echo "no mips BE gcc"
qemu-mipsel --version | head -2
qemu-mips --version | head -2 || echo "no qemu-mips"

mkdir -p "$E03/logs" "$E03/bin"
CFLAGS="-std=c11 -pedantic -Wall -Wextra -Werror -march=mips32r2 -mabi=32 -static -O1"
# Debian cross glibc ships legacy-NaN stubs headers only; the shim
# supplies the missing gnu/stubs-o32_hard_2008.h (see shim2008/ + FINDINGS.md).
SHIM2008="-I $E03/shim2008"

echo "== build LE legacy (default NaN) =="
# shellcheck disable=SC2086
if mipsel-linux-gnu-gcc $CFLAGS -o "$E03/bin/probe_le_legacy" "$E03/probe.c" 2>"$E03/logs/build_le_legacy.err"; then
	echo "le-legacy: ok"
else
	echo "le-legacy: FAIL"; cat "$E03/logs/build_le_legacy.err"
fi
echo "== build LE 2008 =="
# shellcheck disable=SC2086
if mipsel-linux-gnu-gcc $CFLAGS $SHIM2008 -mnan=2008 -o "$E03/bin/probe_le_2008" "$E03/probe.c" 2>"$E03/logs/build_le_2008.err"; then
	echo "le-2008: ok"
else
	echo "le-2008: FAIL"; cat "$E03/logs/build_le_2008.err"
fi
echo "== build LE fp64 attempts =="
# shellcheck disable=SC2086
if mipsel-linux-gnu-gcc $CFLAGS -mfp64 -o "$E03/bin/probe_le_fp64" "$E03/probe.c" 2>"$E03/logs/fp64.err"; then
	echo "fp64(default-nan): ACCEPTED"
else
	echo "fp64(default-nan): REJECTED"; cat "$E03/logs/fp64.err"
fi
# shellcheck disable=SC2086
if mipsel-linux-gnu-gcc $CFLAGS $SHIM2008 -mnan=2008 -mfp64 -o "$E03/bin/probe_le_fp64_2008" "$E03/probe.c" 2>"$E03/logs/fp64_2008.err"; then
	echo "fp64(nan2008): ACCEPTED"
else
	echo "fp64(nan2008): REJECTED"; cat "$E03/logs/fp64_2008.err"
fi
echo "== build BE legacy + BE 2008 (if toolchain present) =="
if command -v mips-linux-gnu-gcc >/dev/null 2>&1; then
	# shellcheck disable=SC2086
	mips-linux-gnu-gcc $CFLAGS -o "$E03/bin/probe_be_legacy" "$E03/probe.c" 2>"$E03/logs/build_be_legacy.err" && echo "be-legacy: ok" || { echo "be-legacy: FAIL"; cat "$E03/logs/build_be_legacy.err"; }
	# shellcheck disable=SC2086
	mips-linux-gnu-gcc $CFLAGS $SHIM2008 -mnan=2008 -o "$E03/bin/probe_be_2008" "$E03/probe.c" 2>"$E03/logs/build_be_2008.err" && echo "be-2008: ok" || { echo "be-2008: FAIL"; cat "$E03/logs/build_be_2008.err"; }
else
	echo "BE: NO TOOLCHAIN (UNVERIFIED)"
fi

echo "== abiflags (cross readelf; full logs saved) =="
for b in "$E03"/bin/probe_*; do
	[ -f "$b" ] || continue
	echo "--- $b"
	file "$b" || true
	case "$b" in
	*"_be_"*) R=mips-linux-gnu-readelf ;;
	*) R=mipsel-linux-gnu-readelf ;;
	esac
	$R -h "$b" | grep -E 'Flags|Machine' || true
	$R -A "$b" >"$E03/logs/$(basename "$b").readelf-A" 2>&1 || true
	grep -E 'Tag_GNU_MIPS_ABI_FP|FP ABI|CPR1|FLAGS|ISA:' "$E03/logs/$(basename "$b").readelf-A" || true
done

echo "== encodings (objdump of probe functions only; full -d regenerable) =="
FNS="main read_fcsr write_fcsr read_fir mfc1_roundtrip mfhc1_roundtrip abs_s abs_d add_s abs_s_trap_test add_s_trap_test abs_d_trap_test print_fcsr"
if [ -f "$E03/bin/probe_le_legacy" ]; then
	: >"$E03/logs/probe_le_legacy.objdump"
	for f in $FNS; do
		mipsel-linux-gnu-objdump -d --disassemble="$f" "$E03/bin/probe_le_legacy" >>"$E03/logs/probe_le_legacy.objdump" 2>&1
	done
	grep -E 'abs\.s|abs\.d|mtc1|mfc1|mthc1|mfhc1|cfc1|ctc1' "$E03/logs/probe_le_legacy.objdump" | head -40 || true
fi
if [ -f "$E03/bin/probe_be_legacy" ]; then
	: >"$E03/logs/probe_be_legacy.objdump"
	for f in $FNS; do
		mips-linux-gnu-objdump -d --disassemble="$f" "$E03/bin/probe_be_legacy" >>"$E03/logs/probe_be_legacy.objdump" 2>&1
	done
	grep -E 'abs\.s|abs\.d|mtc1|mfc1|mthc1|mfhc1|cfc1|ctc1' "$E03/logs/probe_be_legacy.objdump" | head -12 || true
fi

echo "== static NaN codegen (builtin_nansf/nanf rodata) =="
printf 'float f(void){return __builtin_nansf("");}\nfloat g(void){return __builtin_nanf("");}\n' >"$E03/logs/nan.c"
for o in leg nan2008 nan2008_abs2008; do
	case $o in
	leg) F="" ;;
	nan2008) F="-mnan=2008 -I $E03/shim2008" ;;
	nan2008_abs2008) F="-mnan=2008 -mabs=2008 -I $E03/shim2008" ;;
	esac
	echo "--- opt=$o"
	# shellcheck disable=SC2086
	mipsel-linux-gnu-gcc -march=mips32r2 -mabi=32 -O1 $F -c -o "$E03/logs/nan_$o.o" "$E03/logs/nan.c" && {
		mipsel-linux-gnu-objdump -s -j .rodata.cst4 "$E03/logs/nan_$o.o" 2>/dev/null
		mipsel-linux-gnu-readelf -h "$E03/logs/nan_$o.o" | grep Flags || true
	} || echo "$o: COMPILE FAIL"
done

echo "== 2008-mode run (same code, EF_MIPS_NAN2008 patched copy) =="
if [ -f "$E03/bin/probe_le_legacy" ]; then
	cp "$E03/bin/probe_le_legacy" "$E03/bin/probe_le_nan2008flag"
	# e_flags lives at ELF32 offset 36; set bit 10 (0x400 = EF_MIPS_NAN2008).
	# Only the marking differs; machine code is byte-identical (cmp below).
	printf '\007\024\000\160' | dd of="$E03/bin/probe_le_nan2008flag" bs=1 seek=36 count=4 conv=notrunc status=none
	mipsel-linux-gnu-readelf -h "$E03/bin/probe_le_nan2008flag" | grep Flags || true
	cmp -i 40 "$E03/bin/probe_le_legacy" "$E03/bin/probe_le_nan2008flag" && echo "identical except e_flags: YES"
	echo "--- run probe_le_nan2008flag under qemu-mipsel ---"
	set +e
	timeout --kill-after=30s 60s qemu-mipsel "$E03/bin/probe_le_nan2008flag" >"$E03/logs/probe_le_nan2008flag.stdout" 2>"$E03/logs/probe_le_nan2008flag.stderr"
	echo "exit=$?"
	set -e
	cat "$E03/logs/probe_le_nan2008flag.stdout"
fi

run_one() {
	bin="$1"
	emu="$2"
	name="$(basename "$bin")"
	echo "--- run $name under $emu ---"
	set +e
	timeout --kill-after=30s 60s "$emu" "$bin" >"$E03/logs/$name.stdout" 2>"$E03/logs/$name.stderr"
	rc=$?
	set -e
	echo "exit=$rc"
	cat "$E03/logs/$name.stdout"
	if [ -s "$E03/logs/$name.stderr" ]; then
		echo "[stderr]"
		cat "$E03/logs/$name.stderr"
	fi
}

for b in probe_le_legacy probe_le_2008 probe_le_fp64 probe_le_fp64_2008; do
	if [ -x "$E03/bin/$b" ]; then
		run_one "$E03/bin/$b" qemu-mipsel
	else
		echo "--- $b: NO BINARY, skipped"
	fi
done
if [ -x "$E03/bin/probe_be_legacy" ]; then
	run_one "$E03/bin/probe_be_legacy" qemu-mips
	if [ -x "$E03/bin/probe_be_2008" ]; then
		run_one "$E03/bin/probe_be_2008" qemu-mips
	else
		echo "be-2008 run: SKIPPED (no binary)"
	fi
else
	echo "BE runs: SKIPPED (UNVERIFIED)"
fi
echo "INNER-DONE"
