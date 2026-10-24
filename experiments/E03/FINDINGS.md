# E03 Findings — FR=0 vs FR=1 and Legacy vs 2008 NaN/ABS FPU Semantics

All values below are qemu-verified ground truth unless marked UNVERIFIED.
Reproduce: `sh experiments/E03/run.sh` (host; delegates to a unique
`debian:bookworm-slim --platform linux/arm64` container, `--memory 2g
--cpus 2`, apt-installs the toolchain, builds, runs everything under
`timeout --kill-after=30s 60s`). Raw outputs: `experiments/E03/logs/`.

## 1. Toolchain identity (exact)

- `mipsel-linux-gnu-gcc (Debian 12.2.0-14) 12.2.0`
  (configure: `--with-arch-32=mips32r2 --with-arch-64=mips64r2`, no
  `--with-nan` selector; default NaN = legacy)
- `mips-linux-gnu-gcc (Debian 12.2.0-14) 12.2.0` (BE)
- `qemu-mipsel version 7.2.22 (Debian 1:7.2+dfsg-7+deb12u18+b3)`
- `qemu-mips version 7.2.22` (same build)
--binutils `2.40-2cross2` (cross `readelf`/`objdump` used for all dumps)

Build flags (all): `-std=c11 -pedantic -Wall -Wextra -Werror
-march=mips32r2 -mabi=32 -static -O1`, plus per-variant NaN/FP flags.

## 2. What the toolchain accepts (exact outcomes)

| Variant | Flags | Result |
|---|---|---|
| LE legacy (default) | (none) | ok → `bin/probe_le_legacy` |
| LE 2008 | `-mnan=2008` | COMPILE ok, LINK FAILS (see §3) |
| LE fp64 | `-mfp64` | ACCEPTED → `bin/probe_le_fp64` |
| LE fp64+2008 | `-mnan=2008 -mfp64` | LINK FAILS (same reason) |
| BE legacy | (none) | ok → `bin/probe_be_legacy` |
| BE 2008 | `-mnan=2008` | LINK FAILS (same reason) |
| `-mnan=2008 -mabs=2008` (.o only) | — | ACCEPTED (codegen identical to `-mnan=2008`) |

`-mfp64` (FR=1, 64-bit FPRs) links and runs; `-mnan=2008` codegen is real
(`__builtin_nansf("")` folds to `0x7fffffff` legacy vs `0x7fa00000`
2008; `__builtin_nanf("")` folds to `0x7fbfffff` vs `0x7fc00000`;
`e_flags` gains `EF_MIPS_NAN2008`, shown as `nan2008` by readelf), but a
fully-linked `-mnan=2008` binary is not producible with this sysroot.

## 3. Link blocker for `-mnan=2008` (exact error)

Debian cross glibc 2.36 ships only legacy-NaN stubs
(`gnu/stubs-o32_hard.h`); `gnu/stubs-o32_hard_2008.h` is absent, so the
compile needs `-I experiments/E03/shim2008` (byte-equivalent shim, see
`shim2008/gnu/stubs-o32_hard_2008.h`), and the static link then fails
because Debian's CRT/libc objects are legacy-marked:

```text
ld: /tmp/cckmZDUX.o: linking -mnan=2008 module with previous -mnan=legacy modules
ld: failed to merge target specific data of file /tmp/cckmZDUX.o
```

Same failure for LE fp64+2008 and BE 2008. No `ld` override flag exists
(`ld --help | grep -i nan` is empty), and `qemu-mipsel -cpu 24Kf,nan2008=X`
is rejected (`Property '24Kf-mips-cpu.nan2008' not found`).
2008-mode runtime was therefore verified with a copy of the legacy
binary whose `e_flags` alone was patched to set `EF_MIPS_NAN2008`
(`bin/probe_le_nan2008flag`): `cmp -i 40` proves the machine code is
byte-identical past the flags word, so every 2008-mode row below is a
pure qemu FPU-mode response to the same instructions. qemu reads the
mode from `e_flags`, not from any note (see §7).

## 4. Sizes / layout (all runs agree)

`sizeof(float)=4`, `sizeof(double)=8`, `sizeof(void*)=4`;
LE: `endian=little`; BE: `endian=big`. Exit code `0` for every run
(LE legacy, LE fp64, LE nan2008flag, BE legacy); no stderr output.

## 5. ELF markings (cross `readelf -h/-A`, full logs saved)

| Binary | `e_flags` | GNU FP ABI | CPR1 | FLAGS1 | ISA |
|---|---|---|---|---|---|
| `probe_le_legacy` | `0x70001007` o32 mips32r2 | Hard float (32-bit CPU, Any FPU) | 32 | 0 | MIPS32r2 |
| `probe_le_fp64` | `0x70001007` o32 mips32r2 | Hard float (32-bit CPU, 64-bit FPU) | 64 | 1 | MIPS32r2 |
| `probe_be_legacy` | `0x70001007` o32 mips32r2 | Hard float (32-bit CPU, Any FPU) | 32 | 0 | MIPS32r2 |
| `probe_le_nan2008flag` | `0x70001407` o32 mips32r2 **nan2008** | (same as legacy) | 32 | 0 | MIPS32r2 |
| `nan_nan2008.o` (compile only) | `0x70001407` **nan2008** | (same as legacy) | 32 | 0 | MIPS32r2 |

`Tag_GNU_MIPS_ABI_FP` / `.MIPS.abiflags` FP ABI / FLAGS1 do **not**
record NaN2008 under gcc 12.2 (only `e_flags` does); gcc does mark
`-mfp64` (64-bit FPU, CPR1 64, FLAGS1=1 = odd-SP/FR). `file(1)` reports
all as `ELF 32-bit LSB/MSB executable, MIPS, MIPS32 rel2 version 1
(SYSV), statically linked`.

## 6. Runtime ground truth (qemu-mipsel / qemu-mips)

Quiet-bit rule confirmed: Legacy QNaN frac-MSB=0 (`0x7fbfffff`,
`0x7ff7ffffffffffff`), SNaN MSB=1 (`0x7fffffff`,
`0x7ffffffffffbffff`); 2008 inverts the MSB meaning. `div 0.0/0.0`
produces the mode's default QNaN at runtime (not folded:
`-ftrapping-math` is default).

| Test | Legacy LE (`0x00739300` FIR, FCSR reset `0`) | 2008 mode LE (`0x30f30300` FIR, FCSR reset `0x000c0000`) |
|---|---|---|
| `0.0f/0.0f` | `0x7fbfffff` | `0x7fc00000` |
| `0.0/0.0` | `0x7ff7ffffffffffff` | `0x7ff8000000000000` |
| `add.s(0x7fbfffff,1.0)` | `0x7fbfffff`, FCSR `0x0` (quiet) | `0x7fffffff`, FCSR `0x000d0040` (sNaN quieted + Cause.V + Flags.V) |
| `add.s(0x7fffffff,1.0)` | `0x7fbfffff`, FCSR `0x00010040` (sNaN quieted to legacy QNaN + Cause.V + Flags.V) | `0x7fffffff`, FCSR `0x000c0000` (quiet) |
| `add.s(sNaN)` + Invalid trap enabled | SIGFPE (`trapped=1`, handler longjmps out; post FCSR `0x00010800`) | SIGFPE mirror image (`trapped=1`, post FCSR `0x000d0800`) |
| `add.s(QNaN)` + trap enabled | silent, `trapped=0` | silent, `trapped=0` |
| `abs.s`/`abs.d` on **both** patterns, trap enabled | `trapped=0`, result = sign-cleared input, FCSR unchanged (`0x00000800` = only our enable bit) | identical: `trapped=0`, no Cause, no Flags (`0x000c0800`) |
| `abs.s(-1.0f)` / `abs.d(-1.0)` | `0x3f800000` / `0x3ff0000000000000` | same |
| `mtc1`/`mfc1` round trip (`0x12345678`, `0`, `0xffffffff`) | `OK` x3 | `OK` x3 |
| `mtc1`+`mthc1`/`mfc1`+`mfhc1` (`lo=0xdeadbeef hi=0x12345678`) | `OK` (exact round trip) | `OK` |
| LE fp64 (`-mfp64`) binary | identical to Legacy LE in every row (FIR `0x00739300`) | n/a |

BE legacy (`qemu-mips`, `endian=big`) matches Legacy LE in every row,
bit-for-bit. `-cpu M14K` cannot run these binaries (`SIGILL`, expected:
M14K is microMIPS-only) — recorded, not a finding about the FPU.

Key semantic results for the translator:

- **ABS.S/ABS.D are non-arithmetic: they never signal, even on sNaN,
  in either NaN mode.** The task's "trap in Legacy" premise does not
  hold under qemu 7.2 (nor on real MIPS: ABS/NEG/MOV never raise
  Invalid). Arithmetic `add.s` on sNaN is the signaling case, and the
  SIGFPE control proves the trap path works, so the abs silence is
  meaningful, not a broken handler.
- **Quieting preserves the payload, sets the mode's quiet bit:**
  legacy `0x7fffffff→0x7fbfffff`; 2008 `0x7fbfffff→0x7fffffff`.
- **FCSR mode bits:** 2008 mode reset value `0x000c0000` (bits 18+19 =
  NAN2008+ABS2008 indicators, persistent across `ctc1` of other fields);
  legacy reset `0x0`. Cause.V = bit 16, Flags.V = bit 6, enable.V =
  bit 11 (verified by set/readback). No FS/FO/FN bits set in any run.
- **FIR is mode-dependent under qemu:** legacy `0x00739300`
  (F64=L=W=D=S=1, PS=3D=0, procid `0x93`) vs 2008-mode `0x30f30300`
  (procid field reads `0x03`, W/L/F64 clear). This is qemu's FPU-model
  reporting, not guest code: same bytes executed.
- **FR=1 (`-mfp64`) needs no special handling for these ops** under
  qemu: `mthc1`/`mfhc1` on `$f0` round-trip exactly even in the FR=1
  binary; FIR/FCSR identical to FR=0. (Architecturally `MTHC1`/`MFHC1`
  are FR=0-only/UNPREDICTABLE in FR=1; qemu emulates them silently.)

## 7. `.MIPS.abiflags` / notes

- Section `.MIPS.abiflags` (`MIPS_ABIFLAGS`, vaddr `0x400118`, size
  `0x18`) present in all four binaries (incl. BE).
- **No `PT_MIPS_ABIFLAGS` segment is emitted** (segments are two `LOAD`
  only). qemu 7.2 user-mode selects the FPU NaN mode from ELF
  `e_flags.EF_MIPS_NAN2008`, proven by the patched-copy behavior flip.
- `.MIPS.abiflags` content for legacy: `ISA MIPS32r2, GPR 32, CPR1 32,
  FP ABI Hard float (32-bit CPU, Any FPU), FLAGS1/2 = 0`; fp64 differs
  only in `CPR1 64 / FP ABI ... 64-bit FPU / FLAGS1 = 1`.

## 8. Instruction encodings (objdump-verified, LE; BE identical mnemonics)

`mfc1 a0,$f0=0x44040000` (COP1 rs=00000), `mtc1 a1,$f0=0x44850000`
(rs=00100), `mfhc1 a1,$f0=0x44650000` (rs=01001),
`mthc1 a1,$f0=0x44e50000` (rs=01011), `cfc1 v1,fcsr=0x4443f800`
(rs=00010, rd=31), `ctc1 v0,fcsr=0x44c2f800` (rs=00110),
`abs.s=0x46000005` (fmt=10000, func=000101),
`abs.d=0x46200005` (fmt=10001). Full disassemblies in logs.

## 9. UNVERIFIED / limits (honest)

- A genuine `-mnan=2008`-linked executable (CRT+libc also 2008) was
  **not** produced: Debian's cross sysroot is legacy-NaN-only (§3).
  Mitigation is exact: the 2008-mode rows above execute byte-identical
  machine code with only the ELF NaN-marking bit changed, and
  `-mnan=2008` *codegen* (NaN constants, `e_flags`) is verified
  statically. BE-2008 runtime likewise UNVERIFIED beyond this (same
  blocker, same mitigation applies).
- FCSR bit 18/19 assignment (NAN2008 vs ABS2008 order) is reported as
  raw bits only; either order is consistent with these runs.
- qemu 7.2 is the oracle here, not silicon; FIR mode-dependence (§6)
  is a qemu reporting choice.
