# Phase 3 Task Cards — FPU/SIMD Interpreter & Emitter (`mips32rt`)

Run after `RC2` is merged to `master`. Frozen: SPEC 2.4/FPU rules, E03
findings (FR=0 vs FR=1, Legacy vs 2008 NaN/ABS, MTC1/MFHC1/MTHC1,
quiet/signaling bit patterns), `ctx.fpr[32]`/`fcsr` layout (SPEC 2.1),
`mips_dec` fields, `fpmove.c` move semantics (unaligned-safe,
FR-agnostic), `dbt_emit_int` control-flow/exit ABI.

Shared rules: curated C11, every file ≤ 900 lines, W^X + I-cache
discipline, never touch `x18`, no AI/agent names. FP arithmetic faults
(`mips_fault` interp / `EXIT_UNDEF` dbt) until this phase lands; after it,
only unimplemented cases (paired-single `MADD.PS` oddities, if any) may
still fault, documented per-case. `FR=0` pairs even/odd 32-bit halves
(`MTC1` writes low half, upper preserved — as `fpmove` does); `FR=1`
uses full 64-bit lanes (selected by `Status.FR`, default 0). Legacy NaN:
quiet bit = frac MSB *clear*; 2008: quiet bit = frac MSB *set*;
propagate per E03 tables. sNaN arithmetic input raises Invalid Operation
(Legacy traps via `mips_fault`; 2008 quiets the operand).

---

### Lane `L3a` — FPU Reference Interpreter (`src/interp/fp.c`)
- **Worktree**: `../mips32rt-l3a` on branch `lane/p3-l3a`
- **Exclusive Files**: `src/interp/fp.c`, `src/interp/fp.h`
- **Task**: implement `int fp_exec(mips32_ctx_t *, uint32_t pc, const mips_dec_t *)`
  (0 ok, MIPS_FAULT otherwise; declares in `fp.h`):
  FMT S/D arithmetic (ADD/SUB/MUL/DIV/SQRT/ABS/NEG/MOV/ROUND/TRUNC/CEIL/
  FLOOR/CVT.S/CVT.D/CVT.W/CVT.L), comparisons + `BC1T/F/TL` branch helpers
  (condition bit + annul variants), CTC1/CFC1 full control (FCSR fields
  incl. cause/enable/flags/rounding-mode), MFC1/MTC1/MFHC1/MTHC1 64-bit
  halves, DMFC0/DMTC0 FPU-adjacent paths if any. Wire into `interp.c`'s
  COP1 case: replace the `fpmove_cop1`-then-fault path so arithmetic goes
  to `fp_exec` (moves stay in `fpmove.c`; list `src/interp/interp.c` as a
  hook-only shared edit: one call-site change).
- **Acceptance Command**:
  ```sh
  cc -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror -Iinclude -Isrc -c src/interp/fp.c -o /tmp/fp.o
  ```
  (Execution is the RC3 gate; report it deferred.)

---

### Lane `L3b` — AArch64 FPU Emitter (`src/dbt/emit_fp.c`)
- **Worktree**: `../mips32rt-l3b` on branch `lane/p3-l3b`
- **Exclusive Files**: `src/dbt/emit_fp.c`
- **Task**: implement `int dbt_emit_fp(a64_buf_t *, const mips_dec_t *,
  uint32_t fpc, int be, int fr_mode, int nan2008)` (0 ok, nonzero
  decline → dispatcher falls back) with `a64_emit.h` only: S/D ADD/SUB/
  MUL/DIV/SQRT/ABS/NEG/MOV/ROUND/TRUNC/CEIL/FLOOR/CVT.*, comparisons +
  BC1 branches (compare `fpmove.c` move entry for shared helpers; put
  shared bits in `fp.h` if both need them — coordinate via the frozen
  headers, no cross-lane edits). Double-precision in A64 D-regs;
  single-precision in S-regs with explicit 32-bit lane discipline for
  FR=0 pairs; FCSR rounding-mode + flag updates. Also hook
  `dbt_emit_int`'s COP1 case to try `dbt_emit_fp` first (list
  `src/dbt/emit_int.c` as a hook-only shared edit: call + fallback).
- **Acceptance Command**: cross `-c` check as L2c did for
  `src/dbt/emit_fp.c` (execution is the RC3 gate; report it deferred).

---

### Lane `L3c` — FPU Test Suite + QEMU Goldens (`tests/test_p3_fpu.*`)
- **Worktree**: `../mips32rt-l3c` on branch `lane/p3-l3c`
- **Exclusive Files**: `tests/test_p3_fpu.c`, `tests/run_p3_fpu.sh`,
  `tests/p3_golden_*.txt`
- **Task**:
  1. Write `tests/test_p3_fpu.c` (freestanding C + MIPS inline asm,
     `-static`): S/D add/sub/mul/div/sqrt/abs/neg/mov/round/trunc/
     ceil/floor/cvt chains vs `double`/`float` host-side reference
     computed with explicit rounding (no `==` on raw NaN bits — compare
     Legacy vs 2008 quiet/signaling patterns per E03 as *bit tables*),
     comparisons + BC1T/BC1F taken/not-taken incl. annul-likely,
     MFC1/MTC1/MFHC1/MTHC1 round-trips, CTC1/CFC1 FCSR round-trip,
     division-by-zero (±Inf) and overflow (±Inf) and invalid (NaN +
     FCSR flags) cases, unaligned LWC1/SWC1/LDC1/SDC1 spot checks.
     Prints per-check lines + `P3-RESULT: PASS`; exit 0 iff all pass.
  2. Write `tests/run_p3_fpu.sh` mirroring `run_p1_isa.sh`: build
     LE (`-march=mips32r2 -static`, default Legacy-NaN) and BE, run
     under `qemu-mipsel`/`qemu-mips` with bounded timeouts, capture
     stdout + exit into `tests/p3_golden_le.txt` / `p3_golden_be.txt`
     (BE best-effort, mark gaps honestly). A `-mnan=2008` LE variant
     is optional; if the toolchain accepts it, capture a second golden
     (`p3_golden_le2008.txt`) but keep it informational (not gated).
- **Acceptance Command**:
  ```sh
  sh tests/run_p3_fpu.sh && test -s tests/p3_golden_le.txt
  ```

---

## RC3 outcome (coordinator integration)

P3 suite: 73 pass, 0 fail, exit 0 on interp LE+BE; interp-vs-dbt `--difftest`
reports 0 divergences LE+BE; RC1 (52 shared PASS) and D2 gates still green.
Signal/fork-dependent checks SKIP until Phase 4 (6 SKIP lines; the
not-taken pageend line stays a documented SPEC-vs-qemu divergence).

Bugs found at RC3 integration (all verified by the gates):
- MFHC1/MTHC1 decoded as rs 9/11; the encoding is rs 3/7 (interp + noted;
  DBT emitter already correct).
- `fp_from_int` exponent base off by 3 (E init `mb` instead of `mb+3`),
  making int->float results 8x too small (e.g. 12345 -> ~1543).
- DBT emitter byte-swapped FPR *values* on BE (rev + half swap). The
  register file is endian-neutral — only guest *memory* bytes reorder
  (E05) — so all value revs/swaps removed; GPR 64-bit pair order kept
  big-endian per E01.
- CFC1 $0 (FIR) faulted; now returns qemu-observed 0x00739300,
  CTC1 $0 is a NOP.
