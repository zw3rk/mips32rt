# Phase 1 Task Cards — Base Integer Decoder, Reference Interpreter & Minimal Syscalls (`mips32rt`)

Run after `RC0` is merged to `master`. Frozen contract: `src/mips32rt.h`
"Phase 1 frozen contracts" (`mips_dec_t`, `mips_decode`/`mips_fetch`,
`interp_step`/`interp_run`, `guest_*`, `mips_fault`, `mips_syscall`,
`MIPS_FAULT`, `mips_is_be`). Code against the header, not each other.

Shared rules: curated C11 (`-std=c11 -Werror=vla -pedantic -Wall -Wextra
-Werror`), every file ≤ 900 lines, never touch `x18`, no AI/agent names.
`$0` stays 0: any write to `gpr[0]` is discarded by the writer.
Delay slots: every branch/jump executes `pc+4` then transfers control,
`ra = pc+8` on links; branch-likely annuls `pc+4` when not taken (no
fetch, no fault); cross-page branch at `(pc & 0xfff) == 0xffc` is executed
by the interpreter one step at a time (no block formation in Phase 1).
`LL`/`SC`: `llbit/lladdr/llval` per SPEC 2.2; any helper/syscall clears
`llbit`. Unaligned `LW`/`SW` fault (`mips_fault`); `LWL`/`LWR`/`SWL`/`SWR`
compose bytes via `guest_ld8`/`guest_st8` per the E05 tables (both
endiannesses). O32 syscall convention per SPEC 2.3 (stack args at
`sp+16..sp+28`, `$a3` error flag). Faults in Phase 1: `mips_fault` records
`EXIT_FAULT`; `interp_run` returns and the process exits 139.

---

### Lane `L1a` — Instruction Decoder + Self-Test
- **Worktree**: `../mips32rt-l1a` on branch `lane/p1-l1a`
- **Exclusive Files**: `src/interp/decode.c`, `src/interp/decode.h`, `tests/test_decode.c`
- **Task**:
  1. Implement `mips_decode` (pure field splitter, fills every `mips_dec_t`
     field) and `mips_fetch` (endianness-aware via `mips_is_be`, fault on
     bad `pc`) in `src/interp/decode.c`; `decode.h` re-exports the contract
     from `src/mips32rt.h` plus `int mips_is_branch(const mips_dec_t *)`-style
     classifiers if useful (keep them pure).
  2. Write `tests/test_decode.c`: table-driven host-native self-test
     (fixed instruction words → expected fields, LE+BE fetch via a borrowed
     window is NOT needed — test `mips_decode` purely and `mips_fetch` only
     if `guest_mem_init` is on master; else defer fetch checks to RC1).
- **Acceptance Command**:
  ```sh
  cc -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror -Iinclude -Isrc -c src/interp/decode.c -o /tmp/decode.o && cc -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror -Iinclude -Isrc tests/test_decode.c src/interp/decode.c -o /tmp/test_decode && /tmp/test_decode
  ```

---

### Lane `L1b` — Base Integer Reference Interpreter
- **Worktree**: `../mips32rt-l1b` on branch `lane/p1-l1b`
- **Exclusive Files**: `src/interp/interp.c`, `src/interp/interp.h`
- **Task**: Implement `interp_step`/`interp_run` for the full SPEC 2
  integer subset: ALU (ADD/ADDU/SUB/SUBU/AND/OR/XOR/NOR/SLT/SLTI*/LUI),
  shifts (SLL/SRL/SRA/SLLV/SRLV/SRAV), multiply/divide (MULT/MULTU/DIV/DIVU
  via `hi`/`lo`, MFHI/MFLO/MTHI/MTLO), branches/jumps (BEQ/BNE/BLEZ/BGTZ/
  BLTZ/BGEZ + likely variants with annul, J/JAL/JR/JALR, SYSCALL/BREAK →
  dispatcher/fault), loads/stores (LB/LBU/LH/LHU/LW/SB/SH/SW with alignment
  faults, LWL/LWR/SWL/SWR per E05, LL/SC per SPEC 2.2), upper immediates,
  `RDHWR $29` (returns `ulr`), traps (TEQ/TNE/TGE/TLT + immediates →
  `mips_fault` when the condition fires), cache/pref (NOP), MFC0/DMFC0 only
  for the wired registers (`ulr` alias; others → `mips_fault`).
  `interp.h` holds lane-internal helpers only. No FP/COP1 (Phase 3 → fault).
- **Acceptance Command**:
  ```sh
  cc -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror -Iinclude -Isrc -c src/interp/interp.c -o /tmp/interp.o
  ```
  (Full execution is the RC1 gate after all lanes merge; report it deferred.)

---

### Lane `L1c` — Guest Memory + Minimal Syscall Layer
- **Worktree**: `../mips32rt-l1c` on branch `lane/p1-l1c`
- **Exclusive Files**: `src/os/mem.c`, `src/os/syscall_min.c`
- **Task**:
  1. `src/os/mem.c`: `guest_mem_init` (reserve `[G, G+4GiB)` via the
     `src/rt32/` window helpers on master; `G` dynamic standalone),
     endianness-aware `guest_ld/st8/16/32` with alignment faults for
     16/32-bit accesses and `MIPS_FAULT` on unmapped pages; `mips_fault`
     (record `EXIT_FAULT`, stash fault addr in `exit_info`).
  2. `src/os/syscall_min.c`: `mips_syscall` implementing SPEC 2.3
     for `exit`, `exit_group`, `write`, `read`, `brk`, `mmap`/`mmap2`,
     `munmap`, `mprotect`, `uname`, `set_tid_address` (numbers from
     `src/os/syscall_nr.h`); stack args 5..8 at `sp+16..sp+28` per E01;
     64-bit pair alignment per E01; `$a3` convention; unknown syscall →
     `-ENOSYS` with `$a3=1`.
- **Acceptance Command**:
  ```sh
  cc -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror -Iinclude -Isrc -c src/os/mem.c -o /tmp/mem.o && cc -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror -Iinclude -Isrc -c src/os/syscall_min.c -o /tmp/syscall_min.o
  ```
  (Execution is the RC1 gate; report it deferred.)

---

### Lane `L1d` — Freestanding ISA Test Suite + QEMU Goldens
- **Worktree**: `../mips32rt-l1d` on branch `lane/p1-l1d`
- **Exclusive Files**: `tests/test_p1_isa.c`, `tests/run_p1_isa.sh`, `tests/p1_golden_*.txt`
- **Task**:
  1. Write `tests/test_p1_isa.c`: freestanding C + MIPS inline asm,
     `-static`, covering ALU/shifts/MULT/DIV, all branch types with delay
     slots (taken + not-taken), branch-likely annul at `page_end - 4`
     before a `PROT_NONE` page (E02 pattern), `JALR`/`JR`, `LL`/`SC`
     (success + interference-failure), `LWL`/`LWR`/`SWL`/`SWR` all
     alignments (E05), `RDHWR`, a deliberate unaligned-`LW` fault case in
     a child process (expect 139 without killing the suite), and a raw
     `write`+`exit` path. Prints `P1-RESULT: PASS` + per-check lines.
  2. Write `tests/run_p1_isa.sh`: cross-compiles LE (`mipsel-linux-gnu-gcc
     -march=mips32r2 -static`) and BE (`mips-linux-gnu-gcc -EB ...`),
     runs each under `qemu-mipsel`/`qemu-mips` with
     `timeout --kill-after=30s 60s`, captures stdout+exit into
     `tests/p1_golden_le.txt` / `tests/p1_golden_be.txt` (BE: best effort,
     mark missing coverage honestly).
- **Acceptance Command**:
  ```sh
  sh tests/run_p1_isa.sh && test -s tests/p1_golden_le.txt
  ```
