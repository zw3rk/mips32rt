# Phase 2 Task Cards — Static Libc Syscalls & Base Integer AArch64 DBT (`mips32rt`)

Run after `RC1` is merged to `master`. Frozen contracts: `src/mips32rt.h`
"Phase 2 frozen DBT contracts" (`dbt_block_t`, `dbt_lookup`/`dbt_compile`,
`dbt_emit_int`, `mips_dump_regs`, `MIPS32_DBT_MAX_INSNS 64`,
`MIPS32_IBTC_SIZE 4096`), the SPEC 2.1 host GPR map (`w0..w15`, `x19=xCtx`,
`x20=xG`, `x21..x24` scratch, **never `x18`**), and the Phase 1 contracts.
`a64_emit.h` on master is the only encoder (no new emitter framework).

Shared rules: curated C11, every file ≤ 900 lines, W^X + I-cache
discipline for emitted code, no AI/agent names. RC2 integration (by the
coordinator after all lanes merge): drop the `dbt_main` stub from
`src/main.c` (L2b provides the real one), wire `Makefile` if needed
(`SRCS` wildcard already covers `src/dbt/*.c` + `src/os/*.c`), build,
run `--difftest`.

---

### Lane `L2a` — Complete Static-Libc Syscall & Struct Layer
- **Worktree**: `../mips32rt-l2a` on branch `lane/p2-l2a`
- **Exclusive Files**: `src/os/syscalls.c`, `src/os/syscall_nr.h`, `src/os/syscall_min.c` (extend `mips_syscall` switch only)
- **Task**:
  1. Extend `src/os/syscall_nr.h` with the O32 numbers L1c omitted (verify
     each against `/usr/mipsel-linux-gnu/include/asm/unistd.h` in the
     Debian container and cite the header): `openat`, `fcntl`/`fcntl64`,
     `clock_gettime`, `getrandom`, `futex`, `rt_sigprocmask`,
     `rt_sigaction` (Phase-4 delivery arrives later; record ENOSYS-proof
     behavior honestly), `ioctl`, `lseek`/`llseek`, `stat` family
     (`stat64`/`lstat64`/`fstat64`/`fstatat64` + `statx`), `getdents64`,
     `readlink`/`readlinkat`, `access`, `pipe`/`pipe2`, `dup`/`dup2`,
     `close_range`, `nanosleep`, `getpid`/`getppid`/`getuid` family,
     `set_robust_list`/`get_robust_list`, `exit` already covered.
  2. New `src/os/syscalls.c`: struct conversions with MIPS layout
     (`stat64` 104 B, `statx`, `iovec`, open flags per E01 `O_*`, socket
     constants per SPEC 2.3) + handlers wired through an extended
     `mips_syscall` switch (minimal edit to `syscall_min.c` dispatch).
     Unknown syscalls keep `-ENOSYS` with `$a3=1`.
- **Acceptance Command**:
  ```sh
  cc -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror -Iinclude -Isrc -c src/os/syscalls.c -o /tmp/syscalls.o && cc -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror -Iinclude -Isrc -c src/os/syscall_min.c -o /tmp/syscall_min.o
  ```
  (Execution is the RC2 gate; report it deferred.)

---

### Lane `L2b` — AArch64 DBT Core (dispatcher, block cache, IBTC, trampoline)
- **Worktree**: `../mips32rt-l2b` on branch `lane/p2-l2b`
- **Exclusive Files**: `src/dbt/dbt.c`, `src/dbt/dbt.h`, `src/dbt/trampoline_a64.S`
- **Task**:
  1. `src/dbt/dbt.c`: `dbt_main` engine loop, `dbt_lookup` (direct
     chaining + 4096-entry IBTC keyed by guest PC + RAS), `dbt_compile`
     (fetch via `mips_fetch`, decode via `mips_decode`, stop at control
     transfers / 64-insn cap / page crossing per SPEC 2.2; delegate
     emission to frozen `dbt_emit_int`; W^X publish + `__builtin___clear_cache`;
     `EXIT_UNDEF`/`EXIT_SINGLE_STEP` fall back to `interp_step` then
     resume; FP/COP1 arithmetic blocks fall back to `interp_step` until
     Phase 3). `ctx->ibtc_ptr` owns the table; `smc_version` from page
     versioning (bump on `mprotect`/`munmap`/guest writes to translated
     pages; invalidate on mismatch).
  2. `src/dbt/trampoline_a64.S`: host entry/exit (save/restore callee-saved,
     set `x19=xCtx`, `x20=xG`, dispatch to block code, exit-reason return).
     Never read/write `x18`.
  3. `src/dbt/dbt.h`: lane-internal cache/RAS/trampoline declarations.
- **Acceptance Command** (cross compile check, no link):
  ```sh
  nix shell nixpkgs#pkgsCross.aarch64-multiplatform-musl.stdenv.cc -c aarch64-unknown-linux-musl-gcc -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror -Iinclude -Isrc -Isrc/rt32 -c src/dbt/dbt.c -o /tmp/dbt.o
  ```
  (Execution is the RC2 gate; report it deferred. RC2 integration drops
  the `dbt_main` stub from `src/main.c`.)

---

### Lane `L2c` — AArch64 Integer Instruction Emitter
- **Worktree**: `../mips32rt-l2c` on branch `lane/p2-l2c`
- **Exclusive Files**: `src/dbt/emit_int.c`
- **Task**: Implement frozen `dbt_emit_int` with `a64_emit.h` only: ALU
  (ADD/ADDU/SUB/SUBU/AND/OR/XOR/NOR/SLT/SLTI*/LUI), shifts, MULT/MULTU/
  DIV/DIVU + MFHI/MFLO/MTHI/MTLO, branches/jumps + likely-annul (delay
  slot emitted inline; link `ra=pc+8`), loads/stores (aligned fast path
  + LWL/LWR/SWL/SWR byte merge + LL/SC via host atomics with `llbit`
  semantics), J/JAL/JALR direct chaining hooks, SYSCALL/BREAK/traps as
  exits to the dispatcher, RDHWR/`ulr`, cache/pref NOPs, unknown/FP ops
  as `EXIT_UNDEF`. Respect the SPEC 2.1 GPR map; spill non-cached GPRs
  to `[x19, #off]`; `$0` reads as `wzr` and writes are dropped.
- **Acceptance Command**: same cross `-c` check as L2b for
  `src/dbt/emit_int.c` (execution is the RC2 gate; report it deferred).

---

### Lane `L2d` — Difftest Harness + Static Libc Test Suite
- **Worktree**: `../mips32rt-l2d` on branch `lane/p2-l2d`
- **Exclusive Files**: `tests/difftest/**`
- **Task**:
  1. `tests/difftest/run_d2.sh`: builds fixtures `test_d2_{hello,printf,malloc,qsort,fileio}.c`
     (static, LE+BE) with the Debian cross toolchains in a bounded
     container (unique `--name`, `--memory 2g --cpus 2`,
     `timeout --kill-after=30s`, `docker ps` cleanup check); runs each
     under `qemu-mipsel`/`qemu-mips` capturing stdout+exit into
     `tests/difftest/golden_*`; runs each under `--interp` and requires
     stdout+exit identical to golden (the dbt half runs at RC2).
  2. `tests/difftest/run_difftest.sh`: runs a guest under `--interp
     --trace` and `--dbt --trace` (plus `MIPS32RT_DUMPSTATE=1` exit
     dumps), diffs the `pc+word` streams and the `REGS` dumps, prints
     `DIFFTEST: 0 divergences` or the first divergence. Must already
     work interp-vs-interp (self-consistency); interp-vs-dbt goes live
     at RC2.
- **Acceptance Command**:
  ```sh
  sh tests/difftest/run_d2.sh && test -s tests/difftest/golden_le_hello.txt
  ```
