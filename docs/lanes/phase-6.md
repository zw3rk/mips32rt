# Phase 6 Task Cards — `hyper-linux` Host Contract & Dual-Host Parity (`mips32rt`)

Run after `RC5` is merged to `master`. Frozen contracts: `src/mips32rt.h`,
`include/a32host.h` (byte-identical), `src/os/syscall_nr.h`, `Makefile`,
SPEC 1.1 (window) + `../rt-series/docs/HOST-CONTRACT.md` (A32H_ABI 1.0/1.1).
The `/dev/a32host` probe (`src/rt32/host.c`), `MIPS32RT_WINDOW`/`MIPS32RT_HOST`
env handling, and `--window`/`--sysroot`/`--cache`/`--engine` flags exist;
`--execfn`/`--image-fd`/`AT_EXECFD` handling does not yet.

Shared rules: curated C11, every file ≤ 900 lines, no `x18`, W^X kept,
no AI/agent names. RC6 integration by the coordinator after all lanes
merge; `t-` tests keep passing on `interp` + `dbt`.

---

## Lane `L6a` — CLI/`auxv` Descriptor Contract + `a32host` Negotiation
- **Worktree**: `../mips32rt-l6a` on branch `lane/phase-6-l6a`
- **Exclusive Files**: `src/main.c` (CLI only), `src/rt32/host.c` (probe only), `src/rt32/vm.c` (window/G only), `tests/p6_host_check.sh` (new)
- **Task**:
  1. `src/main.c`: add `--execfn PATH` (sets `exec_path`, remaining args become guest `argv` verbatim incl. custom `argv[0]`) and `--image-fd FD` (load ELF from the open descriptor, `close()` after mapping; never touch fds `0,1,2` or caller fds otherwise); without `--execfn`, `argv[i]` stays both path and `argv[0]`.
  2. `src/main.c`: `AT_EXECFD` detection via `errno`-checked `getauxval(AT_EXECFD)` (or raw auxv scan); a value of `0` with `errno == 0` is a valid fd. Prefer `--image-fd` over auxv; close the loader-private fd after mapping.
  3. `src/rt32/host.c` + `src/rt32/vm.c`: verify `/dev/a32host` `A32H_GET_INFO` negotiation, `window_hint` handling, `G = 0` default and `G = 0x1_0000_0000` selection path (`--window`/`MIPS32RT_WINDOW`), `MIPS32RT_HOST=none` skip; fix gaps found.
  4. `tests/p6_host_check.sh`: exercise no-device fallback, `MIPS32RT_HOST=none`, `--window`, `--execfn` custom `argv[0]`, `--image-fd` load, and `AT_EXECFN` presence; all PASS.
- **Acceptance Command**: `sh tests/p6_host_check.sh` exit 0 in the lane worktree.

---

## Lane `L6b` — Full Parity Suite + Adjacent 4 KiB Page Permissions
- **Worktree**: `../mips32rt-l6b` on branch `lane/phase-6-l6b`
- **Exclusive Files**: `tests/run_p6.sh` (new), `tests/test_p6_perms.c` (new)
- **Task**:
  1. `tests/test_p6_perms.c`: adjacent 4 KiB pages with distinct permissions (`PROT_READ|PROT_EXEC` next to `PROT_READ|PROT_WRITE`, `PT_GNU_RELRO`-style RX-then-RW split); guest faults land exactly on the guarded page with the right `si_code`/`PROT_NONE` behavior on `interp` + `dbt`, LE+BE; qemu goldens.
  2. `tests/run_p6.sh`: re-run `test_p1_isa`, `test_p3_fpu`, `test_p4_threads_signals`, `test_p5_dyn` + BusyBox probe under `--interp` and `--dbt`, LE+BE, vs qemu goldens with `0` divergences; invoke L6a's `tests/p6_host_check.sh`.
- **Acceptance Command**: `sh tests/run_p6.sh` exit 0 in the lane worktree.

---

## RC6 gate (coordinator, after all lanes merge)

1. Merge L6a/L6b (`--no-ff`), wire dispatch, cross-build.
2. Re-run `tests/p6_host_check.sh`, `tests/run_p6.sh`, plus P1/P3/P4/P5 gates on both engines × LE+BE with `0` divergences.
