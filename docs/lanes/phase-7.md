# Phase 7 Task Cards — Hardening (`SMC`, `libc-test` + LTP, CoreMark, C++17) (`mips32rt`)

Run after `RC6` is merged to `master`. Frozen contracts: `src/mips32rt.h`,
`include/a32host.h` (byte-identical), `src/os/syscall_nr.h`, `Makefile`,
SPEC 1.1 (window) + `../rt-series/docs/HOST-CONTRACT.md` (A32H_ABI 1.0/1.1).
`--execfn`/`--image-fd`/`AT_EXECFD`, `/dev/a32host` negotiation, and the
full P1/P3/P4/P5/P6 parity suite exist; Phase 7 hardens the translator.

Shared rules: curated C11, every file ≤ 900 lines, no `x18`, W^X kept,
no AI/agent names. RC-H integration by the coordinator after all lanes
merge; P1/P3/P4/P5/P6 suites keep passing on `interp` + `dbt`.

---

## Lane `H1` — Self-Modifying Code & W^X (`test_h1_smc.c`)
- **Worktree**: `../mips32rt-h1` on branch `lane/phase-7-h1`
- **Exclusive Files**: `tests/test_h1_smc.c` (new)
- **Task**:
  1. `tests/test_h1_smc.c`: rewrite guest instructions on stack/heap/anon
     `mmap`, flush cache (`clear_cache`/`SYNCI`), re-execute under `dbt`;
     `mprotect`/`munmap` page-version invalidation; W^X probe (guest data
     pages never `PROT_EXEC` on the host); LE+BE, `interp` + `dbt`, qemu
     goldens with `0` divergences.
- **Acceptance Command**: `sh tests/run_h1_smc.sh` exit 0 in the lane
  worktree (or the documented single bounded container command if the
  harness is folded into `run_p6.sh` style).

---

## Lane `H2` — `libc-test` + LTP Syscall Subset (`docs/h2-report.md`)
- **Worktree**: `../mips32rt-h2` on branch `lane/phase-7-h2`
- **Exclusive Files**: `docs/h2-report.md` (new)
- **Task**:
  1. Run target `libc-test` (math, string, pthread, sig, functional) and
     the LTP syscall subset under `qemu-mipsel (and qemu-mips for BE)`,
     `interp`, `dbt`; commit `docs/h2-report.md` with machine-enforced
     pass/skip/fail assertions (`0` unexpected failures).
- **Acceptance Command**: bounded container `libc-test` + LTP run exit 0
  in the lane worktree with `docs/h2-report.md` committed.

---

## Lane `H3` — Instrumented CoreMark 6-Step Loop (`docs/h3-coremark.md`)
- **Worktree**: `../mips32rt-h3` on branch `lane/phase-7-h3`
- **Exclusive Files**: `docs/h3-coremark.md` (new)
- **Task**:
  1. Follow the mandatory 6-step loop (Instrument -> Measure ->
     Hypothesise -> Fix -> Measure again -> Validate) on CoreMark;
     commit `docs/h3-coremark.md` demonstrating verified `dbt > interp`
     throughput with measured numbers.
- **Acceptance Command**: bounded container CoreMark run exit 0 in the
  lane worktree with `docs/h3-coremark.md` committed.

---

## Lane `H4` — C++17 Exceptions/RTTI/TLS (`test_h4_cxx17.cc`)
- **Worktree**: `../mips32rt-h4` on branch `lane/phase-7-h4`
- **Exclusive Files**: `tests/test_h4_cxx17.cc` (new)
- **Task**:
  1. `tests/test_h4_cxx17.cc`: compile and verify a C++17 binary
     exercising `try`/`catch` stack unwinding across signal/call frames,
     `dynamic_cast` RTTI, `std::thread`, and `thread_local` destructors;
     LE+BE, `interp` + `dbt`, qemu goldens with `0` divergences.
- **Acceptance Command**: bounded container C++17 run exit 0 in the lane
  worktree.

---

## RC-H gate (coordinator, after all lanes merge)

1. Merge H1..H4 (`--no-ff`), wire dispatch, cross-build.
2. Re-run `tests/p6_host_check.sh`, `tests/run_p6.sh`, plus H1/H4 gates
   on both engines × LE+BE with `0` divergences.
3. `docs/h2-report.md` shows `0` unexpected failures; `docs/h3-coremark.md`
   shows measured `dbt > interp` speedup.
4. `make check` and `make check-line-limits` pass with a clean git tree.
