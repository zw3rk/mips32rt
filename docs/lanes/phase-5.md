# Phase 5 Task Cards — Dynamic Linking (`PT_INTERP`), `BusyBox` (`mips32rt`)

Run after `RC4` is merged to `master`. Frozen contracts: `src/mips32rt.h`,
`include/a32host.h`, `src/os/syscall_nr.h`, `Makefile`, SPEC 1.1 (window) +
3.x (dynamic). Loader skeleton exists (`PT_INTERP` detected in
`src/rt32/elf32.c`, minimal auxv in `src/rt32/stack32.c`); Phase 5 makes
dynamically linked MIPS ELFs run.

Shared rules: curated C11, every file ≤ 900 lines, no `x18`, W^X kept,
no AI/agent names. RC5 integration by the coordinator after all lanes
merge; P1/P3/P4 suites are re-run with live dynamic binaries.

---

### Lane `L5a` — `PT_INTERP` Loader, Full auxv, `/proc/self/*` (`ld.so`)
- **Worktree**: `../mips32rt-l5a` on branch `lane/phase-5-l5a`
- **Exclusive Files**: `src/rt32/elf32.c` (`PT_INTERP` only), `src/rt32/stack32.c` (auxv only), `src/os/proc.c` (`/proc` interception only), `tests/run_p5.sh` (gate harness)
- **Task**:
  1. `src/rt32/elf32.c`: load the `PT_INTERP` interpreter (`ld.so`) into
     the window at a non-colliding base, apply its `PT_LOAD` segments with
     correct `PROT_*`, resolve `AT_BASE`; entry point becomes the
     interpreter entry with the exe base/offset communicated via auxv.
  2. `src/rt32/stack32.c`: complete auxiliary vector (`AT_PHDR`,
     `AT_ENTRY`, `AT_BASE`, `AT_HWCAP`, `AT_HWCAP2`, `AT_RANDOM`,
     `AT_EXECFN`, `AT_UID`/`AT_EUID`/`AT_GID`/`AT_EGID`, `AT_PAGESZ`,
     `AT_CLKTCK`, `AT_FLAGS`); `AT_RANDOM` 16 bytes on the stack.
  3. `src/os/proc.c`: intercept `/proc/self/{exe,maps,cmdline,stat,auxv}`
     (`open`/`openat`/`readlink` path rewrite to translator-generated
     content matching the guest view: exe = guest path, maps = window
     VMAs, auxv = the stack auxv).
  4. `tests/run_p5.sh`: build LE+BE dynamic `test_p5_dyn`, qemu goldens,
     run `interp`+`dbt`, `exec-probe` style fork/exec check, difftest.
- **Acceptance Command**: `sh tests/run_p5.sh` exit 0 in the lane
  worktree (qemu goldens + interp/dbt + difftest all PASS).

---

### Lane `L5b` — Dynamic `test_p5_dyn` + Target `BusyBox` Suite
- **Worktree**: `../mips32rt-l5b` on branch `lane/phase-5-l5b`
- **Exclusive Files**: `tests/test_p5_dyn.c` (new), `tests/run_p5_busybox.sh` (new)
- **Task**:
  1. `tests/test_p5_dyn.c`: dynamic `dlopen`/`dlsym` (own `.so` helper
     built alongside), `__thread` TLS access, shared-library calls
     (`printf`/`qsort` via target libc), `argv`/`envp`/`auxv` self-check
     (`getauxval(AT_ENTRY)` == `&_start`-adjacent main entry).
  2. `tests/run_p5_busybox.sh`: build static + dynamic MIPS BusyBox via
     the lane container toolchain, run `sh -c 'ls / && echo ok | wc -c'`
     under qemu (golden), `interp`, `dbt`; byte-identical stdout.
- **Acceptance Command**: `sh tests/run_p5_busybox.sh` exit 0 in the
  lane worktree (static + dynamic BusyBox PASS on both engines).

---

## RC5 gate (coordinator, after all lanes merge)

1. Merge L5a/L5b (`--no-ff`), wire dispatch, cross-build.
2. Re-run `tests/test_p1_isa`, `tests/test_p3_fpu`, `tests/test_p4_threads_signals` under `--interp` and `--dbt`, LE+BE (dynamic libc now live; no new SKIPs).
3. New `tests/test_p5_dyn` + BusyBox match `qemu-mipsel (and qemu-mips for BE)` on both `interp` and `dbt` with `0` difftest divergences.
