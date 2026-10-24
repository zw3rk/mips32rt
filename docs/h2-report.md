# H2 Report — `libc-test` Categories + LTP Syscall Subset (`interp` + `dbt`, LE+BE)

**Verdict: gate green — 0 unexpected failures.**
Machine-enforced container summary (gate exit 0):

```text
H2-SUMMARY: pass=50 xfail=10 fail=0 total=60 (want pass=50 xfail=10 fail=0 total=60)
H2: gate green — no unexpected failures
```

Assertion classes: `GOLDEN` 12 (qemu oracle passes every probe),
`GREEN` 14 (translator byte-identical to golden), `GAP` 10 (documented
failure signatures reproduced exactly), `PARITY` 12 (`interp` stdout ==
`dbt` stdout), `DT` 12 (`run_difftest.sh` exit 0). The gate fails on any
deviation: a new failure, a fixed gap, or a drifted line all break it.

## Environment

- Lane worktree `../mips32rt-h2`, branch `lane/phase-7-h2`, base `0070f0b`.
- Translator `_build/mips32rt` (static-PIE AArch64, cross-built on the host:
  `nix shell nixpkgs#pkgsCross.aarch64-multiplatform-musl.stdenv.cc -c make clean build CC=aarch64-unknown-linux-musl-gcc`).
- Container `debian:bookworm-slim`, `--platform linux/arm64`,
  `--name mips32rt-h2-57675`, `--memory 2g --cpus 2`, per-command
  `timeout --kill-after=30s 120s`; removed afterwards with empty
  `docker ps` for the name.
- In-container toolchains: `qemu-user` (+ `qemu-mipsel`, `qemu-mips`),
  `gcc-mipsel-linux-gnu`, `gcc-mips-linux-gnu`,
  `libc6-dev-mipsel-cross`, `libc6-dev-mips-cross` (glibc 2.36 static).
- Guests: 6 static probes (`-march=mips32r2`, LE+BE), sources generated
  into gitignored `_build/h2src/` scratch (never committed).

## Results matrix (qemu golden / interp / dbt, LE+BE)

| Probe (category) | qemu LE/BE | interp LE/BE | dbt LE/BE | Class |
|---|---|---|---|---|
| `h2math` (libc-test math: trig/exp/pow/NaN/Inf) | PASS | identical | identical | GREEN |
| `h2str` (libc-test string: memcpy/memmove/strcmp/strstr) | PASS | identical | identical | GREEN |
| `h2thr` (libc-test pthread: join/mutex/cond/TLS/once) | PASS | identical | identical | GREEN |
| `h2sig` (libc-test sig) | PASS | exact gap G1 | exact gap G1 | GAP |
| `h2fun` LE (libc-test functional) | PASS | identical | identical | GREEN |
| `h2fun` BE (libc-test functional) | PASS | exact gap G2 | exact gap G2 | GAP |
| `h2ltp` LE (LTP subset: 16 groups) | PASS | exact gaps G3+G4+G5 | exact gaps G3+G4+G5 | GAP |
| `h2ltp` BE (LTP subset: 16 groups) | PASS | exact gaps G2+G3+G4+G5 | exact gaps G2+G3+G4+G5 | GAP |

`PARITY`: all 12 `interp`-vs-`dbt` stdout pairs byte-identical (LE+BE,
including the gap guests: identical failure output on both engines).

## Documented gaps (expected; each breaks the gate if fixed or drifted)

- **G1 — `kill` family undispatched (`h2sig` raise/pending/delivered).**
  `kill` (4037) is declared in `src/os/syscall_nr.h` but has no
  `src/os/syscalls.c` dispatch case (`tgkill`/`tkill` absent too), so
  `raise()` falls to the `-ENOSYS` default. Runtime: `raise(SIGUSR1)`
  returns `-1`/`errno 89` (MIPS ENOSYS per `syscalls.c`), handler never
  runs, on both engines × LE+BE; qemu delivers (`g=1`). `rt_sigaction`
  / `rt_sigprocmask` themselves pass.
- **G2 — BE `getdents64` without endian conversion (`h2fun`/`h2ltp` BE
  `readdir`).** `mips_sc_getdents64` passes the host `linux_dirent64`
  records through raw; correct on LE by identity, garbage `d_reclen`
  on BE so `readdir` stops at 0 entries (LE 113 entries vs BE 0 on the
  same `/tmp`). LE passes on both engines.
- **G3 — `pipe` returns the fd in `$v0` (`h2ltp` pipe, pipe2).**
  `sc_pipe` sets `$v0=fds[0]` (observed guest `rc=3` with valid fds
  3,4) while O32/glibc expects `ret=0` with fds via the array and
  `$v1` (SPEC 2.3: `$v0=(uint32_t)ret`, `$v1=pipefd[1]`).
- **G4 — `clock_nanosleep` unimplemented (`h2ltp` clock-nanosleep).**
  glibc `nanosleep()` emits `clock_nanosleep` (O32 4267; confirmed by
  `qemu-mipsel -strace`), which has no `syscall_nr.h` entry and no
  dispatch case; the existing `mips_sc_nanosleep` (4166) is never
  reached. Guest gets `-ENOSYS`/89 on LE+BE, both engines.
- **G5 — `symlink`/`symlinkat` unimplemented (`h2ltp`
  symlink-readlink).** No dispatch case and no `syscall_nr.h` entry;
  guest gets `-ENOSYS`/89 on LE+BE, both engines. (`readlink` itself
  works; only the create path is missing.)

## Harness observation (not gated; for the coordinator)

`tests/difftest/run_difftest.sh` prints `--- trace divergence ---`
hunks yet still reports `DIFFTEST: 0 divergences`: it counts
`grep -c '^[<>]'` over `diff -u` output, whose change markers are
`+`/`-`. Only the exit-code comparison is effective (observed on the
threaded and LTP guests). The 12 `PARITY` byte-equality checks above
carry the interp-vs-dbt claim independently of that script.

## Reproduction

Rebuild the translator as above, then in the lane worktree run the
bounded gate (unique `--name mips32rt-h2-$$`, `--memory 2g --cpus 2`,
per-command timeouts, `docker ps` cleanup check); it exits 0 only with
`pass=50 xfail=10 fail=0 total=60`. Probes and the gate script live in
gitignored `_build/h2src/`; this report is the lane's committed artifact.
