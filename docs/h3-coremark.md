# H3 — CoreMark 6-Step Loop (`docs/h3-coremark.md`)

Lane `phase-7-h3`, branch `lane/phase-7-h3`. Workload: `h3_coremark_mini`
(CoreMark method: linked-list traversal, 16x16 int16 matrix multiply,
8-state table-driven state machine with CRC, fixed seeds, `iters=200`,
3 repetitions). Guest sources live in gitignored `_build/h3src/` scratch,
never as repo files. All guest runs happen in one bounded container
(`debian:bookworm-slim`, `--memory 2g --cpus 2`, `--platform linux/arm64`,
per-command `timeout`, unique `--name mips32rt-h3-$$`, `docker ps`
cleanup check). Translator built on the host with the project nix cross
toolchain (`aarch64-unknown-linux-musl-gcc`, static-PIE). Oracle:
`qemu-mipsel 7.2.22`. Scope: LE only (`mipsel`).

## Step 1 — Instrument

- Wall-clock timing around each engine run (`date +%s%N` before/after,
  nanosecond resolution, guest stdout redirected to a file).
- Correctness gates per run: stdout `cmp` against the qemu golden, plus
  `tests/difftest/run_difftest.sh <guest> interp dbt` (0 divergences).
- `strace -c -f` syscall profiles of the translator under `--dbt`.

## Step 2 — Measure (baseline, commit `0070f0b` + rebuild)

Golden CRC (qemu, interp, dbt identical): `crc=c5dc007b`.

| rep | interp (ns) | dbt (ns) |
| --- | --- | --- |
| 1 | 216919209 | 2211225751 |
| 2 | 237092833 | 3116135251 |
| 3 | 243645125 | 2550393460 |

Baseline: interp mean ~232 ms, dbt mean ~2626 ms. **dbt is ~11x SLOWER
than interp** — the opposite of the expected result, which is what the
rest of the loop addresses. `strace -c` of a 20-iteration dbt run:

- `rt_sigprocmask`: 107057 calls, 95.9% of syscall time.
- `mprotect`: 1738 calls (one-time W^X publishes at compile time).

Code reading confirmed two further per-dispatch linear scans: a
1024-slot `dbt_smc_version` table scan inside every `dbt_lookup`, and a
`block_count`-slot rescan in `dbt_main` recovering block metadata the
lookup had just resolved.

## Step 3 — Hypothesise

Per-block dispatch overhead dominates, not guest execution:

1. `mips_hostfault_run` calls `sigsetjmp(hf_jb, 1)` per block; `savemask=1`
   costs one `rt_sigprocmask` syscall per dispatched block (~5,350
   blocks/iteration here).
2. `dbt_smc_version` scans all 1024 SMC slots per lookup (table is empty
   in practice — always a full-scan miss).
3. `dbt_main` rescans up to 1024 `blocks[]` entries per dispatch to
   recover `(b, bi)` the lookup already knew.

## Step 4 — Fix (translator, no frozen files touched)

- `src/os/hostfault.c` — `sigsetjmp(hf_jb, 1)` to `sigsetjmp(hf_jb, 0)`
  with a rationale comment. Safe because the host signal mask is
  invariant across the armed window: the handler is installed with
  `SA_NODEFER` and an empty `sa_mask` (delivery never alters the mask),
  and neither the trampoline nor emitted code issues mask-changing
  calls — so save/restore is pure overhead.
- `src/dbt/dbt.c` — `dbt_smc_version` memoizes the last `(page, version)`
  resolution (invalidated by `dbt_smc_bump` and `dbt_flush_all`, so SMC
  wiring stays correct).
- `src/dbt/dbt.c` + `src/dbt/dbt.h` — the lookup carries the block index:
  new static `dbt_lookup_bi` (+ `blk_idx` in the IBTC slot, `last_bi` in
  the cache), frozen `dbt_lookup` kept as a discarding wrapper;
  `dbt_main` validates the carried index instead of rescanning.

## Step 5 — Measure again (same container, same guest, same reps)

Golden CRC unchanged: `crc=c5dc007b` on every run.

| rep | interp (ns) | dbt (ns) | dbt speedup vs interp |
| --- | --- | --- | --- |
| 1 | 190983209 | 65601125 | 2.91x |
| 2 | 223667958 | 68839875 | 3.25x |
| 3 | 227066875 | 75466375 | 3.01x |

dbt mean 70.0 ms vs interp mean 213.9 ms (**~3.1x faster**), and ~37x
faster than the pre-fix dbt mean (2626 ms). Throughput at `iters=200`:
dbt ~2857 iters/s vs interp ~935 iters/s. `strace -c` confirms
`rt_sigprocmask` dropped from 107057 calls to 1 per run; `mprotect`
count unchanged (compile-time only).

## Step 6 — Validate

- qemu golden `cmp`: byte-identical stdout on all 6 post-fix runs.
- `run_difftest.sh h3cm-le interp dbt`: **0 divergences**.
- `run_difftest.sh` on a second guest (`test_d2_qsort`): **0 divergences**.
- `tests/run_p1_isa.sh` regression (covers the edited dispatcher/guard
  on both engines): **55 pass / 0 fail on LE and BE**.
- `make check-line-limits`: pass (every `.c/.h/.S` <= 900 lines).
- `make check` host-link step fails identically on the clean base
  commit (verified via `git stash`; missing `mips_fetch` in the
  macOS-host test link) — pre-existing, unrelated to this lane.

## Acceptance

Report exists with measured numbers: **dbt ~3.1x faster than interp**
(70.0 ms vs 213.9 ms mean, `iters=200`, 3 reps, LE, bounded container),
with golden + difftest parity at 0 divergences.
