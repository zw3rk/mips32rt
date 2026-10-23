# Phase E Task Cards — Empirical Pre-Implementation Experiments (`mips32rt`)

Spawn **concurrent `subagent` worker lanes** for `E01..E06` in isolated worktrees (`../mips32rt-e01` .. `../mips32rt-e06`), merge each into `master`, and verify `RC-E`.

---

### Lane `E01` — O32 Syscall Stack Args 5..8 & `$a3` Error Flag
- **Worktree**: `../mips32rt-e01` on branch `lane/pe-e01`
- **Exclusive Files**: `experiments/E01/**`
- **Task**:
  1. Write a minimal Curated C11 / inline-assembly probe in `experiments/E01/probe.c` (and `Makefile` or `run.sh`).
  2. Cross-compile for `MIPS32r2 (`mipsel` LE & `mips` BE, O32 ABI)` and run under `qemu-mipsel (and qemu-mips for BE)` (with `timeout --kill-after=30s 60s`).
  3. Record exact empirical findings, byte offsets (`sizeof`/`offsetof`), register values, and instruction encodings in `experiments/E01/FINDINGS.md`.
- **Acceptance Command**:
  ```sh
  test -s experiments/E01/FINDINGS.md
  ```

### Lane `E02` — Delay-Slot, Branch-Likely (`BEQL`) Annul & Page-End Faults
- **Worktree**: `../mips32rt-e02` on branch `lane/pe-e02`
- **Exclusive Files**: `experiments/E02/**`
- **Task**:
  1. Write a minimal Curated C11 / inline-assembly probe in `experiments/E02/probe.c` (and `Makefile` or `run.sh`).
  2. Cross-compile for `MIPS32r2 (`mipsel` LE & `mips` BE, O32 ABI)` and run under `qemu-mipsel (and qemu-mips for BE)` (with `timeout --kill-after=30s 60s`).
  3. Record exact empirical findings, byte offsets (`sizeof`/`offsetof`), register values, and instruction encodings in `experiments/E02/FINDINGS.md`.
- **Acceptance Command**:
  ```sh
  test -s experiments/E02/FINDINGS.md
  ```

### Lane `E03` — `FR=0` vs `FR=1` & Legacy vs 2008 NaN/ABS FPU Semantics
- **Worktree**: `../mips32rt-e03` on branch `lane/pe-e03`
- **Exclusive Files**: `experiments/E03/**`
- **Task**:
  1. Write a minimal Curated C11 / inline-assembly probe in `experiments/E03/probe.c` (and `Makefile` or `run.sh`).
  2. Cross-compile for `MIPS32r2 (`mipsel` LE & `mips` BE, O32 ABI)` and run under `qemu-mipsel (and qemu-mips for BE)` (with `timeout --kill-after=30s 60s`).
  3. Record exact empirical findings, byte offsets (`sizeof`/`offsetof`), register values, and instruction encodings in `experiments/E03/FINDINGS.md`.
- **Acceptance Command**:
  ```sh
  test -s experiments/E03/FINDINGS.md
  ```

### Lane `E04` — O32 `rt_sigframe` Layout & 128-Signal (`sigsetsize=16`) UAPI
- **Worktree**: `../mips32rt-e04` on branch `lane/pe-e04`
- **Exclusive Files**: `experiments/E04/**`
- **Task**:
  1. Write a minimal Curated C11 / inline-assembly probe in `experiments/E04/probe.c` (and `Makefile` or `run.sh`).
  2. Cross-compile for `MIPS32r2 (`mipsel` LE & `mips` BE, O32 ABI)` and run under `qemu-mipsel (and qemu-mips for BE)` (with `timeout --kill-after=30s 60s`).
  3. Record exact empirical findings, byte offsets (`sizeof`/`offsetof`), register values, and instruction encodings in `experiments/E04/FINDINGS.md`.
- **Acceptance Command**:
  ```sh
  test -s experiments/E04/FINDINGS.md
  ```

### Lane `E05` — `LWL`/`LWR` & `SWL`/`SWR` Unaligned Semantics (`mipsel` & `mips` BE)
- **Worktree**: `../mips32rt-e05` on branch `lane/pe-e05`
- **Exclusive Files**: `experiments/E05/**`
- **Task**:
  1. Write a minimal Curated C11 / inline-assembly probe in `experiments/E05/probe.c` (and `Makefile` or `run.sh`).
  2. Cross-compile for `MIPS32r2 (`mipsel` LE & `mips` BE, O32 ABI)` and run under `qemu-mipsel (and qemu-mips for BE)` (with `timeout --kill-after=30s 60s`).
  3. Record exact empirical findings, byte offsets (`sizeof`/`offsetof`), register values, and instruction encodings in `experiments/E05/FINDINGS.md`.
- **Acceptance Command**:
  ```sh
  test -s experiments/E05/FINDINGS.md
  ```

### Lane `E06` — TLS (`rdhwr $29` / `set_thread_area 4283`) & `LL`/`SC`
- **Worktree**: `../mips32rt-e06` on branch `lane/pe-e06`
- **Exclusive Files**: `experiments/E06/**`
- **Task**:
  1. Write a minimal Curated C11 / inline-assembly probe in `experiments/E06/probe.c` (and `Makefile` or `run.sh`).
  2. Cross-compile for `MIPS32r2 (`mipsel` LE & `mips` BE, O32 ABI)` and run under `qemu-mipsel (and qemu-mips for BE)` (with `timeout --kill-after=30s 60s`).
  3. Record exact empirical findings, byte offsets (`sizeof`/`offsetof`), register values, and instruction encodings in `experiments/E06/FINDINGS.md`.
- **Acceptance Command**:
  ```sh
  test -s experiments/E06/FINDINGS.md
  ```

