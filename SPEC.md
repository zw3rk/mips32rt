# `mips32rt` — Technical Specification & Execution Plan

**Target Architecture**: MIPS32r2 (`mipsel` LE & `mips` BE, O32 ABI)
**Target Host**: AArch64 Linux (`aarch64-unknown-linux-musl` static-PIE) & macOS on Apple Silicon via `hyper-linux` (`hl`)
**Series Tier**: Tier 1 (Wave 3 — Class-A 32-Bit 4 GiB Window)

---

## 0. Execution Protocol (Muse Spark Coordinator + Parallel Worker-Lane DAG)

1. **Coordinator + Parallel Worker-Lane Split**:
   - The **Coordinator** (`muse` on `master`) owns frozen headers (`src/mips32rt.h`, `include/a32host.h`, `src/os/syscall_nr.h`), `Makefile`, `flake.nix`, `docs/lanes/phase-*.md`, git worktree creation/cleanup, `--no-ff` merges, and phase-level Review Checkpoints (`RC-E`, `RC0..RC6`, `RC-H`).
   - **Concurrent Subagents & Workflows**:
     - For every phase (`Phase E`, `Phase 0` .. `Phase 7`), spawn **multiple concurrent `subagent` worker lanes in parallel** using isolated git worktrees (`../mips32rt-<lane>` on branch `lane/<phase>-<lane>`) and use `run_workflow` / `list_workflows` where helpful.
     - Each worker lane has **exclusive file ownership**, codes against **frozen headers**, and runs **one bounded acceptance check** (`timeout --kill-after=30s ...`).
2. **Dual-Oracle Verification**:
   - Every phase validates `src/interp/` against the independent **`qemu-mipsel (and qemu-mips for BE)` ground-truth oracle** first, and then validates `src/dbt/` against `src/interp/` via `--difftest` (`0` register/PC mismatches).

---

## 1. Target Profile, ELF Admission & Substrate Architecture

### 1.1 Target CPUs & ELF Admission
- **Target CPUs**: MIPS 24Kc / 24KEc / 74Kc (MediaTek MT7620, Qualcomm Atheros AR9331/QCA9531) and Ingenic XBurst (JZ4770)
- **ELF Admission**: `ELFCLASS32`, `e_machine == EM_MIPS (8)`, both `ELFDATA2LSB` (`mipsel`, primary) and `ELFDATA2MSB` (`mips` BE), `(e_flags & EF_MIPS_ABI2) == 0` and `(e_flags & EF_MIPS_ABI) in {0, E_MIPS_ABI_O32 (0x00001000)}`
- **Guest `TASK_SIZE`**: `0x7fff8000 (2 GiB useg compat limit; stack top 0x7fff0000, sigtramp 0x7fff7000)`
- **Ground-Truth Oracle**: `qemu-mipsel (and qemu-mips for BE)`
- **Cross Toolchains**: `pkgsCross.mipsel-linux-gnu (glibc) and musl mipsel/mips toolchains`

### 1.2 Class-A 4 GiB Window (`[G, G + 4 GiB)`) & `src/rt32/` Copy-First Substrate
- `mips32rt` allocates a contiguous 4 GiB + 64 KiB guard region `[G, G + 4 GiB + 64 KiB)` (`PROT_NONE` reservation via `src/rt32/vm.c`).
- Under standalone AArch64 Linux, `G` is chosen dynamically by the host kernel (`mmap(NULL, 0x100010000ULL, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0)`).
- Under `hyper-linux` (`hl`), `/dev/a32host` (`include/a32host.h`, `A32H_ABI 1.0/1.1`) provides `G = 0x100000000ULL` (`A32H_CAP_FIXED_OFFSET_4G`).
- **Phase 0 Lane `L0a`** copies the proven `rt32` substrate from `../i686rt/src/` (or `../a32rt/src/`) into `src/rt32/`:
  - `src/rt32/vm.c`, `src/rt32/elf32.c`, `src/rt32/stack32.c`, `src/rt32/host.c`, `src/rt32/a64_emit.[ch]`, `src/rt32/safe_syscall_a64.S` (with `D18` signal-window race-free commit point and `D19` `CLONE_VM` page-table mutex locking).
  - Parameterize `elf32.c` on `mips32rt`'s `e_machine`, endianness, and `e_flags` admission rules.

---

## 2. CPU Context, ISA Semantics & Linux ABI

### 2.1 `mips32_ctx_t` ABI-Locked Context Layout (`src/mips32rt.h`, Verified in `tests/check_abi_invariants.c`)
- **Zero overlapping fields** (`_Static_assert` verified at `RC0`):
  - `0x000..0x07f`: `uint32_t gpr[32]` (`$0=zero` hardwired 0, `$1=at`, `$2..$3=v0..v1`, `$4..$7=a0..a3`, `$8..$15=t0..t7`, `$16..$23=s0..s7`, `$24..$25=t8..t9`, `$28=gp`, `$29=sp`, `$30=fp`, `$31=ra`)
  - `0x080..0x08f`: `uint32_t pc` (`0x080`), `uint32_t next_pc` (`0x084`), `uint32_t hi` (`0x088`), `uint32_t lo` (`0x08c`)
  - `0x090..0x097`: `uint32_t ulr` (`0x090`, CP0 UserLocal `$29` for TLS), `uint32_t fcsr` (`0x094`, `FCR31` with `fcc[0..7]` in bits `23, 25..31`)
  - `0x098..0x09b`: `uint8_t in_delay_slot` (`0x098`), `uint8_t fr_mode` (`0x099`, `0` = `FR=0`, `1` = `FR=1`), `uint8_t llbit` (`0x09a`), `uint8_t nan2008` (`0x09b`, `0` = Legacy NaN/ABS, `1` = 2008 NaN/ABS)
  - `0x09c..0x0a7`: `uint32_t lladdr` (`0x09c`), `uint32_t llval` (`0x0a0`), `uint32_t cp0_config1` (`0x0a4`, bit 0 `is_be` flag in software config)
  - `0x0a8..0x0bf`: `uint64_t guest_base` (`0x0a8`), `uint64_t ibtc_ptr` (`0x0b0`), `uint32_t exit_reason` (`0x0b8`), `uint32_t exit_info` (`0x0bc`)
  - `0x0c0..0x1bf`: `uint64_t fpr[32]` (256 B, 16-byte aligned at `0x0c0`).
- **AArch64 DBT Register Map (16 Guest GPRs -> 16 Host GPRs `w0..w15`)**:
  - `x19 = xCtx`, `x20 = xG` (`guest_base`), `x21..x24` scratch, `x18` permanently reserved.
  - Because `$0` (`$zero`) is hardwired `wzr`, `w0..w15` cache 16 hot guest GPRs: `$v0 ($2), $v1 ($3), $a0..$a3 ($4..$7), $t0..$t5 ($8..$13), $s0 ($16), $s1 ($17), $sp ($29), $ra ($31)`. Remaining guest GPRs (`$at, $t6..$t9, $s2..$s7, $gp, $fp`) are accessed at `[x19, #off]`.

### 2.2 MIPS32r2 ISA Semantics, Delay Slots, Page-Final Progress, FP NaN Modes & Unaligned Accesses
- **Branch Delay Slots, Branch-Likely (`B*L`), & Page-Boundary Progress Rule**:
  - Every MIPS branch/jump executes the 32-bit instruction at `pc + 4` before transferring control to the branch target, with `ra = pc + 8` on link instructions.
  - For **Branch-Likely** instructions (`BEQL`, `BNEL`, `BLEZL`, `BGTZL`, `BLTZL`, `BGEZL`, `BC1FL`, `BC1TL`), if the branch is **not taken**, the delay-slot instruction at `pc + 4` is **annulled** (`pc` advances directly to `pc + 8` **without fetching or faulting on `pc + 4`** — critical when `pc + 4` lies on an unmapped page!).
  - In DBT (`src/dbt/`), a branch and its delay-slot instruction at `pc + 4` are decoded and emitted as an indivisible unit when both lie on the same 4 KiB page. If a block encounters a branch at `(pc & 0xfff) == 0xffc` after prior instructions, the block terminates *before* `pc`; if a block **starts** at `(pc & 0xfff) == 0xffc`, the DBT emits `EXIT_SINGLE_STEP` (`interp_step(ctx)`) to execute the cross-page branch+delay-slot pair once and resume DBT at the target PC.
  - On synchronous fault or signal delivery while `ctx->in_delay_slot == 1`, `ctx->in_delay_slot` remains translator-internal bookkeeping while `sc_pc` records `branch_pc` (`pc - 4`) so signal return re-executes the branch and its delay slot.
- **FPU Register Mode (`FR=0` vs `FR=1`) & NaN/ABS Mode (`Legacy` vs `NAN2008`)**:
  - Initialized from ELF `e_flags` (`EF_MIPS_FP64`, `EF_MIPS_NAN2008 = 0x400`) and `.MIPS.abiflags` (`PT_MIPS_ABIFLAGS = 0x70000003`).
  - **Legacy NaN (`nan2008 == 0`)**: Quiet NaN has fraction MSB **0** (`0x7fbfffff` / `0x7ff7ffffffffffff`) and signaling NaN has fraction MSB **1** (`0x7fc00000` / `0x7ff8000000000000`); `ABS.S`/`ABS.D` and `NEG.S`/`NEG.D` are arithmetic operations that signal `Invalid Operation` on sNaN.
  - **2008 NaN (`nan2008 == 1`)**: Quiet NaN has fraction MSB **1** (matching IEEE 754-2008 and AArch64 `FPCR.DN = 1`), and `ABS.fmt`/`NEG.fmt` (`ABS2008`) are non-arithmetic sign-bit flips that never trap on sNaN.
- **Unaligned Load/Store Pairs (`LWL`/`LWR`, `SWL`/`SWR`) & `RDHWR`**:
  - `LWL`/`LWR`/`SWL`/`SWR` implemented in both `mipsel` and `mips` BE modes (using `REV32`/`REV16` byte-swapping in BE mode).
  - `rdhwr rt, $29` returns `ctx->ulr` (TLS pointer) in `gpr[rt]`; `set_thread_area (4283)` sets `ctx->ulr`.
- **LL/SC Reservation Invalidation**:
  - `LL` sets `llbit = 1, lladdr = addr, llval = val`; `SC` succeeds iff `llbit == 1 && lladdr == addr` and `atomic_compare_exchange` matches `llval`.
  - Any runtime helper exit, syscall, signal delivery, `sigreturn`, or thread switch clears `ctx->llbit = 0`.

### 2.3 MIPS O32 Linux Syscall & Complete 128-Signal Namespace ABI (`src/os/`)
- **O32 Syscall Convention (`syscall` instruction `0x0000000c`)**:
  - Syscall number in `$v0` (`gpr[2]`), offset from **`__NR_Linux = 4000`**.
  - **Arguments 1..4** in `$a0..$a3` (`gpr[4..7]`). **Arguments 5..8** are read from the guest user stack at **`(uint32_t)(gpr[29] + 16)`**, **`+20`**, **`+24`**, **`+28`**!
  - **64-bit Register-Pair Alignment**: O32 aligns 64-bit arguments to **even** argument pairs (`$a0:$a1` or `$a2:$a3`; in `mipsel`, `lo` is even and `hi` is odd; in `mips` BE, `hi` is even and `lo` is odd).
  - **Return Value & `$a3` Error Flag**:
    - Success (`ret >= 0`): **`gpr[7] ($a3) = 0`**, **`gpr[2] ($v0) = (uint32_t)ret`** (`pipe (4042)` also sets `gpr[3] ($v1) = pipefd[1]`).
    - Error (`ret < 0`): **`gpr[7] ($a3) = 1`**, **`gpr[2] ($v0) = mips_errno_from_host(-ret)`** (positive MIPS errno!).
- **Complete MIPS Constant, Struct & 128-Signal Namespace (`arch/mips/include/uapi/asm/`)**:
  - **Kernel `struct stat64` (`stat64 = 4213`, `lstat64 = 4214`, `fstat64 = 4215`, `fstatat64 = 4293`)**: **104 bytes** in Linux UAPI `arch/mips/include/uapi/asm/stat.h`.
  - **Complete 1..128 Signal Namespace & Guest-Owned Signal Subsystem (`src/os/signals_mips32.c`)**:
    - MIPS defines `_NSIG = 128` (`16-byte` `sigset_t`): `1=SIGHUP, 2=SIGINT, 3=SIGQUIT, 4=SIGILL, 5=SIGTRAP, 6=SIGIOT/SIGABRT, 7=SIGEMT, 8=SIGFPE, 9=SIGKILL, 10=SIGBUS, 11=SIGSEGV, 12=SIGSYS, 13=SIGPIPE, 14=SIGALRM, 15=SIGTERM, 16=SIGUSR1, 17=SIGUSR2, 18=SIGCHLD, 19=SIGPWR, 20=SIGWINCH, 21=SIGURG, 22=SIGIO, 23=SIGSTOP, 24=SIGTSTP, 25=SIGCONT, 26=SIGTTIN, 27=SIGTTOU, 28=SIGVTALRM, 29=SIGPROF, 30=SIGXCPU, 31=SIGXFSZ, 32..128=RT signals`.
    - Because host AArch64 Linux supports only 64 signals (`_NSIG = 64`), `signals_mips32.c` maintains a **guest-owned 128-entry action table** (`mips_sigaction_t actions[128]`), **128-bit per-thread blocked and pending masks** (`uint64_t mask[2]`, `pending[2]`), and a bounded **FIFO real-time signal queue** (`mips_sigqueue_t`) for duplicate queued signals (`32..128`). `SIGEMT (7)` and guest RT signals `63..128` are queued in guest/shared state and notify target threads via reserved host kick signal `SIGRTMAX (64)`.
  - **Socket & Open Constants**: `SOCK_DGRAM = 1`, `SOCK_STREAM = 2`, `SOL_SOCKET = 0xffff`, `O_CREAT = 0x0100`, `O_TRUNC = 0x0200`, `O_EXCL = 0x0400`, `O_NOCTTY = 0x0800`, `O_NONBLOCK = 0x0080`, `O_APPEND = 0x0008`, `O_LARGEFILE = 0x2000`.
- **O32 `rt_sigframe` (`src/os/sigframe_mips32.h`)**:
  - **24-byte prefix** (`uint32_t rs_ass[4]` 16 B + `uint32_t rs_pad[2]` 8 B), `mips_siginfo_t rs_info` (128 B, with `si_code` before `si_errno`), `mips_ucontext_t rs_uc` (`sc_regs[32]` stored as 64-bit `uint64_t` slots, `sc_fpregs[32]`, `sc_mdhi`, `sc_hi1..3`, `sc_mdlo`, `sc_lo1..3`, `sc_pc`, `sc_fpc_csr`).

---

## 3. Dual-Engine Design (`src/interp/` + `src/dbt/`)

1. **Reference Interpreter (`src/interp/`)**:
   - Pure Curated C11 step-by-step and chunked interpreter (`interp_step(mips32_ctx_t *ctx)` and `interp_run(mips32_ctx_t *ctx)`).
   - Serves as:
     - Ground-truth reference engine (`MIPS32RT_ENGINE=interp` or `--interp`),
     - Instruction-by-instruction differential oracle (`--difftest`),
     - Single-instruction fallback (`EXIT_UNDEF` / `EXIT_SINGLE_STEP` -> `interp_step(ctx)` -> resume DBT) for rare system/unaligned/cross-page delay-slot instructions so valid instructions never abort execution.
2. **AArch64 Dynamic Binary Translator (`src/dbt/`)**:
   - Translates guest basic blocks (up to 64 guest instructions, terminating at control transfers or page boundaries) into AArch64 machine code using `a64_emit.[ch]`.
   - Direct block chaining + 4096-entry per-thread Indirect Branch Target Cache (`IBTC`) + Return Address Stack (`RAS`).
   - Enforces W^X (`PROT_READ | PROT_WRITE` during emission -> `PROT_READ | PROT_EXEC` before execution + `__builtin___clear_cache` / `A32H_CAP_ICACHE_TRAP_IALLU`) and self-modifying code (`SMC`) page-version invalidation on `mprotect` / `munmap` / `clear_cache` / guest writes to translated pages.
   - **Never touches `x18`**.

---

## 4. Nine-Phase Implementation Pipeline & Review Checkpoints (`RC`)

| Phase / Gate | Lanes (Run in Parallel Worktrees) | Required Independent Oracle & Acceptance Gate |
|---|---|---|
| **Phase E (`RC-E`)** | `E01` .. `E06` (`experiments/E01..E06/FINDINGS.md`) | All 6 empirical probes compiled with target cross-CC, executed under `qemu-mipsel (and qemu-mips for BE)`, and committed with `FINDINGS.md` (`sizeof`/`offsetof` verified). |
| **Phase 0 (`RC0`)** | `L0a` (Substrate copy + build), `L0b` (`tests/check_abi_invariants.c` + CLI smoke) | `aarch64-unknown-linux-musl-gcc -static-pie` builds `_build/mips32rt`; `make check-line-limits` (`<= 900 LOC`) and `check_abi_invariants` pass; `--version` / `--help` pass in AArch64 Docker container. |
| **Phase 1 (`RC1`)** | `L1a` (Decoder), `L1b` (Integer `src/interp/`), `L1c` (Minimal syscalls `exit`, `write`, `brk`, `mmap`), `L1d` (`test_p1_isa`) | `test_p1_isa` (covering ALU, shifts, branches, delay slots/annul at `page_end - 4` before `PROT_NONE` page, atomics, unaligned accesses) matches `qemu-mipsel (and qemu-mips for BE)` exit code and stdout bit-for-bit under `MIPS32RT_ENGINE=interp`. |
| **Phase 2 (`RC2`)** | `L2a` (`src/os/` static libc syscalls + struct translation), `L2b` (`src/dbt/` dispatcher + block cache + IBTC), `L2c` (`src/dbt/emit_int.c`), `L2d` (`difftest` + static libc tests) | `--difftest` reports `0` register/PC mismatches between `interp` and `dbt` on `test_p1_isa`; static `hello`, `printf`, `qsort`, `malloc`, and file I/O match `qemu-mipsel (and qemu-mips for BE)` on both `interp` and `dbt`. |
| **Phase 3 (`RC3`)** | `L3a` (`src/interp/fp.c` FPU/SIMD), `L3b` (`src/dbt/emit_fp.c` NEON/FP lowering), `L3c` (`test_p3_fp_simd`) | `test_p3_fp_simd` (NaN modes, rounding, FPU/SIMD corner cases) matches `qemu-mipsel (and qemu-mips for BE)` bit-for-bit on both `interp` and `dbt` with `0` difftest divergences. |
| **Phase 4 (`RC4`)** | `L4a` (`rt_sigframe` + `rt_sigaction`/`rt_sigreturn`/altstack), `L4b` (`clone`/TLS/`futex`/reservation invalidation), `L4c` (`fork`/`vfork`/`execve`/`wait4` + `test_p4_threads_signals`) | `test_p4_threads_signals` (signal frame inspection/modification/restoration, `SIGSEGV` recovery, pthreads + futex + atomics, `fork`+`execve`+`wait4`) matches `qemu-mipsel (and qemu-mips for BE)` on both `interp` and `dbt`. |
| **Phase 5 (`RC5`)** | `L5a` (`PT_INTERP` dynamic linker loading + auxv + `/proc/self/*`), `L5b` (Dynamic `glibc`/`musl` + `BusyBox` suite) | Dynamic `test_p5_dyn` and `BusyBox` (`sh -c 'ls / && echo ok | wc -c'`) match `qemu-mipsel (and qemu-mips for BE)` on both `interp` and `dbt`. |
| **Phase 6 (`RC6`)** | `L6a` (`hyper-linux` host contract & packaging), `L6b` (Both-host parity test suite) | `test_p1_isa`, `test_p3_fp_simd`, `test_p4_threads_signals`, `test_p5_dyn`, and `BusyBox` pass on both AArch64 Linux container and `hl` (`hyper-linux`). |
| **Phase 7 (`RC-H`)** | `H1` (`test_h1_smc`), `H2` (`libc-test` + LTP syscall subset -> `docs/h2-report.md`), `H3` (6-step instrumented CoreMark -> `docs/h3-coremark.md`), `H4` (C++17 exceptions/RTTI/TLS smoke) | All 4 hardening gates committed with machine-verified pass counts (`0` unexpected failures) and measured `dbt > interp` speedup in `docs/h3-coremark.md`. |
