# Phase 4 Task Cards — Signals, Threads & Process Lifecycle (`mips32rt`)

Run after `RC3` is merged to `master`. Frozen contracts: `src/mips32rt.h`
Phase 4 section (`mips_raise_guest`, `mips_rt_sigreturn`), E04 sigframe
layout + `src/os/sigframe_mips32rt.h`, SPEC 1.1 (window) + 2.2 (faults) +
2.3 (O32 conventions). `mips_fault` keeps recording `EXIT_FAULT`; L4a
reroutes it to guest delivery when a handler is installed, else the
Phase-1 host-signal death stays. After Phase 4 the P1/P3 SKIP branches go
live (except the documented qemu over-fetch divergence).

Shared rules: curated C11, every file ≤ 900 lines, no `x18`, W^X kept,
no AI/agent names. RC4 integration by the coordinator after all lanes
merge; the P1/P3 suites are re-run with live delivery.

---

### Lane `L4a` — Synchronous Signal Delivery (`rt_sigframe`, `rt_sigreturn`)
- **Worktree**: `../mips32rt-l4a` on branch `lane/p4-l4a`
- **Exclusive Files**: `src/os/signals.c`, `src/os/sigframe_mips32rt.h` (extend layout only), `src/os/mem.c` (fault-dispatch hook only)
- **Task**:
  1. `src/os/signals.c`: real `rt_sigaction` (record guest handler/restorer/
     mask/flags per signal; support `SA_SIGINFO`, `SA_ONSTACK`,
     `SA_RESTART` advisory), `rt_sigprocmask` (record-only process mask;
     keep host mask unblocked so faults stay synchronous), `rt_sigreturn`
     (validate `sp` points into a live frame; restore gpr/pc/fpu/fcsr/mask
     from `mips_rt_sigframe`).
  2. `mips_raise_guest(ctx, signo, fault_addr)`: build `rt_sigframe` on the
     guest stack (E04 layout: 24-byte prefix, 128-B `siginfo` with
     `si_code` before `si_errno`, `mips_ucontext_t` with
     `sc_regs[32]` 64-bit slots + `sc_pc` = faulting pc (branch pc when
     `ctx->in_delay_slot`) + `sc_fpc_csr`, `sc_fpregs`);
     fill `si_signo/si_code/si_addr` (SIGSEGV/SIGBUS/SIGFPE/SIGILL as
     appropriate, `SEGV_MAPERR` vs `SEGV_ACCERR` by range check,
     `BUS_ADRALN`/`BUS_ADRERR` for alignment); set `pc` = handler,
     `a0` = signo, `a1` = siginfo ptr, `a2` = ucontext ptr,
     `ra` = restorer (or a `__kernel_rt_sigreturn` trampoline that issues
     `rt_sigreturn`). Nested signals queue (max depth 8, else kill).
  3. Hook `mips_fault` in `src/os/mem.c`: if a handler is installed for
     the mapped host signal, `mips_raise_guest` and continue execution
     (return without raising); else keep the Phase-1 `raise(SIGSEGV)`.
- **Acceptance Command**: strict host `-c` compile of `src/os/signals.c`
  (execution is the RC4 gate; report it deferred).

---

### Lane `L4b` — Threads (`clone`, `futex`, TLS)
- **Worktree**: `../mips32rt-l4b` on branch `lane/p4-l4b`
- **Exclusive Files**: `src/os/threads.c`, `src/os/syscall_nr.h` (extend numbers only), `src/os/syscall_min.c` (`clone`/`futex` dispatch only), `src/os/syscalls.c` (futex ops only)
- **Task**:
  1. Numbers (verify from `asm/unistd_o32.h`): `clone`, `futex`,
     `set_robust_list`/`get_robust_list` (fill gaps if L2a omitted any).
  2. `src/os/threads.c`: `CLONE_VM`-family guest threads via host
     `clone(2)` sharing the `[G,G+4GiB)` window (child gets its own host
     stack + `mips32_ctx_t` copy: `pc` = child return, `tls` from
     `CLONE_SETTLS`, `ctid`/`ptid` writeback + `CLONE_PARENT_SETTID` /
     `CLONE_CHILD_CLEARTID` futex wake on exit), `CLONE_THREAD` group
     semantics minimal (single-group exit when last thread exits or any
     calls `exit_group`), `CLONE_UNTRACED` ignored, non-VM clone flags →
     `-EINVAL`.
  3. Full `futex` ops (`WAIT`/`WAKE` + `FUTEX_PRIVATE_FLAG`, `REQUEUE`,
     `CMP_REQUEUE`, `WAKE_OP`) via host futex on the guest uaddr
     (validated mapping, `EFAULT` otherwise; `llbit` cleared across).
- **Acceptance Command**: strict host `-c` compile of
  `src/os/threads.c` (execution is the RC4 gate; report it deferred).

---

### Lane `L4c` — Process Lifecycle (`fork`, `execve`, `wait4`)
- **Worktree**: `../mips32rt-l4c` on branch `lane/p4-l4c`
- **Exclusive Files**: `src/os/proc.c`, `src/os/syscall_nr.h` (extend numbers only), `src/os/syscall_min.c` (`fork`/`vfork`/`execve`/`wait4` dispatch only)
- **Task**:
  1. Numbers (verify from `asm/unistd_o32.h`): `fork` (402), `vfork`,
     `execve` (11), `wait4` (114), `waitpid` if distinct.
  2. `src/os/proc.c`: `fork` via host `fork()` (CoW duplicates the
     window; child `ctx` copied, return 0 in child / pid in parent;
     `llbit` cleared in child), `vfork` as `fork` (documented), `execve`
     (validate path, `rt32_vm_reset_for_exec`, re-`rt32_elf_load` +
     `rt32_stack_setup` + fresh brk/mmap cursor, new `argv`/`envp`,
     reset signal dispositions to default, close `O_CLOEXEC` fds),
     `wait4`/`waitpid` via host `wait4` (WUNTRACED|WNOHANG|WCONTINUED →
     guest status encoding incl. WIFSTOPPED bits, `ru_`
     zero-filled `rusage` struct copy-out on request).
- **Acceptance Command**: strict host `-c` compile of
  `src/os/proc.c` (execution is the RC4 gate; report it deferred).

---

## RC4 gate (coordinator, after all lanes merge)

1. Merge L4a/L4b/L4c (`--no-ff`), wire dispatch, cross-build.
2. Re-run `tests/test_p1_isa` + `tests/test_p3_fpu` under `--interp`
   and `--dbt`, LE+BE: all previously-SKIP signal/fork checks must now
   execute; allowed divergences vs qemu goldens: ONLY the documented
   `beql-pageend-nottaken` over-fetch line (SPEC 2.2 annulment vs qemu
   translate-time fetch — permanent) plus exit-code shape differences
   where qemu dies by signal and the translator exits 139.
3. New `tests/difftest/` fixtures for `fork`+`wait` (L4c) and a threaded
   counter (L4b, LL/SC + futex) pass interp-vs-qemu and interp-vs-dbt.
