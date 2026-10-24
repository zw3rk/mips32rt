# E04 — O32 `rt_sigframe` layout and 128-signal UAPI: FINDINGS

Probe: [probe.c](probe.c) · Runner: [run.sh](run.sh) · Logs: [out/](out/)

## 1. Toolchain identities (exact)

| Tool | Identity |
|---|---|
| LE cross compiler | `mipsel-linux-gnu-gcc (Debian 12.2.0-14) 12.2.0` |
| BE cross compiler | `mips-linux-gnu-gcc (Debian 12.2.0-14) 12.2.0` |
| LE emulator | `qemu-mipsel version 7.2.22 (Debian 1:7.2+dfsg-7+deb12u18+b3)` |
| BE emulator | `qemu-mips version 7.2.22 (Debian 1:7.2+dfsg-7+deb12u18+b3)` |
| Native contrast compiler | Debian bookworm `gcc` (AArch64, host glibc) |
| glibc (cross sysroot) | 2.36 (`/usr/mipsel-linux-gnu`, `/usr/mips-linux-gnu`) |
| Linux UAPI headers | Debian `libc6-dev-*-cross` (asm/signal.h, asm/sigcontext.h, asm/stat.h, asm/ucontext.h read in-container) |

Host: macOS Apple Silicon; all builds/runs inside one
`debian:bookworm-slim` container (`--platform linux/arm64`,
`--memory 2g --cpus 2`), repo mounted at `/w`.

## 2. Exact build / run commands

```sh
mipsel-linux-gnu-gcc -std=c11 -Wall -Wextra -static -O1 probe.c -o out/probe-le
mips-linux-gnu-gcc  -std=c11 -Wall -Wextra -static -O1 probe.c -o out/probe-be
qemu-mipsel out/probe-le   # exit 0, RESULT=PASS  (see out/output-le.txt)
qemu-mips   out/probe-be   # exit 0, RESULT=PASS  (see out/output-be.txt)
gcc -std=c11 -Wall -Wextra -O1 probe.c -o out/probe-native && ./out/probe-native
```

Both cross builds are warning-free (`-Wall -Wextra`).
Full command is `run.sh` (`chmod +x run.sh; ./run.sh [outdir]`),
which reproduces all of the above plus `out/versions.txt`;
exit status 0 requires `RESULT=PASS` in both LE and BE logs.
LE and BE outputs are byte-identical except the runtime `seen_pc`
(load address). Raw logs: [out/output-le.txt](out/output-le.txt),
[out/output-be.txt](out/output-be.txt),
[out/output-native.txt](out/output-native.txt).

## 3. `sizeof` table (qemu-verified, mipsel O32)

| Type | `sizeof` (bytes) | Task expectation | Verdict |
|---|---|---|---|
| `sigset_t` (glibc) | 128 | 16 | see §7 — glibc set is 128 B, **kernel** set is 16 B |
| `struct sigaction` (glibc) | 144 | — | flags@0 handler@4 mask@8(128 B) restorer@136 |
| `siginfo_t` | 128 | — | signo@0 code@4 errno@8 |
| `ucontext_t` (glibc) | 744 | — | flags@0 link@4 stack@8 mcontext@24 sigmask@616(128 B) |
| `mcontext_t` (glibc O32) | 592 | — | §4 |
| `gregset_t` | 256 (32 × 8) | — | **yes, 64-bit slots** (`greg_t` = `unsigned long long` even on O32) |
| `fpregset_t` | 256 (32 × 8) | — | 64-bit FP slots |
| `greg_t` | 8 | — | 64-bit slot confirmed |
| `struct sigcontext` (glibc = kernel ABI32 layout) | 592 | — | §4, identical offsets to `mcontext_t` |
| `struct stat64` (glibc) | 160 | 104 | see §6 — glibc translates; **kernel** `stat64` is 104 B |
| `stack_t` | 12 | — | sp@0 size@4 flags@8 |

## 4. `mcontext_t` / `struct sigcontext` offsets (qemu-verified)

glibc O32 `mcontext_t` and `struct sigcontext` agree on every field
(kernel comment: keep in sync with `arch/mips/kernel/asm-offsets.c`):

| Field (`mcontext` / `sigcontext`) | Offset | Size |
|---|---|---|
| `regmask` / `sc_regmask` (unused) | 0 | 4 |
| `status` / `sc_status` (unused) | 4 | 4 |
| `pc` / `sc_pc` | 8 | 8 |
| `gregs` / `sc_regs[32]` | 16 | 256 (32 × u64) |
| `fpregs` / `sc_fpregs[32]` | 272 | 256 (32 × u64) |
| `fp_owned` / `sc_ownedfp` (`sc_acx` in kernel) | 528 | 4 |
| `fpc_csr` / `sc_fpc_csr` | 532 | 4 |
| `fpc_eir` / `sc_fpc_eir` (unused) | 536 | 4 |
| `used_math` / `sc_used_math` | 540 | 4 |
| `dsp` / `sc_dsp` | 544 | 4 |
| `mdhi` / `sc_mdhi` | 552 | 8 (4 B pad at 548) |
| `mdlo` / `sc_mdlo` | 560 | 8 |
| `hi1,lo1,hi2,lo2,hi3,lo3` / `sc_hiN,sc_loN` | 568,572,576,580,584,588 | 4 each |
| total | — | **592** |

Note: kernel names the slot at 528 `sc_acx` (was `sc_ownedfp`);
glibc keeps `sc_ownedfp`/`fp_owned`. Same offset, same size.
DSP `hi/lo1..3` are 32-bit (`unsigned long`) on O32; `mdhi/mdlo`
are 64-bit.

## 5. Runtime observations (qemu-verified, LE and BE)

- `sigaction(35, SA_SIGINFO | mask{64,120})` + `raise(35)` →
  handler ran: `got_sig=35`, exit 0, `RESULT=PASS` (both endianesses).
  The `sa_mask` spans both halves of the 16-byte kernel set
  (signals 64 and 120 set), proving full 128-signal mask delivery.
- `got_code=-6` = `SI_TKILL` (`raise()` uses `tkill`, not `SI_QUEUE`).
- Handler context sane: `seen_pc=0x41a0f0` (LE, code address),
  `seen_sp=0x40800b10` (LE, stack address), `seen_fpc_csr=0x0`.
  Non-null pc/sp check passes — the `ucontext_t` at §3 offsets
  is what the kernel (via qemu) actually filled in.
- Raw `rt_sigprocmask` sigsetsize probe:
  `size=16 → 0, errno=0`; `size=8 → -1, errno=22 (EINVAL)`.
  qemu enforces the 16-byte kernel set size.
- Constants: `_NSIG=128`, `NSIG=128`, `SIGRTMIN=34`, `SIGRTMAX=127`,
  `SI_QUEUE=-1`.
- `sigfillset` coverage: members 1, 31, 64, 120, 127 present;
  **member 32 absent (0)** — signals 32/33 are NPTL-reserved
  (`SIGCANCEL`/`SIGSETXID`); hence `SIGRTMIN=34`, not 32.
  Member 128 is out of range on this glibc (`_NSIG=128` ⇒ 1..127).

## 6. `stat64`: 104 vs 160 resolved

- **Kernel UAPI** `struct stat64` (`asm/stat.h`, ABI32): hand-computed
  from the installed header — `st_dev@0`, `st_ino@16`, `st_mode@24`,
  `st_nlink@28`, `st_uid@32`, `st_gid@36`, `st_size@56`,
  `st_blksize@88`, `st_blocks@96`, total **104 bytes**.
  Matches the task expectation: the translator must emit this 104-byte
  layout for the `stat64`/`fstat64` syscalls.
- **glibc** `struct stat64` is **160 bytes** (own padding/timespec
  scheme, `bits/struct_stat.h`); glibc translates kernel→libc format.
  Phase 0 headers must therefore model the **104-byte kernel** layout,
  not `sizeof(struct stat64)` from the cross sysroot.

## 7. The two `sigset_t`s (Phase 0-critical)

- glibc `sigset_t` = **128 bytes** (1024-bit future-proof mask).
- Kernel `sigset_t` = `_NSIG_WORDS × 4` = **16 bytes** on O32
  (`linux/posix_types.h`: `_NSIG_WORDS = _NSIG/__BITS_PER_LONG`).
  Kernel `struct sigaction` (`asm/signal.h`) is
  `{ u32 sa_flags; handler; sigset_t(16 B) sa_mask }` = 24 bytes —
  no restorer, 16-byte mask. glibc passes `_NSIG/8 = 16` as the
  `sigsetsize` argument to every `rt_*sig*` syscall (§5 verifies
  16 accepted / 8 rejected). **Frozen headers must use 16, never
  `sizeof(sigset_t)`.**

## 8. Kernel `rt_sigframe` reconstruction (from UAPI headers — UNVERIFIED by execution)

qemu-user cannot execute kernel `signal.c`; this frame is *derived*
from the installed UAPI headers (`asm/signal.h`, `asm/ucontext.h`,
`asm/sigcontext.h`), not observed at runtime:

- Kernel `struct ucontext` = `{ ulong uc_flags; uc_link*;
  stack_t(12 B); struct sigcontext(592 B); sigset_t(16 B) }`
  = 4+4+12+592+16 = **628 bytes**.
- Kernel `rt_sigframe` ≈ `{ siginfo_t(128 B) + struct ucontext(628 B) }`
  plus the trampoline (`rs_code`), i.e. ≈756 B before the code stub.
  Exact final size/alignments come from `arch/mips/kernel/signal.c`
  (`setup_rt_frame`) — left to Phase 0 against real-kernel sources.

## 9. Native contrast (AArch64 glibc, executed natively in container)

Same probe, `#ifdef __mips__` guards around MIPS-only context
members; `RESULT=PASS`, exit 0:
`sizes: sigset=128 sigaction=152 siginfo=128 ucontext=4560 stat64=128 stack=24`;
`_NSIG=65 NSIG=65 SIGRTMIN=34 SIGRTMAX=64`;
kernel set 8 bytes (`size8 → 0`, `size16 → EINVAL`);
`sigismember(120)=-1`, `sigismember(127)=-1` (only 1..64 valid).
Confirms every §3–§7 value is genuinely MIPS-O32-specific.

## 10. Phase 0 header inputs (precision summary)

`_NSIG=128`; kernel sigset 16 B (`_NSIG/8`); glibc sigset 128 B;
glibc sigaction 144 B `{flags@0,handler@4,mask@8,restorer@136}`;
kernel sigaction 24 B `{flags,mask16}`;
ucontext 744 B `{mcontext@24,sigmask128@616}`;
sigcontext/mcontext 592 B with `sc_pc@8 sc_regs@16 sc_fpregs@272
sc_fpc_csr@532 sc_mdhi@552 sc_mdlo@560`;
`SIGRTMIN=34 SIGRTMAX=127` (32/33 NPTL-reserved);
kernel stat64 104 B (glibc stat64 160 B — do not use for ABI).
