# E01 Findings — O32 Syscall Stack Args 5..8 & `$a3` Error Flag

All results below are qemu-verified ground truth (LE **and** BE executed).
Nothing in this file is UNVERIFIED.

## 1. Toolchain & Oracle Identity

| Item | Identity |
|---|---|
| LE cross-CC | `mipsel-linux-gnu-gcc (Debian 14.2.0-13) 14.2.0`, target `mipsel-linux-gnu` |
| BE cross-CC | `mips-linux-gnu-gcc (Debian 14.2.0-13) 14.2.0` |
| LE oracle | `qemu-mipsel version 10.0.13 (Debian 1:10.0.13+ds-0+deb13u1)` |
| BE oracle | `qemu-mips version 10.0.13 (Debian 1:10.0.13+ds-0+deb13u1)` |
| Host container | `debian:stable-slim` on linux/arm64, `apt-get install qemu-user gcc-mipsel-linux-gnu gcc-mips-linux-gnu libc6-dev-mipsel-cross libc6-dev-mips-cross` |

## 2. Exact Build / Run Commands

```sh
CFLAGS="-march=mips32r2 -static -no-pie -fno-PIC -mno-shared \
  -std=c11 -Werror=vla -pedantic -Wall -Wextra -Werror -O1"
mipsel-linux-gnu-gcc $CFLAGS -o probe-le probe.c   # LE (O32, MIPS32r2)
mips-linux-gnu-gcc   $CFLAGS -o probe-be probe.c   # BE (O32, MIPS32r2)
mipsel-linux-gnu-readelf -h probe-le   # ELF32, MIPS R3000, flags o32+mips32r2
timeout --kill-after=30s 60s qemu-mipsel ./probe-le
timeout --kill-after=30s 60s qemu-mips    ./probe-be
```

Both binaries: `ELF32`, `Machine: MIPS R3000`,
`Flags: 0x70001007 (noreorder, pic, cpic, o32, mips32r2)`.
`run.sh` performs both builds and both runs; exit code `0`,
`E01-RESULT: PASS (0 checks failed)` on LE and BE.

Build note (benign): one assembler warning remains,
`no .cprestore pseudo-op used in PIC code`, from the hand-written
`caller8` (`jal` without `$gp` setup). It is harmless: the observers
use explicit absolute `%hi`/`%lo` addressing, never touch `$gp`, and
every magic value round-trips exactly (see §4). An earlier segfault
(`si_addr=0x88888888`) was a genuine bug in the first draft of
`caller8` — `$ra` was spilled at `28($sp)`, the outgoing arg-8 slot —
fixed by spilling `$ra` at `0($sp)`.

## 3. `sizeof` / `offsetof` (identical LE and BE)

| Expression | Value |
|---|---|
| `sizeof(long)` | 4 |
| `sizeof(long long)` | 8 |
| `sizeof(void *)` | 4 |
| `sizeof(scres_t)` (`{long v0, a3}`) | 8 |
| `offsetof(scres_t, a3)` | 4 |

## 4. Syscall Args 5..8 on the User Stack at `$sp+16/+20/+24/+28`

Callee-side observation (hand-written `callee8`, reads regs + stack
before any prologue), LE run, compiler-generated call with
`m[8] = {0x10101010 … 0x80808080}`:

```text
compiler-call obs: a0..a3=10101010 20202020 30303030 40404040
                   s5..s8=50505050 60606060 70707070 80808080 sp=2b2abcd0
```

Hand-asm forward (`caller8` → `callee8`, magics `0x11…0x88`) observes
identical placement at `sp=2b2abcb0`. BE run: identical values.
Callee `$sp` is 8-byte aligned in all runs.

Kernel-side proof (raw `syscall`, args 5..8 stored by the wrapper at
`16/20/24/28($sp)` after `subu $sp,$sp,32`):

| Raw call | Observed `$v0` | Observed `$a3` | Verdict |
|---|---|---|---|
| `mmap2(NULL,4096,RW,PRIVATE\|ANON,-1,0)` (6 args) | `0x2b2ad000` | 0 | mapping live, writable, `munmap` ok |
| `mmap2(NULL,4096,R,PRIVATE,-2,0)` (6 args) | 9 (`EBADF`) | 1 | stack args 5,6 reached kernel |
| `syscall#4999` + 8 magics | 89 (`ENOSYS`) | 1 | 8-arg frame safe, error path |
| `getpid` + 8 magics | pid (984 LE / 1027 BE) | 0 | extras ignored |

MIPS `errno` gotcha recorded: MIPS is **not** asm-generic —
`ENOSYS = 89` (not 38); `ENOENT = 2`, `EBADF = 9` (compile-time
`_Static_assert`ed in `probe.c`).

## 5. 64-bit Args Align to Even Pairs

Compiler-generated call `callee_ll(0x11111111, 0x2222222233333333, 0x44444444)`:

```text
LE: a0=11111111 a1=deadbeef a2=33333333 a3=22222222 stack=44444444
BE: a0=11111111 a1=deadbeef a2=22222222 a3=33333333 stack=44444444
```

`$a1` was poisoned to `0xdeadbeef` immediately before the call and is
still intact: the compiler skipped it and placed the `u64` at
`$a2:$a3` — `(lo,hi)` LE, `(hi,lo)` BE. Disassembly of the call site
confirms (`lui a1,0xdead` poison, then `a2=lo, a3=hi`, tail `sw 16(sp)`
for LE; `a2=hi, a3=lo` for BE). Leading-`u64` call
`callee_ll0(0xAAAAAAAA55555555, 0x77777777)` lands at `$a0:$a1`
(`(lo,hi)` LE, `(hi,lo)` BE) with the tail in `$a2`.

Syscall-level pair (`_llseek(fd, hi, lo, &res, wh)` = `__NR 4140`):

| Call | `$v0` | `$a3` | `res` |
|---|---|---|---|
| `_llseek(fd,0,0,&res,SEEK_END)` on 13-byte file | 0 | 0 | 13 |
| `_llseek(fd,0,7,&res,SEEK_SET)` | 0 | 0 | 7 |
| `_llseek(fd,1,2,&res,SEEK_SET)` | 0 | 0 | `0x100000002` |

So `(arg2,arg3) = (hi,lo)` on both endians. (A first draft sought to
`0x1111111122222222` and got `$a3=1/$v0=22 (EINVAL)` — the pair was
delivered correctly; the filesystem just rejects a 4-EiB offset.)

## 6. `$a3` Error Flag (`$v0` = ret / +errno)

| Call | `$v0` | `$a3` |
|---|---|---|
| `getpid` (raw `__NR 4020`; matches libc `getpid()`) | pid | 0 |
| `write(1, msg, 16)` (`__NR 4004`) | 16 | 0 |
| `write(-1, msg, 3)` | 9 (`EBADF`) | 1 |
| `open("/nonexistent-e01-xyz")` (`__NR 4005`) | 2 (`ENOENT`) | 1 |
| `close(fd); close(fd)` (`__NR 4006`) | 0 then 9 (`EBADF`) | 0 then 1 |

Rule confirmed: success → `$a3=0, $v0=(uint32_t)ret`;
error → `$a3=1, $v0`= positive MIPS errno.

## 7. `__NR` Offsets Used (`__NR_Linux = 4000` base)

`write 4004, open 4005, close 4006, getpid 4020, _llseek 4140,
mmap2 4210, munmap 4091` — taken from the target
`<asm/unistd_o32.h>` via `<sys/syscall.h>`, printed by the probe at
startup and matching the table above.

## 8. Instruction Encoding

Every trap assembles to the word `0x0000000c`
(`SPECIAL 000000 | code 0x00000 | SYSCALL 001100` — code field zero,
which Linux ignores). `objdump -d` sample:

```text
400ee4: 3c063333  lui   a2,0x3333
400ee8: 34c63333  ori   a2,a2,0x3333
400eec: 3c072222  lui   a3,0x2222
400ef0: 34e72222  ori   a3,a3,0x2222
...
400f00: 0411fed4  bal   400a54 <callee_ll>
...
401370: 0000000c  syscall
```

`130` occurrences of the `0000000c` word in `probe-le` (7 probe
wrappers + glibc startup/libc). Raw wrappers place stack args with
`sw t0,16(sp)` / `sw t1,20(sp)` (encodings `afa80010/af90014`) after
`addiu sp,sp,-32` (`27bdffe0`), trap, then `move` `$v0/$a3` out and
`addu sp,sp,32`.

## 9. Reproduction

From the worktree root (`../mips32rt-e01`): the probe lives in
`experiments/E01/` (`probe.c`, `run.sh`, this file). Inside the lane
container (`debian:stable-slim`, toolchain per §1):

```sh
cd experiments/E01 && ./run.sh   # builds LE+BE, runs both under qemu
test -s experiments/E01/FINDINGS.md   # lane acceptance command
```
