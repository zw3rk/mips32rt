# E06 FINDINGS — TLS (`rdhwr $29` / `set_thread_area`) and LL/SC

All results below are qemu-verified ground truth (nothing marked UNVERIFIED:
both LE and BE were executed).

## Toolchain identities

- Cross-compiler LE: `mipsel-linux-gnu-gcc (Debian 12.2.0-14) 12.2.0`
- Cross-compiler BE: `mips-linux-gnu-gcc (Debian 12.2.0-14) 12.2.0`
  (Debian bookworm `gcc-mipsel-linux-gnu` / `gcc-mips-linux-gnu` packages,
  `libc6-dev-mipsel-cross` / `libc6-dev-mips-cross`)
- QEMU LE: `qemu-mipsel version 7.2.22 (Debian 1:7.2+dfsg-7+deb12u18+b3)`
- QEMU BE: `qemu-mips version 7.2.22 (Debian 1:7.2+dfsg-7+deb12u18+b3)`
- Container: `--platform linux/arm64 debian:bookworm-slim`
  (`docker run -d --name mips32rt-e06 --memory 2g --cpus 2 ...`, removed after)

## Exact build / run commands

```sh
cd experiments/E06
./run.sh mipsel   # = mipsel-linux-gnu-gcc -static -O2 -mabi=32 \
                  #     -o probe_mipsel probe.c -pthread
                  #   timeout --kill-after=30s 60s qemu-mipsel ./probe_mipsel
./run.sh mips     # = mips-linux-gnu-gcc -static -O2 -mabi=32 \
                  #     -o probe_mips probe.c -pthread
                  #   timeout --kill-after=30s 60s qemu-mips ./probe_mips
```

Both binaries: `ELF 32-bit {LSB,MSB} executable, MIPS, MIPS32 rel2
version 1 (SYSV), statically linked, for GNU/Linux 3.2.0`.
Both runs: `E06 RESULT: PASS`, exit code 0.

## (1) TLS: `set_thread_area` + `rdhwr $29`

- `__NR_set_thread_area = 4283` (used via `syscall(4283, addr)`; rc 0).
- `rdhwr $v1,$29` encoding verified in objdump output: **`0x7c03e83b`**
  (objdump disassembles it as `rdhwr v1,$29`; the probe also executes this
  exact word and cross-checks it against the `rdhwr %0,$29` mnemonic form).

Observed LE values (`qemu-mipsel`):

| quantity | value |
|---|---|
| `rdhwr` before (mnemonic) | `0x004b94e0` |
| `rdhwr` before (fixed word `0x7c03e83b`) | `0x004b94e0` (match) |
| `&tls_var` (`__thread int = 42`) | `0x4b24e0` (28672 bytes from ULR) |
| `pthread_self()` | `0x4b2000` |
| `set_thread_area(0x51ab0001)` rc | `0` |
| `rdhwr` after set | `0x51ab0001` (exact round-trip) |
| `rdhwr` after restore | `0x004b94e0` (matches original) |
| `tls_var` after round-trip | `42` (intact) |

Observed BE values (`qemu-mips`): identical shape —
ULR before `0x004b84e0`, `&tls_var = 0x4b14e0` (28672 bytes away),
`pthread_self() = 0x4b1000`, set/restore round-trip exact, `tls_var` intact.

Notes:

- The fixed-encoding read saves/restores `$3` around the raw `.word`
  (no reliance on `$3`-clobber spelling); mnemonic and raw-word reads agree.
- No libc call is made between the test `set_thread_area` and the restore:
  an earlier revision called `printf` while a foreign value (`0x51ab0001`)
  was installed as the TLS pointer and died with
  `qemu: uncaught target signal 10 (Bus error)`. Restoring first fixes it.
  Output is unbuffered (`setvbuf(stdout, NULL, _IONBF, 0)`).

## (2) LL/SC atomic increment across two pthreads

Loop body (`llsc_add1`):

```asm
1: ll   old, 0(p)
   addu new, old, 1
   sc   new, 0(p)
   beqz new, 1b
   nop
```

Objdump (LE `.o`, `ll`/`sc` words):

```text
c0640000    ll  a0,0(v1)
e0650000    sc  a1,0(v1)
```

Two threads x 200000 increments of a shared `volatile int`:

| run | final | expected | lost updates |
|---|---|---|---|
| LE `qemu-mipsel` | `400000` | `400000` | none |
| BE `qemu-mips` | `400000` | `400000` | none |

## (3) SC fails after an intervening store

Sequence (`sc_after_store`): `ll` → plain `sw` of `0x11111111` to the same
address → `sc` of `0x22222222`. Objdump words:

```text
c0450000    ll  a1,0(v0)
ac430000    sw  v1,0(v0)   (interfering store)
e0440000    sc  a0,0(v0)
```

| run | `sc` return | final cell |
|---|---|---|
| LE `qemu-mipsel` | `0` (failure, as required) | `0x11111111` |
| BE `qemu-mips` | `0` (failure, as required) | `0x11111111` |

Signal-interference (async-signal handler between LL and SC) was **not**
demonstrated: the plain-store case above satisfies the lane's "at least the
store-interference case" clause; anything beyond that is UNVERIFIED.

## Raw program output (LE)

```text
E06 TLS + LL/SC probe
__NR_set_thread_area=4283 (expect 4283)
rdhwr-mnemonic ulr_before=0x004b94e0
rdhwr-fixed-0x7c03e83b ulr=0x004b94e0
&tls_var=0x4b24e0 tls_var=42 pthread_self=0x4b2000
ok: initial ULR nonzero
ok: rdhwr $v1,$29 (0x7c03e83b) matches mnemonic read
tls_var-ulr distance=28672 bytes
ok: __thread var adjacent to ULR
after set_thread_area(0x51ab0001): rdhwr=0x51ab0001
ok: rdhwr $29 returns set_thread_area value
after restore: rdhwr=0x004b94e0 (expect 0x004b94e0)
ok: ULR restored
ok: __thread var intact after TLS round-trip
ll/sc hammer: final=400000 expected=400000
ok: LL/SC increment atomic across 2 threads
sc_after_store: scres=0 cell=0x11111111
ok: SC returns 0 after intervening store
E06 RESULT: PASS
```

(BE output identical except ULR `0x004b84e0`, `&tls_var 0x4b14e0`,
`pthread_self 0x4b1000`.)
