# E05 FINDINGS — LWL/LWR and SWL/SWR unaligned semantics (mipsel + mips BE)

qemu-verified ground truth for both endiannesses. No UNVERIFIED items:
every value below was executed under qemu-user.

## Toolchain identities

- Cross-compiler (both): `mipsel-linux-gnu-gcc (Debian 14.2.0-13) 14.2.0`
  and `mips-linux-gnu-gcc (Debian 14.2.0-13) 14.2.0`
  (`gcc-mipsel-linux-gnu` + `gcc-mips-linux-gnu` Debian trixie packages).
- QEMU: `qemu-mipsel version 10.0.13 (Debian 1:10.0.13+ds-0+deb13u1)`
  and `qemu-mips version 10.0.13 (same build)`.
- Container: `debian:stable-slim` (`--platform linux/arm64`), packages
  `qemu-user gcc-mipsel-linux-gnu gcc-mips-linux-gnu
  libc6-dev-mipsel-cross libc6-dev-mips-cross
  binutils-mipsel-linux-gnu binutils-mips-linux-gnu`.

## Exact build / run commands

Host (worktree root `../mips32rt-e05`):

```sh
docker run -d --name mips32rt-e05-setup --memory 2g --cpus 2 \
  --platform linux/arm64 -v "$PWD:/w" -w /w debian:stable-slim sleep 1200
docker exec mips32rt-e05-setup sh -c 'apt-get update -qq && \
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq qemu-user \
  gcc-mipsel-linux-gnu gcc-mips-linux-gnu libc6-dev-mipsel-cross \
  libc6-dev-mips-cross binutils-mipsel-linux-gnu binutils-mips-linux-gnu'
docker exec mips32rt-e05-setup sh -c 'cd /w/experiments/E05 && sh run.sh'
docker rm -f mips32rt-e05-setup; docker ps   # cleanup check
```

Inside container (`experiments/E05/run.sh`):

```sh
mipsel-linux-gnu-gcc -march=mips32r2 -O1 -static -Wall -Wextra -o probe-le probe.c
mips-linux-gnu-gcc   -march=mips32r2 -EB -O1 -static -Wall -Wextra -o probe-be probe.c
timeout --kill-after=30s 60s qemu-mipsel ./probe-le   # exit 0
timeout --kill-after=30s 60s qemu-mips   ./probe-be   # exit 0
```

Notes: `-static` is required (qemu-user has no dynamic-loader sysroot:
dynamic build fails with `Could not open '/lib/ld.so.1'`). `readelf -h`
reports `ELF32`, `MIPS R3000`, `Data: little/big endian` respectively.
`-march=mips32r2` accepted; LWL/LWR/SWL/SWR assemble (removed only in r6).

Probe setup: `area[16]` 8-aligned, `M[0..3] = 11:22:33:44`, rest `00`;
`INIT_RT = 0xAABBCCDD` (MSB `AA`, LSB `DD`). Full logs: `out-le.txt`,
`out-be.txt`. Both runs printed `DONE`, exit code `0`.

## Instruction encodings (objdump `--show-raw-insn`, identical both ends)

Opcodes: LWL `0x22`, LWR `0x26`, SWL `0x2A`, SWR `0x2E`.

```text
88470000  lwl  a3,0(v0)      98470000/98470003  lwr  a3,0/3(v0)
a8550000/a8550003  swl  s5,0/3(v0)   b8550000  swr  s5,0(v0)
```

Corroboration: the statically linked glibc `memcpy` uses the same idioms —
LE build: `lwl v0,3(v1)` + `lwr v0,0(v1)`; BE build: `lwl v0,0(v1)` +
`lwr v0,3(v1)`.

## LE (qemu-mipsel) results — M = 11:22:33:44, init = AABBCCDD

| off | LWL result | LWR result | SWL mem[0..5]        | SWR mem[0..5]        |
|-----|------------|------------|----------------------|----------------------|
| 0   | 11BBCCDD   | 44332211   | AA:00:00:00:00:00    | DD:CC:BB:AA:00:00    |
| 1   | 2211CCDD   | AA443322   | BB:AA:00:00:00:00    | 00:DD:CC:BB:00:00    |
| 2   | 332211DD   | AABB4433   | CC:BB:AA:00:00:00    | 00:00:DD:CC:00:00    |
| 3   | 44332211   | AABBCC44   | DD:CC:BB:AA:00:00    | 00:00:00:DD:00:00    |

LE merge rules (`A = PA+k`, `M[j]` = byte at `PA+j`):
- `LWL`: top `k+1` bytes of rt <- `M[0..k]`, `M[k]` lands at MSB; low bytes kept.
- `LWR`: low `4-k` bytes of rt <- `M[k..3]`, `M[k]` lands at LSB; high bytes kept.
- `SWL`: `M[0..k]` <- top `k+1` bytes of rt, MSB -> `M[k]`.
- `SWR`: `M[k..3]` <- low `4-k` bytes of rt, LSB -> `M[k]`.

## BE (qemu-mips) results — M = 11:22:33:44, init = AABBCCDD

| off | LWL result | LWR result | SWL mem[0..5]        | SWR mem[0..5]        |
|-----|------------|------------|----------------------|----------------------|
| 0   | 11223344   | AABBCC11   | AA:BB:CC:DD:00:00    | DD:00:00:00:00:00    |
| 1   | 223344DD   | AABB1122   | 00:AA:BB:CC:00:00    | CC:DD:00:00:00:00    |
| 2   | 3344CCDD   | AA112233   | 00:00:AA:BB:00:00    | BB:CC:DD:00:00:00    |
| 3   | 44BBCCDD   | 11223344   | 00:00:00:AA:00:00    | AA:BB:CC:DD:00:00    |

BE merge rules:
- `LWL`: top `4-k` bytes of rt <- `M[k..3]`, `M[k]` lands at MSB; low bytes kept.
- `LWR`: low `k+1` bytes of rt <- `M[0..k]`, `M[k]` lands at LSB; high bytes kept.
- `SWL`: `M[k..3]` <- top `4-k` bytes of rt, MSB -> `M[k]`.
- `SWR`: `M[0..k]` <- low `k+1` bytes of rt, LSB -> `M[k]`.

So the LWL/LWR (and SWL/SWR) roles mirror across endianness: LE-LWL
behaves like BE-LWR with the index reflected (`k` <-> `3-k`), and vice
versa. Per-architecture-manual phrasing: LWL takes the bytes from the
containing aligned word on the MSB side of the effective address into the
MSB side of rt; LWR takes the LSB side into the LSB side.

## Same-address pairs are NOT the unaligned-word idiom

`LWL x; LWR x` (same `x`), init `AABBCCDD`:

- LE off=1: `22443322`; off=2: `33224433`; off=0/3: `44332211`/`44332244`.
- BE off=1: `22331122`; off=2: `33112233`; off=0/3: `11223311`/`11223344`.

A DBT must not lower an unaligned LW to a same-address pair.

## True unaligned idioms verified (sentinel 55:66:77 at M[4..6])

- LE idiom `lwr 0(A); lwl 3(A)` — ULW: off0 `44332211`, off1 `55443322`,
  off2 `66554433`, off3 `77665544` (= bytes `M[k..k+3]` as LE word).
- BE idiom `lwl 0(A); lwr 3(A)` — ULW: off0 `11223344`, off1 `22334455`,
  off2 `33445566`, off3 `44556677`. Cross-boundary byte picked up in all
  `k>0` cases on both ends.
- LE store idiom `swr 0(A); swl 3(A)` storing `AABBCCDD` — USW:
  `DD:CC:BB:AA`, `00:DD:CC:BB:AA:00`, `00:00:DD:CC:BB:AA`,
  `00:00:00:DD:CC:BB`.
- BE store idiom `swl 0(A); swr 3(A)` — USW:
  `AA:BB:CC:DD`, `00:AA:BB:CC:DD:00`, `00:00:AA:BB:CC:DD`,
  `00:00:00:AA:BB:CC`.

## Plain unaligned LW / SW fault behavior

All of `LW off=1,2,3` and `SW off=1,2,3` on BOTH endiannesses:

```text
LW off=1 value=UNSET signal=10
SW off=1 mem=UNSET signal=10
```

`signal=10` is **SIGBUS on MIPS** (MIPS signums: SIGBUS=10, SIGSEGV=11).
qemu-user converts the guest AdEL/AdES address-error exception into
SIGBUS; it does NOT silently emulate misaligned LW/SW. A DBT must raise
the AdEL/AdES equivalent for plain misaligned LW/SW while LWL/LWR/SWL/SWR
at any byte address succeed.
