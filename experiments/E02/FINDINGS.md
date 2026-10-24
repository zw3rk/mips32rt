# E02 FINDINGS — branch delay slots, BEQL annulment, page-end faults

## Toolchain (exact, qemu-verified)

- Cross compiler LE: `mipsel-linux-gnu-gcc (Debian 12.2.0-14) 12.2.0`
- Cross compiler BE: `mips-linux-gnu-gcc (Debian 12.2.0-14) 12.2.0`
- Oracle LE: `qemu-mipsel version 7.2.22 (Debian 1:7.2+dfsg-7+deb12u18+b3)`
- Oracle BE: `qemu-mips version 7.2.22 (Debian 1:7.2+dfsg-7+deb12u18+b3)`
- ELF type: `EXEC (Executable file)`, machine `MIPS R3000` (static
  non-PIE, so objdump addresses are absolute runtime addresses).
- Data model observed at runtime: `sizeof(void *) = 4` (O32 ILP32).

## Build / run commands (exact)

```sh
mipsel-linux-gnu-gcc -O2 -static -o probe-le probe.c
mips-linux-gnu-gcc   -O2 -static -o probe-be probe.c
timeout --kill-after=30s 60s qemu-mipsel ./probe-le   # rc-le=0
timeout --kill-after=30s 60s qemu-mips   ./probe-be   # rc-be=0
```

Full script: [run.sh](./run.sh); probe source: [probe.c](./probe.c).
All result lines below are identical under `qemu-mipsel` (LE) and
`qemu-mips` (BE) unless noted.

## Observed results

```text
T1a beq-taken: delay=1 fall=0 targ=7 (expect 1 0 7) MATCH
T1b beq-nottaken: delay=1 fall=200 targ=0 (expect 1 200 0) MATCH
T1c bal-link: marker=0x51 ra=0x4009a0 land=0x4009a0 diff=0 MATCH
T2 layout: p1=0x3fffd000 p2=0x3fffe000(none) PRO@0x3fffd100=J(0x0bfff7ff)
           BEQL@0x3fffdffc=0x5085fcc0 off=-832
           delay@0x3fffe000 cont@0x3fffe004 safe@0x3fffd300
T2a beql-nottaken: sig=11 si_addr=0x3fffe000 sc_pc=0x3fffdffc
T2b beql-taken:    sig=11 si_addr=0x3fffe000 sc_pc=0x3fffdffc
T2c annul: beq-nt=1 beql-nt=0 beql-t=1 (expect 1 0 1) MATCH
T3 delayslot-fault: sig=11 si_addr=(nil) sc_pc=0x400b68 loaded=-1
```

## (1) Normal branch + link — VERIFIED

- Taken `BEQ`: delay slot at pc+4 executes, fallthrough skipped, control
  reaches the target.
- Not-taken `BEQ`: delay slot still executes, fallthrough executes, target
  skipped.
- `BAL` (used instead of `JAL`, see toolchain note): delay-slot marker
  `0x51` executes and link register `ra = 0x4009a0` equals the address of
  the instruction after the delay slot (`land = 0x4009a0`, diff 0).
  Objdump ground truth: `bal` at `0x400998`, so `ra = bal_pc + 8`. The
  subroutine `jr ra` returns to `0x4009a0`; execution continues normally.

## (2) BEQL annulment vs page-end fetch fault — VERIFIED, with correction

Setup as specified: two pages mapped, `mprotect` second page `PROT_NONE`,
hand-encoded `BEQL a0,a1` as the last word of page 1 (`0x3fffdffc`),
delay-slot word at `0x3fffe000` (unmapped).

- **Counting test (T2c) proves annulment semantics**: with an observable
  `addiu` counter in the delay slot, not-taken `BEQ` counts 1 (executes),
  not-taken `BEQL` counts 0 (**annulled — not executed**), taken `BEQL`
  counts 1 (executes). MATCH on LE and BE.
- **Page-end fetch behavior (T2a/T2b)**: under `qemu-user` BOTH the taken
  and the not-taken case die with `SIGSEGV`, `si_addr = 0x3fffe000`
  (the delay-slot word = page base) and `sc_pc = 0x3fffdffc` (the BEQL
  itself). So qemu fetches/translates the delay-slot word even when the
  branch is not taken — the annulled slot is *not* fetch-exempt at
  translate time, and the not-taken fallthrough (`cont = ...004`) is never
  reached. The "no SIGSEGV when not taken" expectation in the task card
  does not hold under qemu-user; the counting test (T2c) is the valid
  annulment check. Whether real silicon suppresses the fetch is
  UNVERIFIED (no hardware available).

## (3) Delay-slot signal reports branch pc — VERIFIED

`lw v1,0(zero)` in the delay slot of a taken `BEQ` raises `SIGSEGV` with
`si_addr = 0` and `ucontext.mcontext.pc (= sc_pc) = 0x400b68`, which
objdump identifies as the `beq` instruction itself (faulting `lw` is at
`0x400b6c`). So the signal pc is the **branch pc (pc-4)**, and returning
would re-execute branch + delay slot. `loaded` stays `-1` (delay store
never retires). MATCH on LE and BE (BE: branch also at `0x400b68`).

## Instruction encodings (all confirmed in objdump + runtime words)

| Mnemonic | Encoding (word) | Seen at |
|---|---|---|
| BEQ | `0x10000002` (`b`, from `beq $0,$0`) | T1a |
| BEQ zero,v0 | `0x10020003` (off 3) | T2c `0x400a2c` |
| BEQ v0,v0 | `0x10420002` (off 2) | T3 `0x400b68` |
| BEQL zero,v0 | `0x50020003` (off 3) | T2c `0x400a44` |
| BEQL zero,a3 | `0x50070003` (off 3) | T2c `0x400a58` |
| BEQL a0,a1 | `0x5085fcc0` (off -832) | T2 hand, `0x3fffdffc` |
| BAL | `0x04110004` (off 4) | T1c `0x400998` |
| J | `0x0bfff7ff` (-> `0x3fffdffc`) | T2 prologue |
| JR ra | `0x03e00008` | T1c `0x4009ac` |
| LW v1,0(zero) | `0x8c030000` | T3 `0x400b6c` |
| NOP | `0x00000000` | delay slots |
| ADDIU (counter) | `0x24a50001` etc. | T2c delay slots |

Formulae used: `BEQL = 0x50000000 | rs<<21 | rt<<16 | (off & 0xFFFF)`,
`off = (target - (pc+4)) >> 2`; `J = 0x08000000 | ((target>>2) &
0x03FFFFFF)`; upper 4 bits of prologue pc and target both `0x3`.

## Toolchain notes (matter for the DBT emitter work)

1. `jal <forward-local-label>` is PIC-expanded by GAS into a
   `lw t9,.. / bal / lw gp,..` scaffold (linker relaxes the jump to
   `bal` but keeps the scaffolding, shifting later labels). Inline asm
   must use `bal` (a real opcode) for local subroutine calls.
2. Output-only `=r` operands in inline asm make GCC drop the C
   initializer as dead; if control flow skips the writing instruction,
   the register holds garbage. Skippable test writes need `+r`.
3. `la reg, numeric-local-label` under `-mabicalls` goes through the GOT;
   the value is still correct after static link (T1c `land` matched
   `ra`), but prefer `bal`-derived or objdump ground truth for code
   addresses.
4. `si_addr` for translate-time code-fetch faults is page-granular
   (page base `0x3fffe000` for both `...000` and `...004`); `sc_pc`
   attribution is the branch/TB start (`0x3fffdffc`) in both cases.

## Repro

```sh
cd experiments/E02 && ./run.sh   # needs mipsel/mips gcc + qemu-mipsel/qemu-mips
```

BE status: VERIFIED (same binary logic, `qemu-mips`, identical results
and identical code layout). Nothing in this lane is UNVERIFIED except
real-silicon fetch suppression (see above).
