# `mips32rt` — MIPS32r2 (`mipsel` LE & `mips` BE, O32 ABI) User-Mode Binary Translator for AArch64

`mips32rt` is a zero-dependency, static-PIE (`aarch64-unknown-linux-musl`) user-mode binary translator for **MIPS32r2 (`mipsel` LE & `mips` BE, O32 ABI)** Linux ELF binaries on AArch64 Linux and macOS on Apple Silicon (via [`hyper-linux`](../hyper-linux)).

- **Series Tier**: Tier 1 (Wave 3 — Class-A 32-Bit 4 GiB Window)
- **Target CPUs**: MIPS 24Kc / 24KEc / 74Kc (MediaTek MT7620, Qualcomm Atheros AR9331/QCA9531) and Ingenic XBurst (JZ4770)
- **ELF Admission**: `ELFCLASS32`, `e_machine == EM_MIPS (8)`, both `ELFDATA2LSB` (`mipsel`, primary) and `ELFDATA2MSB` (`mips` BE), `(e_flags & EF_MIPS_ABI2) == 0` and `(e_flags & EF_MIPS_ABI) in {0, E_MIPS_ABI_O32 (0x00001000)}`
- **Guest `TASK_SIZE`**: `0x7fff8000 (2 GiB useg compat limit; stack top 0x7fff0000, sigtramp 0x7fff7000)`
- **Dual Execution Engines**:
  1. `src/interp/` — Portable Curated C11 reference interpreter and differential oracle (`MIPS32RT_ENGINE=interp`)
  2. `src/dbt/` — Direct-mapped + IBTC AArch64 dynamic binary translator (`MIPS32RT_ENGINE=dbt`, default) with single-instruction interpreter fallback (`EXIT_UNDEF` / `EXIT_SINGLE_STEP`)

---

## Key Documents

| Document | Purpose |
|---|---|
| [`AGENTS.md`](AGENTS.md) | Repository ground rules, Curated C11 & AArch64 ABI invariants, Muse Spark Coordinator + Parallel Worker-Lane worktree protocol, and host environment notes. |
| [`SPEC.md`](SPEC.md) | Complete technical specification for `mips32rt` (CPU context, ISA semantics, syscall/signal/thread ABI, host contract, and 9-phase verification pipeline). |
| [`GOAL.md`](GOAL.md) | Executable `/goal` specification for autonomous Muse Spark implementation (`Phase E` -> `Phase 0..Phase 7`). |
| [`docs/lanes/`](docs/lanes/) | Phase task cards (`phase-e.md`, `phase-0.md`, and subsequent phase lane cards). |
| [`../rt-series/`](../rt-series/) | Series-wide architecture (`../rt-series/SPEC.md`), master plan (`../rt-series/PLAN.md`), and host contract (`../rt-series/docs/HOST-CONTRACT.md`). |
