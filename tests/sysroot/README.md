# `tests/sysroot/` — minimal committed MIPS32r2 runtime fixture for `p5_dyn`

`tests/parity_suite.sh` runs the dynamic guests (`p5-le`, `p5-be`) under
both `qemu-mipsel`/`qemu-mips` (`-L tests/sysroot`) and `mips32rt`
(`--interp`/`--dbt --sysroot tests/sysroot`), so the smoke path needs no
host cross-toolchain and no network. Only the files the guest loader
actually opens are kept:

- `mipsel/lib/ld.so.1` — LE `PT_INTERP` (`-Wl,--dynamic-linker=/mipsel/lib/ld.so.1`)
- `mipsel/lib/libc.so.6` — LE `DT_NEEDED` (via `-Wl,-rpath,/mipsel/lib`)
- `mips/lib/ld.so.1` — BE `PT_INTERP` (`-Wl,--dynamic-linker=/mips/lib/ld.so.1`)
- `mips/lib/libc.so.6` — BE `DT_NEEDED` (via `-Wl,-rpath,/mips/lib`)

Both endians request the absolute interpreter `/mipsel/lib/ld.so.1` (LE)
or `/mips/lib/ld.so.1` (BE) because the default `/lib/ld.so.1` collides
across endians under one sysroot. The translator prefixes absolute
guest opens with `--sysroot` (`mips_sysroot_open` in `src/vm/vm_file.c`,
read-only non-creating opens only); `qemu -L` resolves the same
absolute paths. `DT_RPATH` keeps the helper shared object out of the
fixture: `p5helper-{le,be}.so` is passed as a relative guest `argv[1]`
and resolves against the suite's `_build/parity` working directory on
every runner.

Provenance: extracted from the pinned `mips32rt-tool` image
(`debian:bookworm-slim`, `gcc-mipsel-linux-gnu` / `gcc-mips-linux-gnu`
12.2.0, `libc6-dev-mipsel-cross` / `libc6-dev-mips-cross` 2.36), which is
the same image the Docker leg builds and runs guests with:

```sh
docker run --rm --platform linux/arm64 \
  -v "$PWD:/w" -w /w mips32rt-tool bash -lc '
    mkdir -p tests/sysroot/mipsel/lib tests/sysroot/mips/lib
    for f in ld.so.1 libc.so.6; do
      cp -a /usr/mipsel-linux-gnu/lib/$f tests/sysroot/mipsel/lib/$f
      cp -a /usr/mips-linux-gnu/lib/$f tests/sysroot/mips/lib/$f
    done'
```

Re-verify after refreshing the fixture (from the repository root):

```sh
sh tests/parity_suite.sh   # p5_dyn rows: 0 FAIL, 0 GAP, 0 SKIP
```
