{
  description = "mips32rt — MIPS32r2 (mipsel/mips O32) to AArch64 Linux user-mode binary translator";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = { self, nixpkgs }:
    let
      darwinSystem = "aarch64-darwin";
      darwinPkgs   = nixpkgs.legacyPackages.${darwinSystem};
      linuxSystem  = "x86_64-linux";
      linuxPkgs    = nixpkgs.legacyPackages.${linuxSystem};
      aarch64LinuxPkgs = nixpkgs.legacyPackages.aarch64-linux;

      # Cross-compilers for aarch64-unknown-linux-musl (mips32rt itself)
      darwinA64Musl = darwinPkgs.pkgsCross.aarch64-multiplatform-musl;
      linuxA64Musl  = linuxPkgs.pkgsCross.aarch64-multiplatform-musl;

      # Build form for the L0a acceptance check on this host
      # (aarch64-darwin + nix external builders): plain
      #   nix build .#mips32rt
      # schedules fine — the darwin->aarch64-linux-musl cross toolchain
      # (aarch64-unknown-linux-musl-gcc-wrapper) is substituted from
      # cache.nixos.org and only the mips32rt derivation builds locally.
      # No --system aarch64-linux fallback was needed.
      mkMips32rt = crossPkgs: crossPkgs.stdenv.mkDerivation {
        pname = "mips32rt";
        version = "0.1.0";
        src = ./.;

        dontStrip = true;
        enableParallelBuilding = true;

        buildPhase = ''
          runHook preBuild
          CC="${crossPkgs.stdenv.cc.targetPrefix}gcc"
          command -v "$CC" >/dev/null 2>&1 || CC="${crossPkgs.stdenv.cc.targetPrefix}cc"
          make build CC="$CC"
          runHook postBuild
        '';

        installPhase = ''
          runHook preInstall
          mkdir -p $out/bin $out/include
          cp _build/mips32rt $out/bin/mips32rt
          # argv0 alias for binfmt_misc registration (mirrors i686rt/a32rt).
          ln -sf mips32rt $out/bin/mips32rt-binfmt-p
          cp include/a32host.h $out/include/a32host.h
          runHook postInstall
        '';

        meta = with crossPkgs.lib; {
          description = "Standalone static-PIE MIPS32r2 (mipsel/mips O32) -> AArch64 Linux user-mode translator";
          mainProgram = "mips32rt";
          platforms = [ "aarch64-linux" ];
          license = licenses.asl20;
        };
      };

      # mkMips32rtTests — eval-only placeholder, intentionally a plain
      # attrset (nothing to build yet).  Phase 1 lands the real guest
      # fixture suite: MIPS test binaries must be cross-built with the
      # mipsel/mips musl or glibc toolchains — NEVER host cc.
      mkMips32rtTests = {
        status = "placeholder — fixtures arrive in Phase 1 via pkgsCross.mipsel-linux-gnu (E01); never host cc";
      };

    in {
      packages.${darwinSystem} = {
        mips32rt  = mkMips32rt darwinA64Musl;
        default = self.packages.${darwinSystem}.mips32rt;
      };

      checks.${darwinSystem} = {
        mips32rt = self.packages.${darwinSystem}.mips32rt;
      };

      packages.${linuxSystem} = {
        mips32rt  = mkMips32rt linuxA64Musl;
        default = self.packages.${linuxSystem}.mips32rt;
      };

      checks.${linuxSystem} = {
        mips32rt = self.packages.${linuxSystem}.mips32rt;
      };

      packages.aarch64-linux = {
        mips32rt  = mkMips32rt aarch64LinuxPkgs.pkgsMusl;
        default = self.packages.aarch64-linux.mips32rt;
      };

      checks.aarch64-linux = {
        mips32rt = self.packages.aarch64-linux.mips32rt;
      };

      # Exposed for `nix eval .#mips32rtTests` only (eval-only, see above).
      mips32rtTests = mkMips32rtTests;

      # ── Hydra Jobs (ci.zw3rk.com) ───────────────────────────────────
      hydraJobs = {
        ${linuxSystem} = {
          mips32rt = self.packages.${linuxSystem}.mips32rt;
        };
        aarch64-linux = {
          mips32rt = self.packages.aarch64-linux.mips32rt;
        };
        ${darwinSystem} = {
          mips32rt = self.packages.${darwinSystem}.mips32rt;
        };
      };

      devShells.${darwinSystem}.default = darwinPkgs.mkShell {
        name = "mips32rt-dev";
        buildInputs = [
          darwinPkgs.gnumake
          darwinA64Musl.stdenv.cc
        ];
      };
    };
}
