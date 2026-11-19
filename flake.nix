{
  description = "Standalone C11 + embedded Psy auth and model-routing daemon/CLI";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    psy.url = "path:/home/y0usaf/dev/developing/psy";
    psy.inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs =
    { self, nixpkgs, psy }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
    in
    {
      packages = forAllSystems (
        pkgs:
        let
          auth-router = pkgs.stdenv.mkDerivation {
            pname = "auth-router";
            version = "0.1.0";
            src = self;
            nativeBuildInputs = [ pkgs.mbedtls ];
            makeFlags = [
              "PREFIX=$(out)"
              "PSY_DIR=${psy}"
              "MBEDTLS_DIR=${pkgs.mbedtls}"
            ];
            buildFlags = [ "auth-router" ];
            installTargets = [ "install" ];
            meta = {
              description = "Standalone C11 + embedded Psy auth and model-routing daemon/CLI";
              mainProgram = "auth-router";
            };
          };
        in
        {
          default = auth-router;
          inherit auth-router;
        }
      );

      apps = forAllSystems (
        pkgs:
        let
          pkg = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
        in
        {
          default = {
            type = "app";
            program = "${pkg}/bin/auth-router";
            inherit (pkg) meta;
          };
        }
      );

      checks = forAllSystems (
        pkgs:
        let
          pkg = self.packages.${pkgs.stdenv.hostPlatform.system}.default;
          psyBin = "${psy.packages.${pkgs.stdenv.hostPlatform.system}.default}/bin/psy";
          pkgClosure = pkgs.closureInfo { rootPaths = [ pkg ]; };
        in
        {
          policy-smt = pkgs.runCommand "auth-router-policy-smt"
            {
              nativeBuildInputs = [ pkgs.z3 pkgs.gnugrep ];
            }
            ''
              ${psyBin} check ${self}/policy/router.psy
              ${psyBin} emit-smt ${self}/policy/router.psy > out.smt2
              z3 out.smt2 > z3.out
              cat z3.out
              if grep -vx 'invariant .*' z3.out | grep -vx 'unsat' > bad.out; then
                echo "Unexpected Z3 output:" >&2
                cat bad.out >&2
                exit 1
              fi
              unsat_cnt=$(grep -cx 'unsat' z3.out)
              if [ "$unsat_cnt" -ne 9 ]; then
                echo "Expected exactly 9 unsat invariants, got $unsat_cnt" >&2
                exit 1
              fi
              cp ${self}/policy/router.psy broken.psy
              chmod u+w broken.psy
              printf '\ninvariant broken_route_rank : forall s in m_slot => s.route_rank == 99\n' >> broken.psy
              ${psyBin} check broken.psy
              ${psyBin} emit-smt broken.psy > broken.smt2
              z3 broken.smt2 > broken.out
              if ! grep -qx 'sat' broken.out; then
                echo "Negative SMT check failed: broken invariant was not rejected" >&2
                exit 1
              fi
              mkdir -p "$out"
              cp z3.out "$out/result"
            '';

          e2e = pkgs.runCommand "auth-router-e2e"
            {
              nativeBuildInputs = [
                pkgs.python3
                pkgs.openssl
                pkgs.glibc.bin
                pkgs.coreutils
              ];
            }
            ''
              env -i PATH="$PATH" TMPDIR="$TMPDIR" \
                python3 ${self}/tests/e2e.py ${pkg}/bin/auth-router ${pkgClosure}/total-nar-size
              mkdir -p "$out"
              echo "ok" > "$out/result"
            '';
        }
      );
    };
}
