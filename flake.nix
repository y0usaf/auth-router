{
  description = "Standalone C11 auth and model-routing daemon/CLI";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs =
    { self, nixpkgs }:
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
              "MBEDTLS_DIR=${pkgs.mbedtls}"
            ];
            buildFlags = [ "auth-router" ];
            installTargets = [ "install" ];
            meta = {
              description = "Standalone C11 auth and model-routing daemon/CLI";
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
          pkgClosure = pkgs.closureInfo { rootPaths = [ pkg ]; };
        in
        {
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
