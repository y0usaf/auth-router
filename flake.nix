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
          staticPkgs = pkgs.pkgsStatic;
          mbedtlsMinimal = staticPkgs.mbedtls.overrideAttrs (old: {
            pname = "mbedtls-client-minimal";
            doCheck = false;
            postConfigure = "";
            postPatch = (old.postPatch or "") + ''
              for sym in \
                MBEDTLS_SSL_SRV_C \
                MBEDTLS_SSL_TICKET_C \
                MBEDTLS_SSL_CACHE_C \
                MBEDTLS_SSL_COOKIE_C \
                MBEDTLS_SSL_PROTO_DTLS \
                MBEDTLS_SSL_DTLS_ANTI_REPLAY \
                MBEDTLS_SSL_DTLS_HELLO_VERIFY \
                MBEDTLS_SSL_DTLS_CLIENT_PORT_REUSE \
                MBEDTLS_SSL_DTLS_CONNECTION_ID \
                MBEDTLS_SSL_DTLS_SRTP \
                MBEDTLS_SELF_TEST \
                MBEDTLS_DEBUG_C \
                MBEDTLS_VERSION_C \
                MBEDTLS_VERSION_FEATURES \
                MBEDTLS_ARIA_C \
                MBEDTLS_CAMELLIA_C \
                MBEDTLS_DES_C \
                MBEDTLS_RIPEMD160_C \
                MBEDTLS_MD5_C \
                MBEDTLS_CCM_C \
                MBEDTLS_CMAC_C \
                MBEDTLS_NIST_KW_C \
                MBEDTLS_SHA3_C \
                MBEDTLS_CIPHER_MODE_CFB \
                MBEDTLS_CIPHER_MODE_OFB \
                MBEDTLS_CIPHER_MODE_CTR \
                MBEDTLS_CIPHER_MODE_XTS \
                MBEDTLS_CIPHER_MODE_CBC \
                MBEDTLS_X509_CSR_PARSE_C \
                MBEDTLS_X509_CSR_WRITE_C \
                MBEDTLS_X509_CREATE_C \
                MBEDTLS_X509_CRT_WRITE_C \
                MBEDTLS_X509_CRL_PARSE_C \
                MBEDTLS_PK_WRITE_C \
                MBEDTLS_PEM_WRITE_C \
                MBEDTLS_ASN1_WRITE_C \
                MBEDTLS_PKCS5_C \
                MBEDTLS_PKCS7_C \
                MBEDTLS_PKCS12_C \
                MBEDTLS_LMS_C \
                MBEDTLS_LMOTS_C \
                MBEDTLS_ECJPAKE_C \
                MBEDTLS_DHM_C \
                MBEDTLS_ECDSA_DETERMINISTIC \
                MBEDTLS_HMAC_DRBG_C \
                MBEDTLS_KEY_EXCHANGE_PSK_ENABLED \
                MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED \
                MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED \
                MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED \
                MBEDTLS_KEY_EXCHANGE_DHE_RSA_ENABLED \
                MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_ENABLED \
                MBEDTLS_SSL_TLS1_3_KEY_EXCHANGE_MODE_PSK_EPHEMERAL_ENABLED \
                MBEDTLS_ECP_DP_SECP192R1_ENABLED \
                MBEDTLS_ECP_DP_SECP224R1_ENABLED \
                MBEDTLS_ECP_DP_SECP192K1_ENABLED \
                MBEDTLS_ECP_DP_SECP224K1_ENABLED \
                MBEDTLS_ECP_DP_SECP256K1_ENABLED \
                MBEDTLS_ECP_DP_BP256R1_ENABLED \
                MBEDTLS_ECP_DP_BP384R1_ENABLED \
                MBEDTLS_ECP_DP_BP512R1_ENABLED \
                MBEDTLS_ECP_DP_CURVE448_ENABLED; do
                python3 scripts/config.py unset "$sym"
              done
            '';
            cmakeFlags =
              (builtins.filter (f: !(pkgs.lib.hasPrefix "-DCMAKE_C_FLAGS=" f)) (old.cmakeFlags or [ ]))
              ++ [
                "-DCMAKE_BUILD_TYPE=MinSizeRel"
                "-DENABLE_PROGRAMS=off"
                "-DENABLE_TESTING=off"
                "-DCMAKE_C_FLAGS=-fzero-init-padding-bits=unions -ffunction-sections -fdata-sections -fno-asynchronous-unwind-tables -fno-unwind-tables"
              ];
          });
          auth-router = staticPkgs.stdenv.mkDerivation {
            pname = "auth-router";
            version = "0.1.0";
            src = self;
            makeFlags = [
              "PREFIX=$(out)"
              "MBEDTLS_DIR=${mbedtlsMinimal}"
            ];
            env = {
              CFLAGS = "-std=c11 -Os -flto -Wall -Wextra -Werror -ffunction-sections -fdata-sections -fno-asynchronous-unwind-tables -fno-unwind-tables";
              LDFLAGS = "-static -flto -Wl,--gc-sections -Wl,-s";
            };
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
                pkgs.binutils
                pkgs.glibc.bin
                pkgs.coreutils
              ];
            }
            ''
              env -i PATH="$PATH" TMPDIR="$TMPDIR" \
                python3 ${self}/tests/e2e.py ${pkg}/bin/auth-router ${pkgClosure}/total-nar-size ${pkgClosure}/store-paths
              mkdir -p "$out"
              echo "ok" > "$out/result"
            '';
        }
      );
    };
}
