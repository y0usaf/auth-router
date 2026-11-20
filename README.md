# auth-router

Standalone C11 credential pool and cross-provider model routing daemon/CLI built as a fully static musl binary with zero runtime shared libraries.

Because it is statically linked against musl, DNS and host resolution read `/etc/hosts` and `/etc/resolv.conf` directly without glibc NSS modules (such as `nss-mdns` or `systemd-resolved` NSS plugins).

## Build and check

```sh
nix build --no-link
nix flake check
```
