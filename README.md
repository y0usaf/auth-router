# auth-router

Standalone C11 credential pool and cross-provider model routing daemon/CLI built as a fully static musl binary with zero runtime shared libraries.

Because it is statically linked against musl, DNS and host resolution read `/etc/hosts` and `/etc/resolv.conf` directly without glibc NSS modules (such as `nss-mdns` or `systemd-resolved` NSS plugins).

## Quotas (`atop`)

`auth-router quota [--json]` reads live usage for every stored credential: Anthropic OAuth windows (5-hour, 7-day, per-model weekly, monthly extra usage), Codex windows and spend control, Vercel AI Gateway credits, and Antigravity per-model quota. The same binary installed as `atop` prints a compact table; on a terminal it redraws every 60 seconds until `q` or Ctrl-C, and when piped it prints once. `atop --json` prints the machine form.

The daemon probes accounts in parallel (20 s ceiling per round; a slow or failing account gets its own error row), refreshes tokens through the same locked refresh path as `token`, and caches each account's reading: Anthropic for 5 minutes, others for 2 minutes, longer after errors or a `Retry-After`. Antigravity readings use the token agy keeps under `$XDG_DATA_HOME/omp/antigravity-cli`, matched by the account's Google email, and never refresh or rewrite it. The restricted socket cannot run `quota`.

## Build and check

```sh
nix build --no-link
nix flake check
```
