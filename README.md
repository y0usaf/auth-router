# auth-router

Standalone C11 credential pool and cross-provider model routing daemon/CLI built as a fully static musl binary with zero runtime shared libraries.

Because it is statically linked against musl, DNS and host resolution read `/etc/hosts` and `/etc/resolv.conf` directly without glibc NSS modules (such as `nss-mdns` or `systemd-resolved` NSS plugins).

## Quotas (`atop`)

`auth-router quota [--json]` reads live usage for every stored credential: Anthropic OAuth windows (5-hour, 7-day, per-model weekly, monthly extra usage), Codex windows and spend control, Vercel AI Gateway credits, and Antigravity per-model quota. The same binary installed as `atop` prints a compact table when piped (or with `--once`), and `atop --json` prints the machine form.

On a terminal `atop` is a full-screen view in the spirit of btop: one rounded box per account with the provider's panel number in its title, a gradient meter, percentage, reset countdown and braille usage history for every window, and a balance bar for money and credit budgets. Windows of one account that report the same usage and the same reset instant are one shared quota pool and draw as a single row, labelled by the model in use (`gemini-4-neon`, `claude-opus-5-5`) or else by the pool's first model, with `+N` for the other members; a model whose usage or reset diverges from its pool keeps its own row. The piped table groups the same way; `--json` always lists every window. Boxes stack vertically in a single aligned column by default (press `v` to toggle balanced multi-column layout); spare height turns the one-line history into taller graphs, and tight heights share horizontal borders and trim rows to `+N more` before scrolling (`j`/`k` or arrows) moves boxes off-screen. Fetches run in a child process so keys stay live, only changed cells are redrawn, and the terminal is restored on exit, suspend, `SIGTERM` and crashes. `NO_COLOR` drops colour; `COLORTERM=truecolor` enables 24-bit colour.

Keys: `q` quit, `r` refresh now (the daemon still rate-limits), `v` toggle vertical stack / multi-column layout, `1`-`4` show or hide a provider panel, `e` expand or collapse shared quota pools, `+`/`-` refresh interval (10 s to 10 min, default 60 s), `j`/`k` or `↑`/`↓` scroll when boxes overflow, `h` help.

History is a by-product of readings the view already shows: each time it receives an account reading with a newer `fetched_ms` (from the daemon, or from its own cache-honouring probe in `--direct` mode) it appends one sample per window to `$XDG_STATE_HOME/atop/history` (default `~/.local/state/atop/history`; at most 240 samples per series, series unseen for 30 days are dropped). It never triggers a provider request. `--now-ms MS` freezes the clock for reproducible output.

The daemon probes accounts in parallel (20 s ceiling per round; a slow or failing account gets its own error row), refreshes tokens through the same locked refresh path as `token`, and caches each account's reading: Anthropic for 5 minutes, others for 2 minutes, longer after errors or a `Retry-After`. Antigravity readings use the token agy keeps under `$XDG_DATA_HOME/omp/antigravity-cli`, matched by the account's Google email, and never refresh or rewrite it. The restricted socket cannot run `quota`.

## Build and check

```sh
nix build --no-link
nix flake check
```
