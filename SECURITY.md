# Security Policy

gmacFTP handles server addresses, usernames, passwords, local paths, and file transfers, so security issues should be treated carefully.

## Supported Versions

The project is pre-1.0. Security fixes are handled on the main development line until formal releases exist.

## Reporting A Vulnerability

If the repository is published with GitHub Security Advisories enabled, report vulnerabilities privately through that feature.

If private advisories are not available yet, open a minimal issue that describes the class of problem without including credentials, server names, logs with tokens, or private file paths. Maintainers can then coordinate a safe disclosure path.

## Sensitive Data Rules

Do not attach:

- Real FTP/SFTP passwords
- Private connection export files
- Full local home-directory screenshots
- Production host lists
- Keychain or vault files
- Logs containing credentials, tokens, or private paths

Use localhost test servers or placeholder domains such as `example.com` when reproducing issues.

## Known dependency advisories (`cargo audit`)

gmacFTP ships **macOS-only**. `cargo audit` surfaces advisories that fall into three buckets —
only the first affects the shipping binary:

- **macOS runtime, accepted risk.** `rsa 0.10.0-rc.18` (RUSTSEC-2023-0071, "Marvin Attack",
  MEDIUM 5.9) is pulled in transitively by `russh` (SFTP). There is **no upstream fix** (the
  RustCrypto RSA maintainer considers the timing side-channel out of scope). Practical exposure
  for an interactive GUI FTP client is low; prefer **ed25519** SSH host keys (already supported)
  to avoid RSA key exchange entirely. CI's `audit` job ignores this one ID so it can still gate
  on every other advisory.
- **macOS runtime, not exploitable here.** `memmap2 0.9.10` (RUSTSEC-2026-0186, unsound raw
  pointer offset) and `crypto-bigint 0.7.4` (yanked — a registry state, not a security defect)
  reach the macOS binary via fontique/russh, but gmacFTP does not exercise the flagged code
  paths. `anyhow`'s unsoundness (RUSTSEC-2026-0190) is **fixed** — Cargo.lock is pinned to
  1.0.103 (bumped during this audit pass), so it no longer flags.
- **Linux-only / build-only (NOT in the macOS binary).** `quick-xml` (RUSTSEC-2026-0194/0195,
  both HIGH 7.5 — ignored in CI as Linux-only), plus the GTK3/X11/Wayland family (`atk`, `gtk`,
  `gdk`, `glib`, `bincode`, `proc-macro-error`, …) pulled by Slint's winit Linux backends, and
  the build-time proc-macros `paste` and `ttf-parser` — `cargo tree -i <crate> --target
aarch64-apple-darwin` returns "nothing to print" for all of them. They will disappear when a
  future Slint bump moves winit. They are tracked, not shippable, and cannot affect macOS users.

When `cargo audit` is run locally, expect these to appear; they are reviewed and classified here.
