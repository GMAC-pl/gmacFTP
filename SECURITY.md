# Security Policy

gmacFTP handles server addresses, usernames, passwords, local paths, and file transfers, so security issues should be treated carefully.

## Supported Versions

The project is pre-1.0. Security fixes are provided for the latest published release and the
`main` branch; older releases should be upgraded.

## Reporting A Vulnerability

Report vulnerabilities privately through
[GitHub Security Advisories](https://github.com/GMAC-pl/gmacFTP/security/advisories/new).

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

gmacFTP ships **macOS-only**. The release lockfile currently has three known vulnerability
advisories, all explicitly reviewed:

- **macOS dependency, vulnerable operation not used.** `rsa 0.10.0-rc.18`
  (RUSTSEC-2023-0071, "Marvin Attack", MEDIUM 5.9) is pulled in transitively by `russh` and has
  no fixed release. The affected operation is RSA private-key decryption. gmacFTP does not load
  user private keys or perform public-key authentication: its SFTP client uses password
  authentication and verifies the server's public host key. CI therefore accepts this advisory
  until `russh` can remove or replace the dependency.
- **Linux-only.** `quick-xml 0.39.4` (RUSTSEC-2026-0194 and RUSTSEC-2026-0195, both HIGH 7.5)
  is pulled by Slint's Wayland/accessibility dependency graph. It is absent from both macOS
  target graphs (`cargo tree -i quick-xml --target aarch64-apple-darwin` and the equivalent
  x86_64 command return nothing), so these parsers are not compiled into the distributed app.

The dependency audit also reports informational maintenance/unsoundness warnings. The GTK3,
X11 and Wayland group (`atk`, `gdk`, `gtk`, `glib`, `bincode`, and `proc-macro-error`) is absent
from the macOS target. `paste` is a proc-macro/build dependency and `ttf-parser` is a macOS
dependency of Slint's font/rendering stack; RustSec currently marks their pinned versions
unmaintained. These warnings have no known vulnerability entry and do not change
`cargo audit`'s exit status; they remain tracked for future Slint upgrades.

RUSTSEC-2026-0186 is fixed by pinning `memmap2 0.9.11`; the lockfile also contains the non-yanked
`crypto-bigint 0.7.5`. CI ignores only the three reviewed vulnerability IDs above, so every new
vulnerability fails the audit gate.
