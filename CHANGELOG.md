# Changelog

## Unreleased

_(Nothing yet.)_

## 0.0.16 — 2026-07-05

A code-quality cleanup pass after the v0.0.15 audit. **No user-facing behavior change; no new features.** Everything works exactly as before — this release removes duplication and tightens a few internals the v0.0.15 audit introduced.

- **FTP connection internals simplified.** The plaintext-fallback flag is now a method on the connection type itself (`FtpConn::is_plaintext()`) instead of a positional `bool` threaded out of `connect()`. The same "Connected via plaintext FTP" warning surfaces in exactly the same situations.
- **Disconnect is one atomic step.** Ending a session now drops it from the pool and evicts its cached password in a single critical section (was two separate locks). No observable difference — just removes a tiny window where the pool and the password cache could disagree if a panic hit between them.
- **Updater download path: one source of truth.** The destination DMG filename is now computed once instead of three times, so the file Finder is told to open can never diverge from the one actually written.
- **Docs clarified:** the SFTP host-key re-verification after the v0.0.15 `host:port` keying change is now documented as a silent re-TOFU (it never prompted the user), and the updater's URL allowlist scope (initial URL only, not the redirect target) is spelled out.

Verified: release build + 20 unit tests + clippy + `cargo audit` all green; the signed app was built, notarized, and manually launched to check the GUI.

## 0.0.15 — 2026-07-05

A second hardening pass from a line-by-line code audit. No customer/personal data was ever at risk; these close defense-in-depth and correctness gaps the audit surfaced.

- **Atomic writes extended to `settings.json` + `known_hosts`.** The v0.0.13 "atomic writes everywhere user data lives" claim now actually covers both: a crash mid-save can no longer truncate your settings or — more importantly — the SFTP `known_hosts` trust anchor (a truncated `known_hosts` would silently re-open previously-verified hosts to MITM on the next connection).
- **Download temp files hardened against symlink-swap (CRYP-3 extended).** FTP/SFTP `.part` files and the updater DMG now open with `O_EXCL` + mode `0600` + symlink-safe retry, matching the vault. A pre-planted `<dest>.part` symlink (e.g. in `~/Downloads`) can no longer redirect downloaded bytes onto the symlink's target.
- **Updater integrity hardening.** The DMG download now (1) refuses any asset URL that isn't `https://` on `github.com`, (2) sanitizes the release version before it becomes a filename (a git tag could contain `/`), (3) streams to disk with a 300 MiB cap instead of reading the whole DMG into memory, and (4) writes via the atomic temp+rename path.
- **FTP STARTTLS downgrade is now visible.** When a server refuses TLS and the connection falls back to plaintext FTP (password sent unencrypted — an active MITM can force this), the status bar warns "Connected via plaintext FTP". The password is still never sent on the failed-secure attempt.
- **Password cache hygiene.** The session password cache (which avoids re-prompting the Keychain) now stores `Zeroizing<String>` (cleartext wiped on drop/overwrite) and evicts a session's password when that session is ejected — instead of holding every password for the whole process.
- **SFTP `known_hosts` keyed by `host:port`.** Two SFTP servers on different ports of the same host no longer collide on the bare hostname (which caused false MITM rejections or cross-port key pinning). Existing entries are re-confirmed once on first connect after the upgrade.
- **Relay copies empty files correctly.** Remote→remote relay no longer rejects legitimate 0-byte files (`.gitkeep`, markers) as "downloaded file is empty".
- **Removed the unused `ubiquity-kvstore` entitlement** (`NSUbiquitousKeyValueStore` is not used — sync is plain files in iCloud Drive). CloudKit + `keychain-access-groups` are retained because the synchronizable vault master-key write requires them.
- **CI: `cargo fmt --check` + `cargo audit`.** The format gate is now enforced, and a dedicated audit job fails on new vulnerabilities (ignoring only the unfixable `rsa` Marvin-Attack advisory and the two Linux-only `quick-xml` advisories that don't reach the macOS binary — see SECURITY.md). Also bumped `anyhow` to 1.0.103 (clears its unsoundness advisory). Added Dependabot for Cargo + GitHub Actions.
- Docs: `SECURITY.md` now classifies the `cargo audit` advisories into macOS-runtime (accepted / not-exploitable) vs Linux-only/build-only (not in the shipped binary).

## 0.0.14 — 2026-07-01

- **Renamed the public app bundle to "gmacFTP".** The app you install is now `gmacFTP.app` with the display name **gmacFTP** (was "gmacFTP Public") — so the menu bar, Applications folder, GitHub DMG, and Homebrew install all show one consistent name. The local personal build is now `gmacFTP-Personal.app` (local-only; avoids a filename clash). Purely cosmetic — no behavior change.
- **Homebrew install.** gmacFTP is now installable via Homebrew: `brew install --cask gmac-pl/gmacftp/gmacftp` (the project tap, installs the same signed + Apple-notarized app as the DMG). Also submitted to Homebrew's official cask tap so the bare `brew install --cask gmacftp` will work once it's reviewed.

## 0.0.13 — 2026-07-01

A hardening + privacy pass following a full code audit. No customer/personal data was ever leaked; this closes the remaining hygiene and correctness gaps.

- **No developer build paths in the app.** The shipped binary no longer embeds `/Users/...` panic-location and cargo-registry paths (which exposed the developer's home folder). Release builds now use `--remap-path-prefix`. Purely cosmetic — no behavior change.
- **Atomic writes everywhere user data lives.** `connections.json`, the vault, and sync-folder pulls all write via temp + fsync + rename now, so a crash or power loss mid-write can no longer truncate your saved-server list or the vault. (Previously only the vault and sync copies were atomic; the primary connections file used a bare truncate+write.)
- **Big-file transfer counter fixed.** The transfer progress text wrapped to a negative number for files >2 GiB, and the bottom progress bar could hide — both now use the true 64-bit size.
- **Future-dated sort fixed.** Files dated after 2038 sorted as pre-1970 (the same `i32` wrap class as the earlier size-sort bug) — now sorted by their true `i64` mtime.
- **Vault write failures surface.** A failed vault encrypt or atomic-write is now returned to the caller instead of being silently logged, so the UI can warn that a credential wasn't durably saved.
- **Sync-conflict model documented.** iCloud sync is last-writer-wins by file mtime (noted in the README) — if you edit servers on two Macs at once, the newest change wins.
- Cleanups: removed 3 unused dependencies (`async-trait`, `tokio-stream`, `tempfile`), a dead keychain helper, and several clippy lints; corrected the README iCloud-sync description (plain files in iCloud Drive, not the abandoned key-value store) and the test-server TLS banner (strict by default). Added a CI workflow (clippy + tests + release build).

## 0.0.12 — 2026-07-01

- **Clearer connect / disconnect icons in the sidebar (Apple HIG).** The per-server row buttons now use unambiguous, familiar symbols instead of generic arrows: **Connect** is a blue plug with a filled background, and **Disconnect** is an eject mark that turns red only when you hover it. Different actions now read as different symbols at a glance, per Apple's Human Interface Guidelines. This is a pure visual change — every callback and the drag-and-drop behaviour are unchanged.

## 0.0.11 — 2026-07-01

- **One Keychain authorization migrates ALL passwords (was one-per-server).** 0.10's migration iterated servers and prompted for each. Now a single Keychain enumeration (one `SecItemCopyMatching`) reads every saved password in ONE authorization — enter your Mac login password ONCE. Also fixed: legacy items saved under any old service prefix (older bundle id / app name) now match (host taken after the last `/`), and the one-shot flag was reset so this re-runs correctly.

## 0.0.10 — 2026-07-01

- **"Send Servers to iCloud" now migrates ALL passwords first, then syncs — one action does the whole job.** The 0.0.9 startup migration could miss some Keychain entries, so connecting a never-before-used server still prompted for the Keychain. Now the menu action folds EVERY saved password into the vault (iterating your servers — guaranteed to find them, same access as connecting) before pushing. You get one Keychain prompt per not-yet-migrated server (click "Always Allow" + your Mac login password — one-time), then everything is in the vault → no more prompts + every server syncs + decrypts on the other Mac.

## 0.0.9 — 2026-07-01

- **All saved passwords now sync + no per-server Keychain prompts.** Passwords were split between the synced vault and legacy per-server Keychain entries (from an older build) — so only servers you'd already connected synced, and each new connection prompted "gmacFTP wants to use confidential data / enter keychain password". On launch (one-time, when sync is on) the app now folds ALL legacy Keychain passwords into the vault in a SINGLE Keychain authorization (one prompt, not one-per-server). After that the vault holds every password → no Keychain prompts + every server syncs + decrypts on the other Mac.

## 0.0.8 — 2026-07-01

- **Fix: the wrapped master key (`gmacftp.key.wrap`) now actually gets created + survives a sync off→on toggle.** 0.0.6/0.0.7 could leave the sync folder with connections + vault but NO wrapped key (a purge on sync-off deleted it, and re-enabling only re-pushed connections/vault) → the other Mac had nothing to unlock. Now: turning sync on re-pushes the wrapped key, and launch auto-heals a missing wrapped key from the cached passphrase (or re-prompts to set one if the passphrase was lost).

## 0.0.7 — 2026-07-01

- **Fix: 2nd Mac now JOINS an existing sync instead of creating its own.** 0.0.6 asked every Mac to SET a new passphrase, so the 2nd Mac started fresh (its own keys/servers) instead of unlocking the main Mac's vault. Now: if a wrapped key already exists in the sync folder (another Mac set up sync), the Mac ENTERS that passphrase to join; only the first Mac SETs one.
- **Fix: unlock adopts the synced vault.** `unlock` reads the SYNCED vault (the main Mac's) and writes it locally, instead of the 2nd Mac's own (undecryptable) local vault. This also stops the per-server Keychain prompts: once the vault is unlocked, every server's password comes from the vault (no Keychain fallback → no prompts).

## 0.0.6 — 2026-07-01

- **Cross-device passwords: passphrase-protected master key (1Password-style).** v0.0.5 synced the connection list + vault, but the master key stayed bundle-local in the Keychain → passwords failed on the other Mac ("missing credential"). The master key is now wrapped with a user-chosen sync passphrase (Argon2id → AES-256-GCM); the wrapped key travels in the sync folder (iCloud Drive), and the passphrase is cached in the Keychain under a FIXED cross-bundle service (iCloud Keychain sync). Result: the synced vault decrypts on any of your Macs — automatically when the passphrase is in iCloud Keychain, or with a one-time manual entry otherwise. The first time you enable sync you set a passphrase; remember/save it (it's the recovery path if iCloud Keychain isn't available). No passwords are recoverable from the synced files without it.

## 0.0.5 — 2026-06-30

- **iCloud sync switched to a plain synced folder — now works for direct (Developer ID) distribution.** 0.0.4 used `NSUbiquitousKeyValueStore`, which Apple restricts to App Store / Mac App Store distribution; for a Developer-ID build it silently never synced (writes stayed local-only, nothing reached the 2nd Mac). gmacFTP now mirrors `connections.json` + the encrypted vault as **ordinary files** in a folder the OS already syncs — by default your iCloud Drive (`~/Library/Mobile Documents/com~apple~CloudDocs/gmacFTP/`), or any synced folder you choose (Dropbox, Google Drive, Syncthing…). No iCloud/CloudKit API, no App-Store-only entitlement. iCloud Drive is just a folder; a non-sandboxed app writes to it with normal file I/O and macOS syncs it. The vault master key stays in the Keychain (iCloud Keychain sync) so the synced vault decrypts on the other Mac.
- The synced files are visible in **Finder → iCloud Drive → gmacFTP** (and on your other Macs), so you can verify the sync physically. Last-writer-wins by file modification time.

## 0.0.4 — 2026-06-30

- **iCloud sync rebuilt on the right mechanism.** v0.0.3 mirrored the connection list and the encrypted vault as _synchronizable Keychain_ items, which Apple's iCloud Keychain propagates unreliably between Macs (so the 2nd Mac often saw "Nothing in iCloud yet"). gmacFTP now syncs server data via **NSUbiquitousKeyValueStore** — Apple's standard "UserDefaults, but synced across your Macs" store for small app data — which is reliable and exactly what iCloud sync is designed for. Only the vault master key (a genuine secret) stays in the Keychain, synced via iCloud Keychain, so the synced vault decrypts on the other Mac. Encrypt locally, sync the ciphertext, keep the key in the Keychain.
- **No data loss on upgrade.** Local `connections.json` + `vault.bin` are always the source of truth; the first launch with sync on seeds iCloud from them if it's empty. Existing servers are preserved.

## 0.0.3 — 2026-06-30

- **Critical iCloud-sync fix**: synchronizable Keychain items (the master key + the synced connections/vault) were written with `kSecAttrSynchronizable=true` but READ without the matching query attribute, so macOS returned only non-synchronizable items. With iCloud sync ON this meant the master key could not be found (a fresh key was generated each launch → vault undecryptable → every connection re-prompted the Keychain) and the 2nd Mac's pull found nothing. Reads/deletes now use `kSecAttrSynchronizableAny` (match both stores).

## 0.0.2 — 2026-06-30

- **In-app update check** (App menu → Check for Updates…): queries GitHub for a newer release, downloads the notarized DMG, opens it for install.
- **Finder drag-and-drop**: dropping multiple files now uploads all of them (not just the first); the drop target is auto-detected from the cursor (no need to click the pane first).
- **Overwrite safety (Finder → server)**: asks before overwriting an existing file; handles several conflicts one at a time, each named in the dialog.
- **Local timezone**: "Date modified" now shows local time instead of UTC.
- **About panel**: fixed mojibake (ASCII-only credits); cleaner layout.
- **iCloud sync toggle** in the menu now shows its current ON/OFF state.
- Polish README mirrors English; softer, natural wording.

## 0.0.1 — 2026-06-30

- Renamed the application to gmacFTP.
- Added a native macOS menu bar (App / File / Edit / View / Window / Help) with a real About panel.
- Added optional iCloud Keychain sync of saved servers across Macs, toggled from the app menu.
- Hardened the menu so the app runs as a proper foreground app (the app-name menu and iCloud item now appear reliably).
- Prepared public GitHub documentation and open-source project files.
- Added sanitized documentation screenshots (light + dark + connection manager + editor + transfers).
- Removed private/internal design audit documents and dev-only scaffolding from the public tree.
