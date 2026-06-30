# Changelog

## Unreleased

_(Nothing yet.)_

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
