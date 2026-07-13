# Architecture

gmacFTP is split into a thin native UI shell and a Rust core that owns protocols, persistence, and transfers.

## UI layer

`ui/app.slint` composes the macOS-style toolbar, sidebar, dual panes, transfer panel, connection
manager, and dialogs. Shared tokens, translations, and model structs live in
`ui/foundation.slint`; focused controls live under `ui/controls/` (`actions`, `fields`, and
`visuals`). Rust keeps the data models fresh and wires Slint callbacks to app behavior.

Important UI principles:

- Left and right panes are independent.
- Icons are vector paths or known text glyphs; no emoji are used.
- Light and dark colors come from the shared token system.
- Public properties and callbacks on `App` are part of the Rust/UI contract.

## App controllers

`src/app.rs` owns application construction, shared state, cross-controller workflows, and the Slint
event loop. Focused callback and projection code is separated under `src/app/`:

- `pane_controller.rs` — pane selection, filtering, sorting, and model projection
- `connection_controller.rs` — connection manager/editor, import, and connection filtering
- `transfer_controller.rs` — queue controls, transfer rows, progress, and reports
- `sync_controller.rs` — sync profiles, scanning, preview, mirror safeguards, and reports
- `settings_controller.rs` — validated settings forms, storage tools, and encrypted backups
- `update_controller.rs` — manual/opt-in release discovery, bounded plain-text notes, explicit
  download consent, and UI state for the verified public updater
- `drag_drop_controller.rs` — bounded native and in-app drag/drop staging
- `command_controller.rs` — keyboard, clipboard, path, and command actions
- `state.rs` — validated enums at the Slint string/integer boundary

The controller keeps blocking protocol work off the UI thread. Results are sent back through Slint's event loop so UI state changes remain on the correct thread.

## Network Layer

`src/net/` contains protocol implementations:

- FTP / FTPS through `suppaftp`
- SFTP through `russh` and `russh-sftp`
- Shared error types and remote listing structures

SFTP host-key verification fails closed on a new or changed key. For a new server, the UI shows
the SHA-256 fingerprint before authentication; only an explicit user approval persists the pin in
the app config directory. A changed pin cannot be replaced automatically.

SFTP supports password, private-key, and SSH Agent authentication. Private keys are read with
`O_NOFOLLOW`, a 1 MiB cap, and private Unix permissions. Built-in RSA private-key signing is
disabled while the transitive RSA implementation has an unresolved timing advisory; RSA keys can
be delegated to the system SSH Agent.

## Storage

Connection metadata is stored without passwords. Secrets go through the credential store abstraction and are backed by macOS Keychain plus an encrypted local vault.

The app uses platform config directories via `directories::ProjectDirs` with the legacy public application identifier `app.mackftp.client`. It intentionally remains unchanged after the gmacFTP rebrand so existing saved servers and credentials continue to load.

## Transfers

The transfer engine dispatches jobs to one ordered worker per endpoint. Workers reuse authenticated
FTP/SFTP sessions, while a dynamic global limiter permits independent endpoints to run in parallel.
Downloads use private resumable fragments and jobs retain enough immutable state for individual
cancel/resume/retry. Progress is throttled before it reaches the UI.

## Folder synchronization

`src/folder_sync.rs` is a pure dry-run planner. The app scans a local and remote tree concurrently,
applies bounded wildcard exclusions, and shows one-way copy actions. Before applying, both sides are
scanned again and the exact plan must match. Target-only files are reported but never deleted.
