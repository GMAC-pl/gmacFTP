# Architecture

gmacFTP is split into a thin native UI shell and a Rust core that owns protocols, persistence, and transfers.

## UI Layer

The UI lives in `ui/app.slint`. It defines the macOS-style toolbar, sidebar, dual panes, transfer panel, connection manager, dialogs, and theme tokens. Rust keeps the data models fresh and wires Slint callbacks to app behavior.

Important UI principles:

- Left and right panes are independent.
- Icons are vector paths or known text glyphs; no emoji are used.
- Light and dark colors come from the shared token system.
- Public properties and callbacks on `App` are part of the Rust/UI contract.

## App Controller

`src/app.rs` owns the Slint window, Tokio runtime, transfer engine, connection list, pane state, callbacks, and UI model updates.

The controller keeps blocking protocol work off the UI thread. Results are sent back through Slint's event loop so UI state changes remain on the correct thread.

## Network Layer

`src/net/` contains protocol implementations:

- FTP / FTPS through `suppaftp`
- SFTP through `russh` and `russh-sftp`
- Shared error types and remote listing structures

SFTP host-key verification fails closed on a new or changed key. For a new server, the UI shows
the SHA-256 fingerprint before authentication; only an explicit user approval persists the pin in
the app config directory. A changed pin cannot be replaced automatically.

## Storage

Connection metadata is stored without passwords. Secrets go through the credential store abstraction and are backed by macOS Keychain plus an encrypted local vault.

The app uses platform config directories via `directories::ProjectDirs` with the legacy public application identifier `app.mackftp.client`. It intentionally remains unchanged after the gmacFTP rebrand so existing saved servers and credentials continue to load.

## Transfers

The transfer engine runs asynchronously and reports progress through throttled updates. The UI presents active, queued, completed, and failed jobs without blocking pane navigation.
