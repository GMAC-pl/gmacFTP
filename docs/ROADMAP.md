# gmacFTP improvement roadmap

This is the implementation checklist for the post-0.1.1 hardening and product work. Items are
checked only after the implementation, automated tests, and relevant manual verification are done.
Security and data-integrity work comes before convenience features.

## Definition of done

- [x] `cargo fmt --check`, `cargo check --all-targets`, `cargo clippy --all-targets -- -D warnings`,
      and `cargo test --all-targets` pass.
- [x] Network and filesystem failure paths have regression tests; no completed transfer is reported
      before the destination is safely finalized.
- [x] No credentials, private server data, local account paths, signing secrets, or unrelated
      contributor attribution are added to tracked files or release artifacts.
- [x] User-facing behavior is documented in English and Polish where the README exposes it.
- [x] The signed/notarized release is built only after all milestones intended for that release pass.

## Milestone A — data integrity and recovery

- [x] Upload FTP/FTPS files through an unpredictable sibling temporary name, then finalize with a
      same-directory rename; clean up on error/cancel and preserve an existing destination until the
      upload succeeds.
- [x] Upload SFTP files through an unpredictable sibling temporary name, then finalize with a
      same-directory rename; clean up on error/cancel and preserve an existing destination until the
      upload succeeds.
- [x] Make local file copies transactional: private sibling temporary file, flush/sync, atomic
      replacement, and cleanup on failure.
- [x] Add fault-injection regression tests for interrupted upload/copy, failed finalization, an
      existing destination, cancellation, and cleanup.
- [x] Replace size-only folder-sync comparison with metadata-aware entries.
- [x] Support sync comparison policies: size + modification time (default, clock tolerance), size
      only, and checksum verification where available/explicitly requested.
- [x] Show the selected comparison policy and clock tolerance in dry-run results; revalidate with the
      same policy immediately before enqueueing.
- [x] Persist the transfer queue without credentials using crash-safe, versioned state.
- [x] Recover interrupted downloads and queued work on launch; provide explicit resume/discard UI.
- [x] Add safe upload resume where the protocol/server supports it; otherwise restart through a new
      temporary destination.
- [x] Replace blanket invalid-certificate acceptance with endpoint certificate pinning, trust-once,
      and a changed-certificate warning. Keep legacy exceptions migratable but visibly unsafe.

## Milestone B — performance and large directories

- [x] Replace eager file-row layouts with a virtualized/recycled list while preserving selection,
      Shift/Command multi-selection, drag and drop, keyboard navigation, context menus, and sorting.
- [x] Move recursive remote-folder size calculation to an on-demand mode; provide a preference for
      background enrichment and enforce a global cancellable work budget.
- [x] Add per-server transfer parallelism with conservative defaults and per-connection override.
- [x] Add adaptive SFTP chunk/window tuning bounded by server limits and measured latency.
- [x] Add cancellable/incremental directory listing updates for very large directories.
- [x] Add repeatable benchmarks for 10k/50k rows, many-small-file transfers, high-latency SFTP, cold
      start, peak memory, and recursive metadata work.

## Milestone C — native Settings and connection management

- [x] Add `gmacFTP > Settings…` (`Command-,`) with General, Transfers, Connections, Sync, Editors,
      and Privacy & Storage sections.
- [x] General: System/Light/Dark theme, system/manual language, hidden files, delete confirmations,
      launch behavior, workspace restoration, pane paths, split position, and window geometry.
- [x] Transfers: global/per-server concurrency, bandwidth limits, retry count/backoff, existing-file
      policy, batch-error policy, atomic-transfer policy, metadata preservation, queue recovery, and
      completion/failure notifications.
- [x] Connections: test connection, initial remote path, groups/tags, timeout, keepalive, FTP
      passive/active mode, filename encoding, proxy, SSH config/ProxyJump, and advanced TLS details.
- [x] Sync: saved profiles, comparison method, clock tolerance, exclusion presets, per-row inclusion,
      reports, and safe one-way/mirror modes; deletion remains opt-in with preview and confirmation.
- [x] Editors: editor mapping by extension, maximum automatic-download size, auto-upload-on-save,
      conflict action, and temporary-file retention policy.
- [x] Privacy & Storage: cache/fragment/log sizes, cleanup controls, redacted diagnostics export,
      encrypted settings export/import, and sync-folder selection.
- [x] Migrate existing settings compatibly and validate every persisted value with safe bounds.

## Milestone D — file management and power-user workflow

- [x] Add editable breadcrumb/path bar and `Command-L`, recent paths, and per-server remote Places.
- [x] Add instant current-directory filtering and cancellable bounded recursive remote search.
- [x] Add directory comparison and synchronized browsing.
- [x] Add batch rename, duplicate, same-server move, copy/paste, and a metadata Inspector.
- [x] Add configurable timestamp/permission preservation and owner/group/permission columns.
- [x] Add queue reorder, priority, per-job pause, retry scheduling, apply-to-all conflict actions,
      completion history, and exportable redacted reports.
- [x] Add editor mappings, safe auto-upload after save, and a conflict diff workflow.
- [x] Add optional remote quarantine/trash behavior; permanent deletion remains explicit.
- [x] Add privacy-safe macOS notifications, Dock progress/badge, and Finder-to-pane /
      pane-to-Finder drag integration. Do not register a generic Finder Service or Dock document
      handler: neither can encode an explicit destination connection/path safely.

## Milestone E — compatibility, accessibility, maintainability, and release

- [x] Add keyboard-interactive SFTP/2FA and `~/.ssh/config` identity/host aliases without weakening
      host-key verification.
- [x] Add implicit FTPS, TLS client certificates, and carefully bounded proxy support.
- [x] Complete the localization catalog; remove user-facing hard-coded English and follow the macOS
      system locale by default.
- [x] Add VoiceOver roles, names, values, actions, focus semantics, and keyboard-only UI tests.
- [x] Split `src/app.rs` into pane, connection, transfer, sync, settings, drag/drop, and command
      controllers; split `ui/app.slint` into reusable focused components.
- [x] Replace stringly typed pane/mode/action state with validated enums at Rust boundaries.
- [x] Add a protocol compatibility/fault matrix for OpenSSH, vsftpd, ProFTPD, Pure-FTPd, slow/stalled
      peers, changed host keys/certificates, disk-full, permission errors, and network loss.
- [x] Decide Intel/universal-binary support from documented demand and test the selected target.
- [x] Add opt-in background update checks, release notes, and signature/digest verification without
      introducing telemetry.
- [x] Complete privacy/secret/history scan, dependency/license/security audit, release build, Apple
      signing, notarization, stapling, DMG verification, GitHub release, and Homebrew cask update.
