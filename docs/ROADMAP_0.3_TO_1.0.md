# gmacFTP active roadmap: 0.2.2 to 1.0

This is the active development checklist after the completed 0.2.0 hardening milestone. Work is
ordered by user-data safety and regression prevention. A feature is checked only after its tests,
documentation, and relevant macOS verification pass.

## Definition of done for every milestone

- [ ] `cargo fmt --check`, Clippy with warnings denied, all tests, the public Apple Silicon target,
      and the dependency audit pass.
- [ ] New UI behavior has pointer, keyboard, accessibility, and layout regression coverage where
      applicable.
- [ ] Test fixtures contain only documented sample hosts, paths, and credentials.
- [ ] Public artifacts contain no private profiles, server data, credentials, local account paths,
      signing material, or unrelated attribution.
- [ ] A signed release is made only after manual verification of the exact notarized artifact.

## 0.2.2 — UI and release stabilization

- [x] Track a deterministic headless renderer for the real Slint component with EN/PL, light/dark,
      manager, editor, context menu, transfer panel, drag, and updater scenarios.
- [x] Add a physical-pointer regression for both updater actions and assert that their hit areas
      are non-zero and reachable above the modal scrim.
- [x] Run the render smoke check in CI without reading the Keychain, saved connections, or network.
- [x] Add a real macOS bundle smoke checklist for toolbar, sidebar, menus, overlays, drag/drop, and
      updater controls.
- [x] Normalize vector icon scale, sidebar hierarchy, protocol badges, toolbar emphasis, and EN/PL
      spacing in light and dark themes.
- [x] Preserve private `.dSYM` output for release crash symbolication without shipping it in DMG.
- [x] Exercise clean install and migrations from representative 0.0.x, 0.1.x, and 0.2.x fixtures.
- [x] Test sleep/wake, network loss/recovery, and safe resume while transfers are active.

## 0.3.0 — protocol compatibility and measurable performance

- [ ] Add real explicit/implicit FTPS interoperability fixtures, certificate rotation, data-channel
      protection, active/passive mode, and optional client-certificate coverage.
- [ ] Cover files larger than 4 GiB, Unicode NFC/NFD names, server clock offsets, symlinks, unusual
      MLSD/LIST output, and low-disk-space recovery.
- [ ] Run the disposable server matrix on a schedule and retain redacted failure artifacts.
- [ ] Record benchmark baselines and enforce conservative regression budgets for startup, 10k/50k
      rows, many-small-file work, high-latency SFTP, and memory use.
- [ ] Split the remaining large application and FTP/SFTP modules along tested state-machine and
      protocol boundaries without changing behavior.

## 0.4.0 — workflow expansion

- [ ] Add tabs or named workspaces while keeping every destination connection/path explicit.
- [ ] Add Quick Connect plus safe `ftp://`, `ftps://`, and `sftp://` URL handling.
- [ ] Add Open in Terminal for local directories and authenticated SFTP sessions.
- [ ] Add conditional transfer/sync rules for path, regex, size, kind, and modification time.
- [ ] Add privacy-safe importers for Cyberduck, Transmit, and WinSCP bookmarks.
- [ ] Design an opt-in CLI and scheduled-sync surface that never exposes credentials in arguments,
      process listings, logs, or reports.
- [ ] Evaluate hardware-backed SSH keys and authenticated proxy support against the fail-closed
      host-key and credential model.

## 1.0 — stable release

- [ ] Complete a public beta period with actionable, redacted issue reporting.
- [ ] Pass the full protocol, migration, accessibility, performance, and release-integrity matrix.
- [ ] Freeze and document configuration/queue formats with tested forward migration.
- [ ] Publish user documentation and short sample-data demonstrations for common workflows.
- [ ] Decide additional protocols such as WebDAV or S3 from demonstrated user demand; do not expand
      protocol scope at the cost of FTP/FTPS/SFTP reliability.
- [ ] Perform the final source/history/privacy/security audit, sign and notarize the arm64 app,
      verify the downloaded GitHub artifact, and update Homebrew.
