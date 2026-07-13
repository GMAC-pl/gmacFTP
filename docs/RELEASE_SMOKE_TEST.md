# macOS release-candidate smoke test

Run this checklist on the exact public `.app` that will be packaged. Use only the repository's
documented demo fixtures or disposable localhost servers until the privacy checks pass. A release
is not approved merely because the automated suite passes.

## 1. Artifact identity and privacy

- [ ] Confirm the bundle identifier, short version, build number, `arm64`-only executable,
      Developer ID team, Hardened Runtime entitlements, notarization, and stapled ticket.
- [ ] Scan the bundle and DMG for credentials, private hostnames/IPs, local usernames and absolute
      project paths, `.env.personal`, provisioning/signing files, and unexpected contributor text.
- [ ] Mount the DMG on a clean macOS account and launch the copied app through Finder/Gatekeeper.
- [ ] Keep the matching `.dSYM` privately; verify that neither it nor signing material is in the
      public DMG or GitHub assets.

## 2. Window and input

- [ ] Physically click Close, Minimize, Full Screen, every toolbar control, pane navigation, both
      column headers, the divider, transfer arrows, sidebar rows, and their compact action icons.
- [ ] Verify that hover/focus rings do not move layout and that disabled controls remain readable.
- [ ] Verify Command/Shift range selection, Command-disjoint selection, Command-A, keyboard arrows,
      Return, Delete, Space, Tab/Shift-Tab, Command-K, Command-L, Command-N, and Command-comma.
- [ ] Check the native app/File/Edit/View/Window/Help menus and their shortcuts after changing
      window focus, entering full screen, and returning from another application.

## 3. Layout, themes, and accessibility

- [ ] Check EN and PL at the default 1180 × 740 size and at the smallest supported window size;
      no toolbar label, protocol badge, path, or dialog action may overlap or clip unexpectedly.
- [ ] Check light, dark, and system theme. Protocol badges, selection, active connection, hover,
      focus, success, warning, and destructive states must remain distinguishable without color
      being the only signal.
- [ ] With VoiceOver, traverse toolbar, sidebar, both panes, divider, menus, and dialogs; names,
      roles, values, enabled state, and default actions must match what is visible.

## 4. Overlays and click blocking

- [ ] Open and close Connections, connection editor, Settings, command palette, context/sort menus,
      transfer queue, sync preview, Inspector, rename/delete/overwrite dialogs, and SSH prompts.
- [ ] For every overlay, click every non-destructive action and verify the scrim cannot intercept
      controls above it. Escape and the visible close/cancel action must restore the main UI.
- [ ] Open an update fixture and physically click **Later**. Reopen it and click **Download &
      Verify**; confirm visible progress, verified identity/digest/ticket, DMG opening, and a useful
      error message for an intentionally damaged fixture.

## 5. File and transfer behavior

- [ ] Drag Finder → each local pane, pane → Finder, local ↔ local, local ↔ disposable FTP/FTPS/SFTP,
      and between two disposable servers. Confirm the visible drop target before release.
- [ ] Copy a mixed multi-selection containing a folder, normal files, and one deliberately
      unreadable/failing item. Verify Skip continues the batch and Stop leaves remaining items
      untouched; the single-item failure still produces a clear notification.
- [ ] Exercise pause/resume/retry/cancel, app restart queue recovery, network loss/recovery,
      sleep/wake, destination conflict choices, insufficient disk space, and safe partial cleanup.

## 6. Updater and downloaded-artifact loop

- [ ] Install the previous public version, discover the candidate through the updater, download and
      verify it, then install it from the opened DMG.
- [ ] Confirm preferences and compatible connection metadata migrate, while passwords remain in the
      intended vault/Keychain and no real server is contacted automatically.
- [ ] Download the GitHub release independently and repeat signature, notarization, digest, launch,
      and version checks on that downloaded artifact rather than only on the local build.
