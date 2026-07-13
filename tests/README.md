# Testing gmacFTP safely (without touching real FTP servers)

You can test essentially the **entire GUI without ever connecting to a real host**.
Two complementary modes:

---

## 1. Zero-FTP testing (local ↔ local)

Both panes start as your **local filesystem**. That means you can exercise most of the
UI right now with **no server at all** and zero risk:

| Flow                                          | How                                                        |
| --------------------------------------------- | ---------------------------------------------------------- |
| Browse / open folders                         | double-click folders in either pane                        |
| Selection + active-pane highlight             | click rows; the active pane gets a colored top bar         |
| Drag-and-drop copy                            | drag a file from one pane to the other (local→local copy)  |
| Context menu                                  | right-click a file (Open / Upload-or-Download / Copy Path) |
| Resize panes                                  | drag the thin center column left/right                     |
| **Connections manager** (add / edit / delete) | toolbar **Connections** → ＋ New / Edit / Delete           |
| Transfer panel popover                        | toolbar **Transfers**                                      |
| Theme / TLS / hidden-files / locale           | toolbar toggles                                            |
| Back / Forward / Up / Home                    | pane header buttons                                        |

Just launch the app:

```
cargo run
# or the built app:
open target/release/gmacFTP.app
```

Nothing leaves the machine. If something breaks here, it's a pure UI bug — safe to
experiment freely.

---

## 2. FTP flows against localhost (FTPS pair)

For the things that _do_ need a server — connecting, listing, **disk→FTP**, **FTP→disk**,
and especially **FTP→FTP relay** — run the two local FTPS servers and point the app at
`127.0.0.1` instead of a real host:

```
bash tests/run-test-servers.sh
```

This starts:

- **FTPS A** — `127.0.0.1:2210` (root `/tmp/mackftp_ftpd_a`, seeded with files + a nested folder)
- **FTPS B** — `127.0.0.1:2211` (root `/tmp/mackftp_ftpd_b`, seeded with files)

Both use **user `testuser` / pass `testpass`**. Certificate verification remains strict by
default; approve/pin the disposable localhost certificate explicitly or use the documented test
override only for this fixture.

Then in the app, open **Connections → ＋ New** and add:

- `Local FTPS A` — ftp, host `127.0.0.1`, port `2210`, user `testuser`, pass `testpass`
- `Local FTPS B` — ftp, host `127.0.0.1`, port `2211`, user `testuser`, pass `testpass`

Connect A into the left pane, B into the right pane, then drag a file across the center
or use the row context menu's transfer action. This exercises the exact same
FTP→FTP relay code path used against real hosts — so if it works A→B here, it works
between real servers too.

Ctrl-C in the terminal stops both servers.

> SFTP isn't covered by this pair (pyftpdlib is FTP-only). For SFTP, test against a
> local `sshd` or a single known-good host, carefully.

For the repeatable OpenSSH/vsftpd/ProFTPD/Pure-FTPd matrix, see
[`docs/COMPATIBILITY.md`](../docs/COMPATIBILITY.md) and run
`bash tests/run-compatibility-matrix.sh` with Docker available.

---

## 3. Headless render verification (for layout / styling)

The render check compiles the real `ui/app.slint` with Slint's software renderer and writes
deterministic PNGs without launching the application controller:

```
bash scripts/check-ui-render.sh
# → /tmp/gmacftp-render-check/gmacftp_render_{en,pl,manager,editor,ctx,panel,drag,dark,update}.png
```

Open those PNGs to confirm overlays (manager, editor, context menu, transfer panel) and
both themes render correctly after a change. The fixture uses only `example.com` hosts and
`/Users/demo` paths; it never loads user settings, Keychain credentials, or a network client.
To replace the six Retina screenshots referenced by README with the same isolated fixture, run:

```
bash scripts/capture-demo-screenshots.sh
```

Before shipping an artifact, also complete the
[`macOS release-candidate smoke test`](../docs/RELEASE_SMOKE_TEST.md) on the exact packaged app.

---

## 4. Clean-install and migration fixtures

The password-free documents under `tests/fixtures/migrations/` reproduce settings and connection
metadata written by representative 0.0.x, 0.1.x, and 0.2.x releases. Unit tests deserialize them
through the current validation path and verify strict TLS defaults, bounded resource settings,
endpoint-bound metadata, and legacy field normalization. Every endpoint is below `example.com`,
and every absolute path starts with `/Users/demo`; never replace a fixture with a real export.

---

## 5. Automated relay regression

```
# (with one test server already on 127.0.0.1:2210, e.g. from run-test-servers.sh)
cargo test --test relay
```

This seeds a source file, downloads it to a temp file, re-uploads it to a destination path
via the same `ftp::upload` the production relay uses, then verifies the destination content
matches. It is the guard that the FTP→FTP relay’s upload step stays identical to the
working disk→FTP path.
