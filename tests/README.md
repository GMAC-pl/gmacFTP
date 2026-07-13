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

`gmacftp-render-check/` renders the real `ui/app.slint` to PNGs headlessly (Slint software
renderer), so UI changes can be verified without launching the window:

```
cd gmacftp-render-check && cargo build && ./target/debug/gmacftp-render-check
# → /tmp/mackftp_render_{en,pl,manager,editor,ctx,panel,drag,dark}.png
```

Open those PNGs to confirm overlays (manager, editor, context menu, transfer panel) and
both themes render correctly after a change.

---

## 4. Automated relay regression

```
# (with one test server already on 127.0.0.1:2210, e.g. from run-test-servers.sh)
cargo test --test relay
```

This seeds a source file, downloads it to a temp file, re-uploads it to a destination path
via the same `ftp::upload` the production relay uses, then verifies the destination content
matches. It is the guard that the FTP→FTP relay’s upload step stays identical to the
working disk→FTP path.
