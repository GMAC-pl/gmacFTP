#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────────
# Safe GUI testing for gmacFTP — start TWO local FTPS servers (A:2210, B:2211).
#
# Lets you exercise EVERY FTP flow with the REAL app against localhost — zero risk
# to your real hosting servers. In particular this is how to verify FTP→FTP copy:
#   • connect the LEFT  pane to "Local FTPS A" (127.0.0.1:2210)
#   • connect the RIGHT pane to "Local FTPS B" (127.0.0.1:2211)
#   • select a file on one side, hit Download/Upload (or drag) — it relays A→B or B→A.
#
# Also: most of the GUI is testable with NO server at all — both panes start as your
# local filesystem, so DnD, context menu, local↔local copy, the Connections manager
# (add / edit / delete), and pane resizing all work offline. See tests/README.md.
#
# Usage:   bash tests/run-test-servers.sh        (Ctrl-C to stop both servers)
# ──────────────────────────────────────────────────────────────────────────────
set -euo pipefail
cd "$(dirname "$0")/.."

CERT=/tmp/mackftp_ftps.pem
if [ ! -f "$CERT" ]; then
  echo "Generating self-signed TLS cert…"
  openssl req -x509 -newkey rsa:2048 -keyout "$CERT" -out "$CERT" -days 3650 -nodes \
    -subj "/CN=localhost" >/dev/null 2>&1 || { echo "openssl failed — install openssl"; exit 1; }
fi

ROOT_A=/tmp/mackftp_ftpd_a
ROOT_B=/tmp/mackftp_ftpd_b
mkdir -p "$ROOT_A/sub/deep" "$ROOT_B/inbox"

# Seed sample data so there's something to browse / copy.
echo "hello from server A"               > "$ROOT_A/hello.txt"
printf 'A line %s\n' {1..200}            > "$ROOT_A/log-200.txt"
head -c 50000 /dev/urandom               > "$ROOT_A/binary-50k.bin"
echo "nested file inside A/sub/deep"     > "$ROOT_A/sub/deep/nested.txt"
echo "ready on server B"                 > "$ROOT_B/welcome.txt"
head -c 4096 /dev/urandom                > "$ROOT_B/seed-4k.bin"

PIDS=()
cleanup() { for p in "${PIDS[@]:-}"; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT INT TERM

MACKFTP_FTP_PORT=2210 MACKFTP_FTP_ROOT="$ROOT_A" python3 tests/srv_ftps.py & PIDS+=($!)
MACKFTP_FTP_PORT=2211 MACKFTP_FTP_ROOT="$ROOT_B" python3 tests/srv_ftps.py & PIDS+=($!)

sleep 0.6
cat <<EOF

──────────────────────────────────────────────────────────────────────
  gmacFTP test servers are UP  (user=testuser  pass=testpass)

   FTPS A   127.0.0.1:2210   root=$ROOT_A   (hello.txt, binary-50k.bin, sub/…)
   FTPS B   127.0.0.1:2211   root=$ROOT_B   (welcome.txt, seed-4k.bin, inbox/)

  In gmacFTP → Connections (toolbar) → ＋ New:
     Name: Local FTPS A   Protocol: ftp   Host: 127.0.0.1   Port: 2210   User: testuser
     Name: Local FTPS B   Protocol: ftp   Host: 127.0.0.1   Port: 2211   User: testuser
  (password "testpass"; the cert is self-signed — gmacFTP verifies TLS STRICTLY by
   default, so toggle the shield off in the toolbar, or run gmacFTP with
   MACKFTP_TLS_INSECURE=1, to connect to these local test servers)

  Then test FTP→FTP: connect A into the left pane, B into the right pane,
  select a file and press Download / Upload (or drag across).
──────────────────────────────────────────────────────────────────────
  Ctrl-C here to stop both servers.
──────────────────────────────────────────────────────────────────────
EOF
wait
