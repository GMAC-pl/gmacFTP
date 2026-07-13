#!/usr/bin/env bash
# Rebuild every public README screenshot from the deterministic demo-only Slint fixture.
# This process never opens application settings, saved connections, the Keychain, or the network.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$(mktemp -d "${TMPDIR:-/tmp}/gmacftp-screenshots.XXXXXX")"
trap 'rm -rf "$OUT"' EXIT

MACKFTP_RENDER_SCALE=2 "$ROOT/scripts/check-ui-render.sh" "$OUT"

install -m 0644 "$OUT/gmacftp_render_en.png" "$ROOT/docs/screenshots/main-light.png"
install -m 0644 "$OUT/gmacftp_render_dark.png" "$ROOT/docs/screenshots/main-dark.png"
install -m 0644 "$OUT/gmacftp_render_manager.png" "$ROOT/docs/screenshots/connections.png"
install -m 0644 "$OUT/gmacftp_render_editor.png" "$ROOT/docs/screenshots/connection-editor.png"
install -m 0644 "$OUT/gmacftp_render_panel.png" "$ROOT/docs/screenshots/transfers.png"
install -m 0644 "$OUT/gmacftp_render_update.png" "$ROOT/docs/screenshots/update.png"

echo "Updated six privacy-safe README screenshots in $ROOT/docs/screenshots"
