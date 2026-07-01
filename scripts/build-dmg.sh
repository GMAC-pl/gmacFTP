#!/usr/bin/env bash
# Build a macOS installer DMG with the standard "drag gmacFTP to Applications" layout
# (the bare hdiutil -srcfolder DMG shows only the app — no Applications shortcut).
# Stages: app + an Applications symlink, then sets icon positions via Finder, then
# converts to a compressed read-only UDZO image.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

APP="${1:-target/release/gmacFTP.app}"
VERSION="${2:-$(grep '^version' Cargo.toml | head -1 | sed 's/.*"\([^"]*\)".*/\1/')}"
VOL="gmacFTP"
OUT="target/release/gmacFTP-${VERSION}.dmg"
RW="target/release/gmacFTP-rw.dmg"

[ -d "$APP" ] || { echo "ERROR: app not found: $APP" >&2; exit 1; }
APP_NAME="$(basename "$APP")"

echo "==> staging $APP_NAME + Applications symlink"
STAGING="$(mktemp -d)"
trap 'rm -rf "$STAGING"' EXIT
cp -R "$APP" "$STAGING/$APP_NAME"
ln -s /Applications "$STAGING/Applications"

echo "==> read-write DMG"
rm -f "$RW"
hdiutil create -ov -volname "$VOL" -srcfolder "$STAGING" -fs HFS+ -format UDRW "$RW" >/dev/null

echo "==> mount + set icon layout (best-effort)"
MNT=$(hdiutil attach -readwrite -noverify -noautoopen "$RW" | grep -o '/Volumes/[^	]*' | sed 's/[[:space:]]*$//' | head -1)
# Position the app + Applications folder side by side. Best-effort: if Finder/AppleScript
# is unavailable the icons still both appear (just not perfectly placed).
osascript <<OSA 2>/dev/null || echo "   (icon positioning skipped — Finder AppleScript unavailable)"
tell application "Finder"
  set d to disk "$VOL"
  open d
  set view of container window of d to icon view
  set the bounds of container window of d to {100, 100, 560, 340}
  set position of item "$APP_NAME" of d to {120, 160}
  set position of item "Applications" of d to {380, 160}
  set toolbar visible of container window of d to false
  set statusbar visible of container window of d to false
  close container window of d
  open d
end tell
OSA
# Give the layout a moment to settle, then detach.
sleep 1
hdiutil detach "$MNT" >/dev/null || hdiutil detach "$MNT" -force >/dev/null

echo "==> convert to compressed read-only -> $OUT"
rm -f "$OUT"
hdiutil convert "$RW" -ov -format UDZO -o "$OUT" >/dev/null
rm -f "$RW"
echo "==> Built $OUT ($(du -h "$OUT" | cut -f1))"
