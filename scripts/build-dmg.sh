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
EXPECTED_TEAM_ID="${MACKFTP_EXPECTED_TEAM_ID:-SY4HQ4PWVU}"
EXPECTED_BUNDLE_ID="${MACKFTP_PUBLIC_BUNDLE_ID:-app.mackftp.client}"
DMG_IDENTIFIER="${MACKFTP_DMG_IDENTIFIER:-app.mackftp.client.dmg}"

if [[ ! "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "ERROR: version must be a numeric x.y.z value" >&2
  exit 1
fi

[ -d "$APP" ] || { echo "ERROR: app not found: $APP" >&2; exit 1; }
APP_NAME="$(basename "$APP")"

if [ "${MACKFTP_STRICT_RELEASE:-0}" = "1" ]; then
  codesign --verify --strict --verbose=2 "$APP"
  APP_SIGNATURE="$(codesign -d --verbose=4 "$APP" 2>&1)"
  grep -Fxq "TeamIdentifier=$EXPECTED_TEAM_ID" <<<"$APP_SIGNATURE" || {
    echo "ERROR: app TeamIdentifier is not $EXPECTED_TEAM_ID" >&2
    exit 1
  }
  grep -Fxq "Identifier=$EXPECTED_BUNDLE_ID" <<<"$APP_SIGNATURE" || {
    echo "ERROR: app bundle identifier is not $EXPECTED_BUNDLE_ID" >&2
    exit 1
  }
fi

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
# The writable HFS+ mount can create local FSEvents records while Finder arranges the window.
# Never ship those machine-generated event logs: replace them with the documented no-log marker
# before detaching, and prevent Spotlight indexing of the installer volume.
rm -rf "$MNT/.fseventsd"
mkdir -p "$MNT/.fseventsd"
touch "$MNT/.fseventsd/no_log" "$MNT/.metadata_never_index"
# Give the layout a moment to settle, then detach.
sleep 1
hdiutil detach "$MNT" >/dev/null || hdiutil detach "$MNT" -force >/dev/null

echo "==> convert to compressed read-only -> $OUT"
rm -f "$OUT"
hdiutil convert "$RW" -ov -format UDZO -o "$OUT" >/dev/null
rm -f "$RW"

IDENTITY="${MACKFTP_SIGN_IDENTITY:-$(security find-identity -v -p codesigning | sed -nE "s/.*\"(Developer ID Application: .*\(${EXPECTED_TEAM_ID}\))\"/\1/p" | head -1)}"
if [ -z "$IDENTITY" ]; then
  if [ "${MACKFTP_STRICT_RELEASE:-0}" = "1" ]; then
    echo "ERROR: no Developer ID Application identity for Team ID $EXPECTED_TEAM_ID" >&2
    exit 1
  fi
  echo "==> WARNING: DMG is unsigned (local build only)" >&2
else
  echo "==> signing DMG with Developer ID"
  codesign --force --timestamp --sign "$IDENTITY" --identifier "$DMG_IDENTIFIER" "$OUT"
  codesign --verify --strict --verbose=2 "$OUT"
  DMG_SIGNATURE="$(codesign -d --verbose=4 "$OUT" 2>&1)"
  grep -Fxq "TeamIdentifier=$EXPECTED_TEAM_ID" <<<"$DMG_SIGNATURE" || {
    echo "ERROR: DMG TeamIdentifier is not $EXPECTED_TEAM_ID" >&2
    exit 1
  }
  grep -Fxq "Identifier=$DMG_IDENTIFIER" <<<"$DMG_SIGNATURE" || {
    echo "ERROR: DMG signing identifier is not $DMG_IDENTIFIER" >&2
    exit 1
  }
fi

NOTARY_PROFILE="${MACKFTP_NOTARY_PROFILE:-}"
if [ -n "$NOTARY_PROFILE" ]; then
  echo "==> submitting DMG for Apple notarization"
  xcrun notarytool submit "$OUT" --keychain-profile "$NOTARY_PROFILE" --wait
  xcrun stapler staple "$OUT"
  xcrun stapler validate "$OUT"
  spctl --assess --type open --context context:primary-signature --verbose=2 "$OUT"
elif [ "${MACKFTP_STRICT_RELEASE:-0}" = "1" ]; then
  echo "ERROR: MACKFTP_NOTARY_PROFILE is required for a public release" >&2
  exit 1
fi

DMG_SHA256="$(shasum -a 256 "$OUT" | awk '{print $1}')"
printf '%s  %s\n' "$DMG_SHA256" "$(basename "$OUT")" >"$OUT.sha256"
echo "==> Built $OUT ($(du -h "$OUT" | cut -f1))"
