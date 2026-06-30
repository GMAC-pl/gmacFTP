#!/usr/bin/env bash
# Assemble two macOS bundles:
#   - target/release/gmacFTP.app        personal/local build (uses .env.personal when present)
#   - target/release/gmacFTP-Public.app public/open-source build (sample/empty app identity)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
ENTITLEMENTS="${MACKFTP_ENTITLEMENTS:-$ROOT/gmacFTP.entitlements}"
# Single source of truth for the version: Cargo.toml (override via MACKFTP_VERSION).
# CFBundleVersion must be a monotonically-increasing integer (git commit count).
PKG_VER="${MACKFTP_VERSION:-$(grep '^version' "$ROOT/Cargo.toml" | head -1 | sed 's/.*"\([^"]*\)".*/\1/')}"
PKG_BUILD="${MACKFTP_BUILD_NUMBER:-$(git -C "$ROOT" rev-list --count HEAD 2>/dev/null || echo 1)}"

sign_app() {
  local app="$1"
  local identity
  identity="$(security find-identity -v -p codesigning | grep -m1 -oE 'Developer ID Application: [^"]+' || true)"
  if [ -z "$identity" ]; then
    identity="$(security find-identity -v -p codesigning | grep -m1 -oE 'Apple Development: [^"]+' || true)"
  fi
  if [ -z "$identity" ]; then
    if [ "${MACKFTP_STRICT_SIGN:-0}" = "1" ]; then
      echo "ERROR (MACKFTP_STRICT_SIGN=1): no Developer ID Application identity found." >&2
      echo "       A distributable bundle MUST be signed with Developer ID — ad-hoc signing is" >&2
      echo "       blocked by Gatekeeper on other users' Macs." >&2
      exit 1
    fi
    echo "==> WARNING: no Developer ID/Apple Development identity — ad-hoc signing (LOCAL ONLY;"
    echo "    Gatekeeper blocks it on other Macs). Set MACKFTP_STRICT_SIGN=1 to fail instead."
    # No --deep (deprecated, Apple TN-3148); sign the bundle root with Hardened Runtime +
    # entitlements best-effort. Ad-hoc builds cannot be notarized.
    codesign -s - --force --options runtime --timestamp --entitlements "$ENTITLEMENTS" "$app" 2>/dev/null || echo "(codesign skipped)"
  else
    echo "==> codesign with: $identity (Hardened Runtime + entitlements)"
    codesign --force --options runtime --timestamp --entitlements "$ENTITLEMENTS" -s "$identity" "$app"
    # Hard gate: a Developer-ID build must verify cleanly before it ships.
    if ! codesign --verify --strict --verbose=2 "$app" >/dev/null 2>&1; then
      echo "ERROR: codesign --verify --strict failed for $app" >&2
      exit 1
    fi
    echo "==> signature verified. Notarize before distribution:"
    echo "    hdiutil create -volname gmacFTP -srcfolder \"$app\" -ov -format UDZO gmacFTP.dmg"
    echo "    xcrun notarytool submit gmacFTP.dmg --keychain-profile gmacftp --wait"
    echo "    xcrun stapler staple gmacFTP.dmg && xcrun stapler staple \"$app\""
  fi
}

build_bundle() {
  local label="$1"
  local app="$2"
  local display_name="$3"
  local bundle_id="$4"
  local qualifier="$5"
  local organization="$6"
  local application="$7"

  echo "==> cargo build --release ($label)"
  MACKFTP_BUNDLE_ID="$bundle_id" \
  MACKFTP_CONFIG_QUALIFIER="$qualifier" \
  MACKFTP_CONFIG_ORGANIZATION="$organization" \
  MACKFTP_CONFIG_APPLICATION="$application" \
    cargo build --release

  rm -rf "$app"
  mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"
  cp target/release/gmacftp "$app/Contents/MacOS/gmacftp"

  cat > "$app/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleName</key><string>$display_name</string>
  <key>CFBundleDisplayName</key><string>$display_name</string>
  <key>CFBundleIdentifier</key><string>$bundle_id</string>
  <key>CFBundleVersion</key><string>$PKG_BUILD</string>
  <key>CFBundleShortVersionString</key><string>$PKG_VER</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleSignature</key><string>????</string>
  <key>CFBundleExecutable</key><string>gmacftp</string>
  <key>CFBundleInfoDictionaryVersion</key><string>6.0</string>
  <key>LSMinimumSystemVersion</key><string>11.0</string>
  <key>LSApplicationCategoryType</key><string>public.app-category.utilities</string>
  <key>NSHighResolutionCapable</key><true/>
  <key>LSUIElement</key><false/>
  <key>NSHumanReadableCopyright</key><string>gmacFTP · GPL-3.0 (dual: GPL or commercial) · github.com/GMAC-pl/gmacftp</string>
  <key>NSAppleEventsUsageDescription</key><string>gmacFTP uses Apple Events only if an external editor is invoked.</string>
  <key>ITSAppUsesNonExemptEncryption</key><false/>
</dict>
</plist>
PLIST

  # About-panel credits (shown by the native About box via App -> About gmacFTP).
  # ASCII-only: the About panel can misrender non-ASCII (em-dash etc.) as mojibake.
  cat > "$app/Contents/Resources/Credits.html" <<'CREDITS'
<!DOCTYPE html><html><body style="font-family:-apple-system,sans-serif;font-size:11px;color:#333;line-height:1.55">
<b style="font-size:13px">gmacFTP</b><br/>
Native macOS FTP, FTPS and SFTP client. Built with Rust and Slint.<br/><br/>
<b>Security.</b> Passwords live in the macOS Keychain inside an AES-256-GCM vault; the master key never touches disk.<br/>
<b>Sync.</b> Optionally keep your saved servers across your Macs via iCloud. Passwords travel only as encrypted ciphertext; the master key stays in your Keychain.<br/><br/>
Open source under GPL v3 (or a commercial license — see the repo):<br/>
<a href="https://github.com/GMAC-pl/gmacftp">github.com/GMAC-pl/gmacftp</a>
</body></html>
CREDITS

  if [ -f assets/icon.icns ]; then
    cp assets/icon.icns "$app/Contents/Resources/icon.icns"
    /usr/libexec/PlistBuddy -c "Add :CFBundleIconFile string icon" "$app/Contents/Info.plist" 2>/dev/null || true
  fi

  # Embed the Developer-ID provisioning profile (the iCloud entitlement needs it). This codesign
  # has no --provisioning-profile flag, so place the profile in the bundle before signing —
  # codesign then seals it into the signature.
  local profile="${MACKFTP_PROVISIONING_PROFILE:-$HOME/Library/MobileDevice/Provisioning Profiles/2135c4cd-cc0e-4c40-8e80-2694dc460cf4.provisionprofile}"
  if [ -f "$profile" ]; then
    cp "$profile" "$app/Contents/embedded.provisionprofile"
    echo "==> embedded provisioning profile"
  else
    echo "==> WARNING: provisioning profile not found ($profile) — iCloud entitlements won't work" >&2
  fi

  sign_app "$app"
  echo "==> Built $app"
}

# Public defaults: safe identity for GitHub/demo use.
PUBLIC_DISPLAY_NAME="${MACKFTP_PUBLIC_DISPLAY_NAME:-gmacFTP Public}"
PUBLIC_BUNDLE_ID="${MACKFTP_PUBLIC_BUNDLE_ID:-app.mackftp.client}"
PUBLIC_CONFIG_QUALIFIER="${MACKFTP_PUBLIC_CONFIG_QUALIFIER:-app}"
PUBLIC_CONFIG_ORGANIZATION="${MACKFTP_PUBLIC_CONFIG_ORGANIZATION:-mackftp}"
PUBLIC_CONFIG_APPLICATION="${MACKFTP_PUBLIC_CONFIG_APPLICATION:-client}"

build_bundle \
  "public" \
  "target/release/gmacFTP-Public.app" \
  "$PUBLIC_DISPLAY_NAME" \
  "$PUBLIC_BUNDLE_ID" \
  "$PUBLIC_CONFIG_QUALIFIER" \
  "$PUBLIC_CONFIG_ORGANIZATION" \
  "$PUBLIC_CONFIG_APPLICATION"

if [ -f .env.personal ]; then
  set -a
  # shellcheck disable=SC1091
  . ./.env.personal
  set +a
  PERSONAL_DISPLAY_NAME="${MACKFTP_PERSONAL_DISPLAY_NAME:-gmacFTP}"
  PERSONAL_BUNDLE_ID="${MACKFTP_PERSONAL_BUNDLE_ID:?MACKFTP_PERSONAL_BUNDLE_ID missing in .env.personal}"
  PERSONAL_CONFIG_QUALIFIER="${MACKFTP_PERSONAL_CONFIG_QUALIFIER:?MACKFTP_PERSONAL_CONFIG_QUALIFIER missing in .env.personal}"
  PERSONAL_CONFIG_ORGANIZATION="${MACKFTP_PERSONAL_CONFIG_ORGANIZATION:?MACKFTP_PERSONAL_CONFIG_ORGANIZATION missing in .env.personal}"
  PERSONAL_CONFIG_APPLICATION="${MACKFTP_PERSONAL_CONFIG_APPLICATION:?MACKFTP_PERSONAL_CONFIG_APPLICATION missing in .env.personal}"

  build_bundle \
    "personal" \
    "target/release/gmacFTP.app" \
    "$PERSONAL_DISPLAY_NAME" \
    "$PERSONAL_BUNDLE_ID" \
    "$PERSONAL_CONFIG_QUALIFIER" \
    "$PERSONAL_CONFIG_ORGANIZATION" \
    "$PERSONAL_CONFIG_APPLICATION"
else
  echo "==> .env.personal not found — skipped personal bundle"
  echo "    Public bundle is ready at: target/release/gmacFTP-Public.app"
fi

echo
echo "Launch personal: open target/release/gmacFTP.app"
echo "Launch public:   open target/release/gmacFTP-Public.app"
