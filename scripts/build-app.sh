#!/usr/bin/env bash
# Assemble two macOS bundles:
#   - target/release/gmacFTP.app          public Apple Silicon build (arm64)
#   - target/release/gmacFTP-Personal.app personal/local native build (uses .env.personal)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
ENTITLEMENTS="${MACKFTP_ENTITLEMENTS:-$ROOT/gmacFTP.entitlements}"
EXPECTED_TEAM_ID="${MACKFTP_EXPECTED_TEAM_ID:-SY4HQ4PWVU}"
PRIVATE_SYMBOLS_DIR="${MACKFTP_SYMBOLS_DIR:-$ROOT/target/release/private-symbols}"
# Strip the developer's absolute home + project paths from the shipped binary (panic locations +
# debug symbols) so the .app never leaks /Users/<name>/... . --remap-path-prefix only rewrites
# paths embedded by file!()/env!()/panic locations — purely cosmetic, zero behavior change.
# Preserves a caller-supplied RUSTFLAGS.
CARGO_HOME="${CARGO_HOME:-$HOME/.cargo}"
export RUSTFLAGS="${RUSTFLAGS:+$RUSTFLAGS }--remap-path-prefix $ROOT=gmacftp --remap-path-prefix $CARGO_HOME/registry/src=/cargo/registry/src"
# Single source of truth for the version: Cargo.toml (override via MACKFTP_VERSION).
# CFBundleVersion must be a monotonically-increasing integer (git commit count).
PKG_VER="${MACKFTP_VERSION:-$(grep '^version' "$ROOT/Cargo.toml" | head -1 | sed 's/.*"\([^"]*\)".*/\1/')}"
PKG_BUILD="${MACKFTP_BUILD_NUMBER:-$(git -C "$ROOT" rev-list --count HEAD 2>/dev/null || echo 1)}"
NATIVE_TARGET="$(rustc -vV | sed -n 's/^host: //p')"
# Public releases intentionally target Apple Silicon only. The override remains available for
# local compatibility experiments, but CI and the documented release path build arm64.
PUBLIC_ARCHS="${MACKFTP_PUBLIC_ARCHS:-aarch64-apple-darwin}"
PERSONAL_ARCHS="${MACKFTP_PERSONAL_ARCHS:-$NATIVE_TARGET}"

ensure_rust_target() {
  local target="$1"
  local target_libdir
  target_libdir="$(rustc --print target-libdir --target "$target" 2>/dev/null || true)"
  if [ -n "$target_libdir" ] && [ -d "$target_libdir" ]; then
    return
  fi
  if ! command -v rustup >/dev/null 2>&1; then
    echo "ERROR: Rust standard library for $target is missing; install it with rustup." >&2
    exit 1
  fi
  echo "==> installing Rust target: $target"
  rustup target add "$target"
}

target_arch_name() {
  case "$1" in
    aarch64-apple-darwin) printf '%s\n' arm64 ;;
    x86_64-apple-darwin) printf '%s\n' x86_64 ;;
    *) echo "ERROR: unsupported macOS release target: $1" >&2; exit 64 ;;
  esac
}

create_private_dsym() {
  local label="$1"
  local binary="$2"
  shift 2
  local dsym="$PRIVATE_SYMBOLS_DIR/gmacFTP-${PKG_VER}-${PKG_BUILD}-${label}.dSYM"
  local binary_uuids
  local dsym_uuids
  local source_dsym
  local resolved_dsym
  local source_dwarf
  local source_dwarf_count
  local -a source_dsyms
  local -a resolved_dsyms
  local -a source_dwarfs
  source_dsyms=("$@")
  resolved_dsyms=()
  source_dwarfs=()

  command -v dsymutil >/dev/null 2>&1 || {
    echo "ERROR: dsymutil is required to preserve private release symbols." >&2
    exit 1
  }
  command -v dwarfdump >/dev/null 2>&1 || {
    echo "ERROR: dwarfdump is required to verify private release symbols." >&2
    exit 1
  }

  mkdir -p "$PRIVATE_SYMBOLS_DIR"
  chmod 700 "$PRIVATE_SYMBOLS_DIR"
  rm -rf "$dsym"
  echo "==> preserving private crash symbols: $dsym"
  if [ "${#source_dsyms[@]}" -eq 0 ]; then
    echo "ERROR: Cargo did not provide a packed dSYM for $label" >&2
    exit 1
  fi
  for source_dsym in "${source_dsyms[@]}"; do
    resolved_dsym="$(cd "$source_dsym" 2>/dev/null && pwd -P)" || {
      echo "ERROR: packed release symbol bundle is missing: $source_dsym" >&2
      exit 1
    }
    source_dwarf_count="$(find "$resolved_dsym/Contents/Resources/DWARF" -maxdepth 1 -type f -print | wc -l | tr -d ' ')"
    if [ "$source_dwarf_count" -ne 1 ]; then
      echo "ERROR: expected exactly one DWARF image in $source_dsym; found $source_dwarf_count" >&2
      exit 1
    fi
    source_dwarf="$(find "$resolved_dsym/Contents/Resources/DWARF" -maxdepth 1 -type f -print | head -1)"
    test -n "$source_dwarf" && test -s "$source_dwarf" || {
      echo "ERROR: packed release symbols are missing from $source_dsym" >&2
      exit 1
    }
    resolved_dsyms+=("$resolved_dsym")
    source_dwarfs+=("$source_dwarf")
  done
  cp -R "${resolved_dsyms[0]}" "$dsym"
  local private_dwarf="$dsym/Contents/Resources/DWARF/$(basename "${source_dwarfs[0]}")"
  if [ "${#source_dwarfs[@]}" -gt 1 ]; then
    lipo -create "${source_dwarfs[@]}" -output "$private_dwarf"
    local index
    for ((index = 1; index < ${#resolved_dsyms[@]}; index++)); do
      if [ -d "${resolved_dsyms[$index]}/Contents/Resources/Relocations" ]; then
        cp -R "${resolved_dsyms[$index]}/Contents/Resources/Relocations/." \
          "$dsym/Contents/Resources/Relocations/"
      fi
    done
  fi
  test -s "$private_dwarf" || {
    echo "ERROR: packed symbols could not be assembled for $label" >&2
    exit 1
  }
  chmod -R go-rwx "$dsym"

  # The public executable keeps no local/debug symbols. UUIDs are stable across stripping, so the
  # private dSYM remains an exact symbolication match without being copied into the app or DMG.
  strip -S -x "$binary"
  binary_uuids="$(dwarfdump --uuid "$binary" | awk '{print $2, $3}' | LC_ALL=C sort)"
  dsym_uuids="$(dwarfdump --uuid "$dsym" | awk '{print $2, $3}' | LC_ALL=C sort)"
  if [ -z "$binary_uuids" ] || [ "$binary_uuids" != "$dsym_uuids" ]; then
    echo "ERROR: private dSYM UUIDs do not match the stripped $label executable" >&2
    exit 1
  fi
  echo "==> private dSYM UUIDs verified (not included in the app or DMG)"
}

sign_app() {
  local app="$1"
  local expected_bundle_id="$2"
  local identity
  identity="${MACKFTP_SIGN_IDENTITY:-$(security find-identity -v -p codesigning | sed -nE "s/.*\"(Developer ID Application: .*\(${EXPECTED_TEAM_ID}\))\"/\1/p" | head -1)}"
  if [ -z "$identity" ]; then
    if [ "${MACKFTP_STRICT_SIGN:-0}" = "1" ]; then
      echo "ERROR (MACKFTP_STRICT_SIGN=1): no Developer ID Application identity for Team ID $EXPECTED_TEAM_ID." >&2
      echo "       A distributable bundle MUST be signed with Developer ID — ad-hoc signing is" >&2
      echo "       blocked by Gatekeeper on other users' Macs." >&2
      exit 1
    fi
    identity="$(security find-identity -v -p codesigning | sed -nE "s/.*\"(Apple Development: .*\(${EXPECTED_TEAM_ID}\))\"/\1/p" | head -1)"
  fi
  if [ -z "$identity" ]; then
    echo "==> WARNING: no matching signing identity — ad-hoc signing (LOCAL ONLY;"
    echo "    Gatekeeper blocks it on other Macs). Set MACKFTP_STRICT_SIGN=1 for release builds."
    # No --deep (deprecated, Apple TN-3148); sign the bundle root with Hardened Runtime +
    # entitlements best-effort. Ad-hoc builds cannot be notarized.
    codesign -s - --force --options runtime --timestamp --entitlements "$ENTITLEMENTS" "$app" 2>/dev/null || echo "(codesign skipped)"
  else
    if [ "${MACKFTP_STRICT_SIGN:-0}" = "1" ] && [[ "$identity" != Developer\ ID\ Application:*"($EXPECTED_TEAM_ID)" ]]; then
      echo "ERROR: strict release signing requires Developer ID Application for Team ID $EXPECTED_TEAM_ID." >&2
      exit 1
    fi
    echo "==> codesign with: $identity (Hardened Runtime + entitlements)"
    codesign --force --options runtime --timestamp --entitlements "$ENTITLEMENTS" -s "$identity" "$app"
    # Hard gate: a Developer-ID build must verify cleanly before it ships.
    if ! codesign --verify --strict --verbose=2 "$app" >/dev/null 2>&1; then
      echo "ERROR: codesign --verify --strict failed for $app" >&2
      exit 1
    fi
    local signature
    signature="$(codesign -d --verbose=4 "$app" 2>&1)"
    if ! grep -Fxq "TeamIdentifier=$EXPECTED_TEAM_ID" <<<"$signature"; then
      echo "ERROR: signed app TeamIdentifier does not match $EXPECTED_TEAM_ID." >&2
      exit 1
    fi
    if ! grep -Fxq "Identifier=$expected_bundle_id" <<<"$signature"; then
      echo "ERROR: signed app identifier does not match $expected_bundle_id." >&2
      exit 1
    fi
    echo "==> Developer ID signature identity + bundle identifier verified"
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
  local targets="$8"
  local target
  local target_arch
  local binary_archs
  local expected_arch_count=0
  local -a target_list
  local -a binaries
  local -a packed_dsyms
  target_list=()
  binaries=()
  packed_dsyms=()
  read -r -a target_list <<<"$targets"

  if [ "${#target_list[@]}" -eq 0 ]; then
    echo "ERROR: at least one macOS build target is required for $label" >&2
    exit 64
  fi

  for target in "${target_list[@]}"; do
    target_arch_name "$target" >/dev/null
    ensure_rust_target "$target"
    echo "==> cargo build --release --target $target ($label)"
    MACKFTP_BUNDLE_ID="$bundle_id" \
    MACKFTP_CONFIG_QUALIFIER="$qualifier" \
    MACKFTP_CONFIG_ORGANIZATION="$organization" \
    MACKFTP_CONFIG_APPLICATION="$application" \
    CARGO_PROFILE_RELEASE_DEBUG=1 \
    CARGO_PROFILE_RELEASE_SPLIT_DEBUGINFO=packed \
    CARGO_PROFILE_RELEASE_STRIP=none \
      cargo build --release --locked --target "$target"
    binaries+=("$ROOT/target/$target/release/gmacftp")
    packed_dsyms+=("$ROOT/target/$target/release/gmacftp.dSYM")
  done

  rm -rf "$app"
  mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"
  if [ "${#binaries[@]}" -eq 1 ]; then
    cp "${binaries[0]}" "$app/Contents/MacOS/gmacftp"
  else
    lipo -create "${binaries[@]}" -output "$app/Contents/MacOS/gmacftp"
  fi

  binary_archs="$(lipo -archs "$app/Contents/MacOS/gmacftp")"
  for target in "${target_list[@]}"; do
    target_arch="$(target_arch_name "$target")"
    if ! grep -qw "$target_arch" <<<"$binary_archs"; then
      echo "ERROR: $app is missing the expected $target_arch architecture" >&2
      exit 1
    fi
    expected_arch_count=$((expected_arch_count + 1))
  done
  if [ "$(wc -w <<<"$binary_archs" | tr -d ' ')" -ne "$expected_arch_count" ]; then
    echo "ERROR: $app contains unexpected architectures: $binary_archs" >&2
    exit 1
  fi
  echo "==> verified executable architectures: $binary_archs"

  create_private_dsym "$label" "$app/Contents/MacOS/gmacftp" "${packed_dsyms[@]}"

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
    local profile_plist profile_app_id
    profile_plist="$(mktemp)"
    if security cms -D -i "$profile" >"$profile_plist" 2>/dev/null; then
      profile_app_id="$(/usr/libexec/PlistBuddy -c 'Print :Entitlements:com.apple.application-identifier' "$profile_plist" 2>/dev/null || true)"
    else
      profile_app_id=""
    fi
    rm -f "$profile_plist"
    if [ "$profile_app_id" = "$EXPECTED_TEAM_ID.$bundle_id" ]; then
      cp "$profile" "$app/Contents/embedded.provisionprofile"
      echo "==> embedded provisioning profile verified for $bundle_id"
    elif [ "${MACKFTP_STRICT_SIGN:-0}" = "1" ]; then
      echo "ERROR: provisioning profile is not valid for $EXPECTED_TEAM_ID.$bundle_id" >&2
      exit 1
    else
      echo "==> WARNING: provisioning profile does not match $bundle_id — not embedding it" >&2
    fi
  else
    echo "==> WARNING: provisioning profile not found ($profile) — iCloud entitlements won't work" >&2
    if [ "${MACKFTP_STRICT_SIGN:-0}" = "1" ]; then
      exit 1
    fi
  fi

  if find "$app" -name '*.dSYM' -print -quit | grep -q .; then
    echo "ERROR: a private dSYM was accidentally placed inside $app" >&2
    exit 1
  fi

  sign_app "$app" "$bundle_id"
  echo "==> Built $app"
}

# Public defaults: the bundle that ships (DMG + Homebrew cask). Display name is "gmacFTP"
# (no "Public" suffix) so the menu bar, Applications, DMG, and cask all show one name.
PUBLIC_DISPLAY_NAME="${MACKFTP_PUBLIC_DISPLAY_NAME:-gmacFTP}"
PUBLIC_BUNDLE_ID="${MACKFTP_PUBLIC_BUNDLE_ID:-app.mackftp.client}"
PUBLIC_CONFIG_QUALIFIER="${MACKFTP_PUBLIC_CONFIG_QUALIFIER:-app}"
PUBLIC_CONFIG_ORGANIZATION="${MACKFTP_PUBLIC_CONFIG_ORGANIZATION:-mackftp}"
PUBLIC_CONFIG_APPLICATION="${MACKFTP_PUBLIC_CONFIG_APPLICATION:-client}"

build_bundle \
  "public" \
  "target/release/gmacFTP.app" \
  "$PUBLIC_DISPLAY_NAME" \
  "$PUBLIC_BUNDLE_ID" \
  "$PUBLIC_CONFIG_QUALIFIER" \
  "$PUBLIC_CONFIG_ORGANIZATION" \
  "$PUBLIC_CONFIG_APPLICATION" \
  "$PUBLIC_ARCHS"

if [ "${MACKFTP_PUBLIC_ONLY:-0}" != "1" ] && [ -f .env.personal ]; then
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
    "target/release/gmacFTP-Personal.app" \
    "$PERSONAL_DISPLAY_NAME" \
    "$PERSONAL_BUNDLE_ID" \
    "$PERSONAL_CONFIG_QUALIFIER" \
    "$PERSONAL_CONFIG_ORGANIZATION" \
    "$PERSONAL_CONFIG_APPLICATION" \
    "$PERSONAL_ARCHS"
else
  echo "==> personal bundle skipped"
  echo "    Public bundle is ready at: target/release/gmacFTP.app"
fi

echo
if [ -d target/release/gmacFTP-Personal.app ]; then
  echo "Launch personal: open target/release/gmacFTP-Personal.app"
fi
echo "Launch public:   open target/release/gmacFTP.app"
