//! In-app update check — lightweight, no Sparkle framework.
//!
//! "Check for Updates…" (App menu) queries the GitHub Releases API for the latest release,
//! compares the version, and if newer, downloads the notarized DMG to ~/Downloads and opens it
//! in Finder (the user drags gmacFTP to Applications — the standard DMG install). This is
//! "update directly from the app" without embedding/signing a 3rd-party framework. Pure Rust
//! (`ureq`) + the system `open` command to mount the DMG.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

/// The GitHub repo that hosts releases (also where the app pulls its source + updates from).
const REPO: &str = "GMAC-pl/gmacftp";
/// The running build's version (e.g. "0.0.2"), baked in at compile time.
pub const CURRENT: &str = env!("CARGO_PKG_VERSION");
/// The host a GitHub release asset URL must resolve to. The Releases API only ever returns
/// `github.com` `browser_download_url` values (which 302 to `objects.githubusercontent.com`);
/// anything else indicates a hijacked release / compromised account / MITM and is refused.
///
/// Scope note: [`validate_asset_url`] checks the URL the API hands us (the `github.com`
/// `browser_download_url`). `ureq` then follows the 302 to `objects.githubusercontent.com` —
/// the allowlist does NOT constrain the redirect target, only the initial URL. For a legitimate
/// GitHub release that's exactly the expected chain; the check is defense-in-depth against a
/// non-`github.com` URL a compromised release/account could inject, not a full redirect-pin
/// defense (which Gatekeeper + the HTTPS transport already cover).
const GH_ASSET_HOST: &str = "github.com";
/// Cap a downloaded DMG at 300 MiB so a hostile or compromised endpoint can't OOM the app with
/// an unbounded stream. A real gmacFTP DMG is ~10–50 MiB.
const MAX_DMG_BYTES: u64 = 300 * 1024 * 1024;

/// Defense-in-depth on top of the (already HTTPS) API call and macOS Gatekeeper: refuse any
/// release asset URL that isn't `https://` on the expected GitHub host. Catches `file://`,
/// `http://`, and off-host URLs a compromised release/account could otherwise inject.
fn validate_asset_url(url: &str) -> Result<(), String> {
    let after = url
        .strip_prefix("https://")
        .ok_or_else(|| format!("refusing non-HTTPS asset URL: {url}"))?;
    let host = after.split(['/', '?', '#']).next().unwrap_or("");
    if host.eq_ignore_ascii_case(GH_ASSET_HOST) {
        Ok(())
    } else {
        Err(format!(
            "refusing off-host asset URL (expected {GH_ASSET_HOST}): {url}"
        ))
    }
}

/// A newer release found on GitHub (None if the running build is current or newer).
#[derive(Debug, Clone)]
pub struct LatestUpdate {
    /// Version without the leading "v" (e.g. "0.0.3").
    pub version: String,
    /// Direct .dmg download URL.
    pub dmg_url: String,
    /// Human-readable release notes (the release body).
    pub notes: String,
}

/// Query GitHub for the latest release; return it only if it's strictly newer than this build.
pub fn check() -> Result<Option<LatestUpdate>, String> {
    let url = format!("https://api.github.com/repos/{REPO}/releases/latest");
    let body: serde_json::Value = ureq::get(&url)
        .set("User-Agent", "gmacFTP-updater")
        .set("Accept", "application/vnd.github+json")
        .call()
        .map_err(|e| format!("GitHub request failed: {e}"))?
        .into_json()
        .map_err(|e| format!("invalid response: {e}"))?;

    let tag = body.get("tag_name").and_then(|v| v.as_str()).unwrap_or("");
    let version = tag.trim_start_matches('v').to_string();
    if version.is_empty() {
        return Err("no tag_name in latest release".into());
    }
    if !is_newer(&version, CURRENT) {
        return Ok(None);
    }
    let dmg_url = body
        .get("assets")
        .and_then(|a| a.as_array())
        .and_then(|arr| {
            arr.iter().find_map(|a| {
                let name = a.get("name")?.as_str()?;
                let url = a.get("browser_download_url")?.as_str()?;
                name.ends_with(".dmg").then(|| url.to_string())
            })
        })
        .ok_or_else(|| "no .dmg asset in latest release".to_string())?;
    let notes = body
        .get("body")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    Ok(Some(LatestUpdate {
        version,
        dmg_url,
        notes,
    }))
}

/// True iff `latest` (e.g. "0.0.3") is strictly newer than `current` (e.g. "0.0.2").
/// Compares the first three numeric dot-segments; non-numeric segments count as 0.
pub fn is_newer(latest: &str, current: &str) -> bool {
    parse_semver(latest) > parse_semver(current)
}
fn parse_semver(v: &str) -> (u32, u32, u32) {
    // Each dot-segment contributes its leading run of digits ("3-beta" -> 3, "0" -> 0).
    let nums: Vec<u32> = v
        .split('.')
        .map(|seg| {
            let digits: String = seg.chars().take_while(|c| c.is_ascii_digit()).collect();
            digits.parse::<u32>().unwrap_or(0)
        })
        .collect();
    (
        *nums.first().unwrap_or(&0),
        *nums.get(1).unwrap_or(&0),
        *nums.get(2).unwrap_or(&0),
    )
}

/// Download `dmg_url` into ~/Downloads/gmacFTP-<version>.dmg. Returns the local path.
///
/// Hardened update path (the v0.0.14 audit found the prior version unbounded + non-atomic +
/// unchecked): (1) refuse any URL that isn't HTTPS on `github.com`; (2) sanitize the version
/// before it flows into the destination path (a git tag may contain `/`); (3) stream to a
/// `.part` temp via an exclusive (O_EXCL + 0600) open — defeating a pre-planted symlink — with
/// a 300 MiB cap against an unbounded/OOM stream; (4) fsync + atomic rename to the final `.dmg`
/// so a crash never leaves a half-written DMG that Finder would try to mount.
pub fn download(url: &str, version: &str) -> Result<PathBuf, String> {
    validate_asset_url(url)?;
    // Sanitize the version: a git tag is attacker-controllable and may contain '/', so an
    // unfiltered `version` could traverse out of ~/Downloads (`0.0.99/../../../tmp/evil`).
    // Keep only alphanumerics, '.', '-', '_'.
    let safe_version: String = version
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
        .collect();
    if safe_version.is_empty() {
        return Err(format!("invalid release version: {version:?}"));
    }

    let dir = directories::UserDirs::new()
        .and_then(|d| d.download_dir()?.canonicalize().ok())
        .unwrap_or_else(|| PathBuf::from("."));
    // Single source of truth for the destination name: `part` is derived from it, the rename
    // target is it, and it's what we return — so the three can never diverge (a release-tool
    // bug where Finder is told to open a different name than the one written would be silent).
    let final_path = dir.join(format!("gmacFTP-{safe_version}.dmg"));
    let mut part = final_path.clone().into_os_string();
    part.push(".part");
    let part = PathBuf::from(part);

    let resp = ureq::get(url)
        .set("User-Agent", "gmacFTP-updater")
        .call()
        .map_err(|e| format!("download failed: {e}"))?;
    let mut reader = resp.into_reader();

    // Stream with a hard size cap (replaces the unbounded read_to_end into a Vec). The exclusive
    // open reuses vault's CRYP-3 hardening (O_EXCL + 0600 + symlink-safe).
    let mut file = crate::store::vault::create_exclusive(&part)
        .map_err(|e| format!("could not create {}: {e}", part.display()))?;
    let mut buf = [0u8; 64 * 1024];
    let mut done: u64 = 0;
    loop {
        let n = reader
            .read(&mut buf)
            .map_err(|e| format!("read failed: {e}"))?;
        if n == 0 {
            break;
        }
        done = done.saturating_add(n as u64);
        if done > MAX_DMG_BYTES {
            let _ = std::fs::remove_file(&part);
            return Err(format!(
                "release too large (>{MAX_DMG_BYTES} bytes) — refusing"
            ));
        }
        file.write_all(&buf[..n])
            .map_err(|e| format!("write failed: {e}"))?;
    }
    file.sync_all().map_err(|e| format!("sync failed: {e}"))?;
    std::fs::rename(&part, &final_path).map_err(|e| format!("rename failed: {e}"))?;
    tracing::info!(
        target: "gmacftp::updater",
        bytes = done,
        path = %final_path.display(),
        "update DMG downloaded (transport-verified: HTTPS + github.com host + size cap + exclusive write). Content integrity + identity are confirmed by macOS Gatekeeper when the DMG is mounted."
    );
    Ok(final_path)
}

/// Open `path` with the default handler (Finder mounts a .dmg → shows the install window).
pub fn open_in_finder(path: &Path) {
    let _ = std::process::Command::new("open").arg(path).spawn();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn newer_detection() {
        assert!(is_newer("0.0.3", "0.0.2"));
        assert!(is_newer("0.1.0", "0.0.99"));
        assert!(is_newer("1.0.0", "0.9.9"));
        assert!(!is_newer("0.0.2", "0.0.2"));
        assert!(!is_newer("0.0.1", "0.0.2"));
    }

    #[test]
    fn non_numeric_segments_are_zero() {
        assert!(is_newer("0.0.3-beta", "0.0.2"));
        assert!(!is_newer("x.y.z", "0.0.0"));
    }

    #[test]
    fn asset_url_accepts_github_https() {
        assert!(validate_asset_url(
            "https://github.com/GMAC-pl/gmacftp/releases/download/v0.0.15/gmacFTP-0.0.15.dmg"
        )
        .is_ok());
    }

    #[test]
    fn asset_url_rejects_non_https_and_off_host() {
        assert!(validate_asset_url("http://github.com/x").is_err()); // not HTTPS
        assert!(validate_asset_url("file:///etc/passwd").is_err()); // not HTTPS
        assert!(validate_asset_url("https://evil.com/x").is_err()); // off-host
        assert!(validate_asset_url("https://github.com.evil.com/x").is_err()); // host spoof
        assert!(validate_asset_url("https://GITHUB.COM/x").is_ok()); // case-insensitive host
    }
}
