//! In-app update check without embedding a third-party updater framework.
//!
//! Updates are accepted only when all of these checks succeed:
//! - the Releases API points at the exact expected DMG name on `github.com`;
//! - GitHub supplies a SHA-256 digest and byte size for that asset;
//! - the streamed download matches both values;
//! - the DMG itself has a valid Developer ID signature from gmacFTP's Apple team and a
//!   stapled notarization ticket.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use sha2::{Digest, Sha256};
use ureq::ResponseExt;

const REPO: &str = "GMAC-pl/gmacftp";
pub const CURRENT: &str = env!("CARGO_PKG_VERSION");
const GH_API_HOST: &str = "api.github.com";
const GH_ASSET_HOST: &str = "github.com";
const GH_REDIRECT_HOSTS: &[&str] = &[
    GH_ASSET_HOST,
    "objects.githubusercontent.com",
    "release-assets.githubusercontent.com",
];
const EXPECTED_TEAM_ID: &str = "SY4HQ4PWVU";
const EXPECTED_APP_BUNDLE_ID: &str = "app.mackftp.client";
const EXPECTED_DMG_IDENTIFIER: &str = "app.mackftp.client.dmg";
const MAX_API_BYTES: u64 = 2 * 1024 * 1024;
const MAX_RELEASE_NOTES_BYTES: usize = 64 * 1024;
const MAX_DMG_BYTES: u64 = 300 * 1024 * 1024;
const CHECK_TIMEOUT: Duration = Duration::from_secs(30);
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(60 * 60);

/// Personal/local bundles use a separate identity and must never offer to replace themselves with
/// the public app. This also keeps the updater unavailable on non-macOS development targets.
pub fn supported() -> bool {
    cfg!(target_os = "macos") && env!("MACKFTP_BUNDLE_ID") == EXPECTED_APP_BUNDLE_ID
}

fn https_host(url: &str) -> Result<&str, String> {
    let after = url
        .strip_prefix("https://")
        .ok_or_else(|| format!("refusing non-HTTPS URL: {url}"))?;
    let authority = after.split(['/', '?', '#']).next().unwrap_or("");
    if authority.is_empty() || authority.contains('@') {
        return Err(format!("invalid HTTPS URL authority: {url}"));
    }
    let (host, port) = authority
        .rsplit_once(':')
        .map_or((authority, None), |(h, p)| (h, Some(p)));
    if port.is_some_and(|p| p != "443") || host.is_empty() {
        return Err(format!("refusing non-standard HTTPS endpoint: {url}"));
    }
    Ok(host)
}

fn validate_url_host(url: &str, allowed: &[&str]) -> Result<(), String> {
    let host = https_host(url)?;
    if allowed
        .iter()
        .any(|expected| host.eq_ignore_ascii_case(expected))
    {
        Ok(())
    } else {
        Err(format!("refusing off-host URL: {url}"))
    }
}

fn parse_version(v: &str) -> Option<(u64, u64, u64)> {
    // Release versions also become filenames. Accept only the project's numeric tag format;
    // allowing an arbitrary semver suffix here would make path separators attacker-controlled.
    let mut parts = v.split('.');
    let parsed = (
        parts.next()?.parse().ok()?,
        parts.next()?.parse().ok()?,
        parts.next()?.parse().ok()?,
    );
    parts.next().is_none().then_some(parsed)
}

fn normalized_sha256(digest: &str) -> Result<String, String> {
    let value = digest.strip_prefix("sha256:").unwrap_or(digest);
    if value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit()) {
        Ok(value.to_ascii_lowercase())
    } else {
        Err("release asset has no valid SHA-256 digest".into())
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn validate_response_hosts(
    response: &ureq::http::Response<ureq::Body>,
    allowed: &[&str],
) -> Result<(), String> {
    if let Some(history) = response.get_redirect_history() {
        for uri in history {
            validate_url_host(&uri.to_string(), allowed)?;
        }
    }
    validate_url_host(&response.get_uri().to_string(), allowed)
}

#[derive(Debug, Clone)]
pub struct LatestUpdate {
    pub version: String,
    pub dmg_url: String,
    pub sha256: String,
    pub size: u64,
    pub notes: String,
}

fn sanitize_release_notes(raw: &str) -> String {
    let mut notes = String::with_capacity(raw.len().min(MAX_RELEASE_NOTES_BYTES));
    let mut truncated = false;
    for character in raw.chars() {
        let character = match character {
            '\r' => continue,
            '\n' | '\t' => character,
            value if value.is_control() => continue,
            value => value,
        };
        if notes.len().saturating_add(character.len_utf8()) > MAX_RELEASE_NOTES_BYTES {
            truncated = true;
            break;
        }
        notes.push(character);
    }
    let trimmed = notes.trim();
    if trimmed.is_empty() {
        return "No release notes were provided.".into();
    }
    let mut notes = trimmed.to_string();
    if truncated {
        notes.push_str("\n\n…");
    }
    notes
}

fn parse_release_response(api_bytes: &[u8]) -> Result<Option<LatestUpdate>, String> {
    let body: serde_json::Value =
        serde_json::from_slice(api_bytes).map_err(|e| format!("invalid GitHub response: {e}"))?;

    let tag = body
        .get("tag_name")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "no tag_name in latest release".to_string())?;
    let version = tag
        .strip_prefix('v')
        .ok_or_else(|| "release tag must start with v".to_string())?;
    parse_version(version).ok_or_else(|| format!("invalid release version: {version:?}"))?;
    parse_version(CURRENT).ok_or_else(|| format!("invalid current version: {CURRENT:?}"))?;
    if !is_newer(version, CURRENT) {
        return Ok(None);
    }

    let expected_name = format!("gmacFTP-{version}.dmg");
    let asset = body
        .get("assets")
        .and_then(|a| a.as_array())
        .and_then(|assets| {
            let mut matches = assets
                .iter()
                .filter(|asset| asset.get("name").and_then(|n| n.as_str()) == Some(&expected_name));
            let first = matches.next()?;
            matches.next().is_none().then_some(first)
        })
        .ok_or_else(|| format!("release must contain exactly one {expected_name} asset"))?;
    let dmg_url = asset
        .get("browser_download_url")
        .and_then(|v| v.as_str())
        .ok_or_else(|| "release asset has no download URL".to_string())?
        .to_string();
    validate_url_host(&dmg_url, &[GH_ASSET_HOST])?;
    let size = asset
        .get("size")
        .and_then(|v| v.as_u64())
        .filter(|n| *n > 0 && *n <= MAX_DMG_BYTES)
        .ok_or_else(|| "release asset has an invalid size".to_string())?;
    let sha256 = normalized_sha256(
        asset
            .get("digest")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "release asset has no GitHub SHA-256 digest".to_string())?,
    )?;
    let notes = sanitize_release_notes(body.get("body").and_then(|v| v.as_str()).unwrap_or(""));
    Ok(Some(LatestUpdate {
        version: version.to_string(),
        dmg_url,
        sha256,
        size,
        notes,
    }))
}

/// Query GitHub for the latest release and require the exact DMG asset, size, and digest.
pub fn check() -> Result<Option<LatestUpdate>, String> {
    if !supported() {
        return Err("updates are available only in the public macOS build".into());
    }
    let url = format!("https://{GH_API_HOST}/repos/{REPO}/releases/latest");
    validate_url_host(&url, &[GH_API_HOST])?;
    let response = ureq::get(&url)
        .header("User-Agent", "gmacFTP-updater")
        .header("Accept", "application/vnd.github+json")
        .config()
        .https_only(true)
        .save_redirect_history(true)
        .timeout_global(Some(CHECK_TIMEOUT))
        .build()
        .call()
        .map_err(|e| format!("GitHub request failed: {e}"))?;
    validate_response_hosts(&response, &[GH_API_HOST])?;
    if response
        .body()
        .content_length()
        .is_some_and(|n| n > MAX_API_BYTES)
    {
        return Err("GitHub release response is unexpectedly large".into());
    }
    let mut api_bytes = Vec::new();
    response
        .into_body()
        .into_reader()
        .take(MAX_API_BYTES.saturating_add(1))
        .read_to_end(&mut api_bytes)
        .map_err(|e| format!("could not read GitHub response: {e}"))?;
    if api_bytes.len() as u64 > MAX_API_BYTES {
        return Err("GitHub release response is unexpectedly large".into());
    }
    parse_release_response(&api_bytes)
}

pub fn is_newer(latest: &str, current: &str) -> bool {
    matches!((parse_version(latest), parse_version(current)), (Some(a), Some(b)) if a > b)
}

/// Download, hash, verify the signed/notarized DMG, then atomically expose it in Downloads.
pub fn download(
    url: &str,
    version: &str,
    expected_sha256: &str,
    expected_size: u64,
) -> Result<PathBuf, String> {
    if !supported() {
        return Err("updates are available only in the public macOS build".into());
    }
    validate_url_host(url, &[GH_ASSET_HOST])?;
    parse_version(version).ok_or_else(|| format!("invalid release version: {version:?}"))?;
    let expected_sha256 = normalized_sha256(expected_sha256)?;
    if expected_size == 0 || expected_size > MAX_DMG_BYTES {
        return Err("invalid expected release size".into());
    }

    let dir = directories::UserDirs::new()
        .and_then(|d| d.download_dir()?.canonicalize().ok())
        .ok_or_else(|| "Downloads directory is unavailable".to_string())?;
    let final_path = dir.join(format!("gmacFTP-{version}.dmg"));
    let part = dir.join(format!(
        ".gmacFTP-{version}-{}-{:016x}{:016x}.part",
        std::process::id(),
        rand::random::<u64>(),
        rand::random::<u64>()
    ));

    let result = (|| -> Result<(), String> {
        let response = ureq::get(url)
            .header("User-Agent", "gmacFTP-updater")
            .config()
            .https_only(true)
            .save_redirect_history(true)
            .timeout_global(Some(DOWNLOAD_TIMEOUT))
            .timeout_connect(Some(CHECK_TIMEOUT))
            .timeout_recv_response(Some(CHECK_TIMEOUT))
            .timeout_recv_body(Some(CHECK_TIMEOUT))
            .build()
            .call()
            .map_err(|e| format!("download failed: {e}"))?;
        validate_response_hosts(&response, GH_REDIRECT_HOSTS)?;
        if response
            .body()
            .content_length()
            .is_some_and(|n| n != expected_size || n > MAX_DMG_BYTES)
        {
            return Err("release Content-Length does not match GitHub metadata".into());
        }
        let mut reader = response.into_body().into_reader();
        let mut file = crate::store::vault::create_exclusive(&part)
            .map_err(|e| format!("could not create {}: {e}", part.display()))?;
        let mut hasher = Sha256::new();
        let mut buf = [0u8; 64 * 1024];
        let mut done = 0u64;
        loop {
            let n = reader
                .read(&mut buf)
                .map_err(|e| format!("read failed: {e}"))?;
            if n == 0 {
                break;
            }
            done = done.saturating_add(n as u64);
            if done > MAX_DMG_BYTES || done > expected_size {
                return Err("release exceeded its declared size".into());
            }
            hasher.update(&buf[..n]);
            file.write_all(&buf[..n])
                .map_err(|e| format!("write failed: {e}"))?;
        }
        if done != expected_size {
            return Err(format!(
                "release size mismatch: expected {expected_size}, received {done}"
            ));
        }
        let actual = encode_hex(&hasher.finalize());
        if actual != expected_sha256 {
            return Err("release SHA-256 mismatch".into());
        }
        file.sync_all().map_err(|e| format!("sync failed: {e}"))?;
        drop(file);
        verify_release_image(&part)?;
        std::fs::rename(&part, &final_path).map_err(|e| format!("rename failed: {e}"))?;
        tracing::info!(
            target: "gmacftp::updater",
            bytes = done,
            sha256 = %actual,
            path = %final_path.display(),
            "update verified (GitHub digest + Developer ID team + notarization)"
        );
        Ok(())
    })();
    if let Err(error) = result {
        let _ = std::fs::remove_file(&part);
        return Err(error);
    }
    Ok(final_path)
}

#[cfg(target_os = "macos")]
fn verify_release_image(path: &Path) -> Result<(), String> {
    let verify = Command::new("codesign")
        .args(["--verify", "--strict", "--verbose=2"])
        .arg(path)
        .output()
        .map_err(|e| format!("could not run codesign: {e}"))?;
    if !verify.status.success() {
        return Err(format!(
            "release DMG signature is invalid: {}",
            String::from_utf8_lossy(&verify.stderr).trim()
        ));
    }
    let details = Command::new("codesign")
        .args(["-d", "--verbose=4"])
        .arg(path)
        .output()
        .map_err(|e| format!("could not inspect DMG signature: {e}"))?;
    if !details.status.success() {
        return Err("could not inspect release DMG signature".into());
    }
    let metadata = String::from_utf8_lossy(&details.stderr);
    if !metadata
        .lines()
        .any(|line| line.trim() == format!("TeamIdentifier={EXPECTED_TEAM_ID}"))
    {
        return Err("release DMG was not signed by the expected Apple team".into());
    }
    if !metadata
        .lines()
        .any(|line| line.trim() == format!("Identifier={EXPECTED_DMG_IDENTIFIER}"))
    {
        return Err("release DMG has an unexpected signing identifier".into());
    }
    let staple = Command::new("xcrun")
        .args(["stapler", "validate"])
        .arg(path)
        .output()
        .map_err(|e| format!("could not validate notarization ticket: {e}"))?;
    if !staple.status.success() {
        return Err("release DMG has no valid stapled notarization ticket".into());
    }
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn verify_release_image(_path: &Path) -> Result<(), String> {
    Err("updates are supported only on macOS".into())
}

pub fn open_in_finder(path: &Path) -> Result<(), String> {
    Command::new("open")
        .arg(path)
        .spawn()
        .map(|_| ())
        .map_err(|e| format!("could not open verified update: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strict_version_detection() {
        assert!(is_newer("0.0.3", "0.0.2"));
        assert!(is_newer("1.0.0", "0.99.99"));
        assert!(!is_newer("0.0.2", "0.0.2"));
        assert!(!is_newer("x.y.z", "0.0.0"));
        assert!(!is_newer("0.0.3.1", "0.0.2"));
        assert!(!is_newer("0.0.3-beta", "0.0.2"));
        assert!(!is_newer("0.0.3-/../../tmp/evil", "0.0.2"));
    }

    #[test]
    fn url_allowlist_rejects_spoofing_and_nonstandard_ports() {
        assert!(validate_url_host("https://github.com/x", &[GH_ASSET_HOST]).is_ok());
        assert!(validate_url_host("https://GITHUB.COM:443/x", &[GH_ASSET_HOST]).is_ok());
        assert!(validate_url_host("http://github.com/x", &[GH_ASSET_HOST]).is_err());
        assert!(validate_url_host("https://github.com.evil.test/x", &[GH_ASSET_HOST]).is_err());
        assert!(validate_url_host("https://user@github.com/x", &[GH_ASSET_HOST]).is_err());
        assert!(validate_url_host("https://github.com:444/x", &[GH_ASSET_HOST]).is_err());
    }

    #[test]
    fn sha256_metadata_is_strict() {
        let hash = "8c6aeb2eafe1c62236dbf13baa061035de99972647be9c751edd28f8999fa352";
        assert_eq!(normalized_sha256(hash).unwrap(), hash);
        assert_eq!(normalized_sha256(&format!("sha256:{hash}")).unwrap(), hash);
        assert!(normalized_sha256("sha256:abcd").is_err());
        assert!(normalized_sha256(&"z".repeat(64)).is_err());
        assert_eq!(encode_hex(&[0x00, 0x0f, 0xa5, 0xff]), "000fa5ff");
    }

    fn valid_newer_release(notes: &str) -> Vec<u8> {
        let version = "18446744073709551615.0.0";
        serde_json::to_vec(&serde_json::json!({
            "tag_name": format!("v{version}"),
            "body": notes,
            "assets": [{
                "name": format!("gmacFTP-{version}.dmg"),
                "browser_download_url": format!(
                    "https://github.com/{REPO}/releases/download/v{version}/gmacFTP-{version}.dmg"
                ),
                "size": 1234,
                "digest": format!("sha256:{}", "a".repeat(64)),
            }],
        }))
        .unwrap()
    }

    #[test]
    fn release_response_requires_one_exact_trusted_asset() {
        let update = parse_release_response(&valid_newer_release("Fixes\n\0Details"))
            .unwrap()
            .unwrap();
        assert_eq!(update.version, "18446744073709551615.0.0");
        assert_eq!(update.size, 1234);
        assert_eq!(update.sha256, "a".repeat(64));
        assert_eq!(update.notes, "Fixes\nDetails");

        let mut body: serde_json::Value =
            serde_json::from_slice(&valid_newer_release("notes")).unwrap();
        let duplicate = body["assets"][0].clone();
        body["assets"].as_array_mut().unwrap().push(duplicate);
        assert!(parse_release_response(&serde_json::to_vec(&body).unwrap()).is_err());

        body["assets"].as_array_mut().unwrap().pop();
        body["assets"][0]["browser_download_url"] =
            serde_json::json!("https://github.com.evil.test/gmacFTP.dmg");
        assert!(parse_release_response(&serde_json::to_vec(&body).unwrap()).is_err());
    }

    #[test]
    fn release_notes_are_plain_bounded_text() {
        assert_eq!(
            sanitize_release_notes("\r\n\0\u{7}"),
            "No release notes were provided."
        );
        let notes = sanitize_release_notes(&"ę".repeat(MAX_RELEASE_NOTES_BYTES));
        assert!(notes.starts_with('ę'));
        assert!(notes.ends_with('…'));
        assert!(notes.len() <= MAX_RELEASE_NOTES_BYTES + 64);
        assert!(!notes
            .chars()
            .any(|character| { character.is_control() && !matches!(character, '\n' | '\t') }));
    }
}
