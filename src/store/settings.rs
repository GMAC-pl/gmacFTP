//! App settings (persisted to `<config_dir>/settings.json`).

use std::fs;
use std::io::Read;
use std::path::PathBuf;

const MAX_SETTINGS_BYTES: usize = 128 * 1024;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Settings {
    /// Accept any TLS certificate (self-signed / hostname mismatch). Default OFF (strict)
    /// since accepting untrusted certs enables active MITM that recovers FTP credentials.
    /// Users who need it for a mismatched-cert shared host can toggle the shield in the
    /// toolbar (the choice is persisted here).
    #[serde(default = "default_accept_any_cert")]
    pub accept_any_cert: bool,
    /// UI language: "en" | "pl".
    #[serde(default = "default_locale")]
    pub locale: String,
    /// UI theme: "light" (macOS Finder) | "dark".
    #[serde(default = "default_theme")]
    pub theme: String,
    /// User-added local folder shortcuts shown under Favorites.
    #[serde(default)]
    pub local_favorites: Vec<String>,
    /// When false, `local_favorites` is treated as legacy extras appended after defaults.
    /// When true, it is the full user-controlled Favorites order.
    #[serde(default)]
    pub local_favorites_customized: bool,
    /// Folder where sync copies of connections.json + vault.bin are written as plain files,
    /// synced by iCloud Drive / Dropbox / etc. (a normal folder — NO iCloud/CloudKit API, so
    /// no App-Store-only entitlement gate). None = default to iCloud Drive
    /// (`~/Library/Mobile Documents/com~apple~CloudDocs/gmacFTP`) when that exists.
    #[serde(default)]
    pub sync_folder: Option<String>,
    /// Enable cross-device sync of the connection list + encrypted vault. Sync mirrors
    /// `connections.json` + `vault.bin` as plain files in a synced folder (default the user's
    /// iCloud Drive). When on, the vault master key is wrapped with the sync passphrase and
    /// the wrapped key travels in the sync folder; the passphrase itself is cached in the
    /// Keychain (FIXED cross-bundle service) so the synced vault decrypts on the other Mac.
    /// Default OFF.
    #[serde(default)]
    pub sync_via_icloud: bool,
    /// True once the user has set a sync passphrase (so enabling sync prompts for one only the
    /// first time). The passphrase itself is NEVER stored here — only in the Keychain / user
    /// memory.
    #[serde(default)]
    pub sync_passphrase_set: bool,
    /// True once this app's saved legacy Keychain passwords have been folded into the vault.
    /// The migration reads only exact, allow-listed service/account pairs from connections.json;
    /// Retained for compatibility with v0.0.18, whose vault still used `(host, user)` keys.
    #[serde(default)]
    pub keychain_migrated_v2: bool,
    /// True once every locally saved connection has received an endpoint-bound credential key
    /// `(protocol, canonical host, effective port, user)`. This must be a separate flag from the
    /// v0.0.18 Keychain migration flag so that upgrading users are not incorrectly skipped.
    #[serde(default)]
    pub endpoint_credentials_migrated_v2: bool,
}

fn default_accept_any_cert() -> bool {
    // Strict-by-default: cert chain validation ON. Lenient mode is an explicit opt-in
    // (toolbar shield) for mismatched-cert hosts, never the shipping default.
    false
}
fn default_locale() -> String {
    "en".to_string()
}
fn default_theme() -> String {
    "light".to_string()
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            accept_any_cert: default_accept_any_cert(),
            locale: default_locale(),
            theme: default_theme(),
            local_favorites: Vec::new(),
            local_favorites_customized: false,
            sync_via_icloud: false,
            sync_folder: None,
            sync_passphrase_set: false,
            keychain_migrated_v2: false,
            endpoint_credentials_migrated_v2: false,
        }
    }
}

fn path() -> Option<PathBuf> {
    directories::ProjectDirs::from(
        env!("MACKFTP_CONFIG_QUALIFIER"),
        env!("MACKFTP_CONFIG_ORGANIZATION"),
        env!("MACKFTP_CONFIG_APPLICATION"),
    )
    .map(|pd| pd.config_dir().join("settings.json"))
}

pub fn load() -> Settings {
    let Some(p) = path() else {
        return Settings::default();
    };
    match read_regular_limited(&p, MAX_SETTINGS_BYTES) {
        Ok(bytes) if !bytes.iter().all(u8::is_ascii_whitespace) => serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| {
                tracing::warn!(error = %e, "settings parse failed; using defaults");
                Settings::default()
            }),
        _ => Settings::default(),
    }
}

fn read_regular_limited(path: &std::path::Path, limit: usize) -> std::io::Result<Vec<u8>> {
    let before = fs::symlink_metadata(path)?;
    if !before.file_type().is_file()
        || before.file_type().is_symlink()
        || before.len() > limit as u64
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "settings are not a bounded regular file",
        ));
    }
    let mut file = fs::File::open(path)?;
    let opened = file.metadata()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if before.dev() != opened.dev() || before.ino() != opened.ino() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "settings changed while opening",
            ));
        }
    }
    if !opened.file_type().is_file() || opened.len() > limit as u64 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "settings changed type or size",
        ));
    }
    let mut bytes = Vec::with_capacity(opened.len() as usize);
    file.by_ref()
        .take(limit.saturating_add(1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "settings exceed their size limit",
        ));
    }
    Ok(bytes)
}

/// Persist settings and report failures to callers that can surface them to the user.
pub fn try_save(s: &Settings) -> Result<(), std::io::Error> {
    let Some(p) = path() else {
        return Ok(());
    };
    // Reuse the hardened atomic_write (O_EXCL + 0600 + fsync + rename) so a crash/power loss
    // mid-save can't truncate settings.json — fulfills the v0.0.13 "atomic writes everywhere
    // user data lives" contract (connections.json + vault already use this same helper).
    let json = serde_json::to_string_pretty(s)
        .map_err(|e| std::io::Error::other(format!("settings serialization failed: {e}")))?;
    crate::store::vault::atomic_write(&p, json.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn old_migration_flag_does_not_skip_endpoint_key_upgrade() {
        let settings: Settings = serde_json::from_str(r#"{"keychain_migrated_v2":true}"#).unwrap();
        assert!(settings.keychain_migrated_v2);
        assert!(!settings.endpoint_credentials_migrated_v2);
    }
}
