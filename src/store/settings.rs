//! App settings (persisted to `<config_dir>/settings.json`).

use std::fs;
use std::path::PathBuf;

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
    /// True once the legacy per-server Keychain passwords have been folded into the vault
    /// (one-time migration via a single Keychain authorization). v2: the v1 flag was set by a
    /// buggy build that matched on the wrong service prefix; renaming forces a correct re-run.
    #[serde(default)]
    pub keychain_migrated_v2: bool,
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
    match fs::read_to_string(&p) {
        Ok(s) if !s.trim().is_empty() => serde_json::from_str(&s).unwrap_or_else(|e| {
            tracing::warn!(error = %e, "settings parse failed; using defaults");
            Settings::default()
        }),
        _ => Settings::default(),
    }
}

pub fn save(s: &Settings) {
    let Some(p) = path() else {
        return;
    };
    if let Some(parent) = p.parent() {
        let _ = fs::create_dir_all(parent);
    }
    if let Ok(json) = serde_json::to_string_pretty(s) {
        let _ = fs::write(&p, json);
    }
}
