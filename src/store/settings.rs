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
    /// Enable iCloud sync of the connection list + encrypted vault across the user's Macs
    /// (via NSUbiquitousKeyValueStore — requires an iCloud account). When on, the vault
    /// master key is ALSO stored as an iCloud-Keychain-syncing item (requires iCloud Keychain
    /// in System Settings) so the synced vault decrypts on the other Mac. Default OFF.
    #[serde(default)]
    pub sync_via_icloud: bool,
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
