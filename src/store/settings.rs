//! App settings (persisted to `<config_dir>/settings.json`).

use std::fs;
use std::io::Read;
use std::path::PathBuf;

const MAX_SETTINGS_BYTES: usize = 128 * 1024;
pub const MIN_TRANSFER_CONCURRENCY: usize = 1;
pub const MAX_TRANSFER_CONCURRENCY: usize = 6;
pub const DEFAULT_TRANSFER_CONCURRENCY: usize = 3;
pub const MIN_SERVER_TRANSFER_CONCURRENCY: usize = 1;
pub const MAX_SERVER_TRANSFER_CONCURRENCY: usize = 4;
pub const DEFAULT_SERVER_TRANSFER_CONCURRENCY: usize = 2;
pub const MAX_TRANSFER_RETRIES: usize = 10;
pub const MIN_RETRY_BACKOFF_MS: u64 = 100;
pub const MAX_RETRY_BACKOFF_MS: u64 = 60_000;
pub const MIN_BANDWIDTH_LIMIT_KIB: u64 = 64;
pub const MAX_BANDWIDTH_LIMIT_KIB: u64 = 1_048_576;
pub const MIN_EDITOR_DOWNLOAD_MIB: usize = 1;
pub const MAX_EDITOR_DOWNLOAD_MIB: usize = 1_024;
pub const MIN_WINDOW_WIDTH_PX: u32 = 900;
pub const MAX_WINDOW_WIDTH_PX: u32 = 7_680;
pub const MIN_WINDOW_HEIGHT_PX: u32 = 600;
pub const MAX_WINDOW_HEIGHT_PX: u32 = 4_320;
pub const MAX_SYNC_PROFILES: usize = 32;
pub const MAX_EDITOR_MAPPINGS: usize = 64;
pub const MAX_REMOTE_PLACES: usize = 128;
const MAX_EDITOR_MAPPING_INPUT_BYTES: usize = 8 * 1024;
const MAX_EDITOR_EXTENSION_BYTES: usize = 32;
const MAX_EDITOR_APPLICATION_BYTES: usize = 1024;
const MAX_SYNC_PROFILE_NAME_BYTES: usize = 128;
const MAX_SYNC_PROFILE_PATH_BYTES: usize = 4 * 1024;
const MAX_SYNC_PROFILE_EXCLUSIONS_BYTES: usize = 8 * 1024;
const MAX_SYNC_PROFILE_TOTAL_BYTES: usize = 96 * 1024;
const MAX_PERSISTED_PATH_BYTES: usize = 16 * 1024;
const MAX_LOCAL_FAVORITES: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct SyncProfile {
    pub name: String,
    pub connection_id: usize,
    /// SHA-256 of protocol + canonical endpoint + port + username. Prevents a profile from
    /// silently targeting a different server if a numeric connection identifier is ever reused.
    #[serde(default)]
    pub endpoint_fingerprint: String,
    pub local_root: String,
    pub remote_root: String,
    pub direction: String,
    #[serde(default = "default_sync_mode")]
    pub mode: String,
    #[serde(default = "default_sync_comparison")]
    pub comparison: String,
    #[serde(default = "default_sync_tolerance")]
    pub mtime_tolerance_secs: i64,
    #[serde(default)]
    pub server_clock_offset_secs: i64,
    #[serde(default = "default_sync_exclusions")]
    pub exclusions: String,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct EditorMapping {
    pub extension: String,
    pub application: String,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct RemotePlace {
    pub connection_id: usize,
    /// Endpoint-bound identity, using the same digest as saved sync profiles. An id reused for a
    /// different server must never inherit another endpoint's private paths.
    pub endpoint_fingerprint: String,
    pub path: String,
}

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
    /// Maximum number of file transfers across all endpoints. Each server has a separate,
    /// smaller lane limit and each lane reuses its own authenticated session.
    #[serde(default = "default_transfer_concurrency")]
    pub transfer_concurrency: usize,
    /// Default number of files transferred concurrently to one server. Individual saved
    /// connections may override it within the same safe bounds.
    #[serde(default = "default_server_transfer_concurrency")]
    pub per_server_transfer_concurrency: usize,
    /// Recursively calculate every visible folder's aggregate size after a directory listing.
    /// Disabled by default because it can create thousands of server requests. Folder size is
    /// always available explicitly from the row context menu.
    #[serde(default)]
    pub background_folder_metadata: bool,
    /// Show dotfiles in both panes.
    #[serde(default)]
    pub show_hidden_files: bool,
    /// Show owner, group and Unix permission columns in both file panes.
    #[serde(default)]
    pub show_advanced_columns: bool,
    /// Require confirmation before local Trash or permanent remote deletion.
    #[serde(default = "default_true")]
    pub confirm_deletes: bool,
    /// Move remote entries into a hidden sibling quarantine directory instead of deleting them.
    /// A permanent remote delete is always an explicit action, even when confirmations are off.
    #[serde(default = "default_true")]
    pub remote_quarantine_deletes: bool,
    /// Restore pane locations and layout from the previous clean session.
    #[serde(default = "default_true")]
    pub restore_workspace: bool,
    /// Show the server manager after launch. Explicit test/demo panel selection takes priority.
    #[serde(default)]
    pub open_connection_manager_on_launch: bool,
    /// Query the public GitHub Releases API once after launch. Opt-in and off by default; a
    /// discovered release is never downloaded without a separate explicit user action.
    #[serde(default)]
    pub check_updates_automatically: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_left_local_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_right_local_path: Option<String>,
    #[serde(default = "default_pane_split_px")]
    pub pane_split_px: u32,
    /// Last clean-session window geometry in physical pixels. Position is optional because some
    /// window systems do not expose it; obviously invalid/off-screen values are ignored.
    #[serde(default = "default_window_width_px")]
    pub window_width_px: u32,
    #[serde(default = "default_window_height_px")]
    pub window_height_px: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub window_x_px: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub window_y_px: Option<i32>,
    /// Number of automatic attempts after a transient transfer failure.
    #[serde(default = "default_retry_count")]
    pub transfer_retry_count: usize,
    /// Initial retry delay; later attempts use bounded exponential backoff.
    #[serde(default = "default_retry_backoff_ms")]
    pub transfer_retry_backoff_ms: u64,
    /// Aggregate transfer ceiling in KiB/s. Zero means unlimited.
    #[serde(default)]
    pub transfer_bandwidth_limit_kib: u64,
    /// Conflict policy: `ask` | `overwrite` | `keep_both` | `skip`.
    #[serde(default = "default_existing_file_policy")]
    pub existing_file_policy: String,
    /// Multi-file failure policy: `ask` | `skip` | `stop`.
    #[serde(default = "default_batch_error_policy")]
    pub batch_error_policy: String,
    /// Recovered queue policy: `ask` | `resume` | `discard`.
    #[serde(default = "default_queue_recovery_policy")]
    pub queue_recovery_policy: String,
    /// Show a privacy-safe macOS notification after the complete queue becomes idle.
    #[serde(default)]
    pub notify_transfer_completion: bool,
    /// Show a privacy-safe macOS notification when an individual transfer fails.
    #[serde(default)]
    pub notify_transfer_failure: bool,
    /// Preserve source modification times where the selected protocol exposes them.
    #[serde(default)]
    pub preserve_transfer_timestamps: bool,
    /// Preserve source Unix permission bits where the selected protocol exposes them.
    #[serde(default)]
    pub preserve_transfer_permissions: bool,
    /// Default sync comparison shown in a new preview (`size_mtime` | `size_only` | `checksum`).
    #[serde(default = "default_sync_comparison")]
    pub sync_comparison: String,
    #[serde(default = "default_sync_tolerance")]
    pub sync_mtime_tolerance_secs: i64,
    #[serde(default = "default_sync_exclusions")]
    pub sync_exclusions: String,
    /// Named folder-sync configurations. Credentials and server addresses are deliberately absent;
    /// the profile references a separately validated saved connection by its local identifier.
    #[serde(default)]
    pub sync_profiles: Vec<SyncProfile>,
    /// Maximum remote file size accepted by the edit-in-default-app workflow.
    #[serde(default = "default_editor_download_mib")]
    pub editor_max_download_mib: usize,
    /// Upload a changed edit only after an optimistic remote-version check succeeds.
    #[serde(default = "default_true")]
    pub editor_auto_upload: bool,
    /// Keep a changed temporary edit after an upload/conflict error so work can be recovered.
    #[serde(default = "default_true")]
    pub editor_retain_on_error: bool,
    /// Extension-specific macOS application mappings. Application values are passed as a single
    /// argument to `open -a`; they are never interpreted by a shell.
    #[serde(default)]
    pub editor_mappings: Vec<EditorMapping>,
    /// Per-server remote folder shortcuts. They contain paths only; credentials and host names
    /// remain in their dedicated stores.
    #[serde(default)]
    pub remote_places: Vec<RemotePlace>,
    /// Remote-change policy: retain_local | upload_copy | overwrite.
    #[serde(default = "default_editor_conflict_action")]
    pub editor_conflict_action: String,
    /// Empty is the legacy migration sentinel; validated values are cleanup | on_error | always.
    #[serde(default)]
    pub editor_temp_retention: String,
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
    "system".to_string()
}
fn default_theme() -> String {
    "system".to_string()
}
fn default_transfer_concurrency() -> usize {
    DEFAULT_TRANSFER_CONCURRENCY
}
fn default_server_transfer_concurrency() -> usize {
    DEFAULT_SERVER_TRANSFER_CONCURRENCY
}
fn default_true() -> bool {
    true
}
fn default_retry_count() -> usize {
    3
}
fn default_pane_split_px() -> u32 {
    440
}
fn default_window_width_px() -> u32 {
    1_180
}
fn default_window_height_px() -> u32 {
    740
}
fn default_retry_backoff_ms() -> u64 {
    1_000
}
fn default_existing_file_policy() -> String {
    "ask".to_string()
}
fn default_batch_error_policy() -> String {
    "ask".to_string()
}
fn default_queue_recovery_policy() -> String {
    "ask".to_string()
}
fn default_sync_comparison() -> String {
    "size_mtime".to_string()
}
fn default_sync_mode() -> String {
    "one_way".to_string()
}
fn default_sync_tolerance() -> i64 {
    2
}
fn default_sync_exclusions() -> String {
    ".git, .DS_Store, *.part, *.tmp".to_string()
}
fn default_editor_download_mib() -> usize {
    64
}
fn default_editor_conflict_action() -> String {
    "retain_local".to_string()
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            accept_any_cert: default_accept_any_cert(),
            locale: default_locale(),
            theme: default_theme(),
            transfer_concurrency: default_transfer_concurrency(),
            per_server_transfer_concurrency: default_server_transfer_concurrency(),
            background_folder_metadata: false,
            show_hidden_files: false,
            show_advanced_columns: false,
            confirm_deletes: true,
            remote_quarantine_deletes: true,
            restore_workspace: true,
            open_connection_manager_on_launch: false,
            check_updates_automatically: false,
            last_left_local_path: None,
            last_right_local_path: None,
            pane_split_px: default_pane_split_px(),
            window_width_px: default_window_width_px(),
            window_height_px: default_window_height_px(),
            window_x_px: None,
            window_y_px: None,
            transfer_retry_count: default_retry_count(),
            transfer_retry_backoff_ms: default_retry_backoff_ms(),
            transfer_bandwidth_limit_kib: 0,
            existing_file_policy: default_existing_file_policy(),
            batch_error_policy: default_batch_error_policy(),
            queue_recovery_policy: default_queue_recovery_policy(),
            notify_transfer_completion: false,
            notify_transfer_failure: false,
            preserve_transfer_timestamps: false,
            preserve_transfer_permissions: false,
            sync_comparison: default_sync_comparison(),
            sync_mtime_tolerance_secs: default_sync_tolerance(),
            sync_exclusions: default_sync_exclusions(),
            sync_profiles: Vec::new(),
            editor_max_download_mib: default_editor_download_mib(),
            editor_auto_upload: true,
            editor_retain_on_error: true,
            editor_mappings: Vec::new(),
            remote_places: Vec::new(),
            editor_conflict_action: default_editor_conflict_action(),
            editor_temp_retention: "on_error".into(),
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
    let settings = match read_regular_limited(&p, MAX_SETTINGS_BYTES) {
        Ok(bytes) if !bytes.iter().all(u8::is_ascii_whitespace) => serde_json::from_slice(&bytes)
            .unwrap_or_else(|e| {
                tracing::warn!(error = %e, "settings parse failed; using defaults");
                Settings::default()
            }),
        _ => Settings::default(),
    };
    validate(settings)
}

/// Normalize every value that can influence resource use or behavior. Applied both after reading
/// legacy JSON and immediately before writing, so invalid UI/import values never reach disk.
pub fn validate(mut settings: Settings) -> Settings {
    if !matches!(settings.locale.as_str(), "system" | "en" | "pl") {
        settings.locale = default_locale();
    }
    if !matches!(settings.theme.as_str(), "system" | "light" | "dark") {
        settings.theme = default_theme();
    }
    settings.transfer_concurrency = settings
        .transfer_concurrency
        .clamp(MIN_TRANSFER_CONCURRENCY, MAX_TRANSFER_CONCURRENCY);
    settings.per_server_transfer_concurrency = settings.per_server_transfer_concurrency.clamp(
        MIN_SERVER_TRANSFER_CONCURRENCY,
        MAX_SERVER_TRANSFER_CONCURRENCY,
    );
    settings.transfer_retry_count = settings.transfer_retry_count.min(MAX_TRANSFER_RETRIES);
    settings.pane_split_px = settings.pane_split_px.clamp(220, 4_000);
    settings.window_width_px = settings
        .window_width_px
        .clamp(MIN_WINDOW_WIDTH_PX, MAX_WINDOW_WIDTH_PX);
    settings.window_height_px = settings
        .window_height_px
        .clamp(MIN_WINDOW_HEIGHT_PX, MAX_WINDOW_HEIGHT_PX);
    for coordinate in [&mut settings.window_x_px, &mut settings.window_y_px] {
        if coordinate.is_some_and(|value| !(-32_768..=32_768).contains(&value)) {
            *coordinate = None;
        }
    }
    for path in [
        &mut settings.last_left_local_path,
        &mut settings.last_right_local_path,
    ] {
        if path.as_deref().is_some_and(|path| !valid_local_path(path)) {
            *path = None;
        }
    }
    let mut favorite_paths = std::collections::HashSet::new();
    settings.local_favorites = settings
        .local_favorites
        .into_iter()
        .take(MAX_LOCAL_FAVORITES)
        .filter_map(|path| {
            let path = path.trim().to_string();
            (valid_local_path(&path) && favorite_paths.insert(path.clone())).then_some(path)
        })
        .collect();
    if settings
        .sync_folder
        .as_deref()
        .is_some_and(|path| !valid_local_path(path))
    {
        settings.sync_folder = None;
    }
    settings.transfer_retry_backoff_ms = settings
        .transfer_retry_backoff_ms
        .clamp(MIN_RETRY_BACKOFF_MS, MAX_RETRY_BACKOFF_MS);
    if settings.transfer_bandwidth_limit_kib != 0 {
        settings.transfer_bandwidth_limit_kib = settings
            .transfer_bandwidth_limit_kib
            .clamp(MIN_BANDWIDTH_LIMIT_KIB, MAX_BANDWIDTH_LIMIT_KIB);
    }
    if !matches!(
        settings.existing_file_policy.as_str(),
        "ask" | "overwrite" | "keep_both" | "skip"
    ) {
        settings.existing_file_policy = default_existing_file_policy();
    }
    if !matches!(
        settings.batch_error_policy.as_str(),
        "ask" | "skip" | "stop"
    ) {
        settings.batch_error_policy = default_batch_error_policy();
    }
    if !matches!(
        settings.queue_recovery_policy.as_str(),
        "ask" | "resume" | "discard"
    ) {
        settings.queue_recovery_policy = default_queue_recovery_policy();
    }
    if settings.sync_comparison == "size" {
        settings.sync_comparison = "size_only".into();
    }
    if !matches!(
        settings.sync_comparison.as_str(),
        "size_mtime" | "size_only" | "checksum"
    ) {
        settings.sync_comparison = default_sync_comparison();
    }
    settings.sync_mtime_tolerance_secs = settings.sync_mtime_tolerance_secs.clamp(0, 86_400);
    if settings.sync_exclusions.len() > MAX_SYNC_PROFILE_EXCLUSIONS_BYTES
        || crate::folder_sync::parse_exclusions(&settings.sync_exclusions).is_err()
    {
        settings.sync_exclusions = default_sync_exclusions();
    }
    let mut profiles = Vec::new();
    let mut names = std::collections::HashSet::new();
    let mut total_bytes = 0usize;
    for mut profile in settings.sync_profiles.into_iter().take(MAX_SYNC_PROFILES) {
        profile.name = profile.name.trim().to_string();
        if profile.comparison == "size" {
            profile.comparison = "size_only".into();
        }
        let local = std::path::Path::new(&profile.local_root);
        let valid_remote = profile.remote_root.starts_with('/')
            && !profile.remote_root.split('/').any(|part| part == "..")
            && !profile.remote_root.chars().any(char::is_control);
        let exclusions = crate::folder_sync::parse_exclusions(&profile.exclusions);
        let valid = !profile.name.is_empty()
            && profile.name.len() <= MAX_SYNC_PROFILE_NAME_BYTES
            && !profile.name.chars().any(char::is_control)
            && profile.connection_id <= i32::MAX as usize
            && profile.endpoint_fingerprint.len() == 64
            && profile
                .endpoint_fingerprint
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            && profile.local_root.len() <= MAX_SYNC_PROFILE_PATH_BYTES
            && local.is_absolute()
            && !profile.local_root.chars().any(char::is_control)
            && profile.remote_root.len() <= MAX_SYNC_PROFILE_PATH_BYTES
            && valid_remote
            && matches!(profile.direction.as_str(), "upload" | "download")
            && matches!(profile.mode.as_str(), "one_way" | "mirror")
            && matches!(
                profile.comparison.as_str(),
                "size_mtime" | "size_only" | "checksum"
            )
            && (0..=86_400).contains(&profile.mtime_tolerance_secs)
            && profile.server_clock_offset_secs.unsigned_abs() <= 86_400
            && profile.exclusions.len() <= MAX_SYNC_PROFILE_EXCLUSIONS_BYTES
            && exclusions.is_ok();
        let canonical_name = profile.name.to_lowercase();
        let profile_bytes = profile
            .name
            .len()
            .saturating_add(profile.endpoint_fingerprint.len())
            .saturating_add(profile.local_root.len())
            .saturating_add(profile.remote_root.len())
            .saturating_add(profile.exclusions.len());
        if !valid
            || names.contains(&canonical_name)
            || total_bytes.saturating_add(profile_bytes) > MAX_SYNC_PROFILE_TOTAL_BYTES
        {
            continue;
        }
        profile.exclusions = exclusions.expect("validated above").join(", ");
        names.insert(canonical_name);
        total_bytes += profile_bytes;
        profiles.push(profile);
    }
    settings.sync_profiles = profiles;
    settings.editor_max_download_mib = settings
        .editor_max_download_mib
        .clamp(MIN_EDITOR_DOWNLOAD_MIB, MAX_EDITOR_DOWNLOAD_MIB);
    let mut mapped_extensions = std::collections::HashSet::new();
    settings.editor_mappings = settings
        .editor_mappings
        .into_iter()
        .take(MAX_EDITOR_MAPPINGS)
        .filter_map(|mut mapping| {
            mapping.extension = normalize_editor_extension(&mapping.extension)?;
            mapping.application = mapping.application.trim().to_string();
            if mapping.application.is_empty()
                || mapping.application.len() > MAX_EDITOR_APPLICATION_BYTES
                || mapping.application.chars().any(char::is_control)
                || !mapped_extensions.insert(mapping.extension.clone())
            {
                return None;
            }
            Some(mapping)
        })
        .collect();
    let mut remote_places = std::collections::HashSet::new();
    settings.remote_places = settings
        .remote_places
        .into_iter()
        .take(MAX_REMOTE_PLACES)
        .filter(|place| {
            place.connection_id <= i32::MAX as usize
                && valid_endpoint_fingerprint(&place.endpoint_fingerprint)
                && valid_remote_path(&place.path)
                && remote_places.insert((place.endpoint_fingerprint.clone(), place.path.clone()))
        })
        .collect();
    if !matches!(
        settings.editor_conflict_action.as_str(),
        "retain_local" | "upload_copy" | "overwrite"
    ) {
        settings.editor_conflict_action = default_editor_conflict_action();
    }
    if settings.editor_temp_retention.is_empty() {
        settings.editor_temp_retention = if settings.editor_retain_on_error {
            "on_error"
        } else {
            "cleanup"
        }
        .into();
    } else if !matches!(
        settings.editor_temp_retention.as_str(),
        "cleanup" | "on_error" | "always"
    ) {
        settings.editor_temp_retention = "on_error".into();
    }
    settings.editor_retain_on_error = settings.editor_temp_retention != "cleanup";
    settings
}

fn valid_local_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= MAX_PERSISTED_PATH_BYTES
        && !path.chars().any(char::is_control)
        && std::path::Path::new(path).is_absolute()
}

fn valid_endpoint_fingerprint(fingerprint: &str) -> bool {
    fingerprint.len() == 64
        && fingerprint
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn valid_remote_path(path: &str) -> bool {
    !path.is_empty()
        && path.len() <= MAX_SYNC_PROFILE_PATH_BYTES
        && path.starts_with('/')
        && !path.chars().any(char::is_control)
        && !path.contains('\\')
        && !path.split('/').any(|component| component == "..")
}

fn normalize_editor_extension(raw: &str) -> Option<String> {
    let extension = raw
        .trim()
        .trim_start_matches('*')
        .trim_start_matches('.')
        .to_ascii_lowercase();
    (!extension.is_empty()
        && extension.len() <= MAX_EDITOR_EXTENSION_BYTES
        && extension
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'_' | b'.'))
        && !extension.starts_with('.')
        && !extension.ends_with('.'))
    .then_some(extension)
}

/// Parse the compact Settings representation: `rs=Visual Studio Code; txt=TextEdit`.
pub fn parse_editor_mappings(input: &str) -> Result<Vec<EditorMapping>, String> {
    if input.len() > MAX_EDITOR_MAPPING_INPUT_BYTES {
        return Err(format!(
            "editor mappings exceed {MAX_EDITOR_MAPPING_INPUT_BYTES} bytes"
        ));
    }
    let mut mappings = Vec::new();
    let mut extensions = std::collections::HashSet::new();
    for raw in input.split([';', '\n', '\r']) {
        let raw = raw.trim();
        if raw.is_empty() {
            continue;
        }
        let (extension, application) = raw
            .split_once('=')
            .ok_or_else(|| format!("invalid editor mapping {raw:?}; use extension=Application"))?;
        let extension = normalize_editor_extension(extension)
            .ok_or_else(|| format!("invalid editor extension: {extension:?}"))?;
        let application = application.trim();
        if application.is_empty()
            || application.len() > MAX_EDITOR_APPLICATION_BYTES
            || application.chars().any(char::is_control)
        {
            return Err(format!("invalid editor application for .{extension}"));
        }
        if !extensions.insert(extension.clone()) {
            return Err(format!("duplicate editor mapping for .{extension}"));
        }
        mappings.push(EditorMapping {
            extension,
            application: application.to_string(),
        });
        if mappings.len() > MAX_EDITOR_MAPPINGS {
            return Err(format!(
                "at most {MAX_EDITOR_MAPPINGS} editor mappings are allowed"
            ));
        }
    }
    Ok(mappings)
}

pub fn format_editor_mappings(mappings: &[EditorMapping]) -> String {
    mappings
        .iter()
        .map(|mapping| format!("{}={}", mapping.extension, mapping.application))
        .collect::<Vec<_>>()
        .join("; ")
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
    let settings = validate(s.clone());
    let json = serde_json::to_string_pretty(&settings)
        .map_err(|e| std::io::Error::other(format!("settings serialization failed: {e}")))?;
    if json.len() > MAX_SETTINGS_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "settings exceed their safe size limit",
        ));
    }
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
        assert_eq!(settings.transfer_concurrency, DEFAULT_TRANSFER_CONCURRENCY);
        assert_eq!(
            settings.per_server_transfer_concurrency,
            DEFAULT_SERVER_TRANSFER_CONCURRENCY
        );
        assert!(!settings.background_folder_metadata);
        assert!(!settings.show_advanced_columns);
        assert!(settings.confirm_deletes);
        assert!(settings.remote_quarantine_deletes);
        assert!(settings.restore_workspace);
        assert!(!settings.open_connection_manager_on_launch);
        assert!(!settings.check_updates_automatically);
        assert_eq!(settings.window_width_px, 1_180);
        assert_eq!(settings.window_height_px, 740);
        assert_eq!(settings.transfer_retry_count, 3);
        assert_eq!(settings.transfer_bandwidth_limit_kib, 0);
        assert_eq!(settings.existing_file_policy, "ask");
        assert_eq!(settings.batch_error_policy, "ask");
        assert_eq!(settings.queue_recovery_policy, "ask");
        assert!(!settings.notify_transfer_completion);
        assert!(!settings.notify_transfer_failure);
        assert!(!settings.preserve_transfer_timestamps);
        assert!(!settings.preserve_transfer_permissions);
        assert_eq!(settings.editor_max_download_mib, 64);
        assert!(settings.sync_profiles.is_empty());
    }

    #[test]
    fn persisted_resource_controls_are_normalized_to_safe_bounds() {
        let settings = Settings {
            transfer_concurrency: usize::MAX,
            per_server_transfer_concurrency: usize::MAX,
            transfer_retry_count: usize::MAX,
            transfer_retry_backoff_ms: u64::MAX,
            transfer_bandwidth_limit_kib: u64::MAX,
            existing_file_policy: "unsafe".into(),
            batch_error_policy: "loop".into(),
            queue_recovery_policy: "silently_delete".into(),
            sync_comparison: "unknown".into(),
            sync_mtime_tolerance_secs: i64::MAX,
            sync_exclusions: "x".repeat(20_000),
            editor_max_download_mib: usize::MAX,
            window_width_px: u32::MAX,
            window_height_px: u32::MAX,
            window_x_px: Some(i32::MAX),
            window_y_px: Some(i32::MIN),
            last_left_local_path: Some("relative/path".into()),
            local_favorites: vec![
                "/Users/example/Documents".into(),
                "/Users/example/Documents".into(),
                "relative/favorite".into(),
                "bad\npath".into(),
            ],
            sync_folder: Some("relative/sync".into()),
            ..Settings::default()
        };

        let settings = validate(settings);
        assert_eq!(settings.transfer_concurrency, MAX_TRANSFER_CONCURRENCY);
        assert_eq!(
            settings.per_server_transfer_concurrency,
            MAX_SERVER_TRANSFER_CONCURRENCY
        );
        assert_eq!(settings.transfer_retry_count, MAX_TRANSFER_RETRIES);
        assert_eq!(settings.transfer_retry_backoff_ms, MAX_RETRY_BACKOFF_MS);
        assert_eq!(
            settings.transfer_bandwidth_limit_kib,
            MAX_BANDWIDTH_LIMIT_KIB
        );
        assert_eq!(settings.existing_file_policy, "ask");
        assert_eq!(settings.batch_error_policy, "ask");
        assert_eq!(settings.queue_recovery_policy, "ask");
        assert_eq!(settings.sync_comparison, "size_mtime");
        assert_eq!(settings.sync_mtime_tolerance_secs, 86_400);
        assert_eq!(settings.sync_exclusions, default_sync_exclusions());
        assert_eq!(settings.editor_max_download_mib, MAX_EDITOR_DOWNLOAD_MIB);
        assert_eq!(settings.window_width_px, MAX_WINDOW_WIDTH_PX);
        assert_eq!(settings.window_height_px, MAX_WINDOW_HEIGHT_PX);
        assert_eq!(settings.window_x_px, None);
        assert_eq!(settings.window_y_px, None);
        assert_eq!(settings.last_left_local_path, None);
        assert_eq!(settings.local_favorites, ["/Users/example/Documents"]);
        assert_eq!(settings.sync_folder, None);
    }

    #[test]
    fn persisted_path_collections_are_bounded_and_deduplicated() {
        let mut favorites = (0..MAX_LOCAL_FAVORITES + 20)
            .map(|index| format!("/Volumes/Test/{index}"))
            .collect::<Vec<_>>();
        favorites.push(format!("/{}", "x".repeat(MAX_PERSISTED_PATH_BYTES)));
        let settings = validate(Settings {
            local_favorites: favorites,
            sync_folder: Some("/Volumes/Team Sync".into()),
            ..Settings::default()
        });
        assert_eq!(settings.local_favorites.len(), MAX_LOCAL_FAVORITES);
        assert_eq!(settings.sync_folder.as_deref(), Some("/Volumes/Team Sync"));
        assert!(settings
            .local_favorites
            .iter()
            .all(|path| path.len() <= MAX_PERSISTED_PATH_BYTES));
    }

    #[test]
    fn sync_profiles_migrate_legacy_comparison_and_drop_unsafe_entries() {
        let settings = Settings {
            sync_profiles: vec![
                SyncProfile {
                    name: " Website ".into(),
                    // Imported seed files historically assign zero to their first connection.
                    connection_id: 0,
                    endpoint_fingerprint: "a".repeat(64),
                    local_root: "/Users/example/Site".into(),
                    remote_root: "/public_html".into(),
                    direction: "upload".into(),
                    mode: "mirror".into(),
                    comparison: "size".into(),
                    mtime_tolerance_secs: 2,
                    server_clock_offset_secs: 0,
                    exclusions: ".git, *.tmp".into(),
                },
                SyncProfile {
                    name: "website".into(),
                    connection_id: 8,
                    endpoint_fingerprint: "b".repeat(64),
                    local_root: "/tmp/duplicate".into(),
                    remote_root: "/duplicate".into(),
                    direction: "download".into(),
                    mode: "one_way".into(),
                    comparison: "checksum".into(),
                    mtime_tolerance_secs: 0,
                    server_clock_offset_secs: 0,
                    exclusions: String::new(),
                },
                SyncProfile {
                    name: "unsafe".into(),
                    connection_id: 9,
                    endpoint_fingerprint: "c".repeat(64),
                    local_root: "relative".into(),
                    remote_root: "/../../etc".into(),
                    direction: "upload".into(),
                    mode: "mirror".into(),
                    comparison: "checksum".into(),
                    mtime_tolerance_secs: 0,
                    server_clock_offset_secs: 0,
                    exclusions: String::new(),
                },
            ],
            ..Settings::default()
        };

        let settings = validate(settings);
        assert_eq!(settings.sync_profiles.len(), 1);
        assert_eq!(settings.sync_profiles[0].name, "Website");
        assert_eq!(settings.sync_profiles[0].comparison, "size_only");
        assert_eq!(settings.sync_profiles[0].exclusions, ".git, *.tmp");
    }

    #[test]
    fn remote_places_are_endpoint_bound_deduplicated_and_safely_bounded() {
        let valid = RemotePlace {
            connection_id: 0,
            endpoint_fingerprint: "a".repeat(64),
            path: "/srv/www".into(),
        };
        let settings = validate(Settings {
            remote_places: vec![
                valid.clone(),
                valid,
                RemotePlace {
                    connection_id: 1,
                    endpoint_fingerprint: "B".repeat(64),
                    path: "/uppercase-fingerprint".into(),
                },
                RemotePlace {
                    connection_id: 2,
                    endpoint_fingerprint: "c".repeat(64),
                    path: "/srv/../private".into(),
                },
                RemotePlace {
                    connection_id: 3,
                    endpoint_fingerprint: "d".repeat(64),
                    path: "relative".into(),
                },
            ],
            ..Settings::default()
        });
        assert_eq!(settings.remote_places.len(), 1);
        assert_eq!(settings.remote_places[0].connection_id, 0);
        assert_eq!(settings.remote_places[0].path, "/srv/www");
    }

    #[test]
    fn editor_mappings_and_legacy_retention_are_strictly_normalized() {
        let mappings =
            parse_editor_mappings("*.RS=Visual Studio Code; toml=TextEdit; tar.gz=Archive Utility")
                .unwrap();
        assert_eq!(mappings[0].extension, "rs");
        assert_eq!(
            format_editor_mappings(&mappings),
            "rs=Visual Studio Code; toml=TextEdit; tar.gz=Archive Utility"
        );
        assert!(parse_editor_mappings("rs=Code; RS=Other").is_err());
        assert!(parse_editor_mappings("../rs=Code").is_err());
        assert!(parse_editor_mappings("rs=Bad\nApplication").is_err());

        let migrated = validate(Settings {
            editor_retain_on_error: false,
            editor_temp_retention: String::new(),
            ..Settings::default()
        });
        assert_eq!(migrated.editor_temp_retention, "cleanup");
        assert!(!migrated.editor_retain_on_error);

        let invalid = validate(Settings {
            editor_conflict_action: "silently_replace_everything".into(),
            editor_temp_retention: "forever_and_ever".into(),
            ..Settings::default()
        });
        assert_eq!(invalid.editor_conflict_action, "retain_local");
        assert_eq!(invalid.editor_temp_retention, "on_error");
    }
}
