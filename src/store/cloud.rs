//! Cross-device sync via a plain synced folder (iCloud Drive / Dropbox / etc.).
//!
//! The connection LIST (`connections.json`, password-free) and the encrypted VAULT
//! (`vault.bin`, AES-256-GCM ciphertext) are mirrored as **ordinary files** in a folder the
//! OS already syncs — by default the user's iCloud Drive
//! (`~/Library/Mobile Documents/com~apple~CloudDocs/gmacFTP/`). iCloud Drive is just a folder
//! on disk; a non-sandboxed Developer-ID app writes to it with normal file I/O and macOS
//! uploads it like any user file. **No iCloud/CloudKit API, no `NSUbiquitousKeyValueStore`,
//! no App-Store-only entitlement** — this deliberately bypasses the gates that silently
//! blocked the earlier CloudKit/KV-store attempts (which Apple's docs restrict to App-Store
//! distribution). The folder is user-configurable (`Settings.sync_folder`), so Dropbox /
//! Google Drive / Syncthing / any synced folder works too.
//!
//! Security model: the folder is not a secret store, and it doesn't hold one.
//! `connections.json` has no passwords (they live only in `vault.bin`), and `vault.bin` is
//! opaque ciphertext. The one secret, the 32-byte vault master key, stays in the macOS
//! **Keychain** (synchronizable via iCloud Keychain) so the synced vault decrypts on the
//! other Mac. *Encrypt locally, sync the ciphertext, keep the key in the Keychain.*
//!
//! Conflict policy is last-writer-wins by file mtime (iCloud Drive / Dropbox preserve
//! mtimes across devices, so the newest write wins everywhere). Local files in the config
//! dir remain the source of truth; the synced files are copies named `gmacftp.connections.json`
//! / `gmacftp.vault.bin`.

use std::path::{Path, PathBuf};

const MAX_CONNECTIONS_BYTES: usize = 1_048_576;
const MAX_VAULT_BYTES: usize = 1_048_576;
const MAX_WRAPPED_KEY_BYTES: usize = 128;

fn max_len(kind: &str) -> Option<usize> {
    match kind {
        "connections" => Some(MAX_CONNECTIONS_BYTES),
        "vault" => Some(MAX_VAULT_BYTES),
        "key" => Some(MAX_WRAPPED_KEY_BYTES),
        _ => None,
    }
}

fn valid_payload(kind: &str, payload: &[u8]) -> bool {
    match kind {
        "connections" => crate::store::connections::validate_metadata_bytes(payload).is_ok(),
        // The encrypted vault's AES-GCM tag is validated by FileVault before it is ever used;
        // here we enforce only an unambiguous minimum/maximum before writing foreign sync data.
        "vault" => (12 + 16..=MAX_VAULT_BYTES).contains(&payload.len()),
        "key" => crate::store::vault::valid_wrapped_key_len(payload),
        _ => false,
    }
}

/// Validate a sync payload and return its safe canonical representation. Connection transport
/// exceptions are deliberately stripped: plaintext FTP and invalid-certificate approval must be
/// made locally on every Mac and can never be enabled by editing the sync folder.
fn normalize_payload(kind: &str, payload: &[u8]) -> Option<Vec<u8>> {
    if max_len(kind).is_none_or(|limit| payload.len() > limit) {
        return None;
    }
    if kind == "connections" {
        crate::store::connections::normalize_sync_metadata_bytes(payload).ok()
    } else {
        valid_payload(kind, payload).then(|| payload.to_vec())
    }
}

fn read_regular_limited(path: &Path, max_len: usize) -> std::io::Result<Vec<u8>> {
    use std::io::Read;

    let before = std::fs::symlink_metadata(path)?;
    if !before.file_type().is_file()
        || before.file_type().is_symlink()
        || before.len() > max_len as u64
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "sync item is not a bounded regular file",
        ));
    }
    let file = std::fs::File::open(path)?;
    let after = file.metadata()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if before.dev() != after.dev() || before.ino() != after.ino() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "sync item changed while opening",
            ));
        }
    }
    if !after.file_type().is_file() || after.len() > max_len as u64 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "sync item changed type or size",
        ));
    }
    let mut bytes = Vec::with_capacity(after.len() as usize);
    file.take((max_len as u64).saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() > max_len {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "sync item exceeds size limit",
        ));
    }
    Ok(bytes)
}

/// Is iCloud sync enabled in Settings? (Centralized so every call site reads the same flag.)
pub fn enabled() -> bool {
    crate::store::settings::load().sync_via_icloud
}

/// Config dir (same resolution as connections.rs / vault.rs).
fn config_dir() -> Option<PathBuf> {
    directories::ProjectDirs::from(
        env!("MACKFTP_CONFIG_QUALIFIER"),
        env!("MACKFTP_CONFIG_ORGANIZATION"),
        env!("MACKFTP_CONFIG_APPLICATION"),
    )
    .map(|pd| pd.config_dir().to_path_buf())
}

pub fn connections_path() -> Option<PathBuf> {
    config_dir().map(|d| d.join("connections.json"))
}
pub fn vault_path() -> Option<PathBuf> {
    config_dir().map(|d| d.join("vault.bin"))
}

// ── Sync backing: plain files in a synced folder (iCloud Drive / Dropbox / …) ──
// No iCloud/CloudKit API is used: iCloud Drive is just a folder on disk, and a non-sandboxed
// Developer-ID app writes to it with normal file I/O. macOS (or Dropbox, etc.) syncs the
// folder. This deliberately avoids the App-Store-only `NSUbiquitousKeyValueStore`/CloudKit
// gate that silently blocked earlier attempts.

#[cfg(target_os = "macos")]
mod imp {
    use std::path::PathBuf;

    /// The user's iCloud Drive root (`~/Library/Mobile Documents/com~apple~CloudDocs`) when
    /// present. Files written here are synced by macOS like any user file.
    fn icloud_drive_root() -> Option<PathBuf> {
        let home = std::env::var_os("HOME")?;
        let p = PathBuf::from(home).join("Library/Mobile Documents/com~apple~CloudDocs");
        p.is_dir().then_some(p)
    }

    /// The active sync folder: the user's chosen folder (`Settings.sync_folder`) if it still
    /// exists, else the default iCloud Drive `gmacFTP/` subfolder when iCloud Drive is set up.
    pub fn sync_dir() -> Option<PathBuf> {
        if let Some(s) = crate::store::settings::load().sync_folder {
            let p = PathBuf::from(&s);
            if p.is_dir() {
                return Some(p);
            }
            tracing::warn!(target: "gmacftp::cloud", folder = %s, "configured sync_folder missing; falling back to iCloud Drive");
        }
        icloud_drive_root().map(|r| r.join("gmacFTP"))
    }

    fn filename(kind: &str) -> &'static str {
        match kind {
            "connections" => "gmacftp.connections.json",
            "vault" => "gmacftp.vault.bin",
            "key" => "gmacftp.key.wrap",
            _ => "gmacftp.unknown",
        }
    }

    fn path_for(kind: &str) -> Option<PathBuf> {
        sync_dir().map(|d| d.join(filename(kind)))
    }

    pub fn write_item(kind: &str, payload: &[u8]) -> Result<(), String> {
        let p =
            path_for(kind).ok_or_else(|| "no sync folder (iCloud Drive not set up)".to_string())?;
        // Reuse vault's hardened atomic_write (O_EXCL + 0600 + fsync + symlink-safe rename) so
        // synced ciphertext gets the same CRYP-3 protection as the local config dir.
        crate::store::vault::atomic_write(&p, payload).map_err(|e| e.to_string())
    }

    /// `(file mtime as unix secs, file bytes)`. mtime drives last-writer-wins.
    pub fn read_item(kind: &str) -> Option<(u64, Vec<u8>)> {
        let p = path_for(kind)?;
        let meta = std::fs::symlink_metadata(&p).ok()?;
        if !meta.file_type().is_file() || meta.file_type().is_symlink() {
            return None;
        }
        let mtime = meta
            .modified()
            .ok()?
            .duration_since(std::time::UNIX_EPOCH)
            .ok()?
            .as_secs();
        let bytes = super::read_regular_limited(&p, super::max_len(kind)?).ok()?;
        let Some(bytes) = super::normalize_payload(kind, &bytes) else {
            tracing::warn!(target: "gmacftp::cloud", kind, "rejected malformed sync item");
            return None;
        };
        Some((mtime, bytes))
    }

    pub fn delete_item(kind: &str) -> Result<(), String> {
        let Some(p) = path_for(kind) else {
            return Ok(());
        };
        match std::fs::remove_file(p) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.to_string()),
        }
    }
}

#[cfg(not(target_os = "macos"))]
mod imp {
    use std::path::PathBuf;
    pub fn sync_dir() -> Option<PathBuf> {
        None
    }
    pub fn write_item(_: &str, _: &[u8]) -> Result<(), String> {
        Ok(())
    }
    pub fn read_item(_: &str) -> Option<(u64, Vec<u8>)> {
        None
    }
    pub fn delete_item(_: &str) -> Result<(), String> {
        Ok(())
    }
}

/// Push a single blob to iCloud. No-op if sync disabled.
pub fn push(kind: &str, payload: &[u8]) {
    if !enabled() {
        return;
    }
    let Some(payload) = normalize_payload(kind, payload) else {
        tracing::warn!(target: "gmacftp::cloud", kind, "refusing to push malformed or oversized sync item");
        return;
    };
    if kind == "vault" && !crate::store::vault::validate_synced_vault(&payload) {
        tracing::warn!(target: "gmacftp::cloud", "refusing to push a vault that cannot be authenticated with the local master key");
        return;
    }
    if let Err(e) = imp::write_item(kind, &payload) {
        tracing::warn!(target: "gmacftp::cloud", kind, error = %e, "iCloud push failed");
    }
}

/// Push BOTH connections.json and vault.bin from disk. Used after a change when the caller
/// doesn't have the bytes handy. No-op if sync disabled.
pub fn push_state() {
    if !enabled() {
        return;
    }
    if let Some(p) = connections_path() {
        if let Ok(bytes) = read_regular_limited(&p, MAX_CONNECTIONS_BYTES) {
            push("connections", &bytes);
        }
    }
    if let Some(p) = vault_path() {
        if let Ok(bytes) = read_regular_limited(&p, MAX_VAULT_BYTES) {
            push("vault", &bytes);
        }
    }
}

/// Push the wrapped master key (`gmacftp.key.wrap`) to the sync folder. No-op if sync off.
pub fn push_key(wrapped: &[u8]) -> Result<(), String> {
    replace_key(wrapped).map(|_| ())
}

/// Replace the synced wrapped key and return its previous validated value for rollback. When
/// sync is disabled no remote mutation occurs.
pub(crate) fn replace_key(wrapped: &[u8]) -> Result<Option<Vec<u8>>, String> {
    if !enabled() {
        return Ok(None);
    }
    let Some(wrapped) = normalize_payload("key", wrapped) else {
        return Err("refusing malformed wrapped master key".to_string());
    };
    let previous = imp::read_item("key").map(|(_, bytes)| bytes);
    imp::write_item("key", &wrapped).map_err(|e| format!("wrapped-key push failed: {e}"))?;
    Ok(previous)
}

pub(crate) fn restore_key(previous: Option<&[u8]>) -> Result<(), String> {
    if !enabled() {
        return Ok(());
    }
    match previous {
        Some(bytes) => imp::write_item("key", bytes),
        None => imp::delete_item("key"),
    }
}

/// Read the wrapped master key from the sync folder (mtime + bytes), or None.
pub fn read_key() -> Option<(u64, Vec<u8>)> {
    imp::read_item("key")
}

/// Read the synced vault bytes from the sync folder (used by vault::unlock to ADOPT the other
/// Mac's vault — the local vault.bin may be this Mac's own, undecryptable with the synced key).
pub fn read_vault() -> Option<(u64, Vec<u8>)> {
    imp::read_item("vault")
}

/// Remove the synced items (used when the user turns sync OFF, to stop sharing). All failures are
/// reported because leaving a wrapped key or vault behind is security-relevant to the user.
pub fn purge() -> Result<(), String> {
    let mut errors = Vec::new();
    for kind in ["connections", "vault", "key"] {
        if let Err(error) = imp::delete_item(kind) {
            tracing::warn!(target: "gmacftp::cloud", kind, %error, "could not remove synced item");
            errors.push(format!("{kind}: {error}"));
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}

/// Toggle iCloud sync on/off (the menu action calls this). Persists the setting, moves the
/// master key between the device-local and iCloud-syncing Keychain stores, then seeds iCloud
/// (enable) or stops sharing (disable). Idempotent.
pub fn set_sync_enabled(enabled: bool) -> Result<(), String> {
    let mut s = crate::store::settings::load();
    if s.sync_via_icloud == enabled {
        return Ok(());
    }
    // Move the master key so the synced vault stays decryptable on the other Mac (enable) or
    // stops syncing (disable). The master key and cached passphrase live in the Keychain, never
    // in plaintext in the synced folder.
    crate::store::vault::set_master_key_syncable(enabled)?;
    if let Err(error) = crate::store::vault::set_sync_passphrase_syncable(enabled) {
        let master_rollback = crate::store::vault::set_master_key_syncable(!enabled);
        return Err(format!(
            "passphrase Keychain move failed: {error}; master-key rollback: {master_rollback:?}"
        ));
    }
    s.sync_via_icloud = enabled;
    if let Err(error) = crate::store::settings::try_save(&s) {
        let passphrase_rollback = crate::store::vault::set_sync_passphrase_syncable(!enabled);
        let master_rollback = crate::store::vault::set_master_key_syncable(!enabled);
        return Err(format!(
            "settings save failed after Keychain move: {error}; passphrase rollback: {passphrase_rollback:?}; master-key rollback: {master_rollback:?}"
        ));
    }
    if enabled {
        // Re-push the wrapped key too — a prior off→on toggle purged it, and push_state only
        // covers connections/vault. No-op if no passphrase is set yet (the SET dialog handles
        // the first-time case).
        if crate::store::settings::load().sync_passphrase_set {
            if let Err(error) = crate::store::vault::repush_sync_key() {
                let settings_rollback = crate::store::settings::try_save(&{
                    let mut previous = crate::store::settings::load();
                    previous.sync_via_icloud = false;
                    previous
                });
                let passphrase_rollback = crate::store::vault::set_sync_passphrase_syncable(false);
                let key_rollback = crate::store::vault::set_master_key_syncable(false);
                return Err(format!(
                    "could not publish wrapped key: {error}; settings rollback: {settings_rollback:?}; passphrase rollback: {passphrase_rollback:?}; master-key rollback: {key_rollback:?}"
                ));
            }
        }
        push_state();
    } else {
        purge().map_err(|error| {
            format!("sync disabled locally, but some remote files could not be removed: {error}")
        })?;
    }
    tracing::info!(target: "gmacftp::cloud", enabled, "iCloud sync toggled");
    Ok(())
}

/// Pull: for each of connections/vault, if the iCloud item is newer than the local file's
/// mtime (or the local file is absent), overwrite the local file. Returns whether anything
/// was applied (so bootstrap knows to (re)load). No-op if sync disabled.
pub fn pull_and_apply() -> bool {
    if !enabled() {
        return false;
    }
    let mut applied = false;
    for (kind, local) in [("connections", connections_path()), ("vault", vault_path())] {
        let Some((ts, payload)) = imp::read_item(kind) else {
            continue;
        };
        if payload.is_empty() || !valid_payload(kind, &payload) {
            continue;
        }
        let local_secs = local
            .as_ref()
            .and_then(|p| std::fs::metadata(p).ok())
            .and_then(|m| m.modified().ok())
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0);
        // iCloud wins on a tie too (it was written by some device; a local file with equal
        // mtime is the just-pushed one and re-writing it is a harmless no-op). No mtime
        // restoration needed: pull sets local mtime=now ≥ iCloud ts. A timestamp tie may cause
        // another harmless atomic rewrite, but never a push/pull feedback loop.
        if ts >= local_secs && ts > 0 {
            if let Some(p) = &local {
                // Never replace an existing local vault with ciphertext whose AES-GCM tag and
                // JSON plaintext cannot be verified using the already-available key. On a new
                // Mac (no local vault yet), the bounded blob may be staged for the explicit
                // passphrase unlock path, which authenticates it before use.
                if kind == "vault"
                    && p.exists()
                    && !crate::store::vault::validate_synced_vault(&payload)
                {
                    tracing::warn!(target: "gmacftp::cloud", "rejected unauthenticated synced vault; local vault preserved");
                    continue;
                }
                if let Some(parent) = p.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                // Validation happens before every overwrite. The metadata remains plaintext for
                // compatibility, but v2 credential binding prevents it from redirecting an
                // endpoint password to a different protocol/host/port/account.
                match crate::store::vault::atomic_write(p, &payload) {
                    Ok(()) => {
                        tracing::info!(target: "gmacftp::cloud", kind, "pulled newer state from iCloud");
                        applied = true;
                    }
                    Err(error) => {
                        tracing::warn!(target: "gmacftp::cloud", kind, error = %error, "could not apply validated sync item")
                    }
                }
            }
        }
    }
    applied
}

/// Run once at startup (after settings load, before the local files are read): pull the
/// newest state from iCloud into the local files, then — if iCloud is still empty but this
/// Mac has a connections.json — seed iCloud from the local files so existing servers reach
/// the user's other Macs. Never deletes local files. No-op if sync disabled.
pub fn bootstrap() {
    if !enabled() {
        return;
    }
    pull_and_apply();
    seed_if_empty();
    // Auto-heal: a passphrase was set but the wrapped key is missing from the sync folder
    // (e.g. purged by a sync off→on toggle, which only re-pushes connections/vault) →
    // re-create it from the cached passphrase. If the passphrase isn't cached either, clear
    // the flag so the SET dialog shows again on this Mac.
    if crate::store::settings::load().sync_passphrase_set && read_key().is_none() {
        if let Err(repush_error) = crate::store::vault::repush_sync_key() {
            let mut s = crate::store::settings::load();
            s.sync_passphrase_set = false;
            match crate::store::settings::try_save(&s) {
                Ok(()) => {
                    tracing::warn!(target: "gmacftp::cloud", %repush_error, "sync passphrase unavailable — will prompt to set one")
                }
                Err(settings_error) => {
                    tracing::error!(target: "gmacftp::cloud", %repush_error, %settings_error, "sync passphrase unavailable and prompt state could not be persisted")
                }
            }
        }
    }
}

/// Migration / first-run: if iCloud has no `connections` entry yet but a local
/// connections.json exists, push it (and the vault) up. Idempotent — no-op once iCloud is
/// populated. Guarantees a Mac that already has servers publishes them on first launch.
fn seed_if_empty() {
    if imp::read_item("connections").is_some() {
        return;
    }
    let mut connections_pushed = false;
    if let Some(p) = connections_path() {
        if let Ok(bytes) = read_regular_limited(&p, MAX_CONNECTIONS_BYTES) {
            if let Some(safe) = normalize_payload("connections", &bytes) {
                match imp::write_item("connections", &safe) {
                    Ok(()) => connections_pushed = true,
                    Err(error) => {
                        tracing::warn!(target: "gmacftp::cloud", %error, "could not seed connection metadata")
                    }
                }
            }
        }
    }
    if let Some(p) = vault_path() {
        if let Ok(bytes) = read_regular_limited(&p, MAX_VAULT_BYTES) {
            if let Some(safe) = normalize_payload("vault", &bytes)
                .filter(|payload| crate::store::vault::validate_synced_vault(payload))
            {
                if let Err(error) = imp::write_item("vault", &safe) {
                    tracing::warn!(target: "gmacftp::cloud", %error, "could not seed encrypted vault");
                }
            }
        }
    }
    if connections_pushed {
        tracing::info!(target: "gmacftp::cloud", "seeded sync folder (iCloud Drive) from local files (migration)");
    }
}

// ── visibility helpers for the iCloud-sync menu (Send / Pull / last-sync time) ──

/// Compact local date-time "Jun 30 11:06" for a unix timestamp (system local timezone).
pub fn fmt_ts(secs: u64) -> String {
    if secs == 0 {
        return "(unknown)".into();
    }
    #[cfg(target_os = "macos")]
    {
        if let Some((mo, d, h, m)) = local_md_hm(secs as i64) {
            const NAMES: [&str; 12] = [
                "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
            ];
            let name = NAMES
                .get((mo - 1).clamp(0, 11) as usize)
                .copied()
                .unwrap_or("???");
            return format!("{name} {d:02} {h:02}:{m:02}");
        }
    }
    let _ = secs;
    format!("(t={secs})")
}

#[cfg(target_os = "macos")]
fn local_md_hm(secs: i64) -> Option<(i32, i32, i32, i32)> {
    #[repr(C)]
    struct Tm {
        tm_sec: i32,
        tm_min: i32,
        tm_hour: i32,
        tm_mday: i32,
        tm_mon: i32,
        tm_year: i32,
        tm_wday: i32,
        tm_yday: i32,
        tm_isdst: i32,
        tm_gmtoff: i64,
        tm_zone: *const std::os::raw::c_char,
    }
    extern "C" {
        fn localtime_r(timep: *const i64, result: *mut Tm) -> *mut Tm;
    }
    let mut tm = Tm {
        tm_sec: 0,
        tm_min: 0,
        tm_hour: 0,
        tm_mday: 1,
        tm_mon: 0,
        tm_year: 0,
        tm_wday: 0,
        tm_yday: 0,
        tm_isdst: 0,
        tm_gmtoff: 0,
        tm_zone: std::ptr::null(),
    };
    let t = secs;
    let ok = unsafe { !localtime_r(&t as *const i64, &mut tm as *mut Tm).is_null() };
    ok.then(|| (tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min))
}

/// The timestamp (unix secs) of the `connections` item currently in iCloud, or None if absent.
/// Shown in the menu so the user can see WHEN the cloud copy was last written (and whether one
/// exists at all on this Mac).
pub fn remote_connections_ts() -> Option<u64> {
    imp::read_item("connections")
        .map(|(ts, _)| ts)
        .filter(|ts| *ts > 0)
}

/// Explicitly push the current connections + vault to the sync folder (the "Send" action).
/// Returns a human-readable diagnostic naming the folder (so the user can verify the files
/// physically) + whether each write + read-back succeeded.
pub fn send_now() -> String {
    if !enabled() {
        return "Sync is OFF — turn it on first.".into();
    }
    let Some(dir) = imp::sync_dir() else {
        return "No sync folder available — turn on iCloud Drive (System Settings → Apple ID → \
                iCloud → iCloud Drive), or choose a synced folder."
            .into();
    };
    let where_ = dir.display().to_string();
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut errors: Vec<String> = Vec::new();
    let conn_wrote = write_kind("connections", connections_path(), &mut errors);
    let vault_wrote = write_kind("vault", vault_path(), &mut errors);
    let readable = imp::read_item("connections").is_some();
    if conn_wrote && vault_wrote && readable {
        format!(
            "Written to {} ({}) — connections + vault. iCloud Drive (or your folder) syncs them \
             to your other Macs; open the menu there → Pull Servers.",
            where_,
            fmt_ts(ts)
        )
    } else if conn_wrote && vault_wrote {
        format!(
            "Written to {} ({}) — connections + vault.",
            where_,
            fmt_ts(ts)
        )
    } else {
        format!(
            "Send ({}) failed: {}",
            fmt_ts(ts),
            if errors.is_empty() {
                "no local data".into()
            } else {
                errors.join("; ")
            }
        )
    }
}

/// Write one local file's bytes to the iCloud item `kind`. Pushes to `errors` on failure.
fn write_kind(kind: &str, path: Option<PathBuf>, errors: &mut Vec<String>) -> bool {
    let bytes = path.and_then(|p| read_regular_limited(&p, max_len(kind)?).ok());
    match bytes {
        Some(bytes) => match normalize_payload(kind, &bytes)
            .filter(|payload| {
                kind != "vault" || crate::store::vault::validate_synced_vault(payload)
            })
            .ok_or_else(|| "invalid local payload".to_string())
            .and_then(|safe| imp::write_item(kind, &safe))
        {
            Ok(()) => true,
            Err(e) => {
                errors.push(format!("{kind} write: {e}"));
                false
            }
        },
        _ => {
            errors.push(format!("{kind}: no valid local file"));
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fmt_ts_zero_is_unknown() {
        assert_eq!(fmt_ts(0), "(unknown)");
    }

    #[test]
    fn sync_payload_limits_are_enforced_before_copying() {
        assert!(normalize_payload("unknown", b"anything").is_none());
        assert!(normalize_payload("vault", &[0u8; 27]).is_none());
        assert_eq!(normalize_payload("vault", &[0u8; 28]).unwrap().len(), 28);
        assert!(normalize_payload("vault", &vec![0u8; MAX_VAULT_BYTES + 1]).is_none());
        assert!(normalize_payload("key", &[0u8; MAX_WRAPPED_KEY_BYTES + 1]).is_none());
    }

    #[test]
    fn bounded_reader_rejects_a_file_over_the_limit() {
        use rand::RngCore;
        let path = std::env::temp_dir().join(format!(
            "gmacftp_cloud_limit_{}_{}",
            std::process::id(),
            rand::rngs::OsRng.next_u64()
        ));
        std::fs::write(&path, vec![7u8; 65]).unwrap();
        assert!(read_regular_limited(&path, 64).is_err());
        assert_eq!(read_regular_limited(&path, 65).unwrap().len(), 65);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(unix)]
    #[test]
    fn bounded_reader_never_follows_a_sync_symlink() {
        use rand::RngCore;
        use std::os::unix::fs::symlink;
        let nonce = rand::rngs::OsRng.next_u64();
        let target = std::env::temp_dir().join(format!("gmacftp_cloud_target_{nonce}"));
        let link = std::env::temp_dir().join(format!("gmacftp_cloud_link_{nonce}"));
        std::fs::write(&target, b"foreign-data").unwrap();
        symlink(&target, &link).unwrap();
        assert!(read_regular_limited(&link, 1024).is_err());
        let _ = std::fs::remove_file(link);
        let _ = std::fs::remove_file(target);
    }
}
