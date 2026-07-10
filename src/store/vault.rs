//! Private encrypted credential vault. FTP/SFTP passwords live in an AES-256-GCM
//! encrypted file under the app's config dir — NOT in the macOS Keychain — so the
//! "gmacFTP wants to use confidential data in your keychain" prompt never appears.
//!
//! ## Master key storage (CRYP-1, fixed)
//! The 32-byte AES key is stored in the **macOS Keychain** as a generic-password item
//! (`security-framework` `set_generic_password_options`), NOT as a plaintext file next to
//! the ciphertext. This gives hardware-backed (Secure Enclave keybag) at-rest protection
//! and ACL binding to the app signature, instead of a world-readable-on-disk key.
//!
//! On upgrade, a legacy plaintext `master.key` is read once, pushed to the Keychain, and
//! shredded off disk. If Keychain access is refused (or the build is non-macOS), the key
//! falls back to the file so the app keeps working — the file path is an emergency
//! fallback, never the primary store.
//!
//! Layout (config dir = `…/app.mackftp.client/`):
//!   vault.bin   — nonce(12) ‖ AES-256-GCM(json), written atomically (ciphertext only — safe on disk)
//!   master.key  — EMERGENCY FALLBACK ONLY; absent on macOS once migrated to the Keychain
//! Keychain item: service = `{MACKFTP_BUNDLE_ID}.master-key`, account = `default`.
//!
//! `MigratingStore` wraps the vault. Legacy Keychain/v1 entries are migrated once, explicitly,
//! from the local saved-endpoint allowlist before cloud bootstrap; ordinary credential reads are
//! endpoint-bound v2 lookups and never perform a legacy fallback.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Mutex,
};

use aes_gcm::{
    aead::{consts::U12, Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use rand::RngCore;
use zeroize::Zeroizing;

use super::creds::{
    canonical_host, legacy_v1_id, CredentialError, CredentialKey, CredentialStore, SERVICE_PREFIX,
};
#[cfg(target_os = "macos")]
use super::keychain::MacCredentialStore;

/// Every public release so far has used this service prefix. Keep this explicit rather than
/// guessing from a Keychain item's shape: generic-password items are shared with every app on
/// the user's Mac.
const RELEASE_SERVICE_PREFIXES: &[&str] = &["app.mackftp.client"];

fn config_dir() -> Option<PathBuf> {
    directories::ProjectDirs::from(
        env!("MACKFTP_CONFIG_QUALIFIER"),
        env!("MACKFTP_CONFIG_ORGANIZATION"),
        env!("MACKFTP_CONFIG_APPLICATION"),
    )
    .map(|pd| pd.config_dir().to_path_buf())
}

fn is_regular_file(path: &Path) -> bool {
    std::fs::symlink_metadata(path)
        .map(|meta| meta.file_type().is_file())
        .unwrap_or(false)
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
            "vault source is not a bounded regular file",
        ));
    }
    let file = std::fs::File::open(path)?;
    let opened = file.metadata()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if before.dev() != opened.dev() || before.ino() != opened.ino() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "vault source changed while opening",
            ));
        }
    }
    if !opened.file_type().is_file() || opened.len() > max_len as u64 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "vault source changed type or size",
        ));
    }
    let mut bytes = Vec::with_capacity(opened.len() as usize);
    file.take((max_len as u64).saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() > max_len {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "vault source exceeds its size limit",
        ));
    }
    Ok(bytes)
}

/// Service prefixes this build is allowed to read during the Keychain-to-vault migration.
///
/// `SERVICE_PREFIX` supports intentionally overridden/private builds; the fixed entry is the
/// only prefix used by public releases, retained so those existing installations keep working.
fn known_service_prefixes() -> Vec<&'static str> {
    let mut prefixes = Vec::with_capacity(RELEASE_SERVICE_PREFIXES.len() + 1);
    prefixes.push(SERVICE_PREFIX);
    for &prefix in RELEASE_SERVICE_PREFIXES {
        if !prefixes.contains(&prefix) {
            prefixes.push(prefix);
        }
    }
    prefixes
}

/// Read only the connection identities that gmacFTP already owns. A broad Keychain query cannot
/// express a prefix match for the service field, so the safe alternative is a set of exact
/// `(service, account)` reads derived from our password-free metadata.
fn keychain_migration_candidates() -> Result<Vec<CredentialKey>, CredentialError> {
    let specs = super::connections::load_metadata()
        .map_err(|error| {
            CredentialError::Other(format!("could not load migration metadata: {error}"))
        })?
        .unwrap_or_default();
    Ok(migration_candidates_from_specs(specs))
}

fn migration_candidates_from_specs(
    specs: impl IntoIterator<Item = crate::model::ConnectionSpec>,
) -> Vec<CredentialKey> {
    let mut candidates = HashSet::new();
    for spec in specs {
        if let Ok(key) = CredentialKey::new(spec.protocol, &spec.host, spec.port, &spec.user) {
            candidates.insert(key);
        }
    }
    candidates.into_iter().collect()
}

fn copy_legacy_v1_for_candidates(
    map: &mut HashMap<String, String>,
    candidates: &[CredentialKey],
) -> usize {
    let mut migrated = 0;
    for key in candidates {
        let v2_id = key.vault_id();
        if map.contains_key(&v2_id) {
            continue;
        }
        let legacy = map.iter().find_map(|(id, secret)| {
            let (host, user) = id.split_once('\0')?;
            (!id.starts_with("v2\0")
                && user == key.user()
                && canonical_host(host).ok().as_deref() == Some(key.host()))
            .then(|| secret.clone())
        });
        if let Some(secret) = legacy {
            map.insert(v2_id, secret);
            migrated += 1;
        }
    }
    migrated
}

/// Encrypted at-rest credential store (in-memory decrypted map mirrored to vault.bin).
pub struct FileVault {
    // v2 identifier (`v2\0protocol\0port\0host\0user`) -> base64(secret). Existing v1
    // `host\0user` entries are read only by the explicit local-endpoint migration.
    map: Mutex<HashMap<String, String>>,
    // `None` means the Keychain/master key could not be read safely. In particular we must not
    // generate a replacement key while an existing vault may still be recoverable.
    key: Mutex<Option<[u8; 32]>>,
    // An existing vault that could not be read must never be replaced by a later credential
    // mutation. A successful explicit passphrase unlock is the only operation that clears this
    // fail-closed state.
    write_blocked: AtomicBool,
    vault_path: PathBuf,
}

impl FileVault {
    /// Open (or create) the vault. Missing key → generated (into the Keychain); missing/
    /// corrupt vault → empty.
    pub fn open() -> Self {
        let dir = config_dir().unwrap_or_else(|| PathBuf::from("."));
        let _ = std::fs::create_dir_all(&dir);
        let key_path = dir.join("master.key");
        let vault_path = dir.join("vault.bin");

        let vault_entry_exists = std::fs::symlink_metadata(&vault_path).is_ok();
        let has_existing_vault = is_regular_file(&vault_path);
        let key = match resolve_master_key(&key_path, vault_entry_exists) {
            Ok(key) => Some(key),
            Err(error) => {
                tracing::error!(error = %error, "vault master key unavailable; refusing to create a replacement key");
                None
            }
        };
        let (map, write_blocked) = if !vault_entry_exists {
            (HashMap::new(), key.is_none())
        } else if !has_existing_vault {
            tracing::error!(path = %vault_path.display(), "vault path is not a regular file; writes disabled");
            (HashMap::new(), true)
        } else if let Some(key) = key.as_ref() {
            match read_regular_limited(&vault_path, MAX_VAULT_BYTES)
                .map_err(|error| error.to_string())
                .and_then(|blob| decode_vault_map(key, &blob))
            {
                Ok(map) => (map, false),
                Err(error) => {
                    tracing::warn!(%error, "vault could not be authenticated and parsed; writes disabled");
                    preserve_unreadable(&vault_path);
                    (HashMap::new(), true)
                }
            }
        } else {
            preserve_unreadable(&vault_path);
            (HashMap::new(), true)
        };
        Self {
            map: Mutex::new(map),
            key: Mutex::new(key),
            write_blocked: AtomicBool::new(write_blocked),
            vault_path,
        }
    }

    fn persist_map(
        &self,
        map: &HashMap<String, String>,
        push_cloud: bool,
    ) -> Result<(), CredentialError> {
        if self.write_blocked.load(Ordering::Acquire) {
            return Err(CredentialError::NoStorageAccess);
        }
        validate_vault_map(map).map_err(CredentialError::Other)?;
        // The plaintext JSON of ALL secrets is the most sensitive transient buffer — wipe it.
        let plaintext = serde_json::to_vec(map)
            .map(Zeroizing::new)
            .map_err(|e| CredentialError::Other(e.to_string()))?;
        // Reuse the in-memory key (Keychain-resolved at open) — do NOT re-hit the Keychain
        // or the master.key file on every write.
        let key = self
            .key
            .lock()
            .map_err(|_| CredentialError::Other("vault key mutex poisoned".to_string()))?
            .ok_or(CredentialError::NoStorageAccess)?;
        let blob = encrypt(&key, &plaintext).map_err(CredentialError::Other)?;
        atomic_write(&self.vault_path, &blob).map_err(|e| CredentialError::Other(e.to_string()))?;
        // Best-effort mirror of vault.bin (and connections.json) to iCloud if sync is on —
        // push_state warns internally, so it never turns a successful local write into a failure.
        if push_cloud {
            crate::store::cloud::push_state();
        }
        Ok(())
    }

    fn set_entry(&self, id: String, b64: String) -> Result<(), CredentialError> {
        let mut map = self
            .map
            .lock()
            .map_err(|_| CredentialError::Other("vault mutex poisoned".to_string()))?;
        let previous = map.insert(id.clone(), b64);
        if let Err(error) = self.persist_map(&map, true) {
            match previous {
                Some(value) => {
                    map.insert(id, value);
                }
                None => {
                    map.remove(&id);
                }
            }
            return Err(error);
        }
        Ok(())
    }

    fn delete_entry(&self, id: &str) -> Result<(), CredentialError> {
        let mut map = self
            .map
            .lock()
            .map_err(|_| CredentialError::Other("vault mutex poisoned".to_string()))?;
        let previous = map.remove(id);
        if previous.is_none() && !self.write_blocked.load(Ordering::Acquire) {
            return Ok(());
        }
        if let Err(error) = self.persist_map(&map, true) {
            if let Some(value) = previous {
                map.insert(id.to_string(), value);
            }
            return Err(error);
        }
        Ok(())
    }

    /// True when the vault came up empty (undecryptable with the locally-available key) AND a
    /// wrapped key exists in the sync folder — i.e. we need the user's passphrase to unlock.
    /// (A genuinely-empty vault has no wrapped key, so it correctly reads as not-locked.)
    pub fn is_locked(&self) -> bool {
        let empty = self.map.lock().map(|m| m.is_empty()).unwrap_or(true);
        (empty || self.write_blocked.load(Ordering::Acquire))
            && crate::store::cloud::read_key().is_some()
    }

    /// Unlock with a passphrase: unwrap the master key from the synced wrapped key, re-read +
    /// decrypt vault.bin with it, swap the key + map in place. Returns true on success. Caches
    /// the master key + passphrase in the Keychain so the next launch auto-unlocks.
    pub fn unlock(&self, passphrase: &str) -> bool {
        let Some((_, wrapped)) = crate::store::cloud::read_key() else {
            return false;
        };
        let Some(key) = unwrap_master_key(&wrapped, passphrase) else {
            return false;
        };
        // Read the SYNCED vault (the local vault.bin may be this Mac's own, undecryptable with
        // the synced key). Adopt it: decrypt + load, then write it locally so future opens match.
        let Some((_, blob)) = crate::store::cloud::read_vault() else {
            return false;
        };
        let Ok(plaintext) = decrypt(&key, &blob).map(Zeroizing::new) else {
            return false;
        };
        let Ok(loaded) = parse_vault_map(&plaintext) else {
            return false;
        };
        // Cache and local persistence are both critical for a successful unlock. Do them before
        // touching in-memory state, so `true` never means a session that will be lost at the
        // next launch.
        // Keep the same map -> key lock order used by set/delete -> persist_map.
        let Ok(mut map_guard) = self.map.lock() else {
            return false;
        };
        let Ok(mut key_guard) = self.key.lock() else {
            return false;
        };
        #[cfg(target_os = "macos")]
        let sync = crate::store::settings::load().sync_via_icloud;
        #[cfg(target_os = "macos")]
        let keychain_snapshot = match keychain_master_key::replace_verified(&key, sync) {
            Ok(snapshot) => snapshot,
            Err(error) => {
                tracing::error!(%error, "could not transactionally cache unlocked master key");
                return false;
            }
        };
        #[cfg(target_os = "macos")]
        let passphrase_snapshot = match keychain_passphrase::replace_verified(passphrase, sync) {
            Ok(snapshot) => snapshot,
            Err(error) => {
                let rollback = keychain_master_key::restore(&keychain_snapshot);
                tracing::error!(%error, ?rollback, "could not transactionally cache sync passphrase");
                return false;
            }
        };
        if let Err(error) = atomic_write(&self.vault_path, &blob) {
            #[cfg(target_os = "macos")]
            {
                let passphrase_rollback = keychain_passphrase::restore(&passphrase_snapshot);
                let master_key_rollback = keychain_master_key::restore(&keychain_snapshot);
                tracing::error!(%error, ?passphrase_rollback, ?master_key_rollback, "unlock local write failed; restored prior Keychain state");
            }
            #[cfg(not(target_os = "macos"))]
            tracing::error!(%error, "unlock local write failed");
            return false;
        }
        *key_guard = Some(key);
        *map_guard = loaded;
        self.write_blocked.store(false, Ordering::Release);
        tracing::info!(target: "gmacftp::vault", "vault unlocked + adopted synced state");
        true
    }

    /// One-shot migration of legacy per-server Keychain entries into the vault.
    ///
    /// This deliberately queries only exact `(service, account)` pairs for servers already
    /// saved in `connections.json`. It never performs a broad generic-password search: that
    /// would expose credentials belonging to unrelated applications and, before this check was
    /// added, could copy them into the synced vault. The service prefix is likewise limited to
    /// the current build identity and the explicit identity used by shipped public releases.
    ///
    /// A missing metadata file simply means there is no connection for the app to migrate.
    /// Every endpoint in this pre-sync local allowlist receives its own v2 copy; normal reads do
    /// not perform a legacy fallback, because doing so for a newly imported endpoint could send
    /// an old password to a different protocol or port. Returns how many endpoint-bound copies
    /// were migrated. Any metadata, Keychain, locking, or persistence error is propagated so the
    /// caller does not mark the one-shot migration as complete.
    pub fn migrate_from_keychain(&self) -> Result<usize, CredentialError> {
        let candidates = keychain_migration_candidates()?;
        let mut map = self
            .map
            .lock()
            .map_err(|_| CredentialError::Other("vault mutex poisoned".to_string()))?;
        let previous = map.clone();
        let mut migrated = copy_legacy_v1_for_candidates(&mut map, &candidates);

        for key in &candidates {
            let v2_id = key.vault_id();
            if map.contains_key(&v2_id) {
                continue;
            }

            #[cfg(target_os = "macos")]
            let legacy = {
                use security_framework::passwords::{generic_password, PasswordOptions};
                const ERR_SEC_ITEM_NOT_FOUND: i32 = -25_300;
                let mut found = None;
                for &prefix in &known_service_prefixes() {
                    let service = format!("{prefix}/{}", key.host());
                    match generic_password(PasswordOptions::new_generic_password(
                        &service,
                        key.user(),
                    )) {
                        Ok(secret) => {
                            let secret = Zeroizing::new(secret);
                            if secret.len() > MAX_CREDENTIAL_BYTES {
                                *map = previous;
                                return Err(CredentialError::Other(
                                    "legacy Keychain credential exceeds size limit".into(),
                                ));
                            }
                            found = Some(B64.encode(&*secret));
                            break;
                        }
                        Err(error) if error.code() == ERR_SEC_ITEM_NOT_FOUND => {}
                        Err(error) => {
                            *map = previous;
                            return Err(CredentialError::Other(format!(
                                "legacy Keychain read failed: {error}"
                            )));
                        }
                    }
                }
                found
            };

            #[cfg(not(target_os = "macos"))]
            let legacy: Option<String> = None;

            if let Some(secret) = legacy {
                map.insert(v2_id, secret);
                migrated += 1;
            }
        }

        if migrated > 0 {
            // This method is intended to run before cloud bootstrap. Persist locally without a
            // cloud push; bootstrap will resolve the normal last-writer-wins policy afterwards.
            if let Err(error) = self.persist_map(&map, false) {
                *map = previous;
                return Err(error);
            }
            tracing::info!(
                "migrated {migrated} saved credentials into endpoint-bound vault entries"
            );
        }
        Ok(migrated)
    }
}

impl CredentialStore for FileVault {
    fn get(&self, host: &str, user: &str) -> Result<Vec<u8>, CredentialError> {
        let key = legacy_v1_id(host, user);
        match self
            .map
            .lock()
            .map_err(|_| CredentialError::Other("vault mutex poisoned".to_string()))?
            .get(&key)
        {
            Some(b64) => B64
                .decode(b64)
                .map_err(|e| CredentialError::Other(e.to_string())),
            None => Err(CredentialError::NotFound),
        }
    }

    fn set(&self, host: &str, user: &str, secret: &[u8]) -> Result<(), CredentialError> {
        if secret.len() > MAX_CREDENTIAL_BYTES {
            return Err(CredentialError::Other(
                "credential exceeds size limit".into(),
            ));
        }
        self.set_entry(legacy_v1_id(host, user), B64.encode(secret))
    }

    fn delete(&self, host: &str, user: &str) -> Result<(), CredentialError> {
        self.delete_entry(&legacy_v1_id(host, user))
    }

    fn get_for(&self, key: &CredentialKey) -> Result<Vec<u8>, CredentialError> {
        let v2_id = key.vault_id();
        let direct = self
            .map
            .lock()
            .map_err(|_| CredentialError::Other("vault mutex poisoned".to_string()))?
            .get(&v2_id)
            .cloned();
        direct.ok_or(CredentialError::NotFound).and_then(|b64| {
            B64.decode(b64)
                .map_err(|e| CredentialError::Other(e.to_string()))
        })
    }

    fn set_for(&self, key: &CredentialKey, secret: &[u8]) -> Result<(), CredentialError> {
        if secret.len() > MAX_CREDENTIAL_BYTES {
            return Err(CredentialError::Other(
                "credential exceeds size limit".into(),
            ));
        }
        self.set_entry(key.vault_id(), B64.encode(secret))
    }

    fn delete_for(&self, key: &CredentialKey) -> Result<(), CredentialError> {
        self.delete_entry(&key.vault_id())
    }
}

/// Encrypted vault plus an explicitly invoked, endpoint-allowlisted Keychain migration source.
/// After migration ordinary reads use the vault only, so they are silent and cannot reuse a v1
/// password for a newly added protocol/port.
pub struct MigratingStore {
    vault: FileVault,
    #[cfg(target_os = "macos")]
    keychain: MacCredentialStore,
}

impl MigratingStore {
    #[cfg(target_os = "macos")]
    pub fn new() -> Self {
        Self {
            vault: FileVault::open(),
            keychain: MacCredentialStore::new(),
        }
    }
    #[cfg(not(target_os = "macos"))]
    pub fn new() -> Self {
        Self {
            vault: FileVault::open(),
        }
    }
}

impl Default for MigratingStore {
    fn default() -> Self {
        Self::new()
    }
}

impl CredentialStore for MigratingStore {
    fn get(&self, host: &str, user: &str) -> Result<Vec<u8>, CredentialError> {
        match self.vault.get(host, user) {
            Ok(secret) => return Ok(secret),
            Err(CredentialError::NotFound) => {}
            Err(error) => return Err(error),
        }
        #[cfg(target_os = "macos")]
        {
            match self.keychain.get(host, user) {
                Ok(secret) => {
                    self.vault.set(host, user, &secret)?;
                    tracing::info!(%host, %user, "migrated credential from Keychain to vault");
                    return Ok(secret);
                }
                Err(CredentialError::NotFound) => {}
                Err(error) => return Err(error),
            }
        }
        let _ = (host, user);
        Err(CredentialError::NotFound)
    }

    fn set(&self, host: &str, user: &str, secret: &[u8]) -> Result<(), CredentialError> {
        self.vault.set(host, user, secret)
    }

    fn delete(&self, host: &str, user: &str) -> Result<(), CredentialError> {
        self.vault.delete(host, user)?;
        #[cfg(target_os = "macos")]
        {
            self.keychain.delete(host, user)?;
        }
        Ok(())
    }

    fn get_for(&self, key: &CredentialKey) -> Result<Vec<u8>, CredentialError> {
        // Legacy credentials are copied only by the explicit, local-metadata allowlisted
        // migration. Falling back here would let a newly imported endpoint claim an old
        // host/account password under a different protocol or port.
        self.vault.get_for(key)
    }

    fn set_for(&self, key: &CredentialKey, secret: &[u8]) -> Result<(), CredentialError> {
        self.vault.set_for(key, secret)
    }

    fn delete_for(&self, key: &CredentialKey) -> Result<(), CredentialError> {
        self.vault.delete_for(key)?;
        #[cfg(target_os = "macos")]
        self.keychain.delete_for(key)?;
        Ok(())
    }

    fn is_locked(&self) -> bool {
        self.vault.is_locked()
    }

    fn unlock(&self, passphrase: &str) -> bool {
        self.vault.unlock(passphrase)
    }

    fn migrate_from_keychain(&self) -> Result<usize, CredentialError> {
        self.vault.migrate_from_keychain()
    }
}

// ── master-key resolution: Keychain (primary) > legacy file (migrate) > generate ──

/// Resolve the AES master key. Order:
/// 1. Keychain (primary — hardware-backed, not on disk).
/// 2. Legacy plaintext `master.key` (one-time migration: read → push to Keychain → shred).
/// 3. Generate a new key and store it in the Keychain (never written to disk on macOS).
///
/// The macOS Keychain path is skipped (file used directly) on non-macOS or when the
/// Keychain refuses access — the app must keep working.
fn resolve_master_key(key_path: &Path, must_not_replace: bool) -> Result<[u8; 32], String> {
    let sync = crate::store::settings::load().sync_via_icloud;

    #[cfg(target_os = "macos")]
    {
        match keychain_master_key::load_any() {
            Ok(Some(key)) => return Ok(key), // already in the Keychain
            Ok(None) => {}
            Err(error) => {
                // A valid legacy on-disk key is still safe to use. Without it, do not generate
                // a new key: an existing vault could become permanently unreadable.
                if let Some(key) = read_legacy_master_key(key_path) {
                    return Ok(key);
                }
                return Err(format!("master-key Keychain read failed: {error}"));
            }
        }
        // Auto-unlock: a wrapped key in the sync folder + the passphrase in the Keychain (synced,
        // fixed cross-bundle service) → unwrap the real master key + cache it locally. This is the cross-device path that does NOT depend on the bundle-specific master-key item (so it survives a bundle mismatch).
        if let Some((_, wrapped)) = crate::store::cloud::read_key() {
            if let Some(pp) = keychain_passphrase::load() {
                if let Some(k) = unwrap_master_key(&wrapped, &pp) {
                    keychain_master_key::store_verified(&k, sync)
                        .map_err(|e| format!("could not cache synced master key: {e}"))?;
                    tracing::info!("unlocked vault master key from synced wrapped key");
                    return Ok(k);
                }
            }
        }
    }

    // Legacy plaintext file present → migrate it into the Keychain, then shred.
    if let Some(k) = read_legacy_master_key(key_path) {
        #[cfg(target_os = "macos")]
        {
            match keychain_master_key::store_verified(&k, sync) {
                Ok(()) => {
                    tracing::info!("migrated master key from plaintext file into Keychain");
                    shred_file(key_path); // CRYP-1: remove plaintext from disk
                    return Ok(k);
                }
                Err(e) => {
                    // Keychain refused (access denied). Keep the legacy file so the user
                    // doesn't lose their vault, and surface it.
                    tracing::warn!(error = %e, "Keychain store failed; keeping legacy master.key");
                    return Ok(k);
                }
            }
        }
        #[cfg(not(target_os = "macos"))]
        return Ok(k);
    }

    if must_not_replace || crate::store::cloud::read_key().is_some() {
        return Err("no usable master key for an existing or synced vault".to_string());
    }

    // No key anywhere → generate and store in the Keychain (never hits disk on macOS).
    let mut k = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut k);
    #[cfg(target_os = "macos")]
    {
        if let Err(e) = keychain_master_key::store_verified(&k, sync) {
            tracing::warn!(error = %e, "Keychain store failed; writing emergency master.key fallback");
            atomic_write(key_path, &k)
                .map_err(|e| format!("master key fallback write failed: {e}"))?;
            set_mode_0600(key_path)
                .map_err(|e| format!("master key fallback permissions failed: {e}"))?;
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        atomic_write(key_path, &k).map_err(|e| format!("master key fallback write failed: {e}"))?;
        set_mode_0600(key_path)
            .map_err(|e| format!("master key fallback permissions failed: {e}"))?;
    }
    Ok(k)
}

fn read_legacy_master_key(key_path: &Path) -> Option<[u8; 32]> {
    use std::io::Read;

    let before = std::fs::symlink_metadata(key_path).ok()?;
    if !before.file_type().is_file() || before.file_type().is_symlink() || before.len() != 32 {
        tracing::error!(path = %key_path.display(), "legacy master.key is not a safe 32-byte regular file");
        return None;
    }
    let file = std::fs::File::open(key_path).ok()?;
    let after = file.metadata().ok()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if before.dev() != after.dev() || before.ino() != after.ino() {
            tracing::error!(path = %key_path.display(), "legacy master.key changed while opening");
            return None;
        }
    }
    let mut bytes = Vec::with_capacity(32);
    file.take(33).read_to_end(&mut bytes).ok()?;
    let bytes = Zeroizing::new(bytes);
    if bytes.len() != 32 {
        tracing::error!(path = %key_path.display(), "legacy master.key has an invalid length");
        return None;
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Some(key)
}

/// Best-effort overwrite+unlink. APFS is copy-on-write so this isn't a forensic shred, but
/// removing the plaintext from the live filesystem is the goal.
fn shred_file(path: &Path) {
    use std::io::{Seek, SeekFrom, Write};

    let Ok(before) = std::fs::symlink_metadata(path) else {
        return;
    };
    if !before.file_type().is_file() || before.file_type().is_symlink() {
        tracing::warn!(path = %path.display(), "refusing to shred a non-regular legacy key path");
        return;
    }
    let Ok(mut file) = std::fs::OpenOptions::new().write(true).open(path) else {
        return;
    };
    let Ok(opened) = file.metadata() else {
        return;
    };
    if opened.len() != 32 {
        tracing::warn!(path = %path.display(), "legacy key changed size; refusing to shred it");
        return;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if before.dev() != opened.dev() || before.ino() != opened.ino() {
            tracing::warn!(path = %path.display(), "legacy key changed while opening; refusing to shred it");
            return;
        }
    }
    if file
        .seek(SeekFrom::Start(0))
        .and_then(|_| file.write_all(&[0u8; 32]))
        .and_then(|_| file.sync_all())
        .is_err()
    {
        return;
    }
    drop(file);
    let Ok(current) = std::fs::symlink_metadata(path) else {
        return;
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if !current.file_type().is_file()
            || current.dev() != before.dev()
            || current.ino() != before.ino()
        {
            return;
        }
    }
    let _ = std::fs::remove_file(path);
}

// ── macOS Keychain backing for the master key (security-framework) ──

#[cfg(target_os = "macos")]
mod keychain_master_key {
    use security_framework::passwords::{
        delete_generic_password_options, generic_password, set_generic_password_options,
    };
    use security_framework::passwords_options::PasswordOptions;

    use crate::store::creds::SERVICE_PREFIX;

    const ACCOUNT: &str = "default";
    const ERR_SEC_ITEM_NOT_FOUND: i32 = -25_300;

    pub struct Snapshot {
        local: Option<[u8; 32]>,
        synced: Option<[u8; 32]>,
    }

    impl Drop for Snapshot {
        fn drop(&mut self) {
            use zeroize::Zeroize;
            if let Some(key) = &mut self.local {
                key.zeroize();
            }
            if let Some(key) = &mut self.synced {
                key.zeroize();
            }
        }
    }

    fn service() -> String {
        format!("{SERVICE_PREFIX}.master-key")
    }

    fn opts(sync: Option<bool>) -> PasswordOptions {
        let mut o = PasswordOptions::new_generic_password(&service(), ACCOUNT);
        o.set_access_synchronized(sync);
        o
    }

    /// Build a read/delete query matching BOTH synchronizable and non-synchronizable items
    /// (kSecAttrSynchronizableAny). A plain `get_generic_password` query has NO synchronizable
    /// attribute, so on macOS it matches only NON-synchronizable items — meaning when sync is on
    /// the master key is stored synchronizable and `load()` could NOT see it, a fresh key was
    /// generated each launch, the vault became undecryptable, and every connection re-prompted
    /// the Keychain. Matching both fixes that and lets pull find synced state.
    fn opts_any() -> PasswordOptions {
        opts(None) // kSecAttrSynchronizableAny
    }

    fn decode_key(bytes: Vec<u8>) -> Result<[u8; 32], String> {
        if bytes.len() != 32 {
            return Err(format!(
                "master-key Keychain item has invalid length {}",
                bytes.len()
            ));
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes);
        Ok(key)
    }

    fn load_with(opts: PasswordOptions) -> Result<Option<[u8; 32]>, String> {
        match generic_password(opts) {
            Ok(bytes) => decode_key(bytes).map(Some),
            Err(error) if error.code() == ERR_SEC_ITEM_NOT_FOUND => Ok(None),
            Err(error) => Err(error.to_string()),
        }
    }

    /// Load the key while distinguishing an absent item from an access error or invalid bytes.
    pub fn load_any() -> Result<Option<[u8; 32]>, String> {
        load_with(opts_any())
    }

    fn load_specific(sync: bool) -> Result<Option<[u8; 32]>, String> {
        load_with(opts(Some(sync)))
    }

    /// Store and read back exactly the requested synchronizability class.
    pub fn store_verified(key: &[u8; 32], sync: bool) -> Result<(), String> {
        set_generic_password_options(key, opts(Some(sync))).map_err(|e| e.to_string())?;
        match load_specific(sync)? {
            Some(read_back) if read_back == *key => Ok(()),
            Some(_) => Err("master-key Keychain read-back mismatch".to_string()),
            None => Err("master-key Keychain write was not readable".to_string()),
        }
    }

    /// Delete the key (idempotent, both stores). Used if the vault is ever reset, or when
    /// moving the key between stores on a sync toggle.
    fn delete_specific(sync: bool) -> Result<(), String> {
        match delete_generic_password_options(opts(Some(sync))) {
            Ok(()) => Ok(()),
            Err(error) if error.code() == ERR_SEC_ITEM_NOT_FOUND => Ok(()),
            Err(error) => Err(error.to_string()),
        }
    }

    fn snapshot() -> Result<Snapshot, String> {
        Ok(Snapshot {
            local: load_specific(false)?,
            synced: load_specific(true)?,
        })
    }

    pub fn restore(snapshot: &Snapshot) -> Result<(), String> {
        let restore_class = |sync: bool, value: Option<&[u8; 32]>| match value {
            Some(key) => store_verified(key, sync),
            None => delete_specific(sync),
        };
        let local = restore_class(false, snapshot.local.as_ref());
        let synced = restore_class(true, snapshot.synced.as_ref());
        match (local, synced) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(a), Ok(())) | (Ok(()), Err(a)) => Err(a),
            (Err(a), Err(b)) => Err(format!(
                "local restore failed: {a}; synced restore failed: {b}"
            )),
        }
    }

    /// Replace both synchronizability classes as one recoverable operation. The prior state is
    /// returned so a later vault-file failure can restore it.
    pub fn replace_verified(key: &[u8; 32], sync: bool) -> Result<Snapshot, String> {
        let before = snapshot()?;
        let operation = store_verified(key, sync)
            .and_then(|()| delete_specific(!sync))
            .and_then(|()| match load_specific(sync)? {
                Some(read_back) if read_back == *key => Ok(()),
                _ => Err("replacement master key was not readable".to_string()),
            });
        if let Err(error) = operation {
            return match restore(&before) {
                Ok(()) => Err(error),
                Err(rollback) => Err(format!("{error}; Keychain rollback failed: {rollback}")),
            };
        }
        Ok(before)
    }

    /// Move the master key without deleting the source until the target was written and read
    /// back. If source deletion fails, remove the newly-created target when possible, leaving
    /// the original key available for recovery.
    pub fn promote_to_sync(sync: bool) -> Result<(), String> {
        let key = load_any()?.ok_or_else(|| "master key not found".to_string())?;
        let target_before = load_specific(sync)?;
        match target_before {
            Some(existing) if existing != key => {
                return Err(
                    "refusing to overwrite a different master key in target Keychain class".into(),
                )
            }
            Some(_) => {}
            None => store_verified(&key, sync)?,
        }

        if let Err(error) = delete_specific(!sync) {
            if target_before.is_none() {
                let _ = delete_specific(sync); // best-effort rollback; source is still intact
            }
            return Err(format!("master-key source deletion failed: {error}"));
        }
        Ok(())
    }
}

// ── macOS Keychain backing for the SYNC PASSPHRASE (FIXED cross-bundle service) ──
// FIXED service (NOT bundle-id derived) so the personal + public bundles SHARE this passphrase
// item — the cross-bundle, cross-device secret that unlocks the synced wrapped master key.
// This is what fixes the bundle-mismatch "missing credential": the master key is bundle-local,
// but the passphrase (which unlocks the synced wrapped key) is shared across bundles.

#[cfg(target_os = "macos")]
mod keychain_passphrase {
    use security_framework::passwords::{
        delete_generic_password_options, generic_password, set_generic_password_options,
    };
    use security_framework::passwords_options::PasswordOptions;
    use zeroize::Zeroizing;

    const SERVICE: &str = "gmacFTP.sync-passphrase";
    const ACCOUNT: &str = "default";
    const ERR_SEC_ITEM_NOT_FOUND: i32 = -25_300;

    pub struct Snapshot {
        local: Option<Vec<u8>>,
        synced: Option<Vec<u8>>,
    }

    impl Drop for Snapshot {
        fn drop(&mut self) {
            use zeroize::Zeroize;
            if let Some(passphrase) = &mut self.local {
                passphrase.zeroize();
            }
            if let Some(passphrase) = &mut self.synced {
                passphrase.zeroize();
            }
        }
    }

    fn opts(sync: Option<bool>) -> PasswordOptions {
        let mut o = PasswordOptions::new_generic_password(SERVICE, ACCOUNT);
        o.set_access_synchronized(sync);
        o
    }

    fn opts_any() -> PasswordOptions {
        opts(None) // match both stores on read
    }

    pub fn store_verified(pp: &str, sync: bool) -> Result<(), String> {
        set_generic_password_options(pp.as_bytes(), opts(Some(sync))).map_err(|e| e.to_string())?;
        match generic_password(opts(Some(sync))) {
            Ok(value) if value == pp.as_bytes() => Ok(()),
            Ok(_) => Err("sync-passphrase Keychain read-back mismatch".to_string()),
            Err(error) => Err(format!(
                "sync-passphrase Keychain read-back failed: {error}"
            )),
        }
    }

    pub fn load() -> Option<String> {
        let bytes = generic_password(opts_any()).ok()?;
        String::from_utf8(bytes).ok()
    }

    fn load_specific(sync: bool) -> Result<Option<Vec<u8>>, String> {
        match generic_password(opts(Some(sync))) {
            Ok(value) => Ok(Some(value)),
            Err(error) if error.code() == ERR_SEC_ITEM_NOT_FOUND => Ok(None),
            Err(error) => Err(error.to_string()),
        }
    }

    fn delete_specific(sync: bool) -> Result<(), String> {
        match delete_generic_password_options(opts(Some(sync))) {
            Ok(()) => Ok(()),
            Err(error) if error.code() == ERR_SEC_ITEM_NOT_FOUND => Ok(()),
            Err(error) => Err(error.to_string()),
        }
    }

    fn snapshot() -> Result<Snapshot, String> {
        Ok(Snapshot {
            local: load_specific(false)?,
            synced: load_specific(true)?,
        })
    }

    pub fn restore(snapshot: &Snapshot) -> Result<(), String> {
        let restore_class = |sync: bool, value: Option<&Vec<u8>>| match value {
            Some(secret) => set_generic_password_options(secret, opts(Some(sync)))
                .map_err(|error| error.to_string()),
            None => delete_specific(sync),
        };
        let local = restore_class(false, snapshot.local.as_ref());
        let synced = restore_class(true, snapshot.synced.as_ref());
        match (local, synced) {
            (Ok(()), Ok(())) => Ok(()),
            (Err(a), Ok(())) | (Ok(()), Err(a)) => Err(a),
            (Err(a), Err(b)) => Err(format!(
                "local restore failed: {a}; synced restore failed: {b}"
            )),
        }
    }

    pub fn replace_verified(passphrase: &str, sync: bool) -> Result<Snapshot, String> {
        let before = snapshot()?;
        let operation = store_verified(passphrase, sync).and_then(|()| delete_specific(!sync));
        if let Err(error) = operation {
            return match restore(&before) {
                Ok(()) => Err(error),
                Err(rollback) => Err(format!("{error}; Keychain rollback failed: {rollback}")),
            };
        }
        Ok(before)
    }

    pub fn promote_to_sync(sync: bool) -> Result<(), String> {
        let before = snapshot()?;
        let (source, target) = if sync {
            (before.local.as_ref(), before.synced.as_ref())
        } else {
            (before.synced.as_ref(), before.local.as_ref())
        };
        let Some(value) = source.or(target) else {
            return Ok(());
        };
        if target.is_some_and(|existing| existing != value) {
            return Err(
                "refusing to overwrite a different passphrase in target Keychain class".into(),
            );
        }
        let value = Zeroizing::new(
            String::from_utf8(value.clone())
                .map_err(|_| "sync passphrase in Keychain is not valid UTF-8".to_string())?,
        );
        let operation = store_verified(&value, sync).and_then(|()| delete_specific(!sync));
        if let Err(error) = operation {
            return match restore(&before) {
                Ok(()) => Err(error),
                Err(rollback) => Err(format!("{error}; Keychain rollback failed: {rollback}")),
            };
        }
        Ok(())
    }
}

/// Public entry: move the master key to/from the iCloud-syncing Keychain store.
#[cfg(target_os = "macos")]
pub fn set_master_key_syncable(sync: bool) -> Result<(), String> {
    keychain_master_key::promote_to_sync(sync)
}
#[cfg(not(target_os = "macos"))]
pub fn set_master_key_syncable(_sync: bool) -> Result<(), String> {
    Ok(())
}

/// Move the cached passphrase between local and iCloud-Keychain classes alongside the master
/// key. A missing passphrase is a valid first-time state.
#[cfg(target_os = "macos")]
pub fn set_sync_passphrase_syncable(sync: bool) -> Result<(), String> {
    keychain_passphrase::promote_to_sync(sync)
}
#[cfg(not(target_os = "macos"))]
pub fn set_sync_passphrase_syncable(_sync: bool) -> Result<(), String> {
    Ok(())
}

/// Enable sync with a passphrase: wrap the current master key, push the wrapped key to the
/// sync folder, cache the passphrase in the Keychain (fixed cross-bundle service), and mark
/// the passphrase as set. Called from the "set passphrase" dialog when first enabling sync.
pub fn enable_sync_passphrase(passphrase: &str) -> Result<(), String> {
    if passphrase.chars().count() < 12 || passphrase.len() > 1024 {
        return Err("sync passphrase must be at least 12 characters and at most 1024 bytes".into());
    }
    let dir = config_dir().unwrap_or_else(|| PathBuf::from("."));
    let key = resolve_master_key(
        &dir.join("master.key"),
        is_regular_file(&dir.join("vault.bin")),
    )?;
    let wrapped = wrap_master_key(&key, passphrase)?;
    #[cfg(target_os = "macos")]
    let keychain_snapshot = keychain_passphrase::replace_verified(
        passphrase,
        crate::store::settings::load().sync_via_icloud,
    )
    .map_err(|e| format!("passphrase keychain store failed: {e}"))?;
    let cloud_snapshot = match crate::store::cloud::replace_key(&wrapped) {
        Ok(snapshot) => snapshot,
        Err(error) => {
            #[cfg(target_os = "macos")]
            {
                let rollback = keychain_passphrase::restore(&keychain_snapshot);
                return Err(format!("{error}; passphrase rollback: {rollback:?}"));
            }
            #[cfg(not(target_os = "macos"))]
            return Err(error);
        }
    };
    let mut s = crate::store::settings::load();
    s.sync_passphrase_set = true;
    if let Err(error) = crate::store::settings::try_save(&s) {
        let cloud_rollback = crate::store::cloud::restore_key(cloud_snapshot.as_deref());
        #[cfg(target_os = "macos")]
        let keychain_rollback = keychain_passphrase::restore(&keychain_snapshot);
        #[cfg(not(target_os = "macos"))]
        let keychain_rollback: Result<(), String> = Ok(());
        return Err(format!(
            "settings save failed: {error}; cloud rollback: {cloud_rollback:?}; Keychain rollback: {keychain_rollback:?}"
        ));
    }
    Ok(())
}

/// Re-create + re-push the wrapped key from the passphrase cached in the Keychain (used to
/// auto-heal when the wrapped key is missing from the sync folder — e.g. after a sync off→on
/// toggle purged it). Errors if no passphrase is cached (caller then prompts to set one).
pub fn repush_sync_key() -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        let pp = keychain_passphrase::load()
            .ok_or_else(|| "no sync passphrase in Keychain".to_string())?;
        let dir = config_dir().unwrap_or_else(|| PathBuf::from("."));
        let key = resolve_master_key(
            &dir.join("master.key"),
            is_regular_file(&dir.join("vault.bin")),
        )?;
        let wrapped = wrap_master_key(&key, &pp)?;
        crate::store::cloud::push_key(&wrapped)?;
        tracing::info!("re-pushed wrapped master key to the sync folder");
        Ok(())
    }
    #[cfg(not(target_os = "macos"))]
    Err("sync not supported on this platform".into())
}

// ── crypto + io helpers ──

const MAX_VAULT_BYTES: usize = 1_048_576;
const MAX_VAULT_ENTRIES: usize = 10_000;
const MAX_VAULT_ID_BYTES: usize = 1_024;
const MAX_CREDENTIAL_BYTES: usize = 65_536;

fn validate_vault_map(map: &HashMap<String, String>) -> Result<(), String> {
    use std::str::FromStr;

    if map.len() > MAX_VAULT_ENTRIES {
        return Err("vault contains too many credential entries".into());
    }
    for (id, encoded) in map {
        if id.is_empty() || id.len() > MAX_VAULT_ID_BYTES {
            return Err("vault credential identifier exceeds its limit".into());
        }
        if let Some(rest) = id.strip_prefix("v2\0") {
            let mut parts = rest.split('\0');
            let protocol = parts
                .next()
                .and_then(|value| crate::model::Protocol::from_str(value).ok())
                .ok_or_else(|| "vault contains an invalid v2 protocol".to_string())?;
            let port = parts
                .next()
                .and_then(|value| value.parse::<u16>().ok())
                .ok_or_else(|| "vault contains an invalid v2 port".to_string())?;
            let host = parts
                .next()
                .ok_or_else(|| "vault contains an invalid v2 host".to_string())?;
            let user = parts
                .next()
                .ok_or_else(|| "vault contains an invalid v2 account".to_string())?;
            if parts.next().is_some()
                || CredentialKey::new(protocol, host, port, user)
                    .map(|key| key.vault_id() != *id)
                    .unwrap_or(true)
            {
                return Err("vault contains a non-canonical v2 identifier".into());
            }
        } else {
            let (host, user) = id
                .split_once('\0')
                .ok_or_else(|| "vault contains an invalid legacy identifier".to_string())?;
            if id.matches('\0').count() != 1
                || canonical_host(host).is_err()
                || user.is_empty()
                || user.len() > 512
                || user.chars().any(char::is_control)
            {
                return Err("vault contains an invalid legacy identifier".into());
            }
        }
        let decoded = Zeroizing::new(
            B64.decode(encoded)
                .map_err(|_| "vault contains invalid base64 credential data".to_string())?,
        );
        if decoded.len() > MAX_CREDENTIAL_BYTES || B64.encode(&*decoded) != *encoded {
            return Err("vault contains a non-canonical or oversized credential".into());
        }
    }
    Ok(())
}

fn parse_vault_map(plaintext: &[u8]) -> Result<HashMap<String, String>, String> {
    let map = serde_json::from_slice::<HashMap<String, String>>(plaintext)
        .map_err(|error| format!("vault JSON parse failed: {error}"))?;
    validate_vault_map(&map)?;
    Ok(map)
}

fn decode_vault_map(key: &[u8; 32], blob: &[u8]) -> Result<HashMap<String, String>, String> {
    if !(12 + 16..=MAX_VAULT_BYTES).contains(&blob.len()) {
        return Err("encrypted vault exceeds its size bounds".into());
    }
    let plaintext = Zeroizing::new(decrypt(key, blob)?);
    parse_vault_map(&plaintext)
}

/// Stash the unreadable vault aside so the user can recover/re-import before a later `set()`
/// overwrites it. Without this, a corrupt/undecryptable vault silently becomes empty and the
/// next persist destroys the original. Best-effort (read-only fs just loses the convenience).
fn preserve_unreadable(vault_path: &Path) {
    use std::io::Write;

    let Some(stem) = vault_path.file_name().and_then(|s| s.to_str()) else {
        return;
    };
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let Ok(bytes) = read_regular_limited(vault_path, MAX_VAULT_BYTES) else {
        return;
    };
    for _ in 0..8 {
        let suffix = rand::rngs::OsRng.next_u64();
        let backup = vault_path.with_file_name(format!("{stem}.corrupt-{secs}-{suffix:016x}"));
        match create_exclusive(&backup) {
            Ok(mut file) => {
                let result = file.write_all(&bytes).and_then(|()| file.sync_all());
                drop(file);
                if result.is_ok() {
                    tracing::error!(backup = %backup.display(), "vault unreadable — preserved a copy aside");
                } else {
                    let _ = std::fs::remove_file(&backup);
                }
                return;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(_) => return,
        }
    }
}

fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = Aes256Gcm::new_from_slice(&key[..]).map_err(|e| e.to_string())?;
    let mut nonce_bytes = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    // Fixed-size array: this conversion cannot fail, and avoids the deprecated `from_slice` API
    // introduced by aes-gcm 0.11's hybrid-array migration.
    let nonce = Nonce::<U12>::try_from(nonce_bytes.as_slice())
        .expect("a 12-byte AES-GCM nonce must convert");
    let ct = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| e.to_string())?;
    let mut out = Vec::with_capacity(12 + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

fn decrypt(key: &[u8; 32], blob: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = Aes256Gcm::new_from_slice(&key[..]).map_err(|e| e.to_string())?;
    let (nonce_bytes, ciphertext) = blob
        .split_at_checked(12)
        .ok_or_else(|| "encrypted vault is shorter than its AES-GCM nonce".to_string())?;
    let nonce = Nonce::<U12>::try_from(nonce_bytes)
        .map_err(|_| "invalid AES-GCM nonce length".to_string())?;
    cipher
        .decrypt(&nonce, ciphertext)
        .map_err(|e| e.to_string())
}

const WRAP_MAGIC: &[u8; 4] = b"GFKW";
const WRAP_VERSION_V2: u8 = 2;
const WRAP_SALT_LEN: usize = 16;
const WRAP_V2_HEADER_LEN: usize = 4 + 1 + 4 + 4 + 4 + WRAP_SALT_LEN;
const WRAP_CIPHERTEXT_LEN: usize = 12 + 32 + 16; // AES-GCM nonce + 32-byte key + tag
const WRAP_V1_LEN: usize = WRAP_SALT_LEN + WRAP_CIPHERTEXT_LEN;
const WRAP_V2_LEN: usize = WRAP_V2_HEADER_LEN + WRAP_CIPHERTEXT_LEN;
const WRAP_MEMORY_KIB: u32 = 19 * 1024;
const WRAP_TIME_COST: u32 = 2;
const WRAP_PARALLELISM: u32 = 1;

/// Derive a 32-byte key-encryption-key from the passphrase + salt via Argon2id. V2 records the
/// parameters in the wrapped blob; V1 used Argon2's then-default parameters and remains readable.
fn derive_kek(
    passphrase: &str,
    salt: &[u8],
    memory_kib: u32,
    time_cost: u32,
    parallelism: u32,
) -> Result<[u8; 32], String> {
    if !(8 * 1024..=256 * 1024).contains(&memory_kib)
        || !(1..=10).contains(&time_cost)
        || !(1..=8).contains(&parallelism)
        || salt.len() != WRAP_SALT_LEN
    {
        return Err("invalid wrapped-key KDF parameters".to_string());
    }
    let params = argon2::Params::new(memory_kib, time_cost, parallelism, Some(32))
        .map_err(|e| e.to_string())?;
    let argon2 = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut kek = [0u8; 32];
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, kek.as_mut_slice())
        .map_err(|e| e.to_string())?;
    Ok(kek)
}

/// Wrap the 32-byte master key in the versioned V2 format:
/// `GFKW ‖ version ‖ m_cost ‖ t_cost ‖ p_cost ‖ salt(16) ‖ nonce(12) ‖ AES-GCM(master_key)`.
fn wrap_master_key(master_key: &[u8; 32], passphrase: &str) -> Result<Vec<u8>, String> {
    let mut salt = [0u8; WRAP_SALT_LEN];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    let kek = Zeroizing::new(derive_kek(
        passphrase,
        &salt,
        WRAP_MEMORY_KIB,
        WRAP_TIME_COST,
        WRAP_PARALLELISM,
    )?);
    let ct = encrypt(&kek, master_key)?; // nonce(12) ‖ ct
    debug_assert_eq!(ct.len(), WRAP_CIPHERTEXT_LEN);
    let mut out = Vec::with_capacity(WRAP_V2_LEN);
    out.extend_from_slice(WRAP_MAGIC);
    out.push(WRAP_VERSION_V2);
    out.extend_from_slice(&WRAP_MEMORY_KIB.to_be_bytes());
    out.extend_from_slice(&WRAP_TIME_COST.to_be_bytes());
    out.extend_from_slice(&WRAP_PARALLELISM.to_be_bytes());
    out.extend_from_slice(&salt);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Validity check used before accepting `gmacftp.key.wrap` from a sync folder.
pub(crate) fn valid_wrapped_key_len(blob: &[u8]) -> bool {
    blob.len() == WRAP_V1_LEN
        || (blob.len() == WRAP_V2_LEN
            && blob.starts_with(WRAP_MAGIC)
            && blob.get(4) == Some(&WRAP_VERSION_V2))
}

/// Validate a synced vault before cloud code replaces the local copy. This function never calls
/// `resolve_master_key`: if the key is unavailable on a new Mac, the remote ciphertext stays in
/// the sync folder for `unlock()` to decrypt directly after the user supplies the passphrase.
pub(crate) fn validate_synced_vault(blob: &[u8]) -> bool {
    if blob.len() < 12 + 16 || blob.len() > MAX_VAULT_BYTES {
        return false;
    }
    #[cfg(target_os = "macos")]
    let key = match keychain_master_key::load_any() {
        Ok(Some(key)) => Some(key),
        Ok(None) | Err(_) => read_legacy_master_key(
            &config_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join("master.key"),
        ),
    };
    #[cfg(not(target_os = "macos"))]
    let key = read_legacy_master_key(
        &config_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("master.key"),
    );
    let Some(key) = key else {
        return false;
    };
    decode_vault_map(&key, blob).is_ok()
}

/// Unwrap V1/V2 master-key formats. `None` on a wrong passphrase or malformed/corrupt blob.
fn unwrap_master_key(blob: &[u8], passphrase: &str) -> Option<[u8; 32]> {
    if passphrase.len() > 1024 {
        return None;
    }
    let (salt, ciphertext, params) = if blob.len() == WRAP_V1_LEN {
        // V1 used Argon2's defaults. Keep this exact compatibility path separate from V2's
        // explicit serialized parameters.
        (
            &blob[..WRAP_SALT_LEN],
            &blob[WRAP_SALT_LEN..],
            (WRAP_MEMORY_KIB, WRAP_TIME_COST, WRAP_PARALLELISM),
        )
    } else if blob.len() == WRAP_V2_LEN
        && blob.starts_with(WRAP_MAGIC)
        && blob[4] == WRAP_VERSION_V2
    {
        let memory_kib = u32::from_be_bytes(blob[5..9].try_into().ok()?);
        let time_cost = u32::from_be_bytes(blob[9..13].try_into().ok()?);
        let parallelism = u32::from_be_bytes(blob[13..17].try_into().ok()?);
        (
            &blob[17..17 + WRAP_SALT_LEN],
            &blob[WRAP_V2_HEADER_LEN..],
            (memory_kib, time_cost, parallelism),
        )
    } else {
        return None;
    };
    let kek = Zeroizing::new(derive_kek(passphrase, salt, params.0, params.1, params.2).ok()?);
    let plain = Zeroizing::new(decrypt(&kek, ciphertext).ok()?);
    (plain.len() == 32).then(|| {
        let mut k = [0u8; 32];
        k.copy_from_slice(&plain);
        k
    })
}

pub(crate) fn atomic_write(path: &Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    // CRYP-3: random temp name (defeats a pre-planted same-name symlink and concurrent writers)
    // + O_EXCL
    // (create_new) + mode 0600 applied AT creation (the secret is never briefly
    // world-readable at 0644), plus fsync so a crash between write and rename can't
    // leave the vault empty.
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let stem = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("gmacftp");
    let (tmp, mut file) = (0..8)
        .find_map(|_| {
            let suffix = rand::rngs::OsRng.next_u64();
            let tmp = parent.join(format!(".{stem}.tmp-{suffix:016x}"));
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            match options.open(&tmp) {
                Ok(file) => Some(Ok((tmp, file))),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => None,
                Err(error) => Some(Err(error)),
            }
        })
        .unwrap_or_else(|| {
            Err(std::io::Error::new(
                std::io::ErrorKind::AlreadyExists,
                "could not allocate an exclusive temporary file",
            ))
        })?;
    let write_result = file.write_all(data).and_then(|()| file.sync_all());
    drop(file);
    if let Err(error) = write_result {
        let _ = std::fs::remove_file(&tmp);
        return Err(error);
    }
    if let Err(error) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(error);
    }
    // Persist the directory entry too; otherwise a power loss after rename can still lose an
    // otherwise fsynced vault file. Once rename succeeds the new file is authoritative, so a
    // filesystem that refuses directory fsync must not make callers roll back only their
    // in-memory map and diverge from disk.
    #[cfg(unix)]
    if let Err(error) = std::fs::File::open(parent).and_then(|dir| dir.sync_all()) {
        tracing::warn!(path = %parent.display(), %error, "directory fsync unavailable after atomic rename");
    }
    Ok(())
}

/// Open `path` for writing exclusively (O_EXCL `create_new`) with mode 0600 on Unix. An existing
/// path — including a symlink or another operation's active temp — is never removed or followed;
/// callers use unique random temp names and retry with a different name on collision.
///
/// Use this for streaming-download temp files (FTP/SFTP `.part`, updater `.dmg`) that are too
/// large to buffer in memory for [`atomic_write`]. After streaming bytes in, the caller does
/// `sync_all` + `rename` to the final path (rename overwrites the destination atomically and
/// replaces any symlink there with the regular file — also safe).
pub(crate) fn create_exclusive(path: &Path) -> std::io::Result<std::fs::File> {
    fn open_new(path: &Path) -> std::io::Result<std::fs::File> {
        let mut o = std::fs::OpenOptions::new();
        o.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            o.mode(0o600);
        }
        o.open(path)
    }
    open_new(path)
}

#[cfg(unix)]
fn set_mode_0600(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}
#[cfg(not(unix))]
fn set_mode_0600(_path: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{ConnectionId, ConnectionSpec, Protocol};

    fn connection(id: usize, host: &str, user: &str) -> ConnectionSpec {
        ConnectionSpec {
            id: ConnectionId(id),
            name: format!("{host} as {user}"),
            protocol: Protocol::Ftp,
            host: host.to_string(),
            port: 21,
            user: user.to_string(),
            initial_path: String::new(),
            allow_plaintext_ftp: false,
            accept_invalid_tls: false,
        }
    }

    #[test]
    fn keychain_migration_candidates_are_only_saved_complete_connections() {
        let mut candidates = migration_candidates_from_specs(vec![
            connection(1, "ftp.example.com", "alice"),
            connection(2, "ftp.example.com", "alice"), // duplicate metadata row
            connection(3, "sftp.example.com", "bob"),
            connection(4, "", "no-host"),
            connection(5, "anonymous.example.com", ""),
        ]);

        candidates.sort_by_key(CredentialKey::vault_id);
        assert_eq!(candidates.len(), 2);
        assert_eq!(candidates[0].host(), "ftp.example.com");
        assert_eq!(candidates[0].user(), "alice");
        assert_eq!(candidates[1].host(), "sftp.example.com");
        assert_eq!(candidates[1].user(), "bob");
    }

    #[test]
    fn migration_service_prefixes_are_an_explicit_allowlist() {
        let prefixes = known_service_prefixes();
        assert_eq!(prefixes.first(), Some(&SERVICE_PREFIX));
        assert!(prefixes.contains(&SERVICE_PREFIX));
        assert!(prefixes.contains(&"app.mackftp.client"));
        assert!(prefixes
            .iter()
            .all(|prefix| *prefix == SERVICE_PREFIX || RELEASE_SERVICE_PREFIXES.contains(prefix)));
    }

    #[test]
    fn vault_roundtrip_in_temp() {
        // Exercise the crypto helpers directly (the store wraps them; FileVault::open hits
        // the real macOS Keychain on this machine, which we deliberately avoid in unit tests).
        let key = {
            let mut k = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut k);
            k
        };
        let pt = br#"{"a\x00b":"c2VjcmV0"}"#; // {"a\0b":"base64(secret)"}
        let blob = encrypt(&key, pt).unwrap();
        assert_eq!(decrypt(&key, &blob).unwrap(), pt);
        // tamper → decrypt fails
        let mut bad = blob.clone();
        bad[20] ^= 0xff;
        assert!(decrypt(&key, &bad).is_err());
        // A corrupted/truncated vault must report an error, never panic on a nonce slice.
        assert!(decrypt(&key, &[0u8; 11]).is_err());
    }

    #[test]
    fn passphrase_wrap_roundtrip() {
        let mk = {
            let mut k = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut k);
            k
        };
        let wrapped = wrap_master_key(&mk, "correct horse battery").unwrap();
        // correct passphrase → unwraps to the same key
        assert_eq!(
            unwrap_master_key(&wrapped, "correct horse battery"),
            Some(mk)
        );
        // wrong passphrase → None (AES-GCM tag fails)
        assert_eq!(unwrap_master_key(&wrapped, "wrong"), None);
        // tamper with the ciphertext → None
        let mut tampered = wrapped.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0xff;
        assert_eq!(unwrap_master_key(&tampered, "correct horse battery"), None);
        // too-short blob → None
        assert_eq!(unwrap_master_key(&[0u8; 10], "x"), None);
    }

    #[test]
    fn wrapped_master_key_v1_remains_readable_and_v2_has_bounded_format() {
        let master = [7u8; 32];
        let passphrase = "legacy passphrase";
        let salt = [9u8; WRAP_SALT_LEN];
        let kek = derive_kek(
            passphrase,
            &salt,
            WRAP_MEMORY_KIB,
            WRAP_TIME_COST,
            WRAP_PARALLELISM,
        )
        .unwrap();
        let ciphertext = encrypt(&kek, &master).unwrap();
        let mut v1 = salt.to_vec();
        v1.extend_from_slice(&ciphertext);
        assert_eq!(v1.len(), WRAP_V1_LEN);
        assert!(valid_wrapped_key_len(&v1));
        assert_eq!(unwrap_master_key(&v1, passphrase), Some(master));

        let v2 = wrap_master_key(&master, passphrase).unwrap();
        assert_eq!(v2.len(), WRAP_V2_LEN);
        assert!(valid_wrapped_key_len(&v2));
        assert_eq!(unwrap_master_key(&v2, passphrase), Some(master));
        let mut malformed = v2.clone();
        malformed.push(0);
        assert!(!valid_wrapped_key_len(&malformed));
    }

    #[test]
    fn failed_persist_rolls_back_vault_map_mutation() {
        let vault = FileVault {
            map: Mutex::new(HashMap::new()),
            key: Mutex::new(Some([3u8; 32])),
            write_blocked: AtomicBool::new(false),
            // A file cannot be created below a regular file, so atomic_write deterministically
            // fails without depending on permissions of a shared temp directory.
            vault_path: PathBuf::from("/dev/null/gmacftp-vault.bin"),
        };
        let key = CredentialKey::new(Protocol::Ftp, "example.com", 21, "alice").unwrap();
        assert!(vault.set_for(&key, b"secret").is_err());
        assert!(matches!(
            vault.get_for(&key),
            Err(CredentialError::NotFound)
        ));
    }

    #[test]
    fn explicit_v1_migration_copies_to_every_allowlisted_endpoint_only() {
        let ftp = CredentialKey::new(Protocol::Ftp, "example.com", 21, "alice").unwrap();
        let sftp = CredentialKey::new(Protocol::Sftp, "example.com", 22, "alice").unwrap();
        let unlisted = CredentialKey::new(Protocol::Ftp, "example.com", 2121, "alice").unwrap();
        let legacy_id = legacy_v1_id("EXAMPLE.com.", "alice");
        let mut map = HashMap::from([(legacy_id.clone(), B64.encode(b"shared-secret"))]);

        assert_eq!(
            copy_legacy_v1_for_candidates(&mut map, &[ftp.clone(), sftp.clone()]),
            2
        );
        assert!(
            map.contains_key(&legacy_id),
            "v1 remains until endpoint cleanup"
        );
        let vault = FileVault {
            map: Mutex::new(map),
            key: Mutex::new(Some([4u8; 32])),
            write_blocked: AtomicBool::new(false),
            vault_path: PathBuf::from("/dev/null/gmacftp-unused-vault.bin"),
        };
        assert_eq!(vault.get_for(&ftp).unwrap(), b"shared-secret");
        assert_eq!(vault.get_for(&sftp).unwrap(), b"shared-secret");
        assert!(matches!(
            vault.get_for(&unlisted),
            Err(CredentialError::NotFound)
        ));
    }

    #[test]
    fn unreadable_vault_state_blocks_overwrite() {
        let path = std::env::temp_dir().join(format!(
            "gmacftp_blocked_vault_{}_{}",
            std::process::id(),
            rand::rngs::OsRng.next_u64()
        ));
        std::fs::write(&path, b"original-unreadable-vault").unwrap();
        let vault = FileVault {
            map: Mutex::new(HashMap::new()),
            key: Mutex::new(Some([5u8; 32])),
            write_blocked: AtomicBool::new(true),
            vault_path: path.clone(),
        };
        let key = CredentialKey::new(Protocol::Ftp, "example.com", 21, "alice").unwrap();
        assert!(matches!(
            vault.set_for(&key, b"must-not-overwrite"),
            Err(CredentialError::NoStorageAccess)
        ));
        assert_eq!(std::fs::read(&path).unwrap(), b"original-unreadable-vault");
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn vault_parser_rejects_oversized_or_noncanonical_entries() {
        let key = CredentialKey::new(Protocol::Ftp, "example.com", 21, "alice").unwrap();
        let valid = HashMap::from([(key.vault_id(), B64.encode(b"secret"))]);
        assert!(validate_vault_map(&valid).is_ok());

        let invalid_base64 = HashMap::from([(key.vault_id(), "not base64!".to_string())]);
        assert!(validate_vault_map(&invalid_base64).is_err());
        let oversized = HashMap::from([(
            key.vault_id(),
            B64.encode(vec![0u8; MAX_CREDENTIAL_BYTES + 1]),
        )]);
        assert!(validate_vault_map(&oversized).is_err());
    }

    #[test]
    fn local_vault_reader_rejects_oversized_files() {
        let path = std::env::temp_dir().join(format!(
            "gmacftp_local_vault_limit_{}_{}",
            std::process::id(),
            rand::rngs::OsRng.next_u64()
        ));
        std::fs::write(&path, vec![1u8; 65]).unwrap();
        assert!(read_regular_limited(&path, 64).is_err());
        assert_eq!(read_regular_limited(&path, 65).unwrap().len(), 65);
        let _ = std::fs::remove_file(path);
    }

    #[cfg(unix)]
    #[test]
    fn legacy_master_key_never_reads_or_shreds_through_a_symlink() {
        use std::os::unix::fs::symlink;
        let nonce = rand::rngs::OsRng.next_u64();
        let target = std::env::temp_dir().join(format!("gmacftp_master_target_{nonce}"));
        let link = std::env::temp_dir().join(format!("gmacftp_master_link_{nonce}"));
        std::fs::write(&target, [9u8; 32]).unwrap();
        symlink(&target, &link).unwrap();

        assert!(read_legacy_master_key(&link).is_none());
        shred_file(&link);
        assert_eq!(std::fs::read(&target).unwrap(), [9u8; 32]);
        assert!(std::fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink());
        let _ = std::fs::remove_file(link);
        let _ = std::fs::remove_file(target);
    }

    #[cfg(unix)]
    #[test]
    fn create_exclusive_never_removes_or_follows_an_existing_symlink() {
        use rand::RngCore;
        use std::os::unix::fs::symlink;
        let nonce = {
            let mut b = [0u8; 8];
            rand::rngs::OsRng.fill_bytes(&mut b);
            u64::from_le_bytes(b)
        };
        let dir = std::env::temp_dir();
        let target = dir.join(format!("gmacftp_test_target_{nonce}"));
        let link = dir.join(format!("gmacftp_test_link_{nonce}.part"));
        std::fs::write(&target, b"precious").unwrap();
        symlink(&target, &link).unwrap();

        let error = create_exclusive(&link).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::AlreadyExists);
        assert!(
            std::fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_symlink(),
            "create_exclusive must leave an existing path untouched"
        );
        // The symlink's target was NOT touched.
        assert_eq!(
            std::fs::read_to_string(&target).unwrap(),
            "precious",
            "create_exclusive must never write through the planted symlink"
        );

        let _ = std::fs::remove_file(&link);
        let _ = std::fs::remove_file(&target);
    }
}
