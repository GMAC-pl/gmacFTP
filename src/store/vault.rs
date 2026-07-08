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
//! `MigratingStore` wraps the vault and falls back to the Keychain ONCE per credential
//! (lazy migration), writing through to the vault so the next read is silent.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use rand::RngCore;
use zeroize::Zeroizing;

use super::creds::{CredentialError, CredentialStore};
#[cfg(target_os = "macos")]
use super::keychain::MacCredentialStore;

fn config_dir() -> Option<PathBuf> {
    directories::ProjectDirs::from(
        env!("MACKFTP_CONFIG_QUALIFIER"),
        env!("MACKFTP_CONFIG_ORGANIZATION"),
        env!("MACKFTP_CONFIG_APPLICATION"),
    )
    .map(|pd| pd.config_dir().to_path_buf())
}

/// NUL-separated "host\x00user" — hostnames/usernames never contain NUL.
fn pack_key(host: &str, user: &str) -> String {
    format!("{host}\x00{user}")
}

/// Encrypted at-rest credential store (in-memory decrypted map mirrored to vault.bin).
pub struct FileVault {
    map: Mutex<HashMap<String, String>>, // "host\x00user" -> base64(secret)
    key: Mutex<[u8; 32]>,                // resolved at open; replaced in place on passphrase unlock
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

        let key = resolve_master_key(&key_path);
        let map = match std::fs::read(&vault_path) {
            Ok(blob) if blob.len() > 12 => match decrypt(&key, &blob) {
                Ok(plaintext) => {
                    match serde_json::from_slice::<HashMap<String, String>>(&plaintext) {
                        Ok(m) => m,
                        Err(e) => {
                            tracing::warn!(error = %e, "vault parse failed; starting empty");
                            preserve_unreadable(&vault_path);
                            HashMap::new()
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, "vault decrypt failed; starting empty");
                    preserve_unreadable(&vault_path);
                    HashMap::new()
                }
            },
            _ => HashMap::new(),
        };
        Self {
            map: Mutex::new(map),
            key: Mutex::new(key),
            vault_path,
        }
    }

    fn persist(&self) -> Result<(), CredentialError> {
        // The plaintext JSON of ALL secrets is the most sensitive transient buffer — wipe it.
        let plaintext = {
            let map = self
                .map
                .lock()
                .map_err(|_| CredentialError::Other("vault mutex poisoned".to_string()))?;
            serde_json::to_vec(&*map)
                .map(Zeroizing::new)
                .map_err(|e| CredentialError::Other(e.to_string()))?
        };
        // Reuse the in-memory key (Keychain-resolved at open) — do NOT re-hit the Keychain
        // or the master.key file on every write.
        let key = *self.key.lock().unwrap_or_else(|e| e.into_inner());
        let blob = encrypt(&key, &plaintext).map_err(CredentialError::Other)?;
        atomic_write(&self.vault_path, &blob).map_err(|e| CredentialError::Other(e.to_string()))?;
        // Best-effort mirror of vault.bin (and connections.json) to iCloud if sync is on —
        // push_state warns internally, so it never turns a successful local write into a failure.
        crate::store::cloud::push_state();
        Ok(())
    }

    /// True when the vault came up empty (undecryptable with the locally-available key) AND a
    /// wrapped key exists in the sync folder — i.e. we need the user's passphrase to unlock.
    /// (A genuinely-empty vault has no wrapped key, so it correctly reads as not-locked.)
    pub fn is_locked(&self) -> bool {
        let empty = self.map.lock().map(|m| m.is_empty()).unwrap_or(true);
        empty && crate::store::cloud::read_key().is_some()
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
        let Ok(plaintext) = decrypt(&key, &blob) else {
            return false;
        };
        let Ok(loaded) = serde_json::from_slice::<HashMap<String, String>>(&plaintext) else {
            return false;
        };
        if let Ok(mut k) = self.key.lock() {
            *k = key;
        }
        if let Ok(mut m) = self.map.lock() {
            *m = loaded;
        }
        let _ = atomic_write(&self.vault_path, &blob); // local vault ← synced vault
        #[cfg(target_os = "macos")]
        {
            let sync = crate::store::settings::load().sync_via_icloud;
            let _ = keychain_master_key::store(&key, sync);
            let _ = keychain_passphrase::store(passphrase, true);
        }
        tracing::info!(target: "gmacftp::vault", "vault unlocked + adopted synced state");
        true
    }

    /// One-shot migration: enumerate the legacy per-server Keychain entries (service
    /// `{SERVICE_PREFIX}/host`, account = user) and fold them into this vault in a single
    /// batched persist. ONE Keychain authorization covers all of them (vs N per-server prompts).
    /// After this the vault holds every password → no Keychain fallback prompts + everything
    /// syncs. Returns how many were migrated.
    pub fn migrate_from_keychain(&self) -> usize {
        #[cfg(target_os = "macos")]
        {
            use security_framework::item::{ItemClass, ItemSearchOptions, Limit};
            // ONE Keychain operation reads EVERY generic-password item (one authorization, not
            // one-per-server). The host is the segment after the last '/' in the service, so
            // legacy items saved under ANY service prefix (old bundle id, old app name) match.
            let results = match ItemSearchOptions::new()
                .class(ItemClass::generic_password())
                .limit(Limit::All)
                .load_attributes(true)
                .load_data(true)
                .search()
            {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!(error = %e, "keychain enumerate failed");
                    return 0;
                }
            };
            let mut n = 0;
            if let Ok(mut map) = self.map.lock() {
                for r in results {
                    let Some(dict) = r.simplify_dict() else {
                        continue;
                    };
                    let Some(svc) = dict.get("svce") else {
                        continue;
                    };
                    let Some((_prefix, host)) = svc.rsplit_once('/') else {
                        continue;
                    };
                    let user = dict.get("acct").cloned().unwrap_or_default();
                    let secret = dict
                        .get("v_Data")
                        .or_else(|| dict.get("data"))
                        .cloned()
                        .unwrap_or_default();
                    if !host.is_empty() && !user.is_empty() && !secret.is_empty() {
                        map.insert(pack_key(host, &user), B64.encode(secret.as_bytes()));
                        n += 1;
                    }
                }
            }
            if n > 0 {
                tracing::info!("migrated {n} keychain credentials into the vault");
                let _ = self.persist(); // one batched write + sync (best-effort)
            }
            n
        }
        #[cfg(not(target_os = "macos"))]
        0
    }
}

impl CredentialStore for FileVault {
    fn get(&self, host: &str, user: &str) -> Result<Vec<u8>, CredentialError> {
        let key = pack_key(host, user);
        match self.map.lock().expect("vault").get(&key) {
            Some(b64) => B64
                .decode(b64)
                .map_err(|e| CredentialError::Other(e.to_string())),
            None => Err(CredentialError::NotFound),
        }
    }

    fn set(&self, host: &str, user: &str, secret: &[u8]) -> Result<(), CredentialError> {
        let b64 = B64.encode(secret);
        self.map
            .lock()
            .expect("vault")
            .insert(pack_key(host, user), b64);
        self.persist()
    }

    fn delete(&self, host: &str, user: &str) -> Result<(), CredentialError> {
        self.map
            .lock()
            .expect("vault")
            .remove(&pack_key(host, user));
        self.persist()
    }
}

/// Vault first; Keychain as a one-time lazy-migration source. After migration the vault
/// holds every credential, so reads are silent (no macOS prompt).
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
        if let Ok(b) = self.vault.get(host, user) {
            return Ok(b);
        }
        #[cfg(target_os = "macos")]
        {
            if let Ok(b) = self.keychain.get(host, user) {
                let _ = self.vault.set(host, user, &b); // migrate; future reads hit the vault
                tracing::info!(%host, %user, "migrated credential from Keychain to vault");
                return Ok(b);
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
            let _ = self.keychain.delete(host, user);
        }
        Ok(())
    }

    fn is_locked(&self) -> bool {
        self.vault.is_locked()
    }

    fn unlock(&self, passphrase: &str) -> bool {
        self.vault.unlock(passphrase)
    }

    fn migrate_from_keychain(&self) -> usize {
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
fn resolve_master_key(key_path: &Path) -> [u8; 32] {
    let sync = crate::store::settings::load().sync_via_icloud;

    #[cfg(target_os = "macos")]
    {
        if let Some(k) = keychain_master_key::load() {
            return k; // already in the Keychain
        }
        // Auto-unlock: a wrapped key in the sync folder + the passphrase in the Keychain (synced,
        // fixed cross-bundle service) → unwrap the real master key + cache it locally. This is the cross-device path that does NOT depend on the bundle-specific master-key item (so it survives a bundle mismatch).
        if let Some((_, wrapped)) = crate::store::cloud::read_key() {
            if let Some(pp) = keychain_passphrase::load() {
                if let Some(k) = unwrap_master_key(&wrapped, &pp) {
                    let _ = keychain_master_key::store(&k, sync);
                    tracing::info!("unlocked vault master key from synced wrapped key");
                    return k;
                }
            }
        }
    }

    // Legacy plaintext file present → migrate it into the Keychain, then shred.
    if let Ok(bytes) = std::fs::read(key_path) {
        if bytes.len() == 32 {
            let mut k = [0u8; 32];
            k.copy_from_slice(&bytes);
            #[cfg(target_os = "macos")]
            {
                match keychain_master_key::store(&k, sync) {
                    Ok(()) => {
                        tracing::info!("migrated master key from plaintext file into Keychain");
                        shred_file(key_path); // CRYP-1: remove plaintext from disk
                        return k;
                    }
                    Err(e) => {
                        // Keychain refused (access denied). Keep the legacy file so the user
                        // doesn't lose their vault, and surface it.
                        tracing::warn!(error = %e, "Keychain store failed; keeping legacy master.key");
                        return k;
                    }
                }
            }
            #[cfg(not(target_os = "macos"))]
            return k;
        }
    }

    // No key anywhere → generate and store in the Keychain (never hits disk on macOS).
    let mut k = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut k);
    #[cfg(target_os = "macos")]
    {
        if let Err(e) = keychain_master_key::store(&k, sync) {
            tracing::warn!(error = %e, "Keychain store failed; writing emergency master.key fallback");
            let _ = atomic_write(key_path, &k);
            let _ = set_mode_0600(key_path);
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = atomic_write(key_path, &k);
        let _ = set_mode_0600(key_path);
    }
    k
}

/// Best-effort overwrite+unlink. APFS is copy-on-write so this isn't a forensic shred, but
/// removing the plaintext from the live filesystem is the goal.
fn shred_file(path: &Path) {
    if let Ok(meta) = std::fs::metadata(path) {
        let zeros = vec![0u8; meta.len() as usize];
        let _ = std::fs::write(path, &zeros);
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

    fn service() -> String {
        format!("{SERVICE_PREFIX}.master-key")
    }

    /// Store the 32-byte key. `sync=true` writes it as an iCloud-Keychain item (requires the
    /// user to have iCloud Keychain enabled); `sync=false` keeps it device-local.
    pub fn store(key: &[u8], sync: bool) -> Result<(), String> {
        let mut o = PasswordOptions::new_generic_password(&service(), ACCOUNT);
        o.set_access_synchronized(Some(sync)); // kSecAttrSynchronizable
        set_generic_password_options(key, o).map_err(|e| e.to_string())
    }

    /// Build a read/delete query matching BOTH synchronizable and non-synchronizable items
    /// (kSecAttrSynchronizableAny). A plain `get_generic_password` query has NO synchronizable
    /// attribute, so on macOS it matches only NON-synchronizable items — meaning when sync is on
    /// the master key is stored synchronizable and `load()` could NOT see it, a fresh key was
    /// generated each launch, the vault became undecryptable, and every connection re-prompted
    /// the Keychain. Matching both fixes that and lets pull find synced state.
    fn opts_any() -> PasswordOptions {
        let mut o = PasswordOptions::new_generic_password(&service(), ACCOUNT);
        o.set_access_synchronized(None); // kSecAttrSynchronizableAny
        o
    }

    /// Load the key, matching it whether it lives in the device-local or iCloud-syncing store.
    pub fn load() -> Option<[u8; 32]> {
        match generic_password(opts_any()) {
            Ok(bytes) if bytes.len() == 32 => {
                let mut k = [0u8; 32];
                k.copy_from_slice(&bytes);
                Some(k)
            }
            _ => None,
        }
    }

    /// Delete the key (idempotent, both stores). Used if the vault is ever reset, or when
    /// moving the key between stores on a sync toggle.
    #[allow(dead_code)]
    pub fn delete_all() {
        let _ = delete_generic_password_options(opts_any());
    }

    /// Move the master key between the device-local and iCloud-syncing Keychain stores — used
    /// when the user toggles Settings.sync_via_icloud. Lossless: load (either store) → delete
    /// both → re-store in the chosen store. No-op if no key exists yet.
    pub fn promote_to_sync(sync: bool) {
        let Some(k) = load() else { return };
        delete_all();
        let _ = store(&k, sync);
    }
}

// ── macOS Keychain backing for the SYNC PASSPHRASE (FIXED cross-bundle service) ──
// FIXED service (NOT bundle-id derived) so the personal + public bundles SHARE this passphrase
// item — the cross-bundle, cross-device secret that unlocks the synced wrapped master key.
// This is what fixes the bundle-mismatch "missing credential": the master key is bundle-local,
// but the passphrase (which unlocks the synced wrapped key) is shared across bundles.

#[cfg(target_os = "macos")]
mod keychain_passphrase {
    use security_framework::passwords::{generic_password, set_generic_password_options};
    use security_framework::passwords_options::PasswordOptions;

    const SERVICE: &str = "gmacFTP.sync-passphrase";
    const ACCOUNT: &str = "default";

    fn opts_any() -> PasswordOptions {
        let mut o = PasswordOptions::new_generic_password(SERVICE, ACCOUNT);
        o.set_access_synchronized(None); // match both stores on read/delete
        o
    }

    pub fn store(pp: &str, sync: bool) -> Result<(), String> {
        let mut o = PasswordOptions::new_generic_password(SERVICE, ACCOUNT);
        o.set_access_synchronized(Some(sync)); // iCloud Keychain when sync=true
        set_generic_password_options(pp.as_bytes(), o).map_err(|e| e.to_string())
    }

    pub fn load() -> Option<String> {
        let bytes = generic_password(opts_any()).ok()?;
        String::from_utf8(bytes).ok()
    }
}

/// Public entry: move the master key to/from the iCloud-syncing Keychain store.
#[cfg(target_os = "macos")]
pub fn set_master_key_syncable(sync: bool) {
    keychain_master_key::promote_to_sync(sync);
}
#[cfg(not(target_os = "macos"))]
pub fn set_master_key_syncable(_sync: bool) {}

/// Enable sync with a passphrase: wrap the current master key, push the wrapped key to the
/// sync folder, cache the passphrase in the Keychain (fixed cross-bundle service), and mark
/// the passphrase as set. Called from the "set passphrase" dialog when first enabling sync.
pub fn enable_sync_passphrase(passphrase: &str) -> Result<(), String> {
    let dir = config_dir().unwrap_or_else(|| PathBuf::from("."));
    let key = resolve_master_key(&dir.join("master.key"));
    let wrapped = wrap_master_key(&key, passphrase)?;
    crate::store::cloud::push_key(&wrapped);
    #[cfg(target_os = "macos")]
    keychain_passphrase::store(passphrase, true)
        .map_err(|e| format!("passphrase keychain store failed: {e}"))?;
    let mut s = crate::store::settings::load();
    s.sync_passphrase_set = true;
    crate::store::settings::save(&s);
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
        let key = resolve_master_key(&dir.join("master.key"));
        let wrapped = wrap_master_key(&key, &pp)?;
        crate::store::cloud::push_key(&wrapped);
        tracing::info!("re-pushed wrapped master key to the sync folder");
        Ok(())
    }
    #[cfg(not(target_os = "macos"))]
    Err("sync not supported on this platform".into())
}

// ── crypto + io helpers ──

/// Stash the unreadable vault aside so the user can recover/re-import before a later `set()`
/// overwrites it. Without this, a corrupt/undecryptable vault silently becomes empty and the
/// next persist destroys the original. Best-effort (read-only fs just loses the convenience).
fn preserve_unreadable(vault_path: &Path) {
    let Some(stem) = vault_path.file_name().and_then(|s| s.to_str()) else {
        return;
    };
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let backup = vault_path.with_file_name(format!("{stem}.corrupt-{secs}"));
    if std::fs::copy(vault_path, &backup).is_ok() {
        tracing::error!(backup = %backup.display(), "vault unreadable — preserved a copy aside");
    }
}

fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = Aes256Gcm::new_from_slice(&key[..]).map_err(|e| e.to_string())?;
    let mut nonce_bytes = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ct = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| e.to_string())?;
    let mut out = Vec::with_capacity(12 + ct.len());
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    Ok(out)
}

fn decrypt(key: &[u8; 32], blob: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = Aes256Gcm::new_from_slice(&key[..]).map_err(|e| e.to_string())?;
    let nonce = Nonce::from_slice(&blob[..12]);
    cipher
        .decrypt(nonce, &blob[12..])
        .map_err(|e| e.to_string())
}

/// Derive a 32-byte key-encryption-key from the passphrase + salt via Argon2id (library
/// defaults: ~19 MiB / 2 iters / 1 lane — strong against offline brute force on the wrapped
/// key, which only ever protects the password vault).
fn derive_kek(passphrase: &str, salt: &[u8]) -> Result<[u8; 32], String> {
    let argon2 = argon2::Argon2::default();
    let mut kek = [0u8; 32];
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, kek.as_mut_slice())
        .map_err(|e| e.to_string())?;
    Ok(kek)
}

/// Wrap the 32-byte master key: `salt(16) ‖ nonce(12) ‖ AES-256-GCM(master_key)`, where the
/// AES key is `Argon2id(passphrase, salt)`.
fn wrap_master_key(master_key: &[u8; 32], passphrase: &str) -> Result<Vec<u8>, String> {
    let mut salt = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    let kek = derive_kek(passphrase, &salt)?;
    let ct = encrypt(&kek, master_key)?; // nonce(12) ‖ ct
    let mut out = Vec::with_capacity(16 + ct.len());
    out.extend_from_slice(&salt);
    out.extend_from_slice(&ct);
    Ok(out)
}

/// Unwrap the master key. `None` on a wrong passphrase or a corrupt blob (AES-GCM tag fails).
fn unwrap_master_key(blob: &[u8], passphrase: &str) -> Option<[u8; 32]> {
    if blob.len() < 16 + 12 + 32 {
        return None;
    }
    let (salt, rest) = blob.split_at(16);
    let kek = derive_kek(passphrase, salt).ok()?;
    let plain = decrypt(&kek, rest).ok()?;
    (plain.len() == 32).then(|| {
        let mut k = [0u8; 32];
        k.copy_from_slice(&plain);
        k
    })
}

pub(crate) fn atomic_write(path: &Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    // CRYP-3: pid-suffixed temp name (defeats a pre-planted same-name symlink) + O_EXCL
    // (create_new) + mode 0600 applied AT creation (the secret is never briefly
    // world-readable at 0644), plus fsync so a crash between write and rename can't
    // leave the vault empty.
    let tmp = path.with_extension(format!("tmp.{}", std::process::id()));

    let write_tmp = || -> std::io::Result<()> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&tmp)?;
            f.write_all(data)?;
            f.sync_all()?;
        }
        #[cfg(not(unix))]
        {
            std::fs::write(&tmp, data)?;
            set_mode_0600(&tmp)?;
        }
        Ok(())
    };

    if let Err(e) = write_tmp() {
        // A stale temp from a crashed prior run (same pid — rare) blocks create_new; remove
        // it and retry. remove_file on a symlink unlinks the link, NOT its target, so this
        // stays symlink-safe.
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            let _ = std::fs::remove_file(&tmp);
            write_tmp()?;
        } else {
            return Err(e);
        }
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// Open `path` for writing exclusively (O_EXCL `create_new`) with mode 0600 on Unix, defeating a
/// pre-planted same-name symlink: if the path already exists (a stale `.part` from a crashed
/// prior run, or a maliciously planted symlink), `remove_file` it first — unlinking a symlink
/// removes the link itself, never its target — then retry the exclusive create.
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
    match open_new(path) {
        Ok(f) => Ok(f),
        // A stale temp (or a pre-planted symlink). remove_file on a symlink unlinks the link,
        // NOT its target — same symlink-safety contract as atomic_write (CRYP-3).
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            let _ = std::fs::remove_file(path);
            open_new(path)
        }
        Err(e) => Err(e),
    }
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

    #[cfg(unix)]
    #[test]
    fn create_exclusive_defeats_planted_symlink() {
        // NEW-1 regression guard: a pre-planted `<dest>.part` symlink must NOT be followed —
        // create_exclusive unlinks the symlink and creates a regular file, leaving the
        // symlink's target untouched.
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

        let f = create_exclusive(&link).expect("exclusive open must succeed despite the symlink");
        drop(f);

        // The path is now a regular file, not a symlink.
        assert!(
            std::fs::symlink_metadata(&link)
                .unwrap()
                .file_type()
                .is_file(),
            "create_exclusive must replace the symlink with a regular file"
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
