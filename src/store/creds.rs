//! Credential storage abstraction. Passwords NEVER live in app state — only here,
//! behind the macOS Keychain (or an in-memory stand-in for tests/non-macOS).

/// Reverse-DNS service prefix. The full Keychain service is `{PREFIX}/{host}`; the
/// Keychain account is the username. That `(service, account)` pair is the unique key.
pub const SERVICE_PREFIX: &str = env!("MACKFTP_BUNDLE_ID");

#[derive(Debug, thiserror::Error)]
pub enum CredentialError {
    #[error("credential not found")]
    NotFound,
    #[error("keychain locked or access denied")]
    NoStorageAccess,
    #[error("keychain write succeeded but read-back mismatch (macOS silent-failure)")]
    ReadbackMismatch,
    #[error("keychain error: {0}")]
    Other(String),
}

/// Platform-agnostic secret store. Implementations: [`MacCredentialStore`] (Keychain,
/// macOS only) and [`InMemoryStore`] (tests / fallback).
pub trait CredentialStore: Send + Sync {
    fn get(&self, host: &str, user: &str) -> Result<Vec<u8>, CredentialError>;
    fn set(&self, host: &str, user: &str, secret: &[u8]) -> Result<(), CredentialError>;
    /// Idempotent: deleting a missing credential is OK.
    fn delete(&self, host: &str, user: &str) -> Result<(), CredentialError>;
    /// True when the vault is present but undecryptable because the master key isn't available
    /// locally AND a wrapped key exists in the sync folder — i.e. the user's sync passphrase is
    /// needed. Default: never locked (plain Keychain/in-memory stores have no passphrase gate).
    fn is_locked(&self) -> bool {
        false
    }
    /// Unlock the vault with the sync passphrase (unwrap the synced master key + re-decrypt the
    /// vault in place). Returns true on success. Default: no-op (returns false).
    fn unlock(&self, _passphrase: &str) -> bool {
        false
    }
}
