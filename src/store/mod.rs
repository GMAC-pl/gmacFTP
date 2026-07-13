//! Persistent storage: an encrypted private vault for secrets (no macOS Keychain prompt),
//! config-dir JSON for connection metadata. The Keychain is kept only as a one-time
//! migration source inside [`MigratingStore`].

pub mod backup;
pub mod cloud;
pub mod connections;
pub mod creds;
#[cfg(target_os = "macos")]
pub mod keychain;
pub mod memory;
pub mod settings;
pub mod vault;

pub use connections::{load_filezilla, load_metadata, load_seed, save_metadata, ImportError};
pub use creds::{canonical_host, CredentialError, CredentialKey, CredentialStore, SERVICE_PREFIX};
#[cfg(target_os = "macos")]
pub use keychain::MacCredentialStore;
pub use memory::InMemoryStore;
pub use vault::{FileVault, MigratingStore};

/// Crash-safe, private (0600 on Unix) writer for explicit user exports. The destination is
/// replaced atomically through an unpredictable sibling temporary file; callers remain
/// responsible for applying an artifact-specific size limit before invoking it.
pub fn write_private_atomic(path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
    vault::atomic_write(path, data)
}

/// The credential store to use: the encrypted private vault. Legacy Keychain entries are copied
/// only by the explicit, local-metadata-allowlisted migration before normal reads begin.
pub fn default_store() -> MigratingStore {
    MigratingStore::new()
}
