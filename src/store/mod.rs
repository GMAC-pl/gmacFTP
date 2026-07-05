//! Persistent storage: an encrypted private vault for secrets (no macOS Keychain prompt),
//! config-dir JSON for connection metadata. The Keychain is kept only as a one-time
//! migration source inside [`MigratingStore`].

pub mod cloud;
pub mod connections;
pub mod creds;
#[cfg(target_os = "macos")]
pub mod keychain;
pub mod memory;
pub mod settings;
pub mod vault;

pub use connections::{load_filezilla, load_metadata, load_seed, save_metadata, ImportError};
pub use creds::{CredentialError, CredentialStore, SERVICE_PREFIX};
#[cfg(target_os = "macos")]
pub use keychain::MacCredentialStore;
pub use memory::InMemoryStore;
pub use vault::{FileVault, MigratingStore};

/// The credential store to use: the encrypted private vault with lazy Keychain migration,
/// so reads are silent (no macOS prompt) once a credential is in the vault.
pub fn default_store() -> MigratingStore {
    MigratingStore::new()
}
