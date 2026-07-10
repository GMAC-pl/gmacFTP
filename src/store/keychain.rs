//! macOS Keychain credential store (generic passwords). Built on `keyring` v4's
//! `apple-native-keyring-store` backend. Init of the default store is automatic in v4
//! (do NOT call any global init). Includes the macOS 15+ silent-failure read-back guard.

use super::creds::{CredentialError, CredentialKey, CredentialStore, SERVICE_PREFIX};

#[derive(Default)]
pub struct MacCredentialStore;

impl MacCredentialStore {
    pub fn new() -> Self {
        Self
    }
}

impl CredentialStore for MacCredentialStore {
    fn get(&self, host: &str, user: &str) -> Result<Vec<u8>, CredentialError> {
        let entry = entry_for(host, user)?;
        match entry.get_secret() {
            Ok(bytes) => Ok(bytes),
            Err(keyring::Error::NoEntry) => Err(CredentialError::NotFound),
            Err(e) => Err(map_err(e)),
        }
    }

    fn set(&self, host: &str, user: &str, secret: &[u8]) -> Result<(), CredentialError> {
        let entry = entry_for(host, user)?;
        entry.set_secret(secret).map_err(map_err)?;
        // macOS 15 (Sequoia) can report Ok(()) without persisting — verify with a read-back.
        match entry.get_secret() {
            Ok(read_back) if read_back == secret => Ok(()),
            Ok(_) => Err(CredentialError::ReadbackMismatch),
            Err(keyring::Error::NoEntry) => Err(CredentialError::ReadbackMismatch),
            Err(e) => Err(map_err(e)),
        }
    }

    fn delete(&self, host: &str, user: &str) -> Result<(), CredentialError> {
        let entry = entry_for(host, user)?;
        match entry.delete_credential() {
            Ok(()) => Ok(()),
            Err(keyring::Error::NoEntry) => Ok(()), // idempotent
            Err(e) => Err(map_err(e)),
        }
    }

    fn get_for(&self, key: &CredentialKey) -> Result<Vec<u8>, CredentialError> {
        read_entry(entry_for_v2(key)?)
    }

    fn set_for(&self, key: &CredentialKey, secret: &[u8]) -> Result<(), CredentialError> {
        write_entry(entry_for_v2(key)?, secret)
    }

    fn delete_for(&self, key: &CredentialKey) -> Result<(), CredentialError> {
        delete_entry(entry_for_v2(key)?)
    }
}

fn entry_for(host: &str, user: &str) -> Result<keyring::Entry, CredentialError> {
    let service = format!("{SERVICE_PREFIX}/{host}");
    keyring::Entry::new(&service, user).map_err(map_err)
}

fn entry_for_v2(key: &CredentialKey) -> Result<keyring::Entry, CredentialError> {
    // Keep components explicit in the Keychain service too. The v2 marker avoids colliding with
    // the released `{PREFIX}/{host}` layout and permits a later format migration.
    let service = format!(
        "{SERVICE_PREFIX}/v2/{}/{}/{}",
        key.protocol(),
        key.port(),
        key.host()
    );
    keyring::Entry::new(&service, key.user()).map_err(map_err)
}

fn read_entry(entry: keyring::Entry) -> Result<Vec<u8>, CredentialError> {
    match entry.get_secret() {
        Ok(bytes) => Ok(bytes),
        Err(keyring::Error::NoEntry) => Err(CredentialError::NotFound),
        Err(e) => Err(map_err(e)),
    }
}

fn write_entry(entry: keyring::Entry, secret: &[u8]) -> Result<(), CredentialError> {
    entry.set_secret(secret).map_err(map_err)?;
    // macOS 15 (Sequoia) can report Ok(()) without persisting — verify with a read-back.
    match entry.get_secret() {
        Ok(read_back) if read_back == secret => Ok(()),
        Ok(_) => Err(CredentialError::ReadbackMismatch),
        Err(keyring::Error::NoEntry) => Err(CredentialError::ReadbackMismatch),
        Err(e) => Err(map_err(e)),
    }
}

fn delete_entry(entry: keyring::Entry) -> Result<(), CredentialError> {
    match entry.delete_credential() {
        Ok(()) => Ok(()),
        Err(keyring::Error::NoEntry) => Ok(()), // idempotent
        Err(e) => Err(map_err(e)),
    }
}

/// Map the `#[non_exhaustive]` keyring::Error onto our small CredentialError.
fn map_err(e: keyring::Error) -> CredentialError {
    match e {
        keyring::Error::NoEntry => CredentialError::NotFound,
        keyring::Error::NoStorageAccess(_) => CredentialError::NoStorageAccess,
        other => CredentialError::Other(other.to_string()),
    }
}
