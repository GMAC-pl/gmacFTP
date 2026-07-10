//! In-memory credential store — for unit tests and as a non-macOS fallback.

use std::collections::HashMap;
use std::sync::Mutex;

use super::creds::{CredentialError, CredentialKey, CredentialStore};

#[derive(Default)]
pub struct InMemoryStore {
    legacy_secrets: Mutex<HashMap<(String, String), Vec<u8>>>,
    v2_secrets: Mutex<HashMap<CredentialKey, Vec<u8>>>,
}

impl CredentialStore for InMemoryStore {
    fn get(&self, host: &str, user: &str) -> Result<Vec<u8>, CredentialError> {
        self.legacy_secrets
            .lock()
            .expect("InMemoryStore poisoned")
            .get(&(host.to_string(), user.to_string()))
            .cloned()
            .ok_or(CredentialError::NotFound)
    }

    fn set(&self, host: &str, user: &str, secret: &[u8]) -> Result<(), CredentialError> {
        self.legacy_secrets
            .lock()
            .expect("InMemoryStore poisoned")
            .insert((host.to_string(), user.to_string()), secret.to_vec());
        Ok(())
    }

    fn delete(&self, host: &str, user: &str) -> Result<(), CredentialError> {
        self.legacy_secrets
            .lock()
            .expect("InMemoryStore poisoned")
            .remove(&(host.to_string(), user.to_string()));
        Ok(())
    }

    fn get_for(&self, key: &CredentialKey) -> Result<Vec<u8>, CredentialError> {
        self.v2_secrets
            .lock()
            .expect("InMemoryStore poisoned")
            .get(key)
            .cloned()
            .ok_or(CredentialError::NotFound)
    }

    fn set_for(&self, key: &CredentialKey, secret: &[u8]) -> Result<(), CredentialError> {
        self.v2_secrets
            .lock()
            .expect("InMemoryStore poisoned")
            .insert(key.clone(), secret.to_vec());
        Ok(())
    }

    fn delete_for(&self, key: &CredentialKey) -> Result<(), CredentialError> {
        self.v2_secrets
            .lock()
            .expect("InMemoryStore poisoned")
            .remove(key);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_delete() {
        let s = InMemoryStore::default();
        assert!(matches!(s.get("h", "u"), Err(CredentialError::NotFound)));
        s.set("h", "u", b"secret").unwrap();
        assert_eq!(s.get("h", "u").unwrap(), b"secret");
        s.delete("h", "u").unwrap();
        assert!(matches!(s.get("h", "u"), Err(CredentialError::NotFound)));
        // idempotent delete
        s.delete("h", "u").unwrap();
    }

    #[test]
    fn v2_credentials_are_endpoint_bound_and_do_not_fall_back_to_legacy() {
        let s = InMemoryStore::default();
        s.set("example.com", "alice", b"legacy").unwrap();
        let ftp =
            CredentialKey::new(crate::model::Protocol::Ftp, "EXAMPLE.com.", 21, "alice").unwrap();
        let sftp =
            CredentialKey::new(crate::model::Protocol::Sftp, "example.com", 22, "alice").unwrap();

        assert!(matches!(s.get_for(&ftp), Err(CredentialError::NotFound)));
        s.set_for(&ftp, b"ftp-secret").unwrap();
        s.set_for(&sftp, b"sftp-secret").unwrap();
        assert_eq!(s.get_for(&sftp).unwrap(), b"sftp-secret");
        assert_eq!(s.get_for(&ftp).unwrap(), b"ftp-secret");
    }
}
