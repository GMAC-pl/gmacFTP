//! Credential storage abstraction. Passwords NEVER live in app state — only here,
//! behind the macOS Keychain (or an in-memory fallback on non-macOS platforms).

use crate::model::{ConnectionSpec, Protocol};

/// Reverse-DNS service prefix used by the Keychain backend.
pub const SERVICE_PREFIX: &str = env!("MACKFTP_BUNDLE_ID");

/// Versioned, endpoint-bound identity for a stored credential.
///
/// Version 1 used only `(host, user)`, which could accidentally reuse a password after a
/// connection was edited from FTP to SFTP or to another port. Version 2 binds every secret to
/// the protocol, canonical host, effective port and account. The serialized identifier is kept
/// private to the store implementations; its `v2` marker makes future migrations explicit.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CredentialKey {
    protocol: Protocol,
    host: String,
    port: u16,
    user: String,
}

impl CredentialKey {
    pub fn for_spec(spec: &ConnectionSpec) -> Result<Self, CredentialError> {
        Self::new(spec.protocol, &spec.host, spec.effective_port(), &spec.user)
    }

    pub fn new(
        protocol: Protocol,
        host: impl AsRef<str>,
        port: u16,
        user: impl AsRef<str>,
    ) -> Result<Self, CredentialError> {
        let host = canonical_host(host.as_ref())?;
        let user = user.as_ref();
        if user.is_empty() || user.len() > 512 || contains_control(user) {
            return Err(CredentialError::InvalidKey("invalid username".to_string()));
        }
        Ok(Self {
            protocol,
            host,
            port: if port == 0 {
                protocol.default_port()
            } else {
                port
            },
            user: user.to_string(),
        })
    }

    pub fn protocol(&self) -> Protocol {
        self.protocol
    }

    pub fn host(&self) -> &str {
        &self.host
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn user(&self) -> &str {
        &self.user
    }

    /// Stable v2 vault-map identifier. NUL is disallowed in host/account, making this
    /// unambiguous without relying on JSON object key escaping.
    pub(crate) fn vault_id(&self) -> String {
        format!(
            "v2\x00{}\x00{}\x00{}\x00{}",
            self.protocol, self.port, self.host, self.user
        )
    }
}

/// Canonical hostname form shared by every credential backend. It deliberately does not try to
/// perform DNS resolution: resolving could make saved credentials depend on a network response.
pub fn canonical_host(host: &str) -> Result<String, CredentialError> {
    let mut host = host.trim();
    if host.starts_with('[') && host.ends_with(']') && host.len() > 2 {
        host = &host[1..host.len() - 1];
    }
    let host = host.trim_end_matches('.');
    if host.is_empty() || host.len() > 253 || contains_control(host) || host.contains(['/', '\\']) {
        return Err(CredentialError::InvalidKey("invalid host".to_string()));
    }
    Ok(host.to_ascii_lowercase())
}

fn contains_control(value: &str) -> bool {
    value.chars().any(|c| c.is_control())
}

/// Legacy v1 vault identifier. Kept only for a one-way lazy migration into [`CredentialKey`].
pub(crate) fn legacy_v1_id(host: &str, user: &str) -> String {
    format!("{host}\x00{user}")
}

#[derive(Debug, thiserror::Error)]
pub enum CredentialError {
    #[error("credential not found")]
    NotFound,
    #[error("keychain locked or access denied")]
    NoStorageAccess,
    #[error("keychain write succeeded but read-back mismatch (macOS silent-failure)")]
    ReadbackMismatch,
    #[error("invalid credential key: {0}")]
    InvalidKey(String),
    #[error("keychain error: {0}")]
    Other(String),
}

/// Privacy-safe summary of how an encrypted vault relates to the currently saved endpoints.
/// It deliberately exposes only counts: never hosts, accounts, identifiers, or secret bytes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct CredentialHealth {
    pub vault_entries: usize,
    pub endpoint_bound_entries: usize,
    pub legacy_entries: usize,
    pub matching_endpoint_credentials: usize,
    pub recoverable_legacy_credentials: usize,
    pub ambiguous_legacy_credentials: usize,
    pub invalid_endpoint_specs: usize,
}

/// Result of an explicitly confirmed conversion from legacy `(host, user)` records to
/// endpoint-bound records. Ambiguous records are never copied automatically.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LegacyCredentialRecovery {
    pub recovered: usize,
    pub ambiguous: usize,
}

/// Platform-agnostic secret store. Implementations: [`MacCredentialStore`] (Keychain,
/// macOS only) and [`InMemoryStore`] (tests / fallback).
pub trait CredentialStore: Send + Sync {
    /// Legacy v1 read by `(host, user)`. Kept temporarily so older callers compile during the
    /// v2 migration. New connection code must use [`CredentialStore::get_for`].
    fn get(&self, host: &str, user: &str) -> Result<Vec<u8>, CredentialError>;
    /// Legacy v1 write by `(host, user)`. New connection code must use
    /// [`CredentialStore::set_for`].
    fn set(&self, host: &str, user: &str, secret: &[u8]) -> Result<(), CredentialError>;
    /// Idempotent: deleting a missing credential is OK.
    fn delete(&self, host: &str, user: &str) -> Result<(), CredentialError>;

    /// Read a protocol/host/port/account-bound v2 credential. Implementations must not fall back
    /// to `(host, user)`: legacy conversion is an explicit, allowlisted one-time operation.
    fn get_for(&self, key: &CredentialKey) -> Result<Vec<u8>, CredentialError>;

    /// Store a protocol/host/port/account-bound v2 credential.
    fn set_for(&self, key: &CredentialKey, secret: &[u8]) -> Result<(), CredentialError>;

    /// Delete a v2 credential. Legacy cleanup is explicit and happens only after the last saved
    /// endpoint for a `(host, user)` pair disappears.
    fn delete_for(&self, key: &CredentialKey) -> Result<(), CredentialError>;
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
    /// One-shot: migrate this app's known legacy per-server Keychain entries into the vault.
    /// Implementations must not enumerate unrelated Keychain items. Errors must be propagated so
    /// callers never mark an incomplete migration as finished. Default: no migrated entries.
    fn migrate_from_keychain(&self) -> Result<usize, CredentialError> {
        Ok(0)
    }

    /// Return a redacted consistency summary for support/recovery UI. Store implementations that
    /// do not use the encrypted file vault may keep the default empty summary.
    fn credential_health(
        &self,
        _specs: &[ConnectionSpec],
    ) -> Result<CredentialHealth, CredentialError> {
        Ok(CredentialHealth::default())
    }

    /// Convert legacy vault entries only after the user has confirmed that the downloaded server
    /// list is trusted. Implementations must refuse ambiguous `(host, user)` mappings.
    fn recover_legacy_credentials(
        &self,
        _specs: &[ConnectionSpec],
    ) -> Result<LegacyCredentialRecovery, CredentialError> {
        Ok(LegacyCredentialRecovery::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v2_key_canonicalizes_host_and_binds_every_endpoint_component() {
        let a = CredentialKey::new(Protocol::Ftp, " EXAMPLE.com. ", 0, "alice").unwrap();
        let same = CredentialKey::new(Protocol::Ftp, "example.com", 21, "alice").unwrap();
        let other_protocol =
            CredentialKey::new(Protocol::Sftp, "example.com", 22, "alice").unwrap();
        let other_port = CredentialKey::new(Protocol::Ftp, "example.com", 2121, "alice").unwrap();

        assert_eq!(a, same);
        assert_ne!(a.vault_id(), other_protocol.vault_id());
        assert_ne!(a.vault_id(), other_port.vault_id());
        assert!(CredentialKey::new(Protocol::Ftp, "bad/host", 21, "alice").is_err());
        assert!(CredentialKey::new(Protocol::Ftp, "host", 21, "a\0b").is_err());
    }
}
