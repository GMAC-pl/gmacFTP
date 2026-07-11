//! A connection's metadata. Passwords NEVER live here — they go straight to the
//! Keychain during import. This struct is the only thing the UI/state ever holds.

use super::Protocol;

#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum SftpAuth {
    #[default]
    Password,
    PrivateKey,
    Agent,
}

/// Index into the App's `Vec<ConnectionSpec>` — stable for the app's lifetime
/// (seed connections load first, user-added ones append; the list never reorders).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct ConnectionId(pub usize);

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ConnectionSpec {
    pub id: ConnectionId,
    pub name: String,
    pub protocol: Protocol,
    pub host: String,
    pub port: u16,
    pub user: String,
    #[serde(default)]
    pub initial_path: String,
    /// Legacy FTP is unencrypted. It is opt-in per saved host only, so approving one old/LAN
    /// server cannot silently permit a TLS-downgrade to plaintext for another connection.
    #[serde(default)]
    pub allow_plaintext_ftp: bool,
    /// Certificate exceptions are security decisions for one endpoint, never a global switch.
    /// `Settings.accept_any_cert` remains readable only as legacy UI state during migration.
    #[serde(default)]
    pub accept_invalid_tls: bool,
    /// SFTP authentication method. FTP always uses a password.
    #[serde(default)]
    pub sftp_auth: SftpAuth,
    /// User-selected private-key path; the key itself is never copied into app storage or sync.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sftp_private_key: Option<String>,
}

impl ConnectionSpec {
    /// Effective port — fall back to the protocol default if 0.
    pub fn effective_port(&self) -> u16 {
        if self.port == 0 {
            self.protocol.default_port()
        } else {
            self.port
        }
    }

    /// Human label for the toolbar / connection manager, e.g. `ftp.example.com (FTP)`.
    pub fn display_label(&self) -> String {
        format!("{} ({})", self.host, self.protocol_label())
    }

    fn protocol_label(&self) -> &'static str {
        // The net layer upgrades FTP to FTPS when the server allows TLS, so the label
        // stays "FTP" — the actual transport is decided at connect time.
        match self.protocol {
            Protocol::Ftp => "FTP",
            Protocol::Sftp => "SFTP",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(port: u16, proto: Protocol) -> ConnectionSpec {
        ConnectionSpec {
            id: ConnectionId(0),
            name: "x".into(),
            protocol: proto,
            host: "host".into(),
            port,
            user: "u".into(),
            initial_path: String::new(),
            allow_plaintext_ftp: false,
            accept_invalid_tls: false,
            sftp_auth: SftpAuth::Password,
            sftp_private_key: None,
        }
    }

    #[test]
    fn effective_port_falls_back() {
        assert_eq!(spec(0, Protocol::Ftp).effective_port(), 21);
        assert_eq!(spec(0, Protocol::Sftp).effective_port(), 22);
        assert_eq!(spec(55000, Protocol::Sftp).effective_port(), 55000);
    }

    #[test]
    fn old_connection_json_defaults_to_password_authentication() {
        let json = r#"{
            "id": 0,
            "name": "old",
            "protocol": "sftp",
            "host": "example.test",
            "port": 22,
            "user": "alice"
        }"#;
        let decoded: ConnectionSpec = serde_json::from_str(json).unwrap();
        assert_eq!(decoded.sftp_auth, SftpAuth::Password);
        assert_eq!(decoded.sftp_private_key, None);
    }
}
