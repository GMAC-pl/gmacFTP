//! A connection's metadata. Passwords NEVER live here — they go straight to the
//! Keychain during import. This struct is the only thing the UI/state ever holds.

use super::Protocol;

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
        }
    }

    #[test]
    fn effective_port_falls_back() {
        assert_eq!(spec(0, Protocol::Ftp).effective_port(), 21);
        assert_eq!(spec(0, Protocol::Sftp).effective_port(), 22);
        assert_eq!(spec(55000, Protocol::Sftp).effective_port(), 55000);
    }
}
