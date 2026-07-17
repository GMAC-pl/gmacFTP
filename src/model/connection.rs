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
    KeyboardInteractive,
}

#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum FtpDataMode {
    #[default]
    Passive,
    Active,
}

#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum FtpFilenameEncoding {
    /// Keep the server default. Commands remain Unicode-safe Rust strings.
    #[default]
    Auto,
    /// Require the server to accept `OPTS UTF8 ON` before any file operation.
    Utf8,
}

#[derive(
    Debug, Clone, Copy, Default, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum FtpTlsMode {
    /// RFC 4217 explicit FTPS: connect on the FTP port, then issue `AUTH TLS` before login.
    #[default]
    Explicit,
    /// Legacy implicit FTPS: TLS starts immediately, conventionally on port 990.
    Implicit,
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
    #[serde(default)]
    pub group: String,
    #[serde(default)]
    pub tags: Vec<String>,
    /// Connection/operation timeout override in seconds. `None` uses protocol defaults.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_secs: Option<u64>,
    /// SFTP keepalive interval. `None` uses the default, `Some(0)` explicitly disables it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keepalive_interval_secs: Option<u64>,
    #[serde(default)]
    pub ftp_data_mode: FtpDataMode,
    #[serde(default)]
    pub ftp_filename_encoding: FtpFilenameEncoding,
    /// Explicit FTPS is the backwards-compatible default. Implicit FTPS is opt-in for legacy
    /// servers that require TLS from the first byte of the control connection.
    #[serde(default)]
    pub ftp_tls_mode: FtpTlsMode,
    /// Optional unauthenticated CONNECT proxy. Credentials are deliberately unsupported here so
    /// secrets can never be serialized into connection metadata or synchronized accidentally.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy_url: Option<String>,
    /// Resolve SFTP host aliases and safe connection parameters from `~/.ssh/config`.
    #[serde(default)]
    pub use_ssh_config: bool,
    /// Optional single SSH jump host (`[user@]host[:port]` or an alias from SSH config).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_proxy_jump: Option<String>,
    /// Plaintext-only FTP is unencrypted. It is an explicit transport mode per saved host, so a
    /// TLS error can never silently downgrade this or any other connection.
    #[serde(default)]
    pub allow_plaintext_ftp: bool,
    /// Certificate exceptions are security decisions for one endpoint, never a global switch.
    /// `Settings.accept_any_cert` remains readable only as legacy UI state during migration.
    #[serde(default)]
    pub accept_invalid_tls: bool,
    /// SHA-256 fingerprint of the exact FTPS leaf certificate trusted for this endpoint. A pin is
    /// safer than disabling certificate verification: a changed certificate fails closed before
    /// USER/PASS is sent. A pane may also hold a session-only pin without persisting this struct.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_pinned_sha256: Option<String>,
    /// Optional local PEM certificate chain and unencrypted PKCS#8 PEM private key used for FTPS
    /// mutual TLS. These are paths only: file contents never enter metadata, diagnostics or sync.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_client_cert: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_client_key: Option<String>,
    /// SFTP authentication method. FTP always uses a password.
    #[serde(default)]
    pub sftp_auth: SftpAuth,
    /// User-selected private-key path; the key itself is never copied into app storage or sync.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sftp_private_key: Option<String>,
    /// Optional parallel-file limit for this endpoint. `None` uses the global conservative
    /// per-server default; values are validated when metadata is loaded or saved.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transfer_concurrency: Option<usize>,
}

impl ConnectionSpec {
    /// Effective port — fall back to the protocol default if 0.
    pub fn effective_port(&self) -> u16 {
        if self.port == 0 {
            if self.protocol == Protocol::Ftp
                && !self.allow_plaintext_ftp
                && self.ftp_tls_mode == FtpTlsMode::Implicit
            {
                990
            } else {
                self.protocol.default_port()
            }
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
            group: String::new(),
            tags: Vec::new(),
            timeout_secs: None,
            keepalive_interval_secs: None,
            ftp_data_mode: FtpDataMode::Passive,
            ftp_filename_encoding: FtpFilenameEncoding::Auto,
            ftp_tls_mode: FtpTlsMode::Explicit,
            proxy_url: None,
            use_ssh_config: false,
            ssh_proxy_jump: None,
            allow_plaintext_ftp: false,
            accept_invalid_tls: false,
            tls_pinned_sha256: None,
            tls_client_cert: None,
            tls_client_key: None,
            sftp_auth: SftpAuth::Password,
            sftp_private_key: None,
            transfer_concurrency: None,
        }
    }

    #[test]
    fn effective_port_falls_back() {
        assert_eq!(spec(0, Protocol::Ftp).effective_port(), 21);
        let mut implicit = spec(0, Protocol::Ftp);
        implicit.ftp_tls_mode = FtpTlsMode::Implicit;
        assert_eq!(implicit.effective_port(), 990);
        implicit.allow_plaintext_ftp = true;
        assert_eq!(implicit.effective_port(), 21);
        implicit.port = 2121;
        assert_eq!(implicit.effective_port(), 2121);
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
        assert_eq!(decoded.ftp_data_mode, FtpDataMode::Passive);
        assert_eq!(decoded.ftp_filename_encoding, FtpFilenameEncoding::Auto);
        assert_eq!(decoded.ftp_tls_mode, FtpTlsMode::Explicit);
        assert_eq!(decoded.tls_client_cert, None);
        assert_eq!(decoded.tls_client_key, None);
        assert_eq!(decoded.proxy_url, None);
        assert!(!decoded.use_ssh_config);
        assert_eq!(decoded.ssh_proxy_jump, None);
        assert_eq!(decoded.timeout_secs, None);
        assert_eq!(decoded.keepalive_interval_secs, None);
    }
}
