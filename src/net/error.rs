//! Network errors unified across FTP (suppaftp) and SFTP (russh).

/// A new, as-yet-untrusted SSH host key presented by an SFTP server.
///
/// The networking layer never persists this value automatically. The UI must show both fields
/// to the user, have them verify the fingerprint through an independent channel, and call
/// [`crate::net::sftp::trust_host_key`] only after an explicit confirmation. Reconnecting then
/// uses the pinned fingerprint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostKeyChallenge {
    endpoint: String,
    fingerprint: String,
}

impl HostKeyChallenge {
    pub(crate) fn new(endpoint: String, fingerprint: String) -> Self {
        Self {
            endpoint,
            fingerprint,
        }
    }

    /// Host and port this key was presented for, e.g. `sftp.example.com:22`.
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// SHA-256 SSH host-key fingerprint to show and verify.
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }
}

impl std::fmt::Display for HostKeyChallenge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "SFTP host key for {} is not trusted yet. Verify fingerprint {} through an independent channel, then explicitly approve it.",
            self.endpoint, self.fingerprint
        )
    }
}

#[derive(Debug, thiserror::Error)]
pub enum NetError {
    #[error("FTP error: {0}")]
    Ftp(String),
    #[error("SFTP/SSH error: {0}")]
    Ssh(String),
    #[error("host key verification failed: {0}")]
    HostKey(String),
    #[error("{0}")]
    HostKeyTrustRequired(HostKeyChallenge),
    #[error("authentication failed for {0}")]
    AuthFailed(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("background task failed: {0}")]
    Join(String),
    #[error("missing credential")]
    MissingCredential,
    #[error("unsafe path: {0}")]
    InvalidPath(String),
    #[error("transfer cancelled")]
    Cancelled,
}

impl NetError {
    pub(crate) fn from_ftp(e: suppaftp::FtpError) -> Self {
        NetError::Ftp(e.to_string())
    }
}
