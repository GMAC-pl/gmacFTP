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

/// An FTPS leaf certificate that is not covered by normal platform trust, or that differs from an
/// endpoint pin. The password has not been sent when this challenge is created.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsCertificateChallenge {
    endpoint: String,
    fingerprint: String,
    previous_fingerprint: Option<String>,
}

impl TlsCertificateChallenge {
    pub(crate) fn new(
        endpoint: String,
        fingerprint: String,
        previous_fingerprint: Option<String>,
    ) -> Self {
        Self {
            endpoint,
            fingerprint,
            previous_fingerprint,
        }
    }

    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    pub fn previous_fingerprint(&self) -> Option<&str> {
        self.previous_fingerprint.as_deref()
    }
}

impl std::fmt::Display for TlsCertificateChallenge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(previous) = self.previous_fingerprint() {
            write!(
                f,
                "FTPS certificate for {} changed from {} to {}; verify it independently before replacing the pin",
                self.endpoint, previous, self.fingerprint
            )
        } else {
            write!(
                f,
                "FTPS certificate for {} is not trusted; verify fingerprint {} independently before trusting it",
                self.endpoint, self.fingerprint
            )
        }
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
    #[error("{0}")]
    TlsCertificateTrustRequired(TlsCertificateChallenge),
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
    #[error("local upload source changed after it was queued; add it to the queue again")]
    UploadSourceChanged,
}

impl NetError {
    pub(crate) fn from_ftp(e: suppaftp::FtpError) -> Self {
        NetError::Ftp(e.to_string())
    }

    /// Whether repeating the same operation may succeed without changing credentials, trust, or
    /// the requested paths. This deliberately errs on the side of *not* retrying permanent errors:
    /// automatic retries must never turn a bad password or a permission problem into a login storm.
    pub(crate) fn is_retryable(&self) -> bool {
        match self {
            Self::Io(error) => matches!(
                error.kind(),
                std::io::ErrorKind::BrokenPipe
                    | std::io::ErrorKind::ConnectionAborted
                    | std::io::ErrorKind::ConnectionRefused
                    | std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::Interrupted
                    | std::io::ErrorKind::NotConnected
                    | std::io::ErrorKind::TimedOut
                    | std::io::ErrorKind::UnexpectedEof
                    | std::io::ErrorKind::WouldBlock
            ),
            Self::Ftp(message) | Self::Ssh(message) => protocol_error_may_be_transient(message),
            Self::Join(_) => true,
            Self::HostKey(_)
            | Self::HostKeyTrustRequired(_)
            | Self::TlsCertificateTrustRequired(_)
            | Self::AuthFailed(_)
            | Self::MissingCredential
            | Self::InvalidPath(_)
            | Self::Cancelled
            | Self::UploadSourceChanged => false,
        }
    }
}

fn protocol_error_may_be_transient(message: &str) -> bool {
    let message = message.to_ascii_lowercase();
    // FTP/SFTP dependencies flatten many server replies to strings. Reject the common permanent
    // classes explicitly and retry only the remainder (disconnects, timeouts, busy servers, etc.).
    ![
        "authentication",
        "permission denied",
        "access denied",
        "not permitted",
        "no such file",
        "not found",
        "invalid path",
        "host key",
        "certificate",
        "login incorrect",
        "bad password",
        "unsupported",
    ]
    .iter()
    .any(|marker| message.contains(marker))
}

#[cfg(test)]
mod retry_tests {
    use super::NetError;

    #[test]
    fn retries_transient_transport_errors_only() {
        assert!(NetError::Io(std::io::Error::from(std::io::ErrorKind::TimedOut)).is_retryable());
        assert!(NetError::Ssh("connection reset by peer".into()).is_retryable());
        assert!(
            !NetError::Io(std::io::Error::from(std::io::ErrorKind::PermissionDenied))
                .is_retryable()
        );
        assert!(!NetError::Ftp("530 Login incorrect".into()).is_retryable());
        assert!(!NetError::InvalidPath("../secret".into()).is_retryable());
        assert!(!NetError::UploadSourceChanged.is_retryable());
    }
}
