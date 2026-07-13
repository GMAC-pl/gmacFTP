//! Private sibling names used to make remote uploads transactional.
//!
//! Uploading directly to the destination destroys the previous file as soon as STOR/SFTP OPEN
//! starts. A random sibling keeps the old destination intact until every byte has been accepted and
//! the remote handle/data channel has closed successfully.

use crate::net::{validate_ftp_path, NetError};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RemoteStagingPaths {
    pub temporary: String,
    pub backup: String,
}

impl RemoteStagingPaths {
    pub(crate) fn for_destination(destination: &str) -> Result<Self, NetError> {
        Self::build(destination, format!("{:032x}", rand::random::<u128>()))
    }

    pub(crate) fn for_resumable_destination(
        destination: &str,
        token: u64,
    ) -> Result<Self, NetError> {
        if token == 0 {
            return Err(NetError::InvalidPath(
                "upload resume token must not be zero".into(),
            ));
        }
        Self::build(destination, format!("{token:016x}"))
    }

    fn build(destination: &str, temporary_token: String) -> Result<Self, NetError> {
        // This also rejects control characters for FTP. SFTP uses binary framing, but accepting a
        // control-bearing destination here would make diagnostics and future protocol dispatch
        // ambiguous, so all upload paths share the stricter boundary.
        validate_ftp_path(destination)?;
        let destination = destination.trim_end_matches('/');
        if destination.is_empty() {
            return Err(NetError::InvalidPath(
                "upload destination must name a file".into(),
            ));
        }

        let parent = match destination.rfind('/') {
            Some(0) => "/",
            Some(index) => &destination[..index],
            None => "",
        };
        let component = destination.rsplit('/').next().unwrap_or_default();
        if component.is_empty() || matches!(component, "." | "..") {
            return Err(NetError::InvalidPath(
                "upload destination must name a safe file".into(),
            ));
        }

        let sibling = |role: &str, token: &str| {
            let name = format!(".gmacftp-{role}-{token}");
            if parent.is_empty() {
                name
            } else if parent == "/" {
                format!("/{name}")
            } else {
                format!("{parent}/{name}")
            }
        };

        Ok(Self {
            temporary: sibling("upload", &temporary_token),
            // A backup only exists during final promotion and is never resumed. Keep it distinct
            // for every attempt so a stale backup cannot be mistaken for the current target.
            backup: sibling("backup", &format!("{:032x}", rand::random::<u128>())),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn staging_names_are_private_siblings() {
        let paths = RemoteStagingPaths::for_destination("/sites/app/index.html").unwrap();
        assert!(paths.temporary.starts_with("/sites/app/.gmacftp-upload-"));
        assert!(paths.backup.starts_with("/sites/app/.gmacftp-backup-"));
        assert_ne!(paths.temporary, paths.backup);
        assert!(paths.temporary.len() < 255 + "/sites/app/".len());

        let relative = RemoteStagingPaths::for_destination("index.html").unwrap();
        assert!(!relative.temporary.contains('/'));

        let resumable =
            RemoteStagingPaths::for_resumable_destination("/sites/app/index.html", 0x2a).unwrap();
        assert_eq!(
            resumable.temporary,
            "/sites/app/.gmacftp-upload-000000000000002a"
        );
        assert!(RemoteStagingPaths::for_resumable_destination("index.html", 0).is_err());
    }

    #[test]
    fn staging_names_reject_non_file_destinations_and_controls() {
        assert!(RemoteStagingPaths::for_destination("/").is_err());
        assert!(RemoteStagingPaths::for_destination("..").is_err());
        assert!(RemoteStagingPaths::for_destination("ok\r\nDELE file").is_err());
    }
}
