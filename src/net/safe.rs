//! Path-safety helpers — the chokepoint between server-controlled strings and the two
//! sinks that can be abused: (a) FTP command arguments (CRLF command smuggling, CWE-93)
//! and (b) the local filesystem (path traversal / absolute-path escape, CWE-22).
//!
//! Guards against path traversal / absolute-path escape (CWE-22) and CRLF command smuggling (CWE-93).
//!
//! Two-layer defense:
//!   1. [`validate_ftp_path`] — reject C0 control bytes (incl. CR/LF/NUL) before a string
//!      is forwarded into an FTP command. suppaftp serializes commands as `"{CMD} {arg}\r\n"`
//!      without stripping CR/LF, so a bare `\r` in a server-supplied filename smuggles a
//!      second command on the authenticated control channel.
//!   2. [`sanitize_local_rel`] — normalize a server-controlled relative path so it cannot
//!      escape the user-chosen local root. Rust `PathBuf::join` (a) does NOT normalize `..`
//!      and (b) discards the base entirely when the argument is absolute — so a remote
//!      entry named `../.ssh/authorized_keys` or `/Users/x/evil.plist` would otherwise be
//!      written outside the download dir.

use crate::net::NetError;

/// Reject any C0 control byte (`< 0x20`, incl. CR/LF/NUL/TAB) in a string destined for an
/// FTP command argument. SFTP is immune (binary SSH framing) so this is FTP-only.
pub fn validate_ftp_path(s: &str) -> Result<(), NetError> {
    if s.bytes().any(|b| b < 0x20) {
        return Err(NetError::InvalidPath(
            "remote path contains a control character (CRLF/NUL injection guard)".into(),
        ));
    }
    Ok(())
}

/// Normalize a server-controlled RELATIVE path so it cannot escape the chosen local root.
///
/// - strips a leading `/` (defeats absolute-path injection through `PathBuf::join`),
/// - drops empty / `.` components,
/// - resolves `..` by popping one segment (a leading `..` that would climb above the root
///   is simply dropped — it cannot escape),
/// - rejects any component containing a control byte or exceeding 255 bytes (NAME_MAX).
///
/// Returns a clean relative path with no leading separator. An input that sanitizes to
/// empty (e.g. all `..` or `/`) is rejected.
pub fn sanitize_local_rel(rel: &str) -> Result<String, NetError> {
    let mut out: Vec<&str> = Vec::new();
    for comp in rel.split('/') {
        match comp {
            "" | "." => continue,
            ".." => {
                out.pop();
            }
            other => {
                if other.bytes().any(|b| b < 0x20) {
                    return Err(NetError::InvalidPath(
                        "filename contains a control character".into(),
                    ));
                }
                if other.len() > 255 {
                    return Err(NetError::InvalidPath(
                        "filename exceeds 255 bytes (NAME_MAX)".into(),
                    ));
                }
                out.push(other);
            }
        }
    }
    let joined = out.join("/");
    if joined.is_empty() {
        return Err(NetError::InvalidPath(
            "server filename sanitizes to empty (refusing to write)".into(),
        ));
    }
    Ok(joined)
}

/// Defense-in-depth at the write boundary: assert the resolved target stays inside the
/// user-chosen root. The root must exist (it is the destination directory the user picked);
/// the target's parent is canonicalized and checked to start with the canonicalized root.
/// Cheap best-effort — the primary defense is [`sanitize_local_rel`] at path-build time.
pub fn assert_within(root: &std::path::Path, target: &std::path::Path) -> Result<(), NetError> {
    let canon_root = std::fs::canonicalize(root).map_err(NetError::Io)?;
    let parent = target.parent().filter(|p| !p.as_os_str().is_empty());
    let Some(parent) = parent else {
        // target is a bare filename with no parent — nothing to escape.
        return Ok(());
    };
    let canon_parent = std::fs::canonicalize(parent)
        // parent may not exist yet (folder download with deep server tree) — trust the
        // build-time sanitize; this guard only fires when the parent is resolvable.
        .unwrap_or_else(|_| parent.to_path_buf());
    if !canon_parent.starts_with(&canon_root) {
        return Err(NetError::InvalidPath(
            "refusing to write outside the destination root (containment guard)".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ftp_path_rejects_control_bytes() {
        assert!(validate_ftp_path("/pub/ok").is_ok());
        assert!(validate_ftp_path("legit\rMKD pwned").is_err()); // bare CR smuggling
        assert!(validate_ftp_path("a\nb").is_err());
        assert!(validate_ftp_path("a\0b").is_err());
    }

    #[test]
    fn local_rel_strips_traversal_and_absolute() {
        assert_eq!(sanitize_local_rel("../etc/passwd").unwrap(), "etc/passwd");
        assert_eq!(sanitize_local_rel("../../a/b").unwrap(), "a/b");
        assert_eq!(sanitize_local_rel("/etc/passwd").unwrap(), "etc/passwd");
        assert_eq!(sanitize_local_rel("a/./b/../c").unwrap(), "a/c");
        assert_eq!(sanitize_local_rel("plain.txt").unwrap(), "plain.txt");
        assert!(sanitize_local_rel("../..").is_err()); // sanitizes to empty
        assert!(sanitize_local_rel("/").is_err());
    }

    #[test]
    fn local_rel_rejects_control_and_long() {
        assert!(sanitize_local_rel("ok\revil").is_err());
        let long = "a".repeat(256);
        assert!(sanitize_local_rel(&long).is_err());
        assert_eq!(
            sanitize_local_rel(&"a".repeat(255)).unwrap(),
            "a".repeat(255)
        );
    }
}
