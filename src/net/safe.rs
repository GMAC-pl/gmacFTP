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

/// Canonicalize `path` while tolerating non-existent TRAILING components.
///
/// `fs::canonicalize` rejects any path that doesn't fully exist. Folder downloads legitimately
/// pass two such paths to [`assert_within`]: the destination root (`dst_cwd/<folder>`, created
/// lazily file-by-file by the downloaders) and, for deeply nested server trees, a target's
/// parent dir. A hard `canonicalize` there fails with `NotFound` and silently skips every file
/// ("downloaded 0 file(s); skipped N unsafe path(s)").
///
/// We climb to the nearest EXISTING ancestor and canonicalize that, then re-append the
/// non-existent tail components verbatim. Non-existent components cannot hold symlinks, so the
/// result is exactly the canonical path `path` will resolve to once created — the prefix
/// containment check in [`assert_within`] stays precise, not loosened.
///
/// PRECONDITION: `path` must not contain `..`/`.` traversal components. `Path::file_name()`
/// returns `None` for a trailing `..`/`.`, so the climb could otherwise silently drop a
/// traversal directive and produce a "canonical" form that hides an escape. [`assert_within`]
/// enforces this precondition; any other caller must too.
fn canonicalize_lenient(path: &std::path::Path) -> std::path::PathBuf {
    if let Ok(c) = std::fs::canonicalize(path) {
        return c;
    }
    // `tail` holds the non-existent components below the first resolvable ancestor, in
    // push-down order; popping reverses them back into place.
    let mut tail: Vec<std::ffi::OsString> = Vec::new();
    let mut cur = path.to_path_buf();
    loop {
        if let Ok(canon) = std::fs::canonicalize(&cur) {
            let mut full = canon;
            while let Some(comp) = tail.pop() {
                full.push(comp);
            }
            return full;
        }
        let Some(parent) = cur.parent() else { break };
        if parent.as_os_str().is_empty() {
            break; // bare component with no anchor — fall through to best-effort return
        }
        // `file_name()` is None when `cur` ends in `..`/`.` — a traversal directive we must NOT
        // silently drop (it would hide an escape). Bail to the honest, unresolved return below;
        // callers reject `..` up front (see [`assert_within`]), so this is strictly defense-in-depth.
        let Some(name) = cur.file_name() else { break };
        tail.push(name.to_os_string());
        cur = parent.to_path_buf();
    }
    path.to_path_buf()
}

/// Defense-in-depth at the write boundary: assert the resolved target stays inside the
/// user-chosen root. Both the root and the target's parent are canonicalized leniently (see
/// [`canonicalize_lenient`]) so a folder download — whose destination root does not exist
/// until the first file is written — is not rejected wholesale. Cheap best-effort; the primary
/// defense is [`sanitize_local_rel`] at path-build time.
pub fn assert_within(root: &std::path::Path, target: &std::path::Path) -> Result<(), NetError> {
    // Defense-in-depth: refuse any `..` traversal component outright. `sanitize_local_rel`
    // already strips these at path-build time, so a `..` reaching here means a caller bypassed
    // sanitization or an upstream invariant broke. We reject rather than feed a traversal
    // directive to canonicalization — `Path::file_name()` returns None for a trailing `..`,
    // which `canonicalize_lenient` must never silently swallow (it would accept a target that
    // resolves outside the root).
    if root
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
        || target
            .components()
            .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err(NetError::InvalidPath(
            "path contains a parent-dir (..) component".into(),
        ));
    }
    let canon_root = canonicalize_lenient(root);
    let parent = target.parent().filter(|p| !p.as_os_str().is_empty());
    let Some(parent) = parent else {
        // target is a bare filename with no parent — nothing to escape.
        return Ok(());
    };
    let canon_parent = canonicalize_lenient(parent);
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

    // --- assert_within: containment guard -------------------------------------

    /// Hermetic scratch dir with no extra crate. Auto-removed on drop.
    struct TestDir(std::path::PathBuf);
    impl TestDir {
        fn new() -> Self {
            static UNIQUE: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
            let p = std::env::temp_dir().join(format!(
                "gmacftp-safe-test-{}-{}",
                std::process::id(),
                UNIQUE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&p).unwrap();
            Self(p)
        }
        fn path(&self) -> &std::path::Path {
            &self.0
        }
    }
    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn assert_within_accepts_not_yet_existing_root() {
        // REGRESSION for the folder-download bug: `copy_remote_to_local` passes the destination
        // ROOT = dst_cwd/<folder>, which does NOT exist yet — the downloaders create it lazily,
        // file-by-file. The guard must not skip every file just because the root folder hasn't
        // been materialised yet. (Previously: fs::canonicalize(root) failed with NotFound →
        // "downloaded 0 file(s); skipped N unsafe path(s)".)
        let tmp = TestDir::new();
        let root = tmp.path().join("newfolder"); // does NOT exist
        let target = root.join("report.pdf");
        assert_within(&root, &target)
            .expect("a not-yet-created destination root must be tolerated");
    }

    #[test]
    fn assert_within_still_rejects_escape_when_root_missing() {
        // Containment must NOT be weakened by the lenient-root fix: a target outside the root
        // (here, a sibling dir) is still rejected even when the root itself doesn't exist yet.
        let tmp = TestDir::new();
        let root = tmp.path().join("newfolder"); // does NOT exist
        let outside = tmp.path().join("elsewhere");
        std::fs::create_dir_all(&outside).unwrap();
        let target = outside.join("evil.txt");
        assert!(
            assert_within(&root, &target).is_err(),
            "an out-of-root target must still be refused"
        );
    }

    #[test]
    fn assert_within_accepts_existing_root_and_target_parent() {
        // The classic single-file case must keep working unchanged.
        let tmp = TestDir::new();
        let target = tmp.path().join("file.txt");
        std::fs::write(&target, b"x").unwrap();
        assert_within(tmp.path(), &target).unwrap();
    }

    #[test]
    fn assert_within_rejects_dotdot_in_target_even_when_root_missing() {
        // REGRESSION for a latent defense-in-depth hole: `canonicalize_lenient` used to silently
        // drop trailing `..` (Path::file_name() returns None for them), so a target that lexically
        // sits under a not-yet-existing root but RESOLVES outside it via `..` was accepted. The
        // primary defense (sanitize_local_rel) strips `..`, so this is unreachable today — but the
        // write-boundary guard must hold on its own. It must refuse any `..` component outright.
        let tmp = TestDir::new();
        let root = tmp.path().join("newfolder"); // does NOT exist
        let escape = root.join("..").join("evil.plist"); // resolves to tmp/evil.plist (outside root)
        assert!(
            assert_within(&root, &escape).is_err(),
            "a `..`-bearing target that resolves outside root must be refused"
        );
    }

    #[test]
    fn assert_within_rejects_dotdot_in_root() {
        // A traversal component in the ROOT is equally suspicious — refuse it too.
        let tmp = TestDir::new();
        let root = tmp.path().join("..").join("newfolder");
        let target = root.join("file.txt");
        assert!(assert_within(&root, &target).is_err());
    }
}
