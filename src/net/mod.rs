//! Protocol clients. FTP (suppaftp) is sync and runs on spawn_blocking; SFTP (russh)
//! is natively async. Both produce the same domain types.

pub mod error;
pub mod ftp;
mod partial;
pub mod proxy;
pub mod safe;
pub mod sftp;
mod ssh_config;
mod staging;

use crate::model::{ConnectionSpec, Protocol, RemoteEntry};

pub use error::{HostKeyChallenge, NetError, TlsCertificateChallenge};
pub use ftp::{accept_invalid_tls, allow_plaintext_ftp};
pub(crate) use partial::discard_download_fragment;
pub use partial::resumable_part_path;
pub use partial::DownloadResume;
pub use safe::{assert_within, sanitize_local_rel, validate_ftp_path, validate_remote_component};
pub use sftp::{
    install_keyboard_interactive_broker, KeyboardInteractivePrompt, KeyboardInteractiveRequest,
};
pub(crate) use staging::RemoteStagingPaths;

/// Validate a single non-executing SFTP ProxyJump reference before it is persisted.
pub fn validate_ssh_proxy_jump(value: &str) -> Result<(), String> {
    ssh_config::validate_jump_reference(value)
}

/// Optional metadata copied alongside file contents. Ownership, groups, ACLs, extended attributes
/// and special permission bits are deliberately excluded: reproducing those across trust
/// boundaries can grant privileges or disclose data unexpectedly.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MetadataPreservation {
    pub timestamps: bool,
    pub permissions: bool,
}

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct TransferMetadata {
    pub modified: Option<std::time::SystemTime>,
    pub permissions: Option<u32>,
}

pub(crate) fn local_transfer_metadata(
    metadata: &std::fs::Metadata,
    policy: MetadataPreservation,
) -> TransferMetadata {
    let modified = policy
        .timestamps
        .then(|| metadata.modified().ok())
        .flatten();
    #[cfg(unix)]
    let permissions = policy.permissions.then(|| {
        use std::os::unix::fs::MetadataExt;
        metadata.mode() & 0o777
    });
    #[cfg(not(unix))]
    let permissions = None;
    TransferMetadata {
        modified,
        permissions,
    }
}

/// Apply metadata through an already-open regular file so a path swap cannot redirect chmod or
/// timestamp changes to a symlink. Downloads are created as private, single-link staging files;
/// rejecting a surprising hard link preserves that invariant through the final rename.
pub(crate) fn apply_local_transfer_metadata(
    path: &std::path::Path,
    metadata: TransferMetadata,
) -> Result<(), std::io::Error> {
    if metadata.modified.is_none() && metadata.permissions.is_none() {
        return Ok(());
    }
    let mut options = std::fs::OpenOptions::new();
    options.read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let file = options.open(path)?;
    let opened = file.metadata()?;
    if !opened.is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "download destination is no longer a regular file",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if opened.nlink() != 1 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "download destination gained an unexpected hard link",
            ));
        }
    }
    if let Some(modified) = metadata.modified {
        file.set_times(std::fs::FileTimes::new().set_modified(modified))?;
    }
    #[cfg(unix)]
    if let Some(mode) = metadata.permissions {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(std::fs::Permissions::from_mode(mode & 0o777))?;
    }
    Ok(())
}

#[derive(Debug, Clone, Copy)]
pub struct UploadResume {
    pub token: u64,
    pub expected_total: u64,
    pub expected_modified_unix_nanos: u64,
}

fn modified_unix_nanos(metadata: &std::fs::Metadata) -> Option<u64> {
    let elapsed = metadata
        .modified()
        .ok()?
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?;
    u64::try_from(elapsed.as_nanos()).ok()
}

pub(crate) fn validate_upload_source(
    metadata: &std::fs::Metadata,
    resume: UploadResume,
) -> Result<(), NetError> {
    if metadata.len() != resume.expected_total
        || modified_unix_nanos(metadata) != Some(resume.expected_modified_unix_nanos)
    {
        return Err(NetError::UploadSourceChanged);
    }
    Ok(())
}

#[derive(Debug, Clone, Default)]
pub struct RemoteTreeStats {
    pub size: u64,
    pub newest_mtime: Option<i64>,
    pub files_scanned: usize,
    pub truncated: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteFileMetadata {
    pub path: String,
    pub size: u64,
    pub mtime: Option<i64>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RemoteMetadata {
    pub is_dir: bool,
    pub size: u64,
    pub mtime: Option<i64>,
    pub permissions: Option<u32>,
    pub owner: Option<String>,
    pub group: Option<String>,
}

pub const MAX_REMOTE_SEARCH_QUERY_BYTES: usize = 256;
pub const MAX_REMOTE_SEARCH_RESULTS: usize = 500;
pub(crate) const MAX_REMOTE_SEARCH_ENTRIES: usize = 20_000;
pub(crate) const MAX_REMOTE_SEARCH_DIRECTORIES: usize = 2_000;
pub(crate) const MAX_REMOTE_SEARCH_DEPTH: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteSearchHit {
    pub path: String,
    pub is_dir: bool,
    pub size: u64,
    pub mtime: Option<i64>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RemoteSearchReport {
    pub hits: Vec<RemoteSearchHit>,
    pub entries_scanned: usize,
    pub directories_scanned: usize,
    pub truncated: bool,
}

fn normalize_remote_search_query(query: &str) -> Result<String, NetError> {
    let query = query.trim();
    if query.chars().count() < 2
        || query.len() > MAX_REMOTE_SEARCH_QUERY_BYTES
        || query.chars().any(char::is_control)
    {
        return Err(NetError::InvalidPath(
            "remote search requires at least 2 printable characters and at most 256 UTF-8 bytes"
                .into(),
        ));
    }
    Ok(query.to_lowercase())
}

pub(crate) fn remote_search_matches(path: &str, normalized_query: &str) -> bool {
    let path = path.to_lowercase();
    normalized_query
        .split_whitespace()
        .all(|term| path.contains(term))
}

/// Bounded, cancellable recursive name search over one authenticated connection. Passwords and
/// endpoint identity are never returned in the report; only absolute paths from the selected
/// remote root are exposed to the calling UI.
pub async fn search_remote(
    spec: &ConnectionSpec,
    password: &str,
    root_dir: &str,
    query: &str,
    cancelled: std::sync::Arc<std::sync::atomic::AtomicBool>,
) -> Result<RemoteSearchReport, NetError> {
    let query = normalize_remote_search_query(query)?;
    match spec.protocol {
        Protocol::Ftp => {
            let spec = spec.clone();
            let password = password.to_string();
            let root = root_dir.to_string();
            tokio::task::spawn_blocking(move || {
                ftp::search(&spec, &password, &root, &query, cancelled.as_ref())
            })
            .await
            .map_err(|error| NetError::Join(error.to_string()))?
        }
        Protocol::Sftp => sftp::search(spec, password, root_dir, &query, cancelled.as_ref()).await,
    }
}

pub async fn inspect_remote(
    spec: &ConnectionSpec,
    password: &str,
    path: &str,
) -> Result<RemoteMetadata, NetError> {
    match spec.protocol {
        Protocol::Ftp => {
            let spec = spec.clone();
            let password = password.to_string();
            let path = path.to_string();
            tokio::task::spawn_blocking(move || ftp::inspect(&spec, &password, &path))
                .await
                .map_err(|error| NetError::Join(error.to_string()))?
        }
        Protocol::Sftp => sftp::inspect(spec, password, path).await,
    }
}

/// Connect + list the (initial) directory. Dispatches by protocol.
/// Returns `(entries, plaintext)`: `true` only when this exact FTP connection was explicitly
/// configured for legacy plaintext mode (password sent unencrypted). SFTP is always encrypted →
/// `false`.
pub async fn connect_and_list(
    spec: &ConnectionSpec,
    password: &str,
) -> Result<(Vec<RemoteEntry>, bool), NetError> {
    connect_and_list_incremental(spec, password, |_| true).await
}

/// List a directory while delivering bounded batches to the caller. The callback runs on the
/// networking worker, never on the UI thread. Returning `false` cancels the listing cleanly.
pub async fn connect_and_list_incremental(
    spec: &ConnectionSpec,
    password: &str,
    on_batch: impl FnMut(Vec<RemoteEntry>) -> bool + Send + 'static,
) -> Result<(Vec<RemoteEntry>, bool), NetError> {
    match spec.protocol {
        Protocol::Ftp => {
            let spec = spec.clone();
            let pw = password.to_string();
            tokio::task::spawn_blocking(move || {
                ftp::connect_and_list_incremental(&spec, &pw, on_batch)
            })
            .await
            .map_err(|e| NetError::Join(e.to_string()))?
        }
        Protocol::Sftp => sftp::connect_and_list_incremental(spec, password, on_batch)
            .await
            .map(|e| (e, false)),
    }
}

/// Recursively summarize files under `root_dir`, bounded by `max_files` for UI responsiveness.
pub async fn remote_tree_stats(
    spec: &ConnectionSpec,
    password: &str,
    root_dir: &str,
    max_files: usize,
) -> Result<RemoteTreeStats, NetError> {
    match spec.protocol {
        Protocol::Ftp => {
            let spec = spec.clone();
            let pw = password.to_string();
            let root = root_dir.to_string();
            tokio::task::spawn_blocking(move || ftp::tree_stats(&spec, &pw, &root, max_files))
                .await
                .map_err(|e| NetError::Join(e.to_string()))?
        }
        Protocol::Sftp => sftp::tree_stats(spec, password, root_dir, max_files).await,
    }
}

/// Recursively list every FILE under `root_dir` as `(absolute_remote_path, size)`.
/// Used for folder downloads.
pub async fn walk_remote(
    spec: &ConnectionSpec,
    password: &str,
    root_dir: &str,
) -> Result<Vec<(String, u64)>, NetError> {
    match spec.protocol {
        Protocol::Ftp => {
            let spec = spec.clone();
            let pw = password.to_string();
            let root = root_dir.to_string();
            tokio::task::spawn_blocking(move || ftp::walk(&spec, &pw, &root))
                .await
                .map_err(|e| NetError::Join(e.to_string()))?
        }
        Protocol::Sftp => sftp::walk(spec, password, root_dir).await,
    }
}

/// Recursively list every remote file with comparison metadata. Folder synchronization uses this
/// richer form so a same-size modification is not silently treated as unchanged.
pub async fn walk_remote_metadata(
    spec: &ConnectionSpec,
    password: &str,
    root_dir: &str,
) -> Result<Vec<RemoteFileMetadata>, NetError> {
    match spec.protocol {
        Protocol::Ftp => {
            let spec = spec.clone();
            let password = password.to_string();
            let root = root_dir.to_string();
            tokio::task::spawn_blocking(move || ftp::walk_metadata(&spec, &password, &root))
                .await
                .map_err(|error| NetError::Join(error.to_string()))?
        }
        Protocol::Sftp => sftp::walk_metadata(spec, password, root_dir).await,
    }
}

/// SHA-256 selected remote files over one authenticated session. This is intentionally explicit
/// and is used only by the user's checksum synchronization mode because it must read every byte.
pub async fn hash_remote_files(
    spec: &ConnectionSpec,
    password: &str,
    paths: &[String],
) -> Result<Vec<(String, [u8; 32])>, NetError> {
    match spec.protocol {
        Protocol::Ftp => {
            let spec = spec.clone();
            let password = password.to_string();
            let paths = paths.to_vec();
            tokio::task::spawn_blocking(move || ftp::hash_files(&spec, &password, &paths))
                .await
                .map_err(|error| NetError::Join(error.to_string()))?
        }
        Protocol::Sftp => sftp::hash_files(spec, password, paths).await,
    }
}

/// Download a single remote file to a local path (used by Quick Look preview of a remote
/// file: download to a temp file, then hand it to the OS previewer).
pub async fn download_file(
    spec: &ConnectionSpec,
    password: &str,
    remote_path: &str,
    local_path: std::path::PathBuf,
) -> Result<u64, NetError> {
    match spec.protocol {
        Protocol::Ftp => {
            let (s, p, r) = (spec.clone(), password.to_string(), remote_path.to_string());
            tokio::task::spawn_blocking(move || {
                ftp::download(&s, &p, &r, local_path.as_path(), |_| {}, None)
            })
            .await
            .map_err(|e| NetError::Join(e.to_string()))?
        }
        Protocol::Sftp => {
            sftp::download(
                spec,
                password,
                remote_path,
                local_path.as_path(),
                |_| {},
                None,
            )
            .await
        }
    }
}

/// Download a temporary helper file with a hard byte ceiling. The server-provided directory
/// listing is only advisory; the progress callback also cancels the transfer if the actual stream
/// exceeds the limit, preventing previews/edit sessions from filling the local disk.
pub async fn download_file_limited(
    spec: &ConnectionSpec,
    password: &str,
    remote_path: &str,
    local_path: std::path::PathBuf,
    max_bytes: u64,
) -> Result<u64, NetError> {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    let exceeded = Arc::new(AtomicBool::new(false));
    let result = match spec.protocol {
        Protocol::Ftp => {
            let (spec, password, remote) =
                (spec.clone(), password.to_string(), remote_path.to_string());
            let exceeded = exceeded.clone();
            tokio::task::spawn_blocking(move || {
                let cancel = Arc::new(AtomicBool::new(false));
                let progress_cancel = cancel.clone();
                let progress_exceeded = exceeded.clone();
                ftp::download(
                    &spec,
                    &password,
                    &remote,
                    &local_path,
                    move |done| {
                        if done > max_bytes {
                            progress_exceeded.store(true, Ordering::Relaxed);
                            progress_cancel.store(true, Ordering::Relaxed);
                        }
                    },
                    Some(cancel.as_ref()),
                )
            })
            .await
            .map_err(|error| NetError::Join(error.to_string()))?
        }
        Protocol::Sftp => {
            let cancel = AtomicBool::new(false);
            let progress_exceeded = exceeded.clone();
            sftp::download(
                spec,
                password,
                remote_path,
                &local_path,
                |done| {
                    if done > max_bytes {
                        progress_exceeded.store(true, Ordering::Relaxed);
                        cancel.store(true, Ordering::Relaxed);
                    }
                },
                Some(&cancel),
            )
            .await
        }
    };
    if exceeded.load(Ordering::Relaxed) {
        Err(NetError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("remote file exceeds the {max_bytes}-byte safety limit"),
        )))
    } else {
        result
    }
}

/// Upload one local file outside the queued transfer UI (remote edit save-back).
pub async fn upload_file(
    spec: &ConnectionSpec,
    password: &str,
    local_path: std::path::PathBuf,
    remote_path: &str,
) -> Result<u64, NetError> {
    match spec.protocol {
        Protocol::Ftp => {
            let (spec, password, remote) =
                (spec.clone(), password.to_string(), remote_path.to_string());
            tokio::task::spawn_blocking(move || {
                ftp::upload(&spec, &password, &local_path, &remote, |_| {}, None)
            })
            .await
            .map_err(|error| NetError::Join(error.to_string()))?
        }
        Protocol::Sftp => {
            sftp::upload(spec, password, &local_path, remote_path, |_| {}, None).await
        }
    }
}

pub async fn rename_remote(
    spec: &ConnectionSpec,
    password: &str,
    from: &str,
    to: &str,
) -> Result<(), NetError> {
    match spec.protocol {
        Protocol::Ftp => {
            let (spec, password, from, to) = (
                spec.clone(),
                password.to_string(),
                from.to_string(),
                to.to_string(),
            );
            tokio::task::spawn_blocking(move || ftp::rename(&spec, &password, &from, &to))
                .await
                .map_err(|error| NetError::Join(error.to_string()))?
        }
        Protocol::Sftp => sftp::rename(spec, password, from, to).await,
    }
}

pub async fn create_remote_dir(
    spec: &ConnectionSpec,
    password: &str,
    path: &str,
) -> Result<(), NetError> {
    match spec.protocol {
        Protocol::Ftp => {
            let (spec, password, path) = (spec.clone(), password.to_string(), path.to_string());
            tokio::task::spawn_blocking(move || ftp::create_dir(&spec, &password, &path))
                .await
                .map_err(|error| NetError::Join(error.to_string()))?
        }
        Protocol::Sftp => sftp::create_dir(spec, password, path).await,
    }
}

pub async fn chmod_remote(
    spec: &ConnectionSpec,
    password: &str,
    path: &str,
    mode: u32,
) -> Result<(), NetError> {
    match spec.protocol {
        Protocol::Ftp => {
            let (spec, password, path) = (spec.clone(), password.to_string(), path.to_string());
            tokio::task::spawn_blocking(move || ftp::chmod(&spec, &password, &path, mode))
                .await
                .map_err(|error| NetError::Join(error.to_string()))?
        }
        Protocol::Sftp => sftp::chmod(spec, password, path, mode).await,
    }
}

/// Does a remote file/dir named `name` exist in directory `dir`? Used by the copy conflict
/// check. Returns `Ok(bool)` for a definitive answer and propagates connection/list errors —
/// the caller must NOT treat an auth/network failure as "does not exist" (that would risk a
/// silent overwrite of an existing file).
pub async fn remote_exists(
    spec: &ConnectionSpec,
    password: &str,
    dir: &str,
    name: &str,
) -> Result<bool, NetError> {
    let mut s = spec.clone();
    s.initial_path = dir.to_string();
    let (entries, _plaintext) = connect_and_list(&s, password).await?;
    Ok(entries.iter().any(|e| e.name == name))
}

/// Delete a remote file (or empty directory). Dispatches by protocol.
pub async fn delete_remote(
    spec: &ConnectionSpec,
    password: &str,
    remote_path: &str,
    is_dir: bool,
) -> Result<(), NetError> {
    match spec.protocol {
        Protocol::Ftp => {
            let spec = spec.clone();
            let pw = password.to_string();
            let path = remote_path.to_string();
            tokio::task::spawn_blocking(move || ftp::delete(&spec, &pw, &path, is_dir))
                .await
                .map_err(|e| NetError::Join(e.to_string()))?
        }
        Protocol::Sftp => sftp::delete(spec, password, remote_path, is_dir).await,
    }
}

#[cfg(test)]
mod metadata_tests {
    use super::*;

    fn scratch() -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "gmacftp-metadata-test-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ))
    }

    #[cfg(unix)]
    #[test]
    fn local_metadata_preserves_only_mtime_and_rwx_bits() {
        use std::os::unix::fs::PermissionsExt;

        let dir = scratch();
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("download.bin");
        std::fs::write(&path, b"complete payload").unwrap();
        let modified = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_123);

        apply_local_transfer_metadata(
            &path,
            TransferMetadata {
                modified: Some(modified),
                // Special bits are untrusted across endpoints and must be stripped.
                permissions: Some(0o7764),
            },
        )
        .unwrap();

        let metadata = std::fs::metadata(&path).unwrap();
        assert_eq!(metadata.permissions().mode() & 0o7777, 0o764);
        assert_eq!(
            metadata
                .modified()
                .unwrap()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            1_700_000_123
        );
        assert_eq!(std::fs::read(&path).unwrap(), b"complete payload");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[cfg(unix)]
    #[test]
    fn local_metadata_rejects_an_unexpected_hard_link() {
        let dir = scratch();
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("download.bin");
        let alias = dir.join("alias.bin");
        std::fs::write(&path, b"complete payload").unwrap();
        std::fs::hard_link(&path, &alias).unwrap();

        let error = apply_local_transfer_metadata(
            &path,
            TransferMetadata {
                modified: None,
                permissions: Some(0o777),
            },
        )
        .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn remote_search_query_is_bounded_and_matches_every_term() {
        let query = normalize_remote_search_query("  FINAL budget  ").unwrap();
        assert_eq!(query, "final budget");
        assert!(remote_search_matches(
            "/Reports/2026/Final-Budget.pdf",
            &query
        ));
        assert!(!remote_search_matches(
            "/Reports/2026/Final-Notes.pdf",
            &query
        ));

        for invalid in ["", "x", "ok\nno"] {
            assert!(normalize_remote_search_query(invalid).is_err());
        }
        assert!(
            normalize_remote_search_query(&"x".repeat(MAX_REMOTE_SEARCH_QUERY_BYTES + 1)).is_err()
        );
    }
}
