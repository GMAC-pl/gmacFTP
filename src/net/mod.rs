//! Protocol clients. FTP (suppaftp) is sync and runs on spawn_blocking; SFTP (russh)
//! is natively async. Both produce the same domain types.

pub mod error;
pub mod ftp;
pub mod safe;
pub mod sftp;

use crate::model::{ConnectionSpec, Protocol, RemoteEntry};

pub use error::NetError;
pub use ftp::{accept_invalid_tls, set_accept_invalid_tls};
pub use safe::{assert_within, sanitize_local_rel, validate_ftp_path};

#[derive(Debug, Clone, Default)]
pub struct RemoteTreeStats {
    pub size: u64,
    pub newest_mtime: Option<i64>,
    pub files_scanned: usize,
    pub truncated: bool,
}

/// Connect + list the (initial) directory. Dispatches by protocol.
/// Returns `(entries, plaintext_fallback)`: `true` when an FTP session fell back to plaintext
/// (password sent unencrypted) so the UI can warn. SFTP is always encrypted → `false`.
pub async fn connect_and_list(
    spec: &ConnectionSpec,
    password: &str,
) -> Result<(Vec<RemoteEntry>, bool), NetError> {
    match spec.protocol {
        Protocol::Ftp => {
            let spec = spec.clone();
            let pw = password.to_string();
            tokio::task::spawn_blocking(move || ftp::connect_and_list(&spec, &pw))
                .await
                .map_err(|e| NetError::Join(e.to_string()))?
        }
        Protocol::Sftp => sftp::connect_and_list(spec, password)
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
