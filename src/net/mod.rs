//! Protocol clients. FTP (suppaftp) is sync and runs on spawn_blocking; SFTP (russh)
//! is natively async. Both produce the same domain types.

pub mod error;
pub mod ftp;
mod partial;
pub mod safe;
pub mod sftp;

use crate::model::{ConnectionSpec, Protocol, RemoteEntry};

pub use error::{HostKeyChallenge, NetError};
pub use ftp::{accept_invalid_tls, allow_plaintext_ftp};
pub(crate) use partial::discard_download_fragment;
pub use partial::DownloadResume;
pub use safe::{assert_within, sanitize_local_rel, validate_ftp_path, validate_remote_component};

#[derive(Debug, Clone, Default)]
pub struct RemoteTreeStats {
    pub size: u64,
    pub newest_mtime: Option<i64>,
    pub files_scanned: usize,
    pub truncated: bool,
}

/// Connect + list the (initial) directory. Dispatches by protocol.
/// Returns `(entries, plaintext)`: `true` only when this exact FTP connection was explicitly
/// configured for legacy plaintext mode (password sent unencrypted). SFTP is always encrypted →
/// `false`.
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
