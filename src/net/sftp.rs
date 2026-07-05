//! SFTP client (russh 0.61 + russh-sftp 2.3). Pure Rust, no C deps.
//!
//! Host-key verification is TOFU: the first connection stores the host's key fingerprint
//! in `<config_dir>/known_hosts`; a later connection with a DIFFERENT fingerprint fails
//! closed (rejected). This prevents silent MITM, unlike leaving check_server_key = Ok(true).
//!
//! Session hygiene: every public operation opens `(Handle, SftpSession)` and explicitly
//! `disconnect()`s the Handle in a finally block. russh 0.61 `Handle::Drop` is a no-op
//! (only a debug log), so without the explicit disconnect every browse/transfer leaked an
//! authenticated SSH session and exhausted server MaxSessions/MaxStartups (MEMO-2/CONC-4).

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use russh_sftp::client::SftpSession;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::model::{ConnectionSpec, RemoteEntry};
use crate::net::error::NetError;
use crate::net::RemoteTreeStats;

struct Handler {
    /// Composite `host:port` key used for known_hosts lookups, so two SFTP servers on different
    /// ports of the same host get distinct trust entries (instead of colliding on the bare
    /// hostname, which caused false MITM rejections or cross-port key pinning).
    host_key: String,
    known_hosts: PathBuf,
}

impl russh::client::Handler for Handler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        key: &russh::keys::ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        match tofu_verify(&self.known_hosts, &self.host_key, key) {
            Ok(accept) => Ok(accept),
            Err(e) => {
                tracing::warn!(host_key = %self.host_key, error = %e, "known_hosts check failed; rejecting");
                Ok(false) // fail closed
            }
        }
    }
}

fn known_hosts_path() -> Option<PathBuf> {
    directories::ProjectDirs::from(
        env!("MACKFTP_CONFIG_QUALIFIER"),
        env!("MACKFTP_CONFIG_ORGANIZATION"),
        env!("MACKFTP_CONFIG_APPLICATION"),
    )
    .map(|pd| pd.config_dir().join("known_hosts"))
}

/// Returns Ok(true) to accept (new or matching key), Ok(false) to reject (mismatch).
///
/// `host_key` is the composite `host:port` trust key (see [`Handler`]). Existing pre-0.0.15
/// entries were written as bare `host` and will no longer match — the user re-confirms each
/// host's key once on first connect after the upgrade (acceptable for a v0.0.x app, and the
/// safer default than silently treating a bare-host entry as trusted for every port).
fn tofu_verify(
    path: &std::path::Path,
    host_key: &str,
    key: &russh::keys::ssh_key::PublicKey,
) -> Result<bool, String> {
    let fp = key
        .fingerprint(russh::keys::ssh_key::HashAlg::Sha256)
        .to_string();
    let existing = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(e.to_string()),
    };
    for line in existing.lines() {
        if let Some((h, f)) = line.split_once(char::is_whitespace) {
            if h.trim() == host_key {
                return Ok(f.trim() == fp.trim());
            }
        }
    }
    // Unknown host — TOFU: persist and accept. Atomic write (O_EXCL + 0600 + fsync + rename) so
    // a crash mid-write can't truncate known_hosts — a truncated trust anchor would silently
    // re-open every previously-verified host to MITM on the next connection. Mode 0600 is
    // applied by atomic_write at creation (known_hosts reveals which hosts you connect to).
    let mut content = existing;
    if !content.is_empty() && !content.ends_with('\n') {
        content.push('\n');
    }
    content.push_str(&format!("{host_key} {fp}\n"));
    crate::store::vault::atomic_write(path, content.as_bytes()).map_err(|e| e.to_string())?;
    Ok(true)
}

fn map_ssh<E: std::fmt::Display>(e: E) -> NetError {
    NetError::Ssh(e.to_string())
}

/// Connect, authenticate, open the SFTP subsystem. Returns the SSH `Handle` (which must be
/// `disconnect()`ed by the caller when done — its `Drop` is a no-op) alongside the session.
async fn open_session(
    spec: &ConnectionSpec,
    password: &str,
) -> Result<(russh::client::Handle<Handler>, SftpSession), NetError> {
    let known_hosts =
        known_hosts_path().ok_or_else(|| NetError::Ssh("no config directory available".into()))?;
    let config = Arc::new(russh::client::Config::default());
    let handler = Handler {
        host_key: format!("{}:{}", spec.host, spec.effective_port()),
        known_hosts,
    };

    let mut handle =
        russh::client::connect(config, (spec.host.as_str(), spec.effective_port()), handler)
            .await
            .map_err(map_ssh)?;

    let auth = handle
        .authenticate_password(spec.user.clone(), password.to_string())
        .await
        .map_err(map_ssh)?;
    if !auth.success() {
        // Best-effort disconnect before returning the auth error (don't leak the session).
        let _ = handle
            .disconnect(russh::Disconnect::ByApplication, "auth-failed", "en")
            .await;
        return Err(NetError::AuthFailed(spec.user.clone()));
    }

    // Post-auth errors must still disconnect the Handle — its Drop is a no-op (MEMO-2/CONC-4).
    let channel = match handle.channel_open_session().await {
        Ok(c) => c,
        Err(e) => {
            let _ = handle
                .disconnect(russh::Disconnect::ByApplication, "chan-open-failed", "en")
                .await;
            return Err(map_ssh(e));
        }
    };
    if let Err(e) = channel.request_subsystem(true, "sftp").await {
        let _ = handle
            .disconnect(russh::Disconnect::ByApplication, "subsystem-failed", "en")
            .await;
        return Err(map_ssh(e));
    }
    let sftp = match SftpSession::new(channel.into_stream()).await {
        Ok(s) => s,
        Err(e) => {
            let _ = handle
                .disconnect(russh::Disconnect::ByApplication, "sftp-init-failed", "en")
                .await;
            return Err(map_ssh(e));
        }
    };
    Ok((handle, sftp))
}

/// Create a remote dir and all ancestors (mkdir -p). Existing segments are ignored.
async fn mkdirs_sftp(sftp: &SftpSession, remote_dir: &str) {
    let clean = remote_dir.trim_matches('/');
    if clean.is_empty() {
        return;
    }
    let mut acc = String::new();
    for seg in clean.split('/') {
        if seg.is_empty() {
            continue;
        }
        if acc.is_empty() {
            acc = format!("/{seg}");
        } else {
            acc.push('/');
            acc.push_str(seg);
        }
        let _ = sftp.create_dir(&acc).await;
    }
}

/// Parent directory of a remote path, absolute.
fn parent_remote(remote_path: &str) -> Option<String> {
    let p = remote_path.trim_end_matches('/');
    match p.rfind('/') {
        Some(0) => Some("/".to_string()),
        Some(idx) => Some(p[..idx].to_string()),
        None => None,
    }
}

/// Connect, authenticate, list the (initial) directory.
pub async fn connect_and_list(
    spec: &ConnectionSpec,
    password: &str,
) -> Result<Vec<RemoteEntry>, NetError> {
    let (handle, sftp) = open_session(spec, password).await?;
    let result: Result<Vec<RemoteEntry>, NetError> = async {
        let dir = if spec.initial_path.trim().is_empty() {
            ".".to_string()
        } else {
            spec.initial_path.clone()
        };

        let mut out = Vec::new();
        const MAX_ENTRIES: usize = 50_000; // M2/M10: bound memory against a hostile huge listing
        for entry in sftp.read_dir(&dir).await.map_err(map_ssh)? {
            if out.len() >= MAX_ENTRIES {
                tracing::warn!("directory listing truncated at {MAX_ENTRIES} entries (DoS guard)");
                break;
            }
            let name = entry.file_name();
            if name == "." || name == ".." {
                continue;
            }
            let attrs = entry.metadata();
            out.push(RemoteEntry {
                name,
                is_dir: attrs.is_dir(),
                size: attrs.size.unwrap_or(0),
                mtime: attrs.mtime.map(|t| t as i64),
            });
        }
        crate::model::sort_entries(&mut out);
        Ok(out)
    }
    .await;
    let _ = handle
        .disconnect(russh::Disconnect::ByApplication, "bye", "en")
        .await; // MEMO-2/CONC-4
    result
}

/// Recursively collect every FILE under `root_dir` as `(absolute_remote_path, size)`.
/// Used for folder downloads.
pub async fn walk(
    spec: &ConnectionSpec,
    password: &str,
    root_dir: &str,
) -> Result<Vec<(String, u64)>, NetError> {
    let (handle, sftp) = open_session(spec, password).await?;
    let root = if root_dir.trim().is_empty() {
        ".".to_string()
    } else {
        root_dir.to_string()
    };
    let mut out = Vec::new();
    let result = walk_sftp(&sftp, &root, &mut out).await;
    let _ = handle
        .disconnect(russh::Disconnect::ByApplication, "bye", "en")
        .await; // MEMO-2/CONC-4
    result?;
    Ok(out)
}

pub async fn tree_stats(
    spec: &ConnectionSpec,
    password: &str,
    root_dir: &str,
    max_files: usize,
) -> Result<RemoteTreeStats, NetError> {
    let (handle, sftp) = open_session(spec, password).await?;
    let root = if root_dir.trim().is_empty() {
        ".".to_string()
    } else {
        root_dir.to_string()
    };
    let mut stats = RemoteTreeStats::default();
    let result = tree_stats_sftp(&sftp, &root, &mut stats, max_files).await;
    let _ = handle
        .disconnect(russh::Disconnect::ByApplication, "bye", "en")
        .await; // MEMO-2/CONC-4
    result?;
    Ok(stats)
}

async fn tree_stats_sftp(
    sftp: &SftpSession,
    dir: &str,
    stats: &mut RemoteTreeStats,
    max_files: usize,
) -> Result<(), NetError> {
    if stats.truncated {
        return Ok(());
    }
    for entry in sftp.read_dir(dir).await.map_err(map_ssh)? {
        if stats.truncated {
            break;
        }
        let name = entry.file_name();
        if name == "." || name == ".." {
            continue;
        }
        let full = join_remote_path(dir, &name);
        let attrs = entry.metadata();
        if attrs.is_dir() {
            Box::pin(tree_stats_sftp(sftp, &full, stats, max_files)).await?;
        } else {
            stats.size = stats.size.saturating_add(attrs.size.unwrap_or(0));
            stats.files_scanned += 1;
            if let Some(mtime) = attrs.mtime.map(|t| t as i64) {
                stats.newest_mtime = Some(stats.newest_mtime.map_or(mtime, |cur| cur.max(mtime)));
            }
            if max_files > 0 && stats.files_scanned >= max_files {
                stats.truncated = true;
            }
        }
    }
    Ok(())
}

async fn walk_sftp(
    sftp: &SftpSession,
    dir: &str,
    out: &mut Vec<(String, u64)>,
) -> Result<(), NetError> {
    const MAX_FILES: usize = 100_000; // M2: bound memory for a folder download
    if out.len() >= MAX_FILES {
        tracing::warn!("folder walk truncated at {MAX_FILES} files (DoS guard)");
        return Ok(());
    }
    for entry in sftp.read_dir(dir).await.map_err(map_ssh)? {
        let name = entry.file_name();
        if name == "." || name == ".." {
            continue;
        }
        let full = join_remote_path(dir, &name);
        let attrs = entry.metadata();
        if attrs.is_dir() {
            Box::pin(walk_sftp(sftp, &full, out)).await?;
        } else {
            out.push((full, attrs.size.unwrap_or(0)));
        }
    }
    Ok(())
}

fn join_remote_path(dir: &str, name: &str) -> String {
    let d = dir.trim_end_matches('/');
    if d.is_empty() || d == "." || d == "/" {
        format!("/{name}")
    } else {
        format!("{d}/{name}")
    }
}

/// Download `remote_path` to `local_path`, reporting cumulative bytes via `progress`.
/// Writes to `<local_path>.part` and renames on success — a failure leaves no partial file.
#[allow(dead_code)] // wired in by the transfer actor (M6)
pub async fn download(
    spec: &ConnectionSpec,
    password: &str,
    remote_path: &str,
    local_path: &std::path::Path,
    progress: impl Fn(u64) + Send,
    cancel: Option<&AtomicBool>, // M1
) -> Result<u64, NetError> {
    let (handle, sftp) = open_session(spec, password).await?;
    let result = download_with_session(&sftp, remote_path, local_path, progress, cancel).await;
    let _ = handle
        .disconnect(russh::Disconnect::ByApplication, "bye", "en")
        .await; // MEMO-2/CONC-4
    result
}

async fn download_with_session(
    sftp: &SftpSession,
    remote_path: &str,
    local_path: &std::path::Path,
    progress: impl Fn(u64) + Send,
    cancel: Option<&AtomicBool>,
) -> Result<u64, NetError> {
    if let Some(parent) = local_path.parent() {
        let _ = tokio::fs::create_dir_all(parent).await; // supports folder downloads
    }
    let mut remote = sftp.open(remote_path).await.map_err(map_ssh)?;
    let part = part_path(local_path);
    // Exclusive (O_EXCL + 0600) open via the vault helper: defeats a pre-planted `<dest>.part`
    // symlink that would otherwise redirect the downloaded bytes onto the symlink's target.
    let mut file = tokio::fs::File::from_std(crate::store::vault::create_exclusive(&part)?);
    let result: Result<u64, NetError> = async {
        let mut buf = vec![0u8; 64 * 1024];
        let mut done: u64 = 0;
        loop {
            if let Some(f) = cancel {
                if f.load(Ordering::Relaxed) {
                    return Err(NetError::Cancelled);
                }
            }
            let n = remote.read(&mut buf).await.map_err(map_ssh)?;
            if n == 0 {
                break;
            }
            file.write_all(&buf[..n]).await?;
            done += n as u64;
            progress(done);
        }
        file.sync_all().await?;
        Ok(done)
    }
    .await;
    match result {
        Ok(done) => {
            tokio::fs::rename(&part, local_path).await?;
            Ok(done)
        }
        Err(e) => {
            let _ = tokio::fs::remove_file(&part).await;
            Err(e)
        }
    }
}

fn part_path(p: &std::path::Path) -> std::path::PathBuf {
    let mut s = p.as_os_str().to_owned();
    s.push(".part");
    std::path::PathBuf::from(s)
}

/// Upload `local_path` to `remote_path`, reporting cumulative bytes via `progress`.
#[allow(dead_code)] // wired in by the transfer actor (M6)
pub async fn upload(
    spec: &ConnectionSpec,
    password: &str,
    local_path: &std::path::Path,
    remote_path: &str,
    progress: impl Fn(u64) + Send,
    cancel: Option<&AtomicBool>, // M1
) -> Result<u64, NetError> {
    let (handle, sftp) = open_session(spec, password).await?;
    if let Some(parent) = parent_remote(remote_path) {
        mkdirs_sftp(&sftp, &parent).await; // supports folder uploads (mkdir -p ancestors)
    }
    let mut remote = sftp.create(remote_path).await.map_err(map_ssh)?;
    let mut file = tokio::fs::File::open(local_path).await?;
    let result: Result<u64, NetError> = async {
        let mut buf = vec![0u8; 64 * 1024];
        let mut done: u64 = 0;
        loop {
            if let Some(f) = cancel {
                if f.load(Ordering::Relaxed) {
                    return Err(NetError::Cancelled);
                }
            }
            let n = file.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            remote.write_all(&buf[..n]).await.map_err(map_ssh)?;
            done += n as u64;
            progress(done);
        }
        remote.shutdown().await.map_err(map_ssh)?; // close the handle server-side
        Ok(done)
    }
    .await;
    let _ = handle
        .disconnect(russh::Disconnect::ByApplication, "bye", "en")
        .await; // MEMO-2/CONC-4
    result
}

/// Delete a remote file or an empty remote directory.
pub async fn delete(
    spec: &ConnectionSpec,
    password: &str,
    remote_path: &str,
    is_dir: bool,
) -> Result<(), NetError> {
    let (handle, sftp) = open_session(spec, password).await?;
    let result: Result<(), NetError> = async {
        if is_dir {
            sftp.remove_dir(remote_path).await.map_err(map_ssh)?;
        } else {
            sftp.remove_file(remote_path).await.map_err(map_ssh)?;
        }
        Ok(())
    }
    .await;
    let _ = handle
        .disconnect(russh::Disconnect::ByApplication, "bye", "en")
        .await; // MEMO-2/CONC-4
    result
}
