//! SFTP client (russh 0.61 + russh-sftp 2.3). Pure Rust, no C deps.
//!
//! Host-key verification is explicit trust-on-first-use: a newly seen fingerprint stops the
//! connection before authentication and is never written automatically. The UI must display the
//! [`HostKeyChallenge`](crate::net::HostKeyChallenge), collect a clear confirmation, call
//! [`trust_host_key`], and reconnect. A changed fingerprint always fails closed.
//!
//! Session hygiene: every public operation opens `(Handle, SftpSession)` and explicitly
//! `disconnect()`s the Handle in a finally block. russh 0.61 `Handle::Drop` is a no-op
//! (only a debug log), so without the explicit disconnect every browse/transfer leaked an
//! authenticated SSH session and exhausted server MaxSessions/MaxStartups (MEMO-2/CONC-4).

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use russh_sftp::client::SftpSession;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::model::{ConnectionSpec, RemoteEntry};
use crate::net::error::{HostKeyChallenge, NetError};
use crate::net::RemoteTreeStats;

const SFTP_CONNECT_TIMEOUT: Duration = Duration::from_secs(20);
const SFTP_INACTIVITY_TIMEOUT: Duration = Duration::from_secs(90);
const SFTP_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(20);
const SFTP_KEEPALIVE_MAX: usize = 3;
const MAX_LISTING_ENTRIES: usize = 50_000;
const MAX_REMOTE_FILES: usize = 100_000;
const MAX_REMOTE_DIRECTORIES: usize = 10_000;
const MAX_RECURSION_DEPTH: usize = 64;

#[derive(Debug, Clone)]
enum HostKeyRejection {
    Unknown(HostKeyChallenge),
    Mismatch { endpoint: String },
    CheckFailed { endpoint: String, error: String },
}

struct Handler {
    /// Composite `host:port` key used for known_hosts lookups, so two SFTP servers on different
    /// ports of the same host get distinct trust entries (instead of colliding on the bare
    /// hostname, which caused false MITM rejections or cross-port key pinning).
    host_key: String,
    known_hosts: PathBuf,
    /// The SSH callback can only return a boolean. Keep the human-actionable rejection here so
    /// `open_session` can return it to the UI instead of losing it in a generic KEX error.
    rejection: Arc<Mutex<Option<HostKeyRejection>>>,
}

impl russh::client::Handler for Handler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        key: &russh::keys::ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        let fingerprint = key
            .fingerprint(russh::keys::ssh_key::HashAlg::Sha256)
            .to_string();
        let rejection = match check_known_host(&self.known_hosts, &self.host_key, &fingerprint) {
            Ok(HostKeyStatus::Trusted) => return Ok(true),
            Ok(HostKeyStatus::Unknown) => {
                HostKeyRejection::Unknown(HostKeyChallenge::new(self.host_key.clone(), fingerprint))
            }
            Ok(HostKeyStatus::Mismatch) => HostKeyRejection::Mismatch {
                endpoint: self.host_key.clone(),
            },
            Err(error) => HostKeyRejection::CheckFailed {
                endpoint: self.host_key.clone(),
                error,
            },
        };
        tracing::warn!(host_key = %self.host_key, "SFTP host-key check rejected the connection");
        if let Ok(mut pending) = self.rejection.lock() {
            *pending = Some(rejection);
        }
        // The verification callback is part of SSH key exchange: returning false ensures that no
        // password authentication or SFTP subsystem request can proceed on an untrusted key.
        Ok(false)
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HostKeyStatus {
    Trusted,
    Unknown,
    Mismatch,
}

/// Check a pinned fingerprint without mutating `known_hosts`.
///
/// `host_key` is the composite `host:port` trust key (see [`Handler`]). Old bare-host records
/// are intentionally not treated as a match: the user must verify and explicitly approve the
/// key for the actual port rather than silently extending a trust decision to a different
/// endpoint.
fn check_known_host(
    path: &std::path::Path,
    host_key: &str,
    fingerprint: &str,
) -> Result<HostKeyStatus, String> {
    let existing = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(e.to_string()),
    };
    for line in existing.lines() {
        if let Some((h, f)) = line.split_once(char::is_whitespace) {
            if h.trim() == host_key {
                return Ok(if f.trim() == fingerprint {
                    HostKeyStatus::Trusted
                } else {
                    HostKeyStatus::Mismatch
                });
            }
        }
    }
    Ok(HostKeyStatus::Unknown)
}

/// Persist a host key that the user has already verified and explicitly approved.
///
/// This is intentionally a separate operation from connecting. The caller should show
/// [`HostKeyChallenge::endpoint`] and [`HostKeyChallenge::fingerprint`] verbatim, require a
/// positive confirmation, call this function, and then retry the connection. If another process
/// pinned a different key in the meantime, this function fails closed and will not replace it.
pub fn trust_host_key(challenge: &HostKeyChallenge) -> Result<(), NetError> {
    let path =
        known_hosts_path().ok_or_else(|| NetError::Ssh("no config directory available".into()))?;
    persist_trusted_host_key(&path, challenge).map_err(NetError::HostKey)
}

fn persist_trusted_host_key(
    path: &std::path::Path,
    challenge: &HostKeyChallenge,
) -> Result<(), String> {
    if challenge.endpoint().is_empty()
        || challenge.fingerprint().is_empty()
        || challenge
            .endpoint()
            .bytes()
            .any(|b| b.is_ascii_control() || b.is_ascii_whitespace())
        || challenge
            .fingerprint()
            .bytes()
            .any(|b| b.is_ascii_control() || b.is_ascii_whitespace())
    {
        return Err("invalid host-key trust record".into());
    }
    let existing = match std::fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(e.to_string()),
    };
    for line in existing.lines() {
        if let Some((host, fingerprint)) = line.split_once(char::is_whitespace) {
            if host.trim() == challenge.endpoint() {
                if fingerprint.trim() == challenge.fingerprint() {
                    return Ok(()); // idempotent approval/retry
                }
                return Err(format!(
                    "refusing to replace the existing host key for {}",
                    challenge.endpoint()
                ));
            }
        }
    }
    // Atomic write (O_EXCL + 0600 + fsync + rename) so a crash mid-write cannot truncate a
    // trust anchor and silently re-open previously verified hosts to MITM.
    let mut content = existing;
    if !content.is_empty() && !content.ends_with('\n') {
        content.push('\n');
    }
    content.push_str(&format!(
        "{} {}\n",
        challenge.endpoint(),
        challenge.fingerprint()
    ));
    crate::store::vault::atomic_write(path, content.as_bytes()).map_err(|e| e.to_string())?;
    Ok(())
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
    // A connection that goes quiet must not retain a runtime task and authenticated socket
    // forever. Keepalives distinguish a temporarily idle SFTP operation from a dead peer.
    let config = Arc::new(russh::client::Config {
        inactivity_timeout: Some(SFTP_INACTIVITY_TIMEOUT),
        keepalive_interval: Some(SFTP_KEEPALIVE_INTERVAL),
        keepalive_max: SFTP_KEEPALIVE_MAX,
        nodelay: true,
        ..Default::default()
    });
    let rejection = Arc::new(Mutex::new(None));
    let handler = Handler {
        host_key: format!("{}:{}", spec.host, spec.effective_port()),
        known_hosts,
        rejection: rejection.clone(),
    };

    let mut handle = match tokio::time::timeout(
        SFTP_CONNECT_TIMEOUT,
        russh::client::connect(config, (spec.host.as_str(), spec.effective_port()), handler),
    )
    .await
    {
        Err(_) => {
            return Err(NetError::Ssh(format!(
                "SFTP connection to {} timed out after {} seconds",
                spec.host,
                SFTP_CONNECT_TIMEOUT.as_secs()
            )));
        }
        Ok(Ok(handle)) => handle,
        Ok(Err(error)) => {
            let rejection = rejection.lock().ok().and_then(|mut pending| pending.take());
            return match rejection {
                Some(HostKeyRejection::Unknown(challenge)) => {
                    Err(NetError::HostKeyTrustRequired(challenge))
                }
                Some(HostKeyRejection::Mismatch { endpoint }) => Err(NetError::HostKey(format!(
                    "stored fingerprint for {endpoint} does not match the server; refusing the connection"
                ))),
                Some(HostKeyRejection::CheckFailed { endpoint, error }) => {
                    Err(NetError::HostKey(format!(
                        "could not verify the stored host key for {endpoint}: {error}"
                    )))
                }
                None => Err(map_ssh(error)),
            };
        }
    };

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
        let entries = sftp.read_dir(&dir).await.map_err(map_ssh)?;
        for (index, entry) in entries.enumerate() {
            if index >= MAX_LISTING_ENTRIES {
                tracing::warn!(
                    "directory listing truncated at {MAX_LISTING_ENTRIES} entries (DoS guard)"
                );
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
    let mut directories_seen = 0;
    let result = walk_sftp(&sftp, &root, &mut out, 0, &mut directories_seen).await;
    let _ = handle
        .disconnect(russh::Disconnect::ByApplication, "bye", "en")
        .await; // MEMO-2/CONC-4
    let _truncated = result?;
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
    let effective_max_files = if max_files == 0 {
        MAX_REMOTE_FILES
    } else {
        max_files.min(MAX_REMOTE_FILES)
    };
    let mut directories_seen = 0;
    let result = tree_stats_sftp(
        &sftp,
        &root,
        &mut stats,
        effective_max_files,
        0,
        &mut directories_seen,
    )
    .await;
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
    depth: usize,
    directories_seen: &mut usize,
) -> Result<(), NetError> {
    if stats.truncated {
        return Ok(());
    }
    if depth >= MAX_RECURSION_DEPTH {
        tracing::warn!("SFTP tree statistics hit depth limit {MAX_RECURSION_DEPTH} (DoS guard)");
        stats.truncated = true;
        return Ok(());
    }
    if *directories_seen >= MAX_REMOTE_DIRECTORIES {
        tracing::warn!(
            "SFTP tree statistics hit directory limit {MAX_REMOTE_DIRECTORIES} (DoS guard)"
        );
        stats.truncated = true;
        return Ok(());
    }
    *directories_seen += 1;
    let entries = sftp.read_dir(dir).await.map_err(map_ssh)?;
    let mut listing_truncated = false;
    for (index, entry) in entries.enumerate() {
        if index >= MAX_LISTING_ENTRIES {
            tracing::warn!(
                "SFTP tree statistics truncated a directory at {MAX_LISTING_ENTRIES} entries (DoS guard)"
            );
            listing_truncated = true;
            break;
        }
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
            Box::pin(tree_stats_sftp(
                sftp,
                &full,
                stats,
                max_files,
                depth + 1,
                directories_seen,
            ))
            .await?;
        } else {
            stats.size = stats.size.saturating_add(attrs.size.unwrap_or(0));
            stats.files_scanned += 1;
            if let Some(mtime) = attrs.mtime.map(|t| t as i64) {
                stats.newest_mtime = Some(stats.newest_mtime.map_or(mtime, |cur| cur.max(mtime)));
            }
            if stats.files_scanned >= max_files {
                stats.truncated = true;
            }
        }
    }
    if listing_truncated {
        stats.truncated = true;
    }
    Ok(())
}

async fn walk_sftp(
    sftp: &SftpSession,
    dir: &str,
    out: &mut Vec<(String, u64)>,
    depth: usize,
    directories_seen: &mut usize,
) -> Result<bool, NetError> {
    if depth >= MAX_RECURSION_DEPTH {
        tracing::warn!("SFTP folder walk hit depth limit {MAX_RECURSION_DEPTH} (DoS guard)");
        return Ok(true);
    }
    if *directories_seen >= MAX_REMOTE_DIRECTORIES {
        tracing::warn!("SFTP folder walk hit directory limit {MAX_REMOTE_DIRECTORIES} (DoS guard)");
        return Ok(true);
    }
    if out.len() >= MAX_REMOTE_FILES {
        tracing::warn!("SFTP folder walk truncated at {MAX_REMOTE_FILES} files (DoS guard)");
        return Ok(true);
    }
    *directories_seen += 1;
    let entries = sftp.read_dir(dir).await.map_err(map_ssh)?;
    for (index, entry) in entries.enumerate() {
        if index >= MAX_LISTING_ENTRIES {
            tracing::warn!(
                "SFTP folder walk truncated a directory at {MAX_LISTING_ENTRIES} entries (DoS guard)"
            );
            return Ok(true);
        }
        if out.len() >= MAX_REMOTE_FILES {
            tracing::warn!("SFTP folder walk truncated at {MAX_REMOTE_FILES} files (DoS guard)");
            return Ok(true);
        }
        let name = entry.file_name();
        if name == "." || name == ".." {
            continue;
        }
        let full = join_remote_path(dir, &name);
        let attrs = entry.metadata();
        if attrs.is_dir() {
            if Box::pin(walk_sftp(sftp, &full, out, depth + 1, directories_seen)).await? {
                return Ok(true);
            }
        } else {
            out.push((full, attrs.size.unwrap_or(0)));
        }
    }
    Ok(false)
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Hermetic scratch dir with no additional test dependency. Auto-removed on drop.
    struct TestDir(PathBuf);

    impl TestDir {
        fn new() -> Self {
            static UNIQUE: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
            let path = std::env::temp_dir().join(format!(
                "gmacftp-sftp-known-hosts-{}-{}",
                std::process::id(),
                UNIQUE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            ));
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }

        fn file(&self) -> PathBuf {
            self.0.join("known_hosts")
        }
    }

    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn unknown_host_is_not_written_until_explicit_approval() {
        let dir = TestDir::new();
        let path = dir.file();
        let endpoint = "sftp.example.test:22";
        let fingerprint = "SHA256:exampleFingerprint";

        assert_eq!(
            check_known_host(&path, endpoint, fingerprint).unwrap(),
            HostKeyStatus::Unknown
        );
        assert!(
            !path.exists(),
            "merely checking a newly presented key must not create known_hosts"
        );

        let challenge = HostKeyChallenge::new(endpoint.into(), fingerprint.into());
        persist_trusted_host_key(&path, &challenge).unwrap();
        assert_eq!(
            check_known_host(&path, endpoint, fingerprint).unwrap(),
            HostKeyStatus::Trusted
        );
    }

    #[test]
    fn host_key_mismatch_fails_closed_and_cannot_replace_pin() {
        let dir = TestDir::new();
        let path = dir.file();
        let endpoint = "sftp.example.test:22";
        let original = HostKeyChallenge::new(endpoint.into(), "SHA256:original".into());
        let changed = HostKeyChallenge::new(endpoint.into(), "SHA256:changed".into());

        persist_trusted_host_key(&path, &original).unwrap();
        assert_eq!(
            check_known_host(&path, endpoint, changed.fingerprint()).unwrap(),
            HostKeyStatus::Mismatch
        );
        assert!(persist_trusted_host_key(&path, &changed).is_err());
        assert_eq!(
            check_known_host(&path, endpoint, original.fingerprint()).unwrap(),
            HostKeyStatus::Trusted
        );
    }
}
