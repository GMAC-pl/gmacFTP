//! SFTP client (russh 0.62 + russh-sftp 2.3). Pure Rust, no C deps.
//!
//! Host-key verification is explicit trust-on-first-use: a newly seen fingerprint stops the
//! connection before authentication and is never written automatically. The UI must display the
//! [`HostKeyChallenge`](crate::net::HostKeyChallenge), collect a clear confirmation, call
//! [`trust_host_key`], and reconnect. A changed fingerprint always fails closed.
//!
//! Session hygiene: every public operation explicitly closes its SFTP channel and asks the SSH
//! handle to disconnect in a finally-style cleanup path. In russh 0.62 `Handle::Drop` only emits
//! a debug log; it does not send a protocol disconnect or await remote cleanup. The explicit,
//! bounded close/disconnect below therefore releases remote resources deterministically.

use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use futures::stream::{FuturesOrdered, FuturesUnordered};
use futures::StreamExt;
use russh_sftp::client::error::Error as SftpError;
use russh_sftp::client::{Config as SftpConfig, RawSftpSession};
use russh_sftp::protocol::{FileAttributes, OpenFlags, StatusCode};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncSeekExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::model::{ConnectionSpec, RemoteEntry, SftpAuth};
use crate::net::error::{HostKeyChallenge, NetError};
use crate::net::partial::open_download_part;
use crate::net::safe::validate_remote_component;
use crate::net::{DownloadResume, RemoteTreeStats};

const SFTP_CONNECT_TIMEOUT: Duration = Duration::from_secs(20);
const SFTP_INACTIVITY_TIMEOUT: Duration = Duration::from_secs(90);
const SFTP_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(20);
const SFTP_KEEPALIVE_MAX: usize = 3;
/// Each protocol action has its own deadline. Transfers renew this for every 64 KiB read/write,
/// so a healthy slow transfer proceeds while a server that stalls any individual request cannot
/// hold an authenticated session indefinitely.
const SFTP_OPERATION_TIMEOUT: Duration = Duration::from_secs(30);
const SFTP_TRANSFER_CHUNK: u32 = 64 * 1024;
/// Multiple SFTP READ/WRITE requests may be in flight on one channel. Eight 64 KiB requests keep
/// a 512 KiB bandwidth-delay window without excessive memory use or pressure on small servers.
const SFTP_TRANSFER_PIPELINE: usize = 8;
/// `RawSftpSession`'s incoming packet reader otherwise accepts a server-declared length up to
/// `u32::MAX` before deserialisation. Enforce a cap on the framed stream itself, before that
/// allocation can happen. Normal OpenSSH SFTP packets are at most a few hundred KiB.
const MAX_SFTP_PACKET_BYTES: usize = 4 * 1024 * 1024;
const MAX_LISTING_ENTRIES: usize = 50_000;
const MAX_LISTING_BYTES: usize = 16 * 1024 * 1024;
const MAX_REMOTE_FILES: usize = 100_000;
const MAX_REMOTE_DIRECTORIES: usize = 10_000;
const MAX_RECURSION_DEPTH: usize = 64;
const MAX_PRIVATE_KEY_BYTES: u64 = 1024 * 1024;

/// Transparent SFTP stream wrapper that rejects an oversized incoming frame as soon as its
/// four-byte length prefix has arrived. Returning the error with the prefix read prevents the
/// upstream raw session from allocating the attacker-declared body.
struct BoundedSftpStream<S> {
    inner: S,
    header: [u8; 4],
    header_len: usize,
    frame_remaining: usize,
    failed: bool,
}

impl<S> BoundedSftpStream<S> {
    fn new(inner: S) -> Self {
        Self {
            inner,
            header: [0; 4],
            header_len: 0,
            frame_remaining: 0,
            failed: false,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for BoundedSftpStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if this.failed {
            // EOF on the read following the reported protocol error terminates russh-sftp's
            // handler task instead of letting it retry a permanently desynchronised stream.
            return Poll::Ready(Ok(()));
        }
        let before = buf.filled().len();
        match Pin::new(&mut this.inner).poll_read(cx, buf) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Ready(Ok(())) => {
                let mut offset = before;
                while offset < buf.filled().len() {
                    if this.frame_remaining > 0 {
                        let available = buf.filled().len() - offset;
                        let consumed = available.min(this.frame_remaining);
                        this.frame_remaining -= consumed;
                        offset += consumed;
                        continue;
                    }
                    let needed = 4 - this.header_len;
                    let available = buf.filled().len() - offset;
                    let copied = available.min(needed);
                    this.header[this.header_len..this.header_len + copied]
                        .copy_from_slice(&buf.filled()[offset..offset + copied]);
                    this.header_len += copied;
                    offset += copied;
                    if this.header_len == 4 {
                        let declared = u32::from_be_bytes(this.header) as usize;
                        this.header_len = 0;
                        if declared > MAX_SFTP_PACKET_BYTES {
                            this.failed = true;
                            return Poll::Ready(Err(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                format!(
                                    "SFTP packet declares {declared} bytes (limit {MAX_SFTP_PACKET_BYTES})"
                                ),
                            )));
                        }
                        this.frame_remaining = declared;
                    }
                }
                Poll::Ready(Ok(()))
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for BoundedSftpStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

static KNOWN_HOSTS_WRITE_MUTEX: OnceLock<Mutex<()>> = OnceLock::new();
const MAX_KNOWN_HOSTS_BYTES: u64 = 1024 * 1024;
const MAX_KNOWN_HOSTS_LOCK_BYTES: u64 = 256;
const KNOWN_HOSTS_LOCK_WAIT: Duration = Duration::from_secs(2);
const KNOWN_HOSTS_LOCK_RETRY: Duration = Duration::from_millis(20);
const KNOWN_HOSTS_OWNER_RECHECK: Duration = Duration::from_millis(250);
const KNOWN_HOSTS_INCOMPLETE_LOCK_GRACE: Duration = Duration::from_secs(30);

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

/// Process- and cross-process serialization for known_hosts updates. `create_new` is atomic, so
/// two gmacFTP processes cannot both read the old file and then overwrite each other's append.
/// The small bounded wait avoids hanging a connect forever if another process is mid-write.
struct KnownHostsWriteLock {
    _process_guard: MutexGuard<'static, ()>,
    lock_path: PathBuf,
    token: String,
    _lock_file: std::fs::File,
}

impl Drop for KnownHostsWriteLock {
    fn drop(&mut self) {
        // Remove only the file created by this guard. Besides avoiding an ABA unlink if the path
        // was replaced, this makes a same-user accidental/manual replacement fail closed.
        let is_ours = std::fs::symlink_metadata(&self.lock_path)
            .map(|metadata| metadata.file_type().is_file())
            .unwrap_or(false)
            && read_regular_file_limited(&self.lock_path, MAX_KNOWN_HOSTS_LOCK_BYTES)
                .and_then(|bytes| {
                    String::from_utf8(bytes).map_err(|error| {
                        std::io::Error::new(std::io::ErrorKind::InvalidData, error)
                    })
                })
                .map(|contents| contents == self.token)
                .unwrap_or(false);
        if is_ours {
            let _ = std::fs::remove_file(&self.lock_path);
        }
    }
}

fn known_hosts_lock_path(path: &std::path::Path) -> PathBuf {
    let mut lock_path = path.as_os_str().to_owned();
    lock_path.push(".lock");
    PathBuf::from(lock_path)
}

fn unix_timestamp_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(unix)]
fn process_is_running(pid: u32) -> bool {
    if pid == std::process::id() {
        return true;
    }
    // gmacFTP is a macOS application and `/bin/kill -0` performs a non-mutating existence check.
    // Treat an inability to run the check as "alive" so lock recovery always fails closed.
    std::process::Command::new("/bin/kill")
        .arg("-0")
        .arg(pid.to_string())
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(true)
}

#[cfg(not(unix))]
fn process_is_running(_pid: u32) -> bool {
    true
}

/// A completed lock records its owner PID. It is safe to reclaim only after that process has
/// exited. A crash between `create_new` and writing the token can leave an empty file, which is
/// reclaimed only after a grace period. Symlinks and malformed records are never removed.
fn known_hosts_lock_is_reclaimable(path: &std::path::Path) -> bool {
    let Ok(metadata) = std::fs::symlink_metadata(path) else {
        return false;
    };
    if !metadata.file_type().is_file() {
        return false;
    }
    let contents =
        match read_regular_file_limited(path, MAX_KNOWN_HOSTS_LOCK_BYTES).and_then(|bytes| {
            String::from_utf8(bytes)
                .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))
        }) {
            Ok(contents) => contents,
            Err(_) => return false,
        };
    let mut fields = contents.split_whitespace();
    let pid = fields.next().and_then(|value| value.parse::<u32>().ok());
    let created = fields.next().and_then(|value| value.parse::<u64>().ok());
    let nonce = fields.next();
    if fields.next().is_some() {
        return false;
    }
    match (pid, created, nonce) {
        (Some(pid), Some(_), Some(_)) => !process_is_running(pid),
        _ if contents.is_empty() => metadata
            .modified()
            .ok()
            .and_then(|modified| modified.elapsed().ok())
            .map(|age| age >= KNOWN_HOSTS_INCOMPLETE_LOCK_GRACE)
            .unwrap_or(false),
        _ => false,
    }
}

fn read_known_hosts(path: &std::path::Path) -> Result<String, String> {
    let bytes = match read_regular_file_limited(path, MAX_KNOWN_HOSTS_BYTES) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(String::new()),
        Err(error) => return Err(error.to_string()),
    };
    String::from_utf8(bytes).map_err(|_| "known_hosts is not valid UTF-8".into())
}

fn read_regular_file_limited(path: &std::path::Path, limit: u64) -> std::io::Result<Vec<u8>> {
    let before = std::fs::symlink_metadata(path)?;
    if !before.file_type().is_file() || before.len() > limit {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "file is not a bounded regular file",
        ));
    }
    let file = std::fs::File::open(path)?;
    let opened = file.metadata()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if before.dev() != opened.dev() || before.ino() != opened.ino() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "file changed while opening",
            ));
        }
    }
    if !opened.file_type().is_file() || opened.len() > limit {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "file changed type or size",
        ));
    }
    let mut bytes = Vec::with_capacity(opened.len() as usize);
    let mut limited = std::io::Read::take(file, limit.saturating_add(1));
    std::io::Read::read_to_end(&mut limited, &mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "file exceeds its size limit",
        ));
    }
    Ok(bytes)
}

/// Read a user-selected SSH private key without following a symlink and reject permissions that
/// expose the secret to another local account. The metadata checks are repeated on the opened
/// descriptor so a path replacement race cannot swap in a different file after validation.
fn read_private_key(path: &std::path::Path) -> std::io::Result<Vec<u8>> {
    let before = std::fs::symlink_metadata(path)?;
    if !before.file_type().is_file() || before.len() > MAX_PRIVATE_KEY_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "SSH private key must be a regular file no larger than 1 MiB",
        ));
    }

    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let file = options.open(path)?;
    let opened = file.metadata()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if before.dev() != opened.dev()
            || before.ino() != opened.ino()
            || opened.nlink() != 1
            || opened.mode() & 0o077 != 0
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "SSH private key changed while opening, is hard-linked, or is readable by other users (use chmod 600)",
            ));
        }
    }
    if !opened.file_type().is_file() || opened.len() > MAX_PRIVATE_KEY_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "SSH private key changed type or size while opening",
        ));
    }
    let mut bytes = Vec::with_capacity(opened.len() as usize);
    let mut limited = std::io::Read::take(file, MAX_PRIVATE_KEY_BYTES + 1);
    std::io::Read::read_to_end(&mut limited, &mut bytes)?;
    if bytes.len() as u64 > MAX_PRIVATE_KEY_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "SSH private key exceeds 1 MiB",
        ));
    }
    Ok(bytes)
}

fn private_key_path(spec: &ConnectionSpec) -> Result<PathBuf, NetError> {
    let raw = spec
        .sftp_private_key
        .as_deref()
        .map(str::trim)
        .filter(|path| !path.is_empty())
        .ok_or_else(|| NetError::Ssh("no SSH private key was selected".into()))?;
    if raw.as_bytes().contains(&0) {
        return Err(NetError::Ssh("SSH private-key path contains NUL".into()));
    }
    if raw == "~" || raw.starts_with("~/") {
        let home = directories::BaseDirs::new()
            .ok_or_else(|| NetError::Ssh("home directory is unavailable".into()))?;
        return Ok(if raw == "~" {
            home.home_dir().to_path_buf()
        } else {
            home.home_dir().join(&raw[2..])
        });
    }
    Ok(PathBuf::from(raw))
}

fn acquire_known_hosts_write_lock(
    known_hosts_path: &std::path::Path,
) -> Result<KnownHostsWriteLock, String> {
    if let Some(parent) = known_hosts_path.parent() {
        std::fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    let deadline = Instant::now() + KNOWN_HOSTS_LOCK_WAIT;
    let mutex = KNOWN_HOSTS_WRITE_MUTEX.get_or_init(|| Mutex::new(()));
    let process_guard = loop {
        match mutex.try_lock() {
            Ok(guard) => break guard,
            Err(std::sync::TryLockError::Poisoned(_)) => {
                return Err("known_hosts write mutex poisoned".into());
            }
            Err(std::sync::TryLockError::WouldBlock) if Instant::now() >= deadline => {
                return Err("known_hosts is busy (timed out waiting for in-process writer)".into());
            }
            Err(std::sync::TryLockError::WouldBlock) => {
                std::thread::sleep(KNOWN_HOSTS_LOCK_RETRY);
            }
        }
    };
    let lock_path = known_hosts_lock_path(known_hosts_path);
    let mut last_owner_check = None;
    loop {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(&lock_path) {
            Ok(mut lock_file) => {
                let token = format!(
                    "{} {} {}\n",
                    std::process::id(),
                    unix_timestamp_secs(),
                    rand::random::<u64>()
                );
                if let Err(error) = std::io::Write::write_all(&mut lock_file, token.as_bytes())
                    .and_then(|_| lock_file.sync_data())
                {
                    let _ = std::fs::remove_file(&lock_path);
                    return Err(format!("could not initialize known_hosts lock: {error}"));
                }
                return Ok(KnownHostsWriteLock {
                    _process_guard: process_guard,
                    lock_path,
                    token,
                    _lock_file: lock_file,
                });
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let check_owner = last_owner_check
                    .map(|last: Instant| last.elapsed() >= KNOWN_HOSTS_OWNER_RECHECK)
                    .unwrap_or(true);
                if check_owner {
                    last_owner_check = Some(Instant::now());
                }
                if check_owner && known_hosts_lock_is_reclaimable(&lock_path) {
                    match std::fs::remove_file(&lock_path) {
                        Ok(()) => continue,
                        Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                        Err(error) => {
                            return Err(format!(
                                "could not reclaim stale known_hosts lock {}: {error}",
                                lock_path.display()
                            ));
                        }
                    }
                }
                if Instant::now() >= deadline {
                    return Err(format!(
                        "known_hosts is busy (timed out waiting for {})",
                        lock_path.display()
                    ));
                }
                std::thread::sleep(KNOWN_HOSTS_LOCK_RETRY);
            }
            Err(error) => return Err(error.to_string()),
        }
    }
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
    let existing = read_known_hosts(path)?;
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
    // Acquire before the read and retain through atomic_write. Re-reading only after acquisition
    // closes the lost-update window between "is this endpoint already pinned?" and append.
    let _lock = acquire_known_hosts_write_lock(path)?;
    let existing = read_known_hosts(path)?;
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

async fn timed<T, E, F>(operation: &str, future: F) -> Result<T, NetError>
where
    E: std::fmt::Display,
    F: Future<Output = Result<T, E>>,
{
    match tokio::time::timeout(SFTP_OPERATION_TIMEOUT, future).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(error)) => Err(NetError::Ssh(format!("SFTP {operation} failed: {error}"))),
        Err(_) => Err(NetError::Ssh(format!(
            "SFTP {operation} timed out after {} seconds",
            SFTP_OPERATION_TIMEOUT.as_secs()
        ))),
    }
}

/// Best-effort, bounded teardown. The raw session closes its SFTP channel locally, while the SSH
/// disconnect waits at most [`SFTP_OPERATION_TIMEOUT`] for the peer's acknowledgement.
async fn close_session(
    handle: &mut russh::client::Handle<Handler>,
    sftp: &RawSftpSession,
    reason: &'static str,
) {
    let _ = sftp.close_session();
    let _ = timed(
        "disconnect",
        handle.disconnect(russh::Disconnect::ByApplication, reason, "en"),
    )
    .await;
}

async fn authenticate(
    handle: &mut russh::client::Handle<Handler>,
    spec: &ConnectionSpec,
    password_or_passphrase: &str,
) -> Result<bool, NetError> {
    match spec.sftp_auth {
        SftpAuth::Password => Ok(timed(
            "password authentication",
            handle.authenticate_password(spec.user.clone(), password_or_passphrase.to_string()),
        )
        .await?
        .success()),
        SftpAuth::PrivateKey => {
            let path = private_key_path(spec)?;
            let bytes = tokio::task::spawn_blocking(move || read_private_key(&path))
                .await
                .map_err(|error| NetError::Join(error.to_string()))??;
            let encoded = zeroize::Zeroizing::new(String::from_utf8(bytes).map_err(|_| {
                NetError::Ssh("SSH private key is not valid UTF-8/OpenSSH text".into())
            })?);
            let passphrase = (!password_or_passphrase.is_empty()).then_some(password_or_passphrase);
            let key = russh::keys::decode_secret_key(&encoded, passphrase).map_err(|error| {
                NetError::Ssh(format!("could not unlock SSH private key: {error}"))
            })?;
            // RustCrypto's transitive `rsa` crate still carries RUSTSEC-2023-0071. Loading is
            // local, but signing would expose private-key timing to the server. Keep built-in key
            // auth on Ed25519/ECDSA; RSA remains available safely through SSH Agent, where the
            // private operation is delegated to the system agent instead of this dependency.
            if key.algorithm().is_rsa() {
                return Err(NetError::Ssh(
                    "built-in RSA private keys are disabled; use an Ed25519/ECDSA key or SSH Agent"
                        .into(),
                ));
            }
            Ok(timed(
                "private-key authentication",
                handle.authenticate_publickey(
                    spec.user.clone(),
                    russh::keys::PrivateKeyWithHashAlg::new(Arc::new(key), None),
                ),
            )
            .await?
            .success())
        }
        SftpAuth::Agent => {
            #[cfg(unix)]
            {
                let mut agent = timed(
                    "connect to SSH agent",
                    russh::keys::agent::client::AgentClient::connect_env(),
                )
                .await?;
                let identities =
                    timed("read SSH agent identities", agent.request_identities()).await?;
                if identities.is_empty() {
                    return Err(NetError::Ssh("SSH agent has no identities".into()));
                }
                let rsa_hash = timed("negotiate RSA signature", handle.best_supported_rsa_hash())
                    .await?
                    .flatten();
                for identity in identities {
                    let auth = match identity {
                        russh::keys::agent::AgentIdentity::PublicKey { key, .. } => {
                            let hash = key.algorithm().is_rsa().then_some(rsa_hash).flatten();
                            timed(
                                "SSH-agent authentication",
                                handle.authenticate_publickey_with(
                                    spec.user.clone(),
                                    key,
                                    hash,
                                    &mut agent,
                                ),
                            )
                            .await?
                        }
                        russh::keys::agent::AgentIdentity::Certificate { certificate, .. } => {
                            let hash = certificate
                                .algorithm()
                                .is_rsa()
                                .then_some(rsa_hash)
                                .flatten();
                            timed(
                                "SSH-agent certificate authentication",
                                handle.authenticate_certificate_with(
                                    spec.user.clone(),
                                    certificate,
                                    hash,
                                    &mut agent,
                                ),
                            )
                            .await?
                        }
                    };
                    if auth.success() {
                        return Ok(true);
                    }
                }
                Ok(false)
            }
            #[cfg(not(unix))]
            {
                Err(NetError::Ssh(
                    "SSH Agent authentication is not supported on this platform".into(),
                ))
            }
        }
    }
}

/// Connect, authenticate, open and initialize the SFTP subsystem. Listing uses the raw request
/// API rather than `SftpSession::read_dir`, whose convenience implementation first accumulates
/// every REaddir page into a Vec.
async fn open_session(
    spec: &ConnectionSpec,
    password: &str,
) -> Result<(russh::client::Handle<Handler>, RawSftpSession), NetError> {
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

    let authenticated = match authenticate(&mut handle, spec, password).await {
        Ok(authenticated) => authenticated,
        Err(error) => {
            let _ = timed(
                "disconnect",
                handle.disconnect(russh::Disconnect::ByApplication, "auth-error", "en"),
            )
            .await;
            return Err(error);
        }
    };
    if !authenticated {
        let _ = timed(
            "disconnect",
            handle.disconnect(russh::Disconnect::ByApplication, "auth-failed", "en"),
        )
        .await;
        return Err(NetError::AuthFailed(spec.user.clone()));
    }

    let channel = match timed("open SFTP channel", handle.channel_open_session()).await {
        Ok(c) => c,
        Err(e) => {
            let _ = timed(
                "disconnect",
                handle.disconnect(russh::Disconnect::ByApplication, "chan-open-failed", "en"),
            )
            .await;
            return Err(e);
        }
    };
    if let Err(e) = timed(
        "request SFTP subsystem",
        channel.request_subsystem(true, "sftp"),
    )
    .await
    {
        let _ = timed(
            "disconnect",
            handle.disconnect(russh::Disconnect::ByApplication, "subsystem-failed", "en"),
        )
        .await;
        return Err(e);
    }
    let sftp = RawSftpSession::new_with_config(
        BoundedSftpStream::new(channel.into_stream()),
        SftpConfig {
            // The packet cap is enforced by `BoundedSftpStream` because RawSftpSession does not
            // apply this config field to incoming packets. Its internal request deadline still
            // matches the hard operation deadline used at this layer.
            max_packet_len: MAX_SFTP_PACKET_BYTES as u32,
            request_timeout_secs: SFTP_OPERATION_TIMEOUT.as_secs(),
            ..Default::default()
        },
    );
    match timed("initialize SFTP", sftp.init()).await {
        Ok(_) => Ok((handle, sftp)),
        Err(e) => {
            close_session(&mut handle, &sftp, "sftp-init-failed").await;
            Err(e)
        }
    }
}

/// Authenticated SFTP channel reusable by the transfer scheduler. Browsing operations retain
/// their short-lived sessions; queued files on the same endpoint can share this one handshake.
pub struct TransferSession {
    handle: russh::client::Handle<Handler>,
    sftp: RawSftpSession,
}

impl TransferSession {
    pub async fn connect(spec: &ConnectionSpec, password: &str) -> Result<Self, NetError> {
        let (handle, sftp) = open_session(spec, password).await?;
        Ok(Self { handle, sftp })
    }

    pub async fn download(
        &self,
        remote_path: &str,
        local_path: &std::path::Path,
        progress: impl Fn(u64) + Send,
        cancel: Option<&AtomicBool>,
    ) -> Result<u64, NetError> {
        self.download_resumable(remote_path, local_path, progress, cancel, None)
            .await
    }

    pub async fn download_resumable(
        &self,
        remote_path: &str,
        local_path: &std::path::Path,
        progress: impl Fn(u64) + Send,
        cancel: Option<&AtomicBool>,
        resume: Option<DownloadResume>,
    ) -> Result<u64, NetError> {
        download_with_session(
            &self.sftp,
            remote_path,
            local_path,
            progress,
            cancel,
            resume,
        )
        .await
    }

    pub async fn upload(
        &self,
        local_path: &std::path::Path,
        remote_path: &str,
        progress: impl Fn(u64) + Send,
        cancel: Option<&AtomicBool>,
    ) -> Result<u64, NetError> {
        let file = tokio::fs::File::open(local_path).await?;
        upload_with_session(&self.sftp, file, remote_path, progress, cancel).await
    }

    pub async fn close(mut self, reason: &'static str) {
        close_session(&mut self.handle, &self.sftp, reason).await;
    }
}

/// Create a remote dir and all ancestors (mkdir -p). Existing segments are ignored.
async fn mkdirs_sftp(sftp: &RawSftpSession, remote_dir: &str) -> Result<(), NetError> {
    let clean = remote_dir.trim_matches('/');
    if clean.is_empty() {
        return Ok(());
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
        // Existing directories are intentionally tolerated. Any other mkdir error (including a
        // timeout) must propagate instead of being silently converted into a later file-open
        // failure with a misleading message.
        if let Err(mkdir_error) =
            timed("mkdir", sftp.mkdir(acc.clone(), FileAttributes::empty())).await
        {
            match timed("verify existing directory", sftp.stat(acc.clone())).await {
                Ok(attributes) if attributes.attrs.is_dir() => {}
                _ => return Err(mkdir_error),
            }
        }
    }
    Ok(())
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
    let (mut handle, sftp) = open_session(spec, password).await?;
    let dir = if spec.initial_path.trim().is_empty() {
        "."
    } else {
        spec.initial_path.as_str()
    };
    let result = list_dir_bounded(&sftp, dir).await;
    close_session(&mut handle, &sftp, "bye").await;
    result.map(|listing| listing.entries)
}

struct SftpListing {
    entries: Vec<RemoteEntry>,
    truncated: bool,
}

/// Stream SFTP `OPENDIR`/`READDIR` pages. Unlike `SftpSession::read_dir`, this never gathers all
/// pages into one Vec. The directory handle is closed on success, failure and truncation.
async fn list_dir_bounded(sftp: &RawSftpSession, dir: &str) -> Result<SftpListing, NetError> {
    let handle = timed("open directory", sftp.opendir(dir.to_string())).await?;
    let handle_name = handle.handle;
    let mut entries = Vec::new();
    let mut stored_bytes = 0usize;
    let mut truncated = false;
    let result: Result<(), NetError> = async {
        loop {
            let page = match tokio::time::timeout(
                SFTP_OPERATION_TIMEOUT,
                sftp.readdir(handle_name.clone()),
            )
            .await
            {
                Ok(Ok(page)) => page,
                Ok(Err(SftpError::Status(status))) if status.status_code == StatusCode::Eof => {
                    break;
                }
                Ok(Err(error)) => {
                    return Err(NetError::Ssh(format!("SFTP readdir failed: {error}")));
                }
                Err(_) => {
                    return Err(NetError::Ssh(format!(
                        "SFTP readdir timed out after {} seconds",
                        SFTP_OPERATION_TIMEOUT.as_secs()
                    )));
                }
            };
            for file in page.files {
                if file.filename == "." || file.filename == ".." {
                    continue;
                }
                validate_remote_component(&file.filename)?;
                let next_bytes = stored_bytes.saturating_add(file.filename.len());
                if entries.len() >= MAX_LISTING_ENTRIES || next_bytes > MAX_LISTING_BYTES {
                    truncated = true;
                    break;
                }
                stored_bytes = next_bytes;
                entries.push(RemoteEntry {
                    name: file.filename,
                    is_dir: file.attrs.is_dir(),
                    size: file.attrs.size.unwrap_or(0),
                    mtime: file.attrs.mtime.map(|time| time as i64),
                });
            }
            if truncated {
                tracing::warn!(
                    "SFTP directory listing truncated at {MAX_LISTING_ENTRIES} entries (DoS guard)"
                );
                break;
            }
        }
        Ok(())
    }
    .await;
    let close_result = timed("close directory", sftp.close(handle_name)).await;
    match result {
        Err(error) => Err(error),
        Ok(()) => {
            close_result?;
            crate::model::sort_entries(&mut entries);
            Ok(SftpListing { entries, truncated })
        }
    }
}

/// Recursively collect every FILE under `root_dir` as `(absolute_remote_path, size)`.
/// Used for folder downloads.
pub async fn walk(
    spec: &ConnectionSpec,
    password: &str,
    root_dir: &str,
) -> Result<Vec<(String, u64)>, NetError> {
    let (mut handle, sftp) = open_session(spec, password).await?;
    let root = if root_dir.trim().is_empty() {
        ".".to_string()
    } else {
        root_dir.to_string()
    };
    let mut out = Vec::new();
    let mut directories_seen = 0;
    let result = walk_sftp(&sftp, &root, &mut out, 0, &mut directories_seen).await;
    close_session(&mut handle, &sftp, "bye").await;
    if result? {
        Err(NetError::Ssh(
            "remote folder walk exceeded a safety limit; refusing an incomplete copy".into(),
        ))
    } else {
        Ok(out)
    }
}

pub async fn tree_stats(
    spec: &ConnectionSpec,
    password: &str,
    root_dir: &str,
    max_files: usize,
) -> Result<RemoteTreeStats, NetError> {
    let (mut handle, sftp) = open_session(spec, password).await?;
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
    close_session(&mut handle, &sftp, "bye").await;
    result?;
    Ok(stats)
}

async fn tree_stats_sftp(
    sftp: &RawSftpSession,
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
    let listing = list_dir_bounded(sftp, dir).await?;
    let listing_truncated = listing.truncated;
    for entry in listing.entries {
        if stats.truncated {
            break;
        }
        let full = join_remote_path(dir, &entry.name);
        if entry.is_dir {
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
            stats.size = stats.size.saturating_add(entry.size);
            stats.files_scanned += 1;
            if let Some(mtime) = entry.mtime {
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
    sftp: &RawSftpSession,
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
    let listing = list_dir_bounded(sftp, dir).await?;
    if listing.truncated {
        return Ok(true);
    }
    for entry in listing.entries {
        if out.len() >= MAX_REMOTE_FILES {
            tracing::warn!("SFTP folder walk truncated at {MAX_REMOTE_FILES} files (DoS guard)");
            return Ok(true);
        }
        let full = join_remote_path(dir, &entry.name);
        if entry.is_dir {
            if Box::pin(walk_sftp(sftp, &full, out, depth + 1, directories_seen)).await? {
                return Ok(true);
            }
        } else {
            out.push((full, entry.size));
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

enum SftpReadChunk {
    Data(Vec<u8>),
    Eof,
}

async fn read_transfer_chunk(
    sftp: &RawSftpSession,
    handle: String,
    offset: u64,
    len: u32,
) -> (u64, u32, Result<SftpReadChunk, NetError>) {
    let result =
        match tokio::time::timeout(SFTP_OPERATION_TIMEOUT, sftp.read(handle, offset, len)).await {
            Ok(Ok(data)) if data.data.is_empty() => Err(NetError::Ssh(
                "SFTP read returned empty data without EOF".into(),
            )),
            Ok(Ok(data)) if data.data.len() > len as usize => Err(NetError::Ssh(format!(
                "SFTP server returned {} bytes for a {len}-byte read",
                data.data.len()
            ))),
            Ok(Ok(data)) => Ok(SftpReadChunk::Data(data.data)),
            Ok(Err(SftpError::Status(status))) if status.status_code == StatusCode::Eof => {
                Ok(SftpReadChunk::Eof)
            }
            Ok(Err(error)) => Err(NetError::Ssh(format!("SFTP read failed: {error}"))),
            Err(_) => Err(NetError::Ssh(format!(
                "SFTP read timed out after {} seconds",
                SFTP_OPERATION_TIMEOUT.as_secs()
            ))),
        };
    (offset, len, result)
}

async fn write_transfer_chunk(
    sftp: &RawSftpSession,
    handle: String,
    offset: u64,
    data: Vec<u8>,
) -> (usize, Result<(), NetError>) {
    let len = data.len();
    let result = timed("write remote file", sftp.write(handle, offset, data))
        .await
        .map(|_| ());
    (len, result)
}

/// Download `remote_path` to `local_path`, reporting cumulative bytes via `progress`.
/// Writes to a unique private sibling and renames on success — a failure leaves no partial file.
#[allow(dead_code)] // wired in by the transfer actor (M6)
pub async fn download(
    spec: &ConnectionSpec,
    password: &str,
    remote_path: &str,
    local_path: &std::path::Path,
    progress: impl Fn(u64) + Send,
    cancel: Option<&AtomicBool>, // M1
) -> Result<u64, NetError> {
    let session = TransferSession::connect(spec, password).await?;
    let result = session
        .download(remote_path, local_path, progress, cancel)
        .await;
    session.close("bye").await;
    result
}

async fn download_with_session(
    sftp: &RawSftpSession,
    remote_path: &str,
    local_path: &std::path::Path,
    progress: impl Fn(u64) + Send,
    cancel: Option<&AtomicBool>,
    resume: Option<DownloadResume>,
) -> Result<u64, NetError> {
    if let Some(parent) = local_path.parent() {
        tokio::fs::create_dir_all(parent).await?; // supports folder downloads
    }
    let part = open_download_part(local_path, resume)?;
    let part_path = part.path;
    let keep_on_error = part.keep_on_error;
    let offset = part.offset;
    let mut file = tokio::fs::File::from_std(part.file);
    file.seek(std::io::SeekFrom::Start(offset)).await?;
    let remote = match timed(
        "open remote file for download",
        sftp.open(
            remote_path.to_string(),
            OpenFlags::READ,
            FileAttributes::empty(),
        ),
    )
    .await
    {
        Ok(remote) => remote,
        Err(error) => {
            if !keep_on_error {
                let _ = tokio::fs::remove_file(&part_path).await;
            }
            return Err(error);
        }
    };
    let remote_handle = remote.handle;
    let result: Result<u64, NetError> = async {
        let mut done = offset;
        let mut next_offset = offset;
        if done > 0 {
            progress(done);
        }
        let mut reads = FuturesOrdered::new();
        for _ in 0..SFTP_TRANSFER_PIPELINE {
            reads.push_back(read_transfer_chunk(
                sftp,
                remote_handle.clone(),
                next_offset,
                SFTP_TRANSFER_CHUNK,
            ));
            next_offset = next_offset.saturating_add(SFTP_TRANSFER_CHUNK as u64);
        }

        'download: while let Some((offset, requested, response)) = reads.next().await {
            if let Some(f) = cancel {
                if f.load(Ordering::Relaxed) {
                    return Err(NetError::Cancelled);
                }
            }
            if offset != done {
                return Err(NetError::Ssh(format!(
                    "SFTP download response gap: expected offset {done}, received {offset}"
                )));
            }

            // Servers are allowed to return less data than requested before EOF. Fill that rare
            // short-read gap synchronously so the already-pipelined next fixed offset can never
            // leave missing bytes in the local file.
            let mut response = response;
            let mut chunk_offset = offset;
            let mut remaining = requested;
            loop {
                match response? {
                    SftpReadChunk::Eof => break 'download,
                    SftpReadChunk::Data(data) => {
                        file.write_all(&data).await?;
                        let received = u32::try_from(data.len()).map_err(|_| {
                            NetError::Ssh("SFTP read length did not fit in u32".into())
                        })?;
                        done = done.saturating_add(received as u64);
                        chunk_offset = chunk_offset.saturating_add(received as u64);
                        remaining = remaining.checked_sub(received).ok_or_else(|| {
                            NetError::Ssh("SFTP server returned overlapping data".into())
                        })?;
                        progress(done);
                        if remaining == 0 {
                            break;
                        }
                    }
                }
                if let Some(f) = cancel {
                    if f.load(Ordering::Relaxed) {
                        return Err(NetError::Cancelled);
                    }
                }
                let (_, _, gap_response) =
                    read_transfer_chunk(sftp, remote_handle.clone(), chunk_offset, remaining).await;
                response = gap_response;
            }

            reads.push_back(read_transfer_chunk(
                sftp,
                remote_handle.clone(),
                next_offset,
                SFTP_TRANSFER_CHUNK,
            ));
            next_offset = next_offset.saturating_add(SFTP_TRANSFER_CHUNK as u64);
        }
        file.sync_all().await?;
        Ok(done)
    }
    .await;
    let close_result = timed("close downloaded file", sftp.close(remote_handle)).await;
    match result {
        Ok(done) => {
            if let Err(error) = close_result {
                if !keep_on_error {
                    let _ = tokio::fs::remove_file(&part_path).await;
                }
                return Err(error);
            }
            match tokio::fs::rename(&part_path, local_path).await {
                Ok(()) => Ok(done),
                Err(error) => {
                    let _ = tokio::fs::remove_file(&part_path).await;
                    Err(error.into())
                }
            }
        }
        Err(e) => {
            if !keep_on_error {
                let _ = tokio::fs::remove_file(&part_path).await;
            }
            Err(e)
        }
    }
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
    // Open local input before authenticating. A local permission/not-found error must not leave a
    // remote session alive merely because `?` returned before the teardown path was installed.
    let file = tokio::fs::File::open(local_path).await?;
    let session = TransferSession::connect(spec, password).await?;
    let result = upload_with_session(&session.sftp, file, remote_path, progress, cancel).await;
    session.close("bye").await;
    result
}

async fn upload_with_session(
    sftp: &RawSftpSession,
    mut file: tokio::fs::File,
    remote_path: &str,
    progress: impl Fn(u64) + Send,
    cancel: Option<&AtomicBool>,
) -> Result<u64, NetError> {
    let result: Result<u64, NetError> = async {
        if let Some(parent) = parent_remote(remote_path) {
            mkdirs_sftp(sftp, &parent).await?; // supports folder uploads (mkdir -p ancestors)
        }
        let remote = timed(
            "open remote file for upload",
            sftp.open(
                remote_path.to_string(),
                OpenFlags::CREATE | OpenFlags::TRUNCATE | OpenFlags::WRITE,
                FileAttributes::empty(),
            ),
        )
        .await?;
        let remote_handle = remote.handle;
        let transfer_result: Result<u64, NetError> = async {
            let mut writes = FuturesUnordered::new();
            let mut next_offset = 0_u64;
            let mut acknowledged = 0_u64;
            let mut eof = false;
            loop {
                if let Some(f) = cancel {
                    if f.load(Ordering::Relaxed) {
                        return Err(NetError::Cancelled);
                    }
                }

                while writes.len() < SFTP_TRANSFER_PIPELINE && !eof {
                    let mut data = vec![0_u8; SFTP_TRANSFER_CHUNK as usize];
                    let read = file.read(&mut data).await?;
                    if read == 0 {
                        eof = true;
                        break;
                    }
                    data.truncate(read);
                    writes.push(write_transfer_chunk(
                        sftp,
                        remote_handle.clone(),
                        next_offset,
                        data,
                    ));
                    next_offset = next_offset.saturating_add(read as u64);
                }

                let Some((written, result)) = writes.next().await else {
                    break;
                };
                result?;
                acknowledged = acknowledged.saturating_add(written as u64);
                progress(acknowledged);
            }
            Ok(acknowledged)
        }
        .await;
        let close_result = timed("close uploaded file", sftp.close(remote_handle)).await;
        match transfer_result {
            Ok(done) => {
                close_result?;
                Ok(done)
            }
            Err(error) => Err(error),
        }
    }
    .await;
    result
}

pub async fn rename(
    spec: &ConnectionSpec,
    password: &str,
    from: &str,
    to: &str,
) -> Result<(), NetError> {
    let (mut handle, sftp) = open_session(spec, password).await?;
    let result = timed("rename path", sftp.rename(from.to_string(), to.to_string()))
        .await
        .map(|_| ());
    close_session(&mut handle, &sftp, "bye").await;
    result
}

pub async fn create_dir(spec: &ConnectionSpec, password: &str, path: &str) -> Result<(), NetError> {
    let (mut handle, sftp) = open_session(spec, password).await?;
    let result = timed(
        "create directory",
        sftp.mkdir(path.to_string(), FileAttributes::empty()),
    )
    .await
    .map(|_| ());
    close_session(&mut handle, &sftp, "bye").await;
    result
}

pub async fn chmod(
    spec: &ConnectionSpec,
    password: &str,
    path: &str,
    mode: u32,
) -> Result<(), NetError> {
    if mode > 0o777 {
        return Err(NetError::InvalidPath("invalid permission mode".into()));
    }
    let (mut handle, sftp) = open_session(spec, password).await?;
    let mut attributes = FileAttributes::empty();
    attributes.permissions = Some(mode);
    let result = timed(
        "change permissions",
        sftp.setstat(path.to_string(), attributes),
    )
    .await
    .map(|_| ());
    close_session(&mut handle, &sftp, "bye").await;
    result
}

async fn collect_delete_tree(
    sftp: &RawSftpSession,
    path: &str,
    out: &mut Vec<(String, bool)>,
    depth: usize,
    directories: &mut usize,
) -> Result<(), NetError> {
    if depth >= MAX_RECURSION_DEPTH || *directories >= MAX_REMOTE_DIRECTORIES {
        return Err(NetError::Ssh(
            "remote folder exceeds recursive-delete safety limits".into(),
        ));
    }
    *directories += 1;
    let listing = list_dir_bounded(sftp, path).await?;
    if listing.truncated {
        return Err(NetError::Ssh(
            "remote folder listing was truncated; refusing incomplete delete".into(),
        ));
    }
    for entry in listing.entries {
        if out.len() >= MAX_REMOTE_FILES + MAX_REMOTE_DIRECTORIES {
            return Err(NetError::Ssh(
                "remote folder exceeds recursive-delete safety limits".into(),
            ));
        }
        let child = join_remote_path(path, &entry.name);
        if entry.is_dir {
            Box::pin(collect_delete_tree(
                sftp,
                &child,
                out,
                depth + 1,
                directories,
            ))
            .await?;
        } else {
            out.push((child, false));
        }
    }
    out.push((path.to_string(), true));
    Ok(())
}

/// Delete a remote file or an empty remote directory.
pub async fn delete(
    spec: &ConnectionSpec,
    password: &str,
    remote_path: &str,
    is_dir: bool,
) -> Result<(), NetError> {
    let (mut handle, sftp) = open_session(spec, password).await?;
    let result: Result<(), NetError> = async {
        if is_dir {
            let mut paths = Vec::new();
            let mut directories = 0;
            collect_delete_tree(&sftp, remote_path, &mut paths, 0, &mut directories).await?;
            for (path, directory) in paths {
                if directory {
                    timed("remove directory", sftp.rmdir(path)).await?;
                } else {
                    timed("remove file", sftp.remove(path)).await?;
                }
            }
        } else {
            timed("remove file", sftp.remove(remote_path.to_string())).await?;
        }
        Ok(())
    }
    .await;
    close_session(&mut handle, &sftp, "bye").await;
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use russh_sftp::protocol::{Data, Handle, Status, Version};

    struct MemorySftpServer {
        data: Arc<Mutex<Vec<u8>>>,
        short_reads: bool,
    }

    impl russh_sftp::server::Handler for MemorySftpServer {
        type Error = StatusCode;

        fn unimplemented(&self) -> Self::Error {
            StatusCode::OpUnsupported
        }

        async fn init(
            &mut self,
            _version: u32,
            _extensions: std::collections::HashMap<String, String>,
        ) -> Result<Version, Self::Error> {
            Ok(Version::new())
        }

        async fn open(
            &mut self,
            id: u32,
            _filename: String,
            flags: OpenFlags,
            _attrs: FileAttributes,
        ) -> Result<Handle, Self::Error> {
            if flags.contains(OpenFlags::TRUNCATE) {
                self.data.lock().unwrap().clear();
            }
            Ok(Handle {
                id,
                handle: "memory-file".into(),
            })
        }

        async fn close(&mut self, id: u32, _handle: String) -> Result<Status, Self::Error> {
            Ok(Status {
                id,
                status_code: StatusCode::Ok,
                error_message: "Ok".into(),
                language_tag: "en-US".into(),
            })
        }

        async fn read(
            &mut self,
            id: u32,
            _handle: String,
            offset: u64,
            len: u32,
        ) -> Result<Data, Self::Error> {
            let data = self.data.lock().unwrap();
            let start = usize::try_from(offset).map_err(|_| StatusCode::Failure)?;
            if start >= data.len() {
                return Err(StatusCode::Eof);
            }
            let requested = len as usize;
            let returned = if self.short_reads {
                requested.min(7_919)
            } else {
                requested
            };
            let end = start.saturating_add(returned).min(data.len());
            Ok(Data {
                id,
                data: data[start..end].to_vec(),
            })
        }

        async fn write(
            &mut self,
            id: u32,
            _handle: String,
            offset: u64,
            bytes: Vec<u8>,
        ) -> Result<Status, Self::Error> {
            let start = usize::try_from(offset).map_err(|_| StatusCode::Failure)?;
            let end = start.checked_add(bytes.len()).ok_or(StatusCode::Failure)?;
            let mut data = self.data.lock().unwrap();
            let new_len = data.len().max(end);
            data.resize(new_len, 0);
            data[start..end].copy_from_slice(&bytes);
            Ok(Status {
                id,
                status_code: StatusCode::Ok,
                error_message: "Ok".into(),
                language_tag: "en-US".into(),
            })
        }
    }

    async fn memory_sftp(data: Arc<Mutex<Vec<u8>>>, short_reads: bool) -> RawSftpSession {
        let (client, server) = tokio::io::duplex(2 * 1024 * 1024);
        russh_sftp::server::run(server, MemorySftpServer { data, short_reads }).await;
        let sftp = RawSftpSession::new_with_config(
            client,
            SftpConfig {
                request_timeout_secs: 5,
                ..Default::default()
            },
        );
        sftp.init().await.unwrap();
        sftp
    }

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

    #[test]
    fn concurrent_host_key_approvals_do_not_lose_updates() {
        let dir = TestDir::new();
        let path = std::sync::Arc::new(dir.file());
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let first_path = path.clone();
        let first_barrier = barrier.clone();
        let first = std::thread::spawn(move || {
            first_barrier.wait();
            let challenge =
                HostKeyChallenge::new("one.example.test:22".into(), "SHA256:one".into());
            persist_trusted_host_key(&first_path, &challenge)
        });
        let second_path = path.clone();
        let second = std::thread::spawn(move || {
            barrier.wait();
            let challenge =
                HostKeyChallenge::new("two.example.test:22".into(), "SHA256:two".into());
            persist_trusted_host_key(&second_path, &challenge)
        });
        first.join().unwrap().unwrap();
        second.join().unwrap().unwrap();

        assert_eq!(
            check_known_host(&path, "one.example.test:22", "SHA256:one").unwrap(),
            HostKeyStatus::Trusted
        );
        assert_eq!(
            check_known_host(&path, "two.example.test:22", "SHA256:two").unwrap(),
            HostKeyStatus::Trusted
        );
    }

    #[test]
    fn stale_known_hosts_lock_is_reclaimed_but_live_owner_is_not() {
        let dir = TestDir::new();
        let lock = known_hosts_lock_path(&dir.file());
        std::fs::write(&lock, "2147483647 1 abandoned\n").unwrap();
        assert!(known_hosts_lock_is_reclaimable(&lock));

        std::fs::write(&lock, format!("{} 1 live\n", std::process::id())).unwrap();
        assert!(!known_hosts_lock_is_reclaimable(&lock));
    }

    #[test]
    fn known_hosts_rejects_oversized_and_non_regular_files() {
        let dir = TestDir::new();
        let path = dir.file();
        std::fs::write(&path, vec![b'x'; (MAX_KNOWN_HOSTS_BYTES + 1) as usize]).unwrap();
        assert!(read_known_hosts(&path).is_err());

        std::fs::remove_file(&path).unwrap();
        let target = dir.0.join("target");
        std::fs::write(&target, b"host fingerprint\n").unwrap();
        std::os::unix::fs::symlink(&target, &path).unwrap();
        assert!(read_known_hosts(&path).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn private_key_reader_requires_a_private_regular_file() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TestDir::new();
        let key = dir.0.join("id_test");
        std::fs::write(&key, b"private key bytes").unwrap();
        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(read_private_key(&key).unwrap(), b"private key bytes");

        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_private_key(&key).is_err());

        std::fs::set_permissions(&key, std::fs::Permissions::from_mode(0o600)).unwrap();
        let link = dir.0.join("id_link");
        std::os::unix::fs::symlink(&key, &link).unwrap();
        assert!(read_private_key(&link).is_err());

        let oversized = dir.0.join("id_oversized");
        std::fs::write(&oversized, vec![0; (MAX_PRIVATE_KEY_BYTES + 1) as usize]).unwrap();
        std::fs::set_permissions(&oversized, std::fs::Permissions::from_mode(0o600)).unwrap();
        assert!(read_private_key(&oversized).is_err());
    }

    #[tokio::test]
    async fn incoming_sftp_packet_length_is_bounded_before_body_allocation() {
        let (mut sender, receiver) = tokio::io::duplex(32);
        sender
            .write_all(&((MAX_SFTP_PACKET_BYTES as u32) + 1).to_be_bytes())
            .await
            .unwrap();
        let mut bounded = BoundedSftpStream::new(receiver);
        let mut header = [0u8; 4];
        let error = bounded.read_exact(&mut header).await.unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);
        assert_eq!(bounded.read(&mut header).await.unwrap(), 0);

        let (mut sender, receiver) = tokio::io::duplex(32);
        sender.write_all(&3u32.to_be_bytes()).await.unwrap();
        sender.write_all(b"abc").await.unwrap();
        let mut bounded = BoundedSftpStream::new(receiver);
        let mut packet = [0u8; 7];
        bounded.read_exact(&mut packet).await.unwrap();
        assert_eq!(&packet[4..], b"abc");
    }

    #[tokio::test]
    async fn pipelined_download_preserves_integrity_across_short_reads() {
        let expected = (0..(SFTP_TRANSFER_CHUNK as usize * 12 + 1_337))
            .map(|index| (index % 251) as u8)
            .collect::<Vec<_>>();
        let remote = Arc::new(Mutex::new(expected.clone()));
        let sftp = memory_sftp(remote, true).await;
        let dir = TestDir::new();
        let destination = dir.0.join("download.bin");
        let progress = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let reported = progress.clone();

        let downloaded = download_with_session(
            &sftp,
            "/download.bin",
            &destination,
            move |bytes| reported.store(bytes, Ordering::Relaxed),
            None,
            None,
        )
        .await
        .unwrap();

        assert_eq!(downloaded, expected.len() as u64);
        assert_eq!(progress.load(Ordering::Relaxed), downloaded);
        assert_eq!(std::fs::read(destination).unwrap(), expected);
        let _ = sftp.close_session();
    }

    #[tokio::test]
    async fn pipelined_upload_preserves_integrity_over_multiple_windows() {
        let expected = (0..(SFTP_TRANSFER_CHUNK as usize * 17 + 733))
            .map(|index| (index % 239) as u8)
            .collect::<Vec<_>>();
        let remote = Arc::new(Mutex::new(Vec::new()));
        let sftp = memory_sftp(remote.clone(), false).await;
        let dir = TestDir::new();
        let source = dir.0.join("upload.bin");
        std::fs::write(&source, &expected).unwrap();
        let file = tokio::fs::File::open(&source).await.unwrap();
        let progress = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let reported = progress.clone();

        let uploaded = upload_with_session(
            &sftp,
            file,
            "/upload.bin",
            move |bytes| reported.store(bytes, Ordering::Relaxed),
            None,
        )
        .await
        .unwrap();

        assert_eq!(uploaded, expected.len() as u64);
        assert_eq!(progress.load(Ordering::Relaxed), uploaded);
        assert_eq!(*remote.lock().unwrap(), expected);
        let _ = sftp.close_session();
    }

    #[tokio::test]
    async fn resumable_download_appends_from_the_fragment_offset() {
        let expected = (0..(SFTP_TRANSFER_CHUNK as usize * 3 + 911))
            .map(|index| (index % 227) as u8)
            .collect::<Vec<_>>();
        let remote = Arc::new(Mutex::new(expected.clone()));
        let sftp = memory_sftp(remote, true).await;
        let dir = TestDir::new();
        let destination = dir.0.join("resumed.bin");
        let resume = DownloadResume {
            token: 0x1234,
            expected_total: Some(expected.len() as u64),
        };
        let part = open_download_part(&destination, Some(resume)).unwrap();
        let prefix_len = 93_117;
        std::fs::write(&part.path, &expected[..prefix_len]).unwrap();
        drop(part);

        let downloaded = download_with_session(
            &sftp,
            "/resumed.bin",
            &destination,
            |_| {},
            None,
            Some(resume),
        )
        .await
        .unwrap();

        assert_eq!(downloaded, expected.len() as u64);
        assert_eq!(std::fs::read(destination).unwrap(), expected);
        let _ = sftp.close_session();
    }
}
