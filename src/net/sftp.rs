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

use russh_sftp::client::error::Error as SftpError;
use russh_sftp::client::{Config as SftpConfig, RawSftpSession};
use russh_sftp::protocol::{FileAttributes, OpenFlags, StatusCode};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::model::{ConnectionSpec, RemoteEntry};
use crate::net::error::{HostKeyChallenge, NetError};
use crate::net::RemoteTreeStats;

const SFTP_CONNECT_TIMEOUT: Duration = Duration::from_secs(20);
const SFTP_INACTIVITY_TIMEOUT: Duration = Duration::from_secs(90);
const SFTP_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(20);
const SFTP_KEEPALIVE_MAX: usize = 3;
/// Each protocol action has its own deadline. Transfers renew this for every 64 KiB read/write,
/// so a healthy slow transfer proceeds while a server that stalls any individual request cannot
/// hold an authenticated session indefinitely.
const SFTP_OPERATION_TIMEOUT: Duration = Duration::from_secs(30);
const SFTP_TRANSFER_CHUNK: u32 = 64 * 1024;
/// `RawSftpSession`'s incoming packet reader otherwise accepts a server-declared length up to
/// `u32::MAX` before deserialisation. Enforce a cap on the framed stream itself, before that
/// allocation can happen. Normal OpenSSH SFTP packets are at most a few hundred KiB.
const MAX_SFTP_PACKET_BYTES: usize = 4 * 1024 * 1024;
const MAX_LISTING_ENTRIES: usize = 50_000;
const MAX_LISTING_BYTES: usize = 16 * 1024 * 1024;
const MAX_REMOTE_FILES: usize = 100_000;
const MAX_REMOTE_DIRECTORIES: usize = 10_000;
const MAX_RECURSION_DEPTH: usize = 64;

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

    let auth = match timed(
        "password authentication",
        handle.authenticate_password(spec.user.clone(), password.to_string()),
    )
    .await
    {
        Ok(auth) => auth,
        Err(error) => {
            let _ = timed(
                "disconnect",
                handle.disconnect(russh::Disconnect::ByApplication, "auth-error", "en"),
            )
            .await;
            return Err(error);
        }
    };
    if !auth.success() {
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
    let (mut handle, sftp) = open_session(spec, password).await?;
    let result = download_with_session(&sftp, remote_path, local_path, progress, cancel).await;
    close_session(&mut handle, &sftp, "bye").await;
    result
}

async fn download_with_session(
    sftp: &RawSftpSession,
    remote_path: &str,
    local_path: &std::path::Path,
    progress: impl Fn(u64) + Send,
    cancel: Option<&AtomicBool>,
) -> Result<u64, NetError> {
    if let Some(parent) = local_path.parent() {
        let _ = tokio::fs::create_dir_all(parent).await; // supports folder downloads
    }
    let (part, file) = create_unique_part(local_path)?;
    let mut file = tokio::fs::File::from_std(file);
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
            let _ = tokio::fs::remove_file(&part).await;
            return Err(error);
        }
    };
    let remote_handle = remote.handle;
    let result: Result<u64, NetError> = async {
        let mut done: u64 = 0;
        loop {
            if let Some(f) = cancel {
                if f.load(Ordering::Relaxed) {
                    return Err(NetError::Cancelled);
                }
            }
            let data = match tokio::time::timeout(
                SFTP_OPERATION_TIMEOUT,
                sftp.read(remote_handle.clone(), done, SFTP_TRANSFER_CHUNK),
            )
            .await
            {
                Ok(Ok(data)) => data,
                Ok(Err(SftpError::Status(status))) if status.status_code == StatusCode::Eof => {
                    break;
                }
                Ok(Err(error)) => {
                    return Err(NetError::Ssh(format!("SFTP read failed: {error}")));
                }
                Err(_) => {
                    return Err(NetError::Ssh(format!(
                        "SFTP read timed out after {} seconds",
                        SFTP_OPERATION_TIMEOUT.as_secs()
                    )));
                }
            };
            if data.data.is_empty() {
                return Err(NetError::Ssh(
                    "SFTP read returned empty data without EOF".into(),
                ));
            }
            file.write_all(&data.data).await?;
            done = done.saturating_add(data.data.len() as u64);
            progress(done);
        }
        file.sync_all().await?;
        Ok(done)
    }
    .await;
    let close_result = timed("close downloaded file", sftp.close(remote_handle)).await;
    match result {
        Ok(done) => {
            if let Err(error) = close_result {
                let _ = tokio::fs::remove_file(&part).await;
                return Err(error);
            }
            match tokio::fs::rename(&part, local_path).await {
                Ok(()) => Ok(done),
                Err(error) => {
                    let _ = tokio::fs::remove_file(&part).await;
                    Err(error.into())
                }
            }
        }
        Err(e) => {
            let _ = tokio::fs::remove_file(&part).await;
            Err(e)
        }
    }
}

fn part_path_with_nonce(p: &std::path::Path, pid: u32, nonce: u64) -> std::path::PathBuf {
    let parent = p.parent().unwrap_or_else(|| std::path::Path::new("."));
    let mut name = std::ffi::OsString::from(".");
    name.push(
        p.file_name()
            .unwrap_or_else(|| std::ffi::OsStr::new("download")),
    );
    name.push(format!(".gmacftp-{pid}-{nonce}.part"));
    parent.join(name)
}

fn create_unique_part(
    destination: &std::path::Path,
) -> Result<(std::path::PathBuf, std::fs::File), std::io::Error> {
    for _ in 0..16 {
        let path = part_path_with_nonce(destination, std::process::id(), rand::random::<u64>());
        match crate::store::vault::create_exclusive(&path) {
            Ok(file) => return Ok((path, file)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "could not allocate a unique download temp file",
    ))
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
    let mut file = tokio::fs::File::open(local_path).await?;
    let (mut handle, sftp) = open_session(spec, password).await?;
    let result: Result<u64, NetError> = async {
        if let Some(parent) = parent_remote(remote_path) {
            mkdirs_sftp(&sftp, &parent).await?; // supports folder uploads (mkdir -p ancestors)
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
        let mut buf = vec![0u8; 64 * 1024];
        let mut done: u64 = 0;
        let transfer_result: Result<u64, NetError> = async {
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
                timed(
                    "write remote file",
                    sftp.write(remote_handle.clone(), done, buf[..n].to_vec()),
                )
                .await?;
                done = done.saturating_add(n as u64);
                progress(done);
            }
            Ok(done)
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
    close_session(&mut handle, &sftp, "bye").await;
    result
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
            timed("remove directory", sftp.rmdir(remote_path.to_string())).await?;
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

    #[test]
    fn download_temp_name_is_unique_and_does_not_claim_dot_part() {
        let destination = std::path::Path::new("/tmp/report.pdf");
        let first = part_path_with_nonce(destination, 42, 1);
        let second = part_path_with_nonce(destination, 42, 2);
        assert_ne!(first, second);
        assert_ne!(first, std::path::PathBuf::from("/tmp/report.pdf.part"));
        assert_eq!(first.file_name().unwrap(), ".report.pdf.gmacftp-42-1.part");
    }
}
