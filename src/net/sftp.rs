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
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncSeekExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::{mpsc, oneshot};
use zeroize::Zeroizing;

use crate::model::{ConnectionSpec, RemoteEntry, SftpAuth};
use crate::net::error::{HostKeyChallenge, NetError};
use crate::net::partial::open_download_part;
use crate::net::safe::validate_remote_component;
use crate::net::{
    DownloadResume, RemoteFileMetadata, RemoteMetadata, RemoteSearchHit, RemoteSearchReport,
    RemoteStagingPaths, RemoteTreeStats, UploadResume, MAX_REMOTE_SEARCH_DEPTH,
    MAX_REMOTE_SEARCH_DIRECTORIES, MAX_REMOTE_SEARCH_ENTRIES, MAX_REMOTE_SEARCH_RESULTS,
};

const SFTP_INACTIVITY_TIMEOUT: Duration = Duration::from_secs(90);
const SFTP_KEEPALIVE_MAX: usize = 3;
/// Each protocol action has its own deadline. Transfers renew this for every 64 KiB read/write,
/// so a healthy slow transfer proceeds while a server that stalls any individual request cannot
/// hold an authenticated session indefinitely.
const SFTP_OPERATION_TIMEOUT: Duration = Duration::from_secs(30);
const SFTP_TRANSFER_CHUNK: u32 = 64 * 1024;
const SFTP_MIN_TRANSFER_CHUNK: u32 = 32 * 1024;
const SFTP_MAX_READ_CHUNK: u32 = 128 * 1024;
const SFTP_MAX_WRITE_CHUNK: u32 = 64 * 1024;
/// Start conservatively and grow the bandwidth-delay window only after successful measured
/// requests. This avoids overwhelming small embedded SFTP servers while filling long-fat links.
const SFTP_TRANSFER_PIPELINE: usize = 4;
const SFTP_MAX_TRANSFER_PIPELINE: usize = 16;
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
const MAX_INTERACTIVE_ROUNDS: usize = 8;
const MAX_INTERACTIVE_PROMPTS: usize = 4;
const MAX_INTERACTIVE_TEXT_BYTES: usize = 8 * 1024;
const MAX_INTERACTIVE_RESPONSE_BYTES: usize = 4 * 1024;
const MAX_INTERACTIVE_TOTAL_RESPONSE_BYTES: usize = 16 * 1024;
const INTERACTIVE_RESPONSE_TIMEOUT: Duration = Duration::from_secs(5 * 60);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyboardInteractivePrompt {
    pub text: String,
    pub echo: bool,
}

#[derive(Debug)]
pub struct KeyboardInteractiveRequest {
    pub endpoint: String,
    pub name: String,
    pub instructions: String,
    pub prompts: Vec<KeyboardInteractivePrompt>,
    pub response: oneshot::Sender<Result<Zeroizing<Vec<String>>, String>>,
}

type KeyboardInteractiveSender = mpsc::UnboundedSender<KeyboardInteractiveRequest>;
static KEYBOARD_INTERACTIVE_BROKER: OnceLock<Mutex<Option<KeyboardInteractiveSender>>> =
    OnceLock::new();

/// Install the process-local keyboard-interactive prompt broker. Reinstalling replaces a stale
/// UI receiver (useful after a clean app restart in the same test process); no response is ever
/// persisted or logged.
pub fn install_keyboard_interactive_broker() -> mpsc::UnboundedReceiver<KeyboardInteractiveRequest>
{
    let (sender, receiver) = mpsc::unbounded_channel();
    *KEYBOARD_INTERACTIVE_BROKER
        .get_or_init(|| Mutex::new(None))
        .lock()
        .expect("keyboard-interactive broker lock") = Some(sender);
    receiver
}

fn bounded_interactive_text(value: &str) -> String {
    let mut output = String::new();
    for character in value.chars() {
        let character = match character {
            '\n' | '\t' => character,
            character if character.is_control() => '�',
            character => character,
        };
        if output.len().saturating_add(character.len_utf8()) > MAX_INTERACTIVE_TEXT_BYTES {
            break;
        }
        output.push(character);
    }
    output
}

async fn request_keyboard_interactive_responses(
    endpoint: &str,
    name: &str,
    instructions: &str,
    prompts: &[russh::client::Prompt],
) -> Result<Zeroizing<Vec<String>>, NetError> {
    if prompts.len() > MAX_INTERACTIVE_PROMPTS {
        return Err(NetError::Ssh(
            "keyboard-interactive server sent too many prompts".into(),
        ));
    }
    let sender = KEYBOARD_INTERACTIVE_BROKER
        .get_or_init(|| Mutex::new(None))
        .lock()
        .map_err(|_| NetError::Ssh("keyboard-interactive broker is unavailable".into()))?
        .clone()
        .ok_or_else(|| {
            NetError::Ssh("keyboard-interactive authentication needs the app prompt UI".into())
        })?;
    let (response, receiver) = oneshot::channel();
    sender
        .send(KeyboardInteractiveRequest {
            endpoint: bounded_interactive_text(endpoint),
            name: bounded_interactive_text(name),
            instructions: bounded_interactive_text(instructions),
            prompts: prompts
                .iter()
                .map(|prompt| KeyboardInteractivePrompt {
                    text: bounded_interactive_text(&prompt.prompt),
                    echo: prompt.echo,
                })
                .collect(),
            response,
        })
        .map_err(|_| NetError::Ssh("keyboard-interactive prompt UI is unavailable".into()))?;
    let responses = tokio::time::timeout(INTERACTIVE_RESPONSE_TIMEOUT, receiver)
        .await
        .map_err(|_| NetError::Ssh("keyboard-interactive prompt timed out".into()))?
        .map_err(|_| NetError::Ssh("keyboard-interactive prompt was closed".into()))?
        .map_err(NetError::Ssh)?;
    if responses.len() != prompts.len()
        || responses.iter().any(|response| {
            response.len() > MAX_INTERACTIVE_RESPONSE_BYTES || response.contains('\0')
        })
        || responses.iter().map(String::len).sum::<usize>() > MAX_INTERACTIVE_TOTAL_RESPONSE_BYTES
    {
        return Err(NetError::Ssh(
            "keyboard-interactive response failed validation".into(),
        ));
    }
    Ok(responses)
}

#[derive(Debug, Clone)]
struct SftpTransferTuning {
    chunk: u32,
    pipeline: usize,
    max_chunk: u32,
    latency_ema_micros: u64,
    successful_samples: u32,
}

impl SftpTransferTuning {
    fn for_read() -> Self {
        Self::new(SFTP_MAX_READ_CHUNK)
    }

    fn for_write() -> Self {
        Self::new(SFTP_MAX_WRITE_CHUNK)
    }

    fn new(max_chunk: u32) -> Self {
        Self {
            chunk: SFTP_MIN_TRANSFER_CHUNK,
            pipeline: SFTP_TRANSFER_PIPELINE,
            max_chunk,
            latency_ema_micros: 0,
            successful_samples: 0,
        }
    }

    // `is_multiple_of` is newer than the project's Rust 1.88 minimum.
    #[allow(clippy::manual_is_multiple_of)]
    fn observe(&mut self, latency: Duration, requested: u32, transferred: usize) {
        let sample = latency.as_micros().min(u64::MAX as u128) as u64;
        self.latency_ema_micros = if self.latency_ema_micros == 0 {
            sample
        } else {
            // A small integer EMA avoids floating-point state in the hot path.
            (self
                .latency_ema_micros
                .saturating_mul(7)
                .saturating_add(sample))
                / 8
        };
        self.successful_samples = self.successful_samples.saturating_add(1);

        if transferred < requested as usize && transferred >= SFTP_MIN_TRANSFER_CHUNK as usize {
            self.chunk = self.chunk.min(transferred as u32);
        }
        if self.successful_samples % 4 != 0 {
            return;
        }

        if self.latency_ema_micros >= 60_000 {
            self.pipeline = (self.pipeline * 2).min(SFTP_MAX_TRANSFER_PIPELINE);
            if transferred == requested as usize {
                self.chunk = self.chunk.saturating_mul(2).min(self.max_chunk);
            }
        } else if self.latency_ema_micros >= 15_000 {
            self.pipeline = self.pipeline.clamp(8, SFTP_MAX_TRANSFER_PIPELINE);
            if self.successful_samples >= 8 && transferred == requested as usize {
                self.chunk = self.chunk.saturating_mul(2).min(self.max_chunk);
            }
        } else {
            self.pipeline = SFTP_TRANSFER_PIPELINE;
            if self.successful_samples >= 16 && transferred == requested as usize {
                self.chunk = self.chunk.saturating_mul(2).min(self.max_chunk);
            }
        }
        self.chunk = self.chunk.clamp(SFTP_MIN_TRANSFER_CHUNK, self.max_chunk);
        self.pipeline = self
            .pipeline
            .clamp(SFTP_TRANSFER_PIPELINE, SFTP_MAX_TRANSFER_PIPELINE);
    }
}

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

fn private_key_path(path: &std::path::Path) -> Result<PathBuf, NetError> {
    let raw = path
        .to_str()
        .map(str::trim)
        .filter(|path| !path.is_empty())
        .ok_or_else(|| NetError::Ssh("SSH private-key path is empty or invalid UTF-8".into()))?;
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

struct SessionHandles {
    target: russh::client::Handle<Handler>,
    jump: Option<russh::client::Handle<Handler>>,
}

async fn disconnect_handle(handle: &mut russh::client::Handle<Handler>, reason: &'static str) {
    let _ = timed(
        "disconnect",
        handle.disconnect(russh::Disconnect::ByApplication, reason, "en"),
    )
    .await;
}

/// Best-effort, bounded teardown. Close the target first so its tunneled stream closes before the
/// optional jump-host transport. Each disconnect waits at most [`SFTP_OPERATION_TIMEOUT`].
async fn close_session(handles: &mut SessionHandles, sftp: &RawSftpSession, reason: &'static str) {
    let _ = sftp.close_session();
    disconnect_handle(&mut handles.target, reason).await;
    if let Some(jump) = handles.jump.as_mut() {
        disconnect_handle(jump, reason).await;
    }
}

async fn authenticate_private_keys(
    handle: &mut russh::client::Handle<Handler>,
    user: &str,
    paths: &[PathBuf],
    passphrase: Option<&str>,
) -> Result<bool, NetError> {
    let mut last_error = None;
    let mut attempted_authentication = false;
    for configured_path in paths {
        let path = match private_key_path(configured_path) {
            Ok(path) => path,
            Err(error) => {
                last_error = Some(error);
                continue;
            }
        };
        let bytes = match tokio::task::spawn_blocking(move || read_private_key(&path)).await {
            Ok(Ok(bytes)) => bytes,
            Ok(Err(error)) => {
                last_error = Some(NetError::Ssh(format!(
                    "could not safely read an SSH IdentityFile: {error}"
                )));
                continue;
            }
            Err(error) => return Err(NetError::Join(error.to_string())),
        };
        let encoded = match String::from_utf8(bytes) {
            Ok(encoded) => zeroize::Zeroizing::new(encoded),
            Err(_) => {
                last_error = Some(NetError::Ssh(
                    "SSH IdentityFile is not valid UTF-8/OpenSSH text".into(),
                ));
                continue;
            }
        };
        let key = match russh::keys::decode_secret_key(&encoded, passphrase) {
            Ok(key) => key,
            Err(error) => {
                last_error = Some(NetError::Ssh(format!(
                    "could not unlock an SSH IdentityFile: {error}"
                )));
                continue;
            }
        };
        // RustCrypto's transitive `rsa` crate still carries RUSTSEC-2023-0071. Loading is local,
        // but signing would expose private-key timing to the server. RSA remains available safely
        // through SSH Agent, where the private operation is delegated to the system agent.
        if key.algorithm().is_rsa() {
            last_error = Some(NetError::Ssh(
                "built-in RSA private keys are disabled; use Ed25519/ECDSA or SSH Agent".into(),
            ));
            continue;
        }
        attempted_authentication = true;
        let authenticated = timed(
            "private-key authentication",
            handle.authenticate_publickey(
                user.to_string(),
                russh::keys::PrivateKeyWithHashAlg::new(Arc::new(key), None),
            ),
        )
        .await?
        .success();
        if authenticated {
            return Ok(true);
        }
    }
    // Once at least one valid key reached the server, a rejection is the authoritative result.
    // Do not surface an unrelated read/parse error from an earlier IdentityFile instead.
    if attempted_authentication {
        Ok(false)
    } else if let Some(error) = last_error {
        Err(error)
    } else {
        Ok(false)
    }
}

async fn authenticate_agent(
    handle: &mut russh::client::Handle<Handler>,
    user: &str,
) -> Result<bool, NetError> {
    #[cfg(unix)]
    {
        let mut agent = timed(
            "connect to SSH agent",
            russh::keys::agent::client::AgentClient::connect_env(),
        )
        .await?;
        let identities = timed("read SSH agent identities", agent.request_identities()).await?;
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
                        handle.authenticate_publickey_with(user.to_string(), key, hash, &mut agent),
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
                            user.to_string(),
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
        let _ = (handle, user);
        Err(NetError::Ssh(
            "SSH Agent authentication is not supported on this platform".into(),
        ))
    }
}

async fn authenticate_keyboard_interactive(
    handle: &mut russh::client::Handle<Handler>,
    endpoint: &crate::net::ssh_config::SshEndpoint,
) -> Result<bool, NetError> {
    use russh::client::KeyboardInteractiveAuthResponse;

    let mut response = timed(
        "start keyboard-interactive authentication",
        handle.authenticate_keyboard_interactive_start(endpoint.user.clone(), None::<String>),
    )
    .await?;
    for _ in 0..MAX_INTERACTIVE_ROUNDS {
        match response {
            KeyboardInteractiveAuthResponse::Success => return Ok(true),
            KeyboardInteractiveAuthResponse::Failure { .. } => return Ok(false),
            KeyboardInteractiveAuthResponse::InfoRequest {
                name,
                instructions,
                prompts,
            } => {
                let responses = if prompts.is_empty() {
                    Zeroizing::new(Vec::new())
                } else {
                    request_keyboard_interactive_responses(
                        &host_key_endpoint(&endpoint.host, endpoint.port),
                        &name,
                        &instructions,
                        &prompts,
                    )
                    .await?
                };
                response = timed(
                    "answer keyboard-interactive authentication",
                    handle.authenticate_keyboard_interactive_respond(responses.to_vec()),
                )
                .await?;
            }
        }
    }
    Err(NetError::Ssh(
        "keyboard-interactive authentication exceeded its round limit".into(),
    ))
}

async fn authenticate_target(
    handle: &mut russh::client::Handle<Handler>,
    endpoint: &crate::net::ssh_config::SshEndpoint,
    spec: &ConnectionSpec,
    password_or_passphrase: &str,
) -> Result<bool, NetError> {
    match spec.sftp_auth {
        SftpAuth::Password => Ok(timed(
            "password authentication",
            handle.authenticate_password(endpoint.user.clone(), password_or_passphrase.to_string()),
        )
        .await?
        .success()),
        SftpAuth::PrivateKey => {
            authenticate_private_keys(
                handle,
                &endpoint.user,
                &endpoint.identity_files,
                (!password_or_passphrase.is_empty()).then_some(password_or_passphrase),
            )
            .await
        }
        SftpAuth::Agent => authenticate_agent(handle, &endpoint.user).await,
        SftpAuth::KeyboardInteractive => authenticate_keyboard_interactive(handle, endpoint).await,
    }
}

async fn authenticate_jump(
    handle: &mut russh::client::Handle<Handler>,
    endpoint: &crate::net::ssh_config::SshEndpoint,
    spec: &ConnectionSpec,
    target_passphrase: &str,
) -> Result<bool, NetError> {
    match authenticate_agent(handle, &endpoint.user).await {
        Ok(true) => return Ok(true),
        Ok(false) => {}
        Err(error) => tracing::debug!(%error, "SSH Agent was unavailable for ProxyJump"),
    }
    if endpoint.identity_files.is_empty() {
        return Ok(false);
    }
    let passphrase = (spec.sftp_auth == SftpAuth::PrivateKey && !target_passphrase.is_empty())
        .then_some(target_passphrase);
    authenticate_private_keys(handle, &endpoint.user, &endpoint.identity_files, passphrase).await
}

/// Connect, authenticate, open and initialize the SFTP subsystem. Listing uses the raw request
/// API rather than `SftpSession::read_dir`, whose convenience implementation first accumulates
/// every REaddir page into a Vec.
fn host_key_endpoint(host: &str, port: u16) -> String {
    if host.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

fn client_config(endpoint: &crate::net::ssh_config::SshEndpoint) -> Arc<russh::client::Config> {
    Arc::new(russh::client::Config {
        inactivity_timeout: Some(SFTP_INACTIVITY_TIMEOUT),
        keepalive_interval: endpoint.keepalive_interval,
        keepalive_max: SFTP_KEEPALIVE_MAX,
        nodelay: true,
        ..Default::default()
    })
}

fn handler_for(
    endpoint: &crate::net::ssh_config::SshEndpoint,
    known_hosts: PathBuf,
) -> (Handler, Arc<Mutex<Option<HostKeyRejection>>>) {
    let rejection = Arc::new(Mutex::new(None));
    (
        Handler {
            host_key: host_key_endpoint(&endpoint.host, endpoint.port),
            known_hosts,
            rejection: rejection.clone(),
        },
        rejection,
    )
}

fn map_connect_failure(
    error: russh::Error,
    rejection: &Arc<Mutex<Option<HostKeyRejection>>>,
) -> NetError {
    let rejection = rejection.lock().ok().and_then(|mut pending| pending.take());
    match rejection {
        Some(HostKeyRejection::Unknown(challenge)) => NetError::HostKeyTrustRequired(challenge),
        Some(HostKeyRejection::Mismatch { endpoint }) => NetError::HostKey(format!(
            "stored fingerprint for {endpoint} does not match the server; refusing the connection"
        )),
        Some(HostKeyRejection::CheckFailed { endpoint, error }) => NetError::HostKey(format!(
            "could not verify the stored host key for {endpoint}: {error}"
        )),
        None => map_ssh(error),
    }
}

async fn connect_outer_ssh(
    endpoint: &crate::net::ssh_config::SshEndpoint,
    proxy_url: Option<&str>,
    known_hosts: PathBuf,
) -> Result<russh::client::Handle<Handler>, NetError> {
    let config = client_config(endpoint);
    let (handler, rejection) = handler_for(endpoint, known_hosts);
    if let Some(proxy_url) = proxy_url {
        let proxy_url = proxy_url.to_string();
        let host = endpoint.host.clone();
        let port = endpoint.port;
        let timeout = endpoint.connect_timeout;
        let tcp = tokio::time::timeout(
            timeout,
            tokio::task::spawn_blocking(move || {
                crate::net::proxy::connect_tunnel(&proxy_url, &host, port, timeout)
            }),
        )
        .await
        .map_err(|_| {
            NetError::Ssh(format!(
                "proxy connection timed out after {} seconds",
                timeout.as_secs()
            ))
        })?
        .map_err(|error| NetError::Join(error.to_string()))??;
        tcp.set_nonblocking(true)?;
        let tcp = tokio::net::TcpStream::from_std(tcp)?;
        return match tokio::time::timeout(
            timeout,
            russh::client::connect_stream(config, tcp, handler),
        )
        .await
        {
            Err(_) => Err(NetError::Ssh(format!(
                "SSH handshake through proxy timed out after {} seconds",
                timeout.as_secs()
            ))),
            Ok(Ok(handle)) => Ok(handle),
            Ok(Err(error)) => Err(map_connect_failure(error, &rejection)),
        };
    }

    match tokio::time::timeout(
        endpoint.connect_timeout,
        russh::client::connect(config, (endpoint.host.as_str(), endpoint.port), handler),
    )
    .await
    {
        Err(_) => Err(NetError::Ssh(format!(
            "SSH connection to {} timed out after {} seconds",
            endpoint.host,
            endpoint.connect_timeout.as_secs()
        ))),
        Ok(Ok(handle)) => Ok(handle),
        Ok(Err(error)) => Err(map_connect_failure(error, &rejection)),
    }
}

async fn connect_tunneled_ssh(
    endpoint: &crate::net::ssh_config::SshEndpoint,
    stream: russh::ChannelStream<russh::client::Msg>,
    known_hosts: PathBuf,
) -> Result<russh::client::Handle<Handler>, NetError> {
    let (handler, rejection) = handler_for(endpoint, known_hosts);
    match tokio::time::timeout(
        endpoint.connect_timeout,
        russh::client::connect_stream(client_config(endpoint), stream, handler),
    )
    .await
    {
        Err(_) => Err(NetError::Ssh(format!(
            "SSH handshake through ProxyJump timed out after {} seconds",
            endpoint.connect_timeout.as_secs()
        ))),
        Ok(Ok(handle)) => Ok(handle),
        Ok(Err(error)) => Err(map_connect_failure(error, &rejection)),
    }
}

async fn open_session(
    spec: &ConnectionSpec,
    password: &str,
) -> Result<(SessionHandles, RawSftpSession), NetError> {
    let known_hosts =
        known_hosts_path().ok_or_else(|| NetError::Ssh("no config directory available".into()))?;
    let resolved = crate::net::ssh_config::resolve(spec)?;

    let (mut handle, jump) = if let Some(jump_endpoint) = resolved.jump.as_ref() {
        let mut jump = connect_outer_ssh(
            jump_endpoint,
            spec.proxy_url.as_deref(),
            known_hosts.clone(),
        )
        .await?;
        let jump_authenticated =
            match authenticate_jump(&mut jump, jump_endpoint, spec, password).await {
                Ok(authenticated) => authenticated,
                Err(error) => {
                    disconnect_handle(&mut jump, "proxyjump-auth-error").await;
                    return Err(error);
                }
            };
        if !jump_authenticated {
            disconnect_handle(&mut jump, "proxyjump-auth-failed").await;
            return Err(NetError::Ssh(format!(
                "ProxyJump authentication failed for {}; load a key in SSH Agent or configure IdentityFile",
                jump_endpoint.user
            )));
        }
        let tunnel = match tokio::time::timeout(
            resolved.target.connect_timeout,
            jump.channel_open_direct_tcpip(
                resolved.target.host.clone(),
                u32::from(resolved.target.port),
                "127.0.0.1",
                0,
            ),
        )
        .await
        {
            Err(_) => {
                disconnect_handle(&mut jump, "proxyjump-tunnel-timeout").await;
                return Err(NetError::Ssh(format!(
                    "ProxyJump tunnel timed out after {} seconds",
                    resolved.target.connect_timeout.as_secs()
                )));
            }
            Ok(Err(error)) => {
                disconnect_handle(&mut jump, "proxyjump-tunnel-error").await;
                return Err(map_ssh(error));
            }
            Ok(Ok(channel)) => channel.into_stream(),
        };
        let target = match connect_tunneled_ssh(&resolved.target, tunnel, known_hosts.clone()).await
        {
            Ok(target) => target,
            Err(error) => {
                disconnect_handle(&mut jump, "proxyjump-target-error").await;
                return Err(error);
            }
        };
        (target, Some(jump))
    } else {
        (
            connect_outer_ssh(&resolved.target, spec.proxy_url.as_deref(), known_hosts).await?,
            None,
        )
    };

    let authenticated =
        match authenticate_target(&mut handle, &resolved.target, spec, password).await {
            Ok(authenticated) => authenticated,
            Err(error) => {
                disconnect_handle(&mut handle, "auth-error").await;
                if let Some(mut jump) = jump {
                    disconnect_handle(&mut jump, "auth-error").await;
                }
                return Err(error);
            }
        };
    if !authenticated {
        disconnect_handle(&mut handle, "auth-failed").await;
        if let Some(mut jump) = jump {
            disconnect_handle(&mut jump, "auth-failed").await;
        }
        return Err(NetError::AuthFailed(resolved.target.user.clone()));
    }

    let mut handles = SessionHandles {
        target: handle,
        jump,
    };

    let channel = match timed("open SFTP channel", handles.target.channel_open_session()).await {
        Ok(c) => c,
        Err(e) => {
            disconnect_handle(&mut handles.target, "chan-open-failed").await;
            if let Some(jump) = handles.jump.as_mut() {
                disconnect_handle(jump, "chan-open-failed").await;
            }
            return Err(e);
        }
    };
    if let Err(e) = timed(
        "request SFTP subsystem",
        channel.request_subsystem(true, "sftp"),
    )
    .await
    {
        disconnect_handle(&mut handles.target, "subsystem-failed").await;
        if let Some(jump) = handles.jump.as_mut() {
            disconnect_handle(jump, "subsystem-failed").await;
        }
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
        Ok(_) => Ok((handles, sftp)),
        Err(e) => {
            close_session(&mut handles, &sftp, "sftp-init-failed").await;
            Err(e)
        }
    }
}

/// Authenticated SFTP channel reusable by the transfer scheduler. Browsing operations retain
/// their short-lived sessions; queued files on the same endpoint can share this one handshake.
pub struct TransferSession {
    handles: SessionHandles,
    sftp: RawSftpSession,
}

impl TransferSession {
    pub async fn connect(spec: &ConnectionSpec, password: &str) -> Result<Self, NetError> {
        let (handles, sftp) = open_session(spec, password).await?;
        Ok(Self { handles, sftp })
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
        self.download_resumable_with_metadata(
            remote_path,
            local_path,
            progress,
            cancel,
            resume,
            crate::net::MetadataPreservation::default(),
        )
        .await
    }

    pub async fn download_resumable_with_metadata(
        &self,
        remote_path: &str,
        local_path: &std::path::Path,
        progress: impl Fn(u64) + Send,
        cancel: Option<&AtomicBool>,
        resume: Option<DownloadResume>,
        policy: crate::net::MetadataPreservation,
    ) -> Result<u64, NetError> {
        let metadata = if policy.timestamps || policy.permissions {
            match timed(
                "inspect remote download metadata",
                self.sftp.stat(remote_path.to_string()),
            )
            .await
            {
                Ok(entry) => crate::net::TransferMetadata {
                    modified: policy
                        .timestamps
                        .then(|| {
                            entry.attrs.mtime.and_then(|seconds| {
                                std::time::UNIX_EPOCH
                                    .checked_add(std::time::Duration::from_secs(seconds.into()))
                            })
                        })
                        .flatten(),
                    permissions: policy
                        .permissions
                        .then(|| entry.attrs.permissions.map(|mode| mode & 0o777))
                        .flatten(),
                },
                Err(error) => {
                    tracing::debug!(%error, "SFTP server did not provide usable download metadata");
                    crate::net::TransferMetadata::default()
                }
            }
        } else {
            crate::net::TransferMetadata::default()
        };
        let result = download_with_session(
            &self.sftp,
            remote_path,
            local_path,
            progress,
            cancel,
            resume,
        )
        .await;
        if result.is_ok() {
            if let Err(error) = crate::net::apply_local_transfer_metadata(local_path, metadata) {
                tracing::warn!(%error, "could not preserve downloaded SFTP file metadata");
            }
        }
        result
    }

    pub async fn upload(
        &self,
        local_path: &std::path::Path,
        remote_path: &str,
        progress: impl Fn(u64) + Send,
        cancel: Option<&AtomicBool>,
    ) -> Result<u64, NetError> {
        self.upload_resumable(local_path, remote_path, progress, cancel, None)
            .await
    }

    pub async fn upload_resumable(
        &self,
        local_path: &std::path::Path,
        remote_path: &str,
        progress: impl Fn(u64) + Send,
        cancel: Option<&AtomicBool>,
        resume: Option<UploadResume>,
    ) -> Result<u64, NetError> {
        self.upload_resumable_with_metadata(
            local_path,
            remote_path,
            progress,
            cancel,
            resume,
            crate::net::MetadataPreservation::default(),
        )
        .await
    }

    pub async fn upload_resumable_with_metadata(
        &self,
        local_path: &std::path::Path,
        remote_path: &str,
        progress: impl Fn(u64) + Send,
        cancel: Option<&AtomicBool>,
        resume: Option<UploadResume>,
        policy: crate::net::MetadataPreservation,
    ) -> Result<u64, NetError> {
        let file = tokio::fs::File::open(local_path).await?;
        let opened_metadata = file.metadata().await?;
        if let Some(resume) = resume {
            crate::net::validate_upload_source(&opened_metadata, resume)?;
        }
        let metadata = crate::net::local_transfer_metadata(&opened_metadata, policy);
        let result =
            upload_with_session(&self.sftp, file, remote_path, progress, cancel, resume).await;
        if result.is_ok() {
            let mut attributes = FileAttributes::empty();
            attributes.permissions = metadata.permissions;
            if let Some(modified) = metadata.modified {
                if let Ok(elapsed) = modified.duration_since(std::time::UNIX_EPOCH) {
                    if let Ok(seconds) = u32::try_from(elapsed.as_secs()) {
                        // SFTP v3 encodes access and modification time as one pair. A newly
                        // uploaded file has no source access time, so use its mtime for both.
                        attributes.atime = Some(seconds);
                        attributes.mtime = Some(seconds);
                    }
                }
            }
            if attributes.permissions.is_some() || attributes.mtime.is_some() {
                if let Err(error) = timed(
                    "preserve uploaded file metadata",
                    self.sftp.setstat(remote_path.to_string(), attributes),
                )
                .await
                {
                    // Contents were atomically promoted. Do not overwrite a valid destination
                    // because this optional follow-up is unsupported or denied.
                    tracing::warn!(%error, "SFTP server could not preserve uploaded file metadata");
                }
            }
        }
        result
    }

    pub async fn close(mut self, reason: &'static str) {
        close_session(&mut self.handles, &self.sftp, reason).await;
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
    connect_and_list_incremental(spec, password, |_| true).await
}

/// Connect and report bounded listing batches after each set of SFTP `READDIR` pages. Returning
/// `false` cancels the request and closes both the directory handle and the authenticated session.
pub async fn connect_and_list_incremental(
    spec: &ConnectionSpec,
    password: &str,
    mut on_batch: impl FnMut(Vec<RemoteEntry>) -> bool + Send,
) -> Result<Vec<RemoteEntry>, NetError> {
    let (mut handles, sftp) = open_session(spec, password).await?;
    let dir = if spec.initial_path.trim().is_empty() {
        "."
    } else {
        spec.initial_path.as_str()
    };
    let result = list_dir_bounded_incremental(&sftp, dir, &mut on_batch).await;
    close_session(&mut handles, &sftp, "bye").await;
    result.map(|listing| listing.entries)
}

struct SftpListing {
    entries: Vec<RemoteEntry>,
    truncated: bool,
}

/// Stream SFTP `OPENDIR`/`READDIR` pages. Unlike `SftpSession::read_dir`, this never gathers all
/// pages into one Vec. The directory handle is closed on success, failure and truncation.
async fn list_dir_bounded(sftp: &RawSftpSession, dir: &str) -> Result<SftpListing, NetError> {
    list_dir_bounded_incremental(sftp, dir, &mut |_| true).await
}

async fn list_dir_bounded_incremental(
    sftp: &RawSftpSession,
    dir: &str,
    on_batch: &mut (dyn FnMut(Vec<RemoteEntry>) -> bool + Send),
) -> Result<SftpListing, NetError> {
    const LISTING_BATCH_ENTRIES: usize = 256;
    let handle = timed("open directory", sftp.opendir(dir.to_string())).await?;
    let handle_name = handle.handle;
    let mut entries = Vec::new();
    let mut stored_bytes = 0usize;
    let mut truncated = false;
    let mut pending = Vec::with_capacity(LISTING_BATCH_ENTRIES);
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
                let attrs = file.attrs;
                let is_dir = attrs.is_dir();
                let entry = RemoteEntry {
                    name: file.filename,
                    is_dir,
                    size: attrs.size.unwrap_or(0),
                    mtime: attrs.mtime.map(i64::from),
                    permissions: attrs.permissions.map(|mode| mode & 0o7777),
                    owner: attrs.user.or_else(|| attrs.uid.map(|uid| uid.to_string())),
                    group: attrs.group.or_else(|| attrs.gid.map(|gid| gid.to_string())),
                };
                pending.push(entry.clone());
                entries.push(entry);
                if pending.len() >= LISTING_BATCH_ENTRIES && !on_batch(std::mem::take(&mut pending))
                {
                    return Err(NetError::Cancelled);
                }
            }
            if truncated {
                tracing::warn!(
                    "SFTP directory listing truncated at {MAX_LISTING_ENTRIES} entries (DoS guard)"
                );
                break;
            }
        }
        if !pending.is_empty() && !on_batch(std::mem::take(&mut pending)) {
            return Err(NetError::Cancelled);
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
    walk_metadata(spec, password, root_dir).await.map(|files| {
        files
            .into_iter()
            .map(|file| (file.path, file.size))
            .collect()
    })
}

pub async fn walk_metadata(
    spec: &ConnectionSpec,
    password: &str,
    root_dir: &str,
) -> Result<Vec<RemoteFileMetadata>, NetError> {
    let (mut handles, sftp) = open_session(spec, password).await?;
    let root = if root_dir.trim().is_empty() {
        ".".to_string()
    } else {
        root_dir.to_string()
    };
    let mut out = Vec::new();
    let mut directories_seen = 0;
    let result = walk_sftp(&sftp, &root, &mut out, 0, &mut directories_seen).await;
    close_session(&mut handles, &sftp, "bye").await;
    if result? {
        Err(NetError::Ssh(
            "remote folder walk exceeded a safety limit; refusing an incomplete copy".into(),
        ))
    } else {
        Ok(out)
    }
}

pub async fn search(
    spec: &ConnectionSpec,
    password: &str,
    root_dir: &str,
    normalized_query: &str,
    cancelled: &AtomicBool,
) -> Result<RemoteSearchReport, NetError> {
    let (mut handles, sftp) = open_session(spec, password).await?;
    let root = if root_dir.trim().is_empty() {
        "/"
    } else {
        root_dir
    };
    let mut report = RemoteSearchReport::default();
    let result = search_sftp(&sftp, root, normalized_query, cancelled, &mut report, 0).await;
    close_session(&mut handles, &sftp, "bye").await;
    result?;
    Ok(report)
}

pub async fn inspect(
    spec: &ConnectionSpec,
    password: &str,
    remote_path: &str,
) -> Result<RemoteMetadata, NetError> {
    let (mut handles, sftp) = open_session(spec, password).await?;
    let result = timed(
        "inspect remote metadata",
        sftp.stat(remote_path.to_string()),
    )
    .await
    .map(|response| {
        let attrs = response.attrs;
        RemoteMetadata {
            is_dir: attrs.is_dir(),
            size: attrs.size.unwrap_or(0),
            mtime: attrs.mtime.map(i64::from),
            permissions: attrs.permissions.map(|mode| mode & 0o7777),
            owner: attrs.user.or_else(|| attrs.uid.map(|uid| uid.to_string())),
            group: attrs.group.or_else(|| attrs.gid.map(|gid| gid.to_string())),
        }
    });
    close_session(&mut handles, &sftp, "inspect-metadata").await;
    result
}

async fn search_sftp(
    sftp: &RawSftpSession,
    directory: &str,
    normalized_query: &str,
    cancelled: &AtomicBool,
    report: &mut RemoteSearchReport,
    depth: usize,
) -> Result<(), NetError> {
    if cancelled.load(Ordering::Relaxed) {
        return Err(NetError::Cancelled);
    }
    if depth >= MAX_REMOTE_SEARCH_DEPTH
        || report.directories_scanned >= MAX_REMOTE_SEARCH_DIRECTORIES
        || report.entries_scanned >= MAX_REMOTE_SEARCH_ENTRIES
    {
        report.truncated = true;
        return Ok(());
    }
    report.directories_scanned += 1;
    let listing = list_dir_bounded(sftp, directory).await?;
    if listing.truncated {
        report.truncated = true;
    }
    for entry in listing.entries {
        if cancelled.load(Ordering::Relaxed) {
            return Err(NetError::Cancelled);
        }
        if report.entries_scanned >= MAX_REMOTE_SEARCH_ENTRIES {
            report.truncated = true;
            break;
        }
        report.entries_scanned += 1;
        let path = join_remote_path(directory, &entry.name);
        if crate::net::remote_search_matches(&path, normalized_query) {
            if report.hits.len() >= MAX_REMOTE_SEARCH_RESULTS {
                report.truncated = true;
                break;
            }
            report.hits.push(RemoteSearchHit {
                path: path.clone(),
                is_dir: entry.is_dir,
                size: entry.size,
                mtime: entry.mtime,
            });
        }
        if entry.is_dir && !report.truncated {
            Box::pin(search_sftp(
                sftp,
                &path,
                normalized_query,
                cancelled,
                report,
                depth + 1,
            ))
            .await?;
        }
        if report.truncated {
            break;
        }
    }
    Ok(())
}

pub async fn hash_files(
    spec: &ConnectionSpec,
    password: &str,
    paths: &[String],
) -> Result<Vec<(String, [u8; 32])>, NetError> {
    let session = TransferSession::connect(spec, password).await?;
    let mut hashes = Vec::with_capacity(paths.len());
    let result: Result<(), NetError> = async {
        for path in paths {
            let digest = hash_file_with_session(&session.sftp, path).await?;
            hashes.push((path.clone(), digest));
        }
        Ok(())
    }
    .await;
    session.close("bye").await;
    result?;
    Ok(hashes)
}

async fn hash_file_with_session(
    sftp: &RawSftpSession,
    remote_path: &str,
) -> Result<[u8; 32], NetError> {
    let remote = timed(
        "open remote file for checksum",
        sftp.open(
            remote_path.to_string(),
            OpenFlags::READ,
            FileAttributes::empty(),
        ),
    )
    .await?;
    let handle = remote.handle;
    let result: Result<[u8; 32], NetError> = async {
        let mut offset = 0_u64;
        let mut hasher = Sha256::new();
        loop {
            let (_, _, _, response) =
                read_transfer_chunk(sftp, handle.clone(), offset, SFTP_TRANSFER_CHUNK).await;
            match response? {
                SftpReadChunk::Eof => break,
                SftpReadChunk::Data(data) if data.is_empty() => {
                    return Err(NetError::Ssh(
                        "SFTP server returned an empty checksum block before EOF".into(),
                    ));
                }
                SftpReadChunk::Data(data) => {
                    offset = offset.saturating_add(data.len() as u64);
                    hasher.update(data);
                }
            }
        }
        Ok(hasher.finalize().into())
    }
    .await;
    let close_result = timed("close checksummed file", sftp.close(handle)).await;
    match result {
        Ok(digest) => {
            close_result?;
            Ok(digest)
        }
        Err(error) => Err(error),
    }
}

pub async fn tree_stats(
    spec: &ConnectionSpec,
    password: &str,
    root_dir: &str,
    max_files: usize,
) -> Result<RemoteTreeStats, NetError> {
    let (mut handles, sftp) = open_session(spec, password).await?;
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
    close_session(&mut handles, &sftp, "bye").await;
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
    out: &mut Vec<RemoteFileMetadata>,
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
            out.push(RemoteFileMetadata {
                path: full,
                size: entry.size,
                mtime: entry.mtime,
            });
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
) -> (u64, u32, Duration, Result<SftpReadChunk, NetError>) {
    let started = Instant::now();
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
    (offset, len, started.elapsed(), result)
}

async fn write_transfer_chunk(
    sftp: &RawSftpSession,
    handle: String,
    offset: u64,
    data: Vec<u8>,
) -> (usize, Duration, Result<(), NetError>) {
    let len = data.len();
    let started = Instant::now();
    let result = timed("write remote file", sftp.write(handle, offset, data))
        .await
        .map(|_| ());
    (len, started.elapsed(), result)
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
        let mut tuning = SftpTransferTuning::for_read();
        let mut reads = FuturesOrdered::new();
        while reads.len() < tuning.pipeline {
            let requested = tuning.chunk;
            reads.push_back(read_transfer_chunk(
                sftp,
                remote_handle.clone(),
                next_offset,
                requested,
            ));
            next_offset = next_offset.saturating_add(requested as u64);
        }

        'download: while let Some((offset, requested, latency, response)) = reads.next().await {
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
            let mut response_latency = latency;
            let mut response_requested = requested;
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
                        tuning.observe(response_latency, response_requested, received as usize);
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
                let (_, gap_requested, gap_latency, gap_response) =
                    read_transfer_chunk(sftp, remote_handle.clone(), chunk_offset, remaining).await;
                response = gap_response;
                response_latency = gap_latency;
                response_requested = gap_requested;
            }

            while reads.len() < tuning.pipeline {
                let requested = tuning.chunk;
                reads.push_back(read_transfer_chunk(
                    sftp,
                    remote_handle.clone(),
                    next_offset,
                    requested,
                ));
                next_offset = next_offset.saturating_add(requested as u64);
            }
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
    let result =
        upload_with_session(&session.sftp, file, remote_path, progress, cancel, None).await;
    session.close("bye").await;
    result
}

pub async fn discard_resumable_upload(
    spec: &ConnectionSpec,
    password: &str,
    remote_path: &str,
    token: u64,
) -> Result<(), NetError> {
    let staging = RemoteStagingPaths::for_resumable_destination(remote_path, token)?;
    let session = TransferSession::connect(spec, password).await?;
    cleanup_staged_sftp_file(&session.sftp, &staging.temporary).await;
    session.close("discard-upload-fragment").await;
    Ok(())
}

async fn upload_with_session(
    sftp: &RawSftpSession,
    mut file: tokio::fs::File,
    remote_path: &str,
    progress: impl Fn(u64) + Send,
    cancel: Option<&AtomicBool>,
    resume: Option<UploadResume>,
) -> Result<u64, NetError> {
    let mut staging = match resume {
        Some(resume) => RemoteStagingPaths::for_resumable_destination(remote_path, resume.token)?,
        None => RemoteStagingPaths::for_destination(remote_path)?,
    };
    let mut preserve_for_resume = resume.is_some();
    let result: Result<u64, NetError> = async {
        if let Some(parent) = parent_remote(remote_path) {
            mkdirs_sftp(sftp, &parent).await?; // supports folder uploads (mkdir -p ancestors)
        }

        let (remote_handle, offset) = if let Some(resume) = resume {
            match open_new_sftp_upload(sftp, &staging.temporary).await {
                Ok(handle) => (handle, 0),
                Err(create_error) => {
                    let existing = match timed(
                        "inspect resumable upload fragment",
                        sftp.stat(staging.temporary.clone()),
                    )
                    .await
                    {
                        Ok(existing) => existing.attrs,
                        Err(_) => return Err(create_error),
                    };
                    let offset = existing.len();
                    let invalid_type = existing.permissions.is_some_and(|_| !existing.is_regular());
                    let prefix_matches = !invalid_type
                        && offset <= resume.expected_total
                        && remote_upload_prefix_matches(
                            sftp,
                            &staging.temporary,
                            &mut file,
                            offset,
                        )
                        .await?;
                    if !prefix_matches {
                        cleanup_staged_sftp_file(sftp, &staging.temporary).await;
                        staging = RemoteStagingPaths::for_destination(remote_path)?;
                        preserve_for_resume = false;
                        file.seek(std::io::SeekFrom::Start(0)).await?;
                        (open_new_sftp_upload(sftp, &staging.temporary).await?, 0)
                    } else {
                        let remote = timed(
                            "open resumable upload fragment",
                            sftp.open(
                                staging.temporary.clone(),
                                OpenFlags::WRITE,
                                FileAttributes::empty(),
                            ),
                        )
                        .await?;
                        file.seek(std::io::SeekFrom::Start(offset)).await?;
                        (remote.handle, offset)
                    }
                }
            }
        } else {
            (open_new_sftp_upload(sftp, &staging.temporary).await?, 0)
        };
        if offset > 0 {
            progress(offset);
        }
        let transfer_result: Result<u64, NetError> = async {
            let mut tuning = SftpTransferTuning::for_write();
            let mut writes = FuturesUnordered::new();
            let mut next_offset = offset;
            let mut acknowledged = offset;
            let mut eof = false;
            loop {
                if let Some(f) = cancel {
                    if f.load(Ordering::Relaxed) {
                        return Err(NetError::Cancelled);
                    }
                }

                while writes.len() < tuning.pipeline && !eof {
                    let mut data = vec![0_u8; tuning.chunk as usize];
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

                let Some((written, latency, result)) = writes.next().await else {
                    break;
                };
                result?;
                tuning.observe(latency, written as u32, written);
                acknowledged = acknowledged.saturating_add(written as u64);
                progress(acknowledged);
            }
            Ok(acknowledged)
        }
        .await;
        let close_result = timed("close uploaded file", sftp.close(remote_handle)).await;
        match transfer_result {
            Ok(done) => {
                if let Err(error) = close_result {
                    if !preserve_for_resume {
                        cleanup_staged_sftp_file(sftp, &staging.temporary).await;
                    }
                    return Err(error);
                }
                if cancel.is_some_and(|flag| flag.load(Ordering::Relaxed)) {
                    if !preserve_for_resume {
                        cleanup_staged_sftp_file(sftp, &staging.temporary).await;
                    }
                    return Err(NetError::Cancelled);
                }
                finalize_staged_sftp_upload(sftp, &staging, remote_path, preserve_for_resume)
                    .await?;
                Ok(done)
            }
            Err(error) => {
                if let Err(close_error) = close_result {
                    tracing::debug!(%close_error, "SFTP handle also failed while aborting upload");
                }
                if !preserve_for_resume {
                    cleanup_staged_sftp_file(sftp, &staging.temporary).await;
                }
                Err(error)
            }
        }
    }
    .await;
    result
}

async fn open_new_sftp_upload(sftp: &RawSftpSession, path: &str) -> Result<String, NetError> {
    timed(
        "open remote file for upload",
        sftp.open(
            path.to_string(),
            OpenFlags::CREATE | OpenFlags::EXCLUDE | OpenFlags::TRUNCATE | OpenFlags::WRITE,
            FileAttributes::empty(),
        ),
    )
    .await
    .map(|remote| remote.handle)
}

async fn remote_upload_prefix_matches(
    sftp: &RawSftpSession,
    path: &str,
    local: &mut tokio::fs::File,
    expected_len: u64,
) -> Result<bool, NetError> {
    if expected_len == 0 {
        return Ok(true);
    }
    let remote = timed(
        "open upload fragment for verification",
        sftp.open(path.to_string(), OpenFlags::READ, FileAttributes::empty()),
    )
    .await?;
    let handle = remote.handle;
    local.seek(std::io::SeekFrom::Start(0)).await?;
    let result: Result<bool, NetError> = async {
        let mut offset = 0_u64;
        while offset < expected_len {
            let remaining = expected_len.saturating_sub(offset);
            let requested = remaining.min(SFTP_TRANSFER_CHUNK as u64) as u32;
            let (_, _, _, response) =
                read_transfer_chunk(sftp, handle.clone(), offset, requested).await;
            let remote_bytes = match response? {
                SftpReadChunk::Eof => return Ok(false),
                SftpReadChunk::Data(bytes) => bytes,
            };
            if remote_bytes.is_empty() || remote_bytes.len() as u64 > remaining {
                return Ok(false);
            }
            let mut local_bytes = vec![0_u8; remote_bytes.len()];
            if local.read_exact(&mut local_bytes).await.is_err() || local_bytes != remote_bytes {
                return Ok(false);
            }
            offset = offset.saturating_add(remote_bytes.len() as u64);
        }
        Ok(true)
    }
    .await;
    let close_result = timed("close verified upload fragment", sftp.close(handle)).await;
    match result {
        Ok(matches) => {
            close_result?;
            Ok(matches)
        }
        Err(error) => Err(error),
    }
}

async fn cleanup_staged_sftp_file(sftp: &RawSftpSession, path: &str) {
    if let Err(error) = timed("remove staged upload", sftp.remove(path.to_string())).await {
        tracing::debug!(%error, path, "could not remove staged SFTP upload");
    }
}

/// Promote a complete SFTP upload. SFTP v3 servers differ on whether RENAME replaces an existing
/// file, so fall back to a same-directory backup with rollback when direct promotion is refused.
async fn finalize_staged_sftp_upload(
    sftp: &RawSftpSession,
    staging: &RemoteStagingPaths,
    destination: &str,
    preserve_temporary_on_failure: bool,
) -> Result<(), NetError> {
    match timed(
        "promote staged upload",
        sftp.rename(staging.temporary.clone(), destination.to_string()),
    )
    .await
    {
        Ok(_) => return Ok(()),
        Err(direct_error) => {
            if let Err(backup_error) = timed(
                "backup existing destination",
                sftp.rename(destination.to_string(), staging.backup.clone()),
            )
            .await
            {
                if !preserve_temporary_on_failure {
                    cleanup_staged_sftp_file(sftp, &staging.temporary).await;
                }
                tracing::debug!(%backup_error, "SFTP destination could not be moved aside");
                return Err(direct_error);
            }
        }
    }

    match timed(
        "promote staged upload",
        sftp.rename(staging.temporary.clone(), destination.to_string()),
    )
    .await
    {
        Ok(_) => {
            cleanup_staged_sftp_file(sftp, &staging.backup).await;
            Ok(())
        }
        Err(promote_error) => {
            let rollback = timed(
                "restore previous destination",
                sftp.rename(staging.backup.clone(), destination.to_string()),
            )
            .await;
            if !preserve_temporary_on_failure {
                cleanup_staged_sftp_file(sftp, &staging.temporary).await;
            }
            match rollback {
                Ok(_) => Err(promote_error),
                Err(rollback_error) => Err(NetError::Ssh(format!(
                    "upload finalization failed ({promote_error}); restoring the previous destination also failed ({rollback_error}); previous data remains at {}",
                    staging.backup
                ))),
            }
        }
    }
}

pub async fn rename(
    spec: &ConnectionSpec,
    password: &str,
    from: &str,
    to: &str,
) -> Result<(), NetError> {
    let (mut handles, sftp) = open_session(spec, password).await?;
    let result = timed("rename path", sftp.rename(from.to_string(), to.to_string()))
        .await
        .map(|_| ());
    close_session(&mut handles, &sftp, "bye").await;
    result
}

pub async fn create_dir(spec: &ConnectionSpec, password: &str, path: &str) -> Result<(), NetError> {
    let (mut handles, sftp) = open_session(spec, password).await?;
    let result = timed(
        "create directory",
        sftp.mkdir(path.to_string(), FileAttributes::empty()),
    )
    .await
    .map(|_| ());
    close_session(&mut handles, &sftp, "bye").await;
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
    let (mut handles, sftp) = open_session(spec, password).await?;
    let mut attributes = FileAttributes::empty();
    attributes.permissions = Some(mode);
    let result = timed(
        "change permissions",
        sftp.setstat(path.to_string(), attributes),
    )
    .await
    .map(|_| ());
    close_session(&mut handles, &sftp, "bye").await;
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
    let (mut handles, sftp) = open_session(spec, password).await?;
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
    close_session(&mut handles, &sftp, "bye").await;
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use russh_sftp::protocol::{Attrs, Data, File as SftpFile, Handle, Name, Status, Version};
    use std::collections::HashMap;

    #[test]
    fn sftp_tuning_grows_latency_window_with_strict_bounds() {
        let mut reads = SftpTransferTuning::for_read();
        for _ in 0..12 {
            let requested = reads.chunk;
            reads.observe(Duration::from_millis(100), requested, requested as usize);
        }
        assert_eq!(reads.pipeline, SFTP_MAX_TRANSFER_PIPELINE);
        assert_eq!(reads.chunk, SFTP_MAX_READ_CHUNK);

        let mut writes = SftpTransferTuning::for_write();
        for _ in 0..32 {
            let requested = writes.chunk;
            writes.observe(Duration::from_millis(100), requested, requested as usize);
        }
        assert_eq!(writes.pipeline, SFTP_MAX_TRANSFER_PIPELINE);
        assert_eq!(writes.chunk, SFTP_MAX_WRITE_CHUNK);

        let mut local = SftpTransferTuning::for_read();
        for _ in 0..16 {
            let requested = local.chunk;
            local.observe(Duration::from_millis(1), requested, requested as usize);
        }
        assert_eq!(local.pipeline, SFTP_TRANSFER_PIPELINE);
        assert!(local.chunk <= SFTP_MAX_READ_CHUNK);
    }

    #[tokio::test]
    async fn keyboard_interactive_broker_round_trips_bounded_ephemeral_responses() {
        let mut requests = install_keyboard_interactive_broker();
        let responder = tokio::spawn(async move {
            let request = requests.recv().await.unwrap();
            assert_eq!(request.endpoint, "sftp.example:22");
            assert_eq!(request.prompts.len(), 2);
            assert_eq!(request.name, "Login�");
            request
                .response
                .send(Ok(Zeroizing::new(vec![
                    "primary secret".into(),
                    "123456".into(),
                ])))
                .unwrap();
        });
        let prompts = vec![
            russh::client::Prompt {
                prompt: "Password:".into(),
                echo: false,
            },
            russh::client::Prompt {
                prompt: "Verification code:".into(),
                echo: false,
            },
        ];
        let responses = request_keyboard_interactive_responses(
            "sftp.example:22",
            "Login\u{1b}",
            "Enter both factors",
            &prompts,
        )
        .await
        .unwrap();
        responder.await.unwrap();
        assert_eq!(&**responses, &["primary secret", "123456"]);
    }

    #[test]
    fn keyboard_interactive_text_and_prompt_counts_are_bounded() {
        assert!(
            bounded_interactive_text(&"x".repeat(MAX_INTERACTIVE_TEXT_BYTES * 2)).len()
                <= MAX_INTERACTIVE_TEXT_BYTES
        );
        assert_eq!(bounded_interactive_text("a\0b"), "a�b");
    }

    struct MemorySftpServer {
        data: Arc<Mutex<Vec<u8>>>,
        short_reads: bool,
        latency: Duration,
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
            tokio::time::sleep(self.latency).await;
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
            tokio::time::sleep(self.latency).await;
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

        async fn rename(
            &mut self,
            id: u32,
            _oldpath: String,
            _newpath: String,
        ) -> Result<Status, Self::Error> {
            Ok(Status {
                id,
                status_code: StatusCode::Ok,
                error_message: "Ok".into(),
                language_tag: "en-US".into(),
            })
        }

        async fn remove(&mut self, id: u32, _filename: String) -> Result<Status, Self::Error> {
            Ok(Status {
                id,
                status_code: StatusCode::Ok,
                error_message: "Ok".into(),
                language_tag: "en-US".into(),
            })
        }
    }

    async fn memory_sftp(data: Arc<Mutex<Vec<u8>>>, short_reads: bool) -> RawSftpSession {
        memory_sftp_with_latency(data, short_reads, Duration::ZERO).await
    }

    async fn memory_sftp_with_latency(
        data: Arc<Mutex<Vec<u8>>>,
        short_reads: bool,
        latency: Duration,
    ) -> RawSftpSession {
        let (client, server) = tokio::io::duplex(2 * 1024 * 1024);
        russh_sftp::server::run(
            server,
            MemorySftpServer {
                data,
                short_reads,
                latency,
            },
        )
        .await;
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

    #[derive(Default)]
    struct DirectoryServerState {
        next_entry: usize,
        readdir_calls: usize,
        close_calls: usize,
    }

    struct DirectorySftpServer {
        state: Arc<Mutex<DirectoryServerState>>,
        total_entries: usize,
    }

    impl russh_sftp::server::Handler for DirectorySftpServer {
        type Error = StatusCode;

        fn unimplemented(&self) -> Self::Error {
            StatusCode::OpUnsupported
        }

        async fn init(
            &mut self,
            _version: u32,
            _extensions: HashMap<String, String>,
        ) -> Result<Version, Self::Error> {
            Ok(Version::new())
        }

        async fn opendir(&mut self, id: u32, _path: String) -> Result<Handle, Self::Error> {
            Ok(Handle {
                id,
                handle: "memory-directory".into(),
            })
        }

        async fn readdir(&mut self, id: u32, _handle: String) -> Result<Name, Self::Error> {
            let mut state = self.state.lock().unwrap();
            state.readdir_calls += 1;
            if state.next_entry >= self.total_entries {
                return Err(StatusCode::Eof);
            }
            let end = (state.next_entry + 100).min(self.total_entries);
            let files = (state.next_entry..end)
                .map(|index| {
                    let mut attrs = FileAttributes::empty();
                    attrs.size = Some(index as u64);
                    attrs.set_regular(true);
                    SftpFile::new(format!("entry-{index:05}"), attrs)
                })
                .collect();
            state.next_entry = end;
            Ok(Name { id, files })
        }

        async fn close(&mut self, id: u32, _handle: String) -> Result<Status, Self::Error> {
            self.state.lock().unwrap().close_calls += 1;
            Ok(ok_status(id))
        }
    }

    async fn directory_sftp(
        state: Arc<Mutex<DirectoryServerState>>,
        total_entries: usize,
    ) -> RawSftpSession {
        let (client, server) = tokio::io::duplex(2 * 1024 * 1024);
        russh_sftp::server::run(
            server,
            DirectorySftpServer {
                state,
                total_entries,
            },
        )
        .await;
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

    #[tokio::test]
    async fn incremental_listing_cancels_and_closes_directory_before_all_pages() {
        let state = Arc::new(Mutex::new(DirectoryServerState::default()));
        let sftp = directory_sftp(state.clone(), 1_000).await;
        let mut batches = Vec::new();
        let result = list_dir_bounded_incremental(&sftp, "/", &mut |batch| {
            batches.push(batch.len());
            false
        })
        .await;

        assert!(matches!(result, Err(NetError::Cancelled)));
        assert_eq!(batches, vec![256]);
        let state = state.lock().unwrap();
        assert_eq!(state.readdir_calls, 3);
        assert_eq!(state.close_calls, 1);
        assert_eq!(state.next_entry, 300);
    }

    struct TransactionalSftpState {
        files: HashMap<String, Vec<u8>>,
        destination: String,
        fail_writes_at_or_after: Option<u64>,
        fail_second_promotion: bool,
    }

    struct TransactionalSftpServer {
        state: Arc<Mutex<TransactionalSftpState>>,
    }

    fn ok_status(id: u32) -> Status {
        Status {
            id,
            status_code: StatusCode::Ok,
            error_message: "Ok".into(),
            language_tag: "en-US".into(),
        }
    }

    impl russh_sftp::server::Handler for TransactionalSftpServer {
        type Error = StatusCode;

        fn unimplemented(&self) -> Self::Error {
            StatusCode::OpUnsupported
        }

        async fn init(
            &mut self,
            _version: u32,
            _extensions: HashMap<String, String>,
        ) -> Result<Version, Self::Error> {
            Ok(Version::new())
        }

        async fn mkdir(
            &mut self,
            id: u32,
            _path: String,
            _attrs: FileAttributes,
        ) -> Result<Status, Self::Error> {
            Ok(ok_status(id))
        }

        async fn open(
            &mut self,
            id: u32,
            filename: String,
            flags: OpenFlags,
            _attrs: FileAttributes,
        ) -> Result<Handle, Self::Error> {
            let mut state = self.state.lock().unwrap();
            if flags.contains(OpenFlags::EXCLUDE) && state.files.contains_key(&filename) {
                return Err(StatusCode::Failure);
            }
            if flags.contains(OpenFlags::CREATE) {
                state.files.entry(filename.clone()).or_default();
            }
            if flags.contains(OpenFlags::TRUNCATE) {
                state
                    .files
                    .get_mut(&filename)
                    .ok_or(StatusCode::NoSuchFile)?
                    .clear();
            }
            Ok(Handle {
                id,
                handle: filename,
            })
        }

        async fn close(&mut self, id: u32, _handle: String) -> Result<Status, Self::Error> {
            Ok(ok_status(id))
        }

        async fn stat(&mut self, id: u32, path: String) -> Result<Attrs, Self::Error> {
            let state = self.state.lock().unwrap();
            let data = state.files.get(&path).ok_or(StatusCode::NoSuchFile)?;
            let mut attrs = FileAttributes::empty();
            attrs.size = Some(data.len() as u64);
            attrs.set_regular(true);
            Ok(Attrs { id, attrs })
        }

        async fn read(
            &mut self,
            id: u32,
            handle: String,
            offset: u64,
            len: u32,
        ) -> Result<Data, Self::Error> {
            let state = self.state.lock().unwrap();
            let data = state.files.get(&handle).ok_or(StatusCode::NoSuchFile)?;
            let start = usize::try_from(offset).map_err(|_| StatusCode::Failure)?;
            if start >= data.len() {
                return Err(StatusCode::Eof);
            }
            let end = start.saturating_add(len as usize).min(data.len());
            Ok(Data {
                id,
                data: data[start..end].to_vec(),
            })
        }

        async fn write(
            &mut self,
            id: u32,
            handle: String,
            offset: u64,
            bytes: Vec<u8>,
        ) -> Result<Status, Self::Error> {
            let mut state = self.state.lock().unwrap();
            if state
                .fail_writes_at_or_after
                .is_some_and(|limit| offset >= limit)
            {
                return Err(StatusCode::Failure);
            }
            let start = usize::try_from(offset).map_err(|_| StatusCode::Failure)?;
            let end = start.checked_add(bytes.len()).ok_or(StatusCode::Failure)?;
            let file = state.files.get_mut(&handle).ok_or(StatusCode::NoSuchFile)?;
            file.resize(file.len().max(end), 0);
            file[start..end].copy_from_slice(&bytes);
            Ok(ok_status(id))
        }

        async fn rename(
            &mut self,
            id: u32,
            oldpath: String,
            newpath: String,
        ) -> Result<Status, Self::Error> {
            let mut state = self.state.lock().unwrap();
            if state.files.contains_key(&newpath) {
                return Err(StatusCode::Failure);
            }
            if state.fail_second_promotion
                && oldpath.contains("/.gmacftp-upload-")
                && newpath == state.destination
            {
                return Err(StatusCode::Failure);
            }
            let bytes = state.files.remove(&oldpath).ok_or(StatusCode::NoSuchFile)?;
            state.files.insert(newpath, bytes);
            Ok(ok_status(id))
        }

        async fn remove(&mut self, id: u32, filename: String) -> Result<Status, Self::Error> {
            self.state.lock().unwrap().files.remove(&filename);
            Ok(ok_status(id))
        }
    }

    async fn transactional_sftp(state: Arc<Mutex<TransactionalSftpState>>) -> RawSftpSession {
        let (client, server) = tokio::io::duplex(2 * 1024 * 1024);
        russh_sftp::server::run(server, TransactionalSftpServer { state }).await;
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

    fn transactional_state(destination: &str, old: &[u8]) -> Arc<Mutex<TransactionalSftpState>> {
        Arc::new(Mutex::new(TransactionalSftpState {
            files: HashMap::from([(destination.to_string(), old.to_vec())]),
            destination: destination.to_string(),
            fail_writes_at_or_after: None,
            fail_second_promotion: false,
        }))
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
    async fn sftp_checksum_handles_short_reads_without_gaps() {
        let expected = (0..(SFTP_TRANSFER_CHUNK as usize * 4 + 333))
            .map(|index| (index % 193) as u8)
            .collect::<Vec<_>>();
        let remote = Arc::new(Mutex::new(expected.clone()));
        let sftp = memory_sftp(remote, true).await;

        let actual = hash_file_with_session(&sftp, "/checksum.bin")
            .await
            .unwrap();
        let reference: [u8; 32] = Sha256::digest(&expected).into();
        assert_eq!(actual, reference);
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
    async fn sftp_upload_replaces_existing_file_only_after_complete_stage() {
        let destination = "/site/app.bin";
        let state = transactional_state(destination, b"old complete data");
        let sftp = transactional_sftp(state.clone()).await;
        let dir = TestDir::new();
        let source = dir.0.join("transactional-upload.bin");
        let expected = vec![0x3d; SFTP_TRANSFER_CHUNK as usize * 3 + 77];
        std::fs::write(&source, &expected).unwrap();
        let file = tokio::fs::File::open(&source).await.unwrap();

        let uploaded = upload_with_session(&sftp, file, destination, |_| {}, None, None)
            .await
            .unwrap();

        let state = state.lock().unwrap();
        assert_eq!(uploaded, expected.len() as u64);
        assert_eq!(state.files.get(destination), Some(&expected));
        assert_eq!(
            state.files.len(),
            1,
            "staging and backup files must be removed"
        );
        drop(state);
        let _ = sftp.close_session();
    }

    #[tokio::test]
    async fn failed_sftp_write_keeps_destination_and_removes_partial_stage() {
        let destination = "/site/app.bin";
        let state = transactional_state(destination, b"old complete data");
        state.lock().unwrap().fail_writes_at_or_after = Some(SFTP_TRANSFER_CHUNK as u64);
        let sftp = transactional_sftp(state.clone()).await;
        let dir = TestDir::new();
        let source = dir.0.join("failing-upload.bin");
        std::fs::write(&source, vec![0x7e; SFTP_TRANSFER_CHUNK as usize * 3]).unwrap();
        let file = tokio::fs::File::open(&source).await.unwrap();

        assert!(
            upload_with_session(&sftp, file, destination, |_| {}, None, None)
                .await
                .is_err()
        );

        let state = state.lock().unwrap();
        assert_eq!(
            state.files.get(destination).map(Vec::as_slice),
            Some(&b"old complete data"[..])
        );
        assert_eq!(state.files.len(), 1, "partial staging file must be removed");
        drop(state);
        let _ = sftp.close_session();
    }

    #[tokio::test]
    async fn resumable_sftp_upload_verifies_then_appends_private_stage() {
        let destination = "/site/app.bin";
        let state = transactional_state(destination, b"old complete data");
        state.lock().unwrap().fail_writes_at_or_after = Some(SFTP_TRANSFER_CHUNK as u64);
        let sftp = transactional_sftp(state.clone()).await;
        let dir = TestDir::new();
        let source = dir.0.join("resumable-upload.bin");
        let expected = (0..(SFTP_TRANSFER_CHUNK as usize * 4 + 57))
            .map(|index| (index % 241) as u8)
            .collect::<Vec<_>>();
        std::fs::write(&source, &expected).unwrap();
        let resume = UploadResume {
            token: 0x55,
            expected_total: expected.len() as u64,
            expected_modified_unix_nanos: 1,
        };
        let first_file = tokio::fs::File::open(&source).await.unwrap();
        assert!(
            upload_with_session(&sftp, first_file, destination, |_| {}, None, Some(resume),)
                .await
                .is_err()
        );

        let staging =
            RemoteStagingPaths::for_resumable_destination(destination, resume.token).unwrap();
        let partial_len = state
            .lock()
            .unwrap()
            .files
            .get(&staging.temporary)
            .map(Vec::len)
            .unwrap_or(0);
        assert!(partial_len > 0 && partial_len < expected.len());
        assert_eq!(
            state
                .lock()
                .unwrap()
                .files
                .get(destination)
                .map(Vec::as_slice),
            Some(&b"old complete data"[..])
        );

        state.lock().unwrap().fail_writes_at_or_after = None;
        let second_file = tokio::fs::File::open(&source).await.unwrap();
        let first_progress = Arc::new(Mutex::new(None));
        let captured = first_progress.clone();
        let uploaded = upload_with_session(
            &sftp,
            second_file,
            destination,
            move |done| {
                captured.lock().unwrap().get_or_insert(done);
            },
            None,
            Some(resume),
        )
        .await
        .unwrap();

        assert_eq!(*first_progress.lock().unwrap(), Some(partial_len as u64));
        assert_eq!(uploaded, expected.len() as u64);
        let state = state.lock().unwrap();
        assert_eq!(state.files.get(destination), Some(&expected));
        assert_eq!(state.files.len(), 1);
        drop(state);
        let _ = sftp.close_session();
    }

    #[tokio::test]
    async fn failed_sftp_promotion_restores_previous_destination() {
        let destination = "/site/app.bin";
        let state = transactional_state(destination, b"old complete data");
        state.lock().unwrap().fail_second_promotion = true;
        let sftp = transactional_sftp(state.clone()).await;
        let dir = TestDir::new();
        let source = dir.0.join("promotion-failure.bin");
        std::fs::write(&source, b"new complete data").unwrap();
        let file = tokio::fs::File::open(&source).await.unwrap();

        assert!(
            upload_with_session(&sftp, file, destination, |_| {}, None, None)
                .await
                .is_err()
        );

        let state = state.lock().unwrap();
        assert_eq!(
            state.files.get(destination).map(Vec::as_slice),
            Some(&b"old complete data"[..])
        );
        assert_eq!(
            state.files.len(),
            1,
            "rollback must clean every staging path"
        );
        drop(state);
        let _ = sftp.close_session();
    }

    #[tokio::test]
    async fn cancelled_sftp_upload_does_not_touch_existing_destination() {
        let destination = "/site/app.bin";
        let state = transactional_state(destination, b"old complete data");
        let sftp = transactional_sftp(state.clone()).await;
        let dir = TestDir::new();
        let source = dir.0.join("cancelled-upload.bin");
        std::fs::write(&source, vec![0x55; SFTP_TRANSFER_CHUNK as usize * 2]).unwrap();
        let file = tokio::fs::File::open(&source).await.unwrap();
        let cancel = AtomicBool::new(true);

        assert!(matches!(
            upload_with_session(&sftp, file, destination, |_| {}, Some(&cancel), None).await,
            Err(NetError::Cancelled)
        ));

        let state = state.lock().unwrap();
        assert_eq!(
            state.files.get(destination).map(Vec::as_slice),
            Some(&b"old complete data"[..])
        );
        assert_eq!(state.files.len(), 1);
        drop(state);
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
