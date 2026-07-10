//! FTP / FTPS client (suppaftp 10 + native-tls).
//!
//! Security ordering: connect (plaintext control channel) -> into_secure (AUTH TLS) ->
//! login (USER/PASS). The password is never sent until explicit FTPS is established. Plain
//! FTP remains available only after a deliberate, application-level opt-in for a legacy host;
//! a refused `AUTH TLS` can never silently downgrade an authenticated session.

use std::io::{BufRead, BufReader, Read, Write};

use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::str::FromStr;
use suppaftp::list::File;
use suppaftp::native_tls::TlsConnector;
use suppaftp::types::FileType;
use suppaftp::{FtpError, FtpStream, NativeTlsConnector, NativeTlsFtpStream, Status};

use crate::model::{ConnectionSpec, RemoteEntry};
use crate::net::error::NetError;
use crate::net::safe::validate_ftp_path;
use crate::net::RemoteTreeStats;
use std::sync::atomic::{AtomicBool, Ordering};

/// Whether this exact saved connection has explicitly disabled TLS certificate verification.
/// Strict verification is the default. `MACKFTP_TLS_INSECURE=1` is a deliberately conspicuous,
/// non-persisted test/CI override and is never a substitute for a user-facing confirmation.
pub fn accept_invalid_tls(spec: &ConnectionSpec) -> bool {
    spec.accept_invalid_tls
        || std::env::var("MACKFTP_TLS_INSECURE")
            .map(|value| value == "1")
            .unwrap_or(false)
}

/// Whether this one saved connection was explicitly approved for plaintext FTP. This deliberately
/// reads the per-connection setting instead of a process-wide switch: accepting legacy FTP for
/// one LAN server must never authorize a downgrade for another host.
pub fn allow_plaintext_ftp(spec: &ConnectionSpec) -> bool {
    spec.allow_plaintext_ftp
}

/// The FTP methods gmacFTP uses, abstracted so a secured (FTPS) and a plain stream are
/// interchangeable behind `Box<dyn FtpConn>`.
trait FtpConn {
    fn cwd(&mut self, path: &str) -> Result<(), FtpError>;
    fn list_bounded(&mut self, path: Option<&str>) -> Result<Listing, FtpError>;
    fn make_dir(&mut self, path: &str) -> Result<(), FtpError>;
    fn remove_file(&mut self, path: &str) -> Result<(), FtpError>;
    fn remove_dir(&mut self, path: &str) -> Result<(), FtpError>;
    fn quit(&mut self) -> Result<(), FtpError>;
    fn retr_stream(&mut self, path: &str) -> Result<Box<dyn Read>, FtpError>;
    fn finalize_retr(&mut self, stream: Box<dyn Read>) -> Result<(), FtpError>;
    fn put_stream(&mut self, path: &str) -> Result<Box<dyn Write>, FtpError>;
    fn finalize_put(&mut self, writer: Box<dyn Write>) -> Result<(), FtpError>;
    /// Whether this is an unencrypted (plaintext) FTP stream — `true` for the plaintext
    /// fallback, `false` for the FTPS (`NativeTlsFtpStream`) path. Co-locates the "was the
    /// password sent in the clear?" fact with the stream type that knows it, instead of
    /// threading it as a positional `bool` out of [`connect`].
    fn is_plaintext(&self) -> bool;
}

macro_rules! impl_ftp_conn {
    ($ty:ty, $plaintext:expr) => {
        impl FtpConn for $ty {
            fn cwd(&mut self, path: &str) -> Result<(), FtpError> {
                self.cwd(path)
            }
            fn list_bounded(&mut self, path: Option<&str>) -> Result<Listing, FtpError> {
                match stream_listing(self, "MLSD", path) {
                    Ok(listing) => Ok(listing),
                    // Old servers commonly reply 500/501/502 to MLSD. Retain LIST fallback,
                    // but perform it through the same bounded streaming reader.
                    Err(FtpError::UnexpectedResponse(resp)) if resp.status.code() >= 500 => {
                        stream_listing(self, "LIST", path)
                    }
                    Err(e) => Err(e),
                }
            }
            fn make_dir(&mut self, path: &str) -> Result<(), FtpError> {
                self.mkdir(path)
            }
            fn remove_file(&mut self, path: &str) -> Result<(), FtpError> {
                self.rm(path)
            }
            fn remove_dir(&mut self, path: &str) -> Result<(), FtpError> {
                self.rmdir(path)
            }
            fn quit(&mut self) -> Result<(), FtpError> {
                self.quit()
            }
            fn retr_stream(&mut self, path: &str) -> Result<Box<dyn Read>, FtpError> {
                self.retr_as_stream(path).and_then(|s| {
                    // Defense in depth: passive streams are configured by
                    // `timed_passive_stream`, and this also covers a future active-mode
                    // caller before the stream is erased behind `dyn Read`.
                    apply_io_timeout(s.get_ref()).map_err(FtpError::ConnectionError)?;
                    Ok(Box::new(s) as Box<dyn Read>)
                })
            }
            fn finalize_retr(&mut self, stream: Box<dyn Read>) -> Result<(), FtpError> {
                self.finalize_retr_stream(stream)
            }
            fn put_stream(&mut self, path: &str) -> Result<Box<dyn Write>, FtpError> {
                self.put_with_stream(path).and_then(|s| {
                    apply_io_timeout(s.get_ref()).map_err(FtpError::ConnectionError)?;
                    Ok(Box::new(s) as Box<dyn Write>)
                })
            }
            fn finalize_put(&mut self, writer: Box<dyn Write>) -> Result<(), FtpError> {
                self.finalize_put_stream(writer)
            }
            fn is_plaintext(&self) -> bool {
                $plaintext
            }
        }
    };
}
impl_ftp_conn!(NativeTlsFtpStream, false);
impl_ftp_conn!(FtpStream, true);

/// A bounded directory listing. `truncated` means the server supplied more entries or bytes than
/// this client is willing to retain; reception is stopped immediately and the data channel is
/// closed, so a hostile peer cannot turn a bounded-memory listing into an unbounded-time one.
struct Listing {
    lines: Vec<String>,
    truncated: bool,
}

/// Stream MLSD/LIST lines directly from suppaftp's data channel. suppaftp's convenient
/// `mlsd()`/`list()` helpers collect every line in a Vec before returning, which makes the limit
/// below ineffective against a hostile listing. This reads and bounds in one pass, then cuts the
/// data channel immediately when the entry/byte limit is reached.
fn stream_listing<T: suppaftp::TlsStream>(
    stream: &mut suppaftp::ImplFtpStream<T>,
    command: &str,
    path: Option<&str>,
) -> Result<Listing, FtpError> {
    const MAX_LISTING_BYTES: usize = 16 * 1024 * 1024;
    const MAX_LISTING_LINE_BYTES: usize = 32 * 1024;
    const MAX_LISTING_DURATION: std::time::Duration = std::time::Duration::from_secs(120);

    let command = match path.filter(|p| !p.is_empty()) {
        Some(path) => format!("{command} {path}"),
        None => command.to_string(),
    };
    let (_, data_stream) =
        stream.custom_data_command(command, &[Status::AboutToSend, Status::AlreadyOpen])?;
    apply_io_timeout(data_stream.get_ref()).map_err(FtpError::ConnectionError)?;
    let mut reader = BufReader::new(data_stream);
    let mut lines = Vec::new();
    let mut stored_bytes = 0usize;
    let mut truncated = false;
    let mut malformed = false;
    let deadline = std::time::Instant::now() + MAX_LISTING_DURATION;

    let read_result: Result<(), FtpError> = (|| {
        while let Some(line) = read_listing_line(&mut reader, MAX_LISTING_LINE_BYTES, deadline)? {
            let Some(line) = line else {
                malformed = true;
                break;
            };
            if line.is_empty() {
                continue;
            }
            let next_bytes = stored_bytes.saturating_add(line.len());
            if lines.len() >= MAX_LISTING_ENTRIES || next_bytes > MAX_LISTING_BYTES {
                truncated = true;
                break;
            }
            stored_bytes = next_bytes;
            lines.push(line);
        }
        Ok(())
    })();
    // `close_data_connection` drops the stream before consuming the terminal control reply. On a
    // deliberate cutoff, a compliant server may answer 426 rather than 226; that response is
    // still consumed within the control-socket timeout, but does not turn a safe truncation into
    // an unbounded wait or a failed UI listing.
    let close_result = stream.close_data_connection(reader);
    match read_result {
        Err(e) => Err(e),
        Ok(()) if malformed => Err(FtpError::BadResponse),
        Ok(()) if truncated => Ok(Listing { lines, truncated }),
        Ok(()) => {
            close_result?;
            Ok(Listing { lines, truncated })
        }
    }
}

/// Read one line while bounding the memory used for an individual server-supplied filename.
/// `Ok(Some(None))` means an overlong line was detected and reception must stop immediately;
/// `Ok(None)` is EOF. The caller drops the reader through `close_data_connection`, rather than
/// draining attacker-controlled bytes until a newline that may never arrive.
fn read_listing_line<R: BufRead>(
    reader: &mut R,
    max_bytes: usize,
    deadline: std::time::Instant,
) -> Result<Option<Option<String>>, FtpError> {
    let mut line = Vec::new();
    let mut saw_data = false;
    loop {
        // A socket read timeout alone bounds only an idle peer. Without an absolute deadline, a
        // malicious server can drip one byte before every timeout and keep LIST alive forever.
        if std::time::Instant::now() >= deadline {
            return Err(FtpError::ConnectionError(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "FTP directory listing exceeded its total time limit",
            )));
        }
        let buf = reader.fill_buf().map_err(FtpError::ConnectionError)?;
        if buf.is_empty() {
            if !saw_data {
                return Ok(None);
            }
            break;
        }
        saw_data = true;
        let take = buf
            .iter()
            .position(|b| *b == b'\n')
            .map(|index| index + 1)
            .unwrap_or(buf.len());
        if line.len().saturating_add(take) > max_bytes {
            return Ok(Some(None));
        }
        line.extend_from_slice(&buf[..take]);
        let ended = buf[take - 1] == b'\n';
        reader.consume(take);
        if ended {
            break;
        }
    }
    while matches!(line.last(), Some(b'\r' | b'\n')) {
        line.pop();
    }
    Ok(Some(Some(String::from_utf8_lossy(&line).into_owned())))
}

/// Create a remote directory and all missing ancestors (mkdir -p). Replies for already-
/// existing segments (550) are ignored, so this is safe to call on existing trees.
fn mkdirs(c: &mut dyn FtpConn, remote_dir: &str) {
    // NETW-4: refuse CR/LF/NUL anywhere in the remote dir before any segment reaches MKD.
    if validate_ftp_path(remote_dir).is_err() {
        return;
    }
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
        let _ = c.make_dir(&acc);
    }
}

/// Parent directory of a remote path, absolute ("/a/b/c.txt" -> "/a/b"; "/c.txt" -> "/").
fn parent_remote(remote_path: &str) -> Option<String> {
    let p = remote_path.trim_end_matches('/');
    match p.rfind('/') {
        Some(0) => Some("/".to_string()),
        Some(idx) => Some(p[..idx].to_string()),
        None => None,
    }
}

/// Connect + authenticate with explicit FTPS.
///
/// A refused `AUTH TLS` is an error by default. A legacy plaintext connection is attempted only
/// when [`ConnectionSpec::allow_plaintext_ftp`] was explicitly enabled for this exact saved
/// connection; even then it starts over on a fresh
/// control socket, so no credentials ever cross the failed FTPS attempt.
///
/// TLS strictness follows `ConnectionSpec::accept_invalid_tls` (**default OFF = strict** — verify
/// the cert chain). `MACKFTP_TLS_INSECURE=1` is a test/CI escape hatch (logged WARN).
/// Per-operation socket I/O timeout: [`IO_TIMEOUT`]
/// (guards every control + data-channel read so a stalled server can't hang the UI forever).
fn connect(spec: &ConnectionSpec, password: &str) -> Result<Box<dyn FtpConn>, NetError> {
    let addr = (spec.host.as_str(), spec.effective_port());

    let insecure = accept_invalid_tls(spec);
    let mut tls_builder = TlsConnector::builder();
    if insecure {
        // Security-relevant event: each connection made with cert validation disabled is
        // a MITM exposure window. Default is strict (false); this only fires on explicit
        // opt-in (toolbar shield) or the MACKFTP_TLS_INSECURE escape hatch.
        tracing::warn!(
            host = %spec.host,
            env_override = !spec.accept_invalid_tls
                && std::env::var("MACKFTP_TLS_INSECURE")
                    .map(|value| value == "1")
                    .unwrap_or(false),
            "TLS certificate verification DISABLED for this connection — vulnerable to MITM"
        );
        tls_builder.danger_accept_invalid_certs(true);
    }

    let tls = tls_builder
        .build()
        .map_err(|e| NetError::Ftp(format!("could not configure TLS: {e}")))?;
    let connector = NativeTlsConnector::from(tls);
    let stream =
        NativeTlsFtpStream::connect_with_stream(connect_tcp(addr)?).map_err(NetError::from_ftp)?;
    match stream.into_secure(connector, &spec.host) {
        Ok(mut sec) => {
            // `suppaftp` otherwise uses unbounded `TcpStream::connect` for every passive data
            // channel. Preserve its passive-mode compatibility while bounding the connection and
            // subsequent I/O on every LIST/RETR/STOR data socket.
            sec = configure_safe_passive_data_connection(sec)?;
            map_login(sec.login(spec.user.as_str(), password))?;
            sec.transfer_type(FileType::Binary)
                .map_err(NetError::from_ftp)?; // TYPE I — preserve binary integrity
            return Ok(Box::new(sec));
        }
        Err(FtpError::UnexpectedResponse(resp)) if allow_plaintext_ftp(spec) => {
            tracing::warn!(
                host = %spec.host,
                code = resp.status.code(),
                "server refused FTPS; opening explicitly authorized plaintext FTP session"
            );
        }
        Err(FtpError::UnexpectedResponse(resp)) => {
            return Err(NetError::Ftp(format!(
                "server refused explicit FTPS (AUTH TLS, reply {}). Plaintext FTP is disabled; explicitly confirm the legacy-server warning before retrying",
                resp.status.code()
            )));
        }
        // Any other failure (e.g. certificate rejected under strict TLS) is a real TLS problem.
        // Never silently downgrade to a credential-leaking plaintext session.
        Err(e) => {
            tracing::warn!(host = %spec.host, error = %e, "TLS negotiation failed");
            return Err(NetError::from_ftp(e));
        }
    }

    // `allow_plaintext_ftp(spec)` was true for the refused-AUTH-TLS branch above. A fresh socket is
    // required because the failed negotiation may have left bytes buffered on the first one.
    let plain = FtpStream::connect_with_stream(connect_tcp(addr)?).map_err(NetError::from_ftp)?;
    let mut plain = configure_safe_passive_data_connection(plain)?;
    map_login(plain.login(spec.user.as_str(), password))?;
    plain
        .transfer_type(FileType::Binary)
        .map_err(NetError::from_ftp)?;
    // The caller can surface that this explicitly approved session is plaintext.
    Ok(Box::new(plain))
}

/// [`connect`] with a bounded retry on transient `421 Too many connections` rejections.
///
/// Shared-hosting FTP servers cap concurrent sessions per user. A folder download fires one RETR
/// connection per file, and the server needs a moment to release the previous slot after QUIT —
/// so the next connect can briefly land on `421 Too many connections`. Without a retry that turned
/// every file in a large folder into an instant failure, cascading into a rapid storm of 421
/// errors in the UI. We back off and retry a few times; the slot frees and the file proceeds.
/// Non-421 errors (auth, TLS, not-found) are returned immediately — only session-limit rejections
/// are transient enough to retry.
fn connect_with_retry(spec: &ConnectionSpec, password: &str) -> Result<Box<dyn FtpConn>, NetError> {
    const ATTEMPTS: u32 = 5;
    // Escalating backoff (ms): give the server time to release the previous session slot. Shared
    // hosts sometimes hold a slot briefly in TCP TIME_WAIT after QUIT, so a large folder needs a
    // few seconds of patience before a file is declared failed (data loss).
    const BACKOFF_MS: [u64; 4] = [300, 800, 2000, 5000];
    let mut last: Option<NetError> = None;
    for attempt in 0..ATTEMPTS {
        match connect(spec, password) {
            Ok(c) => return Ok(c),
            Err(e) => {
                let transient = matches!(&e, NetError::Ftp(msg) if msg.contains("421"));
                if !transient || attempt + 1 == ATTEMPTS {
                    return Err(e);
                }
                tracing::warn!(
                    host = %spec.host,
                    attempt = attempt + 1,
                    "FTP 421 (session limit) — backing off and retrying"
                );
                last = Some(e);
                std::thread::sleep(std::time::Duration::from_millis(
                    BACKOFF_MS[attempt as usize],
                ));
            }
        }
    }
    Err(last.expect("retry loop runs at least once before returning"))
}

/// Per-operation socket I/O timeout. suppaftp's control + data-channel reads are blocking
/// syscalls with no internal timeout; without this, a server that stalls mid-LIST/RETR/STOR
/// (or stops replying on the control channel) hangs the blocking pool thread AND the
/// authenticated session forever — the main browsing/transfer paths have no tokio timeout
/// wrapper. The socket timeout is the only thing that can actually unblock the syscall.
/// 45s tolerates slow large-file data transfers while converting a true stall into a clean
/// std::io::Error -> NetError.
const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);
const IO_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(45);
const MAX_LISTING_ENTRIES: usize = 50_000;
const MAX_REMOTE_FILES: usize = 100_000;
const MAX_REMOTE_DIRECTORIES: usize = 10_000;
const MAX_RECURSION_DEPTH: usize = 64;

/// Resolve every returned address and use a bounded TCP handshake for each. `TcpStream::connect`
/// can otherwise block the `spawn_blocking` pool indefinitely before the control socket exists.
fn connect_tcp(addr: (&str, u16)) -> Result<TcpStream, NetError> {
    let mut resolved = addr.to_socket_addrs()?;
    let Some(first) = resolved.next() else {
        return Err(NetError::Ftp(format!(
            "no addresses found for {}:{}",
            addr.0, addr.1
        )));
    };
    let mut last_error = None;
    for socket_addr in std::iter::once(first).chain(resolved) {
        match TcpStream::connect_timeout(&socket_addr, CONNECT_TIMEOUT) {
            Ok(tcp) => {
                apply_io_timeout(&tcp)?;
                return Ok(tcp);
            }
            Err(e) => last_error = Some(e),
        }
    }
    Err(NetError::Io(
        last_error.expect("at least one resolved address"),
    ))
}

/// `suppaftp` calls this for every passive data connection. Apply both a handshake and per-I/O
/// limit before it can be handed to the library's `DataStream`.
fn timed_passive_stream(addr: SocketAddr) -> Result<TcpStream, FtpError> {
    let tcp =
        TcpStream::connect_timeout(&addr, CONNECT_TIMEOUT).map_err(FtpError::ConnectionError)?;
    apply_io_timeout(&tcp).map_err(FtpError::ConnectionError)?;
    Ok(tcp)
}

/// The 227 PASV response contains a server-controlled IP address. Never connect to that address:
/// it can be used as an SSRF primitive against loopback or private services reachable from the
/// client. Keep the advertised *port*, but always use the authenticated control connection's
/// peer IP. IPv6 uses EPSV (which carries only a port); IPv4 retains PASV compatibility with the
/// same control-peer pinning.
fn configure_safe_passive_data_connection<T: suppaftp::TlsStream>(
    mut stream: suppaftp::ImplFtpStream<T>,
) -> Result<suppaftp::ImplFtpStream<T>, NetError> {
    let control_ip = stream.get_ref().peer_addr()?.ip();
    // suppaftp's own NAT workaround already replaces PASV's address with the control peer. The
    // custom builder below repeats that invariant at the final connect boundary.
    stream.set_passive_nat_workaround(true);
    if control_ip.is_ipv6() {
        // PASV is IPv4-only. EPSV obtains the port from the control peer and works for IPv6.
        stream.set_mode(suppaftp::types::Mode::ExtendedPassive);
    }
    Ok(stream.passive_stream_builder(move |advertised| {
        timed_passive_stream(safe_passive_target(control_ip, advertised))
    }))
}

fn safe_passive_target(control_ip: IpAddr, advertised: SocketAddr) -> SocketAddr {
    SocketAddr::new(control_ip, advertised.port())
}

fn apply_io_timeout(tcp: &std::net::TcpStream) -> std::io::Result<()> {
    tcp.set_read_timeout(Some(IO_TIMEOUT))?;
    tcp.set_write_timeout(Some(IO_TIMEOUT))
}

fn map_login(res: Result<(), FtpError>) -> Result<(), NetError> {
    match res {
        Ok(()) => Ok(()),
        Err(FtpError::UnexpectedResponse(resp)) if resp.status.code() == 530 => {
            Err(NetError::AuthFailed("530 Login incorrect".into()))
        }
        Err(e) => Err(NetError::from_ftp(e)),
    }
}

fn parse_lines(lines: Vec<String>) -> Vec<RemoteEntry> {
    let mut out = Vec::with_capacity(lines.len().min(MAX_LISTING_ENTRIES));
    for line in lines {
        if out.len() >= MAX_LISTING_ENTRIES {
            tracing::warn!(
                "directory listing truncated at {MAX_LISTING_ENTRIES} entries (DoS guard)"
            );
            break;
        }
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Ok(f) = File::from_str(line) {
            let name = f.name().to_string();
            if name == "." || name == ".." {
                continue;
            }
            out.push(RemoteEntry {
                name,
                is_dir: f.is_directory(),
                size: f.size() as u64,
                mtime: f
                    .modified()
                    .duration_since(std::time::UNIX_EPOCH)
                    .ok()
                    .map(|d| d.as_secs() as i64),
            });
        }
    }
    crate::model::sort_entries(&mut out);
    out
}

/// Connect, optionally cwd into the initial path, list the directory.
/// Returns `(entries, plaintext_fallback)` so the UI can warn when the session is plaintext.
pub fn connect_and_list(
    spec: &ConnectionSpec,
    password: &str,
) -> Result<(Vec<RemoteEntry>, bool), NetError> {
    let mut c = connect(spec, password)?;
    if !spec.initial_path.trim().is_empty() {
        // H3 / NETW-4: reject CR/LF/NUL in the initial path before it hits the FTP control
        // channel (command-smuggling guard). suppaftp forwards paths verbatim.
        validate_ftp_path(spec.initial_path.trim())?;
        c.cwd(spec.initial_path.trim())
            .map_err(NetError::from_ftp)?;
    }
    let listing = c.list_bounded(Some(".")).map_err(NetError::from_ftp)?;
    // Do not put the server's QUIT round-trip on the first-paint path. Some FTP servers
    // acknowledge QUIT surprisingly slowly; dropping the short-lived control connection
    // closes its TCP stream immediately after the complete listing has been received.
    if listing.truncated {
        tracing::warn!("FTP initial directory listing truncated by safety limit");
    }
    Ok((parse_lines(listing.lines), c.is_plaintext()))
}

/// Recursively collect every FILE under `root_dir` as `(absolute_remote_path, size)`.
/// Used for folder downloads. cwd-based listing for max server compatibility.
pub fn walk(
    spec: &ConnectionSpec,
    password: &str,
    root_dir: &str,
) -> Result<Vec<(String, u64)>, NetError> {
    let mut c = connect_with_retry(spec, password)?;
    let mut out = Vec::new();
    let root = if root_dir.trim().is_empty() {
        "/"
    } else {
        root_dir
    };
    let mut directories_seen = 0;
    let truncated = walk_inner(c.as_mut(), root, &mut out, 0, &mut directories_seen)?;
    let _ = c.quit();
    if truncated {
        Err(NetError::Ftp(
            "remote folder walk exceeded a safety limit; refusing an incomplete copy".into(),
        ))
    } else {
        Ok(out)
    }
}

pub fn tree_stats(
    spec: &ConnectionSpec,
    password: &str,
    root_dir: &str,
    max_files: usize,
) -> Result<RemoteTreeStats, NetError> {
    let mut c = connect(spec, password)?;
    let mut stats = RemoteTreeStats::default();
    let root = if root_dir.trim().is_empty() {
        "/"
    } else {
        root_dir
    };
    let effective_max_files = if max_files == 0 {
        MAX_REMOTE_FILES
    } else {
        max_files.min(MAX_REMOTE_FILES)
    };
    let mut directories_seen = 0;
    tree_stats_inner(
        c.as_mut(),
        root,
        &mut stats,
        effective_max_files,
        0,
        &mut directories_seen,
    )?;
    let _ = c.quit();
    Ok(stats)
}

fn tree_stats_inner(
    c: &mut dyn FtpConn,
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
        tracing::warn!("FTP tree statistics hit depth limit {MAX_RECURSION_DEPTH} (DoS guard)");
        stats.truncated = true;
        return Ok(());
    }
    if *directories_seen >= MAX_REMOTE_DIRECTORIES {
        tracing::warn!(
            "FTP tree statistics hit directory limit {MAX_REMOTE_DIRECTORIES} (DoS guard)"
        );
        stats.truncated = true;
        return Ok(());
    }
    *directories_seen += 1;
    validate_ftp_path(dir)?; // NETW-4: server-controlled recursion path
    c.cwd(dir).map_err(NetError::from_ftp)?;
    let listing = c.list_bounded(None).map_err(NetError::from_ftp)?;
    let entries = parse_lines(listing.lines);
    let listing_truncated = listing.truncated;
    for e in entries {
        if stats.truncated {
            break;
        }
        let full = join_remote_path(dir, &e.name);
        if e.is_dir {
            tree_stats_inner(c, &full, stats, max_files, depth + 1, directories_seen)?;
        } else {
            stats.size = stats.size.saturating_add(e.size);
            stats.files_scanned += 1;
            if let Some(mtime) = e.mtime {
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

fn walk_inner(
    c: &mut dyn FtpConn,
    dir: &str,
    out: &mut Vec<(String, u64)>,
    depth: usize,
    directories_seen: &mut usize,
) -> Result<bool, NetError> {
    if depth >= MAX_RECURSION_DEPTH {
        tracing::warn!("FTP folder walk hit depth limit {MAX_RECURSION_DEPTH} (DoS guard)");
        return Ok(true);
    }
    if *directories_seen >= MAX_REMOTE_DIRECTORIES {
        tracing::warn!("FTP folder walk hit directory limit {MAX_REMOTE_DIRECTORIES} (DoS guard)");
        return Ok(true);
    }
    if out.len() >= MAX_REMOTE_FILES {
        tracing::warn!("FTP folder walk truncated at {MAX_REMOTE_FILES} files (DoS guard)");
        return Ok(true);
    }
    *directories_seen += 1;
    validate_ftp_path(dir)?; // NETW-4: server-controlled recursion path
    c.cwd(dir).map_err(NetError::from_ftp)?;
    let listing = c.list_bounded(None).map_err(NetError::from_ftp)?;
    let entries = parse_lines(listing.lines);
    let listing_truncated = listing.truncated;
    for e in entries {
        if out.len() >= MAX_REMOTE_FILES {
            tracing::warn!("FTP folder walk truncated at {MAX_REMOTE_FILES} files (DoS guard)");
            return Ok(true);
        }
        let full = join_remote_path(dir, &e.name);
        if e.is_dir {
            if walk_inner(c, &full, out, depth + 1, directories_seen)? {
                return Ok(true);
            }
        } else {
            out.push((full, e.size));
        }
    }
    Ok(listing_truncated)
}

fn join_remote_path(dir: &str, name: &str) -> String {
    let d = dir.trim_end_matches('/');
    if d.is_empty() || d == "/" {
        format!("/{name}")
    } else {
        format!("{d}/{name}")
    }
}

/// Download `remote_path` to `local_path`, reporting cumulative bytes via `progress`.
/// Writes to a unique private sibling and atomically renames on success — a failure never
/// leaves a truncated/partial file at the final path.
#[allow(dead_code)] // wired in by the transfer actor (M6)
pub fn download(
    spec: &ConnectionSpec,
    password: &str,
    remote_path: &str,
    local_path: &std::path::Path,
    progress: impl Fn(u64),
    cancel: Option<&AtomicBool>, // M1: cooperative cancel so abort() stops an in-flight transfer
) -> Result<u64, NetError> {
    validate_ftp_path(remote_path)?; // NETW-4: CRLF/NUL command-smuggling guard
    let mut c = connect_with_retry(spec, password)?;
    if let Some(parent) = local_path.parent() {
        let _ = std::fs::create_dir_all(parent); // supports folder downloads
    }
    let (part, mut file) = create_unique_part(local_path)?;
    let result: Result<u64, NetError> = (|| {
        let mut stream = c.retr_stream(remote_path).map_err(NetError::from_ftp)?;
        let mut buf = [0u8; 64 * 1024];
        let mut done: u64 = 0;
        loop {
            if let Some(f) = cancel {
                if f.load(Ordering::Relaxed) {
                    return Err(NetError::Cancelled);
                }
            }
            let n = stream.read(&mut buf)?;
            if n == 0 {
                break;
            }
            file.write_all(&buf[..n])?;
            done += n as u64;
            progress(done);
        }
        c.finalize_retr(stream).map_err(NetError::from_ftp)?; // #1 suppaftp footgun
        file.sync_all()?;
        Ok(done)
    })();
    let _ = c.quit();
    match result {
        Ok(done) => match std::fs::rename(&part, local_path) {
            Ok(()) => Ok(done),
            Err(error) => {
                let _ = std::fs::remove_file(&part);
                Err(error.into())
            }
        },
        Err(e) => {
            let _ = std::fs::remove_file(&part); // no partial artifact
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
pub fn upload(
    spec: &ConnectionSpec,
    password: &str,
    local_path: &std::path::Path,
    remote_path: &str,
    progress: impl Fn(u64),
    cancel: Option<&AtomicBool>, // M1
) -> Result<u64, NetError> {
    validate_ftp_path(remote_path)?; // NETW-4
    let mut c = connect_with_retry(spec, password)?;
    if let Some(parent) = parent_remote(remote_path) {
        mkdirs(c.as_mut(), &parent); // supports folder uploads (mkdir -p ancestors)
    }
    let mut writer = c.put_stream(remote_path).map_err(NetError::from_ftp)?;
    let mut file = std::fs::File::open(local_path)?;
    let mut buf = [0u8; 64 * 1024];
    let mut done: u64 = 0;
    loop {
        if let Some(f) = cancel {
            if f.load(Ordering::Relaxed) {
                return Err(NetError::Cancelled);
            }
        }
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        writer.write_all(&buf[..n])?;
        done += n as u64;
        progress(done);
    }
    c.finalize_put(writer).map_err(NetError::from_ftp)?;
    let _ = c.quit();
    Ok(done)
}

/// Delete a remote file (DELE) or an empty remote directory (RMD). A non-empty directory
/// will fail with a server error — callers should walk + delete contents first if needed.
pub fn delete(
    spec: &ConnectionSpec,
    password: &str,
    remote_path: &str,
    is_dir: bool,
) -> Result<(), NetError> {
    validate_ftp_path(remote_path)?; // NETW-4
    let mut c = connect(spec, password)?;
    let r = if is_dir {
        c.remove_dir(remote_path)
    } else {
        c.remove_file(remote_path)
    };
    r.map_err(NetError::from_ftp)?;
    let _ = c.quit();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{ConnectionId, Protocol};

    fn spec(allow_plaintext_ftp: bool) -> ConnectionSpec {
        ConnectionSpec {
            id: ConnectionId(0),
            name: "test".into(),
            protocol: Protocol::Ftp,
            host: "legacy.example.test".into(),
            port: 21,
            user: "alice".into(),
            initial_path: String::new(),
            allow_plaintext_ftp,
            accept_invalid_tls: false,
        }
    }

    #[test]
    fn plaintext_ftp_is_opt_in_for_each_connection() {
        assert!(!allow_plaintext_ftp(&spec(false)));
        assert!(allow_plaintext_ftp(&spec(true)));
        // This is deliberately not global state: approving one legacy server cannot enable a
        // downgrade for another server in the same process.
        assert!(!allow_plaintext_ftp(&spec(false)));
    }

    #[test]
    fn pasv_address_is_pinned_to_the_control_peer() {
        let control: IpAddr = "203.0.113.9".parse().unwrap();
        let malicious: SocketAddr = "127.0.0.1:49152".parse().unwrap();
        assert_eq!(
            safe_passive_target(control, malicious),
            "203.0.113.9:49152".parse().unwrap()
        );

        let control_v6: IpAddr = "2001:db8::7".parse().unwrap();
        let advertised_v6: SocketAddr = "[::1]:49153".parse().unwrap();
        assert_eq!(
            safe_passive_target(control_v6, advertised_v6),
            "[2001:db8::7]:49153".parse().unwrap()
        );
    }

    #[test]
    fn listing_line_reader_stops_before_draining_an_unbounded_line() {
        let input = format!("{}\nvalid\n", "x".repeat(64));
        let mut reader = BufReader::new(input.as_bytes());
        assert_eq!(
            read_listing_line(
                &mut reader,
                16,
                std::time::Instant::now() + std::time::Duration::from_secs(1)
            )
            .unwrap(),
            Some(None)
        );
        // The oversized line is deliberately still buffered. The caller must now drop this
        // reader/data stream, rather than wait for an attacker to eventually send a newline.
        assert_eq!(reader.fill_buf().unwrap().first(), Some(&b'x'));
    }

    #[test]
    fn listing_line_reader_has_an_absolute_deadline() {
        let mut reader = BufReader::new(&b"valid\n"[..]);
        let result = read_listing_line(
            &mut reader,
            16,
            std::time::Instant::now() - std::time::Duration::from_millis(1),
        );
        assert!(matches!(
            result,
            Err(FtpError::ConnectionError(error))
                if error.kind() == std::io::ErrorKind::TimedOut
        ));
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
