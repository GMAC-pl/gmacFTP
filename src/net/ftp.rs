//! FTP / FTPS client (suppaftp 10 + native-tls).
//!
//! Security ordering for FTPS: connect (plaintext control channel) -> into_secure (AUTH TLS) ->
//! login (USER/PASS). The password is never sent until explicit FTPS is established. Plain FTP is
//! a separate, deliberate per-host transport mode; TLS failures never trigger an automatic
//! downgrade and the two modes never share a control connection.

use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::path::Path;

use sha2::{Digest, Sha256};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::str::FromStr;
use suppaftp::list::File;
use suppaftp::native_tls::TlsConnector;
use suppaftp::types::FileType;
use suppaftp::{
    FtpError, FtpStream, NativeTlsConnector, NativeTlsFtpStream, RustlsConnector, RustlsFtpStream,
    Status,
};

use crate::model::{ConnectionSpec, FtpTlsMode, RemoteEntry};
use crate::net::error::NetError;
use crate::net::partial::open_download_part;
use crate::net::safe::{validate_ftp_path, validate_remote_component};
use crate::net::{
    DownloadResume, RemoteFileMetadata, RemoteMetadata, RemoteSearchHit, RemoteSearchReport,
    RemoteStagingPaths, RemoteTreeStats, UploadResume, MAX_REMOTE_SEARCH_DEPTH,
    MAX_REMOTE_SEARCH_DIRECTORIES, MAX_REMOTE_SEARCH_ENTRIES, MAX_REMOTE_SEARCH_RESULTS,
};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

use suppaftp::rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use suppaftp::rustls::crypto::WebPkiSupportedAlgorithms;
use suppaftp::rustls::pki_types::pem::PemObject;
use suppaftp::rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use suppaftp::rustls::{DigitallySignedStruct, SignatureScheme};

type ObservedCertificatePin = std::sync::Arc<std::sync::Mutex<Option<String>>>;
type PinnedTlsConnector = (RustlsConnector, ObservedCertificatePin);

#[derive(Debug)]
struct CertificatePinVerifier {
    expected: Option<String>,
    observed: ObservedCertificatePin,
    signature_algorithms: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for CertificatePinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, suppaftp::rustls::Error> {
        let fingerprint = certificate_fingerprint(end_entity.as_ref());
        if let Ok(mut observed) = self.observed.lock() {
            *observed = Some(fingerprint.clone());
        }
        if self
            .expected
            .as_ref()
            .is_some_and(|expected| expected != &fingerprint)
        {
            return Err(suppaftp::rustls::Error::General(
                "FTPS leaf certificate does not match the endpoint pin".into(),
            ));
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, suppaftp::rustls::Error> {
        suppaftp::rustls::crypto::verify_tls12_signature(
            message,
            cert,
            signature,
            &self.signature_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, suppaftp::rustls::Error> {
        suppaftp::rustls::crypto::verify_tls13_signature(
            message,
            cert,
            signature,
            &self.signature_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.signature_algorithms.supported_schemes()
    }
}

fn certificate_fingerprint(der: &[u8]) -> String {
    let digest = Sha256::digest(der);
    let mut value = String::with_capacity("sha256:".len() + digest.len() * 2);
    value.push_str("sha256:");
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(value, "{byte:02x}");
    }
    value
}

pub fn normalize_certificate_pin(value: &str) -> Option<String> {
    let value = value.trim().to_ascii_lowercase();
    let hex = value.strip_prefix("sha256:").unwrap_or(&value);
    (hex.len() == 64 && hex.bytes().all(|byte| byte.is_ascii_hexdigit()))
        .then(|| format!("sha256:{hex}"))
}

fn pinned_tls_connector(
    spec: &ConnectionSpec,
    expected: Option<String>,
) -> Result<PinnedTlsConnector, NetError> {
    let provider = std::sync::Arc::new(suppaftp::rustls::crypto::ring::default_provider());
    let signature_algorithms = provider.signature_verification_algorithms;
    let observed = std::sync::Arc::new(std::sync::Mutex::new(None));
    let verifier = CertificatePinVerifier {
        expected,
        observed: observed.clone(),
        signature_algorithms,
    };
    let builder = suppaftp::rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|error| NetError::Ftp(format!("could not configure pinned TLS: {error}")))?
        .dangerous()
        .with_custom_certificate_verifier(std::sync::Arc::new(verifier));
    let config = match rustls_client_identity(spec)? {
        Some((certificates, key)) => builder
            .with_client_auth_cert(certificates, key)
            .map_err(|error| NetError::Ftp(format!("invalid FTPS client identity: {error}")))?,
        None => builder.with_no_client_auth(),
    };
    Ok((RustlsConnector::from(std::sync::Arc::new(config)), observed))
}

const MAX_TLS_IDENTITY_FILE_BYTES: usize = 1024 * 1024;

/// Read a TLS identity component without following symlinks or accepting mutable/non-regular
/// objects. The private key must be owned by this process's user and inaccessible to group/other.
fn read_tls_identity_file(path: &str, private_key: bool) -> Result<Zeroizing<Vec<u8>>, NetError> {
    if path.is_empty() || path.len() > 4096 || path.chars().any(char::is_control) {
        return Err(NetError::Ftp(
            "FTPS client identity path is empty, too long, or unsafe".into(),
        ));
    }
    let path = Path::new(path);
    if !path.is_absolute() {
        return Err(NetError::Ftp(
            "FTPS client identity paths must be absolute".into(),
        ));
    }
    let before = fs::symlink_metadata(path).map_err(|error| {
        NetError::Ftp(format!(
            "could not inspect FTPS client identity file: {error}"
        ))
    })?;
    if !before.file_type().is_file()
        || before.file_type().is_symlink()
        || before.len() == 0
        || before.len() > MAX_TLS_IDENTITY_FILE_BYTES as u64
    {
        return Err(NetError::Ftp(
            "FTPS client identity must be a non-empty regular file of at most 1 MiB".into(),
        ));
    }

    #[cfg(unix)]
    if private_key {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if before.uid() != unsafe { libc::geteuid() } {
            return Err(NetError::Ftp(
                "FTPS client private key must be owned by the current user".into(),
            ));
        }
        if before.permissions().mode() & 0o077 != 0 {
            return Err(NetError::Ftp(
                "FTPS client private key permissions are too broad; use mode 600".into(),
            ));
        }
    }

    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let mut file = options.open(path).map_err(|error| {
        NetError::Ftp(format!("could not open FTPS client identity file: {error}"))
    })?;
    let opened = file.metadata().map_err(|error| {
        NetError::Ftp(format!(
            "could not inspect opened FTPS identity file: {error}"
        ))
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if before.dev() != opened.dev() || before.ino() != opened.ino() {
            return Err(NetError::Ftp(
                "FTPS client identity file changed while it was being opened".into(),
            ));
        }
    }
    if !opened.file_type().is_file()
        || opened.len() == 0
        || opened.len() > MAX_TLS_IDENTITY_FILE_BYTES as u64
    {
        return Err(NetError::Ftp(
            "FTPS client identity file changed type or size".into(),
        ));
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(opened.len() as usize));
    Read::by_ref(&mut file)
        .take((MAX_TLS_IDENTITY_FILE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| NetError::Ftp(format!("could not read FTPS identity file: {error}")))?;
    if bytes.is_empty() || bytes.len() > MAX_TLS_IDENTITY_FILE_BYTES {
        return Err(NetError::Ftp(
            "FTPS client identity file is empty or exceeds 1 MiB".into(),
        ));
    }
    Ok(bytes)
}

fn client_identity_paths(spec: &ConnectionSpec) -> Result<Option<(&str, &str)>, NetError> {
    match (
        spec.tls_client_cert.as_deref(),
        spec.tls_client_key.as_deref(),
    ) {
        (None, None) => Ok(None),
        (Some(certificate), Some(key)) => Ok(Some((certificate, key))),
        _ => Err(NetError::Ftp(
            "FTPS client certificate and private key must be configured together".into(),
        )),
    }
}

fn native_tls_client_identity(
    spec: &ConnectionSpec,
) -> Result<Option<suppaftp::native_tls::Identity>, NetError> {
    let Some((certificate_path, key_path)) = client_identity_paths(spec)? else {
        return Ok(None);
    };
    let certificate = read_tls_identity_file(certificate_path, false)?;
    let key = read_tls_identity_file(key_path, true)?;
    suppaftp::native_tls::Identity::from_pkcs8(&certificate, &key)
        .map(Some)
        .map_err(|error| {
            NetError::Ftp(format!(
                "invalid FTPS client certificate or unencrypted PKCS#8 key: {error}"
            ))
        })
}

fn rustls_client_identity(
    spec: &ConnectionSpec,
) -> Result<
    Option<(
        Vec<suppaftp::rustls::pki_types::CertificateDer<'static>>,
        suppaftp::rustls::pki_types::PrivateKeyDer<'static>,
    )>,
    NetError,
> {
    let Some((certificate_path, key_path)) = client_identity_paths(spec)? else {
        return Ok(None);
    };
    let certificate = read_tls_identity_file(certificate_path, false)?;
    let key = read_tls_identity_file(key_path, true)?;
    let certificates = CertificateDer::pem_slice_iter(certificate.as_slice())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| NetError::Ftp(format!("invalid FTPS client certificate PEM: {error}")))?;
    if certificates.is_empty() {
        return Err(NetError::Ftp(
            "FTPS client certificate PEM contains no certificates".into(),
        ));
    }
    let mut private_keys = PrivateKeyDer::pem_slice_iter(key.as_slice());
    let Some(private_key) = private_keys
        .next()
        .transpose()
        .map_err(|error| NetError::Ftp(format!("invalid FTPS client private-key PEM: {error}")))?
    else {
        return Err(NetError::Ftp(
            "FTPS client key file contains no private key".into(),
        ));
    };
    if !matches!(
        private_key,
        suppaftp::rustls::pki_types::PrivateKeyDer::Pkcs8(_)
    ) {
        return Err(NetError::Ftp(
            "FTPS client private key must use unencrypted PKCS#8 PEM format".into(),
        ));
    }
    if private_keys
        .next()
        .transpose()
        .map_err(|error| NetError::Ftp(format!("invalid FTPS client private-key PEM: {error}")))?
        .is_some()
    {
        return Err(NetError::Ftp(
            "FTPS client key file must contain exactly one private key".into(),
        ));
    }
    Ok(Some((certificates, private_key)))
}

/// Whether this exact saved connection has explicitly disabled TLS certificate verification.
/// Strict verification is the default. `MACKFTP_TLS_INSECURE=1` is a deliberately conspicuous,
/// non-persisted test/CI override and is never a substitute for a user-facing confirmation.
pub fn accept_invalid_tls(spec: &ConnectionSpec) -> bool {
    spec.accept_invalid_tls
        || std::env::var("MACKFTP_TLS_INSECURE")
            .map(|value| value == "1")
            .unwrap_or(false)
}

/// Whether this one saved connection explicitly uses plaintext-only FTP. This deliberately reads
/// the per-connection setting instead of a process-wide switch: selecting legacy FTP for one LAN
/// server must never authorize a downgrade for another host.
pub fn allow_plaintext_ftp(spec: &ConnectionSpec) -> bool {
    spec.allow_plaintext_ftp
}

/// The FTP methods gmacFTP uses, abstracted so a secured (FTPS) and a plain stream are
/// interchangeable behind `Box<dyn FtpConn>`.
trait FtpConn: Send {
    fn cwd(&mut self, path: &str) -> Result<(), FtpError>;
    fn list_bounded(&mut self, path: Option<&str>) -> Result<Listing, FtpError>;
    fn list_bounded_incremental(
        &mut self,
        path: Option<&str>,
        on_batch: &mut dyn FnMut(Vec<String>) -> bool,
    ) -> Result<Listing, FtpError> {
        let listing = self.list_bounded(path)?;
        if !listing.lines.is_empty() && !on_batch(listing.lines.clone()) {
            return Ok(Listing {
                lines: listing.lines,
                truncated: listing.truncated,
                cancelled: true,
            });
        }
        Ok(listing)
    }
    fn make_dir(&mut self, path: &str) -> Result<(), FtpError>;
    fn remove_file(&mut self, path: &str) -> Result<(), FtpError>;
    fn remove_dir(&mut self, path: &str) -> Result<(), FtpError>;
    fn rename_path(&mut self, from: &str, to: &str) -> Result<(), FtpError>;
    fn chmod(&mut self, path: &str, mode: u32) -> Result<(), FtpError>;
    fn modified_time(&mut self, _path: &str) -> Result<Option<std::time::SystemTime>, FtpError> {
        Ok(None)
    }
    fn quit(&mut self) -> Result<(), FtpError>;
    fn retr_stream(&mut self, path: &str) -> Result<Box<dyn Read>, FtpError>;
    fn finalize_retr(&mut self, stream: Box<dyn Read>) -> Result<(), FtpError>;
    fn file_size(&mut self, path: &str) -> Result<Option<usize>, FtpError>;
    fn resume_transfer(&mut self, offset: usize) -> Result<(), FtpError>;
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
                let mut keep_going = |_| true;
                self.list_bounded_incremental(path, &mut keep_going)
            }
            fn list_bounded_incremental(
                &mut self,
                path: Option<&str>,
                on_batch: &mut dyn FnMut(Vec<String>) -> bool,
            ) -> Result<Listing, FtpError> {
                match stream_listing(self, "MLSD", path, on_batch) {
                    Ok(listing) => Ok(listing),
                    // Old servers commonly reply 500/501/502 to MLSD. Retain LIST fallback,
                    // but perform it through the same bounded streaming reader.
                    Err(FtpError::UnexpectedResponse(resp)) if resp.status.code() >= 500 => {
                        stream_listing(self, "LIST", path, on_batch)
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
            fn rename_path(&mut self, from: &str, to: &str) -> Result<(), FtpError> {
                self.rename(from, to)
            }
            fn chmod(&mut self, path: &str, mode: u32) -> Result<(), FtpError> {
                self.site(format!("CHMOD {mode:03o} {path}")).map(|_| ())
            }
            fn modified_time(
                &mut self,
                path: &str,
            ) -> Result<Option<std::time::SystemTime>, FtpError> {
                let timestamp = self.mdtm(path)?.and_utc().timestamp();
                let Ok(seconds) = u64::try_from(timestamp) else {
                    return Ok(None);
                };
                Ok(std::time::UNIX_EPOCH.checked_add(std::time::Duration::from_secs(seconds)))
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
            fn file_size(&mut self, path: &str) -> Result<Option<usize>, FtpError> {
                match self.size(path) {
                    Ok(size) => Ok(Some(size)),
                    Err(FtpError::UnexpectedResponse(response))
                        if response.status.code() == 550 =>
                    {
                        Ok(None)
                    }
                    Err(error) => Err(error),
                }
            }
            fn resume_transfer(&mut self, offset: usize) -> Result<(), FtpError> {
                self.resume_transfer(offset)
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
impl_ftp_conn!(RustlsFtpStream, false);
impl_ftp_conn!(FtpStream, true);

/// A bounded directory listing. `truncated` means the server supplied more entries or bytes than
/// this client is willing to retain; reception is stopped immediately and the data channel is
/// closed, so a hostile peer cannot turn a bounded-memory listing into an unbounded-time one.
struct Listing {
    lines: Vec<String>,
    truncated: bool,
    cancelled: bool,
}

/// Stream MLSD/LIST lines directly from suppaftp's data channel. suppaftp's convenient
/// `mlsd()`/`list()` helpers collect every line in a Vec before returning, which makes the limit
/// below ineffective against a hostile listing. This reads and bounds in one pass, then cuts the
/// data channel immediately when the entry/byte limit is reached.
fn stream_listing<T: suppaftp::TlsStream>(
    stream: &mut suppaftp::ImplFtpStream<T>,
    command: &str,
    path: Option<&str>,
    on_batch: &mut dyn FnMut(Vec<String>) -> bool,
) -> Result<Listing, FtpError> {
    const MAX_LISTING_BYTES: usize = 16 * 1024 * 1024;
    const MAX_LISTING_LINE_BYTES: usize = 32 * 1024;
    const MAX_LISTING_DURATION: std::time::Duration = std::time::Duration::from_secs(120);
    const LISTING_BATCH_ENTRIES: usize = 256;

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
    let mut cancelled = false;
    let mut malformed = false;
    let mut pending = Vec::with_capacity(LISTING_BATCH_ENTRIES);
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
            pending.push(line.clone());
            lines.push(line);
            if pending.len() >= LISTING_BATCH_ENTRIES && !on_batch(std::mem::take(&mut pending)) {
                cancelled = true;
                break;
            }
        }
        if !cancelled && !pending.is_empty() && !on_batch(std::mem::take(&mut pending)) {
            cancelled = true;
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
        Ok(()) if cancelled => Ok(Listing {
            lines,
            truncated,
            cancelled,
        }),
        Ok(()) if truncated => Ok(Listing {
            lines,
            truncated,
            cancelled,
        }),
        Ok(()) => {
            close_result?;
            Ok(Listing {
                lines,
                truncated,
                cancelled,
            })
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

/// Create a remote directory and all missing ancestors (mkdir -p). FTP commonly reports an
/// already-existing directory as 550; only that protocol response is tolerated. Transport and
/// timeout errors must stop before STOR so they are not hidden behind a later, misleading error.
fn mkdirs(c: &mut dyn FtpConn, remote_dir: &str) -> Result<(), NetError> {
    // NETW-4: refuse CR/LF/NUL anywhere in the remote dir before any segment reaches MKD.
    validate_ftp_path(remote_dir)?;
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
        match c.make_dir(&acc) {
            Ok(()) => {}
            Err(FtpError::UnexpectedResponse(response)) if response.status.code() == 550 => {}
            Err(error) => return Err(NetError::from_ftp(error)),
        }
    }
    Ok(())
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

const IMPLICIT_RELAY_POLL: Duration = Duration::from_millis(200);

/// Forward one half of a loopback relay. All traffic is already TLS ciphertext: this adapter only
/// lets suppaftp's legacy implicit-FTPS constructor consume a TCP stream that gmacFTP opened with
/// its own timeout/proxy policy. Before the TLS welcome completes, a hard deadline closes both
/// directions; afterwards the application-facing socket retains the normal per-I/O timeout.
fn relay_direction(
    mut source: TcpStream,
    mut destination: TcpStream,
    stop: Arc<AtomicBool>,
    handshake_complete: Arc<AtomicBool>,
    handshake_deadline: Instant,
) {
    let _ = source.set_read_timeout(Some(IMPLICIT_RELAY_POLL));
    let _ = destination.set_write_timeout(Some(IO_TIMEOUT));
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        if stop.load(Ordering::Acquire) {
            break;
        }
        if !handshake_complete.load(Ordering::Acquire) && Instant::now() >= handshake_deadline {
            stop.store(true, Ordering::Release);
            break;
        }
        match source.read(&mut buffer) {
            Ok(0) => {
                stop.store(true, Ordering::Release);
                break;
            }
            Ok(count) => {
                if destination.write_all(&buffer[..count]).is_err() {
                    stop.store(true, Ordering::Release);
                    break;
                }
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) => {}
            Err(_) => {
                stop.store(true, Ordering::Release);
                break;
            }
        }
    }
    let _ = source.shutdown(Shutdown::Both);
    let _ = destination.shutdown(Shutdown::Both);
}

fn start_implicit_relay(
    upstream: TcpStream,
    handshake_timeout: Duration,
) -> std::io::Result<(SocketAddr, Arc<AtomicBool>, Arc<AtomicBool>)> {
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))?;
    listener.set_nonblocking(true)?;
    let address = listener.local_addr()?;
    let stop = Arc::new(AtomicBool::new(false));
    let handshake_complete = Arc::new(AtomicBool::new(false));
    let thread_stop = stop.clone();
    let thread_complete = handshake_complete.clone();
    let deadline = Instant::now()
        .checked_add(handshake_timeout)
        .unwrap_or_else(Instant::now);
    std::thread::Builder::new()
        .name("gmacftp-ftps-relay".into())
        .spawn(move || {
            let accepted = loop {
                if thread_stop.load(Ordering::Acquire) || Instant::now() >= deadline {
                    thread_stop.store(true, Ordering::Release);
                    let _ = upstream.shutdown(Shutdown::Both);
                    return;
                }
                match listener.accept() {
                    Ok((stream, peer)) if peer.ip().is_loopback() => break stream,
                    Ok((stream, _)) => {
                        let _ = stream.shutdown(Shutdown::Both);
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => {
                        thread_stop.store(true, Ordering::Release);
                        let _ = upstream.shutdown(Shutdown::Both);
                        return;
                    }
                }
            };

            let client_reader = match accepted.try_clone() {
                Ok(stream) => stream,
                Err(_) => {
                    thread_stop.store(true, Ordering::Release);
                    let _ = accepted.shutdown(Shutdown::Both);
                    let _ = upstream.shutdown(Shutdown::Both);
                    return;
                }
            };
            let server_writer = match upstream.try_clone() {
                Ok(stream) => stream,
                Err(_) => {
                    thread_stop.store(true, Ordering::Release);
                    let _ = accepted.shutdown(Shutdown::Both);
                    let _ = upstream.shutdown(Shutdown::Both);
                    return;
                }
            };
            let reverse_stop = thread_stop.clone();
            let reverse_complete = thread_complete.clone();
            let reverse = std::thread::Builder::new()
                .name("gmacftp-ftps-relay-rx".into())
                .spawn(move || {
                    relay_direction(upstream, accepted, reverse_stop, reverse_complete, deadline);
                });
            if reverse.is_err() {
                thread_stop.store(true, Ordering::Release);
                let _ = client_reader.shutdown(Shutdown::Both);
                let _ = server_writer.shutdown(Shutdown::Both);
                return;
            }
            relay_direction(
                client_reader,
                server_writer,
                thread_stop,
                thread_complete,
                deadline,
            );
        })?;
    Ok((address, stop, handshake_complete))
}

type ImplicitRelay = (SocketAddr, IpAddr, Arc<AtomicBool>, Arc<AtomicBool>);

fn prepare_implicit_relay(spec: &ConnectionSpec) -> Result<ImplicitRelay, FtpError> {
    let timeout = connection_timeout(spec);
    let upstream = connect_tcp(spec, &spec.host, spec.effective_port(), timeout)
        .map_err(|error| FtpError::ConnectionError(std::io::Error::other(error.to_string())))?;
    let upstream_ip = upstream
        .peer_addr()
        .map_err(FtpError::ConnectionError)?
        .ip();
    let (relay_address, stop, handshake_complete) =
        start_implicit_relay(upstream, timeout).map_err(FtpError::ConnectionError)?;
    Ok((relay_address, upstream_ip, stop, handshake_complete))
}

fn connect_native_implicit_with_relay(
    spec: &ConnectionSpec,
    connector: NativeTlsConnector,
) -> Result<(NativeTlsFtpStream, IpAddr), FtpError> {
    let (relay_address, upstream_ip, stop, handshake_complete) = prepare_implicit_relay(spec)?;
    let result = NativeTlsFtpStream::connect_secure_implicit(relay_address, connector, &spec.host);
    match result {
        Ok(stream) => {
            handshake_complete.store(true, Ordering::Release);
            if let Err(error) = apply_io_timeout(stream.get_ref()) {
                stop.store(true, Ordering::Release);
                return Err(FtpError::ConnectionError(error));
            }
            Ok((stream, upstream_ip))
        }
        Err(error) => {
            stop.store(true, Ordering::Release);
            Err(error)
        }
    }
}

fn connect_rustls_implicit_with_relay(
    spec: &ConnectionSpec,
    connector: RustlsConnector,
) -> Result<(RustlsFtpStream, IpAddr), FtpError> {
    let (relay_address, upstream_ip, stop, handshake_complete) = prepare_implicit_relay(spec)?;
    let result = RustlsFtpStream::connect_secure_implicit(relay_address, connector, &spec.host);
    match result {
        Ok(stream) => {
            handshake_complete.store(true, Ordering::Release);
            if let Err(error) = apply_io_timeout(stream.get_ref()) {
                stop.store(true, Ordering::Release);
                return Err(FtpError::ConnectionError(error));
            }
            Ok((stream, upstream_ip))
        }
        Err(error) => {
            stop.store(true, Ordering::Release);
            Err(error)
        }
    }
}

fn require_implicit_private_data<T: suppaftp::TlsStream>(
    stream: &mut suppaftp::ImplFtpStream<T>,
) -> Result<(), NetError> {
    stream
        .custom_command("PBSZ 0", &[Status::CommandOk])
        .map_err(NetError::from_ftp)?;
    stream
        .custom_command("PROT P", &[Status::CommandOk])
        .map_err(NetError::from_ftp)?;
    Ok(())
}

fn connect_plaintext(spec: &ConnectionSpec, password: &str) -> Result<Box<dyn FtpConn>, NetError> {
    tracing::warn!(
        host = %spec.host,
        "connecting with explicitly selected plaintext-only FTP; credentials and files are not encrypted"
    );
    let plain = FtpStream::connect_with_stream(connect_tcp(
        spec,
        &spec.host,
        spec.effective_port(),
        connection_timeout(spec),
    )?)
    .map_err(NetError::from_ftp)?;
    let mut plain = configure_data_connection(plain, spec, None)?;
    map_login(plain.login(spec.user.as_str(), password))?;
    configure_filename_encoding(&mut plain, spec)?;
    plain
        .transfer_type(FileType::Binary)
        .map_err(NetError::from_ftp)?;
    Ok(Box::new(plain))
}

/// Connect + authenticate with the explicitly selected FTP transport.
///
/// FTPS never falls back after a refused `AUTH TLS`, certificate error, or handshake failure.
/// [`ConnectionSpec::allow_plaintext_ftp`] selects a separate plaintext-only connection before any
/// TLS negotiation starts, making the credential exposure explicit and deterministic.
///
/// TLS strictness follows `ConnectionSpec::accept_invalid_tls` (**default OFF = strict** — verify
/// the cert chain). `MACKFTP_TLS_INSECURE=1` is a test/CI escape hatch (logged WARN).
/// Per-operation socket I/O timeout: [`IO_TIMEOUT`]
/// (guards every control + data-channel read so a stalled server can't hang the UI forever).
fn connect(spec: &ConnectionSpec, password: &str) -> Result<Box<dyn FtpConn>, NetError> {
    let connect_timeout = connection_timeout(spec);

    if spec.allow_plaintext_ftp && spec.ftp_tls_mode == FtpTlsMode::Implicit {
        return Err(NetError::Ftp(
            "plaintext FTP cannot be combined with implicit TLS mode".into(),
        ));
    }
    if spec.allow_plaintext_ftp && client_identity_paths(spec)?.is_some() {
        return Err(NetError::Ftp(
            "an FTPS client certificate cannot be used with plaintext FTP".into(),
        ));
    }
    if spec.allow_plaintext_ftp && (spec.tls_pinned_sha256.is_some() || spec.accept_invalid_tls) {
        return Err(NetError::Ftp(
            "FTPS certificate trust settings cannot be used with plaintext FTP".into(),
        ));
    }
    if allow_plaintext_ftp(spec) {
        return connect_plaintext(spec, password);
    }

    if let Some(raw_pin) = spec.tls_pinned_sha256.as_deref() {
        let pin = normalize_certificate_pin(raw_pin).ok_or_else(|| {
            NetError::Ftp("saved FTPS certificate pin is malformed; review this connection".into())
        })?;
        return connect_with_certificate_pin(spec, password, pin);
    }

    let insecure = accept_invalid_tls(spec);
    let mut tls_builder = TlsConnector::builder();
    if let Some(identity) = native_tls_client_identity(spec)? {
        tls_builder.identity(identity);
    }
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
    let secure_result = match spec.ftp_tls_mode {
        FtpTlsMode::Explicit => {
            let stream = NativeTlsFtpStream::connect_with_stream(connect_tcp(
                spec,
                &spec.host,
                spec.effective_port(),
                connect_timeout,
            )?)
            .map_err(NetError::from_ftp)?;
            stream
                .into_secure(connector, &spec.host)
                .map(|stream| (stream, None))
        }
        FtpTlsMode::Implicit => connect_native_implicit_with_relay(spec, connector)
            .map(|(stream, peer)| (stream, Some(peer))),
    };
    match secure_result {
        Ok((mut sec, control_peer)) => {
            if spec.ftp_tls_mode == FtpTlsMode::Implicit {
                require_implicit_private_data(&mut sec)?;
            }
            // `suppaftp` otherwise uses unbounded `TcpStream::connect` for every passive data
            // channel. Preserve its passive-mode compatibility while bounding the connection and
            // subsequent I/O on every LIST/RETR/STOR data socket.
            sec = configure_data_connection(sec, spec, control_peer)?;
            map_login(sec.login(spec.user.as_str(), password))?;
            configure_filename_encoding(&mut sec, spec)?;
            sec.transfer_type(FileType::Binary)
                .map_err(NetError::from_ftp)?; // TYPE I — preserve binary integrity
            Ok(Box::new(sec))
        }
        Err(FtpError::UnexpectedResponse(resp)) => {
            let message = match spec.ftp_tls_mode {
                FtpTlsMode::Explicit => format!(
                    "server refused explicit FTPS (AUTH TLS, reply {}). Plaintext FTP is disabled; explicitly confirm the legacy-server warning before retrying",
                    resp.status.code()
                ),
                FtpTlsMode::Implicit => format!(
                    "implicit FTPS server rejected the encrypted session (reply {})",
                    resp.status.code()
                ),
            };
            Err(NetError::Ftp(message))
        }
        // Any other failure (e.g. certificate rejected under strict TLS) is a real TLS problem.
        // Never silently downgrade to a credential-leaking plaintext session.
        Err(e) => {
            tracing::warn!(host = %spec.host, error = %e, "TLS negotiation failed");
            if !insecure {
                if let Ok(fingerprint) = discover_tls_certificate(spec) {
                    return Err(NetError::TlsCertificateTrustRequired(
                        crate::net::TlsCertificateChallenge::new(
                            format!("{}:{}", spec.host, spec.effective_port()),
                            fingerprint,
                            None,
                        ),
                    ));
                }
            }
            Err(NetError::from_ftp(e))
        }
    }
}

fn connect_with_certificate_pin(
    spec: &ConnectionSpec,
    password: &str,
    expected: String,
) -> Result<Box<dyn FtpConn>, NetError> {
    let (connector, observed) = pinned_tls_connector(spec, Some(expected.clone()))?;
    let result = match spec.ftp_tls_mode {
        FtpTlsMode::Explicit => {
            let stream = RustlsFtpStream::connect_with_stream(connect_tcp(
                spec,
                &spec.host,
                spec.effective_port(),
                connection_timeout(spec),
            )?)
            .map_err(NetError::from_ftp)?;
            stream
                .into_secure(connector, &spec.host)
                .map(|stream| (stream, None))
        }
        FtpTlsMode::Implicit => connect_rustls_implicit_with_relay(spec, connector)
            .map(|(stream, peer)| (stream, Some(peer))),
    };
    let (mut secure, control_peer) = match result {
        Ok(secure) => secure,
        Err(error) => {
            let actual = observed.lock().ok().and_then(|value| value.clone());
            if let Some(actual) = actual.filter(|actual| actual != &expected) {
                return Err(NetError::TlsCertificateTrustRequired(
                    crate::net::TlsCertificateChallenge::new(
                        format!("{}:{}", spec.host, spec.effective_port()),
                        actual,
                        Some(expected),
                    ),
                ));
            }
            return Err(NetError::from_ftp(error));
        }
    };
    if spec.ftp_tls_mode == FtpTlsMode::Implicit {
        require_implicit_private_data(&mut secure)?;
    }
    secure = configure_data_connection(secure, spec, control_peer)?;
    map_login(secure.login(spec.user.as_str(), password))?;
    configure_filename_encoding(&mut secure, spec)?;
    secure
        .transfer_type(FileType::Binary)
        .map_err(NetError::from_ftp)?;
    Ok(Box::new(secure))
}

/// Complete an AUTH TLS handshake without USER/PASS and return the leaf certificate fingerprint.
/// The custom verifier still verifies the handshake signature, so the observed certificate must
/// prove possession of its private key even though chain/hostname trust is intentionally deferred
/// to the user-facing pin decision.
fn discover_tls_certificate(spec: &ConnectionSpec) -> Result<String, NetError> {
    let (connector, observed) = pinned_tls_connector(spec, None)?;
    let result = match spec.ftp_tls_mode {
        FtpTlsMode::Explicit => {
            let stream = RustlsFtpStream::connect_with_stream(connect_tcp(
                spec,
                &spec.host,
                spec.effective_port(),
                connection_timeout(spec),
            )?)
            .map_err(NetError::from_ftp)?;
            stream
                .into_secure(connector, &spec.host)
                .map(|stream| (stream, None))
        }
        FtpTlsMode::Implicit => connect_rustls_implicit_with_relay(spec, connector)
            .map(|(stream, peer)| (stream, Some(peer))),
    };
    let result_error = result.err();
    let fingerprint = observed
        .lock()
        .ok()
        .and_then(|value| value.clone())
        .ok_or_else(|| {
            result_error.map_or_else(
                || NetError::Ftp("FTPS server did not present a leaf certificate".into()),
                NetError::from_ftp,
            )
        })?;
    Ok(fingerprint)
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

/// Authenticated FTP/FTPS control connection reusable by the transfer scheduler. Data streams
/// remain per-file, while repeated files avoid TLS negotiation and USER/PASS round-trips.
pub struct TransferSession {
    connection: Box<dyn FtpConn>,
}

impl TransferSession {
    pub fn connect(spec: &ConnectionSpec, password: &str) -> Result<Self, NetError> {
        connect_with_retry(spec, password).map(|connection| Self { connection })
    }

    pub fn download(
        &mut self,
        remote_path: &str,
        local_path: &std::path::Path,
        progress: impl Fn(u64),
        cancel: Option<&AtomicBool>,
    ) -> Result<u64, NetError> {
        self.download_resumable(remote_path, local_path, progress, cancel, None)
    }

    pub fn download_resumable(
        &mut self,
        remote_path: &str,
        local_path: &std::path::Path,
        progress: impl Fn(u64),
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
    }

    pub fn download_resumable_with_metadata(
        &mut self,
        remote_path: &str,
        local_path: &std::path::Path,
        progress: impl Fn(u64),
        cancel: Option<&AtomicBool>,
        resume: Option<DownloadResume>,
        policy: crate::net::MetadataPreservation,
    ) -> Result<u64, NetError> {
        validate_ftp_path(remote_path)?;
        let modified = if policy.timestamps {
            match self.connection.modified_time(remote_path) {
                Ok(modified) => modified,
                Err(error) => {
                    tracing::debug!(%error, "FTP server did not provide a usable modification time");
                    None
                }
            }
        } else {
            None
        };
        let result = download_with_session(
            self.connection.as_mut(),
            remote_path,
            local_path,
            progress,
            cancel,
            resume,
        );
        if result.is_ok() {
            if let Err(error) = crate::net::apply_local_transfer_metadata(
                local_path,
                crate::net::TransferMetadata {
                    modified,
                    permissions: None,
                },
            ) {
                // File contents are already durably and atomically committed. Metadata support is
                // optional on FTP, so never turn this into a destructive re-transfer loop.
                tracing::warn!(%error, "could not preserve downloaded FTP file metadata");
            }
        }
        result
    }

    pub fn upload(
        &mut self,
        local_path: &std::path::Path,
        remote_path: &str,
        progress: impl Fn(u64),
        cancel: Option<&AtomicBool>,
    ) -> Result<u64, NetError> {
        self.upload_resumable(local_path, remote_path, progress, cancel, None)
    }

    pub fn upload_resumable(
        &mut self,
        local_path: &std::path::Path,
        remote_path: &str,
        progress: impl Fn(u64),
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
    }

    pub fn upload_resumable_with_metadata(
        &mut self,
        local_path: &std::path::Path,
        remote_path: &str,
        progress: impl Fn(u64),
        cancel: Option<&AtomicBool>,
        resume: Option<UploadResume>,
        policy: crate::net::MetadataPreservation,
    ) -> Result<u64, NetError> {
        let file = std::fs::File::open(local_path)?;
        let opened_metadata = file.metadata()?;
        if let Some(resume) = resume {
            crate::net::validate_upload_source(&opened_metadata, resume)?;
        }
        let metadata = crate::net::local_transfer_metadata(&opened_metadata, policy);
        let result = upload_with_session(
            self.connection.as_mut(),
            file,
            remote_path,
            progress,
            cancel,
            resume,
        );
        if result.is_ok() {
            if let Some(mode) = metadata.permissions {
                if let Err(error) = self.connection.chmod(remote_path, mode) {
                    // SITE CHMOD is an optional extension. A successfully promoted upload remains
                    // a success if the server declines this best-effort metadata operation.
                    tracing::warn!(%error, "FTP server could not preserve uploaded file permissions");
                }
            }
        }
        result
    }

    pub fn close(mut self) {
        let _ = self.connection.quit();
    }
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
fn connect_tcp(
    spec: &ConnectionSpec,
    target_host: &str,
    target_port: u16,
    timeout: std::time::Duration,
) -> Result<TcpStream, NetError> {
    if let Some(proxy_url) = spec.proxy_url.as_deref() {
        let tcp = crate::net::proxy::connect_tunnel(proxy_url, target_host, target_port, timeout)?;
        apply_io_timeout(&tcp)?;
        return Ok(tcp);
    }
    let mut resolved = (target_host, target_port).to_socket_addrs()?;
    let Some(first) = resolved.next() else {
        return Err(NetError::Ftp(format!(
            "no addresses found for {}:{}",
            target_host, target_port
        )));
    };
    let mut last_error = None;
    for socket_addr in std::iter::once(first).chain(resolved) {
        match TcpStream::connect_timeout(&socket_addr, timeout) {
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
fn timed_passive_stream(
    proxy_url: Option<&str>,
    target_host: &str,
    target: SocketAddr,
    timeout: std::time::Duration,
) -> Result<TcpStream, FtpError> {
    let tcp = if let Some(proxy_url) = proxy_url {
        crate::net::proxy::connect_tunnel(proxy_url, target_host, target.port(), timeout)
            .map_err(FtpError::ConnectionError)?
    } else {
        TcpStream::connect_timeout(&target, timeout).map_err(FtpError::ConnectionError)?
    };
    apply_io_timeout(&tcp).map_err(FtpError::ConnectionError)?;
    Ok(tcp)
}

/// The 227 PASV response contains a server-controlled IP address. Never connect to that address:
/// it can be used as an SSRF primitive against loopback or private services reachable from the
/// client. Keep the advertised *port*, but always use the authenticated control connection's
/// peer IP. IPv6 uses EPSV (which carries only a port); IPv4 retains PASV compatibility with the
/// same control-peer pinning.
fn configure_data_connection<T: suppaftp::TlsStream>(
    mut stream: suppaftp::ImplFtpStream<T>,
    spec: &ConnectionSpec,
    control_peer_override: Option<IpAddr>,
) -> Result<suppaftp::ImplFtpStream<T>, NetError> {
    let timeout = connection_timeout(spec);
    if spec.ftp_data_mode == crate::model::FtpDataMode::Active {
        if spec.proxy_url.is_some() {
            return Err(NetError::Ftp(
                "active FTP mode cannot be used through an HTTP/SOCKS proxy".into(),
            ));
        }
        // Active mode accepts an inbound data socket. It is restricted to FTPS by metadata
        // validation so a peer must still complete the authenticated TLS data-channel handshake.
        return Ok(stream.active_mode(timeout));
    }
    if let Some(proxy_url) = spec.proxy_url.clone() {
        // The control peer is the proxy, not the FTP server. Ignore PASV's server-controlled IP
        // and ask the same proxy for a tunnel to the configured server and advertised data port.
        let target_host = spec.host.clone();
        stream.set_passive_nat_workaround(false);
        return Ok(stream.passive_stream_builder(move |advertised| {
            timed_passive_stream(
                Some(proxy_url.as_str()),
                target_host.as_str(),
                advertised,
                timeout,
            )
        }));
    }
    let control_ip = match control_peer_override {
        Some(peer) => peer,
        None => stream.get_ref().peer_addr()?.ip(),
    };
    // suppaftp's own NAT workaround already replaces PASV's address with the control peer. The
    // custom builder below repeats that invariant at the final connect boundary.
    stream.set_passive_nat_workaround(true);
    if control_ip.is_ipv6() {
        // PASV is IPv4-only. EPSV obtains the port from the control peer and works for IPv6.
        stream.set_mode(suppaftp::types::Mode::ExtendedPassive);
    }
    Ok(stream.passive_stream_builder(move |advertised| {
        timed_passive_stream(
            None,
            "",
            safe_passive_target(control_ip, advertised),
            timeout,
        )
    }))
}

fn connection_timeout(spec: &ConnectionSpec) -> std::time::Duration {
    spec.timeout_secs
        .map(std::time::Duration::from_secs)
        .unwrap_or(CONNECT_TIMEOUT)
}

fn configure_filename_encoding<T: suppaftp::TlsStream>(
    stream: &mut suppaftp::ImplFtpStream<T>,
    spec: &ConnectionSpec,
) -> Result<(), NetError> {
    if spec.ftp_filename_encoding == crate::model::FtpFilenameEncoding::Utf8 {
        stream
            .opts("UTF8", Some("ON"))
            .map_err(NetError::from_ftp)?;
    }
    Ok(())
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

fn parse_listing_line(line: &str) -> Result<Option<RemoteEntry>, NetError> {
    let line = line.trim();
    if line.is_empty() {
        return Ok(None);
    }
    let Ok(file) = File::from_str(line) else {
        return Ok(None);
    };
    let name = file.name().to_string();
    if name == "." || name == ".." {
        return Ok(None);
    }
    validate_remote_component(&name)?;
    let (permissions, owner, group) = posix_listing_metadata(line);
    Ok(Some(RemoteEntry {
        name,
        is_dir: file.is_directory(),
        size: file.size() as u64,
        mtime: file
            .modified()
            .duration_since(std::time::UNIX_EPOCH)
            .ok()
            .map(|duration| duration.as_secs() as i64),
        permissions,
        owner,
        group,
    }))
}

fn parse_lines(lines: Vec<String>) -> Result<Vec<RemoteEntry>, NetError> {
    let mut out = Vec::with_capacity(lines.len().min(MAX_LISTING_ENTRIES));
    for line in lines {
        if out.len() >= MAX_LISTING_ENTRIES {
            tracing::warn!(
                "directory listing truncated at {MAX_LISTING_ENTRIES} entries (DoS guard)"
            );
            break;
        }
        if let Some(entry) = parse_listing_line(&line)? {
            out.push(entry);
        }
    }
    crate::model::sort_entries(&mut out);
    Ok(out)
}

/// Connect, optionally cwd into the initial path, list the directory.
/// Returns `(entries, plaintext_fallback)` so the UI can warn when the session is plaintext.
pub fn connect_and_list(
    spec: &ConnectionSpec,
    password: &str,
) -> Result<(Vec<RemoteEntry>, bool), NetError> {
    connect_and_list_incremental(spec, password, |_| true)
}

/// Connect and report parsed listing batches as they arrive. Returning `false` from `on_batch`
/// closes the data stream and reports [`NetError::Cancelled`], allowing navigation to supersede a
/// very large directory without waiting for its complete listing.
pub fn connect_and_list_incremental(
    spec: &ConnectionSpec,
    password: &str,
    mut on_batch: impl FnMut(Vec<RemoteEntry>) -> bool,
) -> Result<(Vec<RemoteEntry>, bool), NetError> {
    let mut c = connect(spec, password)?;
    if !spec.initial_path.trim().is_empty() {
        // H3 / NETW-4: reject CR/LF/NUL in the initial path before it hits the FTP control
        // channel (command-smuggling guard). suppaftp forwards paths verbatim.
        validate_ftp_path(spec.initial_path.trim())?;
        c.cwd(spec.initial_path.trim())
            .map_err(NetError::from_ftp)?;
    }
    let mut parse_error = None;
    let listing = {
        let mut parse_batch = |lines: Vec<String>| {
            let mut entries = Vec::with_capacity(lines.len());
            for line in lines {
                match parse_listing_line(&line) {
                    Ok(Some(entry)) => entries.push(entry),
                    Ok(None) => {}
                    Err(error) => {
                        parse_error = Some(error);
                        return false;
                    }
                }
            }
            entries.is_empty() || on_batch(entries)
        };
        c.list_bounded_incremental(Some("."), &mut parse_batch)
            .map_err(NetError::from_ftp)?
    };
    if let Some(error) = parse_error {
        return Err(error);
    }
    if listing.cancelled {
        return Err(NetError::Cancelled);
    }
    // Do not put the server's QUIT round-trip on the first-paint path. Some FTP servers
    // acknowledge QUIT surprisingly slowly; dropping the short-lived control connection
    // closes its TCP stream immediately after the complete listing has been received.
    if listing.truncated {
        tracing::warn!("FTP initial directory listing truncated by safety limit");
    }
    Ok((parse_lines(listing.lines)?, c.is_plaintext()))
}

/// Recursively collect every FILE under `root_dir` as `(absolute_remote_path, size)`.
/// Used for folder downloads. cwd-based listing for max server compatibility.
pub fn walk(
    spec: &ConnectionSpec,
    password: &str,
    root_dir: &str,
) -> Result<Vec<(String, u64)>, NetError> {
    walk_metadata(spec, password, root_dir).map(|files| {
        files
            .into_iter()
            .map(|file| (file.path, file.size))
            .collect()
    })
}

pub fn walk_metadata(
    spec: &ConnectionSpec,
    password: &str,
    root_dir: &str,
) -> Result<Vec<RemoteFileMetadata>, NetError> {
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

pub fn search(
    spec: &ConnectionSpec,
    password: &str,
    root_dir: &str,
    normalized_query: &str,
    cancelled: &AtomicBool,
) -> Result<RemoteSearchReport, NetError> {
    let mut connection = connect_with_retry(spec, password)?;
    let root = if root_dir.trim().is_empty() {
        "/"
    } else {
        root_dir
    };
    validate_ftp_path(root)?;
    let mut report = RemoteSearchReport::default();
    let result = search_inner(
        connection.as_mut(),
        root,
        normalized_query,
        cancelled,
        &mut report,
        0,
    );
    let _ = connection.quit();
    result?;
    Ok(report)
}

fn posix_listing_metadata(line: &str) -> (Option<u32>, Option<String>, Option<String>) {
    let fields = line.split_whitespace().collect::<Vec<_>>();
    let Some(mode) = fields.first().copied() else {
        return (None, None, None);
    };
    let bytes = mode.as_bytes();
    if bytes.len() < 10 || !matches!(bytes[0], b'-' | b'd' | b'l') {
        return (None, None, None);
    }
    let permission = |offset: usize| {
        let read = u32::from(bytes[offset] == b'r') * 4;
        let write = u32::from(bytes[offset + 1] == b'w') * 2;
        let execute = u32::from(matches!(bytes[offset + 2], b'x' | b's' | b't'));
        read + write + execute
    };
    let permissions = (permission(1) << 6) | (permission(4) << 3) | permission(7);
    (
        Some(permissions),
        fields.get(2).map(|owner| (*owner).to_string()),
        fields.get(3).map(|group| (*group).to_string()),
    )
}

pub fn inspect(
    spec: &ConnectionSpec,
    password: &str,
    remote_path: &str,
) -> Result<RemoteMetadata, NetError> {
    validate_ftp_path(remote_path)?;
    let path = std::path::Path::new(remote_path);
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| NetError::InvalidPath("remote metadata path has no filename".into()))?;
    validate_remote_component(name)?;
    let parent = path
        .parent()
        .map(|parent| parent.to_string_lossy().into_owned())
        .filter(|parent| !parent.is_empty())
        .unwrap_or_else(|| "/".into());
    validate_ftp_path(&parent)?;
    let mut connection = connect_with_retry(spec, password)?;
    let result = (|| {
        connection.cwd(&parent).map_err(NetError::from_ftp)?;
        let listing = connection.list_bounded(None).map_err(NetError::from_ftp)?;
        for line in listing.lines {
            let Ok(file) = File::from_str(line.trim()) else {
                continue;
            };
            if file.name() != name {
                continue;
            }
            let (permissions, owner, group) = posix_listing_metadata(&line);
            return Ok(RemoteMetadata {
                is_dir: file.is_directory(),
                size: file.size() as u64,
                mtime: file
                    .modified()
                    .duration_since(std::time::UNIX_EPOCH)
                    .ok()
                    .map(|duration| duration.as_secs() as i64),
                permissions,
                owner,
                group,
            });
        }
        Err(NetError::Ftp(if listing.truncated {
            "remote metadata listing was truncated before the item was found".into()
        } else {
            "remote item no longer exists".into()
        }))
    })();
    let _ = connection.quit();
    result
}

fn search_inner(
    connection: &mut dyn FtpConn,
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
    validate_ftp_path(directory)?;
    connection.cwd(directory).map_err(NetError::from_ftp)?;
    let listing = connection.list_bounded(None).map_err(NetError::from_ftp)?;
    if listing.truncated {
        report.truncated = true;
    }
    for entry in parse_lines(listing.lines)? {
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
            search_inner(
                connection,
                &path,
                normalized_query,
                cancelled,
                report,
                depth + 1,
            )?;
        }
        if report.truncated {
            break;
        }
    }
    Ok(())
}

pub fn hash_files(
    spec: &ConnectionSpec,
    password: &str,
    paths: &[String],
) -> Result<Vec<(String, [u8; 32])>, NetError> {
    let mut connection = connect_with_retry(spec, password)?;
    let result = paths
        .iter()
        .map(|path| {
            validate_ftp_path(path)?;
            hash_file_with_session(connection.as_mut(), path).map(|digest| (path.clone(), digest))
        })
        .collect();
    let _ = connection.quit();
    result
}

fn hash_file_with_session(
    connection: &mut dyn FtpConn,
    remote_path: &str,
) -> Result<[u8; 32], NetError> {
    let mut stream = connection
        .retr_stream(remote_path)
        .map_err(NetError::from_ftp)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    let read_result: Result<(), NetError> = (|| {
        loop {
            let read = stream.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            hasher.update(&buffer[..read]);
        }
        Ok(())
    })();
    let close_result = connection.finalize_retr(stream).map_err(NetError::from_ftp);
    read_result?;
    close_result?;
    Ok(hasher.finalize().into())
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
    let entries = parse_lines(listing.lines)?;
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
    out: &mut Vec<RemoteFileMetadata>,
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
    let entries = parse_lines(listing.lines)?;
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
            out.push(RemoteFileMetadata {
                path: full,
                size: e.size,
                mtime: e.mtime,
            });
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
    let mut session = TransferSession::connect(spec, password)?;
    let result = session.download(remote_path, local_path, progress, cancel);
    session.close();
    result
}

fn download_with_session(
    connection: &mut dyn FtpConn,
    remote_path: &str,
    local_path: &std::path::Path,
    progress: impl Fn(u64),
    cancel: Option<&AtomicBool>,
    resume: Option<DownloadResume>,
) -> Result<u64, NetError> {
    validate_ftp_path(remote_path)?; // NETW-4: CRLF/NUL command-smuggling guard
    if let Some(parent) = local_path.parent() {
        std::fs::create_dir_all(parent)?; // supports folder downloads
    }
    let part = open_download_part(local_path, resume)?;
    let part_path = part.path;
    let keep_on_error = part.keep_on_error;
    let mut file = part.file;
    let mut offset = part.offset;
    file.seek(SeekFrom::Start(offset))?;
    let result: Result<u64, NetError> = (|| {
        if offset > 0 {
            let platform_offset = usize::try_from(offset).map_err(|_| {
                NetError::Ftp("download resume offset does not fit this platform".into())
            })?;
            match connection.resume_transfer(platform_offset) {
                Ok(()) => {}
                // REST is optional. A server explicitly rejecting it falls back to a clean
                // restart; transport errors still fail so a broken session is never reused.
                Err(FtpError::UnexpectedResponse(response)) if response.status.code() >= 500 => {
                    tracing::info!(
                        code = response.status.code(),
                        "FTP server does not support resume; restarting download from zero"
                    );
                    file.set_len(0)?;
                    file.seek(SeekFrom::Start(0))?;
                    offset = 0;
                }
                Err(error) => return Err(NetError::from_ftp(error)),
            }
        }
        let mut stream = connection
            .retr_stream(remote_path)
            .map_err(NetError::from_ftp)?;
        let mut buf = [0u8; 64 * 1024];
        let mut done = offset;
        if done > 0 {
            progress(done);
        }
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
        connection
            .finalize_retr(stream)
            .map_err(NetError::from_ftp)?; // #1 suppaftp footgun
        file.sync_all()?;
        Ok(done)
    })();
    match result {
        Ok(done) => match std::fs::rename(&part_path, local_path) {
            Ok(()) => Ok(done),
            Err(error) => {
                let _ = std::fs::remove_file(&part_path);
                Err(error.into())
            }
        },
        Err(e) => {
            if !keep_on_error {
                let _ = std::fs::remove_file(&part_path);
            }
            Err(e)
        }
    }
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
    // Verify/read the source before authentication or STOR can truncate a remote destination.
    let file = std::fs::File::open(local_path)?;
    let mut session = TransferSession::connect(spec, password)?;
    let result = upload_with_session(
        session.connection.as_mut(),
        file,
        remote_path,
        progress,
        cancel,
        None,
    );
    session.close();
    result
}

pub fn discard_resumable_upload(
    spec: &ConnectionSpec,
    password: &str,
    remote_path: &str,
    token: u64,
) -> Result<(), NetError> {
    let staging = RemoteStagingPaths::for_resumable_destination(remote_path, token)?;
    let mut session = TransferSession::connect(spec, password)?;
    cleanup_staged_ftp_file(session.connection.as_mut(), &staging.temporary);
    session.close();
    Ok(())
}

fn upload_with_session(
    connection: &mut dyn FtpConn,
    mut file: std::fs::File,
    remote_path: &str,
    progress: impl Fn(u64),
    cancel: Option<&AtomicBool>,
    resume: Option<UploadResume>,
) -> Result<u64, NetError> {
    validate_ftp_path(remote_path)?; // NETW-4
    let mut staging = match resume {
        Some(resume) => RemoteStagingPaths::for_resumable_destination(remote_path, resume.token)?,
        None => RemoteStagingPaths::for_destination(remote_path)?,
    };
    let mut preserve_for_resume = resume.is_some();
    if let Some(parent) = parent_remote(remote_path) {
        mkdirs(connection, &parent)?; // supports folder uploads (mkdir -p ancestors)
    }

    let mut offset = 0_u64;
    if let Some(resume) = resume {
        match connection.file_size(&staging.temporary) {
            Ok(Some(size)) => {
                offset = size as u64;
                if offset > resume.expected_total {
                    cleanup_staged_ftp_file(connection, &staging.temporary);
                    staging = RemoteStagingPaths::for_destination(remote_path)?;
                    preserve_for_resume = false;
                    offset = 0;
                }
            }
            Ok(None) => {}
            Err(FtpError::UnexpectedResponse(response))
                if matches!(response.status.code(), 500 | 501 | 502 | 504) =>
            {
                // SIZE is optional. Without a trustworthy remote length we must never append;
                // abandon the stable fragment and restart through an unrelated private stage.
                cleanup_staged_ftp_file(connection, &staging.temporary);
                staging = RemoteStagingPaths::for_destination(remote_path)?;
                preserve_for_resume = false;
            }
            Err(error) => return Err(NetError::from_ftp(error)),
        }

        if offset == resume.expected_total && offset > 0 {
            progress(offset);
            finalize_staged_ftp_upload(connection, &staging, remote_path, preserve_for_resume)?;
            return Ok(offset);
        }

        if offset > 0 {
            let platform_offset = usize::try_from(offset).map_err(|_| {
                NetError::Ftp("upload resume offset does not fit this platform".into())
            })?;
            match connection.resume_transfer(platform_offset) {
                Ok(()) => {
                    file.seek(SeekFrom::Start(offset))?;
                    progress(offset);
                }
                Err(FtpError::UnexpectedResponse(response)) if response.status.code() >= 500 => {
                    // REST before STOR is optional. A rejecting server gets a clean full restart;
                    // the existing destination remains untouched until promotion.
                    cleanup_staged_ftp_file(connection, &staging.temporary);
                    staging = RemoteStagingPaths::for_destination(remote_path)?;
                    preserve_for_resume = false;
                    offset = 0;
                    file.seek(SeekFrom::Start(0))?;
                }
                Err(error) => return Err(NetError::from_ftp(error)),
            }
        }
    }

    let mut writer = match connection.put_stream(&staging.temporary) {
        Ok(writer) => writer,
        Err(error) => {
            if !preserve_for_resume {
                cleanup_staged_ftp_file(connection, &staging.temporary);
            }
            return Err(NetError::from_ftp(error));
        }
    };
    let mut buf = [0u8; 64 * 1024];
    let mut done = offset;
    let transfer_result: Result<u64, NetError> = (|| {
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
        Ok(done)
    })();
    // Always close the data stream and consume the final FTP response. Without this, a DELE used
    // for cleanup would race the pending STOR completion reply on the control connection.
    let close_result = connection.finalize_put(writer).map_err(NetError::from_ftp);
    match transfer_result {
        Ok(done) => {
            if let Err(error) = close_result {
                if !preserve_for_resume {
                    cleanup_staged_ftp_file(connection, &staging.temporary);
                }
                return Err(error);
            }
            if cancel.is_some_and(|flag| flag.load(Ordering::Relaxed)) {
                if !preserve_for_resume {
                    cleanup_staged_ftp_file(connection, &staging.temporary);
                }
                return Err(NetError::Cancelled);
            }
            finalize_staged_ftp_upload(connection, &staging, remote_path, preserve_for_resume)?;
            Ok(done)
        }
        Err(error) => {
            if let Err(close_error) = close_result {
                tracing::debug!(%close_error, "FTP data stream also failed while aborting upload");
            }
            if !preserve_for_resume {
                cleanup_staged_ftp_file(connection, &staging.temporary);
            }
            Err(error)
        }
    }
}

fn cleanup_staged_ftp_file(connection: &mut dyn FtpConn, path: &str) {
    if let Err(error) = connection.remove_file(path) {
        tracing::debug!(%error, path, "could not remove staged FTP upload");
    }
}

/// Promote a complete temporary upload without exposing a partial destination. Most servers
/// replace an existing regular file during RNFR/RNTO. Servers that reject an occupied target use a
/// same-directory backup/rollback sequence instead.
fn finalize_staged_ftp_upload(
    connection: &mut dyn FtpConn,
    staging: &RemoteStagingPaths,
    destination: &str,
    preserve_temporary_on_failure: bool,
) -> Result<(), NetError> {
    match connection.rename_path(&staging.temporary, destination) {
        Ok(()) => return Ok(()),
        Err(direct_error) => {
            if let Err(backup_error) = connection.rename_path(destination, &staging.backup) {
                if !preserve_temporary_on_failure {
                    cleanup_staged_ftp_file(connection, &staging.temporary);
                }
                tracing::debug!(%backup_error, "FTP destination could not be moved aside");
                return Err(NetError::from_ftp(direct_error));
            }
        }
    }

    match connection.rename_path(&staging.temporary, destination) {
        Ok(()) => {
            cleanup_staged_ftp_file(connection, &staging.backup);
            Ok(())
        }
        Err(promote_error) => {
            let rollback = connection.rename_path(&staging.backup, destination);
            if !preserve_temporary_on_failure {
                cleanup_staged_ftp_file(connection, &staging.temporary);
            }
            match rollback {
                Ok(()) => Err(NetError::from_ftp(promote_error)),
                Err(rollback_error) => Err(NetError::Ftp(format!(
                    "upload finalization failed ({promote_error}); restoring the previous destination also failed ({rollback_error}); previous data remains at {}",
                    staging.backup
                ))),
            }
        }
    }
}

pub fn rename(spec: &ConnectionSpec, password: &str, from: &str, to: &str) -> Result<(), NetError> {
    validate_ftp_path(from)?;
    validate_ftp_path(to)?;
    let mut connection = connect(spec, password)?;
    let result = connection.rename_path(from, to).map_err(NetError::from_ftp);
    let _ = connection.quit();
    result
}

pub fn create_dir(spec: &ConnectionSpec, password: &str, path: &str) -> Result<(), NetError> {
    validate_ftp_path(path)?;
    let mut connection = connect(spec, password)?;
    let result = connection.make_dir(path).map_err(NetError::from_ftp);
    let _ = connection.quit();
    result
}

pub fn chmod(spec: &ConnectionSpec, password: &str, path: &str, mode: u32) -> Result<(), NetError> {
    validate_ftp_path(path)?;
    if mode > 0o777 {
        return Err(NetError::InvalidPath("invalid permission mode".into()));
    }
    let mut connection = connect(spec, password)?;
    let result = connection.chmod(path, mode).map_err(NetError::from_ftp);
    let _ = connection.quit();
    result
}

fn collect_delete_tree(
    connection: &mut dyn FtpConn,
    path: &str,
    out: &mut Vec<(String, bool)>,
    depth: usize,
    directories: &mut usize,
) -> Result<(), NetError> {
    if depth >= MAX_RECURSION_DEPTH || *directories >= MAX_REMOTE_DIRECTORIES {
        return Err(NetError::Ftp(
            "remote folder exceeds recursive-delete safety limits".into(),
        ));
    }
    *directories += 1;
    validate_ftp_path(path)?;
    connection.cwd(path).map_err(NetError::from_ftp)?;
    let listing = connection.list_bounded(None).map_err(NetError::from_ftp)?;
    if listing.truncated {
        return Err(NetError::Ftp(
            "remote folder listing was truncated; refusing incomplete delete".into(),
        ));
    }
    for entry in parse_lines(listing.lines)? {
        if out.len() >= MAX_REMOTE_FILES + MAX_REMOTE_DIRECTORIES {
            return Err(NetError::Ftp(
                "remote folder exceeds recursive-delete safety limits".into(),
            ));
        }
        let child = join_remote_path(path, &entry.name);
        if entry.is_dir {
            collect_delete_tree(connection, &child, out, depth + 1, directories)?;
        } else {
            out.push((child, false));
        }
    }
    out.push((path.to_string(), true));
    Ok(())
}

/// Delete a remote file (DELE) or an empty remote directory (RMD). A non-empty directory
/// is preflighted recursively and then removed deepest-first.
pub fn delete(
    spec: &ConnectionSpec,
    password: &str,
    remote_path: &str,
    is_dir: bool,
) -> Result<(), NetError> {
    validate_ftp_path(remote_path)?; // NETW-4
    let mut c = connect(spec, password)?;
    let result: Result<(), NetError> = (|| {
        if is_dir {
            let mut paths = Vec::new();
            let mut directories = 0;
            collect_delete_tree(c.as_mut(), remote_path, &mut paths, 0, &mut directories)?;
            paths.into_iter().try_for_each(|(path, directory)| {
                if directory {
                    c.remove_dir(&path)
                } else {
                    c.remove_file(&path)
                }
                .map_err(NetError::from_ftp)
            })
        } else {
            c.remove_file(remote_path).map_err(NetError::from_ftp)
        }
    })();
    let _ = c.quit();
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{ConnectionId, Protocol};
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    fn ftp_test_error(message: &str) -> FtpError {
        FtpError::ConnectionError(std::io::Error::other(message.to_string()))
    }

    struct MemoryRemoteWriter {
        path: String,
        files: Arc<Mutex<HashMap<String, Vec<u8>>>>,
        bytes_before_failure: Option<usize>,
    }

    impl Write for MemoryRemoteWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if self.bytes_before_failure == Some(0) {
                return Err(std::io::Error::other("injected STOR failure"));
            }
            let count = self
                .bytes_before_failure
                .map(|remaining| remaining.min(bytes.len()))
                .unwrap_or(bytes.len());
            self.files
                .lock()
                .unwrap()
                .entry(self.path.clone())
                .or_default()
                .extend_from_slice(&bytes[..count]);
            if let Some(remaining) = &mut self.bytes_before_failure {
                *remaining -= count;
            }
            Ok(count)
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    struct MemoryFtp {
        files: Arc<Mutex<HashMap<String, Vec<u8>>>>,
        bytes_before_failure: Option<usize>,
        destination: String,
        fail_second_promotion: bool,
        resume_offset: Option<usize>,
        current_directory: String,
        listings: HashMap<String, Listing>,
    }

    impl MemoryFtp {
        fn new(destination: &str, old: &[u8]) -> Self {
            Self {
                files: Arc::new(Mutex::new(HashMap::from([(
                    destination.to_string(),
                    old.to_vec(),
                )]))),
                bytes_before_failure: None,
                destination: destination.to_string(),
                fail_second_promotion: false,
                resume_offset: None,
                current_directory: "/".into(),
                listings: HashMap::new(),
            }
        }
    }

    impl FtpConn for MemoryFtp {
        fn cwd(&mut self, path: &str) -> Result<(), FtpError> {
            self.current_directory = path.to_string();
            Ok(())
        }

        fn list_bounded(&mut self, _path: Option<&str>) -> Result<Listing, FtpError> {
            Ok(self
                .listings
                .remove(&self.current_directory)
                .unwrap_or(Listing {
                    lines: Vec::new(),
                    truncated: false,
                    cancelled: false,
                }))
        }

        fn make_dir(&mut self, _path: &str) -> Result<(), FtpError> {
            Ok(())
        }

        fn remove_file(&mut self, path: &str) -> Result<(), FtpError> {
            self.files.lock().unwrap().remove(path);
            Ok(())
        }

        fn remove_dir(&mut self, _path: &str) -> Result<(), FtpError> {
            Ok(())
        }

        fn rename_path(&mut self, from: &str, to: &str) -> Result<(), FtpError> {
            let mut files = self.files.lock().unwrap();
            if files.contains_key(to) {
                return Err(ftp_test_error("target exists"));
            }
            if self.fail_second_promotion
                && from.contains("/.gmacftp-upload-")
                && to == self.destination
            {
                return Err(ftp_test_error("injected promotion failure"));
            }
            let bytes = files
                .remove(from)
                .ok_or_else(|| ftp_test_error("source missing"))?;
            files.insert(to.to_string(), bytes);
            Ok(())
        }

        fn chmod(&mut self, _path: &str, _mode: u32) -> Result<(), FtpError> {
            Ok(())
        }

        fn quit(&mut self) -> Result<(), FtpError> {
            Ok(())
        }

        fn retr_stream(&mut self, path: &str) -> Result<Box<dyn Read>, FtpError> {
            let bytes = self
                .files
                .lock()
                .unwrap()
                .get(path)
                .cloned()
                .ok_or_else(|| ftp_test_error("source missing"))?;
            Ok(Box::new(std::io::Cursor::new(bytes)))
        }

        fn finalize_retr(&mut self, _stream: Box<dyn Read>) -> Result<(), FtpError> {
            Ok(())
        }

        fn file_size(&mut self, path: &str) -> Result<Option<usize>, FtpError> {
            Ok(self.files.lock().unwrap().get(path).map(Vec::len))
        }

        fn resume_transfer(&mut self, offset: usize) -> Result<(), FtpError> {
            self.resume_offset = Some(offset);
            Ok(())
        }

        fn put_stream(&mut self, path: &str) -> Result<Box<dyn Write>, FtpError> {
            if self.resume_offset.take().is_none() {
                self.files
                    .lock()
                    .unwrap()
                    .insert(path.to_string(), Vec::new());
            }
            Ok(Box::new(MemoryRemoteWriter {
                path: path.to_string(),
                files: self.files.clone(),
                bytes_before_failure: self.bytes_before_failure,
            }))
        }

        fn finalize_put(&mut self, _writer: Box<dyn Write>) -> Result<(), FtpError> {
            Ok(())
        }

        fn is_plaintext(&self) -> bool {
            false
        }
    }

    fn test_listing(lines: &[&str]) -> Listing {
        Listing {
            lines: lines.iter().map(|line| (*line).to_string()).collect(),
            truncated: false,
            cancelled: false,
        }
    }

    #[test]
    fn recursive_search_reuses_one_session_and_honours_cancellation() {
        let mut ftp = MemoryFtp::new("/unused", b"");
        ftp.listings.insert(
            "/".into(),
            test_listing(&[
                "drwxr-xr-x 2 owner group 4096 Jan 01 12:00 Reports",
                "-rw-r--r-- 1 owner group 12 Jan 01 12:00 notes.txt",
            ]),
        );
        ftp.listings.insert(
            "/Reports".into(),
            test_listing(&[
                "-rw-r--r-- 1 owner group 42 Jan 01 12:00 Final-Budget.pdf",
                "drwxr-xr-x 2 owner group 4096 Jan 01 12:00 Archive",
            ]),
        );
        ftp.listings.insert(
            "/Reports/Archive".into(),
            test_listing(&["-rw-r--r-- 1 owner group 9 Jan 01 12:00 draft.txt"]),
        );

        let mut report = RemoteSearchReport::default();
        search_inner(
            &mut ftp,
            "/",
            "final budget",
            &AtomicBool::new(false),
            &mut report,
            0,
        )
        .unwrap();
        assert_eq!(report.directories_scanned, 3);
        assert_eq!(report.entries_scanned, 5);
        assert_eq!(report.hits.len(), 1);
        assert_eq!(report.hits[0].path, "/Reports/Final-Budget.pdf");
        assert!(!report.truncated);

        let error = search_inner(
            &mut ftp,
            "/",
            "anything",
            &AtomicBool::new(true),
            &mut RemoteSearchReport::default(),
            0,
        )
        .unwrap_err();
        assert!(matches!(error, NetError::Cancelled));
    }

    #[test]
    fn posix_inspector_metadata_extracts_bounded_mode_owner_and_group() {
        let (permissions, owner, group) =
            posix_listing_metadata("-rwxr-x--- 1 deploy web 42 Jan 01 12:00 release.sh");
        assert_eq!(permissions, Some(0o750));
        assert_eq!(owner.as_deref(), Some("deploy"));
        assert_eq!(group.as_deref(), Some("web"));
        assert_eq!(
            posix_listing_metadata("type=file;size=42; release.sh").0,
            None
        );
        let entry = parse_listing_line("-rwxr-x--- 1 deploy web 42 Jan 01 12:00 release.sh")
            .unwrap()
            .unwrap();
        assert_eq!(entry.permissions, Some(0o750));
        assert_eq!(entry.owner.as_deref(), Some("deploy"));
        assert_eq!(entry.group.as_deref(), Some("web"));
    }

    fn test_source(bytes: &[u8]) -> (std::path::PathBuf, std::fs::File) {
        let path = std::env::temp_dir().join(format!(
            "gmacftp-upload-test-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::write(&path, bytes).unwrap();
        let file = std::fs::File::open(&path).unwrap();
        (path, file)
    }

    struct NoRemoteTouch {
        put_called: Arc<AtomicBool>,
    }

    impl FtpConn for NoRemoteTouch {
        fn cwd(&mut self, _path: &str) -> Result<(), FtpError> {
            panic!("remote connection must not be touched")
        }

        fn list_bounded(&mut self, _path: Option<&str>) -> Result<Listing, FtpError> {
            panic!("remote connection must not be touched")
        }

        fn make_dir(&mut self, _path: &str) -> Result<(), FtpError> {
            panic!("remote connection must not be touched")
        }

        fn remove_file(&mut self, _path: &str) -> Result<(), FtpError> {
            panic!("remote connection must not be touched")
        }

        fn remove_dir(&mut self, _path: &str) -> Result<(), FtpError> {
            panic!("remote connection must not be touched")
        }

        fn rename_path(&mut self, _from: &str, _to: &str) -> Result<(), FtpError> {
            panic!("remote connection must not be touched")
        }

        fn chmod(&mut self, _path: &str, _mode: u32) -> Result<(), FtpError> {
            panic!("remote connection must not be touched")
        }

        fn quit(&mut self) -> Result<(), FtpError> {
            Ok(())
        }

        fn retr_stream(&mut self, _path: &str) -> Result<Box<dyn Read>, FtpError> {
            panic!("remote connection must not be touched")
        }

        fn finalize_retr(&mut self, _stream: Box<dyn Read>) -> Result<(), FtpError> {
            panic!("remote connection must not be touched")
        }

        fn file_size(&mut self, _path: &str) -> Result<Option<usize>, FtpError> {
            panic!("remote connection must not be touched")
        }

        fn resume_transfer(&mut self, _offset: usize) -> Result<(), FtpError> {
            panic!("remote connection must not be touched")
        }

        fn put_stream(&mut self, _path: &str) -> Result<Box<dyn Write>, FtpError> {
            self.put_called.store(true, Ordering::Relaxed);
            panic!("STOR must not run for an unreadable local source")
        }

        fn finalize_put(&mut self, _writer: Box<dyn Write>) -> Result<(), FtpError> {
            panic!("remote connection must not be touched")
        }

        fn is_plaintext(&self) -> bool {
            false
        }
    }

    fn spec(allow_plaintext_ftp: bool) -> ConnectionSpec {
        ConnectionSpec {
            id: ConnectionId(0),
            name: "test".into(),
            protocol: Protocol::Ftp,
            host: "legacy.example.test".into(),
            port: 21,
            user: "alice".into(),
            initial_path: String::new(),
            group: String::new(),
            tags: Vec::new(),
            timeout_secs: None,
            keepalive_interval_secs: None,
            ftp_data_mode: Default::default(),
            ftp_filename_encoding: Default::default(),
            ftp_tls_mode: Default::default(),
            proxy_url: None,
            use_ssh_config: false,
            ssh_proxy_jump: None,
            allow_plaintext_ftp,
            accept_invalid_tls: false,
            tls_pinned_sha256: None,
            tls_client_cert: None,
            tls_client_key: None,
            sftp_auth: Default::default(),
            sftp_private_key: None,
            transfer_concurrency: None,
        }
    }

    #[test]
    fn plaintext_ftp_is_opt_in_for_each_connection() {
        assert!(!allow_plaintext_ftp(&spec(false)));
        assert!(allow_plaintext_ftp(&spec(true)));
        // This is deliberately not global state: selecting plaintext for one legacy server cannot
        // change the transport used by another server in the same process.
        assert!(!allow_plaintext_ftp(&spec(false)));
    }

    #[test]
    fn plaintext_only_mode_authenticates_without_an_auth_tls_probe() {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let commands = Arc::new(Mutex::new(Vec::<String>::new()));
        let recorded = commands.clone();
        let server = std::thread::spawn(move || loop {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            stream.write_all(b"220 test FTP ready\r\n").unwrap();
            stream.flush().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut quit = false;
            loop {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap() == 0 {
                    break;
                }
                let command = line.trim_end_matches(['\r', '\n']).to_string();
                recorded.lock().unwrap().push(command.clone());
                let response = if command.starts_with("USER ") {
                    "331 password required\r\n"
                } else if command.starts_with("PASS ") {
                    "230 logged in\r\n"
                } else if command == "TYPE I" || command == "OPTS UTF8 ON" {
                    "200 command accepted\r\n"
                } else if command == "AUTH TLS" {
                    // Keep this branch so a regression to the old probe-then-fallback behavior
                    // completes quickly and fails the command-order assertion below.
                    stream.write_all(b"500 TLS unavailable\r\n").unwrap();
                    stream.flush().unwrap();
                    break;
                } else if command == "QUIT" {
                    quit = true;
                    "221 goodbye\r\n"
                } else {
                    "500 unexpected command\r\n"
                };
                stream.write_all(response.as_bytes()).unwrap();
                stream.flush().unwrap();
                if quit {
                    break;
                }
            }
            if quit {
                break;
            }
        });

        let mut connection_spec = spec(true);
        connection_spec.host = address.ip().to_string();
        connection_spec.port = address.port();
        connection_spec.timeout_secs = Some(2);
        let mut connection = connect(&connection_spec, "test-password").unwrap();
        assert!(connection.is_plaintext());
        connection.quit().unwrap();
        server.join().unwrap();

        let commands = commands.lock().unwrap();
        assert!(commands
            .first()
            .is_some_and(|command| command == "USER alice"));
        assert!(commands.iter().all(|command| command != "AUTH TLS"));
    }

    #[test]
    fn implicit_relay_forwards_the_preconnected_socket_bidirectionally() {
        let server = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
        let server_address = server.local_addr().unwrap();
        let server_thread = std::thread::spawn(move || {
            let (mut stream, _) = server.accept().unwrap();
            let mut request = [0_u8; 4];
            stream.read_exact(&mut request).unwrap();
            assert_eq!(&request, b"ping");
            stream.write_all(b"pong").unwrap();
        });

        let upstream = TcpStream::connect(server_address).unwrap();
        let (relay_address, stop, handshake_complete) =
            start_implicit_relay(upstream, Duration::from_secs(2)).unwrap();
        assert!(relay_address.ip().is_loopback());
        let mut client = TcpStream::connect(relay_address).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        client
            .set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        handshake_complete.store(true, Ordering::Release);
        client.write_all(b"ping").unwrap();
        let mut response = [0_u8; 4];
        client.read_exact(&mut response).unwrap();
        assert_eq!(&response, b"pong");
        stop.store(true, Ordering::Release);
        let _ = client.shutdown(Shutdown::Both);
        server_thread.join().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn client_private_key_reader_rejects_broad_permissions_and_symlinks() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let directory = std::env::temp_dir().join(format!(
            "gmacftp-tls-identity-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        fs::create_dir(&directory).unwrap();
        let key = directory.join("client-key.pem");
        fs::write(&key, b"private material").unwrap();
        fs::set_permissions(&key, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(read_tls_identity_file(key.to_str().unwrap(), true).is_err());

        fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            read_tls_identity_file(key.to_str().unwrap(), true)
                .unwrap()
                .as_slice(),
            b"private material"
        );

        let link = directory.join("client-key-link.pem");
        symlink(&key, &link).unwrap();
        assert!(read_tls_identity_file(link.to_str().unwrap(), true).is_err());
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn certificate_pins_are_canonical_and_detect_leaf_changes() {
        let expected = certificate_fingerprint(b"expected certificate DER");
        assert_eq!(normalize_certificate_pin(&expected), Some(expected.clone()));
        assert_eq!(
            normalize_certificate_pin(expected.trim_start_matches("sha256:")),
            Some(expected.clone())
        );
        assert!(normalize_certificate_pin("sha256:abcd").is_none());

        let provider = suppaftp::rustls::crypto::ring::default_provider();
        let observed = Arc::new(Mutex::new(None));
        let verifier = CertificatePinVerifier {
            expected: Some(expected),
            observed: observed.clone(),
            signature_algorithms: provider.signature_verification_algorithms,
        };
        let certificate = CertificateDer::from(b"different certificate DER".to_vec());
        let server_name = ServerName::try_from("example.test".to_string()).unwrap();
        assert!(verifier
            .verify_server_cert(
                &certificate,
                &[],
                &server_name,
                &[],
                UnixTime::since_unix_epoch(std::time::Duration::ZERO),
            )
            .is_err());
        assert_eq!(
            observed.lock().unwrap().as_deref(),
            Some(certificate_fingerprint(certificate.as_ref()).as_str())
        );
    }

    #[test]
    fn upload_checks_local_source_before_remote_stor() {
        let put_called = Arc::new(AtomicBool::new(false));
        let mut session = TransferSession {
            connection: Box::new(NoRemoteTouch {
                put_called: put_called.clone(),
            }),
        };
        let missing = std::env::temp_dir().join(format!(
            "gmacftp-definitely-missing-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));

        assert!(session
            .upload(&missing, "/destination.bin", |_| {}, None)
            .is_err());
        assert!(!put_called.load(Ordering::Relaxed));
    }

    #[test]
    fn upload_replaces_only_after_complete_staged_transfer() {
        let destination = "/site/app.bin";
        let mut ftp = MemoryFtp::new(destination, b"old complete data");
        let expected = vec![0x5a; 128 * 1024 + 17];
        let (source, file) = test_source(&expected);

        let uploaded =
            upload_with_session(&mut ftp, file, destination, |_| {}, None, None).unwrap();
        let files = ftp.files.lock().unwrap();
        assert_eq!(uploaded, expected.len() as u64);
        assert_eq!(files.get(destination), Some(&expected));
        assert_eq!(files.len(), 1, "temporary and backup files must be removed");
        drop(files);
        let _ = std::fs::remove_file(source);
    }

    #[test]
    fn failed_upload_keeps_destination_and_removes_partial_stage() {
        let destination = "/site/app.bin";
        let mut ftp = MemoryFtp::new(destination, b"old complete data");
        ftp.bytes_before_failure = Some(70_000);
        let expected = vec![0x7b; 128 * 1024];
        let (source, file) = test_source(&expected);

        assert!(upload_with_session(&mut ftp, file, destination, |_| {}, None, None).is_err());
        let files = ftp.files.lock().unwrap();
        assert_eq!(
            files.get(destination).map(Vec::as_slice),
            Some(&b"old complete data"[..])
        );
        assert_eq!(files.len(), 1, "partial staging file must be removed");
        drop(files);
        let _ = std::fs::remove_file(source);
    }

    #[test]
    fn resumable_ftp_upload_preserves_then_appends_private_stage() {
        let destination = "/site/app.bin";
        let mut ftp = MemoryFtp::new(destination, b"old complete data");
        ftp.bytes_before_failure = Some(70_000);
        let expected = vec![0x31; 192 * 1024 + 23];
        let (source, first_file) = test_source(&expected);
        let resume = UploadResume {
            token: 42,
            expected_total: expected.len() as u64,
            expected_modified_unix_nanos: 1,
        };

        assert!(upload_with_session(
            &mut ftp,
            first_file,
            destination,
            |_| {},
            None,
            Some(resume),
        )
        .is_err());
        let staging =
            RemoteStagingPaths::for_resumable_destination(destination, resume.token).unwrap();
        assert_eq!(
            ftp.files
                .lock()
                .unwrap()
                .get(destination)
                .map(Vec::as_slice),
            Some(&b"old complete data"[..])
        );
        assert_eq!(
            ftp.files
                .lock()
                .unwrap()
                .get(&staging.temporary)
                .map(Vec::len),
            Some(70_000)
        );

        ftp.bytes_before_failure = None;
        let second_file = std::fs::File::open(&source).unwrap();
        let first_progress = Arc::new(Mutex::new(None));
        let captured = first_progress.clone();
        let uploaded = upload_with_session(
            &mut ftp,
            second_file,
            destination,
            move |done| {
                captured.lock().unwrap().get_or_insert(done);
            },
            None,
            Some(resume),
        )
        .unwrap();
        assert_eq!(*first_progress.lock().unwrap(), Some(70_000));
        assert_eq!(uploaded, expected.len() as u64);
        let files = ftp.files.lock().unwrap();
        assert_eq!(files.get(destination), Some(&expected));
        assert_eq!(files.len(), 1);
        drop(files);
        let _ = std::fs::remove_file(source);
    }

    #[test]
    fn resumable_upload_rejects_a_changed_local_source_before_remote_io() {
        let destination = "/site/app.bin";
        let ftp = MemoryFtp::new(destination, b"old complete data");
        let (source, _) = test_source(b"new data");
        let mut session = TransferSession {
            connection: Box::new(ftp),
        };
        let result = session.upload_resumable(
            &source,
            destination,
            |_| {},
            None,
            Some(UploadResume {
                token: 9,
                expected_total: 8,
                expected_modified_unix_nanos: 0,
            }),
        );
        assert!(matches!(result, Err(NetError::UploadSourceChanged)));
        let _ = std::fs::remove_file(source);
    }

    #[test]
    fn failed_ftp_promotion_rolls_previous_destination_back() {
        let destination = "/site/app.bin";
        let mut ftp = MemoryFtp::new(destination, b"old complete data");
        ftp.fail_second_promotion = true;
        let (source, file) = test_source(b"new complete data");

        assert!(upload_with_session(&mut ftp, file, destination, |_| {}, None, None).is_err());
        let files = ftp.files.lock().unwrap();
        assert_eq!(
            files.get(destination).map(Vec::as_slice),
            Some(&b"old complete data"[..])
        );
        assert_eq!(files.len(), 1, "rollback must clean every staging path");
        drop(files);
        let _ = std::fs::remove_file(source);
    }

    #[test]
    fn ftp_checksum_streams_the_complete_remote_file() {
        let destination = "/site/app.bin";
        let expected = vec![0xa7; 128 * 1024 + 19];
        let mut ftp = MemoryFtp::new(destination, &expected);
        let actual = hash_file_with_session(&mut ftp, destination).unwrap();
        let reference: [u8; 32] = Sha256::digest(&expected).into();
        assert_eq!(actual, reference);
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
}
