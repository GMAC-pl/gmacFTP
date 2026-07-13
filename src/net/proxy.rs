//! Bounded, credential-free HTTP CONNECT and SOCKS5 tunnels.
//!
//! Connection metadata may contain only `http://host:port` or `socks5://host:port`. Userinfo is
//! rejected so a password can never leak into `connections.json`, settings export, diagnostics or
//! sync. SOCKS5 uses remote DNS for host names; HTTP CONNECT sends only the target authority.

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv6Addr, TcpStream, ToSocketAddrs};
use std::time::Duration;

const MAX_PROXY_HOST_BYTES: usize = 253;
const MAX_TARGET_HOST_BYTES: usize = 255;
const MAX_HTTP_RESPONSE_HEADER_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProxyKind {
    HttpConnect,
    Socks5,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProxyEndpoint {
    kind: ProxyKind,
    host: String,
    port: u16,
}

fn invalid(message: impl Into<String>) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidInput, message.into())
}

fn proxy_failure(kind: std::io::ErrorKind, message: impl Into<String>) -> std::io::Error {
    std::io::Error::new(kind, message.into())
}

fn parse_proxy_url(value: &str) -> Result<ProxyEndpoint, String> {
    let value = value.trim();
    if value.is_empty() {
        return Err("proxy URL is empty".into());
    }
    if value.len() > 512 || value.chars().any(char::is_control) {
        return Err("proxy URL is too long or contains control characters".into());
    }
    let (scheme, authority) = value
        .split_once("://")
        .ok_or_else(|| "proxy URL must start with http:// or socks5://".to_string())?;
    let kind = match scheme.to_ascii_lowercase().as_str() {
        "http" => ProxyKind::HttpConnect,
        "socks5" => ProxyKind::Socks5,
        _ => return Err("only http:// and socks5:// proxies are supported".into()),
    };
    if authority.contains('@') {
        return Err("proxy credentials in URLs are not allowed".into());
    }
    if authority
        .bytes()
        .any(|byte| byte.is_ascii_whitespace() || matches!(byte, b'/' | b'?' | b'#'))
    {
        return Err("proxy URL must contain only a host and port".into());
    }

    let (host, port_text) = if let Some(bracketed) = authority.strip_prefix('[') {
        let (host, rest) = bracketed
            .split_once(']')
            .ok_or_else(|| "proxy IPv6 address is missing a closing bracket".to_string())?;
        let port = rest
            .strip_prefix(':')
            .ok_or_else(|| "proxy URL is missing a port".to_string())?;
        if host.parse::<Ipv6Addr>().is_err() {
            return Err("bracketed proxy host is not a valid IPv6 address".into());
        }
        (host, port)
    } else {
        let (host, port) = authority
            .rsplit_once(':')
            .ok_or_else(|| "proxy URL is missing a port".to_string())?;
        if host.contains(':') {
            return Err("proxy IPv6 addresses must be enclosed in brackets".into());
        }
        (host, port)
    };
    if host.is_empty()
        || host.len() > MAX_PROXY_HOST_BYTES
        || host
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return Err("proxy host is empty, too long, or invalid".into());
    }
    let port = port_text
        .parse::<u16>()
        .ok()
        .filter(|port| *port != 0)
        .ok_or_else(|| "proxy port must be between 1 and 65535".to_string())?;

    Ok(ProxyEndpoint {
        kind,
        host: host.to_string(),
        port,
    })
}

/// Validate a persisted proxy setting without opening a socket.
pub fn validate_proxy_url(value: &str) -> Result<(), String> {
    parse_proxy_url(value).map(|_| ())
}

fn validate_target(host: &str, port: u16) -> std::io::Result<()> {
    if port == 0 {
        return Err(invalid("proxy target port must not be zero"));
    }
    if host.is_empty()
        || host.len() > MAX_TARGET_HOST_BYTES
        || host.bytes().any(|byte| {
            byte.is_ascii_control()
                || byte.is_ascii_whitespace()
                || matches!(byte, b'[' | b']' | b'/' | b'@')
        })
    {
        return Err(invalid("proxy target host is empty, too long, or invalid"));
    }
    Ok(())
}

fn connect_endpoint(endpoint: &ProxyEndpoint, timeout: Duration) -> std::io::Result<TcpStream> {
    let addresses = (endpoint.host.as_str(), endpoint.port).to_socket_addrs()?;
    let mut last_error = None;
    for address in addresses {
        match TcpStream::connect_timeout(&address, timeout) {
            Ok(stream) => {
                stream.set_read_timeout(Some(timeout))?;
                stream.set_write_timeout(Some(timeout))?;
                stream.set_nodelay(true)?;
                return Ok(stream);
            }
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or_else(|| {
        proxy_failure(
            std::io::ErrorKind::NotFound,
            "proxy host resolved to no addresses",
        )
    }))
}

fn authority(host: &str, port: u16) -> String {
    if host.parse::<Ipv6Addr>().is_ok() {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

fn http_connect(
    stream: &mut TcpStream,
    target_host: &str,
    target_port: u16,
) -> std::io::Result<()> {
    let target = authority(target_host, target_port);
    write!(
        stream,
        "CONNECT {target} HTTP/1.1\r\nHost: {target}\r\nProxy-Connection: keep-alive\r\n\r\n"
    )?;
    stream.flush()?;

    // Read only through the header terminator. A buffered reader could consume initial bytes from
    // the tunneled SSH/FTP server and make the following protocol handshake fail nondeterministically.
    let mut header = Vec::with_capacity(256);
    let mut byte = [0_u8; 1];
    while header.len() < MAX_HTTP_RESPONSE_HEADER_BYTES {
        stream.read_exact(&mut byte)?;
        header.push(byte[0]);
        if header.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    if !header.ends_with(b"\r\n\r\n") {
        return Err(proxy_failure(
            std::io::ErrorKind::InvalidData,
            "HTTP proxy response headers exceed 16 KiB",
        ));
    }
    let header = std::str::from_utf8(&header).map_err(|_| {
        proxy_failure(
            std::io::ErrorKind::InvalidData,
            "HTTP proxy returned non-UTF-8 response headers",
        )
    })?;
    let status = header.lines().next().unwrap_or_default();
    let mut parts = status.split_whitespace();
    let version = parts.next().unwrap_or_default();
    let code = parts.next().and_then(|value| value.parse::<u16>().ok());
    if !matches!(version, "HTTP/1.0" | "HTTP/1.1") || code.is_none() {
        return Err(proxy_failure(
            std::io::ErrorKind::InvalidData,
            "HTTP proxy returned a malformed status line",
        ));
    }
    match code.expect("checked above") {
        200 => Ok(()),
        407 => Err(proxy_failure(
            std::io::ErrorKind::PermissionDenied,
            "HTTP proxy requires authentication; credentials in connection metadata are intentionally unsupported",
        )),
        code => Err(proxy_failure(
            std::io::ErrorKind::ConnectionRefused,
            format!("HTTP proxy refused the tunnel (status {code})"),
        )),
    }
}

fn socks5_connect(
    stream: &mut TcpStream,
    target_host: &str,
    target_port: u16,
) -> std::io::Result<()> {
    stream.write_all(&[5, 1, 0])?;
    let mut greeting = [0_u8; 2];
    stream.read_exact(&mut greeting)?;
    match greeting {
        [5, 0] => {}
        [5, 0xff] => {
            return Err(proxy_failure(
                std::io::ErrorKind::PermissionDenied,
                "SOCKS5 proxy does not allow unauthenticated connections",
            ));
        }
        _ => {
            return Err(proxy_failure(
                std::io::ErrorKind::InvalidData,
                "SOCKS5 proxy returned an invalid greeting",
            ));
        }
    }

    let mut request = Vec::with_capacity(target_host.len() + 10);
    request.extend_from_slice(&[5, 1, 0]);
    if let Ok(ip) = target_host.parse::<IpAddr>() {
        match ip {
            IpAddr::V4(ip) => {
                request.push(1);
                request.extend_from_slice(&ip.octets());
            }
            IpAddr::V6(ip) => {
                request.push(4);
                request.extend_from_slice(&ip.octets());
            }
        }
    } else {
        let length = u8::try_from(target_host.len())
            .map_err(|_| invalid("SOCKS5 target host exceeds 255 bytes"))?;
        request.extend_from_slice(&[3, length]);
        request.extend_from_slice(target_host.as_bytes());
    }
    request.extend_from_slice(&target_port.to_be_bytes());
    stream.write_all(&request)?;

    let mut reply = [0_u8; 4];
    stream.read_exact(&mut reply)?;
    if reply[0] != 5 || reply[2] != 0 {
        return Err(proxy_failure(
            std::io::ErrorKind::InvalidData,
            "SOCKS5 proxy returned a malformed reply",
        ));
    }
    if reply[1] != 0 {
        return Err(proxy_failure(
            std::io::ErrorKind::ConnectionRefused,
            format!("SOCKS5 proxy refused the tunnel (reply {})", reply[1]),
        ));
    }
    let address_len = match reply[3] {
        1 => 4,
        4 => 16,
        3 => {
            let mut length = [0_u8; 1];
            stream.read_exact(&mut length)?;
            usize::from(length[0])
        }
        _ => {
            return Err(proxy_failure(
                std::io::ErrorKind::InvalidData,
                "SOCKS5 proxy returned an invalid bound-address type",
            ));
        }
    };
    let mut remainder = vec![0_u8; address_len + 2];
    stream.read_exact(&mut remainder)?;
    Ok(())
}

/// Open a bounded TCP tunnel through a validated HTTP CONNECT or SOCKS5 proxy.
pub(crate) fn connect_tunnel(
    proxy_url: &str,
    target_host: &str,
    target_port: u16,
    timeout: Duration,
) -> std::io::Result<TcpStream> {
    validate_target(target_host, target_port)?;
    let endpoint = parse_proxy_url(proxy_url).map_err(invalid)?;
    let mut stream = connect_endpoint(&endpoint, timeout)?;
    match endpoint.kind {
        ProxyKind::HttpConnect => http_connect(&mut stream, target_host, target_port)?,
        ProxyKind::Socks5 => socks5_connect(&mut stream, target_host, target_port)?,
    }
    Ok(stream)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, TcpListener};

    #[test]
    fn proxy_url_validation_rejects_credentials_paths_and_unsafe_schemes() {
        assert!(validate_proxy_url("http://proxy.example:8080").is_ok());
        assert!(validate_proxy_url("socks5://[::1]:1080").is_ok());
        let proxy_with_credentials =
            ["http://", "user", ":", "pass", "@proxy.example:8080"].concat();
        assert!(validate_proxy_url(&proxy_with_credentials).is_err());
        assert!(validate_proxy_url("https://proxy.example:443").is_err());
        assert!(validate_proxy_url("http://proxy.example:8080/path").is_err());
        assert!(validate_proxy_url("http://proxy.example:0").is_err());
        assert!(validate_proxy_url("http://proxy.example:8080\r\nInjected: yes").is_err());
    }

    #[test]
    fn http_connect_does_not_overread_tunneled_bytes() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut byte = [0_u8; 1];
            while !request.ends_with(b"\r\n\r\n") {
                socket.read_exact(&mut byte).unwrap();
                request.push(byte[0]);
            }
            let request = String::from_utf8(request).unwrap();
            assert!(request.starts_with("CONNECT files.example:22 HTTP/1.1\r\n"));
            socket.write_all(b"HTTP/1.1 200 OK\r\n\r\nSSH-").unwrap();
            let mut ping = [0_u8; 4];
            socket.read_exact(&mut ping).unwrap();
            assert_eq!(&ping, b"ping");
        });

        let mut stream = connect_tunnel(
            &format!("http://{address}"),
            "files.example",
            22,
            Duration::from_secs(2),
        )
        .unwrap();
        let mut banner = [0_u8; 4];
        stream.read_exact(&mut banner).unwrap();
        assert_eq!(&banner, b"SSH-");
        stream.write_all(b"ping").unwrap();
        server.join().unwrap();
    }

    #[test]
    fn socks5_uses_remote_dns_and_completes_the_bounded_reply() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().unwrap();
            let mut greeting = [0_u8; 3];
            socket.read_exact(&mut greeting).unwrap();
            assert_eq!(greeting, [5, 1, 0]);
            socket.write_all(&[5, 0]).unwrap();
            let mut prefix = [0_u8; 5];
            socket.read_exact(&mut prefix).unwrap();
            assert_eq!(&prefix[..4], &[5, 1, 0, 3]);
            let mut host = vec![0_u8; usize::from(prefix[4])];
            socket.read_exact(&mut host).unwrap();
            assert_eq!(&host, b"private.example");
            let mut port = [0_u8; 2];
            socket.read_exact(&mut port).unwrap();
            assert_eq!(u16::from_be_bytes(port), 2222);
            socket
                .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0x12, 0x34])
                .unwrap();
            socket.write_all(b"ready").unwrap();
        });

        let mut stream = connect_tunnel(
            &format!("socks5://{address}"),
            "private.example",
            2222,
            Duration::from_secs(2),
        )
        .unwrap();
        let mut ready = [0_u8; 5];
        stream.read_exact(&mut ready).unwrap();
        assert_eq!(&ready, b"ready");
        server.join().unwrap();
    }
}
