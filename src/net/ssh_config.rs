//! Restricted, non-executing OpenSSH client-config resolution for SFTP.
//!
//! The parser is used only for declarative host aliases. `ProxyCommand`, `Match`, and `Include`
//! are rejected: the application never launches config-supplied commands, and it does not follow
//! an unbounded include graph. Host keys remain pinned by the resolved endpoint in gmacFTP's own
//! `known_hosts` file.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::model::{ConnectionSpec, SftpAuth};
use crate::net::error::NetError;

const MAX_SSH_CONFIG_BYTES: u64 = 1024 * 1024;
const MAX_SSH_HOST_BYTES: usize = 253;
const MAX_SSH_USER_BYTES: usize = 256;
const MAX_SSH_CONFIG_SECTIONS: usize = 4096;
const MAX_SSH_CONFIG_TOKENS_PER_LINE: usize = 128;
const MAX_SSH_IDENTITY_FILES: usize = 64;

#[derive(Debug, Clone, Default)]
struct HostParams {
    host_name: Option<String>,
    user: Option<String>,
    port: Option<u16>,
    identity_file: Option<Vec<PathBuf>>,
    proxy_jump: Option<Vec<String>>,
    connect_timeout: Option<Duration>,
    server_alive_interval: Option<Duration>,
    proxy_command: bool,
}

impl HostParams {
    fn merge_first(&mut self, other: &Self) {
        if self.host_name.is_none() {
            self.host_name.clone_from(&other.host_name);
        }
        if self.user.is_none() {
            self.user.clone_from(&other.user);
        }
        if self.port.is_none() {
            self.port = other.port;
        }
        if self.proxy_jump.is_none() {
            self.proxy_jump.clone_from(&other.proxy_jump);
        }
        if self.connect_timeout.is_none() {
            self.connect_timeout = other.connect_timeout;
        }
        if self.server_alive_interval.is_none() {
            self.server_alive_interval = other.server_alive_interval;
        }
        self.proxy_command |= other.proxy_command;
        if let Some(paths) = other.identity_file.as_ref() {
            let identities = self.identity_file.get_or_insert_with(Vec::new);
            for path in paths {
                if identities.len() >= MAX_SSH_IDENTITY_FILES {
                    break;
                }
                identities.push(path.clone());
            }
        }
    }
}

#[derive(Debug, Clone)]
struct HostBlock {
    patterns: Vec<String>,
    params: HostParams,
}

#[derive(Debug, Clone, Default)]
struct SshConfig {
    global: HostParams,
    hosts: Vec<HostBlock>,
}

impl SshConfig {
    fn query(&self, alias: &str) -> HostParams {
        let mut params = HostParams::default();
        params.merge_first(&self.global);
        for host in &self.hosts {
            if host_matches(&host.patterns, alias) {
                params.merge_first(&host.params);
            }
        }
        params
    }
}

#[derive(Debug, Clone)]
pub(crate) struct SshEndpoint {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub identity_files: Vec<PathBuf>,
    pub connect_timeout: Duration,
    pub keepalive_interval: Option<Duration>,
}

#[derive(Debug, Clone)]
pub(crate) struct ResolvedSshConnection {
    pub target: SshEndpoint,
    pub jump: Option<SshEndpoint>,
}

#[derive(Debug, Clone)]
struct JumpReference {
    alias: String,
    user: Option<String>,
    port: Option<u16>,
}

fn ssh_error(message: impl Into<String>) -> NetError {
    NetError::Ssh(message.into())
}

fn tokenize_config_line(line: &str, line_number: usize) -> Result<Vec<String>, NetError> {
    let mut tokens = Vec::new();
    let mut token = String::new();
    let mut quote = None;
    let mut escaped = false;
    for character in line.chars() {
        if escaped {
            token.push(character);
            escaped = false;
            continue;
        }
        if character == '\\' {
            escaped = true;
            continue;
        }
        if let Some(delimiter) = quote {
            if character == delimiter {
                quote = None;
            } else {
                token.push(character);
            }
            continue;
        }
        match character {
            '#' => break,
            '\'' | '"' => quote = Some(character),
            '=' if tokens.is_empty() && !token.is_empty() => {
                tokens.push(std::mem::take(&mut token));
            }
            '=' if tokens.len() == 1 && token.is_empty() => {}
            character if character.is_ascii_whitespace() => {
                if !token.is_empty() {
                    tokens.push(std::mem::take(&mut token));
                }
            }
            character => token.push(character),
        }
        if tokens.len() > MAX_SSH_CONFIG_TOKENS_PER_LINE || token.len() > 4096 {
            return Err(ssh_error(format!(
                "~/.ssh/config line {line_number} exceeds a safety limit"
            )));
        }
    }
    if escaped || quote.is_some() {
        return Err(ssh_error(format!(
            "~/.ssh/config line {line_number} has an unfinished escape or quote"
        )));
    }
    if !token.is_empty() {
        tokens.push(token);
    }
    if tokens.len() > MAX_SSH_CONFIG_TOKENS_PER_LINE {
        return Err(ssh_error(format!(
            "~/.ssh/config line {line_number} has too many fields"
        )));
    }
    Ok(tokens)
}

fn wildcard_matches(pattern: &str, value: &str) -> bool {
    let pattern = pattern.as_bytes();
    let value = value.as_bytes();
    let mut previous = vec![false; value.len() + 1];
    previous[0] = true;
    for pattern_byte in pattern {
        let mut current = vec![false; value.len() + 1];
        if *pattern_byte == b'*' {
            current[0] = previous[0];
            for index in 1..=value.len() {
                current[index] = previous[index] || current[index - 1];
            }
        } else {
            for index in 1..=value.len() {
                current[index] = previous[index - 1]
                    && (*pattern_byte == b'?' || *pattern_byte == value[index - 1]);
            }
        }
        previous = current;
    }
    previous[value.len()]
}

fn host_matches(patterns: &[String], alias: &str) -> bool {
    let alias = alias.to_ascii_lowercase();
    let mut positive = false;
    for pattern in patterns {
        let (negated, pattern) = pattern
            .strip_prefix('!')
            .map_or((false, pattern.as_str()), |pattern| (true, pattern));
        let pattern = pattern.to_ascii_lowercase();
        if wildcard_matches(&pattern, &alias) {
            if negated {
                return false;
            }
            positive = true;
        }
    }
    positive
}

fn set_first<T>(slot: &mut Option<T>, value: T) {
    if slot.is_none() {
        *slot = Some(value);
    }
}

fn one_argument<'a>(
    arguments: &'a [String],
    field: &str,
    line_number: usize,
) -> Result<&'a str, NetError> {
    if arguments.len() != 1 {
        return Err(ssh_error(format!(
            "~/.ssh/config {field} on line {line_number} needs exactly one value"
        )));
    }
    Ok(arguments[0].as_str())
}

fn parse_config_text(text: &str) -> Result<SshConfig, NetError> {
    if text.as_bytes().contains(&0) {
        return Err(ssh_error("~/.ssh/config contains NUL"));
    }
    let mut config = SshConfig::default();
    let mut current_host = None;
    for (index, line) in text.lines().enumerate() {
        let line_number = index + 1;
        let tokens = tokenize_config_line(line, line_number)?;
        let Some((field, arguments)) = tokens.split_first() else {
            continue;
        };
        let field = field.to_ascii_lowercase();
        if field == "host" {
            if arguments.is_empty() {
                return Err(ssh_error(format!(
                    "~/.ssh/config Host on line {line_number} has no patterns"
                )));
            }
            if config.hosts.len() >= MAX_SSH_CONFIG_SECTIONS {
                return Err(ssh_error("~/.ssh/config has too many Host sections"));
            }
            for pattern in arguments {
                let pattern = pattern.strip_prefix('!').unwrap_or(pattern);
                if pattern.is_empty()
                    || pattern.len() > MAX_SSH_HOST_BYTES
                    || pattern.bytes().any(|byte| {
                        byte.is_ascii_control()
                            || byte.is_ascii_whitespace()
                            || matches!(byte, b'/' | b'@' | b'[' | b']')
                    })
                {
                    return Err(ssh_error(format!(
                        "~/.ssh/config Host pattern on line {line_number} is invalid"
                    )));
                }
            }
            config.hosts.push(HostBlock {
                patterns: arguments.to_vec(),
                params: HostParams::default(),
            });
            current_host = Some(config.hosts.len() - 1);
            continue;
        }
        let params = current_host
            .map(|index| &mut config.hosts[index].params)
            .unwrap_or(&mut config.global);
        match field.as_str() {
            "include" => {
                return Err(ssh_error(
                    "SSH config Include is not supported; merge the required Host block into ~/.ssh/config",
                ));
            }
            "match" => {
                return Err(ssh_error(
                    "SSH config Match blocks are not supported because their conditions may execute commands",
                ));
            }
            "hostname" => set_first(
                &mut params.host_name,
                one_argument(arguments, "HostName", line_number)?.to_string(),
            ),
            "user" => set_first(
                &mut params.user,
                one_argument(arguments, "User", line_number)?.to_string(),
            ),
            "port" => {
                let port = one_argument(arguments, "Port", line_number)?
                    .parse::<u16>()
                    .ok()
                    .filter(|port| *port != 0)
                    .ok_or_else(|| {
                        ssh_error(format!(
                            "~/.ssh/config Port on line {line_number} must be 1–65535"
                        ))
                    })?;
                set_first(&mut params.port, port);
            }
            "identityfile" => {
                if arguments.is_empty() {
                    return Err(ssh_error(format!(
                        "~/.ssh/config IdentityFile on line {line_number} has no path"
                    )));
                }
                let identities = params.identity_file.get_or_insert_with(Vec::new);
                if identities.len().saturating_add(arguments.len()) > MAX_SSH_IDENTITY_FILES {
                    return Err(ssh_error(
                        "~/.ssh/config contains more than 64 matching IdentityFile entries",
                    ));
                }
                identities.extend(arguments.iter().map(PathBuf::from));
            }
            "connecttimeout" => {
                let seconds = one_argument(arguments, "ConnectTimeout", line_number)?
                    .parse::<u64>()
                    .map_err(|_| {
                        ssh_error(format!(
                            "~/.ssh/config ConnectTimeout on line {line_number} is invalid"
                        ))
                    })?;
                set_first(&mut params.connect_timeout, Duration::from_secs(seconds));
            }
            "serveraliveinterval" => {
                let seconds = one_argument(arguments, "ServerAliveInterval", line_number)?
                    .parse::<u64>()
                    .map_err(|_| {
                        ssh_error(format!(
                            "~/.ssh/config ServerAliveInterval on line {line_number} is invalid"
                        ))
                    })?;
                set_first(
                    &mut params.server_alive_interval,
                    Duration::from_secs(seconds),
                );
            }
            "proxyjump" => set_first(
                &mut params.proxy_jump,
                vec![one_argument(arguments, "ProxyJump", line_number)?.to_string()],
            ),
            "proxycommand"
                if !arguments
                    .first()
                    .is_some_and(|value| value.eq_ignore_ascii_case("none")) =>
            {
                params.proxy_command = true;
            }
            _ => {}
        }
    }
    Ok(config)
}

fn read_bounded_config(path: &Path) -> Result<String, NetError> {
    let file = std::fs::File::open(path)
        .map_err(|error| ssh_error(format!("could not open ~/.ssh/config: {error}")))?;
    let metadata = file
        .metadata()
        .map_err(|error| ssh_error(format!("could not inspect ~/.ssh/config: {error}")))?;
    if !metadata.is_file() || metadata.len() > MAX_SSH_CONFIG_BYTES {
        return Err(ssh_error(
            "~/.ssh/config must be a regular file no larger than 1 MiB",
        ));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_SSH_CONFIG_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| ssh_error(format!("could not read ~/.ssh/config: {error}")))?;
    if bytes.len() as u64 > MAX_SSH_CONFIG_BYTES {
        return Err(ssh_error("~/.ssh/config exceeds 1 MiB"));
    }
    String::from_utf8(bytes).map_err(|_| ssh_error("~/.ssh/config must contain valid UTF-8 text"))
}

fn default_config_path() -> Result<PathBuf, NetError> {
    directories::BaseDirs::new()
        .map(|base| base.home_dir().join(".ssh/config"))
        .ok_or_else(|| ssh_error("home directory is unavailable"))
}

fn load_config(required: bool) -> Result<Option<SshConfig>, NetError> {
    let path = default_config_path()?;
    match read_bounded_config(&path) {
        Ok(text) => parse_config_text(&text).map(Some),
        Err(NetError::Ssh(message))
            if !required
                && std::fs::symlink_metadata(&path)
                    .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound) =>
        {
            let _ = message;
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

fn validate_host(host: String, label: &str) -> Result<String, NetError> {
    if host.is_empty()
        || host.len() > MAX_SSH_HOST_BYTES
        || host.contains('%')
        || host.bytes().any(|byte| {
            byte.is_ascii_control()
                || byte.is_ascii_whitespace()
                || matches!(byte, b'/' | b'@' | b'[' | b']')
        })
    {
        return Err(ssh_error(format!("{label} resolves to an invalid host")));
    }
    Ok(host)
}

fn validate_user(user: String, label: &str) -> Result<String, NetError> {
    if user.is_empty()
        || user.len() > MAX_SSH_USER_BYTES
        || user.bytes().any(|byte| {
            byte.is_ascii_control() || byte.is_ascii_whitespace() || matches!(byte, b'@' | b':')
        })
    {
        return Err(ssh_error(format!("{label} resolves to an invalid user")));
    }
    Ok(user)
}

fn has_proxy_command(params: &HostParams) -> bool {
    params.proxy_command
}

fn safe_timeout(explicit: Option<u64>, configured: Option<Duration>) -> Result<Duration, NetError> {
    let seconds = explicit
        .or_else(|| configured.map(|duration| duration.as_secs()))
        .unwrap_or(20);
    if !(crate::store::connections::MIN_CONNECTION_TIMEOUT_SECS
        ..=crate::store::connections::MAX_CONNECTION_TIMEOUT_SECS)
        .contains(&seconds)
    {
        return Err(ssh_error(format!(
            "SSH ConnectTimeout must be {}–{} seconds",
            crate::store::connections::MIN_CONNECTION_TIMEOUT_SECS,
            crate::store::connections::MAX_CONNECTION_TIMEOUT_SECS
        )));
    }
    Ok(Duration::from_secs(seconds))
}

fn safe_keepalive(
    explicit: Option<u64>,
    configured: Option<Duration>,
) -> Result<Option<Duration>, NetError> {
    let seconds = explicit.or_else(|| configured.map(|duration| duration.as_secs()));
    let Some(seconds) = seconds else {
        return Ok(Some(Duration::from_secs(20)));
    };
    if seconds == 0 {
        return Ok(None);
    }
    if !(crate::store::connections::MIN_KEEPALIVE_INTERVAL_SECS
        ..=crate::store::connections::MAX_KEEPALIVE_INTERVAL_SECS)
        .contains(&seconds)
    {
        return Err(ssh_error(format!(
            "SSH ServerAliveInterval must be 0 or {}–{} seconds",
            crate::store::connections::MIN_KEEPALIVE_INTERVAL_SECS,
            crate::store::connections::MAX_KEEPALIVE_INTERVAL_SECS
        )));
    }
    Ok(Some(Duration::from_secs(seconds)))
}

fn expand_identity_path(
    path: &Path,
    alias: &str,
    host: &str,
    user: &str,
) -> Result<PathBuf, NetError> {
    let raw = path
        .to_str()
        .ok_or_else(|| ssh_error("SSH IdentityFile path is not valid UTF-8"))?;
    if raw.len() > 4096 || raw.chars().any(char::is_control) {
        return Err(ssh_error("SSH IdentityFile path is invalid or too long"));
    }
    let base =
        directories::BaseDirs::new().ok_or_else(|| ssh_error("home directory unavailable"))?;
    let home = base.home_dir().to_string_lossy();
    let local_user = std::env::var("USER").unwrap_or_default();
    let mut expanded = String::with_capacity(raw.len());
    let mut chars = raw.chars();
    while let Some(character) = chars.next() {
        if character != '%' {
            expanded.push(character);
            continue;
        }
        let token = chars
            .next()
            .ok_or_else(|| ssh_error("SSH IdentityFile ends with an incomplete % token"))?;
        match token {
            '%' => expanded.push('%'),
            'd' => expanded.push_str(&home),
            'h' => expanded.push_str(host),
            'n' => expanded.push_str(alias),
            'r' => expanded.push_str(user),
            'u' if !local_user.is_empty() => expanded.push_str(&local_user),
            _ => {
                return Err(ssh_error(format!(
                    "SSH IdentityFile uses unsupported token %{token}"
                )));
            }
        }
    }
    let expanded = PathBuf::from(expanded);
    Ok(if expanded.is_absolute() {
        expanded
    } else {
        base.home_dir().join(".ssh").join(expanded)
    })
}

fn identities(
    params: Option<&HostParams>,
    alias: &str,
    host: &str,
    user: &str,
) -> Result<Vec<PathBuf>, NetError> {
    params
        .and_then(|params| params.identity_file.as_ref())
        .into_iter()
        .flatten()
        .map(|path| expand_identity_path(path, alias, host, user))
        .collect()
}

fn parse_jump_reference(value: &str) -> Result<Option<JumpReference>, NetError> {
    let value = value.trim();
    if value.eq_ignore_ascii_case("none") {
        return Ok(None);
    }
    if value.is_empty()
        || value.len() > 512
        || value.contains(',')
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return Err(ssh_error(
            "ProxyJump must contain exactly one [user@]host[:port] entry",
        ));
    }
    let value = value.strip_prefix("ssh://").unwrap_or(value);
    if value.contains('/') || value.contains('?') || value.contains('#') {
        return Err(ssh_error("ProxyJump URI contains unsupported components"));
    }
    let (user, authority) = value
        .rsplit_once('@')
        .map_or((None, value), |(user, authority)| (Some(user), authority));
    let user = user
        .map(|user| validate_user(user.to_string(), "ProxyJump"))
        .transpose()?;
    let (alias, port) = if let Some(bracketed) = authority.strip_prefix('[') {
        let (host, rest) = bracketed
            .split_once(']')
            .ok_or_else(|| ssh_error("ProxyJump IPv6 address is missing ]"))?;
        if host.parse::<std::net::Ipv6Addr>().is_err() {
            return Err(ssh_error("ProxyJump bracketed host is not valid IPv6"));
        }
        let port = if rest.is_empty() {
            None
        } else {
            Some(
                rest.strip_prefix(':')
                    .and_then(|value| value.parse::<u16>().ok())
                    .filter(|port| *port != 0)
                    .ok_or_else(|| ssh_error("ProxyJump port must be 1–65535"))?,
            )
        };
        (host.to_string(), port)
    } else if authority.matches(':').count() == 1 {
        let (host, port) = authority
            .rsplit_once(':')
            .expect("one colon was counted above");
        let port = port
            .parse::<u16>()
            .ok()
            .filter(|port| *port != 0)
            .ok_or_else(|| ssh_error("ProxyJump port must be 1–65535"))?;
        (host.to_string(), Some(port))
    } else if authority.contains(':') {
        return Err(ssh_error(
            "ProxyJump IPv6 addresses must be enclosed in brackets",
        ));
    } else {
        (authority.to_string(), None)
    };
    let alias = validate_host(alias, "ProxyJump")?;
    Ok(Some(JumpReference { alias, user, port }))
}

pub(crate) fn validate_jump_reference(value: &str) -> Result<(), String> {
    parse_jump_reference(value)
        .map(|_| ())
        .map_err(|error| error.to_string())
}

fn resolve_with_config(
    spec: &ConnectionSpec,
    config: Option<&SshConfig>,
) -> Result<ResolvedSshConnection, NetError> {
    let target_params = spec.use_ssh_config.then(|| {
        config
            .expect("SSH config is required when use_ssh_config is true")
            .query(&spec.host)
    });
    if target_params.as_ref().is_some_and(has_proxy_command) {
        return Err(ssh_error(
            "ProxyCommand is configured for this host and is intentionally not executed; use ProxyJump or HTTP/SOCKS5 proxy instead",
        ));
    }
    let target_host = validate_host(
        target_params
            .as_ref()
            .and_then(|params| params.host_name.clone())
            .unwrap_or_else(|| spec.host.clone()),
        "SSH host",
    )?;
    let target_user = validate_user(
        target_params
            .as_ref()
            .and_then(|params| params.user.clone())
            .unwrap_or_else(|| spec.user.clone()),
        "SSH host",
    )?;
    let target_port = target_params
        .as_ref()
        .and_then(|params| params.port)
        .unwrap_or_else(|| spec.effective_port());
    if target_port == 0 {
        return Err(ssh_error("SSH host resolves to port 0"));
    }
    let mut target_identities = if let Some(path) = spec.sftp_private_key.as_ref() {
        vec![PathBuf::from(path)]
    } else {
        identities(
            target_params.as_ref(),
            &spec.host,
            &target_host,
            &target_user,
        )?
    };
    target_identities.dedup();
    if spec.sftp_auth == SftpAuth::PrivateKey && target_identities.is_empty() {
        return Err(ssh_error(
            "private-key authentication needs a selected key or IdentityFile in ~/.ssh/config",
        ));
    }

    let configured_jump = target_params
        .as_ref()
        .and_then(|params| params.proxy_jump.as_ref())
        .map(|values| {
            if values.len() == 1 {
                Ok(values[0].as_str())
            } else {
                Err(ssh_error(
                    "only one ProxyJump host is supported; multi-hop chains are rejected",
                ))
            }
        })
        .transpose()?;
    let jump_value = spec.ssh_proxy_jump.as_deref().or(configured_jump);
    let jump_reference = jump_value.map(parse_jump_reference).transpose()?.flatten();

    let target_timeout = safe_timeout(
        spec.timeout_secs,
        target_params
            .as_ref()
            .and_then(|params| params.connect_timeout),
    )?;
    let target_keepalive = safe_keepalive(
        spec.keepalive_interval_secs,
        target_params
            .as_ref()
            .and_then(|params| params.server_alive_interval),
    )?;
    let target = SshEndpoint {
        host: target_host,
        port: target_port,
        user: target_user,
        identity_files: target_identities,
        connect_timeout: target_timeout,
        keepalive_interval: target_keepalive,
    };

    let jump = if let Some(reference) = jump_reference {
        let params = config.map(|config| config.query(&reference.alias));
        if params.as_ref().is_some_and(has_proxy_command) {
            return Err(ssh_error(
                "ProxyCommand is configured for the jump host and is intentionally not executed",
            ));
        }
        if params
            .as_ref()
            .and_then(|params| params.proxy_jump.as_ref())
            .is_some_and(|jumps| !jumps.is_empty() && !jumps[0].eq_ignore_ascii_case("none"))
        {
            return Err(ssh_error(
                "nested or multi-hop ProxyJump chains are not supported",
            ));
        }
        let host = validate_host(
            params
                .as_ref()
                .and_then(|params| params.host_name.clone())
                .unwrap_or_else(|| reference.alias.clone()),
            "ProxyJump",
        )?;
        let user = validate_user(
            reference
                .user
                .or_else(|| params.as_ref().and_then(|params| params.user.clone()))
                .unwrap_or_else(|| spec.user.clone()),
            "ProxyJump",
        )?;
        let port = reference
            .port
            .or_else(|| params.as_ref().and_then(|params| params.port))
            .unwrap_or(22);
        let mut identity_files = identities(params.as_ref(), &reference.alias, &host, &user)?;
        if identity_files.is_empty() && spec.sftp_auth == SftpAuth::PrivateKey {
            identity_files = target.identity_files.clone();
        }
        identity_files.dedup();
        Some(SshEndpoint {
            host,
            port,
            user,
            identity_files,
            connect_timeout: safe_timeout(
                spec.timeout_secs,
                params.as_ref().and_then(|params| params.connect_timeout),
            )?,
            keepalive_interval: safe_keepalive(
                spec.keepalive_interval_secs,
                params
                    .as_ref()
                    .and_then(|params| params.server_alive_interval),
            )?,
        })
    } else {
        None
    };

    Ok(ResolvedSshConnection { target, jump })
}

pub(crate) fn resolve(spec: &ConnectionSpec) -> Result<ResolvedSshConnection, NetError> {
    let needs_optional_config = spec.ssh_proxy_jump.is_some();
    let config = if spec.use_ssh_config || needs_optional_config {
        load_config(spec.use_ssh_config)?
    } else {
        None
    };
    resolve_with_config(spec, config.as_ref())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{ConnectionId, FtpDataMode, FtpFilenameEncoding, Protocol};

    fn spec() -> ConnectionSpec {
        ConnectionSpec {
            id: ConnectionId(1),
            name: "alias".into(),
            protocol: Protocol::Sftp,
            host: "prod".into(),
            port: 22,
            user: "fallback".into(),
            initial_path: String::new(),
            group: String::new(),
            tags: Vec::new(),
            timeout_secs: None,
            keepalive_interval_secs: None,
            ftp_data_mode: FtpDataMode::Passive,
            ftp_filename_encoding: FtpFilenameEncoding::Auto,
            ftp_tls_mode: Default::default(),
            proxy_url: None,
            use_ssh_config: true,
            ssh_proxy_jump: None,
            allow_plaintext_ftp: false,
            accept_invalid_tls: false,
            tls_pinned_sha256: None,
            tls_client_cert: None,
            tls_client_key: None,
            sftp_auth: SftpAuth::Agent,
            sftp_private_key: None,
            transfer_concurrency: None,
        }
    }

    #[test]
    fn resolves_alias_and_single_jump_without_executing_any_command() {
        let config = parse_config_text(
            r#"
Host prod
    HostName internal.example
    User deploy
    Port 2222
    ConnectTimeout 12
    ServerAliveInterval 30
    ProxyJump bastion

Host bastion
    HostName gateway.example
    User jump
    Port 2200
    IdentityFile ~/.ssh/id_ed25519
"#,
        )
        .unwrap();
        let resolved = resolve_with_config(&spec(), Some(&config)).unwrap();
        assert_eq!(resolved.target.host, "internal.example");
        assert_eq!(resolved.target.user, "deploy");
        assert_eq!(resolved.target.port, 2222);
        assert_eq!(resolved.target.connect_timeout, Duration::from_secs(12));
        assert_eq!(
            resolved.target.keepalive_interval,
            Some(Duration::from_secs(30))
        );
        let jump = resolved.jump.unwrap();
        assert_eq!(jump.host, "gateway.example");
        assert_eq!(jump.user, "jump");
        assert_eq!(jump.port, 2200);
        assert_eq!(jump.identity_files.len(), 1);
    }

    #[test]
    fn rejects_commands_match_includes_and_multi_hop_jumps() {
        for config in [
            "Host prod\n ProxyCommand nc %h %p\n",
            "Match exec true\n HostName bad.example\n",
            "Include config.d/*\n",
        ] {
            let parsed = parse_config_text(config);
            if config.contains("ProxyCommand") {
                let parsed = parsed.unwrap();
                assert!(resolve_with_config(&spec(), Some(&parsed)).is_err());
            } else {
                assert!(parsed.is_err());
            }
        }
        let config = parse_config_text("Host prod\n ProxyJump one,two\n").unwrap();
        assert!(resolve_with_config(&spec(), Some(&config)).is_err());
    }

    #[test]
    fn explicit_jump_parser_rejects_credentials_and_ambiguous_ipv6() {
        assert!(parse_jump_reference("user@jump.example:2222")
            .unwrap()
            .is_some());
        assert!(parse_jump_reference("ssh://user@[::1]:2222")
            .unwrap()
            .is_some());
        assert!(parse_jump_reference("user:password@jump.example").is_err());
        assert!(parse_jump_reference("2001:db8::1").is_err());
        assert!(parse_jump_reference("one,two").is_err());
    }
}
