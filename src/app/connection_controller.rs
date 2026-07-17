//! Saved-connection/session model projection and filtering.

use super::*;

pub(super) fn parse_editor_tags(raw: &str) -> Result<Vec<String>, String> {
    let mut tags = Vec::new();
    let mut seen = HashSet::new();
    for tag in raw.split(',').map(str::trim).filter(|tag| !tag.is_empty()) {
        if tag.len() > 128 || tag.chars().any(char::is_control) {
            return Err("each tag must be at most 128 characters and contain no controls".into());
        }
        if !seen.insert(tag.to_lowercase()) {
            return Err(format!("duplicate tag: {tag}"));
        }
        tags.push(tag.to_string());
        if tags.len() > 32 {
            return Err("a connection can have at most 32 tags".into());
        }
    }
    Ok(tags)
}

pub(super) fn parse_editor_timeout(raw: &str) -> Result<Option<u64>, String> {
    let seconds = raw
        .trim()
        .parse::<u64>()
        .map_err(|_| "timeout must be a whole non-negative number".to_string())?;
    if seconds == 0 {
        return Ok(None);
    }
    if !(store::connections::MIN_CONNECTION_TIMEOUT_SECS
        ..=store::connections::MAX_CONNECTION_TIMEOUT_SECS)
        .contains(&seconds)
    {
        return Err(format!(
            "timeout must be 0 or {}–{} seconds",
            store::connections::MIN_CONNECTION_TIMEOUT_SECS,
            store::connections::MAX_CONNECTION_TIMEOUT_SECS
        ));
    }
    Ok(Some(seconds))
}

pub(super) fn parse_editor_keepalive(raw: &str) -> Result<Option<u64>, String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Ok(None);
    }
    let seconds = raw
        .parse::<u64>()
        .map_err(|_| "keepalive must be a whole non-negative number".to_string())?;
    if seconds != 0
        && !(store::connections::MIN_KEEPALIVE_INTERVAL_SECS
            ..=store::connections::MAX_KEEPALIVE_INTERVAL_SECS)
            .contains(&seconds)
    {
        return Err(format!(
            "keepalive must be blank, 0, or {}–{} seconds",
            store::connections::MIN_KEEPALIVE_INTERVAL_SECS,
            store::connections::MAX_KEEPALIVE_INTERVAL_SECS
        ));
    }
    Ok(Some(seconds))
}

pub(super) fn editor_connection_draft(
    ui: &App,
    connection_id: ConnectionId,
) -> Result<(ConnectionSpec, String), String> {
    let name = ui.get_editor_name().trim().to_string();
    let host = ui.get_editor_host().trim().to_string();
    let user = ui.get_editor_user().trim().to_string();
    if name.is_empty() || host.is_empty() || user.is_empty() {
        return Err("name, host and user are required".into());
    }
    let protocol: Protocol = ui
        .get_editor_protocol()
        .trim()
        .to_ascii_lowercase()
        .parse()
        .map_err(|error: String| format!("invalid protocol: {error}"))?;
    let port = ui
        .get_editor_port()
        .trim()
        .parse::<u16>()
        .map_err(|_| "port must be a whole number from 0 to 65535".to_string())?;
    let initial_path = ui.get_editor_initial_path().trim().to_string();
    if initial_path.chars().any(char::is_control) {
        return Err("initial path contains a control character".into());
    }
    if protocol == Protocol::Ftp && !initial_path.is_empty() {
        net::validate_ftp_path(&initial_path).map_err(|error| error.to_string())?;
    }
    let group = ui.get_editor_group().trim().to_string();
    if group.len() > 256 || group.chars().any(char::is_control) {
        return Err("group must be at most 256 characters and contain no controls".into());
    }
    let tags = parse_editor_tags(ui.get_editor_tags().as_str())?;
    let timeout_secs = parse_editor_timeout(ui.get_editor_timeout_secs().as_str())?;
    let keepalive_interval_secs = if protocol == Protocol::Sftp {
        parse_editor_keepalive(ui.get_editor_keepalive_secs().as_str())?
    } else {
        None
    };
    let proxy_url =
        Some(ui.get_editor_proxy_url().trim().to_string()).filter(|value| !value.is_empty());
    if let Some(proxy) = proxy_url.as_deref() {
        net::proxy::validate_proxy_url(proxy).map_err(|error| format!("invalid proxy: {error}"))?;
    }
    let use_ssh_config = protocol == Protocol::Sftp && ui.get_editor_use_ssh_config();
    let ssh_proxy_jump = (protocol == Protocol::Sftp)
        .then(|| ui.get_editor_ssh_proxy_jump().trim().to_string())
        .filter(|value| !value.is_empty());
    if let Some(jump) = ssh_proxy_jump.as_deref() {
        net::validate_ssh_proxy_jump(jump)?;
    }
    let sftp_auth = if protocol == Protocol::Sftp {
        match ui.get_editor_sftp_auth().trim() {
            "password" => SftpAuth::Password,
            "private_key" => SftpAuth::PrivateKey,
            "agent" => SftpAuth::Agent,
            "keyboard_interactive" => SftpAuth::KeyboardInteractive,
            other => return Err(format!("invalid SFTP authentication mode: {other}")),
        }
    } else {
        SftpAuth::Password
    };
    let sftp_private_key = (sftp_auth == SftpAuth::PrivateKey)
        .then(|| ui.get_editor_sftp_key_path().trim().to_string())
        .filter(|path| !path.is_empty());
    if sftp_auth == SftpAuth::PrivateKey && sftp_private_key.is_none() && !use_ssh_config {
        return Err("choose an SSH private-key file or enable ~/.ssh/config IdentityFile".into());
    }
    let transfer_concurrency = match ui.get_editor_transfer_concurrency() {
        0 => None,
        value
            if (gmacftp::transfer::MIN_SERVER_CONCURRENCY as i32
                ..=gmacftp::transfer::MAX_SERVER_CONCURRENCY as i32)
                .contains(&value) =>
        {
            Some(value as usize)
        }
        value => return Err(format!("invalid per-server transfer limit: {value}")),
    };
    let ftp_data_mode = if protocol == Protocol::Ftp {
        match ui.get_editor_ftp_data_mode().as_str() {
            "passive" => FtpDataMode::Passive,
            "active" => FtpDataMode::Active,
            other => return Err(format!("invalid FTP data mode: {other}")),
        }
    } else {
        FtpDataMode::Passive
    };
    let ftp_filename_encoding = if protocol == Protocol::Ftp {
        match ui.get_editor_ftp_filename_encoding().as_str() {
            "auto" => FtpFilenameEncoding::Auto,
            "utf8" => FtpFilenameEncoding::Utf8,
            other => return Err(format!("invalid FTP filename encoding: {other}")),
        }
    } else {
        FtpFilenameEncoding::Auto
    };
    let configured_ftp_tls_mode = if protocol == Protocol::Ftp {
        match ui.get_editor_ftp_tls_mode().as_str() {
            "explicit" => FtpTlsMode::Explicit,
            "implicit" => FtpTlsMode::Implicit,
            other => return Err(format!("invalid FTPS TLS mode: {other}")),
        }
    } else {
        FtpTlsMode::Explicit
    };
    let allow_plaintext_ftp = protocol == Protocol::Ftp && ui.get_editor_allow_plaintext_ftp();
    // Plaintext is a distinct transport, not a fallback policy. Canonicalize the unused TLS mode
    // so saved metadata cannot contain a contradictory plaintext + implicit-TLS combination.
    let ftp_tls_mode = if allow_plaintext_ftp {
        FtpTlsMode::Explicit
    } else {
        configured_ftp_tls_mode
    };
    if ftp_data_mode == FtpDataMode::Active && (allow_plaintext_ftp || proxy_url.is_some()) {
        return Err(
            "active data mode requires FTPS and cannot be combined with HTTP/SOCKS5 proxy".into(),
        );
    }
    let tls_pinned_sha256 = if protocol == Protocol::Ftp && !allow_plaintext_ftp {
        let raw = ui.get_editor_tls_pin();
        if raw.trim().is_empty() {
            None
        } else {
            Some(
                net::ftp::normalize_certificate_pin(raw.as_str())
                    .ok_or_else(|| "saved TLS fingerprint is malformed".to_string())?,
            )
        }
    } else {
        None
    };
    let tls_client_cert = (protocol == Protocol::Ftp && !allow_plaintext_ftp)
        .then(|| ui.get_editor_tls_client_cert().trim().to_string())
        .filter(|path| !path.is_empty());
    let tls_client_key = (protocol == Protocol::Ftp && !allow_plaintext_ftp)
        .then(|| ui.get_editor_tls_client_key().trim().to_string())
        .filter(|path| !path.is_empty());
    if tls_client_cert.is_some() != tls_client_key.is_some() {
        return Err("choose both the TLS client certificate and its PKCS#8 private key".into());
    }
    if allow_plaintext_ftp && tls_client_cert.is_some() {
        return Err("TLS client certificates cannot be used with plaintext FTP".into());
    }
    for path in [tls_client_cert.as_deref(), tls_client_key.as_deref()]
        .into_iter()
        .flatten()
    {
        if path.len() > 4096 || path.chars().any(char::is_control) {
            return Err(
                "TLS client identity path is too long or contains a control character".into(),
            );
        }
        if !Path::new(path).is_absolute() {
            return Err("TLS client identity paths must be absolute".into());
        }
    }
    let password = if matches!(sftp_auth, SftpAuth::Agent | SftpAuth::KeyboardInteractive) {
        String::new()
    } else {
        ui.get_editor_password().to_string()
    };
    Ok((
        ConnectionSpec {
            id: connection_id,
            name,
            protocol,
            host,
            port,
            user,
            initial_path,
            group,
            tags,
            timeout_secs,
            keepalive_interval_secs,
            ftp_data_mode,
            ftp_filename_encoding,
            ftp_tls_mode,
            proxy_url,
            use_ssh_config,
            ssh_proxy_jump,
            allow_plaintext_ftp,
            accept_invalid_tls: protocol == Protocol::Ftp
                && !allow_plaintext_ftp
                && ui.get_editor_legacy_invalid_tls(),
            tls_pinned_sha256,
            tls_client_cert,
            tls_client_key,
            sftp_auth,
            sftp_private_key,
            transfer_concurrency,
        },
        password,
    ))
}

pub(super) fn wire_new(ui: &App) {
    let ui_weak = ui.as_weak();
    ui.on_new_connection(move || {
        let Some(ui) = ui_weak.upgrade() else { return };
        ui.set_editor_id(-1);
        ui.set_editor_name("".into());
        ui.set_editor_protocol("ftp".into());
        ui.set_editor_host("".into());
        ui.set_editor_port("21".into());
        ui.set_editor_user("".into());
        ui.set_editor_password("".into());
        ui.set_editor_initial_path("".into());
        ui.set_editor_group("".into());
        ui.set_editor_tags("".into());
        ui.set_editor_timeout_secs("0".into());
        ui.set_editor_keepalive_secs("".into());
        ui.set_editor_ftp_data_mode("passive".into());
        ui.set_editor_ftp_filename_encoding("auto".into());
        ui.set_editor_ftp_tls_mode("explicit".into());
        ui.set_editor_proxy_url("".into());
        ui.set_editor_use_ssh_config(false);
        ui.set_editor_ssh_proxy_jump("".into());
        ui.set_editor_sftp_auth("password".into());
        ui.set_editor_sftp_key_path("".into());
        ui.set_editor_transfer_concurrency(0);
        ui.set_editor_allow_plaintext_ftp(false);
        ui.set_editor_tls_pin("".into());
        ui.set_editor_tls_client_cert("".into());
        ui.set_editor_tls_client_key("".into());
        ui.set_editor_legacy_invalid_tls(false);
        ui.set_editor_testing(false);
        ui.set_manager_message("".into());
        ui.set_editor_open(true);
    });
}

pub(super) fn wire_choose_private_key(ui: &App, handle: &Handle) {
    let handle = handle.clone();
    let ui_weak = ui.as_weak();
    ui.on_choose_private_key(move || {
        let ui_weak = ui_weak.clone();
        handle.spawn(async move {
            let mut dialog = rfd::AsyncFileDialog::new().set_title("Choose SSH private key");
            if let Some(home) = directories::BaseDirs::new() {
                let ssh = home.home_dir().join(".ssh");
                if ssh.is_dir() {
                    dialog = dialog.set_directory(ssh);
                }
            }
            let Some(file) = dialog.pick_file().await else {
                return;
            };
            let path = file.path().to_string_lossy().into_owned();
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(ui) = ui_weak.upgrade() {
                    ui.set_editor_sftp_key_path(path.into());
                }
            });
        });
    });
}

pub(super) fn wire_choose_tls_client_identity(ui: &App, handle: &Handle) {
    let ui_weak = ui.as_weak();
    let cert_handle = handle.clone();
    ui.on_choose_tls_client_cert(move || {
        let ui_weak = ui_weak.clone();
        cert_handle.spawn(async move {
            let Some(file) = rfd::AsyncFileDialog::new()
                .set_title("Choose TLS client certificate chain")
                .add_filter("PEM certificate", &["pem", "crt", "cer"])
                .pick_file()
                .await
            else {
                return;
            };
            let path = file.path().to_string_lossy().into_owned();
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(ui) = ui_weak.upgrade() {
                    ui.set_editor_tls_client_cert(path.into());
                }
            });
        });
    });

    let ui_weak = ui.as_weak();
    let key_handle = handle.clone();
    ui.on_choose_tls_client_key(move || {
        let ui_weak = ui_weak.clone();
        key_handle.spawn(async move {
            let Some(file) = rfd::AsyncFileDialog::new()
                .set_title("Choose unencrypted PKCS#8 private key")
                .add_filter("PEM private key", &["pem", "key"])
                .pick_file()
                .await
            else {
                return;
            };
            let path = file.path().to_string_lossy().into_owned();
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(ui) = ui_weak.upgrade() {
                    ui.set_editor_tls_client_key(path.into());
                }
            });
        });
    });
}

pub(super) fn wire_reset_editor_tls_trust(ui: &App) {
    let ui_weak = ui.as_weak();
    ui.on_reset_editor_tls_trust(move || {
        if let Some(ui) = ui_weak.upgrade() {
            ui.set_editor_tls_pin("".into());
            ui.set_editor_legacy_invalid_tls(false);
            ui.set_manager_message(
                "Saved TLS trust will be removed when this connection is saved.".into(),
            );
        }
    });
}

pub(super) fn wire_test_connection(ui: &App, handle: &Handle, conns: ConnList) {
    let handle = handle.clone();
    let ui_weak = ui.as_weak();
    ui.on_test_connection(move || {
        let Some(ui) = ui_weak.upgrade() else { return };
        let id = ui.get_editor_id();
        let connection_id = if id >= 0 {
            ConnectionId(id as usize)
        } else {
            ConnectionId(next_id(&conns.lock().expect("connections lock")))
        };
        let (spec, password) = match editor_connection_draft(&ui, connection_id) {
            Ok(draft) => draft,
            Err(error) => {
                ui.set_manager_message(error.into());
                return;
            }
        };
        ui.set_editor_testing(true);
        ui.set_manager_message("Testing connection without saving…".into());
        let ui_weak = ui.as_weak();
        handle.spawn(async move {
            let password = Zeroizing::new(password);
            let result = net::connect_and_list(&spec, password.as_str()).await;
            let message = match result {
                Ok((entries, plaintext)) if plaintext => format!(
                    "Connection successful — listed {} item(s), but the session is plaintext FTP.",
                    entries.len()
                ),
                Ok((entries, _)) => format!(
                    "Connection successful — authentication and listing completed ({} item(s)).",
                    entries.len()
                ),
                Err(net::NetError::HostKeyTrustRequired(challenge)) => format!(
                    "Server reached. Verify SSH fingerprint {} independently, then Save and Connect to approve it.",
                    challenge.fingerprint()
                ),
                Err(net::NetError::TlsCertificateTrustRequired(challenge)) => format!(
                    "Server reached. Verify TLS fingerprint {} independently, then Save and Connect to pin it.",
                    challenge.fingerprint()
                ),
                Err(error) => format!("Connection test failed: {error}"),
            };
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(ui) = ui_weak.upgrade() {
                    ui.set_editor_testing(false);
                    ui.set_manager_message(message.into());
                }
            });
        });
    });
}

pub(super) fn wire_edit(ui: &App, store: Arc<dyn CredentialStore>, conns: ConnList) {
    let ui_weak = ui.as_weak();
    ui.on_edit_connection(move |id| {
        let Some(ui) = ui_weak.upgrade() else { return };
        let spec = conns
            .lock()
            .expect("connections lock")
            .iter()
            .find(|c| c.id.0 as i32 == id)
            .cloned();
        let Some(spec) = spec else { return };
        let pw = if matches!(
            spec.sftp_auth,
            SftpAuth::Agent | SftpAuth::KeyboardInteractive
        ) {
            String::new()
        } else {
            CredentialKey::for_spec(&spec)
                .ok()
                .and_then(|key| store.get_for(&key).ok())
                .map(|b| String::from_utf8_lossy(&b).into_owned())
                .unwrap_or_default()
        };
        ui.set_editor_id(spec.id.0 as i32);
        ui.set_editor_name(spec.name.into());
        ui.set_editor_protocol(spec.protocol.to_string().into());
        ui.set_editor_host(spec.host.into());
        ui.set_editor_port(spec.port.to_string().into());
        ui.set_editor_user(spec.user.into());
        ui.set_editor_password(pw.into());
        ui.set_editor_initial_path(spec.initial_path.clone().into());
        ui.set_editor_group(spec.group.clone().into());
        ui.set_editor_tags(spec.tags.join(", ").into());
        ui.set_editor_timeout_secs(spec.timeout_secs.unwrap_or(0).to_string().into());
        ui.set_editor_keepalive_secs(
            spec.keepalive_interval_secs
                .map(|seconds| seconds.to_string())
                .unwrap_or_default()
                .into(),
        );
        ui.set_editor_ftp_data_mode(
            match spec.ftp_data_mode {
                FtpDataMode::Passive => "passive",
                FtpDataMode::Active => "active",
            }
            .into(),
        );
        ui.set_editor_ftp_filename_encoding(
            match spec.ftp_filename_encoding {
                FtpFilenameEncoding::Auto => "auto",
                FtpFilenameEncoding::Utf8 => "utf8",
            }
            .into(),
        );
        ui.set_editor_ftp_tls_mode(
            match spec.ftp_tls_mode {
                FtpTlsMode::Explicit => "explicit",
                FtpTlsMode::Implicit => "implicit",
            }
            .into(),
        );
        ui.set_editor_proxy_url(spec.proxy_url.clone().unwrap_or_default().into());
        ui.set_editor_use_ssh_config(spec.use_ssh_config);
        ui.set_editor_ssh_proxy_jump(spec.ssh_proxy_jump.clone().unwrap_or_default().into());
        ui.set_editor_sftp_auth(
            match spec.sftp_auth {
                SftpAuth::Password => "password",
                SftpAuth::PrivateKey => "private_key",
                SftpAuth::Agent => "agent",
                SftpAuth::KeyboardInteractive => "keyboard_interactive",
            }
            .into(),
        );
        ui.set_editor_sftp_key_path(spec.sftp_private_key.unwrap_or_default().into());
        ui.set_editor_transfer_concurrency(spec.transfer_concurrency.unwrap_or(0).min(4) as i32);
        ui.set_editor_allow_plaintext_ftp(spec.allow_plaintext_ftp);
        ui.set_editor_tls_pin(spec.tls_pinned_sha256.unwrap_or_default().into());
        ui.set_editor_tls_client_cert(spec.tls_client_cert.unwrap_or_default().into());
        ui.set_editor_tls_client_key(spec.tls_client_key.unwrap_or_default().into());
        ui.set_editor_legacy_invalid_tls(spec.accept_invalid_tls);
        ui.set_editor_testing(false);
        ui.set_manager_message("".into());
        ui.set_editor_open(true);
    });
}

pub(super) fn wire_delete(ui: &App, store: Arc<dyn CredentialStore>, conns: ConnList) {
    let ui_weak = ui.as_weak();
    ui.on_delete_connection(move |id| {
        let Some(ui) = ui_weak.upgrade() else { return };
        let current = conns.lock().expect("connections lock").clone();
        let Some(pos) = current.iter().position(|c| c.id.0 as i32 == id) else {
            return;
        };
        let removed = current[pos].clone();
        let key = match CredentialKey::for_spec(&removed) {
            Ok(key) => key,
            Err(e) => {
                ui.set_manager_message(format!("invalid saved connection: {e}").into());
                return;
            }
        };
        let mut candidate = current;
        candidate.remove(pos);
        // Persist the new list before changing in-memory state or deleting a secret. This makes
        // a failed metadata write recoverable and avoids reporting a deletion that did not stick.
        if let Err(e) = store::save_metadata(&candidate) {
            ui.set_manager_message(format!("could not delete “{}”: {e}", removed.name).into());
            return;
        }
        let still_referenced = candidate
            .iter()
            .filter_map(|spec| CredentialKey::for_spec(spec).ok())
            .any(|candidate_key| candidate_key == key);
        let legacy_still_referenced = candidate.iter().any(|spec| {
            CredentialKey::for_spec(spec).is_ok_and(|candidate_key| {
                candidate_key.host() == key.host() && candidate_key.user() == key.user()
            })
        });
        *conns.lock().expect("connections lock") = candidate;
        if !still_referenced {
            // The credential key can be shared by several saved connection rows. Only delete it
            // once the last row is gone, and never let a Keychain cleanup error masquerade as a
            // fully successful delete.
            if let Ok(mut cache) = PASSWORD_CACHE.lock() {
                cache.remove(&key);
            }
            if let Err(e) = store.delete_for(&key) {
                refresh_connections_model(&ui, &conns);
                ui.set_manager_message(
                    format!(
                        "deleted “{}” from the list, but could not remove its saved credential: {e}",
                        removed.name
                    )
                    .into(),
                );
                return;
            }
        }
        if !legacy_still_referenced {
            // Once no saved endpoint can need the old `(host, user)` fallback, remove it too so a
            // deleted password cannot be resurrected by lazy migration on a future re-add.
            if let Err(e) = store.delete(key.host(), key.user()) {
                refresh_connections_model(&ui, &conns);
                ui.set_manager_message(
                    format!(
                        "deleted “{}”, but could not remove its legacy credential: {e}",
                        removed.name
                    )
                    .into(),
                );
                return;
            }
        }
        refresh_connections_model(&ui, &conns);
        ui.set_manager_message(format!("deleted “{}”", removed.name).into());
    });
}

pub(super) fn wire_save(ui: &App, store: Arc<dyn CredentialStore>, conns: ConnList) {
    let ui_weak = ui.as_weak();
    ui.on_save_connection(move || {
        let Some(ui) = ui_weak.upgrade() else { return };

        let id = ui.get_editor_id();
        let current = conns.lock().expect("connections lock").clone();
        let previous = if id >= 0 {
            match current.iter().find(|spec| spec.id.0 as i32 == id).cloned() {
                Some(spec) => Some(spec),
                None => {
                    ui.set_manager_message("connection no longer exists".into());
                    return;
                }
            }
        } else {
            None
        };
        let connection_id = ConnectionId(if id < 0 {
            next_id(&current)
        } else {
            id as usize
        });
        let (spec, password) = match editor_connection_draft(&ui, connection_id) {
            Ok(draft) => draft,
            Err(error) => {
                ui.set_manager_message(error.into());
                return;
            }
        };

        let new_key = match CredentialKey::for_spec(&spec) {
            Ok(key) => key,
            Err(e) => {
                ui.set_manager_message(format!("invalid connection endpoint: {e}").into());
                return;
            }
        };
        // If a metadata save fails after writing a new password, restore the exact prior value
        // (or remove the newly-created key). Refuse to proceed when the old value cannot be read:
        // otherwise an attempted rollback could erase an unrelated/shared credential.
        let prior_new_secret = if password.is_empty() {
            None
        } else {
            match store.get_for(&new_key) {
                Ok(secret) => Some(secret),
                Err(store::CredentialError::NotFound) => None,
                Err(e) => {
                    ui.set_manager_message(format!("could not safely update credential: {e}").into());
                    return;
                }
            }
        };
        if !password.is_empty() {
            if let Err(e) = store.set_for(&new_key, password.as_bytes()) {
                ui.set_manager_message(format!("credential error: {e}").into());
                return;
            }
        }

        let mut candidate = current;
        if let Some(previous) = previous.as_ref() {
            let pos = candidate
                .iter()
                .position(|entry| entry.id == previous.id)
                .expect("edited connection must remain in snapshot");
            candidate[pos] = spec.clone();
        } else {
            candidate.push(spec.clone());
        }
        if let Err(e) = store::save_metadata(&candidate) {
            if !password.is_empty() {
                let rollback = match prior_new_secret {
                    Some(secret) => store.set_for(&new_key, &secret),
                    None => store.delete_for(&new_key),
                };
                if let Err(rollback_error) = rollback {
                    ui.set_manager_message(
                        format!(
                            "could not save connection metadata: {e}; credential rollback also failed: {rollback_error}"
                        )
                        .into(),
                    );
                    return;
                }
            }
            ui.set_manager_message(format!("could not save connection metadata: {e}").into());
            return;
        }

        // Commit observable app state only after durable metadata succeeds.
        *conns.lock().expect("connections lock") = candidate.clone();
        if !password.is_empty() {
            if let Ok(mut cache) = PASSWORD_CACHE.lock() {
                cache.insert(new_key.clone(), Zeroizing::new(password.clone()));
            }
        }
        let mut cleanup_error = None;
        let endpoint_secret_still_needed = candidate.iter().any(|entry| {
            !matches!(
                (entry.protocol, entry.sftp_auth),
                (
                    Protocol::Sftp,
                    SftpAuth::Agent | SftpAuth::KeyboardInteractive
                )
            ) && CredentialKey::for_spec(entry).is_ok_and(|key| key == new_key)
        });
        if !endpoint_secret_still_needed {
            if let Ok(mut cache) = PASSWORD_CACHE.lock() {
                cache.remove(&new_key);
            }
            if let Err(error) = store.delete_for(&new_key) {
                cleanup_error = Some(format!("unused credential cleanup failed: {error}"));
            }
        }
        if let Some(previous) = previous {
            let old_key = match CredentialKey::for_spec(&previous) {
                Ok(key) => key,
                Err(e) => {
                    refresh_connections_model(&ui, &conns);
                    ui.set_editor_open(false);
                    ui.set_manager_message(
                        format!(
                            "saved “{}”, but could not identify the old credential: {e}",
                            spec.name
                        )
                        .into(),
                    );
                    return;
                }
            };
            let old_key_still_referenced = candidate
                .iter()
                .filter_map(|entry| CredentialKey::for_spec(entry).ok())
                .any(|candidate_key| candidate_key == old_key);
            if old_key != new_key && !old_key_still_referenced {
                // Metadata and the replacement credential are both durable now. Only now may we
                // erase the old key, and only when no other connection still uses it.
                if let Ok(mut cache) = PASSWORD_CACHE.lock() {
                    cache.remove(&old_key);
                }
                if let Err(e) = store.delete_for(&old_key) {
                    cleanup_error = Some(e.to_string());
                }
            }
            let legacy_old_key_still_referenced = candidate.iter().any(|entry| {
                CredentialKey::for_spec(entry).is_ok_and(|candidate_key| {
                    candidate_key.host() == old_key.host()
                        && candidate_key.user() == old_key.user()
                })
            });
            if old_key != new_key && !legacy_old_key_still_referenced {
                if let Err(e) = store.delete(old_key.host(), old_key.user()) {
                    cleanup_error = Some(format!("legacy credential cleanup failed: {e}"));
                }
            }
        }
        refresh_connections_model(&ui, &conns);
        ui.set_editor_password("".into());
        ui.set_editor_sftp_key_path("".into());
        ui.set_editor_open(false);
        let message = if let Some(error) = cleanup_error {
            format!(
                "saved “{}”, but could not remove the old credential: {error}",
                spec.name
            )
        } else if id < 0 {
            format!("added “{}”", spec.name)
        } else {
            format!("saved “{}”", spec.name)
        };
        ui.set_manager_message(message.into());
    });
}

pub(super) fn wire_import(
    ui: &App,
    handle: &Handle,
    store: Arc<dyn CredentialStore>,
    conns: ConnList,
) {
    let handle = handle.clone();
    let ui_weak = ui.as_weak();
    ui.on_import_forklift(move || {
        let Some(ui) = ui_weak.upgrade() else { return };
        ui.set_manager_message("choose a file to import…".into());
        let store = store.clone();
        let conns = conns.clone();
        let ui_weak = ui_weak.clone();
        handle.spawn(async move {
            // Native macOS open panel (NSOpenPanel). Awaited directly on this tokio task — the
            // future is Send and non-blocking: rfd drives the sheet via a completion handler +
            // Waker (only the brief panel setup hops to the main thread, where Slint's ui.run()
            // NSApplication loop is already spinning). Do NOT wrap in spawn_blocking.
            let file = rfd::AsyncFileDialog::new()
                .set_title("Import connections — FileZilla sitemanager.xml or a third-party file manager JSON")
                .add_filter("FileZilla sitemanager.xml", &["xml"])
                .add_filter("a third-party file manager / JSON export", &["json"])
                .pick_file()
                .await;
            let Some(file) = file else {
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(ui) = ui_weak.upgrade() {
                        ui.set_manager_message("import cancelled".into());
                    }
                });
                return;
            };
            let path = file.path().to_path_buf();
            // Parse off-thread (XML/JSON parse = CPU + small I/O), then hop back to the UI
            // thread — Slint models are !Send and must be touched via invoke_from_event_loop.
            let (conns_c, store_c) = (conns.clone(), store.clone());
            let message = tokio::task::spawn_blocking(move || import_from_path(&path, &conns_c, &store_c))
                .await
                .unwrap_or_else(|_| "import failed".to_string());
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(ui) = ui_weak.upgrade() {
                    refresh_connections_model(&ui, &conns);
                    ui.set_manager_message(message.into());
                }
            });
        });
    });
}

/// Merge `specs` into the connection list, skipping (host, user) pairs already present.
/// Metadata is persisted before the in-memory model changes, so callers never report an import
/// as successful when `connections.json` could not be updated.
pub(super) fn merge_new(conns: &ConnList, specs: Vec<ConnectionSpec>) -> Result<usize, String> {
    let current = conns.lock().expect("connections lock").clone();
    let mut candidate = current;
    let mut next = next_id(&candidate);
    let mut count = 0;
    for s in specs {
        let key = CredentialKey::for_spec(&s).map_err(|e| e.to_string())?;
        if candidate.iter().any(|c| {
            CredentialKey::for_spec(c)
                .map(|candidate_key| candidate_key == key)
                .unwrap_or(false)
        }) {
            continue;
        }
        candidate.push(ConnectionSpec {
            id: ConnectionId(next),
            ..s
        });
        next += 1;
        count += 1;
    }
    if count == 0 {
        return Ok(0);
    }
    store::save_metadata(&candidate).map_err(|e| e.to_string())?;
    *conns.lock().expect("connections lock") = candidate;
    Ok(count)
}

/// Import from a user-picked file. Detects the format (FileZilla `sitemanager.xml` vs the
/// a third-party file manager JSON seed) by extension, then by content sniff, loads it, stores passwords in the
/// vault, and merges new complete endpoints. Returns a status line for the manager dialog.
pub(super) fn import_from_path(
    path: &Path,
    conns: &ConnList,
    store: &Arc<dyn CredentialStore>,
) -> String {
    let label = path
        .file_name()
        .map(|f| f.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.display().to_string());
    let text = match read_bounded_regular_utf8(path, MAX_IMPORT_BYTES) {
        Ok(text) => text,
        Err(e) => {
            return format!(
                "could not read {label} ({} limit): {e}",
                fmt_size(MAX_IMPORT_BYTES)
            )
        }
    };
    let ext_is = |e: &str| {
        path.extension()
            .and_then(|x| x.to_str())
            .map(|x| x.eq_ignore_ascii_case(e))
            .unwrap_or(false)
    };
    let trimmed = text.trim_start();
    let result = if ext_is("json") {
        store::load_seed(&text, store.as_ref())
    } else if ext_is("xml") || trimmed.starts_with('<') {
        store::load_filezilla(&text, store.as_ref())
    } else if trimmed.starts_with('{') || trimmed.starts_with('[') {
        store::load_seed(&text, store.as_ref())
    } else {
        return format!("unrecognized file format: {label} (use FileZilla .xml or .json)");
    };
    match result {
        Ok(specs) => match merge_new(conns, specs) {
            Ok(n) => {
                if n > 0 {
                    format!("imported {n} connection(s) from {label}")
                } else {
                    format!("no new connections from {label} (all already present)")
                }
            }
            Err(e) => format!("import failed ({label}): could not save metadata: {e}"),
        },
        Err(e) => format!("import failed ({label}): {e}"),
    }
}

pub(super) fn refresh_connections_model(ui: &App, conns: &ConnList) {
    let active = ui.get_active_connection();
    let demo = use_design_demo_connections();
    let model: Vec<ConnRow> = conns
        .lock()
        .expect("connections lock")
        .iter()
        .map(|c| {
            let mut sub = if demo {
                format!("{}:{}", c.host, c.port)
            } else {
                format!("{}@{}:{}", c.user, c.host, c.port)
            };
            if !c.group.is_empty() {
                sub.push_str(" · ");
                sub.push_str(&c.group);
            }
            if !c.tags.is_empty() {
                sub.push_str(" · #");
                sub.push_str(&c.tags.join(" #"));
            }
            ConnRow {
                id: c.id.0 as i32,
                label: c.name.clone().into(),
                sub: sub.into(),
                protocol: demo_protocol_label(c, demo).into(),
                connected: c.id.0 as i32 == active,
            }
        })
        .collect();
    ui.set_connections(ModelRc::from(Rc::new(VecModel::from(model))));
    apply_server_filter(ui);
    apply_palette_filter(ui);
}

pub(super) fn demo_protocol_label(c: &ConnectionSpec, demo: bool) -> String {
    if demo && c.name == "Production" {
        "FTPS".to_string()
    } else {
        c.protocol.to_string().to_uppercase()
    }
}

pub(super) fn conn_row_matches(row: &ConnRow, query: &str) -> bool {
    let query = query.trim().to_lowercase();
    if query.is_empty() {
        return true;
    }
    row.label.to_string().to_lowercase().contains(&query)
        || row.sub.to_string().to_lowercase().contains(&query)
        || row.protocol.to_string().to_lowercase().contains(&query)
}

pub(super) fn model_rows(model: ModelRc<ConnRow>) -> Vec<ConnRow> {
    (0..model.row_count())
        .filter_map(|i| model.row_data(i))
        .collect()
}

pub(super) fn apply_server_filter(ui: &App) {
    let query = ui.get_server_filter().to_string();
    let connections = model_rows(ui.get_connections());
    let sessions = model_rows(ui.get_sessions());
    let filtered_connections: Vec<ConnRow> = connections
        .into_iter()
        .filter(|row| conn_row_matches(row, &query))
        .collect();
    let filtered_sessions: Vec<ConnRow> = sessions
        .into_iter()
        .filter(|row| conn_row_matches(row, &query))
        .collect();
    ui.set_filtered_connections(ModelRc::from(Rc::new(VecModel::from(filtered_connections))));
    ui.set_filtered_sessions(ModelRc::from(Rc::new(VecModel::from(filtered_sessions))));
}

pub(super) fn wire_server_filter(ui: &App) {
    let ui_weak = ui.as_weak();
    ui.on_filter_servers(move |query| {
        if let Some(ui) = ui_weak.upgrade() {
            ui.set_server_filter(query);
            apply_server_filter(&ui);
        }
    });
}
