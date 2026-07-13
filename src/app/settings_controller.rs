//! Validated settings-form projection plus locale, theme, and window restoration.

use super::*;

pub(super) fn bounded_tree_size(root: &Path, max_entries: usize) -> (u64, usize, bool) {
    let metadata = match std::fs::symlink_metadata(root) {
        Ok(metadata) => metadata,
        Err(_) => return (0, 0, false),
    };
    if metadata.file_type().is_symlink() {
        return (0, 0, true);
    }
    if metadata.is_file() {
        return (metadata.len(), 1, false);
    }
    if !metadata.is_dir() {
        return (0, 0, true);
    }
    let mut bytes = 0_u64;
    let mut entries_seen = 0usize;
    let mut truncated = false;
    let mut stack = vec![root.to_path_buf()];
    while let Some(directory) = stack.pop() {
        let entries = match std::fs::read_dir(directory) {
            Ok(entries) => entries,
            Err(_) => {
                truncated = true;
                continue;
            }
        };
        for entry in entries {
            if entries_seen == max_entries {
                truncated = true;
                stack.clear();
                break;
            }
            entries_seen += 1;
            let Ok(entry) = entry else {
                truncated = true;
                continue;
            };
            let Ok(metadata) = std::fs::symlink_metadata(entry.path()) else {
                truncated = true;
                continue;
            };
            if metadata.file_type().is_symlink() {
                continue;
            }
            if metadata.is_dir() {
                stack.push(entry.path());
            } else if metadata.is_file() {
                bytes = bytes.saturating_add(metadata.len());
            }
        }
    }
    (bytes, entries_seen, truncated)
}

pub(super) fn read_regular_file_bounded(path: &Path, max_bytes: usize) -> Result<Vec<u8>, String> {
    let before = std::fs::symlink_metadata(path)
        .map_err(|error| format!("could not inspect selected file: {error}"))?;
    if !before.file_type().is_file()
        || before.file_type().is_symlink()
        || before.len() > max_bytes as u64
    {
        return Err("selected file is not a bounded regular file".into());
    }
    let mut file = std::fs::File::open(path)
        .map_err(|error| format!("could not open selected file: {error}"))?;
    let opened = file
        .metadata()
        .map_err(|error| format!("could not verify selected file: {error}"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if before.dev() != opened.dev() || before.ino() != opened.ino() {
            return Err("selected file changed while opening".into());
        }
    }
    if !opened.file_type().is_file() || opened.len() > max_bytes as u64 {
        return Err("selected file changed type or size".into());
    }
    let mut bytes = Vec::with_capacity(opened.len() as usize);
    file.by_ref()
        .take(max_bytes.saturating_add(1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("could not read selected file: {error}"))?;
    if bytes.len() > max_bytes {
        return Err("selected file exceeds its safe size limit".into());
    }
    Ok(bytes)
}

pub(super) fn compute_storage_stats(engine: &TransferEngine) -> StorageStats {
    let mut stats = StorageStats::default();
    if let Some(project) = directories::ProjectDirs::from(
        env!("MACKFTP_CONFIG_QUALIFIER"),
        env!("MACKFTP_CONFIG_ORGANIZATION"),
        env!("MACKFTP_CONFIG_APPLICATION"),
    ) {
        let (bytes, _, truncated) = bounded_tree_size(project.config_dir(), 4_096);
        stats.config_bytes = bytes;
        stats.scan_truncated |= truncated;
    }

    if let Ok(cache) = LOCAL_FOLDER_STATS_CACHE.lock() {
        stats.cache_entries = stats.cache_entries.saturating_add(cache.len());
        stats.cache_bytes_approx = stats.cache_bytes_approx.saturating_add(
            cache
                .keys()
                .map(|(path, _)| {
                    path.to_string_lossy().len() as u64
                        + std::mem::size_of::<LocalFolderStatsCacheSlot>() as u64
                })
                .sum::<u64>(),
        );
    }
    if let Ok(cache) = REMOTE_FOLDER_STATS_CACHE.lock() {
        stats.cache_entries = stats.cache_entries.saturating_add(cache.len());
        stats.cache_bytes_approx = stats.cache_bytes_approx.saturating_add(
            cache
                .keys()
                .map(|(_, path, _)| {
                    path.len() as u64 + std::mem::size_of::<CachedRemoteFolderStats>() as u64
                })
                .sum::<u64>(),
        );
    }

    let mut fragments = HashSet::new();
    for (job, _) in engine.recovered_jobs() {
        if job.direction != TransferDirection::Download || job.resume_token == 0 {
            continue;
        }
        let path = net::resumable_part_path(Path::new(&job.local_path), job.resume_token);
        if !fragments.insert(path.clone()) {
            continue;
        }
        if let Ok(metadata) = std::fs::symlink_metadata(path) {
            if metadata.file_type().is_file() && !metadata.file_type().is_symlink() {
                stats.fragment_count += 1;
                stats.fragment_bytes = stats.fragment_bytes.saturating_add(metadata.len());
            }
        }
    }

    if let Ok(entries) = std::fs::read_dir(std::env::temp_dir()) {
        for entry in entries.take(512).flatten() {
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            if !name.starts_with("gmacftp-drag-") {
                continue;
            }
            let path = entry.path();
            let is_real_directory = std::fs::symlink_metadata(&path)
                .map(|metadata| metadata.file_type().is_dir() && !metadata.file_type().is_symlink())
                .unwrap_or(false);
            if !is_real_directory {
                continue;
            }
            stats.temporary_directories += 1;
            let (bytes, _, truncated) = bounded_tree_size(&path, 10_000);
            stats.temporary_bytes = stats.temporary_bytes.saturating_add(bytes);
            stats.scan_truncated |= truncated;
        }
    }
    // gmacFTP writes diagnostics to stderr only. There is intentionally no persistent log file.
    stats.persistent_log_bytes = 0;
    stats
}

pub(super) fn storage_stats_summary(stats: StorageStats) -> String {
    format!(
        "Config: {}  |  Metadata cache: ~{} ({} entries)\nResume fragments: {} ({} files)  |  Temporary edits/drags: {} ({} dirs)\nPersistent logs: {}{}",
        fmt_size(stats.config_bytes),
        fmt_size(stats.cache_bytes_approx),
        stats.cache_entries,
        fmt_size(stats.fragment_bytes),
        stats.fragment_count,
        fmt_size(stats.temporary_bytes),
        stats.temporary_directories,
        fmt_size(stats.persistent_log_bytes),
        if stats.scan_truncated { "  |  bounded scan truncated" } else { "" },
    )
}

pub(super) fn settings_backup_plaintext(
    settings: &store::settings::Settings,
) -> Result<Vec<u8>, String> {
    let document = SettingsBackupDocument {
        format: "gmacftp-settings".into(),
        version: 1,
        settings: settings.clone(),
    };
    let plaintext = serde_json::to_vec_pretty(&document)
        .map_err(|error| format!("could not serialize settings: {error}"))?;
    if plaintext.len() > store::backup::MAX_PLAINTEXT_BYTES {
        return Err("settings export exceeds its safe size limit".into());
    }
    Ok(plaintext)
}

pub(super) fn imported_settings_from_plaintext_with_current(
    plaintext: &[u8],
    current: &store::settings::Settings,
) -> Result<store::settings::Settings, String> {
    if plaintext.len() > store::backup::MAX_PLAINTEXT_BYTES {
        return Err("decrypted settings exceed their safe size limit".into());
    }
    let document: SettingsBackupDocument = serde_json::from_slice(plaintext)
        .map_err(|error| format!("invalid settings backup: {error}"))?;
    if document.format != "gmacftp-settings" || document.version != 1 {
        return Err("unsupported settings backup document".into());
    }
    let mut imported = store::settings::validate(document.settings);
    // A settings-only backup cannot carry the vault key/passphrase. Preserve this Mac's security
    // and migration state so importing preferences never enables cloud sync or strands secrets.
    imported.sync_via_icloud = current.sync_via_icloud;
    imported.sync_folder = current.sync_folder.clone();
    imported.sync_passphrase_set = current.sync_passphrase_set;
    imported.keychain_migrated_v2 = current.keychain_migrated_v2;
    imported.endpoint_credentials_migrated_v2 = current.endpoint_credentials_migrated_v2;
    Ok(store::settings::validate(imported))
}

pub(super) fn imported_settings_from_plaintext(
    plaintext: &[u8],
) -> Result<store::settings::Settings, String> {
    imported_settings_from_plaintext_with_current(plaintext, &store::settings::load())
}

pub(super) fn refresh_storage_stats_async(handle: &Handle, engine: TransferEngine, ui: Weak<App>) {
    handle.spawn(async move {
        let stats = tokio::task::spawn_blocking(move || compute_storage_stats(&engine))
            .await
            .unwrap_or_default();
        let summary = storage_stats_summary(stats);
        let _ = slint::invoke_from_event_loop(move || {
            if let Some(ui) = ui.upgrade() {
                ui.set_settings_storage_summary(summary.into());
            }
        });
    });
}

pub(super) fn redacted_diagnostics(
    settings: &store::settings::Settings,
    connections: &[ConnectionSpec],
    storage: StorageStats,
    recoverable_transfers: usize,
) -> Result<Vec<u8>, String> {
    #[derive(serde::Serialize)]
    struct ConnectionSummary {
        total: usize,
        ftp: usize,
        sftp: usize,
        plaintext_ftp_opt_ins: usize,
        legacy_tls_exceptions: usize,
        pinned_tls_endpoints: usize,
        implicit_ftps_endpoints: usize,
        tls_client_identity_endpoints: usize,
        proxy_endpoints: usize,
        ssh_config_endpoints: usize,
    }
    #[derive(serde::Serialize)]
    struct Diagnostics<'a> {
        format: &'static str,
        format_version: u8,
        privacy: &'static str,
        app_version: &'static str,
        target_os: &'static str,
        target_arch: &'static str,
        locale_mode: &'a str,
        theme_mode: &'a str,
        background_folder_metadata: bool,
        transfer_concurrency: usize,
        per_server_transfer_concurrency: usize,
        retry_count: usize,
        bandwidth_limit_kib: u64,
        saved_sync_profiles: usize,
        editor_mappings: usize,
        recoverable_transfers: usize,
        storage: StorageStats,
        connections: ConnectionSummary,
    }
    let summary = ConnectionSummary {
        total: connections.len(),
        ftp: connections
            .iter()
            .filter(|connection| connection.protocol == Protocol::Ftp)
            .count(),
        sftp: connections
            .iter()
            .filter(|connection| connection.protocol == Protocol::Sftp)
            .count(),
        plaintext_ftp_opt_ins: connections
            .iter()
            .filter(|connection| connection.allow_plaintext_ftp)
            .count(),
        legacy_tls_exceptions: connections
            .iter()
            .filter(|connection| connection.accept_invalid_tls)
            .count(),
        pinned_tls_endpoints: connections
            .iter()
            .filter(|connection| connection.tls_pinned_sha256.is_some())
            .count(),
        implicit_ftps_endpoints: connections
            .iter()
            .filter(|connection| {
                connection.protocol == Protocol::Ftp
                    && connection.ftp_tls_mode == FtpTlsMode::Implicit
            })
            .count(),
        tls_client_identity_endpoints: connections
            .iter()
            .filter(|connection| {
                connection.tls_client_cert.is_some() && connection.tls_client_key.is_some()
            })
            .count(),
        proxy_endpoints: connections
            .iter()
            .filter(|connection| connection.proxy_url.is_some())
            .count(),
        ssh_config_endpoints: connections
            .iter()
            .filter(|connection| connection.use_ssh_config)
            .count(),
    };
    let locale_mode = match settings.locale.as_str() {
        "system" | "en" | "pl" => settings.locale.as_str(),
        _ => "invalid",
    };
    let theme_mode = match settings.theme.as_str() {
        "system" | "light" | "dark" => settings.theme.as_str(),
        _ => "invalid",
    };
    let diagnostics = Diagnostics {
        format: "gmacftp-redacted-diagnostics",
        format_version: 1,
        privacy: "aggregate counts only; no host, username, credential, file name, or path",
        app_version: env!("CARGO_PKG_VERSION"),
        target_os: std::env::consts::OS,
        target_arch: std::env::consts::ARCH,
        locale_mode,
        theme_mode,
        background_folder_metadata: settings.background_folder_metadata,
        transfer_concurrency: settings.transfer_concurrency,
        per_server_transfer_concurrency: settings.per_server_transfer_concurrency,
        retry_count: settings.transfer_retry_count,
        bandwidth_limit_kib: settings.transfer_bandwidth_limit_kib,
        saved_sync_profiles: settings.sync_profiles.len(),
        editor_mappings: settings.editor_mappings.len(),
        recoverable_transfers,
        storage,
        connections: summary,
    };
    serde_json::to_vec_pretty(&diagnostics)
        .map_err(|error| format!("could not serialize diagnostics: {error}"))
}

pub(super) fn wire_settings(
    ui: &App,
    handle: &Handle,
    credential_store: Arc<dyn CredentialStore>,
    conns: ConnList,
    panes: Panes,
    engine: TransferEngine,
) {
    let reload_ui = ui.as_weak();
    ui.on_reload_settings(move || {
        if let Some(ui) = reload_ui.upgrade() {
            let settings = store::settings::load();
            load_settings_form(&ui, &settings);
        }
    });

    let clear_ui = ui.as_weak();
    ui.on_clear_performance_caches(move || {
        if let Ok(mut cache) = LOCAL_FOLDER_STATS_CACHE.lock() {
            cache.clear();
        }
        if let Ok(mut cache) = REMOTE_FOLDER_STATS_CACHE.lock() {
            cache.clear();
        }
        if let Some(ui) = clear_ui.upgrade() {
            ui.set_settings_message("Metadata caches cleared.".into());
            ui.set_status("Calculated folder metadata caches cleared.".into());
        }
    });

    let stats_handle = handle.clone();
    let stats_engine = engine.clone();
    let stats_ui = ui.as_weak();
    ui.on_refresh_storage_stats(move || {
        if let Some(ui) = stats_ui.upgrade() {
            ui.set_settings_storage_summary("Calculating bounded storage use…".into());
        }
        refresh_storage_stats_async(&stats_handle, stats_engine.clone(), stats_ui.clone());
    });

    let cleanup_handle = handle.clone();
    let cleanup_engine = engine.clone();
    let cleanup_ui = ui.as_weak();
    ui.on_cleanup_abandoned_temporary_files(move || {
        let ui = cleanup_ui.clone();
        let engine = cleanup_engine.clone();
        cleanup_handle.spawn(async move {
            let removed = tokio::task::spawn_blocking(|| {
                cleanup_abandoned_drag_roots_in(&std::env::temp_dir())
            })
            .await
            .unwrap_or(0);
            let stats = tokio::task::spawn_blocking(move || compute_storage_stats(&engine))
                .await
                .unwrap_or_default();
            let summary = storage_stats_summary(stats);
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(ui) = ui.upgrade() {
                    ui.set_settings_storage_summary(summary.into());
                    ui.set_settings_message(
                        format!(
                            "Removed {removed} abandoned temporary director{}; active and retained edits were kept.",
                            if removed == 1 { "y" } else { "ies" }
                        )
                        .into(),
                    );
                }
            });
        });
    });

    let folder_handle = handle.clone();
    let folder_ui = ui.as_weak();
    ui.on_choose_sync_folder(move || {
        let ui = folder_ui.clone();
        folder_handle.spawn(async move {
            let folder = rfd::AsyncFileDialog::new()
                .set_title("Choose gmacFTP sync folder")
                .pick_folder()
                .await;
            let Some(folder) = folder else {
                return;
            };
            let selected = folder.path().to_path_buf();
            let result = tokio::task::spawn_blocking(move || {
                let selected = selected
                    .canonicalize()
                    .map_err(|error| format!("could not resolve sync folder: {error}"))?;
                let metadata = std::fs::symlink_metadata(&selected)
                    .map_err(|error| format!("could not inspect sync folder: {error}"))?;
                if !metadata.is_dir() || metadata.file_type().is_symlink() {
                    return Err("sync destination must be a real local directory".to_string());
                }
                let path = selected.to_string_lossy().into_owned();
                let mut settings = store::settings::load();
                settings.sync_folder = Some(path.clone());
                store::settings::try_save(&settings).map_err(|error| error.to_string())?;
                if settings.sync_via_icloud {
                    store::cloud::push_state();
                    store::vault::repush_sync_key()?;
                }
                Ok(path)
            })
            .await
            .map_err(|error| error.to_string())
            .and_then(|result| result);
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(ui) = ui.upgrade() {
                    match result {
                        Ok(path) => {
                            ui.set_settings_sync_folder(path.into());
                            ui.set_settings_message("Sync folder updated safely.".into());
                            ui.set_error("".into());
                        }
                        Err(error) => {
                            ui.set_error(format!("Could not change sync folder: {error}").into())
                        }
                    }
                }
            });
        });
    });

    let default_folder_handle = handle.clone();
    let default_folder_ui = ui.as_weak();
    ui.on_clear_sync_folder(move || {
        let ui = default_folder_ui.clone();
        default_folder_handle.spawn(async move {
            let result = tokio::task::spawn_blocking(move || {
                let mut settings = store::settings::load();
                settings.sync_folder = None;
                store::settings::try_save(&settings).map_err(|error| error.to_string())?;
                if settings.sync_via_icloud {
                    store::cloud::push_state();
                    store::vault::repush_sync_key()?;
                }
                Ok::<(), String>(())
            })
            .await
            .map_err(|error| error.to_string())
            .and_then(|result| result);
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(ui) = ui.upgrade() {
                    match result {
                        Ok(()) => {
                            ui.set_settings_sync_folder("".into());
                            ui.set_settings_message(
                                "Automatic iCloud Drive sync folder restored.".into(),
                            );
                            ui.set_error("".into());
                        }
                        Err(error) => ui.set_error(
                            format!("Could not restore default sync folder: {error}").into(),
                        ),
                    }
                }
            });
        });
    });

    let diagnostics_handle = handle.clone();
    let diagnostics_ui = ui.as_weak();
    let diagnostics_conns = conns.clone();
    let diagnostics_engine = engine.clone();
    ui.on_export_redacted_diagnostics(move || {
        let Some(ui) = diagnostics_ui.upgrade() else {
            return;
        };
        ui.set_settings_message("Choose where to save redacted diagnostics…".into());
        let ui = diagnostics_ui.clone();
        let connections = diagnostics_conns
            .lock()
            .map(|connections| connections.clone())
            .unwrap_or_default();
        let engine = diagnostics_engine.clone();
        diagnostics_handle.spawn(async move {
            let file = rfd::AsyncFileDialog::new()
                .set_title("Export redacted gmacFTP diagnostics")
                .set_file_name("gmacftp-diagnostics.json")
                .add_filter("JSON diagnostics", &["json"])
                .save_file()
                .await;
            let Some(file) = file else {
                return;
            };
            let path = file.path().to_path_buf();
            let result = tokio::task::spawn_blocking(move || {
                let settings = store::settings::load();
                let storage = compute_storage_stats(&engine);
                let recoverable = engine.recovered_jobs().len();
                let bytes = redacted_diagnostics(&settings, &connections, storage, recoverable)?;
                store::write_private_atomic(&path, &bytes).map_err(|error| error.to_string())
            })
            .await
            .map_err(|error| error.to_string())
            .and_then(|result| result);
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(ui) = ui.upgrade() {
                    match result {
                        Ok(()) => {
                            ui.set_settings_message("Redacted diagnostics exported.".into());
                            ui.set_error("".into());
                        }
                        Err(error) => {
                            ui.set_error(format!("Could not export diagnostics: {error}").into())
                        }
                    }
                }
            });
        });
    });

    let settings_export_handle = handle.clone();
    let settings_export_ui = ui.as_weak();
    ui.on_export_encrypted_settings(move || {
        let Some(ui) = settings_export_ui.upgrade() else {
            return;
        };
        let plaintext = match settings_backup_plaintext(&store::settings::load()) {
            Ok(plaintext) => Zeroizing::new(plaintext),
            Err(error) => {
                ui.set_error(error.into());
                return;
            }
        };
        ui.set_settings_message("Choose an encrypted settings export file…".into());
        let ui = settings_export_ui.clone();
        settings_export_handle.spawn(async move {
            let file = rfd::AsyncFileDialog::new()
                .set_title("Export encrypted gmacFTP settings")
                .set_file_name("gmacftp-settings.gmftpsettings")
                .add_filter("Encrypted gmacFTP settings", &["gmftpsettings"])
                .save_file()
                .await;
            let Some(file) = file else {
                return;
            };
            if let Ok(mut pending) = PENDING_SETTINGS_CRYPTO.lock() {
                *pending = Some(PendingSettingsCrypto::Export {
                    path: file.path().to_path_buf(),
                    plaintext,
                });
            } else {
                return;
            }
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(ui) = ui.upgrade() {
                    ui.set_passphrase_value("".into());
                    ui.set_passphrase_confirm("".into());
                    ui.set_passphrase_mode("backup_export".into());
                    ui.set_passphrase_open(true);
                }
            });
        });
    });

    let settings_import_handle = handle.clone();
    let settings_import_ui = ui.as_weak();
    ui.on_import_encrypted_settings(move || {
        let Some(ui) = settings_import_ui.upgrade() else {
            return;
        };
        ui.set_settings_message("Choose an encrypted settings export…".into());
        let ui = settings_import_ui.clone();
        settings_import_handle.spawn(async move {
            let file = rfd::AsyncFileDialog::new()
                .set_title("Import encrypted gmacFTP settings")
                .add_filter("Encrypted gmacFTP settings", &["gmftpsettings"])
                .pick_file()
                .await;
            let Some(file) = file else {
                return;
            };
            let path = file.path().to_path_buf();
            let ciphertext = tokio::task::spawn_blocking(move || {
                read_regular_file_bounded(&path, store::backup::MAX_BACKUP_BYTES)
            })
            .await
            .map_err(|error| error.to_string())
            .and_then(|result| result);
            match ciphertext {
                Ok(ciphertext) => {
                    if let Ok(mut pending) = PENDING_SETTINGS_CRYPTO.lock() {
                        *pending = Some(PendingSettingsCrypto::Import { ciphertext });
                    } else {
                        return;
                    }
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(ui) = ui.upgrade() {
                            ui.set_passphrase_value("".into());
                            ui.set_passphrase_confirm("".into());
                            ui.set_passphrase_mode("backup_import".into());
                            ui.set_passphrase_open(true);
                        }
                    });
                }
                Err(error) => {
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(ui) = ui.upgrade() {
                            ui.set_error(
                                format!("Could not open encrypted settings: {error}").into(),
                            );
                        }
                    });
                }
            }
        });
    });

    let ui_weak = ui.as_weak();
    let handle = handle.clone();
    ui.on_save_settings(move || {
        let Some(ui) = ui_weak.upgrade() else {
            return;
        };
        let parse_usize = |value: &str, label: &str| -> Result<usize, String> {
            value
                .trim()
                .parse::<usize>()
                .map_err(|_| format!("{label} must be a whole non-negative number."))
        };
        let parse_u64 = |value: &str, label: &str| -> Result<u64, String> {
            value
                .trim()
                .parse::<u64>()
                .map_err(|_| format!("{label} must be a whole non-negative number."))
        };
        let parse_i64 = |value: &str, label: &str| -> Result<i64, String> {
            value
                .trim()
                .parse::<i64>()
                .map_err(|_| format!("{label} must be a whole number."))
        };
        let parse_u32 = |value: &str, label: &str| -> Result<u32, String> {
            value
                .trim()
                .parse::<u32>()
                .map_err(|_| format!("{label} must be a whole non-negative number."))
        };

        let retry_count = match parse_usize(ui.get_settings_retry_count().as_str(), "Retries") {
            Ok(value) => value,
            Err(error) => {
                ui.set_settings_message(error.into());
                return;
            }
        };
        let retry_backoff =
            match parse_u64(ui.get_settings_retry_backoff().as_str(), "Retry backoff") {
                Ok(value) => value,
                Err(error) => {
                    ui.set_settings_message(error.into());
                    return;
                }
            };
        let bandwidth_limit = match parse_u64(
            ui.get_settings_bandwidth_limit().as_str(),
            "Bandwidth limit",
        ) {
            Ok(value) => value,
            Err(error) => {
                ui.set_settings_message(error.into());
                return;
            }
        };
        let sync_tolerance =
            match parse_i64(ui.get_settings_sync_tolerance().as_str(), "Sync tolerance") {
                Ok(value) if value >= 0 => value,
                _ => {
                    ui.set_settings_message(
                        "Sync tolerance must be a whole non-negative number.".into(),
                    );
                    return;
                }
            };
        let editor_max =
            match parse_usize(ui.get_settings_editor_max_mib().as_str(), "Editor limit") {
                Ok(value) => value,
                Err(error) => {
                    ui.set_settings_message(error.into());
                    return;
                }
            };
        let editor_mappings = match store::settings::parse_editor_mappings(
            ui.get_settings_editor_mappings().as_str(),
        ) {
            Ok(mappings) => mappings,
            Err(error) => {
                ui.set_settings_message(format!("Editor mappings: {error}").into());
                return;
            }
        };
        let left_path =
            match parse_settings_local_path(ui.get_settings_left_path().as_str(), "Left pane path")
            {
                Ok(value) => value,
                Err(error) => {
                    ui.set_settings_message(error.into());
                    return;
                }
            };
        let right_path = match parse_settings_local_path(
            ui.get_settings_right_path().as_str(),
            "Right pane path",
        ) {
            Ok(value) => value,
            Err(error) => {
                ui.set_settings_message(error.into());
                return;
            }
        };
        let pane_split = match parse_u32(ui.get_settings_pane_split().as_str(), "Pane split") {
            Ok(value) => value,
            Err(error) => {
                ui.set_settings_message(error.into());
                return;
            }
        };
        let window_width = match parse_u32(ui.get_settings_window_width().as_str(), "Window width")
        {
            Ok(value) => value,
            Err(error) => {
                ui.set_settings_message(error.into());
                return;
            }
        };
        let window_height =
            match parse_u32(ui.get_settings_window_height().as_str(), "Window height") {
                Ok(value) => value,
                Err(error) => {
                    ui.set_settings_message(error.into());
                    return;
                }
            };

        let previous = store::settings::load();
        let mut settings = previous.clone();
        settings.theme = ui.get_settings_theme().to_string();
        settings.locale = ui.get_settings_locale().to_string();
        settings.show_hidden_files = ui.get_settings_show_hidden();
        settings.show_advanced_columns = ui.get_settings_show_advanced_columns();
        settings.background_folder_metadata = ui.get_settings_background_metadata();
        settings.confirm_deletes = ui.get_settings_confirm_deletes();
        settings.remote_quarantine_deletes = ui.get_settings_remote_quarantine_deletes();
        settings.restore_workspace = ui.get_settings_restore_workspace();
        settings.open_connection_manager_on_launch = ui.get_settings_open_manager_on_launch();
        settings.check_updates_automatically = ui.get_settings_check_updates_automatically();
        settings.last_left_local_path = left_path;
        settings.last_right_local_path = right_path;
        settings.pane_split_px = pane_split;
        settings.window_width_px = window_width;
        settings.window_height_px = window_height;
        settings.transfer_concurrency = ui.get_settings_transfer_concurrency().max(0) as usize;
        settings.per_server_transfer_concurrency =
            ui.get_settings_server_concurrency().max(0) as usize;
        settings.transfer_retry_count = retry_count;
        settings.transfer_retry_backoff_ms = retry_backoff;
        settings.transfer_bandwidth_limit_kib = bandwidth_limit;
        settings.existing_file_policy = ui.get_settings_existing_file_policy().to_string();
        settings.batch_error_policy = ui.get_settings_batch_error_policy().to_string();
        settings.queue_recovery_policy = ui.get_settings_queue_recovery_policy().to_string();
        settings.notify_transfer_completion = ui.get_settings_notify_transfer_completion();
        settings.notify_transfer_failure = ui.get_settings_notify_transfer_failure();
        settings.preserve_transfer_timestamps = ui.get_settings_preserve_transfer_timestamps();
        settings.preserve_transfer_permissions = ui.get_settings_preserve_transfer_permissions();
        settings.sync_comparison = ui.get_settings_sync_comparison().to_string();
        settings.sync_mtime_tolerance_secs = sync_tolerance;
        settings.sync_exclusions = ui.get_settings_sync_exclusions().to_string();
        settings.editor_max_download_mib = editor_max;
        settings.editor_auto_upload = ui.get_settings_editor_auto_upload();
        settings.editor_mappings = editor_mappings;
        settings.editor_conflict_action = ui.get_settings_editor_conflict_action().to_string();
        settings.editor_temp_retention = ui.get_settings_editor_temp_retention().to_string();
        settings.editor_retain_on_error = settings.editor_temp_retention != "cleanup";
        let settings = store::settings::validate(settings);

        if let Err(error) = store::settings::try_save(&settings) {
            ui.set_settings_message(format!("Could not save settings: {error}").into());
            return;
        }

        if !previous.notify_transfer_completion
            && !previous.notify_transfer_failure
            && (settings.notify_transfer_completion || settings.notify_transfer_failure)
        {
            crate::notifications::request_authorization();
        }

        apply_locale(&ui, &settings.locale);
        crate::Tokens::get(&ui).set_theme(effective_theme(&ui, &settings.theme).into());
        ui.set_show_hidden(settings.show_hidden_files);
        set_advanced_columns_visibility(&ui, settings.show_advanced_columns);
        ui.set_background_folder_metadata(settings.background_folder_metadata);
        ui.set_pane_split(settings.pane_split_px as f32);
        if !ui.window().is_fullscreen() && !ui.window().is_maximized() {
            ui.window().set_size(slint::PhysicalSize::new(
                settings.window_width_px,
                settings.window_height_px,
            ));
        }
        ui.set_sync_comparison(settings.sync_comparison.clone().into());
        ui.set_sync_mtime_tolerance(settings.sync_mtime_tolerance_secs.to_string().into());
        ui.set_sync_exclusions(settings.sync_exclusions.clone().into());
        ui.set_transfer_concurrency(
            engine.set_endpoint_concurrency(settings.transfer_concurrency) as i32,
        );
        engine.set_default_server_concurrency(settings.per_server_transfer_concurrency);
        engine.set_retry_policy(
            settings.transfer_retry_count,
            settings.transfer_retry_backoff_ms,
        );
        engine.set_bandwidth_limit_kib(settings.transfer_bandwidth_limit_kib);
        load_settings_form(&ui, &settings);
        crate::macos_menu::refresh_background_metadata_title();

        if previous.background_folder_metadata != settings.background_folder_metadata {
            refresh_pane(
                &handle,
                credential_store.clone(),
                panes.clone(),
                ui.as_weak(),
                0,
            );
            refresh_pane(
                &handle,
                credential_store.clone(),
                panes.clone(),
                ui.as_weak(),
                1,
            );
        } else if previous.show_hidden_files != settings.show_hidden_files {
            apply_view_pane(&ui, 0);
            apply_view_pane(&ui, 1);
        }
        ui.set_settings_open(false);
        ui.set_error("".into());
        ui.set_status("Settings saved.".into());
    });
}

pub(super) fn effective_locale(preference: &str) -> &'static str {
    match preference {
        "pl" => "pl",
        "en" => "en",
        _ if system_prefers_polish() => "pl",
        _ => "en",
    }
}

pub(super) fn system_prefers_polish() -> bool {
    #[cfg(target_os = "macos")]
    {
        use objc2_foundation::NSLocale;

        let languages = NSLocale::preferredLanguages();
        if let Some(language) = languages.firstObject() {
            return language.to_string().to_ascii_lowercase().starts_with("pl");
        }
    }
    ["LC_ALL", "LC_MESSAGES", "LANG"]
        .into_iter()
        .filter_map(|name| std::env::var(name).ok())
        .any(|locale| locale.to_ascii_lowercase().starts_with("pl"))
}

pub(super) fn apply_locale(ui: &App, preference: &str) {
    let locale = effective_locale(preference);
    let translation = if locale == "en" { "" } else { locale };
    if let Err(error) = slint::select_bundled_translation(translation) {
        tracing::warn!(%error, locale, "could not select bundled UI translation");
    }
    crate::I18n::get(ui).set_locale(locale.into());
}

pub(super) fn effective_theme(ui: &App, preference: &str) -> &'static str {
    match preference {
        "dark" => "dark",
        "light" => "light",
        _ => ui
            .window()
            .with_winit_window(|window| window.theme())
            .flatten()
            .map(|theme| match theme {
                slint::winit_030::winit::window::Theme::Dark => "dark",
                slint::winit_030::winit::window::Theme::Light => "light",
            })
            .unwrap_or("light"),
    }
}

pub(super) fn restore_window_geometry(ui: &App, settings: &store::settings::Settings) {
    if !settings.restore_workspace {
        return;
    }
    ui.window().set_size(slint::PhysicalSize::new(
        settings.window_width_px,
        settings.window_height_px,
    ));
    let (Some(x), Some(y)) = (settings.window_x_px, settings.window_y_px) else {
        return;
    };
    let width = settings.window_width_px.min(i32::MAX as u32) as i32;
    let height = settings.window_height_px.min(i32::MAX as u32) as i32;
    let is_visible = ui
        .window()
        .with_winit_window(|window| {
            window.available_monitors().any(|monitor| {
                let origin = monitor.position();
                let size = monitor.size();
                let monitor_right = origin
                    .x
                    .saturating_add(size.width.min(i32::MAX as u32) as i32);
                let monitor_bottom = origin
                    .y
                    .saturating_add(size.height.min(i32::MAX as u32) as i32);
                let window_right = x.saturating_add(width);
                let window_bottom = y.saturating_add(height);
                let visible_width = window_right.min(monitor_right) - x.max(origin.x);
                let visible_height = window_bottom.min(monitor_bottom) - y.max(origin.y);
                visible_width >= 200 && visible_height >= 80
            })
        })
        .unwrap_or(false);
    if is_visible {
        ui.window().set_position(slint::PhysicalPosition::new(x, y));
    }
}

pub(super) fn parse_settings_local_path(raw: &str, label: &str) -> Result<Option<String>, String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Ok(None);
    }
    let path = if raw == "~" {
        home_dir()
    } else if let Some(rest) = raw.strip_prefix("~/") {
        home_dir().join(rest)
    } else {
        PathBuf::from(raw)
    };
    if !path.is_absolute() {
        return Err(format!("{label} must be an absolute local folder path."));
    }
    let path = path
        .canonicalize()
        .map_err(|error| format!("{label} is unavailable: {error}"))?;
    if !path.is_dir() {
        return Err(format!("{label} must point to a local folder."));
    }
    Ok(Some(path.to_string_lossy().into_owned()))
}

pub(super) fn load_settings_form(ui: &App, settings: &store::settings::Settings) {
    ui.set_settings_theme(settings.theme.clone().into());
    ui.set_settings_locale(settings.locale.clone().into());
    ui.set_settings_show_hidden(settings.show_hidden_files);
    ui.set_settings_show_advanced_columns(settings.show_advanced_columns);
    ui.set_settings_background_metadata(settings.background_folder_metadata);
    ui.set_settings_confirm_deletes(settings.confirm_deletes);
    ui.set_settings_remote_quarantine_deletes(settings.remote_quarantine_deletes);
    ui.set_settings_restore_workspace(settings.restore_workspace);
    ui.set_settings_open_manager_on_launch(settings.open_connection_manager_on_launch);
    ui.set_settings_check_updates_automatically(settings.check_updates_automatically);
    ui.set_settings_updates_supported(gmacftp::updater::supported());
    ui.set_settings_left_path(
        settings
            .last_left_local_path
            .clone()
            .unwrap_or_default()
            .into(),
    );
    ui.set_settings_right_path(
        settings
            .last_right_local_path
            .clone()
            .unwrap_or_default()
            .into(),
    );
    ui.set_settings_pane_split(settings.pane_split_px.to_string().into());
    ui.set_settings_window_width(settings.window_width_px.to_string().into());
    ui.set_settings_window_height(settings.window_height_px.to_string().into());
    ui.set_settings_transfer_concurrency(settings.transfer_concurrency as i32);
    ui.set_settings_server_concurrency(settings.per_server_transfer_concurrency as i32);
    ui.set_settings_retry_count(settings.transfer_retry_count.to_string().into());
    ui.set_settings_retry_backoff(settings.transfer_retry_backoff_ms.to_string().into());
    ui.set_settings_bandwidth_limit(settings.transfer_bandwidth_limit_kib.to_string().into());
    ui.set_settings_existing_file_policy(settings.existing_file_policy.clone().into());
    ui.set_settings_batch_error_policy(settings.batch_error_policy.clone().into());
    ui.set_settings_queue_recovery_policy(settings.queue_recovery_policy.clone().into());
    ui.set_settings_notify_transfer_completion(settings.notify_transfer_completion);
    ui.set_settings_notify_transfer_failure(settings.notify_transfer_failure);
    ui.set_settings_preserve_transfer_timestamps(settings.preserve_transfer_timestamps);
    ui.set_settings_preserve_transfer_permissions(settings.preserve_transfer_permissions);
    ui.set_settings_sync_comparison(settings.sync_comparison.clone().into());
    ui.set_settings_sync_tolerance(settings.sync_mtime_tolerance_secs.to_string().into());
    ui.set_settings_sync_exclusions(settings.sync_exclusions.clone().into());
    ui.set_settings_editor_max_mib(settings.editor_max_download_mib.to_string().into());
    ui.set_settings_editor_auto_upload(settings.editor_auto_upload);
    ui.set_settings_editor_retain_on_error(settings.editor_retain_on_error);
    ui.set_settings_editor_mappings(
        store::settings::format_editor_mappings(&settings.editor_mappings).into(),
    );
    ui.set_settings_editor_conflict_action(settings.editor_conflict_action.clone().into());
    ui.set_settings_editor_temp_retention(settings.editor_temp_retention.clone().into());
    ui.set_settings_sync_folder(settings.sync_folder.clone().unwrap_or_default().into());
    ui.set_settings_message("".into());
}
