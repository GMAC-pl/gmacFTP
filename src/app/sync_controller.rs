//! Folder-sync context validation, mirror deletion, preview, and redacted reporting.

use super::*;

pub(super) fn refresh_sync_profile_model(
    ui: &App,
    profiles: &[store::settings::SyncProfile],
    selected: Option<usize>,
) {
    let names = profiles
        .iter()
        .map(|profile| slint::SharedString::from(profile.name.clone()))
        .collect::<Vec<_>>();
    ui.set_sync_profile_names(ModelRc::from(Rc::new(VecModel::from(names))));
    ui.set_sync_profile_selected(
        selected
            .filter(|index| *index < profiles.len())
            .and_then(|index| i32::try_from(index).ok())
            .unwrap_or(-1),
    );
}

pub(super) fn sync_endpoint_fingerprint(spec: &ConnectionSpec) -> Result<String, String> {
    use sha2::Digest;

    let key = CredentialKey::for_spec(spec).map_err(|error| error.to_string())?;
    let identity = format!(
        "{}\0{}\0{}\0{}",
        key.protocol(),
        key.host(),
        key.port(),
        key.user()
    );
    let digest = sha2::Sha256::digest(identity.as_bytes());
    Ok(digest.iter().map(|byte| format!("{byte:02x}")).collect())
}

pub(super) fn parse_folder_sync_options(
    direction: TransferDirection,
    comparison: &str,
    tolerance: &str,
    server_clock_offset: &str,
    mode: &str,
) -> Result<gmacftp::folder_sync::SyncOptions, String> {
    const MAX_TOLERANCE_SECONDS: u64 = 24 * 60 * 60;
    const MAX_CLOCK_OFFSET_SECONDS: i64 = 24 * 60 * 60;
    let comparison = match comparison {
        "size_only" => gmacftp::folder_sync::SyncComparison::SizeOnly,
        "checksum" => gmacftp::folder_sync::SyncComparison::Checksum,
        "size_mtime" => gmacftp::folder_sync::SyncComparison::SizeAndModificationTime,
        _ => return Err("unknown folder-sync comparison method".into()),
    };
    let tolerance = tolerance
        .trim()
        .parse::<u64>()
        .map_err(|_| "timestamp tolerance must be a whole number of seconds".to_string())?;
    if tolerance > MAX_TOLERANCE_SECONDS {
        return Err(format!(
            "timestamp tolerance cannot exceed {MAX_TOLERANCE_SECONDS} seconds"
        ));
    }
    let server_clock_offset = server_clock_offset
        .trim()
        .parse::<i64>()
        .map_err(|_| "server clock offset must be a whole number of seconds".to_string())?;
    if server_clock_offset.unsigned_abs() > MAX_CLOCK_OFFSET_SECONDS as u64 {
        return Err(format!(
            "server clock offset must stay within ±{MAX_CLOCK_OFFSET_SECONDS} seconds"
        ));
    }
    let remote_adjustment = server_clock_offset
        .checked_neg()
        .ok_or_else(|| "server clock offset is out of range".to_string())?;
    let (source_time_adjustment_seconds, target_time_adjustment_seconds) = match direction {
        TransferDirection::Upload => (0, remote_adjustment),
        TransferDirection::Download => (remote_adjustment, 0),
    };
    Ok(gmacftp::folder_sync::SyncOptions {
        mode: match mode {
            "one_way" => gmacftp::folder_sync::SyncMode::OneWay,
            "mirror" => gmacftp::folder_sync::SyncMode::Mirror,
            _ => return Err("unknown folder-sync mode".into()),
        },
        comparison,
        mtime_tolerance_seconds: tolerance,
        source_time_adjustment_seconds,
        target_time_adjustment_seconds,
    })
}

pub(super) fn start_folder_sync_scan(
    handle: Handle,
    store: Arc<dyn CredentialStore>,
    panes: Panes,
    engine: TransferEngine,
    idx: Arc<Mutex<HashMap<i32, usize>>>,
    ui: Weak<App>,
    direction: String,
    exclusions: String,
    comparison: String,
    tolerance: String,
    server_clock_offset: String,
    mode: String,
    mirror_confirmed: bool,
    apply: bool,
) {
    let direction = match SyncDirection::try_from(direction.as_str()) {
        Ok(direction) => TransferDirection::from(direction),
        Err(error) => {
            if let Some(ui) = ui.upgrade() {
                ui.set_sync_summary(error.into());
                ui.set_error("Invalid synchronization direction.".into());
            }
            return;
        }
    };
    let options = match parse_folder_sync_options(
        direction,
        &comparison,
        &tolerance,
        &server_clock_offset,
        &mode,
    ) {
        Ok(options) => options,
        Err(error) => {
            if let Some(ui) = ui.upgrade() {
                ui.set_sync_summary(format!("Invalid comparison settings: {error}").into());
                ui.set_error(format!("Invalid sync comparison settings: {error}").into());
            }
            return;
        }
    };
    let exclusions = match gmacftp::folder_sync::parse_exclusions(&exclusions) {
        Ok(exclusions) => exclusions,
        Err(error) => {
            if let Some(ui) = ui.upgrade() {
                ui.set_sync_summary(format!("Invalid exclusions: {error}").into());
                ui.set_error(format!("Invalid sync exclusions: {error}").into());
            }
            return;
        }
    };
    let context = match folder_sync_context(&panes) {
        Ok(context) => context,
        Err(error) => {
            if let Some(ui) = ui.upgrade() {
                ui.set_sync_summary(error.clone().into());
                ui.set_error(error.into());
            }
            return;
        }
    };
    let expected = if apply {
        PENDING_FOLDER_SYNC
            .lock()
            .ok()
            .and_then(|pending| pending.clone())
    } else {
        None
    };
    if apply && expected.is_none() {
        if let Some(ui) = ui.upgrade() {
            ui.set_sync_summary("Run a dry-run preview before applying.".into());
        }
        return;
    }
    if apply
        && options.mode == gmacftp::folder_sync::SyncMode::Mirror
        && !mirror_confirmed
        && expected
            .as_ref()
            .is_some_and(|prepared| prepared.deletions.iter().any(|item| item.included))
    {
        if let Some(ui) = ui.upgrade() {
            ui.set_sync_summary(
                "Confirm the mirror deletion warning before applying selected deletions.".into(),
            );
        }
        return;
    }
    let Some(password) = password_for(&store, &context.spec) else {
        if let Some(ui) = ui.upgrade() {
            ui.set_sync_summary("The server credential is unavailable.".into());
            ui.set_error("missing credential".into());
        }
        return;
    };
    let generation = FOLDER_SYNC_GENERATION.fetch_add(1, AtomicOrdering::Relaxed) + 1;
    if let Some(ui) = ui.upgrade() {
        ui.set_error("".into());
        ui.set_sync_scanning(true);
        ui.set_sync_summary(
            if apply {
                "Rechecking both folders before applying…"
            } else {
                "Scanning both folders for a dry-run preview…"
            }
            .into(),
        );
        if !apply {
            ui.set_sync_preview_ready(false);
            ui.set_sync_rows(ModelRc::from(Rc::new(
                VecModel::from(Vec::<SyncRow>::new()),
            )));
        }
    }
    handle.clone().spawn(async move {
        let prepared = prepare_folder_sync(context, direction, exclusions, options, password).await;
        if FOLDER_SYNC_GENERATION.load(AtomicOrdering::Relaxed) != generation {
            return;
        }
        let mut prepared = match prepared {
            Ok(prepared) => prepared,
            Err(error) => {
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(ui) = ui.upgrade() {
                        ui.set_sync_scanning(false);
                        ui.set_sync_preview_ready(false);
                        ui.set_sync_summary(format!("Sync preview failed: {error}").into());
                        ui.set_error(format!("Sync preview failed: {error}").into());
                    }
                });
                return;
            }
        };
        if !folder_sync_context_is_current(&panes, &prepared.context.key) {
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(ui) = ui.upgrade() {
                    ui.set_sync_scanning(false);
                    ui.set_sync_preview_ready(false);
                    ui.set_sync_summary(
                        "A pane changed during the scan; run the preview again.".into(),
                    );
                }
            });
            return;
        }

        if let Some(expected) = expected.as_ref() {
            let same_policy = expected.context.key == prepared.context.key
                && expected.direction == prepared.direction
                && expected.exclusions == prepared.exclusions
                && expected.options == prepared.options;
            if same_policy {
                let copy_selection = expected
                    .candidates
                    .iter()
                    .map(|item| (item.label.as_str(), item.included))
                    .collect::<HashMap<_, _>>();
                for candidate in &mut prepared.candidates {
                    if let Some(included) = copy_selection.get(candidate.label.as_str()) {
                        candidate.included = *included;
                    }
                }
                let deletion_selection = expected
                    .deletions
                    .iter()
                    .map(|item| (item.label.as_str(), item.included))
                    .collect::<HashMap<_, _>>();
                for deletion in &mut prepared.deletions {
                    if let Some(included) = deletion_selection.get(deletion.label.as_str()) {
                        deletion.included = *included;
                    }
                }
            }
        }

        if !apply {
            if let Ok(mut pending) = PENDING_FOLDER_SYNC.lock() {
                *pending = Some(prepared.clone());
            }
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(ui) = ui.upgrade() {
                    ui.set_sync_mirror_confirmed(false);
                    show_folder_sync_preview(&ui, &prepared, false);
                }
            });
            return;
        }

        let expected = expected.expect("apply path checked above");
        let unchanged = expected.context.key == prepared.context.key
            && expected.direction == prepared.direction
            && expected.exclusions == prepared.exclusions
            && expected.options == prepared.options
            && expected.preview == prepared.preview
            && expected.candidates == prepared.candidates
            && expected.deletions == prepared.deletions;
        if !unchanged {
            if let Ok(mut pending) = PENDING_FOLDER_SYNC.lock() {
                *pending = Some(prepared.clone());
            }
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(ui) = ui.upgrade() {
                    ui.set_sync_mirror_confirmed(false);
                    show_folder_sync_preview(&ui, &prepared, true);
                }
            });
            return;
        }

        let plans = prepared
            .candidates
            .iter()
            .filter(|candidate| candidate.included)
            .map(|candidate| PlannedXfer {
                id: fresh_xfer_id(),
                label: candidate.label.clone(),
                local_path: candidate.local_path.clone(),
                remote_path: candidate.remote_path.clone(),
                bytes_total: Some(candidate.bytes),
            })
            .collect::<Vec<_>>();
        let deletions = prepared
            .deletions
            .iter()
            .filter(|deletion| deletion.included)
            .cloned()
            .collect::<Vec<_>>();
        if plans.is_empty() && deletions.is_empty() {
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(ui) = ui.upgrade() {
                    ui.set_sync_scanning(false);
                    ui.set_sync_summary(
                        "Nothing is selected. Select at least one copy or deletion action.".into(),
                    );
                }
            });
            return;
        }
        if let Ok(mut pending) = PENDING_FOLDER_SYNC.lock() {
            *pending = None;
        }
        let count = plans.len();
        let context = prepared.context.clone();
        let spec = context.spec.clone();
        let host = spec.host.clone();
        let direction = prepared.direction;
        let batch = fresh_batch(count > 1);
        let mirror_pending = (!deletions.is_empty()).then(|| PendingMirrorBatch {
            context,
            direction,
            job_ids: plans.iter().map(|plan| plan.id).collect(),
            finished: HashSet::new(),
            failed: false,
            deletions,
        });
        if !plans.is_empty() {
            if let Some(pending) = mirror_pending.clone() {
                let Ok(mut batches) = PENDING_MIRROR_BATCHES.lock() else {
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(ui) = ui.upgrade() {
                            ui.set_sync_scanning(false);
                            ui.set_error(
                                "Could not initialize the mirror safety tracker; nothing was queued."
                                    .into(),
                            );
                        }
                    });
                    return;
                };
                batches.insert(batch.id, pending);
            }
        }
        let close_ui = ui.clone();
        let has_deletions = mirror_pending.is_some();
        let _ = slint::invoke_from_event_loop(move || {
            if let Some(ui) = close_ui.upgrade() {
                ui.set_sync_scanning(false);
                ui.set_sync_open(false);
                ui.set_status(
                    if count == 0 && has_deletions {
                        "rechecking selected mirror deletions…".into()
                    } else if has_deletions {
                        format!(
                            "queued {count} synchronized file(s); deletions wait for every copy…"
                        )
                        .into()
                    } else {
                        format!("queued {count} synchronized file(s)…").into()
                    },
                );
            }
        });
        if !plans.is_empty() {
            stream_folder_transfers(
                &engine,
                ui,
                idx,
                spec,
                direction,
                host,
                plans,
                format!("synchronizing {count} files…"),
                batch,
            )
            .await;
        } else if let Some(pending) = mirror_pending {
            run_mirror_deletions(handle, store, panes, ui, pending).await;
        }
    });
}

pub(super) fn wire_folder_sync(
    ui: &App,
    handle: &Handle,
    store: Arc<dyn CredentialStore>,
    sessions: Sessions,
    panes: Panes,
    engine: TransferEngine,
    idx: Arc<Mutex<HashMap<i32, usize>>>,
) {
    let open_panes = panes.clone();
    let open_ui = ui.as_weak();
    ui.on_open_folder_sync(move || {
        let Some(ui) = open_ui.upgrade() else {
            return;
        };
        if let Err(error) = folder_sync_context(&open_panes) {
            ui.set_error(error.into());
            return;
        }
        FOLDER_SYNC_GENERATION.fetch_add(1, AtomicOrdering::Relaxed);
        if let Ok(mut pending) = PENDING_FOLDER_SYNC.lock() {
            *pending = None;
        }
        let settings = store::settings::load();
        ui.set_sync_direction("upload".into());
        ui.set_sync_mode("one_way".into());
        ui.set_sync_mirror_confirmed(false);
        ui.set_sync_exclusions(settings.sync_exclusions.clone().into());
        ui.set_sync_comparison(settings.sync_comparison.clone().into());
        ui.set_sync_mtime_tolerance(settings.sync_mtime_tolerance_secs.to_string().into());
        ui.set_sync_server_clock_offset("0".into());
        ui.set_sync_profile_name("".into());
        refresh_sync_profile_model(&ui, &settings.sync_profiles, None);
        ui.set_sync_summary("Choose a direction, then run the dry-run preview.".into());
        ui.set_sync_rows(ModelRc::from(Rc::new(
            VecModel::from(Vec::<SyncRow>::new()),
        )));
        ui.set_sync_preview_ready(false);
        ui.set_sync_scanning(false);
        ui.set_sync_open(true);
    });

    let (preview_handle, preview_store, preview_panes, preview_engine, preview_idx, preview_ui) = (
        handle.clone(),
        store.clone(),
        panes.clone(),
        engine.clone(),
        idx.clone(),
        ui.as_weak(),
    );
    ui.on_preview_folder_sync(
        move |direction, exclusions, comparison, tolerance, server_clock_offset, mode| {
            start_folder_sync_scan(
                preview_handle.clone(),
                preview_store.clone(),
                preview_panes.clone(),
                preview_engine.clone(),
                preview_idx.clone(),
                preview_ui.clone(),
                direction.to_string(),
                exclusions.to_string(),
                comparison.to_string(),
                tolerance.to_string(),
                server_clock_offset.to_string(),
                mode.to_string(),
                false,
                false,
            );
        },
    );

    let toggle_ui = ui.as_weak();
    ui.on_toggle_sync_row(move |row| {
        let Some(ui) = toggle_ui.upgrade() else {
            return;
        };
        if ui.get_sync_scanning() {
            return;
        }
        let Ok(row) = usize::try_from(row) else {
            return;
        };
        let Ok(mut pending) = PENDING_FOLDER_SYNC.lock() else {
            return;
        };
        let Some(prepared) = pending.as_mut() else {
            return;
        };
        let changed = if let Some(candidate) = prepared.candidates.get_mut(row) {
            candidate.included = !candidate.included;
            true
        } else {
            prepared
                .deletions
                .get_mut(row.saturating_sub(prepared.candidates.len()))
                .map(|deletion| {
                    deletion.included = !deletion.included;
                })
                .is_some()
        };
        if changed {
            ui.set_sync_mirror_confirmed(false);
            show_folder_sync_preview(&ui, prepared, false);
        }
    });

    let save_profile_ui = ui.as_weak();
    let save_profile_panes = panes.clone();
    ui.on_save_sync_profile(move |name| {
        let Some(ui) = save_profile_ui.upgrade() else {
            return;
        };
        let name = name.trim();
        if name.is_empty() || name.len() > 128 || name.chars().any(char::is_control) {
            ui.set_sync_summary("Profile name must contain 1–128 printable characters.".into());
            return;
        }
        let context = match folder_sync_context(&save_profile_panes) {
            Ok(context) => context,
            Err(error) => {
                ui.set_sync_summary(error.into());
                return;
            }
        };
        let direction = match SyncDirection::try_from(ui.get_sync_direction().as_str()) {
            Ok(direction) => TransferDirection::from(direction),
            Err(error) => {
                ui.set_sync_summary(format!("Cannot save profile: {error}").into());
                return;
            }
        };
        if let Err(error) = parse_folder_sync_options(
            direction,
            ui.get_sync_comparison().as_str(),
            ui.get_sync_mtime_tolerance().as_str(),
            ui.get_sync_server_clock_offset().as_str(),
            ui.get_sync_mode().as_str(),
        ) {
            ui.set_sync_summary(format!("Cannot save profile: {error}").into());
            return;
        }
        let exclusions =
            match gmacftp::folder_sync::parse_exclusions(ui.get_sync_exclusions().as_str()) {
                Ok(exclusions) => exclusions.join(", "),
                Err(error) => {
                    ui.set_sync_summary(format!("Cannot save profile: {error}").into());
                    return;
                }
            };
        let tolerance = ui
            .get_sync_mtime_tolerance()
            .as_str()
            .trim()
            .parse::<i64>()
            .expect("validated above");
        let clock_offset = ui
            .get_sync_server_clock_offset()
            .as_str()
            .trim()
            .parse::<i64>()
            .expect("validated above");
        let endpoint_fingerprint = match sync_endpoint_fingerprint(&context.spec) {
            Ok(fingerprint) => fingerprint,
            Err(error) => {
                ui.set_sync_summary(
                    format!("Cannot identify this profile's server safely: {error}").into(),
                );
                return;
            }
        };
        let profile = store::settings::SyncProfile {
            name: name.to_string(),
            connection_id: context.key.connection_id.0,
            endpoint_fingerprint,
            local_root: context.key.local_root.to_string_lossy().into_owned(),
            remote_root: context.key.remote_root,
            direction: ui.get_sync_direction().to_string(),
            mode: ui.get_sync_mode().to_string(),
            comparison: ui.get_sync_comparison().to_string(),
            mtime_tolerance_secs: tolerance,
            server_clock_offset_secs: clock_offset,
            exclusions,
        };
        let mut settings = store::settings::load();
        let canonical_name = name.to_lowercase();
        let existing = settings
            .sync_profiles
            .iter()
            .position(|saved| saved.name.to_lowercase() == canonical_name);
        if existing.is_none() && settings.sync_profiles.len() >= store::settings::MAX_SYNC_PROFILES
        {
            ui.set_sync_summary(
                format!(
                    "At most {} synchronization profiles can be saved.",
                    store::settings::MAX_SYNC_PROFILES
                )
                .into(),
            );
            return;
        }
        let selected = if let Some(index) = existing {
            settings.sync_profiles[index] = profile;
            index
        } else {
            settings.sync_profiles.push(profile);
            settings.sync_profiles.len() - 1
        };
        if let Err(error) = store::settings::try_save(&settings) {
            ui.set_sync_summary(format!("Could not save sync profile: {error}").into());
            return;
        }
        let settings = store::settings::load();
        let selected = settings
            .sync_profiles
            .iter()
            .position(|profile| profile.name.to_lowercase() == canonical_name)
            .unwrap_or(selected.min(settings.sync_profiles.len().saturating_sub(1)));
        refresh_sync_profile_model(&ui, &settings.sync_profiles, Some(selected));
        ui.set_sync_profile_name(name.into());
        ui.set_sync_summary(format!("Saved synchronization profile “{name}”.").into());
    });

    let load_profile_ui = ui.as_weak();
    let load_profile_handle = handle.clone();
    let load_profile_store = store.clone();
    let load_profile_sessions = sessions.clone();
    let load_profile_panes = panes.clone();
    ui.on_load_sync_profile(move |index| {
        let Some(ui) = load_profile_ui.upgrade() else {
            return;
        };
        let Ok(index) = usize::try_from(index) else {
            return;
        };
        let settings = store::settings::load();
        let Some(profile) = settings.sync_profiles.get(index).cloned() else {
            refresh_sync_profile_model(&ui, &settings.sync_profiles, None);
            return;
        };
        let context = match folder_sync_context(&load_profile_panes) {
            Ok(context) => context,
            Err(error) => {
                ui.set_sync_summary(error.into());
                return;
            }
        };
        let endpoint_matches = sync_endpoint_fingerprint(&context.spec)
            .is_ok_and(|fingerprint| fingerprint == profile.endpoint_fingerprint);
        if context.key.connection_id.0 != profile.connection_id || !endpoint_matches {
            ui.set_sync_summary(
                "Connect the exact server referenced by this profile in the remote pane first."
                    .into(),
            );
            return;
        }
        let local_root = match parse_settings_local_path(&profile.local_root, "Profile folder") {
            Ok(Some(path)) => path,
            Ok(None) => {
                ui.set_sync_summary("The profile has no local folder.".into());
                return;
            }
            Err(error) => {
                ui.set_sync_summary(error.into());
                return;
            }
        };
        {
            let Ok(mut panes) = load_profile_panes.lock() else {
                ui.set_sync_summary("Could not update panes for this profile.".into());
                return;
            };
            if panes
                .get(context.key.remote_pane)
                .and_then(|pane| pane.conn.as_ref())
                .map(|spec| spec.id.0)
                != Some(profile.connection_id)
            {
                ui.set_sync_summary(
                    "The remote connection changed; profile was not loaded.".into(),
                );
                return;
            }
            panes[context.key.local_pane].cwd = local_root.clone();
            panes[context.key.local_pane].nav.go(local_root);
            panes[context.key.remote_pane].cwd = profile.remote_root.clone();
            panes[context.key.remote_pane]
                .nav
                .go(profile.remote_root.clone());
        }
        save_pane_session(
            &load_profile_sessions,
            &load_profile_panes,
            context.key.remote_pane,
        );
        FOLDER_SYNC_GENERATION.fetch_add(1, AtomicOrdering::Relaxed);
        if let Ok(mut pending) = PENDING_FOLDER_SYNC.lock() {
            *pending = None;
        }
        ui.set_sync_direction(profile.direction.into());
        ui.set_sync_mode(profile.mode.into());
        ui.set_sync_comparison(profile.comparison.into());
        ui.set_sync_mtime_tolerance(profile.mtime_tolerance_secs.to_string().into());
        ui.set_sync_server_clock_offset(profile.server_clock_offset_secs.to_string().into());
        ui.set_sync_exclusions(profile.exclusions.into());
        ui.set_sync_profile_name(profile.name.clone().into());
        ui.set_sync_mirror_confirmed(false);
        ui.set_sync_preview_ready(false);
        ui.set_sync_rows(ModelRc::from(Rc::new(
            VecModel::from(Vec::<SyncRow>::new()),
        )));
        ui.set_sync_summary(
            format!(
                "Loaded profile “{}”; run a fresh dry-run preview.",
                profile.name
            )
            .into(),
        );
        ui.set_error("".into());
        refresh_sync_profile_model(&ui, &settings.sync_profiles, Some(index));
        refresh_pane(
            &load_profile_handle,
            load_profile_store.clone(),
            load_profile_panes.clone(),
            ui.as_weak(),
            context.key.local_pane,
        );
        refresh_pane(
            &load_profile_handle,
            load_profile_store.clone(),
            load_profile_panes.clone(),
            ui.as_weak(),
            context.key.remote_pane,
        );
    });

    let delete_profile_ui = ui.as_weak();
    ui.on_delete_sync_profile(move |index| {
        let Some(ui) = delete_profile_ui.upgrade() else {
            return;
        };
        let Ok(index) = usize::try_from(index) else {
            return;
        };
        let mut settings = store::settings::load();
        if index >= settings.sync_profiles.len() {
            refresh_sync_profile_model(&ui, &settings.sync_profiles, None);
            return;
        }
        let name = settings.sync_profiles.remove(index).name;
        if let Err(error) = store::settings::try_save(&settings) {
            ui.set_sync_summary(format!("Could not delete sync profile: {error}").into());
            return;
        }
        refresh_sync_profile_model(&ui, &settings.sync_profiles, None);
        ui.set_sync_profile_name("".into());
        ui.set_sync_summary(format!("Deleted synchronization profile “{name}”.").into());
    });

    let export_ui = ui.as_weak();
    let export_handle = handle.clone();
    ui.on_export_sync_report(move || {
        let Some(ui) = export_ui.upgrade() else {
            return;
        };
        let prepared = PENDING_FOLDER_SYNC
            .lock()
            .ok()
            .and_then(|pending| pending.clone());
        let Some(prepared) = prepared else {
            ui.set_sync_summary("Run a dry-run preview before exporting a report.".into());
            return;
        };
        let bytes = match folder_sync_report_bytes(&prepared) {
            Ok(bytes) => bytes,
            Err(error) => {
                ui.set_sync_summary(error.into());
                return;
            }
        };
        ui.set_sync_summary(
            "Choose where to save the redacted dry-run report (relative paths only)…".into(),
        );
        let ui_weak = export_ui.clone();
        export_handle.spawn(async move {
            let file = rfd::AsyncFileDialog::new()
                .set_title("Export gmacFTP synchronization dry-run")
                .set_file_name("gmacftp-sync-report.json")
                .add_filter("JSON report", &["json"])
                .save_file()
                .await;
            let Some(file) = file else {
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(ui) = ui_weak.upgrade() {
                        ui.set_sync_summary("Sync report export cancelled.".into());
                    }
                });
                return;
            };
            let path = file.path().to_path_buf();
            let result = tokio::task::spawn_blocking(move || {
                store::write_private_atomic(&path, &bytes).map_err(|error| error.to_string())
            })
            .await
            .map_err(|error| error.to_string())
            .and_then(|result| result);
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(ui) = ui_weak.upgrade() {
                    match result {
                        Ok(()) => {
                            ui.set_sync_summary("Redacted synchronization report exported.".into());
                            ui.set_error("".into());
                        }
                        Err(error) => ui.set_error(
                            format!("Could not export synchronization report: {error}").into(),
                        ),
                    }
                }
            });
        });
    });

    let (apply_handle, apply_store, apply_panes, apply_engine, apply_idx, apply_ui) = (
        handle.clone(),
        store.clone(),
        panes.clone(),
        engine.clone(),
        idx.clone(),
        ui.as_weak(),
    );
    ui.on_apply_folder_sync(
        move |direction,
              exclusions,
              comparison,
              tolerance,
              server_clock_offset,
              mode,
              mirror_confirmed| {
            start_folder_sync_scan(
                apply_handle.clone(),
                apply_store.clone(),
                apply_panes.clone(),
                apply_engine.clone(),
                apply_idx.clone(),
                apply_ui.clone(),
                direction.to_string(),
                exclusions.to_string(),
                comparison.to_string(),
                tolerance.to_string(),
                server_clock_offset.to_string(),
                mode.to_string(),
                mirror_confirmed,
                true,
            );
        },
    );
}

/// One planned file in a folder transfer (the Send-friendly payload built off the UI thread; the
/// panel row is materialised from it on the UI thread because Slint models are !Send).
pub(super) fn sync_metadata_matches(
    expected: gmacftp::folder_sync::SyncFileMetadata,
    actual_bytes: u64,
    actual_modified: Option<i64>,
) -> bool {
    expected.bytes == actual_bytes && expected.modified == actual_modified
}

pub(super) fn local_sync_file_metadata(
    path: &Path,
) -> Result<Option<gmacftp::folder_sync::SyncFileMetadata>, String> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("cannot inspect {}: {error}", path.display())),
    };
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(format!("{} is no longer a regular file", path.display()));
    }
    let modified = metadata
        .modified()
        .ok()
        .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
        .and_then(|duration| i64::try_from(duration.as_secs()).ok());
    Ok(Some(gmacftp::folder_sync::SyncFileMetadata {
        bytes: metadata.len(),
        modified,
        sha256: None,
    }))
}

#[derive(Default)]
struct MirrorDeletionReport {
    deleted: usize,
    skipped: usize,
    failed: usize,
    first_problem: Option<String>,
}

impl MirrorDeletionReport {
    fn skip(&mut self, problem: String) {
        self.skipped += 1;
        self.first_problem.get_or_insert(problem);
    }

    fn fail(&mut self, problem: String) {
        self.failed += 1;
        self.first_problem.get_or_insert(problem);
    }

    fn skip_many(&mut self, count: usize, problem: String) {
        self.skipped = self.skipped.saturating_add(count);
        self.first_problem.get_or_insert(problem);
    }
}

pub(super) fn folder_sync_context(panes: &Panes) -> Result<FolderSyncContext, String> {
    let panes = panes
        .lock()
        .map_err(|_| "could not inspect the panes".to_string())?;
    let local = panes
        .iter()
        .enumerate()
        .filter(|(_, pane)| matches!(pane.kind, PaneKind::Local))
        .collect::<Vec<_>>();
    let remote = panes
        .iter()
        .enumerate()
        .filter(|(_, pane)| matches!(pane.kind, PaneKind::Remote))
        .collect::<Vec<_>>();
    if local.len() != 1 || remote.len() != 1 {
        return Err(
            "folder sync requires exactly one local pane and one connected server pane".to_string(),
        );
    }
    let (local_pane, local) = local[0];
    let (remote_pane, remote) = remote[0];
    let spec = remote
        .conn
        .clone()
        .ok_or_else(|| "the remote pane is not connected".to_string())?;
    Ok(FolderSyncContext {
        key: FolderSyncContextKey {
            local_pane,
            remote_pane,
            local_root: PathBuf::from(&local.cwd),
            remote_root: remote.cwd.clone(),
            connection_id: spec.id,
        },
        spec,
    })
}

pub(super) fn folder_sync_context_is_current(
    panes: &Panes,
    expected: &FolderSyncContextKey,
) -> bool {
    let Ok(panes) = panes.lock() else {
        return false;
    };
    let Some(local) = panes.get(expected.local_pane) else {
        return false;
    };
    let Some(remote) = panes.get(expected.remote_pane) else {
        return false;
    };
    matches!(local.kind, PaneKind::Local)
        && Path::new(&local.cwd) == expected.local_root
        && matches!(remote.kind, PaneKind::Remote)
        && remote.cwd == expected.remote_root
        && remote.conn.as_ref().map(|spec| spec.id) == Some(expected.connection_id)
}

pub(super) async fn remote_sync_snapshot(
    context: &FolderSyncContext,
    password: &str,
) -> Result<BTreeMap<String, (String, gmacftp::folder_sync::SyncFileMetadata)>, String> {
    let files =
        net::walk_remote_metadata(&context.spec, password, context.key.remote_root.as_str())
            .await
            .map_err(|error| format!("remote safety scan failed: {error}"))?;
    let mut snapshot = BTreeMap::new();
    for file in files {
        let relative = remote_sync_relative(&context.key.remote_root, &file.path)?;
        let metadata = gmacftp::folder_sync::SyncFileMetadata {
            bytes: file.size,
            modified: file.mtime,
            sha256: None,
        };
        if snapshot
            .insert(relative.clone(), (file.path, metadata))
            .is_some()
        {
            return Err(format!(
                "server returned a duplicate path during the safety scan: {relative}"
            ));
        }
    }
    Ok(snapshot)
}

pub(super) fn delete_local_mirror_target(
    local_root: &Path,
    deletion: &FolderSyncDeletion,
) -> Result<bool, String> {
    let expected_path = remote_local_target(local_root, &deletion.label)
        .map_err(|error| format!("{}: unsafe local path: {error}", deletion.label))?;
    let stored_path = PathBuf::from(&deletion.local_path);
    if stored_path != expected_path {
        return Err(format!("{}: local target path changed", deletion.label));
    }
    net::assert_within(local_root, &stored_path)
        .map_err(|error| format!("{}: unsafe local target: {error}", deletion.label))?;
    let Some(current) = local_sync_file_metadata(&stored_path)? else {
        return Ok(false);
    };
    if !sync_metadata_matches(deletion.metadata, current.bytes, current.modified) {
        return Ok(false);
    }
    trash::delete(&stored_path)
        .map_err(|error| format!("{}: could not move to Trash: {error}", deletion.label))?;
    Ok(true)
}

fn finish_mirror_deletions(
    handle: Handle,
    store: Arc<dyn CredentialStore>,
    panes: Panes,
    ui: Weak<App>,
    report: MirrorDeletionReport,
) {
    let status = format!(
        "mirror complete: {} deleted, {} skipped by safety checks, {} failed",
        report.deleted, report.skipped, report.failed
    );
    let problem = report.first_problem;
    let should_refresh = report.deleted > 0;
    let _ = slint::invoke_from_event_loop(move || {
        if let Some(ui) = ui.upgrade() {
            ui.set_status(status.into());
            ui.set_error(
                problem
                    .map(|problem| format!("Mirror safety: {problem}"))
                    .unwrap_or_default()
                    .into(),
            );
            if should_refresh {
                refresh_both_panes(&handle, store, panes, ui.as_weak());
            }
        }
    });
}

/// Apply only mirror deletions selected by the user. Copy jobs must have completed successfully
/// before this function is called. It then performs another source/target safety scan and skips
/// individual files that appeared at the source, changed at the target, disappeared, became a
/// symlink/special file, or cannot be removed. One bad item never blocks the remaining deletions.
pub(super) async fn run_mirror_deletions(
    handle: Handle,
    store: Arc<dyn CredentialStore>,
    panes: Panes,
    ui: Weak<App>,
    pending: PendingMirrorBatch,
) {
    let mut report = MirrorDeletionReport::default();
    let deletions = pending
        .deletions
        .into_iter()
        .filter(|deletion| deletion.included)
        .collect::<Vec<_>>();
    if deletions.is_empty() {
        finish_mirror_deletions(handle, store, panes, ui, report);
        return;
    }
    if !folder_sync_context_is_current(&panes, &pending.context.key) {
        report.skip_many(
            deletions.len(),
            "pane or synchronized folder changed before deletion; nothing was removed".into(),
        );
        finish_mirror_deletions(handle, store, panes, ui, report);
        return;
    }
    let Some(password) = password_for(&store, &pending.context.spec) else {
        report.skip_many(
            deletions.len(),
            "server credential became unavailable; nothing was removed".into(),
        );
        finish_mirror_deletions(handle, store, panes, ui, report);
        return;
    };
    let remote = match remote_sync_snapshot(&pending.context, &password).await {
        Ok(snapshot) => snapshot,
        Err(error) => {
            report.skip_many(deletions.len(), format!("{error}; nothing was removed"));
            finish_mirror_deletions(handle, store, panes, ui, report);
            return;
        }
    };

    for (position, deletion) in deletions.iter().enumerate() {
        if !folder_sync_context_is_current(&panes, &pending.context.key) {
            report.skip_many(
                deletions.len().saturating_sub(position),
                "pane or synchronized folder changed; remaining deletions were cancelled".into(),
            );
            break;
        }
        match pending.direction {
            TransferDirection::Upload => {
                let source_path =
                    match remote_local_target(&pending.context.key.local_root, &deletion.label) {
                        Ok(path) => path,
                        Err(error) => {
                            report.skip(format!("{}: unsafe source path: {error}", deletion.label));
                            continue;
                        }
                    };
                match std::fs::symlink_metadata(&source_path) {
                    Ok(_) => {
                        report.skip(format!("{}: source appeared after preview", deletion.label));
                        continue;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => {
                        report.skip(format!(
                            "{}: could not confirm source absence: {error}",
                            deletion.label
                        ));
                        continue;
                    }
                }
                let Some((current_path, current)) = remote.get(&deletion.label) else {
                    report.skip(format!("{}: target disappeared", deletion.label));
                    continue;
                };
                if current_path != &deletion.remote_path
                    || !sync_metadata_matches(deletion.metadata, current.bytes, current.modified)
                {
                    report.skip(format!("{}: target changed after preview", deletion.label));
                    continue;
                }
                match net::delete_remote(&pending.context.spec, &password, current_path, false)
                    .await
                {
                    Ok(()) => report.deleted += 1,
                    Err(error) => report.fail(format!("{}: {error}", deletion.label)),
                }
            }
            TransferDirection::Download => {
                if remote.contains_key(&deletion.label) {
                    report.skip(format!("{}: source appeared after preview", deletion.label));
                    continue;
                }
                let root = pending.context.key.local_root.clone();
                let label = deletion.label.clone();
                let deletion = deletion.clone();
                match tokio::task::spawn_blocking(move || {
                    delete_local_mirror_target(&root, &deletion)
                })
                .await
                {
                    Ok(Ok(true)) => report.deleted += 1,
                    Ok(Ok(false)) => report.skip(format!(
                        "{}: target disappeared or changed after preview",
                        label
                    )),
                    Ok(Err(error)) => report.fail(error),
                    Err(error) => {
                        report.fail(format!("{}: local deletion task failed: {error}", label))
                    }
                }
            }
        }
    }
    finish_mirror_deletions(handle, store, panes, ui, report);
}

pub(super) fn remote_sync_relative(root: &str, full_path: &str) -> Result<String, String> {
    let root = root.trim().trim_end_matches('/');
    let relative = if root.is_empty() || root == "." || root == "/" {
        full_path.trim_start_matches('/')
    } else {
        let prefix = format!("{root}/");
        full_path.strip_prefix(&prefix).ok_or_else(|| {
            format!("server returned a path outside the synchronized folder: {full_path}")
        })?
    };
    if relative.is_empty() {
        return Err("server returned an empty file path".to_string());
    }
    net::sanitize_local_rel(relative).map_err(|error| error.to_string())
}

pub(super) async fn prepare_folder_sync(
    context: FolderSyncContext,
    direction: TransferDirection,
    exclusions: Vec<String>,
    options: gmacftp::folder_sync::SyncOptions,
    password: String,
) -> Result<PreparedFolderSync, String> {
    let local_root = context.key.local_root.clone();
    let local_exclusions = exclusions.clone();
    let local_walk =
        tokio::task::spawn_blocking(move || walk_local_for_sync(&local_root, &local_exclusions));
    let remote_walk =
        net::walk_remote_metadata(&context.spec, &password, context.key.remote_root.as_str());
    let (local_tree, remote_files) = tokio::join!(local_walk, remote_walk);
    let local_tree = local_tree
        .map_err(|error| format!("local scan failed: {error}"))?
        .map_err(|error| format!("local scan failed: {error}"))?;
    let remote_files = remote_files.map_err(|error| format!("remote scan failed: {error}"))?;

    let mut local_metadata = BTreeMap::new();
    let mut local_paths = BTreeMap::new();
    for (path, relative, bytes) in local_tree.files {
        let metadata = std::fs::symlink_metadata(&path)
            .map_err(|error| format!("local file changed during sync scan: {relative}: {error}"))?;
        if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.len() != bytes {
            return Err(format!("local file changed during sync scan: {relative}"));
        }
        let modified = metadata
            .modified()
            .ok()
            .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
            .and_then(|duration| i64::try_from(duration.as_secs()).ok());
        let comparison_metadata = gmacftp::folder_sync::SyncFileMetadata {
            bytes,
            modified,
            sha256: None,
        };
        if local_metadata
            .insert(relative.clone(), comparison_metadata)
            .is_some()
        {
            return Err(format!("duplicate local path in sync scan: {relative}"));
        }
        local_paths.insert(relative, path);
    }

    let mut remote_metadata = BTreeMap::new();
    let mut remote_paths = BTreeMap::new();
    for file in remote_files {
        let relative = remote_sync_relative(&context.key.remote_root, &file.path)?;
        let comparison_metadata = gmacftp::folder_sync::SyncFileMetadata {
            bytes: file.size,
            modified: file.mtime,
            sha256: None,
        };
        if remote_metadata
            .insert(relative.clone(), comparison_metadata)
            .is_some()
        {
            return Err(format!("server returned duplicate path: {relative}"));
        }
        remote_paths.insert(relative, file.path);
    }

    if options.comparison == gmacftp::folder_sync::SyncComparison::Checksum {
        let common = local_metadata
            .iter()
            .filter_map(|(relative, local)| {
                remote_metadata
                    .get(relative)
                    .filter(|remote| remote.bytes == local.bytes)
                    .filter(|_| !gmacftp::folder_sync::is_excluded(relative, &exclusions))
                    .map(|_| relative.clone())
            })
            .collect::<Vec<_>>();
        if common.len() > MAX_SYNC_CHECKSUM_FILES {
            return Err(format!(
                "checksum comparison is limited to {MAX_SYNC_CHECKSUM_FILES} matching files per run"
            ));
        }

        let local_hash_inputs = common
            .iter()
            .map(|relative| {
                local_paths
                    .get(relative)
                    .cloned()
                    .map(|path| (relative.clone(), path))
                    .ok_or_else(|| format!("local file disappeared during scan: {relative}"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let remote_hash_inputs = common
            .iter()
            .map(|relative| {
                remote_paths
                    .get(relative)
                    .cloned()
                    .map(|path| (relative.clone(), path))
                    .ok_or_else(|| format!("remote file disappeared during scan: {relative}"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let local_hashes = tokio::task::spawn_blocking(move || {
            local_hash_inputs
                .into_iter()
                .map(|(relative, path)| sha256_file(&path).map(|digest| (relative, digest)))
                .collect::<Result<Vec<_>, _>>()
        });
        let remote_paths_to_hash = remote_hash_inputs
            .iter()
            .map(|(_, path)| path.clone())
            .collect::<Vec<_>>();
        let remote_hashes = net::hash_remote_files(&context.spec, &password, &remote_paths_to_hash);
        let (local_hashes, remote_hashes) = tokio::join!(local_hashes, remote_hashes);
        let local_hashes =
            local_hashes.map_err(|error| format!("local checksum task failed: {error}"))??;
        let remote_hashes = remote_hashes
            .map_err(|error| format!("remote checksum scan failed: {error}"))?
            .into_iter()
            .collect::<BTreeMap<_, _>>();
        for (relative, digest) in local_hashes {
            if let Some(metadata) = local_metadata.get_mut(&relative) {
                metadata.sha256 = Some(digest);
            }
        }
        for (relative, path) in remote_hash_inputs {
            let digest = remote_hashes
                .get(&path)
                .copied()
                .ok_or_else(|| format!("server omitted checksum for {relative}"))?;
            if let Some(metadata) = remote_metadata.get_mut(&relative) {
                metadata.sha256 = Some(digest);
            }
        }
    }

    let (source, target) = match direction {
        TransferDirection::Upload => (&local_metadata, &remote_metadata),
        TransferDirection::Download => (&remote_metadata, &local_metadata),
    };
    let preview = gmacftp::folder_sync::build_preview(source, target, &exclusions, options);
    let mut candidates = Vec::with_capacity(preview.actions.len());
    for action in &preview.actions {
        let relative = &action.relative_path;
        let (local_path, remote_path) = match direction {
            TransferDirection::Upload => {
                let local = local_paths
                    .get(relative)
                    .ok_or_else(|| format!("local file disappeared during scan: {relative}"))?;
                let remote = join_remote(PathBuf::from(&context.key.remote_root).join(relative));
                (local.clone(), remote)
            }
            TransferDirection::Download => {
                let remote = remote_paths
                    .get(relative)
                    .ok_or_else(|| format!("remote file disappeared during scan: {relative}"))?;
                let local = remote_local_target(&context.key.local_root, relative)
                    .map_err(|error| error.to_string())?;
                (local, remote.clone())
            }
        };
        candidates.push(FolderSyncCandidate {
            label: relative.clone(),
            local_path: local_path.to_string_lossy().into_owned(),
            remote_path,
            bytes: action.bytes,
            included: true,
        });
    }
    let mut deletions = Vec::with_capacity(preview.deletions.len());
    for action in &preview.deletions {
        let relative = &action.relative_path;
        let metadata = target
            .get(relative)
            .copied()
            .ok_or_else(|| format!("sync deletion target disappeared during scan: {relative}"))?;
        let (local_path, remote_path) = match direction {
            TransferDirection::Upload => (
                String::new(),
                remote_paths
                    .get(relative)
                    .cloned()
                    .ok_or_else(|| format!("remote deletion target disappeared: {relative}"))?,
            ),
            TransferDirection::Download => (
                local_paths
                    .get(relative)
                    .map(|path| path.to_string_lossy().into_owned())
                    .ok_or_else(|| format!("local deletion target disappeared: {relative}"))?,
                String::new(),
            ),
        };
        deletions.push(FolderSyncDeletion {
            label: relative.clone(),
            local_path,
            remote_path,
            metadata,
            included: true,
        });
    }
    Ok(PreparedFolderSync {
        context,
        direction,
        exclusions,
        options,
        preview,
        candidates,
        deletions,
    })
}

pub(super) fn folder_sync_summary(
    prepared: &PreparedFolderSync,
    changed_since_preview: bool,
) -> String {
    let p = &prepared.preview;
    let prefix = if changed_since_preview {
        "Folders changed; review the refreshed dry-run. "
    } else {
        ""
    };
    let total_rows = p.actions.len().saturating_add(p.deletions.len());
    let hidden = total_rows.saturating_sub(MAX_SYNC_PREVIEW_ROWS);
    let shown = if hidden > 0 {
        format!(" Showing the first {MAX_SYNC_PREVIEW_ROWS} (+{hidden} more).")
    } else {
        String::new()
    };
    let comparison = match prepared.options.comparison {
        gmacftp::folder_sync::SyncComparison::SizeOnly => "size",
        gmacftp::folder_sync::SyncComparison::SizeAndModificationTime => "size + modified time",
        gmacftp::folder_sync::SyncComparison::Checksum => "SHA-256",
    };
    let selected_copies = prepared
        .candidates
        .iter()
        .filter(|candidate| candidate.included)
        .count();
    let selected_deletions = prepared
        .deletions
        .iter()
        .filter(|candidate| candidate.included)
        .count();
    let deletion_summary = if prepared.options.mode == gmacftp::folder_sync::SyncMode::Mirror {
        format!("{selected_deletions} selected for deletion")
    } else {
        format!("{} target-only kept; no deletions", p.target_only)
    };
    format!(
        "{prefix}{selected_copies}/{} selected to copy; {} unchanged; {deletion_summary}; {} excluded. Comparison: {comparison} (±{}s).{shown}",
        p.actions.len(),
        p.unchanged,
        p.excluded,
        prepared.options.mtime_tolerance_seconds,
    )
}

pub(super) fn show_folder_sync_preview(ui: &App, prepared: &PreparedFolderSync, changed: bool) {
    let action = match prepared.direction {
        TransferDirection::Upload => "UPLOAD",
        TransferDirection::Download => "DOWNLOAD",
    };
    let mut rows = prepared
        .preview
        .actions
        .iter()
        .zip(prepared.candidates.iter())
        .map(|(item, candidate)| SyncRow {
            included: candidate.included,
            path: item.relative_path.clone().into(),
            action: action.into(),
            reason: match item.reason {
                gmacftp::folder_sync::SyncReason::Missing => "missing",
                gmacftp::folder_sync::SyncReason::DifferentSize => "size differs",
                gmacftp::folder_sync::SyncReason::DifferentModificationTime => "date differs",
                gmacftp::folder_sync::SyncReason::ModificationTimeUnavailable => "date unavailable",
                gmacftp::folder_sync::SyncReason::DifferentChecksum => "checksum differs",
                gmacftp::folder_sync::SyncReason::ChecksumUnavailable => "checksum unavailable",
                gmacftp::folder_sync::SyncReason::TargetOnly => "target only",
            }
            .into(),
            size_text: fmt_size(item.bytes).into(),
        })
        .collect::<Vec<_>>();
    rows.extend(
        prepared
            .preview
            .deletions
            .iter()
            .zip(prepared.deletions.iter())
            .map(|(item, deletion)| SyncRow {
                included: deletion.included,
                path: item.relative_path.clone().into(),
                action: "DELETE".into(),
                reason: "target only".into(),
                size_text: fmt_size(item.bytes).into(),
            }),
    );
    rows.truncate(MAX_SYNC_PREVIEW_ROWS);
    ui.set_sync_rows(ModelRc::from(Rc::new(VecModel::from(rows))));
    ui.set_sync_summary(folder_sync_summary(prepared, changed).into());
    ui.set_sync_preview_ready(true);
    ui.set_sync_scanning(false);
}

pub(super) fn sync_reason_name(reason: gmacftp::folder_sync::SyncReason) -> &'static str {
    match reason {
        gmacftp::folder_sync::SyncReason::Missing => "missing",
        gmacftp::folder_sync::SyncReason::DifferentSize => "different_size",
        gmacftp::folder_sync::SyncReason::DifferentModificationTime => {
            "different_modification_time"
        }
        gmacftp::folder_sync::SyncReason::ModificationTimeUnavailable => {
            "modification_time_unavailable"
        }
        gmacftp::folder_sync::SyncReason::DifferentChecksum => "different_checksum",
        gmacftp::folder_sync::SyncReason::ChecksumUnavailable => "checksum_unavailable",
        gmacftp::folder_sync::SyncReason::TargetOnly => "target_only",
    }
}

pub(super) fn folder_sync_report_bytes(prepared: &PreparedFolderSync) -> Result<Vec<u8>, String> {
    #[derive(serde::Serialize)]
    struct ReportItem<'a> {
        relative_path: &'a str,
        action: &'static str,
        reason: &'static str,
        bytes: u64,
        included: bool,
    }

    #[derive(serde::Serialize)]
    struct Report<'a> {
        format: &'static str,
        format_version: u8,
        privacy: &'static str,
        direction: &'static str,
        mode: &'static str,
        comparison: &'static str,
        mtime_tolerance_seconds: u64,
        source_time_adjustment_seconds: i64,
        target_time_adjustment_seconds: i64,
        unchanged: usize,
        target_only: usize,
        excluded: usize,
        total_actions: usize,
        exported_actions: usize,
        truncated: bool,
        items: Vec<ReportItem<'a>>,
    }

    let direction = match prepared.direction {
        TransferDirection::Upload => "upload",
        TransferDirection::Download => "download",
    };
    let mode = match prepared.options.mode {
        gmacftp::folder_sync::SyncMode::OneWay => "one_way",
        gmacftp::folder_sync::SyncMode::Mirror => "mirror",
    };
    let comparison = match prepared.options.comparison {
        gmacftp::folder_sync::SyncComparison::SizeOnly => "size_only",
        gmacftp::folder_sync::SyncComparison::SizeAndModificationTime => "size_mtime",
        gmacftp::folder_sync::SyncComparison::Checksum => "checksum",
    };
    let mut items = Vec::new();
    for (action, candidate) in prepared.preview.actions.iter().zip(&prepared.candidates) {
        if items.len() == MAX_SYNC_REPORT_ROWS {
            break;
        }
        items.push(ReportItem {
            relative_path: &action.relative_path,
            action: direction,
            reason: sync_reason_name(action.reason),
            bytes: action.bytes,
            included: candidate.included,
        });
    }
    for (action, deletion) in prepared.preview.deletions.iter().zip(&prepared.deletions) {
        if items.len() == MAX_SYNC_REPORT_ROWS {
            break;
        }
        items.push(ReportItem {
            relative_path: &action.relative_path,
            action: "delete",
            reason: sync_reason_name(action.reason),
            bytes: action.bytes,
            included: deletion.included,
        });
    }
    let total_actions = prepared
        .preview
        .actions
        .len()
        .saturating_add(prepared.preview.deletions.len());
    let report = Report {
        format: "gmacftp-sync-dry-run",
        format_version: 1,
        privacy: "relative paths only; no host, username, credential, or absolute local path",
        direction,
        mode,
        comparison,
        mtime_tolerance_seconds: prepared.options.mtime_tolerance_seconds,
        source_time_adjustment_seconds: prepared.options.source_time_adjustment_seconds,
        target_time_adjustment_seconds: prepared.options.target_time_adjustment_seconds,
        unchanged: prepared.preview.unchanged,
        target_only: prepared.preview.target_only,
        excluded: prepared.preview.excluded,
        total_actions,
        exported_actions: items.len(),
        truncated: items.len() < total_actions,
        items,
    };
    let bytes = serde_json::to_vec_pretty(&report)
        .map_err(|error| format!("could not serialize the sync report: {error}"))?;
    if bytes.len() > MAX_SYNC_REPORT_BYTES {
        return Err(format!(
            "sync report exceeds the {MAX_SYNC_REPORT_BYTES}-byte safety limit"
        ));
    }
    Ok(bytes)
}
