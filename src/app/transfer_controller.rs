//! Transfer-panel state, summaries, and stable transfer/batch identifiers.

use super::*;

pub(super) fn wire_clear_finished(
    ui: &App,
    idx: Arc<Mutex<HashMap<i32, usize>>>,
    engine: TransferEngine,
) {
    let ui_weak = ui.as_weak();
    ui.on_clear_finished_transfers(move || {
        let ui = ui_weak.upgrade();
        TRANSFER_JOBS.with(|jm| {
            let b = jm.borrow();
            let Some(jobs) = b.as_ref() else { return };
            // remove done/failed rows back-to-front so indices stay valid
            let mut i = jobs.row_count();
            while i > 0 {
                i -= 1;
                let finished = jobs.row_data(i).is_some_and(|r| {
                    matches!(
                        r.state.as_str(),
                        "done" | "failed" | "cancelled" | "recovered"
                    )
                });
                if finished {
                    if let Some(row) = jobs.row_data(i) {
                        engine.forget_job(TransferId(row.id as usize));
                    }
                    jobs.remove(i);
                }
            }
            if let Ok(mut g) = idx.lock() {
                g.clear();
                for k in 0..jobs.row_count() {
                    if let Some(r) = jobs.row_data(k) {
                        g.insert(r.id, k);
                    }
                }
            }
            if let Some(ui) = ui.as_ref() {
                update_transfer_summary_from_model(ui, jobs);
            }
        });
    });
}

/// Per-row ✕ in the transfer panel: remove that one row (by id) and rebuild the id→row index.
pub(super) fn wire_dismiss_transfer(
    ui: &App,
    idx: Arc<Mutex<HashMap<i32, usize>>>,
    engine: TransferEngine,
) {
    let ui_weak = ui.as_weak();
    ui.on_dismiss_transfer(move |id| {
        TRANSFER_JOBS.with(|jm| {
            let b = jm.borrow();
            let Some(jobs) = b.as_ref() else { return };
            if let Some(i) = (0..jobs.row_count())
                .find(|&i| jobs.row_data(i).map(|r| r.id == id).unwrap_or(false))
            {
                engine.forget_job(TransferId(id as usize));
                jobs.remove(i);
            }
            if let Ok(mut g) = idx.lock() {
                g.clear();
                for k in 0..jobs.row_count() {
                    if let Some(r) = jobs.row_data(k) {
                        g.insert(r.id, k);
                    }
                }
            }
            if let Some(ui) = ui_weak.upgrade() {
                update_transfer_summary_from_model(&ui, jobs);
            }
        });
    });
}

pub(super) fn wire_individual_transfer_controls(
    ui: &App,
    idx: Arc<Mutex<HashMap<i32, usize>>>,
    engine: TransferEngine,
) {
    let cancel_engine = engine.clone();
    let cancel_ui = ui.as_weak();
    let cancel_idx = idx.clone();
    ui.on_cancel_transfer(move |id| {
        cancel_engine.cancel_job(TransferId(id as usize));
        TRANSFER_JOBS.with(|jm| {
            let jobs = jm.borrow();
            let Some(jobs) = jobs.as_ref() else { return };
            let Some(index) = cancel_idx.lock().ok().and_then(|map| map.get(&id).copied()) else {
                return;
            };
            if let Some(mut row) = jobs.row_data(index) {
                row.message = "cancelling…".into();
                jobs.set_row_data(index, row);
            }
        });
        if let Some(ui) = cancel_ui.upgrade() {
            ui.set_status("cancelling selected transfer…".into());
            ui.set_error("".into());
        }
    });

    let retry_ui = ui.as_weak();
    ui.on_retry_transfer(move |id| {
        let Some(ui) = retry_ui.upgrade() else { return };
        match engine.retry_job(TransferId(id as usize)) {
            Ok(()) => {
                TRANSFER_JOBS.with(|jm| {
                    let jobs = jm.borrow();
                    let Some(jobs) = jobs.as_ref() else { return };
                    let Some(index) = idx.lock().ok().and_then(|map| map.get(&id).copied()) else {
                        return;
                    };
                    let Some(mut row) = jobs.row_data(index) else {
                        return;
                    };
                    let resumable = matches!(row.direction.as_str(), "download" | "upload");
                    row.done = 0;
                    row.fraction = 0.0;
                    row.progress_text = fmt_transfer_progress(0, row.total.max(0) as u64).into();
                    row.state = "queued".into();
                    row.message = if resumable {
                        "resuming safely…"
                    } else {
                        "retrying…"
                    }
                    .into();
                    jobs.set_row_data(index, row);
                    update_transfer_summary_from_model(&ui, jobs);
                });
                ui.set_transfer_error_open(false);
                ui.set_error("".into());
                ui.set_status("transfer queued again".into());
            }
            Err(gmacftp::transfer::RetryError::NotFound) => {
                ui.set_error("Retry data is no longer available.".into())
            }
            Err(gmacftp::transfer::RetryError::QueueFull) => {
                ui.set_error("Transfer queue is full.".into())
            }
        }
    });
}

pub(super) fn transfer_priority(value: &str) -> Option<TransferPriority> {
    match value {
        "low" => Some(TransferPriority::Low),
        "normal" => Some(TransferPriority::Normal),
        "high" => Some(TransferPriority::High),
        _ => None,
    }
}

pub(super) fn rebuild_transfer_index(
    jobs: &Rc<VecModel<TransferRow>>,
    idx: &Arc<Mutex<HashMap<i32, usize>>>,
) {
    if let Ok(mut index) = idx.lock() {
        index.clear();
        for row_index in 0..jobs.row_count() {
            if let Some(row) = jobs.row_data(row_index) {
                index.insert(row.id, row_index);
            }
        }
    }
}

pub(super) fn wire_transfer_queue_controls(
    ui: &App,
    idx: Arc<Mutex<HashMap<i32, usize>>>,
    engine: TransferEngine,
) {
    let pause_ui = ui.as_weak();
    let pause_idx = idx.clone();
    let pause_engine = engine.clone();
    ui.on_pause_transfer(move |id, paused| {
        let Some(ui) = pause_ui.upgrade() else {
            return;
        };
        if !pause_engine.set_job_paused(TransferId(id as usize), paused) {
            ui.set_error("Only a transfer that is still queued can be paused.".into());
            return;
        }
        TRANSFER_JOBS.with(|jobs| {
            let jobs = jobs.borrow();
            let Some(jobs) = jobs.as_ref() else { return };
            let Some(index) = pause_idx
                .lock()
                .ok()
                .and_then(|index| index.get(&id).copied())
            else {
                return;
            };
            if let Some(mut row) = jobs.row_data(index) {
                row.state = if paused { "paused" } else { "queued" }.into();
                row.message = if paused {
                    "paused before start"
                } else {
                    "waiting"
                }
                .into();
                jobs.set_row_data(index, row);
                update_transfer_summary_from_model(&ui, jobs);
            }
        });
        ui.set_error("".into());
        ui.set_status(
            if paused {
                "Queued transfer paused."
            } else {
                "Transfer resumed in the queue."
            }
            .into(),
        );
    });

    let priority_ui = ui.as_weak();
    let priority_idx = idx.clone();
    let priority_engine = engine.clone();
    ui.on_set_transfer_priority(move |id, value| {
        let Some(ui) = priority_ui.upgrade() else {
            return;
        };
        let Some(priority) = transfer_priority(value.as_str()) else {
            ui.set_error("Invalid transfer priority.".into());
            return;
        };
        if !priority_engine.set_job_priority(TransferId(id as usize), priority) {
            ui.set_error("Priority can be changed only while a transfer is queued.".into());
            return;
        }
        TRANSFER_JOBS.with(|jobs| {
            let jobs = jobs.borrow();
            let Some(jobs) = jobs.as_ref() else { return };
            let Some(index) = priority_idx
                .lock()
                .ok()
                .and_then(|index| index.get(&id).copied())
            else {
                return;
            };
            if let Some(mut row) = jobs.row_data(index) {
                row.priority = value.clone();
                jobs.set_row_data(index, row);
            }
        });
        ui.set_error("".into());
        ui.set_status("Transfer priority updated.".into());
    });

    let move_ui = ui.as_weak();
    ui.on_move_transfer(move |id, direction| {
        let Some(ui) = move_ui.upgrade() else {
            return;
        };
        TRANSFER_JOBS.with(|jobs| {
            let jobs = jobs.borrow();
            let Some(jobs) = jobs.as_ref() else { return };
            let Some(current_index) = (0..jobs.row_count())
                .find(|index| jobs.row_data(*index).is_some_and(|row| row.id == id))
            else {
                return;
            };
            let Some(current) = jobs.row_data(current_index) else {
                return;
            };
            if !matches!(current.state.as_str(), "queued" | "paused") {
                ui.set_error("Only queued transfers can be reordered.".into());
                return;
            }
            let candidate = if direction < 0 {
                (0..current_index).rev().find(|index| {
                    jobs.row_data(*index).is_some_and(|row| {
                        matches!(row.state.as_str(), "queued" | "paused")
                            && row.priority == current.priority
                    })
                })
            } else {
                ((current_index + 1)..jobs.row_count()).find(|index| {
                    jobs.row_data(*index).is_some_and(|row| {
                        matches!(row.state.as_str(), "queued" | "paused")
                            && row.priority == current.priority
                    })
                })
            };
            let Some(other_index) = candidate else {
                ui.set_status("Transfer is already at the edge of its priority group.".into());
                return;
            };
            let Some(other) = jobs.row_data(other_index) else {
                return;
            };
            if !engine.swap_queued_jobs(
                TransferId(current.id as usize),
                TransferId(other.id as usize),
            ) {
                ui.set_error("Transfer started before it could be reordered.".into());
                return;
            }
            jobs.set_row_data(current_index, other);
            jobs.set_row_data(other_index, current);
            rebuild_transfer_index(jobs, &idx);
            ui.set_error("".into());
            ui.set_status("Transfer queue reordered.".into());
        });
    });
}

const MAX_TRANSFER_REPORT_BYTES: usize = 2 * 1024 * 1024;

pub(super) fn transfer_error_category(state: &str, message: &str) -> Option<&'static str> {
    if state == "cancelled" {
        return Some("cancelled");
    }
    if state != "failed" {
        return None;
    }
    let message = message.to_ascii_lowercase();
    Some(
        if message.contains("permission") || message.contains("denied") {
            "permission"
        } else if message.contains("auth") || message.contains("login") {
            "authentication"
        } else if message.contains("space") || message.contains("disk") {
            "storage"
        } else if message.contains("timeout")
            || message.contains("network")
            || message.contains("connection")
        {
            "network"
        } else if message.contains("exist") || message.contains("conflict") {
            "conflict"
        } else {
            "other"
        },
    )
}

pub(super) fn transfer_report_bytes(rows: &[TransferRow]) -> Result<Vec<u8>, String> {
    #[derive(serde::Serialize)]
    struct Item<'a> {
        ordinal: usize,
        direction: &'a str,
        state: &'a str,
        priority: &'a str,
        displayed_bytes_done: u64,
        displayed_bytes_total: u64,
        error_category: Option<&'static str>,
    }
    #[derive(serde::Serialize)]
    struct Report<'a> {
        schema: &'static str,
        generated_unix_seconds: u64,
        privacy: &'static str,
        items: Vec<Item<'a>>,
    }

    let generated_unix_seconds = SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    let items = rows
        .iter()
        .enumerate()
        .map(|(index, row)| Item {
            ordinal: index + 1,
            direction: row.direction.as_str(),
            state: row.state.as_str(),
            priority: row.priority.as_str(),
            displayed_bytes_done: row.done.max(0) as u64,
            displayed_bytes_total: row.total.max(0) as u64,
            error_category: transfer_error_category(row.state.as_str(), row.message.as_str()),
        })
        .collect();
    let bytes = serde_json::to_vec_pretty(&Report {
        schema: "gmacftp-redacted-transfer-report-v1",
        generated_unix_seconds,
        privacy: "filenames, paths, server identities and raw error messages omitted",
        items,
    })
    .map_err(|error| format!("could not serialize transfer report: {error}"))?;
    if bytes.len() > MAX_TRANSFER_REPORT_BYTES {
        return Err("transfer report exceeds its safe size limit".into());
    }
    Ok(bytes)
}

pub(super) fn wire_export_transfer_report(ui: &App, handle: &Handle) {
    let ui_weak = ui.as_weak();
    let handle = handle.clone();
    ui.on_export_transfer_report(move || {
        let rows = TRANSFER_JOBS.with(|jobs| {
            jobs.borrow()
                .as_ref()
                .map(|jobs| {
                    (0..jobs.row_count())
                        .filter_map(|index| jobs.row_data(index))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default()
        });
        let bytes = match transfer_report_bytes(&rows) {
            Ok(bytes) => bytes,
            Err(error) => {
                if let Some(ui) = ui_weak.upgrade() {
                    ui.set_error(error.into());
                }
                return;
            }
        };
        let request_ui = ui_weak.clone();
        handle.spawn(async move {
            let selected = rfd::AsyncFileDialog::new()
                .set_title("Save redacted transfer report")
                .set_file_name("gmacftp-transfer-report.json")
                .add_filter("JSON report", &["json"])
                .save_file()
                .await;
            let Some(selected) = selected else {
                return;
            };
            let path = selected.path().to_path_buf();
            let result =
                tokio::task::spawn_blocking(move || store::write_private_atomic(&path, &bytes))
                    .await
                    .map_err(|error| std::io::Error::other(error.to_string()))
                    .and_then(|result| result);
            let _ = slint::invoke_from_event_loop(move || {
                let Some(ui) = request_ui.upgrade() else {
                    return;
                };
                match result {
                    Ok(()) => {
                        ui.set_error("".into());
                        ui.set_status("Redacted transfer history exported.".into());
                    }
                    Err(error) => {
                        ui.set_error(format!("Could not export transfer report: {error}").into())
                    }
                }
            });
        });
    });
}

/// Transfer-panel "Pause all" toggle → engine.set_paused (stops dequeue of new transfers).
pub(super) fn wire_set_transfers_paused(ui: &App, engine: TransferEngine) {
    ui.on_set_transfers_paused(move |paused| {
        engine.set_paused(paused);
    });
}

pub(super) fn wire_set_transfer_concurrency(ui: &App, engine: TransferEngine) {
    let ui_weak = ui.as_weak();
    ui.on_set_transfer_concurrency(move |requested| {
        let Some(ui) = ui_weak.upgrade() else { return };
        let limit = (requested.max(0) as usize).clamp(
            gmacftp::transfer::MIN_ENDPOINT_CONCURRENCY,
            gmacftp::transfer::MAX_ENDPOINT_CONCURRENCY,
        );
        let mut settings = store::settings::load();
        let previous = settings.transfer_concurrency;
        settings.transfer_concurrency = limit;
        match store::settings::try_save(&settings) {
            Ok(()) => {
                let applied = engine.set_endpoint_concurrency(limit);
                ui.set_transfer_concurrency(applied as i32);
                ui.set_error("".into());
                ui.set_status(format!("Parallel server transfers: {applied}.").into());
            }
            Err(error) => {
                ui.set_transfer_concurrency(previous as i32);
                ui.set_error(format!("Could not save transfer concurrency: {error}").into());
            }
        }
    });
}

pub(super) fn wire_resolve_transfer_error(ui: &App, engine: TransferEngine) {
    let ui_weak = ui.as_weak();
    ui.on_resolve_transfer_error(move |should_continue| {
        let Some(ui) = ui_weak.upgrade() else { return };
        let Ok(batch_id) = ui.get_transfer_error_batch().parse::<usize>() else {
            return;
        };
        ui.set_transfer_error_open(false);
        ui.set_transfer_error_needs_decision(false);
        ui.set_transfer_error_batch("".into());
        engine.resolve_batch_failure(batch_id, should_continue);
        if should_continue {
            ui.set_status("failed file skipped — continuing batch".into());
        } else {
            ui.set_status("stopping remaining files in this batch…".into());
        }
    });
}

pub(super) fn jobs_push(row: TransferRow, idx: &Arc<Mutex<HashMap<i32, usize>>>) {
    TRANSFER_JOBS.with(|j| {
        let b = j.borrow();
        if let Some(jobs) = b.as_ref() {
            if let Ok(mut g) = idx.lock() {
                g.insert(row.id, jobs.row_count());
            }
            jobs.push(row);
        }
    });
}

pub(super) fn transfer_summary_from_rows(rows: &[TransferRow]) -> String {
    if rows.is_empty() {
        return "0 transfers".to_string();
    }

    let count = |expected| {
        rows.iter()
            .filter(|row| TransferRowState::try_from(row.state.as_str()) == Ok(expected))
            .count()
    };
    let active = count(TransferRowState::Active);
    let queued = count(TransferRowState::Queued);
    let paused = count(TransferRowState::Paused);
    let failed = count(TransferRowState::Failed);
    let cancelled = count(TransferRowState::Cancelled);
    let recovered = count(TransferRowState::Recovered);
    let done = count(TransferRowState::Done);
    let speed = rows
        .iter()
        .filter(|row| {
            TransferRowState::try_from(row.state.as_str()) == Ok(TransferRowState::Active)
        })
        .filter_map(|r| parse_mbps(r.message.as_str()))
        .sum::<f32>();

    let total = rows.len();
    let mut parts = Vec::new();
    // Lead with overall progress so a batch transfer always shows "X / Y done" at a glance
    // (was: only "N active / N queued" — the total and how far along were not visible).
    parts.push(format!("{done} / {total} done"));
    if active > 0 {
        parts.push(format!("{active} active"));
        if speed > 0.0 {
            parts.push(format!("{speed:.1} MB/s"));
        }
    }
    if queued > 0 {
        parts.push(format!("{queued} queued"));
    }
    if paused > 0 {
        parts.push(format!("{paused} paused"));
    }
    if failed > 0 {
        parts.push(format!("{failed} failed"));
    }
    if cancelled > 0 {
        parts.push(format!("{cancelled} cancelled"));
    }
    if recovered > 0 {
        parts.push(format!("{recovered} recovered"));
    }
    parts.join(" · ")
}

pub(super) fn parse_mbps(message: &str) -> Option<f32> {
    let (number, rest) = message.trim().split_once(' ')?;
    if !rest.starts_with("MB/s") {
        return None;
    }
    number.parse::<f32>().ok()
}

pub(super) fn update_transfer_summary_from_model(ui: &App, jobs: &Rc<VecModel<TransferRow>>) {
    let rows = (0..jobs.row_count())
        .filter_map(|i| jobs.row_data(i))
        .collect::<Vec<_>>();
    let done = rows
        .iter()
        .filter(|row| TransferRowState::try_from(row.state.as_str()) == Ok(TransferRowState::Done))
        .count() as i32;
    let pending = rows
        .iter()
        .filter(|row| {
            matches!(
                TransferRowState::try_from(row.state.as_str()),
                Ok(TransferRowState::Active | TransferRowState::Queued | TransferRowState::Paused)
            )
        })
        .count() as i32;
    ui.set_transfer_done_count(done);
    ui.set_transfer_pending_count(pending);
    ui.set_transfer_summary(transfer_summary_from_rows(&rows).into());
    let active = rows
        .iter()
        .filter(|row| {
            TransferRowState::try_from(row.state.as_str()) == Ok(TransferRowState::Active)
        })
        .collect::<Vec<_>>();
    let active_total = active
        .iter()
        .map(|row| row.total.max(0) as u64)
        .sum::<u64>();
    let progress = if active_total > 0 {
        Some(
            active
                .iter()
                .map(|row| row.done.max(0).min(row.total.max(0)) as u64)
                .sum::<u64>() as f64
                / active_total as f64,
        )
    } else if !active.is_empty() {
        Some(
            active
                .iter()
                .map(|row| row.fraction.clamp(0.0, 1.0) as f64)
                .sum::<f64>()
                / active.len() as f64,
        )
    } else {
        None
    };
    crate::notifications::update_dock(pending.max(0) as usize, progress);
}

pub(super) fn update_transfer_summary(ui: &App) {
    TRANSFER_JOBS.with(|jm| {
        let b = jm.borrow();
        if let Some(jobs) = b.as_ref() {
            update_transfer_summary_from_model(ui, jobs);
        } else {
            ui.set_transfer_summary("0 transfers".into());
            crate::notifications::update_dock(0, None);
        }
    });
}

/// Monotonic transfer id shared by single-file (`enqueue`), folder-batch, and relay rows so two
/// transfers can never collide on the same panel-row id (the forwarder matches updates by id).
static XFER_ID: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(1);
static XFER_BATCH_ID: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(1);
pub(super) fn fresh_xfer_id() -> usize {
    XFER_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

pub(super) fn reserve_xfer_ids_after(existing: usize) {
    XFER_ID.fetch_max(
        existing.saturating_add(1),
        std::sync::atomic::Ordering::Relaxed,
    );
}

pub(super) fn fresh_batch(pause_on_error: bool) -> TransferBatch {
    TransferBatch {
        id: XFER_BATCH_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        pause_on_error,
    }
}

pub(super) fn next_xfer_id() -> i32 {
    fresh_xfer_id() as i32
}

/// Update an existing transfer row by id (UI thread).
pub(super) fn jobs_set(
    id: i32,
    idx: &Arc<Mutex<HashMap<i32, usize>>>,
    state: &str,
    done: i32,
    total: i32,
    msg: &str,
) {
    TRANSFER_JOBS.with(|jm| {
        let b = jm.borrow();
        let Some(jobs) = b.as_ref() else { return };
        let Some(i) = idx.lock().ok().and_then(|g| g.get(&id).copied()) else {
            return;
        };
        if let Some(mut row) = jobs.row_data(i) {
            row.state = state.into();
            row.done = done;
            row.total = total;
            row.fraction = if total > 0 {
                done as f32 / total as f32
            } else if state == "done" {
                1.0
            } else {
                0.0
            };
            row.progress_text =
                fmt_transfer_progress(done.max(0) as u64, total.max(0) as u64).into();
            row.message = msg.into();
            jobs.set_row_data(i, row);
        }
    });
}
