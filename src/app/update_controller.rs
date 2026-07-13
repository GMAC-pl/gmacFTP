//! Opt-in update discovery and explicit, verified release download UI.

use super::*;

#[derive(Clone, Copy, PartialEq, Eq)]
enum CheckOrigin {
    Manual,
    Automatic,
}

static PENDING_UPDATE: LazyLock<Mutex<Option<gmacftp::updater::LatestUpdate>>> =
    LazyLock::new(|| Mutex::new(None));
static UPDATE_CHECK_RUNNING: AtomicBool = AtomicBool::new(false);
static UPDATE_DOWNLOAD_RUNNING: AtomicBool = AtomicBool::new(false);
static UPDATE_CHECK_ATTEMPTED_THIS_LAUNCH: AtomicBool = AtomicBool::new(false);

fn on_ui<F>(ui: Weak<App>, callback: F)
where
    F: FnOnce(&App) + Send + 'static,
{
    let _ = slint::invoke_from_event_loop(move || {
        if let Some(ui) = ui.upgrade() {
            callback(&ui);
        }
    });
}

fn start_update_check(ui: Weak<App>, origin: CheckOrigin) {
    if origin == CheckOrigin::Automatic
        && UPDATE_CHECK_ATTEMPTED_THIS_LAUNCH.swap(true, AtomicOrdering::AcqRel)
    {
        return;
    }
    if origin == CheckOrigin::Manual {
        UPDATE_CHECK_ATTEMPTED_THIS_LAUNCH.store(true, AtomicOrdering::Release);
    }
    if !gmacftp::updater::supported() {
        if origin == CheckOrigin::Manual {
            on_ui(ui, |ui| {
                ui.set_error("Update checks are available only in the public gmacFTP build.".into())
            });
        }
        return;
    }
    if UPDATE_CHECK_RUNNING
        .compare_exchange(false, true, AtomicOrdering::AcqRel, AtomicOrdering::Acquire)
        .is_err()
    {
        if origin == CheckOrigin::Manual {
            on_ui(ui, |ui| {
                ui.set_status("An update check is already running.".into())
            });
        }
        return;
    }

    if origin == CheckOrigin::Manual {
        on_ui(ui.clone(), |ui| {
            ui.set_error("".into());
            ui.set_status("Checking for updates…".into());
        });
    }
    std::thread::spawn(move || {
        let result = gmacftp::updater::check();
        UPDATE_CHECK_RUNNING.store(false, AtomicOrdering::Release);
        match result {
            Ok(Some(update)) => {
                let version = update.version.clone();
                let notes = update.notes.clone();
                if let Ok(mut pending) = PENDING_UPDATE.lock() {
                    *pending = Some(update);
                } else {
                    on_ui(ui, |ui| {
                        ui.set_error("Could not prepare the verified update prompt.".into())
                    });
                    return;
                }
                on_ui(ui, move |ui| {
                    ui.set_update_version(version.into());
                    ui.set_update_notes(notes.into());
                    ui.set_update_message("".into());
                    ui.set_update_busy(false);
                    ui.set_update_open(true);
                    ui.set_status("A new gmacFTP version is available.".into());
                    ui.set_error("".into());
                });
            }
            Ok(None) if origin == CheckOrigin::Manual => on_ui(ui, |ui| {
                ui.set_status(
                    format!("gmacFTP is up to date (v{}).", gmacftp::updater::CURRENT).into(),
                );
                ui.set_error("".into());
            }),
            Ok(None) => {}
            Err(error) if origin == CheckOrigin::Manual => on_ui(ui, move |ui| {
                ui.set_error(format!("Update check failed: {error}").into())
            }),
            Err(error) => {
                tracing::warn!(target: "gmacftp::updater", %error, "automatic update check failed");
            }
        }
    });
}

fn start_update_download(ui: Weak<App>) {
    if UPDATE_DOWNLOAD_RUNNING
        .compare_exchange(false, true, AtomicOrdering::AcqRel, AtomicOrdering::Acquire)
        .is_err()
    {
        return;
    }
    let update = PENDING_UPDATE
        .lock()
        .ok()
        .and_then(|pending| pending.clone());
    let Some(update) = update else {
        UPDATE_DOWNLOAD_RUNNING.store(false, AtomicOrdering::Release);
        on_ui(ui, |ui| {
            ui.set_update_busy(false);
            ui.set_update_message(
                "The selected update is no longer available; check again.".into(),
            );
        });
        return;
    };

    if let Some(ui) = ui.upgrade() {
        ui.set_update_busy(true);
        ui.set_update_message("Downloading and verifying the signed update…".into());
    }
    std::thread::spawn(move || {
        let version = update.version.clone();
        let result = gmacftp::updater::download(
            &update.dmg_url,
            &update.version,
            &update.sha256,
            update.size,
        )
        .and_then(|path| {
            gmacftp::updater::open_in_finder(&path)?;
            Ok(path)
        });
        UPDATE_DOWNLOAD_RUNNING.store(false, AtomicOrdering::Release);
        match result {
            Ok(_) => {
                if let Ok(mut pending) = PENDING_UPDATE.lock() {
                    *pending = None;
                }
                on_ui(ui, move |ui| {
                    ui.set_update_busy(false);
                    ui.set_update_open(false);
                    ui.set_update_version("".into());
                    ui.set_update_notes("".into());
                    ui.set_update_message("".into());
                    ui.set_status(
                        format!(
                            "Verified update {version} opened — drag gmacFTP to Applications, then relaunch."
                        )
                        .into(),
                    );
                    ui.set_error("".into());
                });
            }
            Err(error) => on_ui(ui, move |ui| {
                ui.set_update_busy(false);
                ui.set_update_message(format!("Update download failed: {error}").into());
            }),
        }
    });
}

pub(super) fn wire_updates(ui: &App, automatic_enabled: bool, allow_background: bool) {
    let check_ui = ui.as_weak();
    ui.on_check_for_updates(move || {
        start_update_check(check_ui.clone(), CheckOrigin::Manual);
    });

    let download_ui = ui.as_weak();
    ui.on_download_update(move || {
        start_update_download(download_ui.clone());
    });

    let dismiss_ui = ui.as_weak();
    ui.on_dismiss_update(move || {
        if UPDATE_DOWNLOAD_RUNNING.load(AtomicOrdering::Acquire) {
            return;
        }
        if let Ok(mut pending) = PENDING_UPDATE.lock() {
            *pending = None;
        }
        if let Some(ui) = dismiss_ui.upgrade() {
            ui.set_update_open(false);
            ui.set_update_version("".into());
            ui.set_update_notes("".into());
            ui.set_update_message("".into());
        }
    });

    if automatic_enabled && allow_background && gmacftp::updater::supported() {
        let automatic_ui = ui.as_weak();
        std::thread::spawn(move || {
            // Let initial window/store restoration finish before the opt-in network request.
            std::thread::sleep(Duration::from_secs(3));
            if store::settings::load().check_updates_automatically {
                start_update_check(automatic_ui, CheckOrigin::Automatic);
            }
        });
    }
}
