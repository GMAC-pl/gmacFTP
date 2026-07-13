//! Keyboard commands, active-pane actions, clipboard text, and sort commands.

use super::*;

pub(super) fn move_selection(ui: &App, delta: i32, extend: bool) {
    let pane = active_pane_idx(ui);
    let count = if pane == 0 {
        ui.get_local_count()
    } else {
        ui.get_remote_count()
    };
    if count <= 0 {
        return;
    }
    let cur = pane_selected(ui, pane);
    let next = if cur < 0 {
        if delta > 0 {
            0
        } else {
            count - 1
        }
    } else {
        (cur + delta).max(0).min(count - 1)
    };
    select_entry(ui, pane, next, extend, false);
    refresh_selected_path(ui);
}

/// Type-ahead: jump to the first entry in the active pane whose name starts with `letter`.
/// Ignores non-single-letter input (so modifier/special keys passing through are no-ops).
pub(super) fn type_ahead(ui: &App, letter: &str) {
    let mut it = letter.chars();
    let c = match (it.next(), it.next()) {
        (Some(c), None) if c.is_ascii_alphabetic() => c.to_ascii_lowercase(),
        _ => return,
    };
    let pane = active_pane_idx(ui);
    let entries = pane_entries(ui, pane);
    for i in 0..entries.row_count() {
        if let Some(row) = entries.row_data(i) {
            if row.name.to_string().to_lowercase().starts_with(c) {
                select_entry(ui, pane, i as i32, false, false);
                return;
            }
        }
    }
}

/// Enter: copy the active pane's selected entry to the OTHER pane.
pub(super) fn pane_enter(
    handle: &Handle,
    store: Arc<dyn CredentialStore>,
    panes: Panes,
    engine: TransferEngine,
    idx: Arc<Mutex<HashMap<i32, usize>>>,
    ui: Weak<App>,
) {
    let Some(ui) = ui.upgrade() else { return };
    let active = active_pane_idx(&ui);
    let (src, dst) = if active == 0 { (0, 1) } else { (1, 0) };
    transfer(handle, store, panes, engine, idx, ui.as_weak(), src, dst);
}

/// Delete (Del/Backspace): delete the active pane's selected entry — routed through
/// `request_delete` so the confirmation dialog (and "don't ask again") applies to keyboard
/// deletes too, not just the right-click menu.
pub(super) fn pane_delete(
    handle: &Handle,
    store: Arc<dyn CredentialStore>,
    panes: Panes,
    ui: Weak<App>,
) {
    let Some(ui) = ui.upgrade() else { return };
    let pane = active_pane_idx(&ui);
    let sel = pane_selected(&ui, pane);
    if sel < 0 {
        return;
    }
    let Some(row) = pane_entries(&ui, pane).row_data(sel as usize) else {
        return;
    };
    request_delete(
        &ui,
        handle,
        store,
        panes,
        pane,
        row.name.to_string(),
        row.is_dir,
    );
}

/// Space: Quick Look preview (macOS). Local file → `qlmanage -p`; remote → download to a temp
/// file first, then preview. Folders are skipped (no Quick Look for directories).
pub(super) fn pane_preview(
    handle: &Handle,
    store: Arc<dyn CredentialStore>,
    panes: Panes,
    ui: Weak<App>,
) {
    let Some(ui) = ui.upgrade() else { return };
    let pane = active_pane_idx(&ui);
    let sel = pane_selected(&ui, pane);
    if sel < 0 {
        return;
    }
    let Some(row) = pane_entries(&ui, pane).row_data(sel as usize) else {
        return;
    };
    if row.is_dir {
        return;
    }
    let name = row.name.to_string();
    let (kind, conn, cwd) = {
        let p = panes.lock().expect("panes");
        (
            p[pane].kind.clone(),
            p[pane].conn.clone(),
            p[pane].cwd.clone(),
        )
    };
    match kind {
        PaneKind::Local => {
            let path = PathBuf::from(&cwd).join(&name);
            let _ = std::process::Command::new("qlmanage")
                .arg("-p")
                .arg(&path)
                .spawn();
        }
        PaneKind::Remote => {
            let Some(spec) = conn else { return };
            let Some(pw) = password_for(&store, &spec) else {
                return;
            };
            let rp = join_remote(PathBuf::from(&cwd).join(&name));
            let tmp =
                std::env::temp_dir().join(format!("gmacftp-preview-{}", rand::random::<u64>()));
            handle.spawn(async move {
                let mut s = spec.clone();
                s.initial_path = cwd.clone();
                let _ = std::fs::remove_file(&tmp);
                if net::download_file(&s, &pw, &rp, tmp.clone()).await.is_ok() {
                    // M3/MEMO-3: run qlmanage to completion on a dedicated OS thread, then remove
                    // the temp file so remote file contents (id_rsa, *.kdbx, …) don't persist in
                    // $TMPDIR (and Time Machine snapshots of it). .status() blocks until the panel
                    // closes — safe because it's not on the async runtime.
                    std::thread::spawn(move || {
                        let _ = std::process::Command::new("qlmanage")
                            .arg("-p")
                            .arg(&tmp)
                            .status();
                        let _ = std::fs::remove_file(&tmp);
                    });
                }
            });
        }
    }
}

/// Sidebar "eject" / pane-specific disconnect: abort in-flight transfers and return `pane` to
/// the local filesystem.
pub(super) fn disconnect_pane(engine: TransferEngine, panes: Panes, ui: Weak<App>, pane: usize) {
    set_skip_delete_confirm(pane, false); // THIS pane's connection ended → re-arm it
                                          // Abort only THIS pane's connection's transfers — not every session's.
    if let Some(id) = panes.lock().expect("panes")[pane]
        .conn
        .as_ref()
        .map(|c| c.id)
    {
        engine.abort(id);
    }
    set_pane_local(panes, ui, pane);
}

/// Recompute the bottom-bar path for the active pane. When no entry is selected, show the pane cwd.
pub(super) fn refresh_selected_path(ui: &App) {
    ui.set_selected_path(current_selected_path(ui).into());
}

pub(super) fn current_selected_path(ui: &App) -> String {
    let pane = active_pane_idx(ui);
    let entries = pane_entries(ui, pane);
    let selection = pane_selection(ui, pane);
    let selected: Vec<usize> = (0..entries.row_count())
        .filter(|i| selection.row_data(*i).unwrap_or(false))
        .collect();
    if selected.len() > 1 {
        return format!("{} items selected", selected.len());
    }
    let cwd = if pane == 0 {
        ui.get_local_cwd().to_string()
    } else {
        ui.get_remote_cwd().to_string()
    };
    if let Some(sel) = selected.first() {
        entries
            .row_data(*sel)
            .map(|r| {
                let n = r.name.to_string();
                if pane == 0 {
                    PathBuf::from(&cwd).join(&n).to_string_lossy().into_owned()
                } else {
                    join_remote(PathBuf::from(&cwd).join(&n))
                }
            })
            .unwrap_or_else(|| cwd.clone())
    } else {
        cwd
    }
}

/// Clipboard companion to the compact bottom-bar label. For a range/all selection, copy every
/// concrete path separated by newlines instead of the display-only "N items selected" text.
pub(super) fn selected_paths_for_clipboard(ui: &App) -> String {
    let pane = active_pane_idx(ui);
    let entries = pane_entries(ui, pane);
    let rows = selected_transfer_rows(&entries, &pane_selection(ui, pane));
    if rows.is_empty() {
        return current_selected_path(ui);
    }
    let cwd = if pane == 0 {
        ui.get_local_cwd().to_string()
    } else {
        ui.get_remote_cwd().to_string()
    };
    rows.into_iter()
        .map(|row| {
            if pane == 0 {
                PathBuf::from(&cwd)
                    .join(row.name.as_str())
                    .to_string_lossy()
                    .into_owned()
            } else {
                join_remote(PathBuf::from(&cwd).join(row.name.as_str()))
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

/// Copy `text` to the macOS clipboard (pbcopy). Best-effort.
pub(super) fn copy_to_clipboard(text: &str) -> bool {
    use std::io::Write;
    let Ok(mut child) = std::process::Command::new("pbcopy")
        .stdin(std::process::Stdio::piped())
        .spawn()
    else {
        return false;
    };
    let wrote = child
        .stdin
        .take()
        .map(|mut stdin| stdin.write_all(text.as_bytes()).is_ok())
        .unwrap_or(false);
    wrote && child.wait().map(|s| s.success()).unwrap_or(false)
}

/// Sort popover → set the targeted pane's sort key and re-apply the view.
pub(super) fn apply_sort_field(ui: &App, key: &str) {
    let Ok(pane) = PaneId::try_from(ui.get_sort_pane().as_str()) else {
        ui.set_error("Invalid pane in sort request.".into());
        return;
    };
    let Ok(key) = SortKey::try_from(key) else {
        ui.set_error("Invalid sort field.".into());
        return;
    };
    let pane = pane.index();
    if pane == 0 {
        ui.set_local_sort_key(key.as_str().into());
    } else {
        ui.set_remote_sort_key(key.as_str().into());
    }
    ui.set_error("".into());
    apply_view_pane(ui, pane);
}

/// Sort popover → toggle the targeted pane's asc/desc and re-apply.
pub(super) fn toggle_sort_dir(ui: &App) {
    let Ok(pane) = PaneId::try_from(ui.get_sort_pane().as_str()) else {
        ui.set_error("Invalid pane in sort request.".into());
        return;
    };
    let pane = pane.index();
    let current = if pane == 0 {
        ui.get_local_sort_dir()
    } else {
        ui.get_remote_sort_dir()
    };
    let Ok(next) = SortDirection::try_from(current.as_str()).map(SortDirection::reversed) else {
        ui.set_error("Invalid sort direction.".into());
        return;
    };
    if pane == 0 {
        ui.set_local_sort_dir(next.as_str().into());
    } else {
        ui.set_remote_sort_dir(next.as_str().into());
    }
    ui.set_error("".into());
    apply_view_pane(ui, pane);
}

/// Wire the bottom-bar path + sort-popover callbacks.
pub(super) fn wire_misc_ui(ui: &App) {
    {
        let uw = ui.as_weak();
        ui.on_update_selected_path(move || {
            if let Some(ui) = uw.upgrade() {
                refresh_selected_path(&ui);
            }
        });
    }
    {
        let uw = ui.as_weak();
        ui.on_copy_selected_path(move || {
            if let Some(ui) = uw.upgrade() {
                let p = selected_paths_for_clipboard(&ui);
                refresh_selected_path(&ui);
                if !p.is_empty() && copy_to_clipboard(&p) {
                    ui.set_status("copied to clipboard".into());
                    ui.set_error("".into());
                } else {
                    ui.set_status("".into());
                    ui.set_error("clipboard copy failed".into());
                }
            }
        });
    }
    {
        let uw = ui.as_weak();
        ui.on_apply_sort_field(move |key| {
            if let Some(ui) = uw.upgrade() {
                apply_sort_field(&ui, &key);
            }
        });
    }
    {
        let uw = ui.as_weak();
        ui.on_toggle_sort_dir(move || {
            if let Some(ui) = uw.upgrade() {
                toggle_sort_dir(&ui);
            }
        });
    }
}

/// Wire all keyboard + sidebar-eject callbacks.
pub(super) fn wire_keyboard(
    ui: &App,
    handle: &Handle,
    store: Arc<dyn CredentialStore>,
    panes: Panes,
    engine: TransferEngine,
    idx: Arc<Mutex<HashMap<i32, usize>>>,
) {
    {
        let ui_weak = ui.as_weak();
        ui.on_select_entry(move |pane, index, extend, toggle| {
            if let Some(ui) = ui_weak.upgrade() {
                match PaneId::try_from(pane.as_str()) {
                    Ok(pane) => select_entry(&ui, pane.index(), index, extend, toggle),
                    Err(error) => ui.set_error(error.into()),
                }
            }
        });
    }
    {
        let ui_weak = ui.as_weak();
        ui.on_select_all(move |pane, selected| {
            if let Some(ui) = ui_weak.upgrade() {
                match PaneId::try_from(pane.as_str()) {
                    Ok(pane) => select_all_entries(&ui, pane.index(), selected),
                    Err(error) => ui.set_error(error.into()),
                }
            }
        });
    }
    {
        let ui_weak = ui.as_weak();
        ui.on_move_selection(move |delta, extend| {
            if let Some(ui) = ui_weak.upgrade() {
                move_selection(&ui, delta, extend);
            }
        });
    }
    {
        let ui_weak = ui.as_weak();
        ui.on_type_ahead(move |letter| {
            if let Some(ui) = ui_weak.upgrade() {
                type_ahead(&ui, &letter);
            }
        });
    }
    {
        let (h, st, pn, en, ix, uw) = (
            handle.clone(),
            store.clone(),
            panes.clone(),
            engine.clone(),
            idx.clone(),
            ui.as_weak(),
        );
        ui.on_pane_enter(move || {
            pane_enter(
                &h,
                st.clone(),
                pn.clone(),
                en.clone(),
                ix.clone(),
                uw.clone(),
            );
        });
    }
    {
        let (h, st, pn, uw) = (handle.clone(), store.clone(), panes.clone(), ui.as_weak());
        ui.on_pane_delete(move || {
            pane_delete(&h, st.clone(), pn.clone(), uw.clone());
        });
    }
    {
        let (h, st, pn, uw) = (handle.clone(), store.clone(), panes.clone(), ui.as_weak());
        ui.on_pane_preview(move || {
            pane_preview(&h, st.clone(), pn.clone(), uw.clone());
        });
    }
    {
        let (en, pn, uw) = (engine.clone(), panes.clone(), ui.as_weak());
        ui.on_disconnect_pane(move |pane| {
            let Ok(pane) = PaneId::try_from(pane) else {
                if let Some(ui) = uw.upgrade() {
                    ui.set_error("pane index is out of range".into());
                }
                return;
            };
            disconnect_pane(en.clone(), pn.clone(), uw.clone(), pane.index());
        });
    }
}
