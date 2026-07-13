//! Pane selection, filtering, focus, and Slint model projection.

use super::*;

pub(super) fn active_pane_idx(ui: &App) -> usize {
    PaneId::try_from(ui.get_active_pane().as_str())
        .unwrap_or_default()
        .index()
}

/// Give the window keyboard focus to the root FocusScope. Slint delivers `key-pressed` ONLY to the
/// focused item (+ ancestors), and nothing focuses the root on startup — so the keyboard
/// (arrows / type-ahead / space / delete / enter) silently did nothing. `focus_next_item()`
/// focuses the first focusable item (the root FocusScope) when nothing is focused. Called on
/// launch and on every pane activation (pane/row click) so focus is re-asserted if a popup lost it.
pub(super) fn focus_root(ui: &App) {
    // Focus the ROOT FocusScope directly — NOT focus_next_item(). The old call advanced
    // (Tab-style) through the focus chain: when the root FocusScope already had focus, the
    // next focusable item is the sidebar "Filter servers" TextInput, so every pane/row click
    // stole keyboard focus and arrows/letters landed in the filter instead of the file list.
    //
    // set_focus_item with Programmatic reason walks focus from the given start item every time
    // (it does NOT advance from the currently-focused item): starting at the component root
    // (index 0) it lands on the first focusable item — the root FocusScope — regardless of what
    // (TextInput / nothing) held focus before. Idempotent and safe to call on every pane click.
    let inner = i_slint_core::window::WindowInner::from_pub(ui.window());
    let root = i_slint_core::item_tree::ItemRc::new_root(inner.component());
    inner.set_focus_item(&root, true, i_slint_core::items::FocusReason::Programmatic);
}

pub(super) fn pane_selected(ui: &App, pane: usize) -> i32 {
    if pane == 0 {
        ui.get_local_selected()
    } else {
        ui.get_remote_selected()
    }
}

pub(super) fn clear_range_selection(ui: &App, pane: usize) {
    if pane == 0 {
        ui.set_local_range_selected(false);
        ui.set_local_selection_anchor(-1);
        ui.set_local_selection_end(-1);
    } else {
        ui.set_remote_range_selected(false);
        ui.set_remote_selection_anchor(-1);
        ui.set_remote_selection_end(-1);
    }
}

pub(super) fn pane_selection(ui: &App, pane: usize) -> ModelRc<bool> {
    if pane == 0 {
        ui.get_local_selection()
    } else {
        ui.get_remote_selection()
    }
}

pub(super) fn selection_flags(ui: &App, pane: usize, count: usize) -> Vec<bool> {
    let model = pane_selection(ui, pane);
    (0..count)
        .map(|i| model.row_data(i).unwrap_or(false))
        .collect()
}

pub(super) fn set_selection_flags(ui: &App, pane: usize, flags: Vec<bool>) {
    let all = !flags.is_empty() && flags.iter().all(|selected| *selected);
    let model = ModelRc::from(Rc::new(VecModel::from(flags)));
    if pane == 0 {
        ui.set_local_selection(model);
        ui.set_local_all_selected(all);
    } else {
        ui.set_remote_selection(model);
        ui.set_remote_all_selected(all);
    }
}

pub(super) fn select_all_entries(ui: &App, pane: usize, selected: bool) {
    let count = pane_entries(ui, pane).row_count();
    set_selection_flags(ui, pane, vec![selected; count]);
    clear_range_selection(ui, pane);
    let cursor = if selected && count > 0 { 0 } else { -1 };
    if pane == 0 {
        ui.set_local_selected(cursor);
        ui.set_local_selection_anchor(cursor);
        ui.set_local_selection_end(cursor);
    } else {
        ui.set_remote_selected(cursor);
        ui.set_remote_selection_anchor(cursor);
        ui.set_remote_selection_end(cursor);
    }
}

pub(super) fn select_entry(ui: &App, pane: usize, index: i32, extend: bool, toggle: bool) {
    let count = pane_entries(ui, pane).row_count();
    if index < 0 || index as usize >= count {
        return;
    }
    let mut flags = selection_flags(ui, pane, count);
    let previous = pane_selected(ui, pane);
    let cursor;
    if toggle {
        flags[index as usize] = !flags[index as usize];
        clear_range_selection(ui, pane);
        if pane == 0 {
            ui.set_local_selection_anchor(index);
            ui.set_local_selection_end(index);
        } else {
            ui.set_remote_selection_anchor(index);
            ui.set_remote_selection_end(index);
        }
        cursor = if flags[index as usize] {
            index
        } else {
            flags
                .iter()
                .enumerate()
                .find_map(|(i, selected)| selected.then_some(i as i32))
                .unwrap_or(-1)
        };
    } else if extend && previous >= 0 {
        let anchor = if pane == 0 {
            ui.get_local_selection_anchor()
        } else {
            ui.get_remote_selection_anchor()
        };
        let anchor = if anchor >= 0 { anchor } else { previous };
        flags.fill(false);
        let start = anchor.min(index).max(0) as usize;
        let end = anchor.max(index).min(count.saturating_sub(1) as i32) as usize;
        for selected in &mut flags[start..=end] {
            *selected = true;
        }
        if pane == 0 {
            ui.set_local_selection_anchor(anchor);
            ui.set_local_selection_end(index);
            ui.set_local_range_selected(true);
        } else {
            ui.set_remote_selection_anchor(anchor);
            ui.set_remote_selection_end(index);
            ui.set_remote_range_selected(true);
        }
        cursor = index;
    } else {
        flags.fill(false);
        flags[index as usize] = true;
        clear_range_selection(ui, pane);
        if pane == 0 {
            ui.set_local_selection_anchor(index);
            ui.set_local_selection_end(index);
        } else {
            ui.set_remote_selection_anchor(index);
            ui.set_remote_selection_end(index);
        }
        cursor = index;
    }
    set_selection_flags(ui, pane, flags);
    if pane == 0 {
        ui.set_local_selected(cursor);
    } else {
        ui.set_remote_selected(cursor);
    }
}

pub(super) fn pane_entries(ui: &App, pane: usize) -> ModelRc<EntryRow> {
    if pane == 0 {
        ui.get_local_entries()
    } else {
        ui.get_remote_entries()
    }
}

pub(super) fn selected_transfer_rows(
    entries: &ModelRc<EntryRow>,
    selection: &ModelRc<bool>,
) -> Vec<EntryRow> {
    (0..entries.row_count())
        .filter(|i| selection.row_data(*i).unwrap_or(false))
        .filter_map(|i| entries.row_data(i))
        .collect()
}

pub(super) fn entry_matches_filter(entry: &EntryRow, query: &str) -> bool {
    let name = entry.name.to_string().to_lowercase();
    query
        .split_whitespace()
        .map(str::to_lowercase)
        .all(|token| name.contains(&token))
}

pub(super) fn pane_file_filter(ui: &App, pane: usize) -> String {
    if pane == 0 {
        ui.get_local_file_filter().to_string()
    } else {
        ui.get_remote_file_filter().to_string()
    }
}

/// Apply the current view (hidden-files + instant name filter + sort) of a pane's FULL list to
/// its UI model.
pub(super) fn apply_view_pane(ui: &App, pane: usize) {
    let show_hidden = ui.get_show_hidden();
    let file_filter = pane_file_filter(ui, pane);
    let (key, dir) = if pane == 0 {
        (
            ui.get_local_sort_key().to_string(),
            ui.get_local_sort_dir().to_string(),
        )
    } else {
        (
            ui.get_remote_sort_key().to_string(),
            ui.get_remote_sort_dir().to_string(),
        )
    };
    let key = SortKey::try_from(key.as_str()).unwrap_or(SortKey::Name);
    let direction = SortDirection::try_from(dir.as_str()).unwrap_or(SortDirection::Ascending);
    let full_model = if pane == 0 {
        ui.get_local_full()
    } else {
        ui.get_remote_full()
    };
    let mut rows: Vec<EntryRow> = (0..full_model.row_count())
        .filter_map(|i| full_model.row_data(i))
        .filter(|e| show_hidden || !e.name.starts_with('.'))
        .filter(|entry| entry_matches_filter(entry, &file_filter))
        .collect();
    // Snapshot of the TRUE u64 sizes for this pane (EntryRow.size is i32 and wraps >2 GiB).
    // Keyed by name so the size sort is correct for large files; missing entries (e.g. demo
    // rows) fall back to the i32 field.
    let true_sizes: HashMap<String, u64> = TRUE_SIZE
        .lock()
        .ok()
        .map(|g| {
            g.iter()
                .filter(|((p, _), _)| *p == pane)
                .map(|((_, n), s)| (n.clone(), *s))
                .collect()
        })
        .unwrap_or_default();
    // Same trick for mtimes: EntryRow.mtime is i32 and wraps after 2038-01-19, so the date sort
    // would order future-dated files as pre-1970. Use the true i64 mtime when we have it.
    let true_mtimes: HashMap<String, i64> = TRUE_MTIME
        .lock()
        .ok()
        .map(|g| {
            g.iter()
                .filter(|((p, _), _)| *p == pane)
                .map(|((_, n), m)| (n.clone(), *m))
                .collect()
        })
        .unwrap_or_default();
    rows.sort_by(|a, b| {
        let dirs = match (a.is_dir, b.is_dir) {
            (true, false) => Ordering::Less,
            (false, true) => Ordering::Greater,
            _ => Ordering::Equal,
        };
        if dirs != Ordering::Equal {
            return dirs;
        }
        let mut ord = match key {
            SortKey::Size => {
                let sa = true_sizes
                    .get(a.name.as_str())
                    .map(|s| *s as i128)
                    .unwrap_or(a.size as i128);
                let sb = true_sizes
                    .get(b.name.as_str())
                    .map(|s| *s as i128)
                    .unwrap_or(b.size as i128);
                sa.cmp(&sb)
            }
            SortKey::Date => {
                let ma = true_mtimes
                    .get(a.name.as_str())
                    .copied()
                    .unwrap_or(a.mtime as i64);
                let mb = true_mtimes
                    .get(b.name.as_str())
                    .copied()
                    .unwrap_or(b.mtime as i64);
                ma.cmp(&mb)
            }
            SortKey::Owner => a.owner.to_lowercase().cmp(&b.owner.to_lowercase()),
            SortKey::Group => a.group.to_lowercase().cmp(&b.group.to_lowercase()),
            SortKey::Permissions => a.permissions.cmp(&b.permissions),
            SortKey::Name => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
        };
        if direction == SortDirection::Descending {
            ord = ord.reverse();
        }
        ord
    });
    let count = rows.len() as i32;
    let model = ModelRc::from(Rc::new(VecModel::from(rows)));
    if pane == 0 {
        ui.set_local_entries(model);
        ui.set_local_count(count);
        ui.set_local_selected(-1);
        set_selection_flags(ui, pane, vec![false; count as usize]);
        clear_range_selection(ui, pane);
    } else {
        ui.set_remote_entries(model);
        ui.set_remote_count(count);
        ui.set_remote_selected(-1);
        set_selection_flags(ui, pane, vec![false; count as usize]);
        clear_range_selection(ui, pane);
    }
}

pub(super) fn set_pane_full(ui: &App, pane: usize, rows: Vec<EntryRow>, cwd: &str) {
    let m = ModelRc::from(Rc::new(VecModel::from(rows)));
    if pane == 0 {
        ui.set_local_full(m);
        ui.set_local_cwd(cwd.into());
        ui.set_local_path_display(display_path(cwd).into());
        ui.set_left_in_remote_trash(cwd_is_remote_trash(cwd));
    } else {
        ui.set_remote_full(m);
        ui.set_remote_cwd(cwd.into());
        ui.set_remote_path_display(display_path(cwd).into());
        ui.set_right_in_remote_trash(cwd_is_remote_trash(cwd));
    }
    apply_view_pane(ui, pane);
}
