//! App controller: owns the Slint window, the Tokio runtime, the credential store and
//! the transfer engine, and bridges every async result back onto the UI thread via
//! `slint::invoke_from_event_loop`. All Slint callbacks are wired here, including the
//! connection manager (add / edit / delete / import from a third-party file manager).

use std::path::{Path, PathBuf};
use std::rc::Rc;
#[cfg(target_os = "macos")]
use std::cell::Cell;
use std::time::Instant;
use std::sync::{Arc, LazyLock, Mutex};
use std::collections::{HashMap, HashSet, VecDeque};
use std::cmp::Ordering;

use futures::{stream, StreamExt};
use slint::{ComponentHandle, Global, Model, ModelRc, VecModel, Weak};
use slint::winit_030::WinitWindowAccessor;
use tokio::sync::mpsc;
use tokio::runtime::Handle;

use gmacftp::model::{
    ConnectionId, ConnectionSpec, Protocol, RemoteEntry, TransferDirection, TransferId,
    TransferJob,
};
use gmacftp::net;
use gmacftp::store::{self, CredentialStore};
use gmacftp::transfer::{TransferEngine, TransferState, TransferUpdate};

use crate::{App, ConnRow, EntryRow, LocalFavoriteRow, TransferRow};

type ConnList = Arc<Mutex<Vec<ConnectionSpec>>>;

/// Per-session password cache: (host, user) -> password. The first read per connection
/// hits the Keychain (one macOS auth prompt); every later connect/navigation/refresh in
/// the same session uses the cached value — so you get prompted ONCE per connection,
/// not on every folder-enter. (Without a paid Developer-ID signature, macOS can't bind
/// "Always Allow" to an ad-hoc-signed app across launches, so this in-memory cache is
/// the fix within a session.)
static PASSWORD_CACHE: LazyLock<Mutex<HashMap<(String, String), String>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

const MAX_LOCAL_FOLDER_STAT_FILES: usize = 3_000;
const MAX_REMOTE_FOLDER_STAT_FILES: usize = 2_000;

/// A copy blocked on a name conflict, awaiting the user's choice in the overwrite dialog.
/// (src_pane, dst_pane, name, is_dir, total)
static PENDING_COPY: LazyLock<Mutex<Option<(usize, usize, String, bool, Option<u64>)>>> =
    LazyLock::new(|| Mutex::new(None));

/// Finder→server uploads blocked on the overwrite-conflict dialog (the external-drag twin of
/// PENDING_COPY). A FIFO queue: a multi-file drop may contain several conflicting names, confirmed
/// one at a time. (spec, local source path, remote directory, name, byte size, is_dir).
static PENDING_EXTERNAL_UPLOAD:
    LazyLock<Mutex<VecDeque<(ConnectionSpec, PathBuf, String, String, Option<u64>, bool)>>> =
    LazyLock::new(|| Mutex::new(VecDeque::new()));

/// Per-pane "Don't ask again this session" for the delete-confirmation dialog, indexed by pane
/// (0 = left, 1 = right). Keying per-pane (not one global flag) means ticking it while deleting on
/// one connection ONLY silences confirms for that pane — a local-Trash delete on the other pane
/// still asks, and a different server in the other pane is unaffected. Each slot is reset when
/// THAT pane's connection ends (connect / switch / Home / eject / disconnect on that pane), so the
/// suppression is scoped to a single steady connection — closer to how a third-party file manager / Transmit gate
/// "don't ask again", but session-local rather than app-persistent.
static SKIP_DELETE_CONFIRM: LazyLock<Mutex<[bool; 2]>> = LazyLock::new(|| Mutex::new([false, false]));

fn delete_confirm_skipped(pane: usize) -> bool {
    SKIP_DELETE_CONFIRM.lock().map(|g| g.get(pane).copied().unwrap_or(false)).unwrap_or(false)
}

fn set_skip_delete_confirm(pane: usize, v: bool) {
    if let Ok(mut g) = SKIP_DELETE_CONFIRM.lock() {
        if let Some(slot) = g.get_mut(pane) {
            *slot = v;
        }
    }
}

// The transfer-panel's VecModel lives on the UI thread only (Slint models are !Send).
// Background tasks (transfer forwarder, folder walks) reach it via this thread-local on the
// UI thread instead of capturing the Rc across threads (which would violate Send).
thread_local! {
    static TRANSFER_JOBS: std::cell::RefCell<Option<Rc<VecModel<TransferRow>>>> =
        std::cell::RefCell::new(None);
}
/// Push a transfer row from anywhere on the UI thread.
fn jobs_push(row: TransferRow, idx: &Arc<Mutex<HashMap<i32, usize>>>) {
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

fn transfer_summary_from_rows(rows: &[TransferRow]) -> String {
    if rows.is_empty() {
        return "0 transfers".to_string();
    }

    let active = rows.iter().filter(|r| r.state.as_str() == "active").count();
    let queued = rows.iter().filter(|r| r.state.as_str() == "queued").count();
    let failed = rows.iter().filter(|r| r.state.as_str() == "failed").count();
    let done = rows.iter().filter(|r| r.state.as_str() == "done").count();
    let speed = rows
        .iter()
        .filter(|r| r.state.as_str() == "active")
        .filter_map(|r| parse_mbps(r.message.as_str()))
        .sum::<f32>();

    let mut parts = Vec::new();
    if active > 0 {
        parts.push(format!("{active} active"));
        if speed > 0.0 {
            parts.push(format!("{speed:.1} MB/s total"));
        }
    }
    if queued > 0 {
        parts.push(format!("{queued} queued"));
    }
    if failed > 0 {
        parts.push(format!("{failed} failed"));
    }
    if done > 0 && active == 0 && queued == 0 && failed == 0 {
        parts.push(format!("{done} done"));
    }
    if parts.is_empty() {
        parts.push(format!("{} transfers", rows.len()));
    }
    parts.join(" · ")
}

fn parse_mbps(message: &str) -> Option<f32> {
    let (number, rest) = message.trim().split_once(' ')?;
    if !rest.starts_with("MB/s") {
        return None;
    }
    number.parse::<f32>().ok()
}

fn update_transfer_summary_from_model(ui: &App, jobs: &Rc<VecModel<TransferRow>>) {
    let rows = (0..jobs.row_count())
        .filter_map(|i| jobs.row_data(i))
        .collect::<Vec<_>>();
    ui.set_transfer_summary(transfer_summary_from_rows(&rows).into());
}

fn update_transfer_summary(ui: &App) {
    TRANSFER_JOBS.with(|jm| {
        let b = jm.borrow();
        if let Some(jobs) = b.as_ref() {
            update_transfer_summary_from_model(ui, jobs);
        } else {
            ui.set_transfer_summary("0 transfers".into());
        }
    });
}

fn next_xfer_id() -> i32 {
    static NEXT: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(1);
    NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed) as i32
}

/// Update an existing transfer row by id (UI thread).
fn jobs_set(id: i32, idx: &Arc<Mutex<HashMap<i32, usize>>>, state: &str, done: i32, total: i32, msg: &str) {
    TRANSFER_JOBS.with(|jm| {
        let b = jm.borrow();
        let Some(jobs) = b.as_ref() else { return };
        let Some(i) = idx.lock().ok().and_then(|g| g.get(&id).copied()) else { return };
        if let Some(mut row) = jobs.row_data(i) {
            row.state = state.into();
            row.done = done;
            row.total = total;
            row.fraction = if total > 0 { done as f32 / total as f32 } else if state == "done" { 1.0 } else { 0.0 };
            row.progress_text = fmt_transfer_progress(done, total).into();
            row.message = msg.into();
            jobs.set_row_data(i, row);
        }
    });
}

/// Compact "Jun 19 11:06" for a unix timestamp, in the system LOCAL timezone. Empty if unknown.
/// File mtimes are unix-epoch (UTC) at the source; this renders them in local time (via the C
/// library's TZ database, so DST is handled). Previously it rendered UTC, which read 2h off in
/// e.g. CEST (UTC+2).
fn fmt_date(secs: i64) -> String {
    if secs <= 0 {
        return String::new();
    }
    let (mo, d, h, m) = local_md_hm(secs);
    let month = match mo {
        1 => "Jan",
        2 => "Feb",
        3 => "Mar",
        4 => "Apr",
        5 => "May",
        6 => "Jun",
        7 => "Jul",
        8 => "Aug",
        9 => "Sep",
        10 => "Oct",
        11 => "Nov",
        _ => "Dec",
    };
    format!("{month} {d:02}  {h:02}:{m:02}")
}

/// Broken-down LOCAL time (month 1-12, day, hour, minute) for a unix timestamp.
#[cfg(unix)]
fn local_md_hm(secs: i64) -> (i32, i32, i32, i32) {
    // C `struct tm` (macOS/glibc): nine ints, then `long tm_gmtoff`, then `char *tm_zone`. Only the
    // leading int fields (tm_mon/tm_mday/tm_hour/tm_min) are read; the trailing fields are sized to
    // match the struct so localtime_r writes within bounds.
    #[repr(C)]
    struct Tm {
        tm_sec: i32,
        tm_min: i32,
        tm_hour: i32,
        tm_mday: i32,
        tm_mon: i32,
        tm_year: i32,
        tm_wday: i32,
        tm_yday: i32,
        tm_isdst: i32,
        tm_gmtoff: i64,
        tm_zone: *const std::os::raw::c_char,
    }
    extern "C" {
        fn localtime_r(timep: *const i64, result: *mut Tm) -> *mut Tm;
    }
    let mut tm = Tm {
        tm_sec: 0,
        tm_min: 0,
        tm_hour: 0,
        tm_mday: 1,
        tm_mon: 0,
        tm_year: 0,
        tm_wday: 0,
        tm_yday: 0,
        tm_isdst: 0,
        tm_gmtoff: 0,
        tm_zone: std::ptr::null(),
    };
    // SAFETY: localtime_r fills the broken-down local time for the given time_t into `tm`. The Tm
    // layout matches the platform struct tm; the pointers are valid for the call.
    let t = secs;
    let ok = unsafe { !localtime_r(&t as *const i64, &mut tm as *mut Tm).is_null() };
    if ok {
        (tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min)
    } else {
        utc_md_hm(secs)
    }
}

#[cfg(not(unix))]
fn local_md_hm(secs: i64) -> (i32, i32, i32, i32) {
    utc_md_hm(secs)
}

/// UTC fallback (non-Unix, or if localtime_r returns null).
fn utc_md_hm(secs: i64) -> (i32, i32, i32, i32) {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let h = (rem / 3600) as i32;
    let m = ((rem % 3600) / 60) as i32;
    // civil date from days-since-epoch (Howard Hinnant's algorithm)
    let z = days + 719_468;
    let era = (if z >= 0 { z } else { z - 146_096 }) / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as i32;
    let mo = if mp < 10 { mp + 3 } else { mp - 9 } as i32;
    (mo, d, h, m)
}

fn fmt_size(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * KB;
    const GB: u64 = 1024 * MB;
    if bytes < KB {
        format!("{bytes} B")
    } else if bytes < MB {
        format!("{} KB", (bytes + KB / 2) / KB)
    } else if bytes < GB {
        let whole = bytes / MB;
        let tenth = ((bytes % MB) * 10 + MB / 2) / MB;
        if tenth == 0 {
            format!("{whole} MB")
        } else if tenth == 10 {
            format!("{} MB", whole + 1)
        } else {
            format!("{whole}.{tenth} MB")
        }
    } else {
        let whole = bytes / GB;
        let tenth = ((bytes % GB) * 10 + GB / 2) / GB;
        if tenth == 0 {
            format!("{whole} GB")
        } else if tenth == 10 {
            format!("{} GB", whole + 1)
        } else {
            format!("{whole}.{tenth} GB")
        }
    }
}

fn fmt_size_partial(bytes: u64, partial: bool) -> String {
    let mut s = fmt_size(bytes);
    if partial {
        s.push('+');
    }
    s
}

fn fmt_transfer_progress(done: i32, total: i32) -> String {
    let done = done.max(0) as u64;
    if total > 0 {
        format!("{} / {}", fmt_size(done), fmt_size(total as u64))
    } else {
        fmt_size(done)
    }
}

// ── pane model (Tier 2: each of the two panes is independently Local or Remote) ──
#[derive(Clone)]
enum PaneKind { Local, Remote }

#[derive(Clone)]
struct PaneState {
    kind: PaneKind,
    conn: Option<ConnectionSpec>,
    cwd: String,
    nav: Nav,
}
type Panes = Arc<Mutex<[PaneState; 2]>>; // pane 0 = left (local-* props), pane 1 = right (remote-* props)

/// A live background session: a connected server + its current directory + nav history. The
/// CONNECTED sidebar lists these. Connecting a 2nd server ADDS a session (the 1st stays alive in
/// the background) instead of replacing it; clicking a session swaps it into a pane; eject removes
/// it. Each pane shows one session at a time, but many can be open concurrently.
#[derive(Clone)]
struct ActiveSession { conn: ConnectionSpec, cwd: String, nav: Nav }
type Sessions = Arc<Mutex<Vec<ActiveSession>>>;

fn active_pane_idx(ui: &App) -> usize {
    if ui.get_active_pane().as_str() == "remote" { 1 } else { 0 }
}

/// Give the window keyboard focus to the root FocusScope. Slint delivers `key-pressed` ONLY to the
/// focused item (+ ancestors), and nothing focuses the root on startup — so the keyboard
/// (arrows / type-ahead / space / delete / enter) silently did nothing. `focus_next_item()`
/// focuses the first focusable item (the root FocusScope) when nothing is focused. Called on
/// launch and on every pane activation (pane/row click) so focus is re-asserted if a popup lost it.
fn focus_root(ui: &App) {
    // Focus the ROOT FocusScope directly — NOT focus_next_item(). The old call advanced
    // (Tab-style) through the focus chain: when the root FocusScope already had focus, the
    // next focusable item is the sidebar "Filter servers" TextInput, so every pane/row click
    // stole keyboard focus and arrows/letters landed in the filter instead of the file list.
    //
    // set_focus_item with Programmatic reason walks focus from the given start item every time
    // (it does NOT advance from the currently-focused item): starting at the component root
    // (index 0) it lands on the first focusable item — the root FocusScope — regardless of what
    // (TextInput / nothing) held focus before. Idempotent and safe to call on every pane click.
    let inner = i_slint_core::window::WindowInner::from_pub(&ui.window());
    let root = i_slint_core::item_tree::ItemRc::new_root(inner.component());
    inner.set_focus_item(&root, true, i_slint_core::items::FocusReason::Programmatic);
}

fn pane_selected(ui: &App, pane: usize) -> i32 {
    if pane == 0 { ui.get_local_selected() } else { ui.get_remote_selected() }
}
fn pane_entries(ui: &App, pane: usize) -> ModelRc<EntryRow> {
    if pane == 0 { ui.get_local_entries() } else { ui.get_remote_entries() }
}

/// Apply the current view (hidden-files filter + sort) of a pane's FULL list to its UI model.
fn apply_view_pane(ui: &App, pane: usize) {
    let show_hidden = ui.get_show_hidden();
    let (key, dir) = if pane == 0 {
        (ui.get_local_sort_key().to_string(), ui.get_local_sort_dir().to_string())
    } else {
        (ui.get_remote_sort_key().to_string(), ui.get_remote_sort_dir().to_string())
    };
    let desc = dir == "desc";
    let full_model = if pane == 0 { ui.get_local_full() } else { ui.get_remote_full() };
    let mut rows: Vec<EntryRow> = (0..full_model.row_count())
        .filter_map(|i| full_model.row_data(i))
        .filter(|e| show_hidden || !e.name.starts_with('.'))
        .collect();
    // Snapshot of the TRUE u64 sizes for this pane (EntryRow.size is i32 and wraps >2 GiB).
    // Keyed by name so the size sort is correct for large files; missing entries (e.g. demo
    // rows) fall back to the i32 field.
    let true_sizes: HashMap<String, u64> = TRUE_SIZE
        .lock()
        .ok()
        .map(|g| g.iter().filter(|((p, _), _)| *p == pane).map(|((_, n), s)| (n.clone(), *s)).collect())
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
        let mut ord = match key.as_str() {
            "size" => {
                let sa = true_sizes.get(a.name.as_str()).map(|s| *s as i128).unwrap_or(a.size as i128);
                let sb = true_sizes.get(b.name.as_str()).map(|s| *s as i128).unwrap_or(b.size as i128);
                sa.cmp(&sb)
            }
            "date" => a.mtime.cmp(&b.mtime),
            _ => a.name.to_lowercase().cmp(&b.name.to_lowercase()),
        };
        if desc {
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
    } else {
        ui.set_remote_entries(model);
        ui.set_remote_count(count);
        ui.set_remote_selected(-1);
    }
}

fn set_pane_full(ui: &App, pane: usize, rows: Vec<EntryRow>, cwd: &str) {
    let m = ModelRc::from(Rc::new(VecModel::from(rows)));
    if pane == 0 {
        ui.set_local_full(m);
        ui.set_local_cwd(cwd.into());
        ui.set_local_path_display(display_path(cwd).into());
    } else {
        ui.set_remote_full(m);
        ui.set_remote_cwd(cwd.into());
        ui.set_remote_path_display(display_path(cwd).into());
    }
    apply_view_pane(ui, pane);
}

fn display_path(path: &str) -> String {
    let trimmed = path.trim();
    if trimmed.is_empty() || trimmed == "/" {
        return "/".to_string();
    }
    let parts = trimmed
        .trim_start_matches('/')
        .split('/')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>();
    if parts.is_empty() {
        "/".to_string()
    } else {
        format!("/ {}", parts.join(" / "))
    }
}

fn set_pane_kind_label(ui: &App, pane: usize, p: &PaneState) {
    let (k, host, proto, conn_id) = match p.kind {
        PaneKind::Local => ("local".to_string(), String::new(), String::new(), -1),
        PaneKind::Remote => (
            "remote".to_string(),
            p.conn.as_ref().map(|c| c.host.clone()).unwrap_or_default(),
            p.conn.as_ref().map(|c| c.protocol.to_string().to_uppercase()).unwrap_or_default(),
            p.conn.as_ref().map(|c| c.id.0 as i32).unwrap_or(-1),
        ),
    };
    if pane == 0 {
        ui.set_left_kind(k.into());
        ui.set_left_host(host.into());
        ui.set_left_protocol(proto.into());
        ui.set_left_conn_id(conn_id);
    } else {
        ui.set_right_kind(k.into());
        ui.set_right_host(host.into());
        ui.set_right_protocol(proto.into());
        ui.set_right_conn_id(conn_id);
    }
}

/// Per-pane navigation history (back / forward).
#[derive(Clone)]
struct Nav {
    history: Vec<String>,
    idx: usize,
}
impl Nav {
    fn at(path: String) -> Self {
        Nav { history: vec![path], idx: 0 }
    }
    fn current(&self) -> String {
        self.history.get(self.idx).cloned().unwrap_or_else(|| "/".to_string())
    }
    fn go(&mut self, path: String) {
        if self.history.last().map(|s| s.as_str()) == Some(path.as_str()) {
            return;
        }
        self.history.truncate(self.idx + 1);
        self.history.push(path);
        self.idx = self.history.len() - 1;
    }
    fn back(&mut self) -> Option<String> {
        if self.idx > 0 {
            self.idx -= 1;
            Some(self.current())
        } else {
            None
        }
    }
    fn forward(&mut self) -> Option<String> {
        if self.idx + 1 < self.history.len() {
            self.idx += 1;
            Some(self.current())
        } else {
            None
        }
    }
    fn reset(&mut self, path: String) {
        self.history = vec![path];
        self.idx = 0;
    }
}
impl Default for Nav {
    fn default() -> Self {
        Nav::at("/".to_string())
    }
}

/// Run the app: build window, runtime, store, engine; wire callbacks; enter event loop.
pub fn run() {
    // Build the winit backend directly (instead of via BackendSelector) so we can DISABLE
    // Slint's default (muda) menu bar. Without this, WinitWindowAdapter::activation_changed()
    // lazily installs muda's default NSMenu via NSApplication::setMainMenu on every
    // WindowEvent::Focused — overwriting the objc2 menu we install (the intermittent
    // "iCloud toggle missing" symptom). With the default menu bar off, our menu is the only
    // one, so it stays put.
    let mut builder = i_slint_backend_winit::Backend::builder();
    #[cfg(target_os = "macos")]
    {
        builder = builder.with_default_menu_bar(false);
    }
    let backend = builder
        .with_window_attributes_hook(|attributes| {
            #[cfg(target_os = "macos")]
            {
                use slint::winit_030::winit::platform::macos::WindowAttributesExtMacOS;

                return attributes
                    .with_transparent(true)
                    .with_decorations(true)
                    .with_titlebar_transparent(true)
                    .with_title_hidden(true)
                    .with_titlebar_hidden(true)
                    .with_titlebar_buttons_hidden(true)
                    .with_fullsize_content_view(true)
                    .with_has_shadow(true);
            }

            #[cfg(not(target_os = "macos"))]
            attributes.with_transparent(true)
        })
        .build()
        .expect("failed to build winit backend");
    slint::platform::set_platform(Box::new(backend))
        .expect("failed to set the slint platform");

    let ui = App::new().expect("failed to construct gmacFTP UI");

    // Native macOS menu bar (App/File/Edit/View/Window/Help). No-op off macOS.
    crate::macos_menu::install(ui.as_weak());

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("failed to build Tokio runtime");
    let handle = runtime.handle().clone();
    let store: Arc<dyn CredentialStore> = Arc::new(store::default_store());

    // Settings → TLS policy + locale + theme.
    let settings = store::settings::load();
    net::set_accept_invalid_tls(settings.accept_any_cert);
    crate::I18n::get(&ui).set_locale(settings.locale.clone().into());
    let theme = std::env::var("MACKFTP_THEME").unwrap_or_else(|_| settings.theme.clone());
    if matches!(theme.as_str(), "light" | "dark") {
        crate::Tokens::get(&ui).set_theme(theme.into());
    } else {
        crate::Tokens::get(&ui).set_theme(settings.theme.clone().into());
    }
    ui.set_accept_any_cert(settings.accept_any_cert);
    refresh_local_favorites_model(&ui);

    // iCloud sync (BEFORE bootstrap loads local files): pull the newest connections.json /
    // vault.bin from iCloud (NSUbiquitousKeyValueStore) into the local copies so this Mac
    // reflects the latest state from the user's other devices — and, if iCloud is still
    // empty but this Mac already has servers, seed iCloud from them (migration). No-op if
    // sync disabled. Local files are never deleted, so existing servers are always kept.
    let _ = store::cloud::bootstrap();

    let connections = if use_design_demo_connections() {
        design_demo_connections()
    } else {
        bootstrap(&store)
    };
    let conns: ConnList = Arc::new(Mutex::new(connections));

    let home = home_dir();
    let home_s = home.to_string_lossy().to_string();
    // Tier 2: two independent panes; both start as the local filesystem.
    let panes: Panes = Arc::new(Mutex::new([
        PaneState { kind: PaneKind::Local, conn: None, cwd: home_s.clone(), nav: Nav::at(home_s.clone()) },
        PaneState { kind: PaneKind::Local, conn: None, cwd: home_s.clone(), nav: Nav::at(home_s.clone()) },
    ]));
    {
        let p = panes.lock().expect("panes");
        set_pane_kind_label(&ui, 0, &p[0]);
        set_pane_kind_label(&ui, 1, &p[1]);
    }
    list_local_pane(&ui, 0, &home, &home_s);
    list_local_pane(&ui, 1, &home, &home_s);
    refresh_connections_model(&ui, &conns);
    // background session pool (CONNECTED sidebar) — empty until the first Connect
    let sessions: Sessions = Arc::new(Mutex::new(Vec::new()));
    ui.set_sessions(ModelRc::from(Rc::new(VecModel::default())));
    refresh_sessions_model(&ui, &sessions);

    let (upd_tx, upd_rx) = mpsc::channel::<TransferUpdate>(64);
    let engine = runtime.block_on(async { TransferEngine::start(store.clone(), upd_tx) });
    let jobs_model: Rc<VecModel<TransferRow>> = Rc::new(VecModel::default());
    let jobs_index: Arc<Mutex<HashMap<i32, usize>>> = Arc::new(Mutex::new(HashMap::new()));
    let eta_samples: Arc<Mutex<HashMap<i32, (Instant, u64)>>> = Arc::new(Mutex::new(HashMap::new()));
    ui.set_transfer_jobs(ModelRc::from(jobs_model.clone()));
    let demo_transfers = std::env::var_os("MACKFTP_DEMO_TRANSFERS").is_some();
    if demo_transfers {
        let demo = [
            ("backup-06-19.sql.gz", "download", "ftp.example.com  ->  ~/Downloads", "92 / 184 MB", 92 * 1024 * 1024, 184 * 1024 * 1024, 0.50, "active", "2.1 MB/s · 44s left"),
            ("photo-archive.zip", "upload", "~/Sites  ->  sftp.example.com", "47 / 58 MB", 47 * 1024 * 1024, 58 * 1024 * 1024, 0.82, "active", "3.4 MB/s · 3s left"),
            ("report-Q3.pdf", "download", "ftp.example.com  ->  ~/Downloads", "2.4 MB", 24 * 1024 * 100, 0, 0.0, "queued", "Waiting"),
            ("invoice-8871.pdf", "download", "ftp.example.com  ->  ~/Downloads", "412 KB", 412 * 1024, 412 * 1024, 1.0, "done", "Completed"),
            ("deploy.sh", "upload", "~/Sites  ->  sftp.example.com", "5 / 22 MB", 5 * 1024 * 1024, 22 * 1024 * 1024, 0.25, "failed", "Permission denied"),
        ];
        for (idx, (name, direction, route, progress_text, done, total, fraction, state, message)) in demo.into_iter().enumerate() {
            jobs_model.push(TransferRow {
                id: 10_000 + idx as i32,
                name: name.into(),
                direction: direction.into(),
                route: route.into(),
                done,
                total,
                progress_text: progress_text.into(),
                fraction,
                state: state.into(),
                message: message.into(),
            });
        }
    }
    update_transfer_summary_from_model(&ui, &jobs_model);
    if demo_transfers {
        ui.set_transfer_summary("2 active · 9.2 MB/s total · 1 queued".into());
    }
    if use_design_demo_main() {
        apply_design_demo_main(&ui, &panes, &sessions, &conns);
    }
    TRANSFER_JOBS.with(|j| *j.borrow_mut() = Some(jobs_model));
    spawn_progress_forwarder(&handle, store.clone(), panes.clone(), upd_rx, ui.as_weak(), jobs_index.clone(), eta_samples.clone());

    // ── callbacks ──
    wire_connect(&ui, &handle, store.clone(), conns.clone(), sessions.clone(), panes.clone());
    wire_refresh(&ui, &handle, store.clone(), panes.clone());
    wire_nav_pane(&ui, &handle, store.clone(), panes.clone(), 0);
    wire_nav_pane(&ui, &handle, store.clone(), panes.clone(), 1);
    wire_transfer_download(&ui, &handle, store.clone(), panes.clone(), engine.clone(), jobs_index.clone());
    wire_transfer_upload(&ui, &handle, store.clone(), panes.clone(), engine.clone(), jobs_index.clone());
    wire_toggle_locale(&ui);
    wire_toggle_tls(&ui);
    wire_toggle_theme(&ui);
    wire_copy_path(&ui);
    wire_disconnect(&ui, panes.clone(), sessions.clone(), engine.clone());
    wire_toggle_hidden(&ui);
    wire_sort(&ui, 0);
    wire_sort(&ui, 1);
    // connection manager
    wire_new(&ui);
    wire_edit(&ui, store.clone(), conns.clone());
    wire_delete(&ui, store.clone(), conns.clone());
    wire_save(&ui, store.clone(), conns.clone());
    wire_import(&ui, &handle, store.clone(), conns.clone());
    wire_connect_selected(&ui, &handle, store.clone(), conns.clone(), sessions.clone(), panes.clone());
    wire_server_filter(&ui);
    wire_reorder_saved_connections(&ui, conns.clone());
    wire_palette_filter(&ui);
    wire_set_pane_local(&ui, panes.clone());
    wire_local_favorites(&ui, panes.clone());
    wire_clear_finished(&ui, jobs_index.clone());
    wire_dismiss_transfer(&ui, jobs_index.clone());
    wire_set_transfers_paused(&ui, engine.clone());
    wire_window_controls(&ui, &handle, store.clone(), panes.clone(), engine.clone(), jobs_index.clone());
    wire_external_drag(&ui, &handle, store.clone(), panes.clone());
    wire_request_delete(&ui, &handle, store.clone(), panes.clone());
    wire_confirm_delete(&ui, &handle, store.clone(), panes.clone());
    wire_keyboard(&ui, &handle, store.clone(), panes.clone(), engine.clone(), jobs_index.clone());
    wire_misc_ui(&ui);
    wire_overwrite(&ui, &handle, store.clone(), panes.clone(), engine.clone(), jobs_index.clone());
    wire_session_controls(&ui, &handle, store.clone(), sessions.clone(), panes.clone(), engine.clone());
    // Re-assert keyboard focus on every pane/row click — Slint delivers key-pressed only to the
    // focused item, so we focus the root FocusScope whenever a pane becomes active.
    { let uw = ui.as_weak(); ui.on_activate_pane(move |_| { if let Some(ui) = uw.upgrade() { focus_root(&ui); refresh_selected_path(&ui); } }); }

    // Focus the root so keyboard control works immediately on launch (before any click).
    focus_root(&ui);

    // Test affordance: MACKFTP_AUTO_CONNECT=<id> auto-connects into the active pane.
    if let Ok(id) = std::env::var("MACKFTP_AUTO_CONNECT") {
        if let Ok(id) = id.trim().parse::<i32>() {
            let (handle2, store2, conns2, sessions2, panes2, ui_weak2) =
                (handle.clone(), store.clone(), conns.clone(), sessions.clone(), panes.clone(), ui.as_weak());
            std::thread::spawn(move || {
                std::thread::sleep(std::time::Duration::from_millis(1500));
                let _ = slint::invoke_from_event_loop(move || {
                    do_connect(&handle2, store2, conns2, sessions2, panes2, ui_weak2, id);
                });
            });
        }
    }

    if let Ok(panel) = std::env::var("MACKFTP_OPEN_PANEL") {
        match panel.trim().to_lowercase().as_str() {
            "transfers" | "transfer" => ui.set_transfer_panel_open(true),
            "servers" | "connections" | "manager" => ui.set_manager_open(true),
            "editor" | "connection-editor" => {
                ui.set_editor_id(1);
                ui.set_editor_name("Production".into());
                ui.set_editor_protocol("ftp".into());
                ui.set_editor_host("ftp.example.com".into());
                ui.set_editor_port("21".into());
                ui.set_editor_user("deploy".into());
                ui.set_editor_password("password".into());
                ui.set_editor_open(true);
            }
            "delete" | "delete-dialog" => {
                ui.set_delete_pane("local".into());
                ui.set_delete_name("deploy.sh".into());
                ui.set_delete_path("/Sites/Projects/deploy.sh".into());
                ui.set_delete_is_dir(false);
                ui.set_delete_open(true);
            }
            "sort" | "sort-popover" => {
                ui.set_sort_pane("local".into());
                ui.set_sort_open(true);
            }
            "overwrite" | "overwrite-dialog" => {
                ui.set_overwrite_name("report-Q3.pdf".into());
                ui.set_overwrite_open(true);
            }
            "palette" | "command-palette" => {
                ui.set_palette_query("production".into());
                apply_palette_filter(&ui);
                ui.set_palette_open(true);
            }
            _ => {}
        }
    }

    ui.run().expect("gmacFTP event loop exited with error");
    drop(engine);
    drop(runtime);
}

// ── bootstrap / import ────────────────────────────────────────────────────────

fn bootstrap(store: &Arc<dyn CredentialStore>) -> Vec<ConnectionSpec> {
    // Seed import is ONE-TIME: only when no metadata exists yet (first launch). We do NOT
    // re-read the plaintext seed on every launch — that would let a modified/dropped
    // connections.json (or a hostile MACKFTP_SEED) silently OVERWRITE vault credentials
    // (M12). initial_seed_import already persists metadata + seeds the vault.
    match store::load_metadata() {
        Ok(Some(s)) if !s.is_empty() => s,
        _ => initial_seed_import(store),
    }
}

fn use_design_demo_connections() -> bool {
    if std::env::var_os("MACKFTP_DEMO_CONNECTIONS").is_some() {
        return true;
    }
    let Ok(panel) = std::env::var("MACKFTP_OPEN_PANEL") else { return false };
    matches!(
        panel.trim().to_lowercase().as_str(),
        "servers" | "connections" | "manager" | "palette" | "command-palette"
    )
}

fn use_design_demo_main() -> bool {
    std::env::var_os("MACKFTP_DEMO_MAIN").is_some()
}

fn design_demo_connections() -> Vec<ConnectionSpec> {
    [
        (1, "Production", Protocol::Ftp, "ftp.example.com", 21, "deploy"),
        (2, "Staging", Protocol::Sftp, "sftp.example.com", 22, "release"),
        (3, "CDN Edge", Protocol::Ftp, "cdn.example.com", 21, "edge"),
        (4, "Backups", Protocol::Sftp, "backup.example.com", 22, "backup"),
        (5, "Analytics", Protocol::Ftp, "stats.example.com", 21, "reports"),
    ]
    .into_iter()
    .map(|(id, name, protocol, host, port, user)| ConnectionSpec {
        id: ConnectionId(id),
        name: name.to_string(),
        protocol,
        host: host.to_string(),
        port,
        user: user.to_string(),
        initial_path: String::new(),
    })
    .collect()
}

fn demo_entry(name: &str, is_dir: bool, date: &str, size_text: &str, size: i32, mtime: i32) -> EntryRow {
    EntryRow {
        name: name.into(),
        is_dir,
        size,
        mtime,
        date: date.into(),
        size_text: size_text.into(),
        metadata_state: "ready".into(),
    }
}

fn set_exact_pane(ui: &App, pane: usize, cwd: &str, rows: Vec<EntryRow>, selected: i32) {
    let count = rows.len() as i32;
    let full = ModelRc::from(Rc::new(VecModel::from(rows.clone())));
    let visible = ModelRc::from(Rc::new(VecModel::from(rows)));
    if pane == 0 {
        ui.set_local_full(full);
        ui.set_local_entries(visible);
        ui.set_local_cwd(cwd.into());
        ui.set_local_path_display(display_path(cwd).into());
        ui.set_local_count(count);
        ui.set_local_selected(selected);
    } else {
        ui.set_remote_full(full);
        ui.set_remote_entries(visible);
        ui.set_remote_cwd(cwd.into());
        ui.set_remote_path_display(display_path(cwd).into());
        ui.set_remote_count(count);
        ui.set_remote_selected(selected);
    }
}

fn apply_design_demo_main(ui: &App, panes: &Panes, sessions: &Sessions, conns: &ConnList) {
    let specs = conns.lock().expect("connections lock").clone();
    let production = specs
        .iter()
        .find(|c| c.name == "Production")
        .cloned()
        .unwrap_or_else(|| design_demo_connections().remove(0));
    let staging = specs
        .iter()
        .find(|c| c.name == "Staging")
        .cloned()
        .unwrap_or_else(|| {
            let mut demo = design_demo_connections();
            demo.remove(1)
        });

    {
        let mut p = panes.lock().expect("panes");
        p[0] = PaneState {
            kind: PaneKind::Local,
            conn: None,
            cwd: "/Users/demo/Sites".to_string(),
            nav: Nav::at("/Users/demo/Sites".to_string()),
        };
        p[1] = PaneState {
            kind: PaneKind::Remote,
            conn: Some(production.clone()),
            cwd: "/var/www/html".to_string(),
            nav: Nav::at("/var/www/html".to_string()),
        };
        set_pane_kind_label(ui, 0, &p[0]);
        set_pane_kind_label(ui, 1, &p[1]);
    }
    ui.set_right_protocol("FTPS".into());

    {
        let mut s = sessions.lock().expect("sessions");
        s.clear();
        s.push(ActiveSession {
            conn: production.clone(),
            cwd: "/var/www/html".to_string(),
            nav: Nav::at("/var/www/html".to_string()),
        });
        s.push(ActiveSession {
            conn: staging,
            cwd: "/srv/stage".to_string(),
            nav: Nav::at("/srv/stage".to_string()),
        });
    }

    ui.set_active_pane("local".into());
    ui.set_active_connection(production.id.0 as i32);
    ui.set_active_host(production.host.clone().into());
    ui.set_show_hidden(true);
    ui.set_local_sort_key("custom".into());
    ui.set_remote_sort_key("custom".into());

    set_exact_pane(
        ui,
        0,
        "/Users/demo/Sites",
        vec![
            demo_entry("Sites", true, "", "", 0, 0),
            demo_entry("Projects", true, "", "", 0, 0),
            demo_entry("Backups", true, "", "", 0, 0),
            demo_entry("report-Q3.pdf", false, "Jun 12 14:22", "2.4 MB", 2_400_000, 1),
            demo_entry("invoice-8871.pdf", false, "Jun 09 09:10", "412 KB", 412_000, 2),
            demo_entry("photo-archive.zip", false, "May 28 18:44", "58 MB", 58_000_000, 3),
            demo_entry("deploy.sh", false, "Jun 18 11:02", "4 KB", 4_000, 4),
            demo_entry("README.md", false, "Jun 04 08:30", "6 KB", 6_000, 5),
        ],
        1,
    );
    set_exact_pane(
        ui,
        1,
        "/var/www/html",
        vec![
            demo_entry("html", true, "", "", 0, 0),
            demo_entry("logs", true, "", "", 0, 0),
            demo_entry("config", true, "", "", 0, 0),
            demo_entry("index.php", false, "Jun 19 10:15", "8 KB", 8_000, 1),
            demo_entry(".htaccess", false, "Jun 18 22:40", "2 KB", 2_000, 2),
            demo_entry("backup-06-19.sql.gz", false, "Jun 19 03:00", "184 MB", 184_000_000, 3),
            demo_entry("favicon.ico", false, "Jun 10 13:00", "8 KB", 8_000, 4),
            demo_entry("sitemap.xml", false, "Jun 09 09:05", "24 KB", 24_000, 5),
        ],
        5,
    );

    ui.set_selected_path("/Users/demo/Sites/Projects".into());
    ui.set_transfer_active(true);
    ui.set_transfer_fraction(0.38);
    ui.set_transfer_label("Downloading report-Q3.pdf".into());
    ui.set_transfer_done(1_400_000);
    ui.set_transfer_total(2_400_000);
    ui.set_transfer_progress_text(fmt_transfer_progress(1_400_000, 2_400_000).into());
    ui.set_error("".into());
    ui.set_status("".into());
    refresh_sessions_model(ui, sessions);
    refresh_connections_model(ui, conns);
}

/// First-launch import: parse the a third-party file manager seed, store passwords, persist metadata.
fn initial_seed_import(store: &Arc<dyn CredentialStore>) -> Vec<ConnectionSpec> {
    for candidate in seed_candidates() {
        if let Ok(json) = std::fs::read_to_string(&candidate) {
            tracing::info!(path = %candidate.display(), "importing connection seed");
            match store::load_seed(&json, store.as_ref()) {
                Ok(specs) => {
                    let _ = store::save_metadata(&specs);
                    return specs;
                }
                Err(e) => tracing::warn!(error = %e, "seed import failed"),
            }
        }
    }
    Vec::new()
}

/// Where to look for an optional local JSON seed. The default public build never embeds
/// a developer-machine path; pass MACKFTP_SEED explicitly when importing private data.
fn seed_candidates() -> Vec<PathBuf> {
    let mut v = Vec::new();
    if let Ok(p) = std::env::var("MACKFTP_SEED") {
        v.push(PathBuf::from(p));
    }
    v.push(PathBuf::from("data/connections.json"));
    v
}

fn refresh_connections_model(ui: &App, conns: &ConnList) {
    let active = ui.get_active_connection();
    let demo = use_design_demo_connections();
    let model: Vec<ConnRow> = conns
        .lock()
        .expect("connections lock")
        .iter()
        .map(|c| ConnRow {
            id: c.id.0 as i32,
            label: c.name.clone().into(),
            sub: if demo {
                format!("{}:{}", c.host, c.port)
            } else {
                format!("{}@{}:{}", c.user, c.host, c.port)
            }
            .into(),
            protocol: demo_protocol_label(c, demo).into(),
            connected: c.id.0 as i32 == active,
        })
        .collect();
    ui.set_connections(ModelRc::from(Rc::new(VecModel::from(model))));
    apply_server_filter(ui);
    apply_palette_filter(ui);
}

fn demo_protocol_label(c: &ConnectionSpec, demo: bool) -> String {
    if demo && c.name == "Production" {
        "FTPS".to_string()
    } else {
        c.protocol.to_string().to_uppercase()
    }
}

fn conn_row_matches(row: &ConnRow, query: &str) -> bool {
    let query = query.trim().to_lowercase();
    if query.is_empty() {
        return true;
    }
    row.label.to_string().to_lowercase().contains(&query)
        || row.sub.to_string().to_lowercase().contains(&query)
        || row.protocol.to_string().to_lowercase().contains(&query)
}

fn model_rows(model: ModelRc<ConnRow>) -> Vec<ConnRow> {
    (0..model.row_count())
        .filter_map(|i| model.row_data(i))
        .collect()
}

fn apply_server_filter(ui: &App) {
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

fn wire_server_filter(ui: &App) {
    let ui_weak = ui.as_weak();
    ui.on_filter_servers(move |query| {
        if let Some(ui) = ui_weak.upgrade() {
            ui.set_server_filter(query);
            apply_server_filter(&ui);
        }
    });
}

fn wire_window_controls(
    ui: &App,
    handle: &Handle,
    store: Arc<dyn CredentialStore>,
    panes: Panes,
    engine: TransferEngine,
    idx: Arc<Mutex<HashMap<i32, usize>>>,
) {
    #[cfg(target_os = "macos")]
    {
        let window_shape_configured = Rc::new(Cell::new(false));
        // The menu is installed before `ui.run()`; this flag drives a ONE-SHOT re-assert on the
        // first winit window event (which fires after the event loop has started), so our menu
        // wins over any default menu the winit backend installs during launch.
        let menu_reasserted = Rc::new(Cell::new(false));
        let (uw, handle, store, panes, engine, idx) =
            (ui.as_weak(), handle.clone(), store.clone(), panes.clone(), engine.clone(), idx.clone());
        ui.window().on_winit_window_event(move |slint_window, event| {
            if !menu_reasserted.replace(true) {
                crate::macos_menu::reassert(uw.clone());
            }
            if !window_shape_configured.get()
                && slint_window
                    .with_winit_window(configure_macos_window_shape)
                    .is_some()
            {
                window_shape_configured.set(true);
            }
            if let Some(ui) = uw.upgrade() {
                match event {
                    slint::winit_030::winit::event::WindowEvent::HoveredFile(_) => {
                        let pane = slint_window
                            .with_winit_window(cursor_x_in_window)
                            .flatten()
                            .map(|x| if x > 240.0 + ui.get_pane_split() as f64 + 24.0 { 1 } else { 0 })
                            .unwrap_or_else(|| active_pane_idx(&ui));
                        ui.set_external_drop_pane(pane as i32);
                        ui.set_external_drop_active(true);
                    }
                    slint::winit_030::winit::event::WindowEvent::HoveredFileCancelled => {
                        ui.set_external_drop_active(false);
                        ui.set_external_drop_pane(-1);
                    }
                    slint::winit_030::winit::event::WindowEvent::DroppedFile(path) => {
                        // Detect the drop target from the LIVE cursor position (where the file is
                        // dropped), not the HoveredFile-set value. That value is reset after the
                        // first file of a multi-file drop — so files 2..N would otherwise land in
                        // pane 0 (local) and only the first file uploads — and it falls back to the
                        // active pane when hover detection is unreliable, forcing the user to click
                        // the target pane first. Reading the cursor here auto-detects the pane and
                        // routes every file of a multi-file drop to the correct pane.
                        let pane = slint_window
                            .with_winit_window(cursor_x_in_window)
                            .flatten()
                            .map(|x| if x > 240.0 + ui.get_pane_split() as f64 + 24.0 { 1 } else { 0 })
                            .unwrap_or_else(|| ui.get_external_drop_pane().max(0) as usize);
                        ui.set_external_drop_active(false);
                        ui.set_external_drop_pane(-1);
                        receive_external_path(&handle, store.clone(), panes.clone(), engine.clone(), idx.clone(), ui.as_weak(), pane.min(1), path.clone());
                    }
                    _ => {}
                }
            }
            slint::winit_030::EventResult::Propagate
        });
    }

    let ui_weak = ui.as_weak();
    ui.on_start_window_drag(move || {
        if let Some(ui) = ui_weak.upgrade() {
            let _ = ui.window().with_winit_window(|window| window.drag_window());
        }
    });

    let ui_weak = ui.as_weak();
    ui.on_minimize_window(move || {
        if let Some(ui) = ui_weak.upgrade() {
            let _ = ui.window().with_winit_window(|window| window.set_minimized(true));
        }
    });

    let ui_weak = ui.as_weak();
    ui.on_toggle_window_fullscreen(move || {
        if let Some(ui) = ui_weak.upgrade() {
            let _ = ui.window().with_winit_window(|window| {
                if window.fullscreen().is_some() {
                    window.set_fullscreen(None);
                } else {
                    window.set_fullscreen(Some(slint::winit_030::winit::window::Fullscreen::Borderless(None)));
                }
            });
        }
    });

    ui.on_close_window(move || {
        let _ = slint::quit_event_loop();
    });
}

fn wire_external_drag(ui: &App, handle: &Handle, store: Arc<dyn CredentialStore>, panes: Panes) {
    let (uw, handle, panes) = (ui.as_weak(), handle.clone(), panes.clone());
    ui.on_start_external_drag(move |pane_name, row| {
        let Some(ui) = uw.upgrade() else { return };
        let pane = if pane_name.as_str() == "remote" { 1 } else { 0 };
        let entry = if pane == 0 { ui.get_local_entries().row_data(row as usize) } else { ui.get_remote_entries().row_data(row as usize) };
        let Some(entry) = entry else { return };
        let state = panes.lock().ok().map(|p| p[pane].clone());
        let Some(state) = state else { return };
        let mut path = PathBuf::from(&state.cwd).join(entry.name.as_str());
        if matches!(state.kind, PaneKind::Remote) {
            let Some(spec) = state.conn else { return };
            let Some(password) = password_for(&store, &spec) else { return };
            let remote = join_remote(PathBuf::from(&state.cwd).join(entry.name.as_str()));
            match materialize_remote_drag(&handle, &spec, &password, &remote, entry.name.as_str(), entry.is_dir) {
                Ok(p) => path = p,
                Err(e) => { ui.set_error(format!("Could not prepare drag: {e}").into()); return; }
            };
        }
        let Ok(path) = std::fs::canonicalize(path) else { return };
        let image = drag_preview_image().unwrap_or_else(|| drag::Image::File(path.clone()));
        let _ = ui.window().with_winit_window(|window| {
            let _ = drag::start_drag(window, drag::DragItem::Files(vec![path]), image, |_, _| {}, Default::default());
        });
    });
}

fn receive_external_path(
    handle: &Handle,
    store: Arc<dyn CredentialStore>,
    panes: Panes,
    engine: TransferEngine,
    idx: Arc<Mutex<HashMap<i32, usize>>>,
    ui: Weak<App>,
    pane: usize,
    source: PathBuf,
) {
    let Some(name) = source.file_name().and_then(|n| n.to_str()).map(str::to_owned) else { return };
    let Some(state) = panes.lock().ok().map(|p| p[pane].clone()) else { return };
    let is_dir = source.is_dir();
    match state.kind {
        PaneKind::Local => {
            let destination = PathBuf::from(&state.cwd).join(&name);
            if destination == source { return; }
            let (h, st, pn, uw) = (handle.clone(), store, panes, ui.clone());
            if let Some(u) = ui.upgrade() { u.set_status(format!("Copying {name}...").into()); }
            handle.spawn(async move {
                let result = tokio::task::spawn_blocking(move || {
                    if is_dir { fs_copy_tree(&source, &destination); Ok(()) }
                    else { std::fs::copy(&source, &destination).map(|_| ()).map_err(|_| ()) }
                }).await;
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(u) = uw.upgrade() {
                        match result { Ok(Ok(())) => u.set_status(format!("Copied {name}").into()), _ => u.set_error(format!("Could not copy {name}").into()) }
                        refresh_both_panes(&h, st, pn, u.as_weak());
                    }
                });
            });
        }
        PaneKind::Remote => {
            let Some(spec) = state.conn else { return };
            let remote_dir = state.cwd.clone();
            let size = source.metadata().ok().map(|m| m.len());
            // Check for a name conflict on the server before uploading — never silently overwrite
            // (Finder→server used to clobber an existing same-name file with no prompt). On conflict,
            // route through the same overwrite dialog as the in-app copy.
            let Some(pw) = password_for(&store, &spec) else { set_err(&ui, "missing credential"); return };
            let (h, engine2, idx2, spec2, source2, name2, size2, ui2) = (
                handle.clone(), engine.clone(), idx.clone(), spec.clone(), source.clone(),
                name.clone(), size, ui.clone(),
            );
            handle.spawn(async move {
                let exists = match net::remote_exists(&spec2, &pw, &remote_dir, &name2).await {
                    Ok(b) => b,
                    // A connect/list failure must NOT read as "does not exist" (silent overwrite risk).
                    Err(e) => {
                        let msg = e.to_string();
                        let _ = slint::invoke_from_event_loop(move || set_err(&ui2, &msg));
                        return;
                    }
                };
                let _ = slint::invoke_from_event_loop(move || {
                    if exists {
                        // Queue this conflict; only open the dialog if none is already showing.
                        // A multi-file drop with several existing names is confirmed one at a time.
                        let show_now = match PENDING_EXTERNAL_UPLOAD.lock() {
                            Ok(mut g) => {
                                let show = g.is_empty();
                                g.push_back((spec2, source2, remote_dir, name2.clone(), size2, is_dir));
                                show
                            }
                            Err(_) => false,
                        };
                        if show_now {
                            if let Some(u) = ui2.upgrade() {
                                u.set_overwrite_name(name2.into());
                                u.set_overwrite_open(true);
                            }
                        }
                    } else {
                        let remote = join_remote(PathBuf::from(&remote_dir).join(&name2));
                        if let Some(u) = ui2.upgrade() {
                            do_external_upload(&h, engine2, idx2, u.as_weak(), spec2, source2, remote, name2, size2, is_dir);
                        }
                    }
                });
            });
        }
    }
}

fn materialize_remote_drag(
    handle: &Handle,
    spec: &ConnectionSpec,
    password: &str,
    remote: &str,
    name: &str,
    is_dir: bool,
) -> Result<PathBuf, String> {
    let root = std::env::temp_dir().join("gmacftp-drag").join(format!("{}", rand::random::<u64>()));
    let target = root.join(name);
    std::fs::create_dir_all(if is_dir { &target } else { &root }).map_err(|e| e.to_string())?;
    if !is_dir {
        handle.block_on(net::download_file(spec, password, remote, target.clone())).map_err(|e| e.to_string())?;
        return Ok(target);
    }
    let files = handle.block_on(net::walk_remote(spec, password, remote)).map_err(|e| e.to_string())?;
    for (remote_file, _) in files {
        let rel = remote_file.strip_prefix(remote).unwrap_or(&remote_file).trim_start_matches('/');
        let rel = net::sanitize_local_rel(rel).map_err(|e| e.to_string())?;
        let local = target.join(rel);
        if let Some(parent) = local.parent() { std::fs::create_dir_all(parent).map_err(|e| e.to_string())?; }
        handle.block_on(net::download_file(spec, password, &remote_file, local)).map_err(|e| e.to_string())?;
    }
    Ok(target)
}

fn drag_preview_image() -> Option<drag::Image> {
    let exe = std::env::current_exe().ok()?;
    let bundled = exe.parent()?.parent()?.join("Resources/icon.icns");
    let path = if bundled.exists() { bundled } else { PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("assets/icon-preview.png") };
    path.exists().then_some(drag::Image::File(path))
}

#[cfg(target_os = "macos")]
fn cursor_x_in_window(window: &slint::winit_030::winit::window::Window) -> Option<f64> {
    use objc2::{msg_send, runtime::AnyObject};
    use objc2_foundation::NSPoint;
    use raw_window_handle::{HasWindowHandle, RawWindowHandle};
    let RawWindowHandle::AppKit(appkit) = window.window_handle().ok()?.as_raw() else { return None };
    unsafe {
        let view = &*appkit.ns_view.as_ptr().cast::<AnyObject>();
        let ns_window: *mut AnyObject = msg_send![view, window];
        let ns_window = ns_window.as_ref()?;
        let point: NSPoint = msg_send![ns_window, mouseLocationOutsideOfEventStream];
        Some(point.x)
    }
}

#[cfg(target_os = "macos")]
fn configure_macos_window_shape(window: &slint::winit_030::winit::window::Window) {
    use objc2::{msg_send, runtime::AnyObject};
    use raw_window_handle::{HasWindowHandle, RawWindowHandle};

    let Ok(handle) = window.window_handle() else {
        return;
    };
    let RawWindowHandle::AppKit(appkit) = handle.as_raw() else {
        return;
    };

    window.set_transparent(true);

    unsafe {
        let view = &*appkit.ns_view.as_ptr().cast::<AnyObject>();
        let _: () = msg_send![view, setWantsLayer: true];
        let layer: *mut AnyObject = msg_send![view, layer];
        if let Some(layer) = layer.as_ref() {
            let _: () = msg_send![layer, setCornerRadius: 10.0_f64];
            let _: () = msg_send![layer, setMasksToBounds: true];
        }
    }

    window.request_redraw();
}

fn reorder_saved_connection(ui: &App, conns: &ConnList, id: i32, drop_index: i32) {
    let filtered = model_rows(ui.get_filtered_connections());
    if filtered.len() < 2 || id < 0 {
        return;
    }

    let before_id = if drop_index >= 0 && (drop_index as usize) < filtered.len() {
        Some(filtered[drop_index as usize].id)
    } else {
        None
    };
    if before_id == Some(id) {
        return;
    }

    let mut g = conns.lock().expect("connections lock");
    let Some(from_pos) = g.iter().position(|c| c.id.0 as i32 == id) else {
        return;
    };
    let item = g.remove(from_pos);

    let insert_pos = if let Some(before_id) = before_id {
        g.iter()
            .position(|c| c.id.0 as i32 == before_id)
            .unwrap_or(g.len())
    } else {
        filtered
            .iter()
            .rev()
            .find(|row| row.id != id)
            .and_then(|row| g.iter().position(|c| c.id.0 as i32 == row.id).map(|pos| pos + 1))
            .unwrap_or(g.len())
    };

    let insert_pos = insert_pos.min(g.len());
    g.insert(insert_pos, item);
    let snapshot = g.clone();
    drop(g);

    let _ = store::save_metadata(&snapshot);
    refresh_connections_model(ui, conns);
    ui.set_error("".into());
    ui.set_status("Saved servers reordered.".into());
}

fn wire_reorder_saved_connections(ui: &App, conns: ConnList) {
    let ui_weak = ui.as_weak();
    ui.on_reorder_saved_connection(move |id, drop_index| {
        if let Some(ui) = ui_weak.upgrade() {
            reorder_saved_connection(&ui, &conns, id, drop_index);
        }
    });
}

fn apply_palette_filter(ui: &App) {
    let query = ui.get_palette_query().to_string();
    let demo = use_design_demo_connections();
    let connections = model_rows(ui.get_connections());
    let filtered: Vec<ConnRow> = connections
        .into_iter()
        .filter(|row| {
            conn_row_matches(row, &query)
                || (demo && row.label.to_string() == "Backups" && "production backups".contains(query.trim().to_lowercase().as_str()))
        })
        .map(|mut row| {
            if demo && row.label.to_string() == "Backups" {
                row.label = "Production Backups".into();
            }
            row
        })
        .collect();
    ui.set_palette_connections(ModelRc::from(Rc::new(VecModel::from(filtered))));
}

fn wire_palette_filter(ui: &App) {
    let ui_weak = ui.as_weak();
    ui.on_filter_palette(move |query| {
        if let Some(ui) = ui_weak.upgrade() {
            ui.set_palette_query(query);
            apply_palette_filter(&ui);
        }
    });
}

fn next_id(specs: &[ConnectionSpec]) -> usize {
    specs.iter().map(|s| s.id.0).max().unwrap_or(0) + 1
}

// ── local filesystem ──────────────────────────────────────────────────────────

fn home_dir() -> PathBuf {
    directories::BaseDirs::new()
        .map(|b| b.home_dir().to_path_buf())
        .unwrap_or_else(|| PathBuf::from("/"))
}

/// True byte sizes for the current pane views, keyed by (pane, name). Slint's `int` is i32, so
/// EntryRow.size truncates files >2 GiB; this sidecar carries the real u64 for transfer
/// accounting (progress bar) so large-file transfers get a correct total. Populated on re-list.
static TRUE_SIZE: LazyLock<Mutex<HashMap<(usize, String), u64>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

#[derive(Debug, Clone, Copy, Default)]
struct FolderStats {
    size: u64,
    newest_mtime: Option<i64>,
    files_scanned: usize,
    truncated: bool,
}

fn set_pane_loading(ui: &App, pane: usize, loading: bool) {
    if pane == 0 {
        ui.set_local_loading(loading);
    } else {
        ui.set_remote_loading(loading);
    }
    ui.set_is_connecting(ui.get_local_loading() || ui.get_remote_loading());
}

fn clear_pane_view(ui: &App, pane: usize, cwd: &str) {
    let empty = ModelRc::from(Rc::new(VecModel::from(Vec::<EntryRow>::new())));
    if let Ok(mut g) = TRUE_SIZE.lock() {
        g.retain(|(p, _), _| *p != pane);
    }
    if pane == 0 {
        ui.set_local_full(empty.clone());
        ui.set_local_entries(empty);
        ui.set_local_count(0);
        ui.set_local_selected(-1);
        ui.set_local_cwd(cwd.into());
        ui.set_local_path_display(display_path(cwd).into());
    } else {
        ui.set_remote_full(empty.clone());
        ui.set_remote_entries(empty);
        ui.set_remote_count(0);
        ui.set_remote_selected(-1);
        ui.set_remote_cwd(cwd.into());
        ui.set_remote_path_display(display_path(cwd).into());
    }
    refresh_selected_path(ui);
}

fn set_true_sizes(pane: usize, sizes: &[(String, u64)]) {
    if let Ok(mut g) = TRUE_SIZE.lock() {
        g.retain(|(p, _), _| *p != pane);
        for (n, s) in sizes {
            g.insert((pane, n.clone()), *s);
        }
    }
}

fn local_folder_stats(root: &Path, max_files: usize) -> FolderStats {
    let mut stats = FolderStats::default();
    let mut visited = HashSet::new();
    local_folder_stats_inner(root, max_files, &mut stats, &mut visited);
    stats
}

fn local_folder_stats_inner(
    dir: &Path,
    max_files: usize,
    stats: &mut FolderStats,
    visited: &mut HashSet<PathBuf>,
) {
    if stats.truncated {
        return;
    }
    if let Ok(canon) = dir.canonicalize() {
        if !visited.insert(canon) {
            return;
        }
    }
    let Ok(read) = std::fs::read_dir(dir) else { return };
    for entry in read.flatten() {
        if stats.truncated {
            break;
        }
        let path = entry.path();
        let Ok(md) = entry.metadata() else { continue };
        if md.is_dir() {
            local_folder_stats_inner(&path, max_files, stats, visited);
        } else {
            stats.size = stats.size.saturating_add(md.len());
            stats.files_scanned += 1;
            if let Ok(modified) = md.modified() {
                if let Ok(d) = modified.duration_since(std::time::UNIX_EPOCH) {
                    let mtime = d.as_secs() as i64;
                    stats.newest_mtime = Some(stats.newest_mtime.map_or(mtime, |cur| cur.max(mtime)));
                }
            }
            if max_files > 0 && stats.files_scanned >= max_files {
                stats.truncated = true;
            }
        }
    }
}

fn list_local_pane(ui: &App, pane: usize, path: &Path, cwd: &str) {
    let mut rows: Vec<EntryRow> = Vec::new();
    let mut sizes: Vec<(String, u64)> = Vec::new();
    match std::fs::read_dir(path) {
        Ok(read) => {
            for entry in read.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                let md = match entry.metadata() {
                    Ok(m) => m,
                    Err(_) => continue,
                };
                let is_dir = md.is_dir();
                let len = md.len();
                let item_path = entry.path();
                let folder_stats = is_dir.then(|| local_folder_stats(&item_path, MAX_LOCAL_FOLDER_STAT_FILES));
                let display_size = folder_stats.map(|s| s.size).unwrap_or(len);
                let partial = folder_stats.map(|s| s.truncated).unwrap_or(false);
                let own_mtime = md.modified().ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_secs() as i64).unwrap_or(0);
                let mtime = folder_stats.and_then(|s| s.newest_mtime).unwrap_or(own_mtime);
                rows.push(EntryRow {
                    name: name.clone().into(),
                    is_dir,
                    size: display_size as i32,
                    mtime: mtime as i32,
                    date: fmt_date(mtime).into(),
                    size_text: fmt_size_partial(display_size, partial).into(),
                    metadata_state: "ready".into(),
                });
                sizes.push((name, display_size));
            }
        }
        Err(e) => ui.set_error(format!("local: {e}").into()),
    }
    set_true_sizes(pane, &sizes);
    set_pane_full(ui, pane, rows, cwd);
}

fn set_pane_entries(
    ui: &App,
    pane: usize,
    entries: &[RemoteEntry],
    cwd: &str,
    partials: &HashMap<String, bool>,
    metadata_states: &HashMap<String, &'static str>,
) {
    let rows: Vec<EntryRow> = entries.iter().map(|e| {
        let mtime = e.mtime.unwrap_or(0);
        let partial = partials.get(&e.name).copied().unwrap_or(false);
        EntryRow {
            name: e.name.clone().into(),
            is_dir: e.is_dir,
            size: e.size as i32,
            mtime: mtime as i32,
            date: fmt_date(mtime).into(),
            size_text: fmt_size_partial(e.size, partial).into(),
            metadata_state: metadata_states
                .get(&e.name)
                .copied()
                .unwrap_or("ready")
                .into(),
        }
    }).collect();
    let sizes = entries.iter().map(|e| (e.name.clone(), e.size)).collect::<Vec<_>>();
    set_true_sizes(pane, &sizes);
    set_pane_full(ui, pane, rows, cwd);
}

fn update_pane_entry_metadata(
    ui: &App,
    pane: usize,
    entry: &RemoteEntry,
    partial: bool,
    metadata_state: &'static str,
) {
    let mtime = entry.mtime.unwrap_or(0);
    let row = EntryRow {
        name: entry.name.clone().into(),
        is_dir: entry.is_dir,
        size: entry.size as i32,
        mtime: mtime as i32,
        date: fmt_date(mtime).into(),
        size_text: fmt_size_partial(entry.size, partial).into(),
        metadata_state: metadata_state.into(),
    };

    if let Ok(mut sizes) = TRUE_SIZE.lock() {
        sizes.insert((pane, entry.name.clone()), entry.size);
    }

    // Update both backing models in place. Replacing either model would reset selection,
    // keyboard navigation and the Flickable viewport every time one folder finishes scanning.
    let models = if pane == 0 {
        [ui.get_local_full(), ui.get_local_entries()]
    } else {
        [ui.get_remote_full(), ui.get_remote_entries()]
    };
    for model in models {
        if let Some(index) = (0..model.row_count()).find(|&i| {
            model
                .row_data(i)
                .map(|candidate| candidate.name == row.name)
                .unwrap_or(false)
        }) {
            model.set_row_data(index, row.clone());
        }
    }
}

fn remote_pane_request_is_current(
    panes: &Panes,
    pane: usize,
    connection_id: ConnectionId,
    cwd: &str,
) -> bool {
    let Ok(panes) = panes.lock() else { return false };
    let Some(state) = panes.get(pane) else { return false };
    matches!(state.kind, PaneKind::Remote)
        && state.conn.as_ref().map(|conn| conn.id) == Some(connection_id)
        && state.cwd == cwd
}

/// Re-list a pane at its current cwd (Local → fs read; Remote → connect + list, per-op).
fn refresh_pane(handle: &Handle, store: Arc<dyn CredentialStore>, panes: Panes, ui: Weak<App>, pane: usize) {
    let (kind, conn, cwd) = {
        let p = panes.lock().expect("panes");
        (p[pane].kind.clone(), p[pane].conn.clone(), p[pane].cwd.clone())
    };
    match kind {
        PaneKind::Local => {
            let _ = ui.upgrade().map(|ui| {
                set_pane_loading(&ui, pane, false);
                list_local_pane(&ui, pane, Path::new(&cwd), &cwd);
            });
        }
        PaneKind::Remote => {
            let Some(spec) = conn else { return };
            let _ = ui.upgrade().map(|ui| {
                set_pane_loading(&ui, pane, true);
                clear_pane_view(&ui, pane, &cwd);
            });
            let Some(password) = password_for(&store, &spec) else {
                let _ = ui.upgrade().map(|ui| set_pane_loading(&ui, pane, false));
                set_err(&ui, "missing credential"); return;
            };
            handle.spawn(async move {
                let mut s = spec.clone(); s.initial_path = cwd.clone();
                let started = Instant::now();
                let entries = match net::connect_and_list(&s, &password).await {
                    Ok(entries) => entries,
                    Err(e) => {
                        let request_panes = panes.clone();
                        let request_ui = ui.clone();
                        let request_cwd = cwd.clone();
                        let connection_id = spec.id;
                        let _ = slint::invoke_from_event_loop(move || {
                            if !remote_pane_request_is_current(
                                &request_panes,
                                pane,
                                connection_id,
                                &request_cwd,
                            ) {
                                return;
                            }
                            let Some(ui) = request_ui.upgrade() else { return };
                            set_pane_loading(&ui, pane, false);
                            ui.set_error(e.to_string().into());
                        });
                        return;
                    }
                };

                tracing::info!(
                    target: "gmacftp",
                    pane,
                    host = %spec.host,
                    entries = entries.len(),
                    elapsed_ms = started.elapsed().as_millis(),
                    "initial directory listed"
                );

                // The directory listing is the interactive result. Surface it immediately;
                // recursive folder sizes/dates are optional enrichment and must never keep
                // the pane behind a Loading placeholder.
                let initial_entries = entries.clone();
                let initial_states = entries
                    .iter()
                    .filter(|entry| entry.is_dir)
                    .map(|entry| (entry.name.clone(), "loading"))
                    .collect::<HashMap<_, _>>();
                let request_panes = panes.clone();
                let request_ui = ui.clone();
                let request_cwd = cwd.clone();
                let connection_id = spec.id;
                let _ = slint::invoke_from_event_loop(move || {
                    if !remote_pane_request_is_current(
                        &request_panes,
                        pane,
                        connection_id,
                        &request_cwd,
                    ) {
                        return;
                    }
                    let Some(ui) = request_ui.upgrade() else { return };
                    set_pane_loading(&ui, pane, false);
                    ui.set_error("".into());
                    set_pane_entries(
                        &ui,
                        pane,
                        &initial_entries,
                        &request_cwd,
                        &HashMap::new(),
                        &initial_states,
                    );
                });

                let enrichment_started = Instant::now();
                let folders = entries
                    .iter()
                    .enumerate()
                    .filter(|(_, entry)| entry.is_dir)
                    .map(|(index, entry)| {
                        (
                            index,
                            entry.name.clone(),
                            join_remote(PathBuf::from(&cwd).join(entry.name.as_str())),
                        )
                    })
                    .collect::<Vec<_>>();
                let tasks = stream::iter(folders.into_iter().map(|(index, _, remote_path)| {
                    let spec = s.clone();
                    let password = password.clone();
                    async move {
                        let result = tokio::time::timeout(
                            std::time::Duration::from_secs(15),
                            net::remote_tree_stats(
                                &spec,
                                &password,
                                &remote_path,
                                MAX_REMOTE_FOLDER_STAT_FILES,
                            ),
                        )
                        .await;
                        (index, remote_path, result)
                    }
                }))
                .buffer_unordered(4);
                tokio::pin!(tasks);
                let mut entries = entries;
                while let Some((index, remote_path, result)) = tasks.next().await {
                    let (metadata_state, partial) = match result {
                        Ok(Ok(stats)) => {
                            if let Some(entry) = entries.get_mut(index) {
                                entry.size = stats.size;
                                if let Some(mtime) = stats.newest_mtime {
                                    entry.mtime = Some(mtime);
                                }
                            }
                            ("ready", stats.truncated)
                        }
                        Ok(Err(e)) => {
                            tracing::debug!(
                                target: "gmacftp",
                                path = %remote_path,
                                error = %e,
                                "remote folder stats unavailable"
                            );
                            ("unavailable", false)
                        }
                        Err(_) => {
                            tracing::debug!(
                                target: "gmacftp",
                                path = %remote_path,
                                "remote folder stats timed out"
                            );
                            ("unavailable", false)
                        }
                    };

                    let Some(updated_entry) = entries.get(index).cloned() else { continue };
                    let request_panes = panes.clone();
                    let request_ui = ui.clone();
                    let request_cwd = cwd.clone();
                    let connection_id = spec.id;
                    let _ = slint::invoke_from_event_loop(move || {
                        if !remote_pane_request_is_current(
                            &request_panes,
                            pane,
                            connection_id,
                            &request_cwd,
                        ) {
                            return;
                        }
                        let Some(ui) = request_ui.upgrade() else { return };
                        update_pane_entry_metadata(
                            &ui,
                            pane,
                            &updated_entry,
                            partial,
                            metadata_state,
                        );
                    });
                }
                tracing::debug!(
                    target: "gmacftp",
                    pane,
                    host = %spec.host,
                    elapsed_ms = enrichment_started.elapsed().as_millis(),
                    "folder metadata enriched"
                );

            });
        }
    }
}

/// Re-list both panes at their current cwd (Local -> fs read; Remote -> connect + list). Called
/// after a transfer or delete so the new/removed entry is visible immediately — no manual refresh.
fn refresh_both_panes(handle: &Handle, store: Arc<dyn CredentialStore>, panes: Panes, ui: Weak<App>) {
    refresh_pane(handle, store.clone(), panes.clone(), ui.clone(), 0);
    refresh_pane(handle, store, panes, ui, 1);
}

/// Delete an entry from a pane (right-click → Delete). Local files go to the macOS Trash
/// (reversible); remote files are deleted server-side (DELE/RMD or SFTP remove). The pane is
/// re-listed afterward so the removal is reflected immediately.
fn delete_entry(handle: &Handle, store: Arc<dyn CredentialStore>, panes: Panes, ui: Weak<App>, pane: usize, name: String, is_dir: bool) {
    let (kind, conn, cwd) = {
        let p = panes.lock().expect("panes");
        (p[pane].kind.clone(), p[pane].conn.clone(), p[pane].cwd.clone())
    };
    match kind {
        PaneKind::Local => {
            let path = PathBuf::from(&cwd).join(&name);
            let (h, st, pn, uw, nm) = (handle.clone(), store.clone(), panes.clone(), ui.clone(), name.clone());
            handle.spawn(async move {
                let res = tokio::task::spawn_blocking(move || trash::delete(&path))
                    .await
                    .map_err(|e| e.to_string())
                    .and_then(|r| r.map_err(|e| e.to_string()));
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(ui) = uw.upgrade() {
                        match &res {
                            Ok(()) => { ui.set_status(format!("moved {nm} to Trash").into()); ui.set_error("".into()); }
                            Err(e) => ui.set_error(format!("delete failed: {e}").into()),
                        }
                    }
                    refresh_pane(&h, st, pn, uw, pane);
                });
            });
        }
        PaneKind::Remote => {
            let Some(spec) = conn else { set_err(&ui, "not connected"); return };
            let Some(password) = password_for(&store, &spec) else { set_err(&ui, "missing credential"); return };
            let rp = join_remote(PathBuf::from(&cwd).join(&name));
            let (h, st, pn, uw, nm) = (handle.clone(), store.clone(), panes.clone(), ui.clone(), name.clone());
            handle.spawn(async move {
                let mut s = spec.clone(); s.initial_path = cwd.clone();
                let res = net::delete_remote(&s, &password, &rp, is_dir).await;
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(ui) = uw.upgrade() {
                        match &res {
                            Ok(()) => { ui.set_status(format!("deleted {nm}").into()); ui.set_error("".into()); }
                            Err(e) => ui.set_error(format!("delete failed: {e}").into()),
                        }
                    }
                    refresh_pane(&h, st, pn, uw, pane);
                });
            });
        }
    }
}

/// Bind a pane to a saved server (Remote) and list its initial directory.
fn connect_into_pane(handle: &Handle, store: Arc<dyn CredentialStore>, conns: ConnList, sessions: Sessions, panes: Panes, ui: Weak<App>, pane: usize, conn_id: i32) {
    let Some(spec) = conns.lock().expect("connections lock").iter().find(|c| c.id.0 as i32 == conn_id).cloned() else { return };
    // Connect ADDS a background session (the pane's previous session stays alive in the pool).
    show_session_in_pane(handle, store, sessions, panes, ui, pane, &spec, true);
}

/// Show `spec`'s session in `pane`. With `create_if_missing` (Connect), a session is added to the
/// pool if absent — so connecting never drops the pane's previous session. Without it (switch),
/// only an existing pool session can be shown.
fn show_session_in_pane(handle: &Handle, store: Arc<dyn CredentialStore>, sessions: Sessions, panes: Panes, ui: Weak<App>, pane: usize, spec: &ConnectionSpec, create_if_missing: bool) {
    // A (different) connection is taking the pane → the "don't ask again" delete suppression
    // was scoped to the previous connection, so re-arm the confirmation for THIS pane.
    set_skip_delete_confirm(pane, false);
    // 1. save the pane's CURRENT session position back to the pool (restored on switch-back)
    save_pane_session(&sessions, &panes, pane);
    // 2. find-or-create the session for this spec
    let (cwd, nav) = {
        let mut g = sessions.lock().expect("sessions");
        if let Some(s) = g.iter().find(|s| s.conn.id.0 == spec.id.0) {
            (s.cwd.clone(), s.nav.clone())
        } else if create_if_missing {
            let cwd = if spec.initial_path.trim().is_empty() { "/".to_string() } else { spec.initial_path.clone() };
            let nav = Nav::at(cwd.clone());
            g.push(ActiveSession { conn: spec.clone(), cwd: cwd.clone(), nav: nav.clone() });
            (cwd, nav)
        } else {
            return; // session no longer in the pool
        }
    };
    {
        let mut p = panes.lock().expect("panes");
        p[pane].kind = PaneKind::Remote;
        p[pane].conn = Some(spec.clone());
        p[pane].cwd = cwd.clone();
        p[pane].nav = nav;
    }
    let label = PaneState { kind: PaneKind::Remote, conn: Some(spec.clone()), cwd, nav: Nav::default() };
    let _ = ui.upgrade().map(|ui| {
        set_pane_kind_label(&ui, pane, &label);
        ui.set_active_pane(if pane == 0 { "local".into() } else { "remote".into() });
        refresh_sessions_model(&ui, &sessions);
    });
    refresh_pane(handle, store, panes, ui, pane);
}

/// Write a pane's current cwd/nav back into its session in the pool (if remote), so the position
/// survives a switch away + back. Called before a pane changes which session it shows.
fn save_pane_session(sessions: &Sessions, panes: &Panes, pane: usize) {
    let (id, cwd, nav, is_remote) = {
        let p = panes.lock().expect("panes");
        let s = &p[pane];
        (s.conn.as_ref().map(|c| c.id), s.cwd.clone(), s.nav.clone(), matches!(s.kind, PaneKind::Remote))
    };
    if let (true, Some(id)) = (is_remote, id) {
        if let Some(s) = sessions.lock().expect("sessions").iter_mut().find(|s| s.conn.id == id) {
            s.cwd = cwd;
            s.nav = nav;
        }
    }
}

/// Refresh the CONNECTED sidebar from the background session pool.
fn refresh_sessions_model(ui: &App, sessions: &Sessions) {
    let demo = use_design_demo_connections();
    let model: Vec<ConnRow> = sessions.lock().expect("sessions").iter().map(|s| ConnRow {
        id: s.conn.id.0 as i32,
        label: s.conn.name.clone().into(),
        sub: if demo {
            format!("{}:{}", s.conn.host, s.conn.port)
        } else {
            format!("{}@{}", s.conn.user, s.conn.host)
        }.into(),
        protocol: demo_protocol_label(&s.conn, demo).into(),
        connected: true,
    }).collect();
    ui.set_sessions(ModelRc::from(Rc::new(VecModel::from(model))));
    apply_server_filter(ui);
}

/// Click a CONNECTED session → swap it into the active pane (the previous session stays alive).
fn switch_to_session(handle: &Handle, store: Arc<dyn CredentialStore>, sessions: Sessions, panes: Panes, ui: Weak<App>, pane: usize, conn_id: i32) {
    let Some(spec) = sessions.lock().expect("sessions").iter().find(|s| s.conn.id.0 as i32 == conn_id).map(|s| s.conn.clone()) else { return };
    show_session_in_pane(handle, store, sessions, panes, ui, pane, &spec, false);
}

/// Eject a session from the background pool entirely. Any pane currently showing it goes local.
fn disconnect_session(engine: TransferEngine, sessions: Sessions, panes: Panes, ui: Weak<App>, conn_id: i32) {
    engine.abort(ConnectionId(conn_id as usize));
    // Note: per-pane delete-confirm re-arm happens via the set_pane_local() calls below for any
    // pane that was showing the ejected session; untouched panes keep their own setting.
    sessions.lock().expect("sessions").retain(|s| s.conn.id.0 as i32 != conn_id);
    for pane in 0..2 {
        let shown = panes.lock().expect("panes")[pane].conn.as_ref().map(|c| c.id.0 as i32 == conn_id).unwrap_or(false);
        if shown {
            set_pane_local(panes.clone(), ui.clone(), pane);
        }
    }
    let _ = ui.upgrade().map(|ui| {
        ui.set_status("".into());
        ui.set_error("".into());
        refresh_sessions_model(&ui, &sessions);
    });
}

/// Switch a pane back to the local filesystem (home dir).
fn set_pane_local(panes: Panes, ui: Weak<App>, pane: usize) {
    set_skip_delete_confirm(pane, false); // THIS pane left its server (Home / eject / disconnect) → re-arm it
    let home = home_dir();
    let cwd = home.to_string_lossy().to_string();
    {
        let mut p = panes.lock().expect("panes");
        p[pane].kind = PaneKind::Local;
        p[pane].conn = None;
        p[pane].cwd = cwd.clone();
        p[pane].nav.reset(cwd.clone());
    }
    let label = PaneState { kind: PaneKind::Local, conn: None, cwd: cwd.clone(), nav: Nav::default() };
    let _ = ui.upgrade().map(|ui| {
        set_pane_kind_label(&ui, pane, &label);
        list_local_pane(&ui, pane, &home, &cwd);
    });
}

fn expand_local_favorite(path: &str) -> PathBuf {
    if path == "~" {
        home_dir()
    } else if let Some(rest) = path.strip_prefix("~/") {
        home_dir().join(rest)
    } else {
        PathBuf::from(path)
    }
}

fn open_local_favorite(panes: Panes, ui: Weak<App>, path: String) {
    let target = expand_local_favorite(&path);
    if !target.is_dir() {
        let _ = ui.upgrade().map(|ui| {
            ui.set_status("".into());
            ui.set_error(format!("folder not found: {}", target.display()).into());
        });
        return;
    }

    let cwd = target.to_string_lossy().to_string();
    set_skip_delete_confirm(0, false);
    {
        let mut p = panes.lock().expect("panes");
        p[0].kind = PaneKind::Local;
        p[0].conn = None;
        p[0].cwd = cwd.clone();
        p[0].nav.reset(cwd.clone());
    }

    let label = PaneState { kind: PaneKind::Local, conn: None, cwd: cwd.clone(), nav: Nav::default() };
    let _ = ui.upgrade().map(|ui| {
        ui.set_active_pane("local".into());
        set_pane_kind_label(&ui, 0, &label);
        list_local_pane(&ui, 0, &target, &cwd);
        refresh_selected_path(&ui);
        ui.set_status("".into());
        ui.set_error("".into());
    });
}

fn local_favorite_label(path: &Path) -> String {
    path.file_name()
        .and_then(|s| s.to_str())
        .filter(|s| !s.trim().is_empty())
        .map(|s| s.to_string())
        .unwrap_or_else(|| path.to_string_lossy().to_string())
}

fn local_favorite_label_for_raw(raw: &str, path: &Path) -> String {
    if raw == "~" || canonical_favorite_key(path) == canonical_favorite_key(&home_dir()) {
        "Home".to_string()
    } else {
        local_favorite_label(path)
    }
}

fn canonical_favorite_key(path: &Path) -> String {
    std::fs::canonicalize(path)
        .unwrap_or_else(|_| path.to_path_buf())
        .to_string_lossy()
        .to_string()
}

fn built_in_local_favorite_paths() -> Vec<String> {
    vec![
        "~".to_string(),
        "~/Documents".to_string(),
        "~/Downloads".to_string(),
        "~/Desktop".to_string(),
        "/Applications".to_string(),
    ]
}

fn effective_local_favorite_paths(settings: &store::settings::Settings) -> Vec<String> {
    let mut paths = if settings.local_favorites_customized {
        settings.local_favorites.clone()
    } else {
        let mut defaults = built_in_local_favorite_paths();
        defaults.extend(settings.local_favorites.clone());
        defaults
    };
    let mut seen = HashSet::new();
    paths.retain(|raw| {
        let path = expand_local_favorite(raw);
        let key = canonical_favorite_key(&path);
        path.is_dir() && seen.insert(key)
    });
    paths
}

fn save_local_favorites(paths: Vec<String>) {
    let mut settings = store::settings::load();
    settings.local_favorites = paths;
    settings.local_favorites_customized = true;
    store::settings::save(&settings);
}

fn local_favorite_rows(settings: &store::settings::Settings) -> Vec<LocalFavoriteRow> {
    let mut seen = HashSet::new();
    effective_local_favorite_paths(settings)
        .iter()
        .filter_map(|raw| {
            let path = expand_local_favorite(raw);
            let key = canonical_favorite_key(&path);
            if !seen.insert(key) || !path.is_dir() {
                return None;
            }
            Some(LocalFavoriteRow {
                label: local_favorite_label_for_raw(raw, &path).into(),
                path: path.to_string_lossy().to_string().into(),
            })
        })
        .collect()
}

fn refresh_local_favorites_model(ui: &App) {
    let settings = store::settings::load();
    ui.set_local_favorites(ModelRc::from(Rc::new(VecModel::from(local_favorite_rows(&settings)))));
}

fn add_local_favorite_from_pane(ui: &App, panes: Panes, source: String, index: i32) {
    let pane = if source == "remote" { 1 } else { 0 };
    let Some(row) = (index >= 0).then(|| pane_entries(ui, pane).row_data(index as usize)).flatten() else {
        return;
    };
    if !row.is_dir {
        ui.set_status("".into());
        ui.set_error("Only folders can be added to Favorites.".into());
        return;
    }

    let cwd = {
        let p = panes.lock().expect("panes");
        if !matches!(p[pane].kind, PaneKind::Local) {
            ui.set_status("".into());
            ui.set_error("Only local folders can be added to Favorites.".into());
            return;
        }
        p[pane].cwd.clone()
    };

    let path = PathBuf::from(cwd).join(row.name.as_str());
    if !path.is_dir() {
        ui.set_status("".into());
        ui.set_error(format!("folder not found: {}", path.display()).into());
        return;
    }

    let key = canonical_favorite_key(&path);
    let settings = store::settings::load();
    let mut paths = effective_local_favorite_paths(&settings);
    let existing: HashSet<String> = paths.iter().map(|raw| canonical_favorite_key(&expand_local_favorite(raw))).collect();
    if existing.contains(&key) {
        ui.set_error("".into());
        ui.set_status("Favorite already exists.".into());
        return;
    }

    paths.push(path.to_string_lossy().to_string());
    save_local_favorites(paths);
    refresh_local_favorites_model(ui);
    ui.set_error("".into());
    ui.set_status(format!("Added to Favorites: {}", local_favorite_label(&path)).into());
}

fn reorder_local_favorite(ui: &App, from: i32, to: i32) {
    let settings = store::settings::load();
    let mut paths = effective_local_favorite_paths(&settings);
    let len = paths.len();
    if len == 0 || from < 0 {
        return;
    }
    let from = from as usize;
    if from >= len {
        return;
    }
    let mut to = to.max(0) as usize;
    if to > len {
        to = len;
    }
    if to > from {
        to -= 1;
    }
    if from == to {
        return;
    }

    let item = paths.remove(from);
    paths.insert(to, item);
    save_local_favorites(paths);
    refresh_local_favorites_model(ui);
    ui.set_error("".into());
    ui.set_status("Favorites reordered.".into());
}

fn remove_local_favorite(ui: &App, index: i32) {
    let settings = store::settings::load();
    let mut paths = effective_local_favorite_paths(&settings);
    if index < 0 || index as usize >= paths.len() {
        return;
    }
    let removed = expand_local_favorite(&paths.remove(index as usize));
    save_local_favorites(paths);
    refresh_local_favorites_model(ui);
    ui.set_error("".into());
    ui.set_status(format!("Removed from Favorites: {}", local_favorite_label(&removed)).into());
}

/// Copy the selected entry from `src_pane` to `dst_pane`. Reads the selection, then for a single
/// file checks the destination for a clash and asks before overwriting (folders merge silently).
fn transfer(
    handle: &Handle,
    store: Arc<dyn CredentialStore>,
    panes: Panes,
    engine: TransferEngine,
    idx: Arc<Mutex<HashMap<i32, usize>>>,
    ui: Weak<App>,
    src_pane: usize,
    dst_pane: usize,
) {
    let Some(ui) = ui.upgrade() else { return };
    let sel = pane_selected(&ui, src_pane);
    if sel < 0 { return; }
    let Some(row) = pane_entries(&ui, src_pane).row_data(sel as usize) else { return };
    let name = row.name.to_string();
    let is_dir = row.is_dir;
    // Use the true u64 size from the sidecar (EntryRow.size is i32 and truncates >2 GiB);
    // fall back to the i32 field only if the sidecar missed it.
    let total = TRUE_SIZE
        .lock()
        .ok()
        .and_then(|g| g.get(&(src_pane, name.clone())).copied())
        .or_else(|| if row.size > 0 { Some(row.size as u64) } else { None });
    start_transfer(handle, store, panes, engine, idx, ui.as_weak(), src_pane, dst_pane, name, is_dir, total);
}

/// Start a copy: for a single file, check the destination for a name clash and open the overwrite
/// dialog if there is one; otherwise (or for folders) run the transfer immediately.
fn start_transfer(
    handle: &Handle,
    store: Arc<dyn CredentialStore>,
    panes: Panes,
    engine: TransferEngine,
    idx: Arc<Mutex<HashMap<i32, usize>>>,
    ui: Weak<App>,
    src_pane: usize,
    dst_pane: usize,
    name: String,
    is_dir: bool,
    total: Option<u64>,
) {
    if is_dir {
        do_transfer(handle, store, panes, engine, idx, ui, src_pane, dst_pane, name.clone(), name, is_dir, total);
        return;
    }
    let (dst_kind, dst_conn, dst_cwd) = {
        let p = panes.lock().expect("panes");
        let s = &p[dst_pane];
        (s.kind.clone(), s.conn.clone(), s.cwd.clone())
    };
    // Sanitize the server-controlled name before it reaches the local FS: strip a leading
    // '/', drop '.'/'..' and resolve '..' segments, reject control bytes/NAME_MAX. The
    // REMOTE source keeps its real name; only the local destination is contained (PATH-1/2).
    let dst_local = match net::sanitize_local_rel(&name) {
        Ok(clean) => PathBuf::from(&dst_cwd).join(clean),
        Err(e) => {
            set_err(&ui, &e.to_string());
            return;
        }
    };
    let store2 = store.clone();
    let h = handle.clone();
    h.clone().spawn(async move {
        let exists = match dst_kind {
            PaneKind::Local => dst_local.exists(),
            PaneKind::Remote => match dst_conn.as_ref() {
                Some(spec) => match password_for(&store2, spec) {
                    Some(pw) => match net::remote_exists(spec, &pw, &dst_cwd, &name).await {
                        Ok(b) => b,
                        // A connect/list failure must NOT read as "does not exist" — that would
                        // risk a silent overwrite. Surface the error and abort this copy.
                        Err(e) => { set_err(&ui, &e.to_string()); return; }
                    },
                    None => { set_err(&ui, "missing credential"); return; }
                },
                None => false,
            },
        };
        if exists {
            let nm = name.clone();
            let uw = ui.clone();
            let _ = slint::invoke_from_event_loop(move || {
                if let Ok(mut g) = PENDING_COPY.lock() {
                    *g = Some((src_pane, dst_pane, nm.clone(), is_dir, total));
                }
                if let Some(ui) = uw.upgrade() {
                    ui.set_overwrite_name(nm.into());
                    ui.set_overwrite_open(true);
                }
            });
        } else {
            let _ = slint::invoke_from_event_loop(move || {
                do_transfer(&h, store2, panes, engine, idx, ui, src_pane, dst_pane, name.clone(), name, is_dir, total);
            });
        }
    });
}

/// Perform the copy from `src_pane` to `dst_pane` (no conflict check). Reached after the check
/// passes, or after the user picks Overwrite / Save-as-new in the dialog.
///
/// `src_name` is the entry's name at the source (where it actually exists); `dst_name` is the name
/// to write at the destination. They differ ONLY for the "Save as new" choice, where the source
/// keeps its original name and the destination uses the auto-suffixed one. Passing a single name
/// for both would point the source path at a file that doesn't exist (the bug that left downloads
/// stuck on "queued": RETR of the renamed source path hung the data channel).
fn do_transfer(
    handle: &Handle,
    store: Arc<dyn CredentialStore>,
    panes: Panes,
    engine: TransferEngine,
    idx: Arc<Mutex<HashMap<i32, usize>>>,
    ui: Weak<App>,
    src_pane: usize,
    dst_pane: usize,
    src_name: String,
    dst_name: String,
    is_dir: bool,
    total: Option<u64>,
) {
    let Some(ui) = ui.upgrade() else { return };
    let (src_kind, src_conn, src_cwd) = { let p = panes.lock().expect("panes"); let s = &p[src_pane]; (s.kind.clone(), s.conn.clone(), s.cwd.clone()) };
    let (dst_kind, dst_conn, dst_cwd) = { let p = panes.lock().expect("panes"); let s = &p[dst_pane]; (s.kind.clone(), s.conn.clone(), s.cwd.clone()) };
    let src_local = PathBuf::from(&src_cwd).join(&src_name);
    let src_remote = join_remote(PathBuf::from(&src_cwd).join(&src_name));
    let dst_local = PathBuf::from(&dst_cwd).join(&dst_name);
    let dst_remote = join_remote(PathBuf::from(&dst_cwd).join(&dst_name));
    let ui_weak = ui.as_weak();

    match (src_kind, dst_kind) {
        (PaneKind::Local, PaneKind::Local) => {
            // recursive filesystem copy (no engine, so no progress-forwarder auto-refresh).
            let src2 = src_local.clone();
            let dst2 = dst_local.clone();
            let (h2, st2, pn2) = (handle.clone(), store.clone(), panes.clone());
            ui.set_status("copying…".into());
            handle.spawn(async move {
                let n = tokio::task::spawn_blocking(move || fs_copy_tree(&src2, &dst2)).await.unwrap_or(0);
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(ui) = ui_weak.upgrade() {
                        ui.set_status(format!("copied {n} files").into());
                        // Re-list both panes so the new file is visible immediately. Without this
                        // the Local→Local path (e.g. a "save as new" copy in the same folder)
                        // left the destination invisible until a manual Refresh.
                        refresh_both_panes(&h2, st2, pn2, ui.as_weak());
                    }
                });
            });
        }
        (PaneKind::Local, PaneKind::Remote) => {
            let Some(spec) = dst_conn else { return };
            if !is_dir {
                enqueue(&engine, &ui, &idx, spec, TransferDirection::Upload, src_local, dst_remote, &dst_name, total);
            } else {
                copy_local_to_remote(handle, engine, idx, ui_weak, spec, src_local, dst_remote);
            }
        }
        (PaneKind::Remote, PaneKind::Local) => {
            let Some(spec) = src_conn else { return };
            if !is_dir {
                enqueue(&engine, &ui, &idx, spec, TransferDirection::Download, dst_local, src_remote, &dst_name, total);
            } else {
                copy_remote_to_local(handle, store, engine, idx, ui_weak, spec, src_remote, dst_local);
            }
        }
        (PaneKind::Remote, PaneKind::Remote) => {
            let (Some(src_spec), Some(dst_spec)) = (src_conn, dst_conn) else { return };
            // relay through a temp dir: download from src, then upload to dst
            copy_remote_to_remote(handle, store, engine, idx, ui_weak, panes.clone(), src_spec, dst_spec, src_remote, dst_remote, dst_name.clone(), is_dir, total.unwrap_or(0));
        }
    }
}

/// Upload a single Finder-dropped file or folder tree to a server (no conflict check — reached
/// after the check passes, or after the user picks Overwrite / Save-as-new in the dialog).
fn do_external_upload(
    handle: &Handle,
    engine: TransferEngine,
    idx: Arc<Mutex<HashMap<i32, usize>>>,
    ui: Weak<App>,
    spec: ConnectionSpec,
    source: PathBuf,
    remote: String,
    name: String,
    size: Option<u64>,
    is_dir: bool,
) {
    if is_dir {
        copy_local_to_remote(handle, engine, idx, ui, spec, source, remote);
    } else if let Some(u) = ui.upgrade() {
        enqueue(&engine, &u, &idx, spec, TransferDirection::Upload, source, remote, &name, size);
    }
}

/// Resolve the overwrite dialog: 0 = cancel, 1 = overwrite, 2 = save under a new (auto-suffixed) name.
fn resolve_overwrite(
    handle: &Handle,
    store: Arc<dyn CredentialStore>,
    panes: Panes,
    engine: TransferEngine,
    idx: Arc<Mutex<HashMap<i32, usize>>>,
    ui: Weak<App>,
    decision: i32,
) {
    if let Some(ui) = ui.upgrade() { ui.set_overwrite_open(false); }
    // Finder→server uploads blocked on the dialog are a FIFO queue (a multi-file drop may contain
    // several conflicting names — confirmed one at a time). Pop the one currently shown; after
    // resolving it, show the next if any. Checked before the in-app copy pending.
    let item = PENDING_EXTERNAL_UPLOAD.lock().ok().and_then(|mut g| g.pop_front());
    if let Some((spec, source, remote_dir, name, size, is_dir)) = item {
        match decision {
            1 => {
                // overwrite
                let remote = join_remote(PathBuf::from(&remote_dir).join(&name));
                do_external_upload(handle, engine, idx, ui.clone(), spec, source, remote, name, size, is_dir);
            }
            2 => {
                // save under a new (auto-suffixed) remote name
                let (h, en, ix, uw, st, sp, rd, nm) = (
                    handle.clone(), engine.clone(), idx.clone(), ui.clone(), store.clone(),
                    spec.clone(), remote_dir.clone(), name.clone(),
                );
                handle.spawn(async move {
                    let dst_kind = PaneKind::Remote;
                    let new_name = unique_dest_name(&nm, &dst_kind, Some(&sp), &rd, &st).await;
                    let remote = join_remote(PathBuf::from(&rd).join(&new_name));
                    let _ = slint::invoke_from_event_loop(move || {
                        do_external_upload(&h, en, ix, uw, sp, source, remote, new_name, size, is_dir);
                    });
                });
            }
            _ => { if let Some(u) = ui.upgrade() { u.set_status("cancelled".into()); } } // 0 = cancel
        }
        // show the next queued conflict, if any (tuple field index 3 == name)
        if let Some(next) = PENDING_EXTERNAL_UPLOAD.lock().ok().and_then(|g| g.front().cloned()) {
            if let Some(u) = ui.upgrade() {
                u.set_overwrite_name(next.3.into());
                u.set_overwrite_open(true);
            }
        }
        return;
    }
    // in-app copy
    let pending = PENDING_COPY.lock().ok().and_then(|mut g| g.take());
    let Some((src_pane, dst_pane, name, is_dir, total)) = pending else { return };
    match decision {
        1 => do_transfer(handle, store, panes, engine, idx, ui, src_pane, dst_pane, name.clone(), name, is_dir, total),
        2 => {
            let (dst_kind, dst_conn, dst_cwd) = {
                let p = panes.lock().expect("panes");
                let s = &p[dst_pane];
                (s.kind.clone(), s.conn.clone(), s.cwd.clone())
            };
            let store2 = store.clone();
            let h = handle.clone();
            handle.spawn(async move {
                let new_name = unique_dest_name(&name, &dst_kind, dst_conn.as_ref(), &dst_cwd, &store2).await;
                // Keep the ORIGINAL name as the source; `new_name` names only the destination.
                // Building the source path from `new_name` pointed RETR/STOR at a file that does
                // not exist at the source and left the transfer stuck on "queued".
                let src_name = name;
                let _ = slint::invoke_from_event_loop(move || {
                    do_transfer(&h, store2, panes, engine, idx, ui, src_pane, dst_pane, src_name, new_name, is_dir, total);
                });
            });
        }
        _ => { if let Some(ui) = ui.upgrade() { ui.set_status("cancelled".into()); } } // 0 = cancel
    }
}

/// Pick a non-clashing destination name: "file new.ext", then "file new 2.ext", …
async fn unique_dest_name(
    name: &str,
    dst_kind: &PaneKind,
    dst_conn: Option<&ConnectionSpec>,
    dst_cwd: &str,
    store: &Arc<dyn CredentialStore>,
) -> String {
    let (stem, ext) = match name.rfind('.') {
        Some(i) if i > 0 => (&name[..i], &name[i..]),
        _ => (name, ""),
    };
    let mut candidates = vec![format!("{} new{}", stem, ext)];
    for n in 2..=99u32 {
        candidates.push(format!("{} new {}{}", stem, n, ext));
    }
    match dst_kind {
        PaneKind::Local => {
            for c in &candidates {
                if !PathBuf::from(dst_cwd).join(c).exists() {
                    return c.clone();
                }
            }
        }
        PaneKind::Remote => {
            if let Some(spec) = dst_conn {
                if let Some(pw) = password_for(store, spec) {
                    let mut s = spec.clone();
                    s.initial_path = dst_cwd.to_string();
                    if let Ok(entries) = net::connect_and_list(&s, &pw).await {
                        let taken: std::collections::HashSet<&str> = entries.iter().map(|e| e.name.as_str()).collect();
                        for c in &candidates {
                            if !taken.contains(c.as_str()) {
                                return c.clone();
                            }
                        }
                    }
                }
            }
        }
    }
    candidates.into_iter().next().unwrap_or_else(|| format!("{} new{}", stem, ext))
}

/// Wire the overwrite-conflict dialog buttons.
fn wire_overwrite(ui: &App, handle: &Handle, store: Arc<dyn CredentialStore>, panes: Panes, engine: TransferEngine, idx: Arc<Mutex<HashMap<i32, usize>>>) {
    let (h, st, pn, en, ix, uw) = (handle.clone(), store.clone(), panes.clone(), engine.clone(), idx.clone(), ui.as_weak());
    ui.on_resolve_overwrite(move |decision| {
        resolve_overwrite(&h, st.clone(), pn.clone(), en.clone(), ix.clone(), uw.clone(), decision);
    });
}

/// Local → Remote folder: walk local, enqueue one upload per file (mkdir -p on the server).
fn copy_local_to_remote(handle: &Handle, engine: TransferEngine, idx: Arc<Mutex<HashMap<i32, usize>>>, ui: Weak<App>, spec: ConnectionSpec, local_base: PathBuf, remote_base: String) {
    let (engine2, idx2, uw, lb) = (engine.clone(), idx.clone(), ui.clone(), local_base.clone());
    let _ = ui.upgrade().map(|u| u.set_status("preparing folder upload…".into()));
    handle.spawn(async move {
        let files = tokio::task::spawn_blocking(move || walk_local(&lb)).await.unwrap_or_default();
        let _ = slint::invoke_from_event_loop(move || {
            let Some(ui) = uw.upgrade() else { return };
            if files.is_empty() { ui.set_status("folder is empty".into()); return; }
            ui.set_status(format!("uploading {} files…", files.len()).into());
            for (lp, rel, size) in &files {
                let rp = join_remote(PathBuf::from(&remote_base).join(rel));
                enqueue(&engine2, &ui, &idx2, spec.clone(), TransferDirection::Upload, lp.clone(), rp, rel, if *size > 0 { Some(*size) } else { None });
            }
        });
    });
}

/// Remote → Local folder: walk remote, enqueue one download per file (mkdir -p local).
fn copy_remote_to_local(handle: &Handle, store: Arc<dyn CredentialStore>, engine: TransferEngine, idx: Arc<Mutex<HashMap<i32, usize>>>, ui: Weak<App>, spec: ConnectionSpec, remote_base: String, local_base: PathBuf) {
    let Some(password) = password_for(&store, &spec) else { set_err(&ui, "missing credential"); return };
    let (engine2, idx2, uw, rb) = (engine.clone(), idx.clone(), ui.clone(), remote_base.clone());
    let _ = ui.upgrade().map(|u| u.set_status("preparing folder download…".into()));
    handle.spawn(async move {
        let files = net::walk_remote(&spec, &password, &rb).await;
        let _ = slint::invoke_from_event_loop(move || {
            let Some(ui) = uw.upgrade() else { return };
            match files {
                Ok(list) if list.is_empty() => ui.set_status("folder is empty".into()),
                Ok(list) => {
                    ui.set_status(format!("downloading {} files…", list.len()).into());
                    let mut skipped: usize = 0;
                    for (rp, size) in &list {
                        // Contain server-controlled relative paths (PATH-1/2): reject `..`/
                        // absolute/control-byte entries instead of joining them verbatim.
                        let rel = match net::sanitize_local_rel(
                            &rp.strip_prefix(&remote_base).map(|p| p.to_string()).unwrap_or_default(),
                        ) {
                            Ok(c) => c,
                            Err(e) => {
                                tracing::warn!(remote = %rp, error = %e, "skipping unsafe remote path");
                                skipped += 1;
                                continue;
                            }
                        };
                        let lp = local_base.join(&rel);
                        // Defense-in-depth (safe.rs assert_within): confirm the resolved local
                        // path stays inside the user-chosen download root.
                        if let Err(e) = net::assert_within(&local_base, &lp) {
                            tracing::warn!(remote = %rp, error = %e, "skipping out-of-root path");
                            skipped += 1;
                            continue;
                        }
                        enqueue(&engine2, &ui, &idx2, spec.clone(), TransferDirection::Download, lp, rp.clone(), &rel, if *size > 0 { Some(*size) } else { None });
                    }
                    if skipped > 0 {
                        ui.set_status(
                            format!("downloaded {} file(s); skipped {skipped} unsafe path(s)", list.len() - skipped).into(),
                        );
                    }
                }
                Err(e) => ui.set_error(e.to_string().into()),
            }
        });
    });
}

/// Remote → Remote folder: relay each file through a temp dir (download then upload).
/// Relay one file: download src→temp (any protocol), then upload temp→dst (any protocol).
/// Retries once after a short delay — many shared-hosting FTP servers limit concurrent
/// sessions and need a moment to release the slot after the browsing connection's quit().
async fn relay_one(src_spec: &ConnectionSpec, pw_src: &str, dst_spec: &ConnectionSpec, pw_dst: &str, rp: &str, tmpf: &Path, dst_rp: &str) -> Result<(), String> {
    // 1. Download src → temp (retry once)
    let dl = relay_download(src_spec, pw_src, rp, tmpf).await;
    if dl.is_err() {
        tracing::warn!(target: "gmacftp", error = ?dl, "relay download failed, retrying");
        tokio::time::sleep(std::time::Duration::from_millis(800)).await;
        relay_download(src_spec, pw_src, rp, tmpf).await?;
    }
    // Verify temp file has content
    let local_size = std::fs::metadata(tmpf).map(|m| m.len()).unwrap_or(0);
    if local_size == 0 {
        let _ = std::fs::remove_file(tmpf);
        return Err("downloaded file is empty".to_string());
    }
    // 2. Pause to let the src server release the session slot
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    // 3. Upload temp → dst (FTPS first, plaintext fallback)
    let ul = relay_upload(dst_spec, pw_dst, tmpf, dst_rp).await;
    if ul.is_err() {
        tracing::warn!(target: "gmacftp", error = ?ul, "relay upload failed, retrying");
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        relay_upload(dst_spec, pw_dst, tmpf, dst_rp).await?;
    }
    Ok(())
}

async fn relay_download(spec: &ConnectionSpec, pw: &str, remote: &str, local: &Path) -> Result<(), String> {
    match spec.protocol {
        Protocol::Ftp => {
            let (s, p, r, t) = (spec.clone(), pw.to_string(), remote.to_string(), local.to_path_buf());
            tokio::time::timeout(std::time::Duration::from_secs(30),
                tokio::task::spawn_blocking(move || net::ftp::download(&s, &p, &r, &t, |_| {}, None)))
                .await
                .map_err(|_| "download timeout (30s)".to_string())?
                .map_err(|e| e.to_string())?
                .map_err(|e| e.to_string())?;
        }
        Protocol::Sftp => {
            tokio::time::timeout(std::time::Duration::from_secs(30),
                net::sftp::download(spec, pw, remote, local, |_| {}, None))
                .await
                .map_err(|_| "download timeout (30s)".to_string())?
                .map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}

/// Upload temp → dst, using the SAME `upload()` the working disk→FTP path uses. The relay
/// previously tried an FTPS+PROT-C variant then a plaintext CWD+basename fallback — both
/// divergences from the proven path: PROT C deadlocks the data channel on many servers (a
/// 20s stall every copy), and the plaintext fallback hit 5xx ("filename only letters/numbers",
/// "no file name") on real hosts. There is no reason to differ from disk→FTP, so we don't.
async fn relay_upload(spec: &ConnectionSpec, pw: &str, local: &Path, remote: &str) -> Result<(), String> {
    match spec.protocol {
        Protocol::Ftp => {
            let (s, p, r, t) = (spec.clone(), pw.to_string(), remote.to_string(), local.to_path_buf());
            tokio::time::timeout(std::time::Duration::from_secs(30),
                tokio::task::spawn_blocking(move || net::ftp::upload(&s, &p, &t, &r, |_| {}, None)))
                .await
                .map_err(|_| "upload timeout (30s)".to_string())?
                .map_err(|e| e.to_string())?
                .map_err(|e| e.to_string())?;
        }
        Protocol::Sftp => {
            tokio::time::timeout(std::time::Duration::from_secs(30),
                net::sftp::upload(spec, pw, local, remote, |_| {}, None))
                .await
                .map_err(|_| "upload timeout (30s)".to_string())?
                .map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}

/// Remote → Remote: relay each file through a temp dir in ONE sequential task (download then
/// upload per file), so the upload always runs after its download — no engine-job-ordering race.
fn copy_remote_to_remote(handle: &Handle, store: Arc<dyn CredentialStore>, _engine: TransferEngine, idx: Arc<Mutex<HashMap<i32, usize>>>, ui: Weak<App>, panes: Panes, src_spec: ConnectionSpec, dst_spec: ConnectionSpec, src_base: String, dst_base: String, name: String, is_dir: bool, size: u64) {
    let Some(pw_src) = password_for(&store, &src_spec) else { set_err(&ui, "missing src credential"); return };
    let Some(pw_dst) = password_for(&store, &dst_spec) else { set_err(&ui, "missing dst credential"); return };
    let ui_weak = ui.clone();
    // clones captured by the task so it can refresh both panes once the relay finishes
    let (handle_r, store_r, panes_r) = (handle.clone(), store.clone(), panes.clone());
    let route = format!("{} -> {}", src_spec.host, dst_spec.host);
    handle.spawn(async move {
        // Brief delay so the browsing connection's session slot is released by the server
        // (many shared hosts limit concurrent sessions per FTP user).
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        tracing::info!(target: "gmacftp", "relay: src={} dst={} is_dir={}", src_spec.host, dst_spec.host, is_dir);
        // For a single file rel="" so dst_rp = dst_base (the file itself, NOT dst_base/name).
        let items: Vec<(String, String, u64)> = if is_dir {
            match net::walk_remote(&src_spec, &pw_src, &src_base).await {
                Ok(v) => v.into_iter().map(|(rp, sz)| {
                    let rel = rp.strip_prefix(&src_base).map(|p| p.to_string()).unwrap_or_default();
                    (rp, rel, sz)
                }).collect(),
                Err(e) => { set_err(&ui_weak, &e.to_string()); return; }
            }
        } else {
            vec![(src_base.clone(), String::new(), size)]
        };
        for (rp, rel, size) in items {
            let row_id = next_xfer_id();
            let label = if rel.is_empty() { name.clone() } else { rel.clone() };
            let total = size as i32;
            let idx_p = idx.clone();
            let label_p = label.clone();
            let route_p = route.clone();
            let _ = slint::invoke_from_event_loop(move || {
                jobs_push(TransferRow { id: row_id, name: label_p.into(), direction: "→".into(), done: 0, total, progress_text: "".into(), fraction: 0.0, state: "active".into(), message: "relay".into(), route: route_p.into() }, &idx_p);
            });
            let tmpf = std::env::temp_dir().join(format!("gmacftp-relay-{row_id}-{}", rand::random::<u64>()));
            // For a single file, rel == "" and dst_rp IS dst_base. NEVER join("") here:
            // PathBuf::join("") appends a TRAILING SLASH, so the STOR target becomes
            // ".../file.txt/" → the server sees an empty filename → "501 No file name".
            // (Folder copies pass a non-empty rel, so the join is correct there.)
            let dst_rp = if rel.is_empty() {
                dst_base.clone()
            } else {
                join_remote(PathBuf::from(&dst_base).join(&rel))
            };
            let res = relay_one(&src_spec, &pw_src, &dst_spec, &pw_dst, &rp, &tmpf, &dst_rp).await;
            tracing::info!(target: "gmacftp", "relay file {}: {:?}", rel, res.as_ref().map(|_| "ok").map_err(|e| e.as_str()));
            let _ = std::fs::remove_file(&tmpf);
            let idx_s = idx.clone();
            let uw_err = ui_weak.clone();
            let _ = slint::invoke_from_event_loop(move || {
                match &res {
                    Ok(_) => jobs_set(row_id, &idx_s, "done", total, total, ""),
                    Err(e) => {
                        jobs_set(row_id, &idx_s, "failed", 0, total, e);
                        if let Some(ui) = uw_err.upgrade() {
                            ui.set_error(format!("FTP→FTP relay failed: {e}").into());
                        }
                    }
                }
            });
        }
        let _ = slint::invoke_from_event_loop({ let ui_weak = ui_weak.clone(); move || {
            if let Some(ui) = ui_weak.upgrade() { ui.set_transfer_panel_open(true); ui.set_status("remote→remote copy complete".into()); }
            // Auto-refresh both panes so the relayed file is visible immediately — no manual refresh.
            refresh_both_panes(&handle_r, store_r, panes_r, ui_weak);
        }});
    });
}

/// Recursively copy a local file/tree to a local destination. Returns file count.
fn fs_copy_tree(src: &Path, dst: &Path) -> usize {
    let md = match std::fs::metadata(src) { Ok(m) => m, Err(_) => return 0 };
    if !md.is_dir() {
        if let Some(p) = dst.parent() { let _ = std::fs::create_dir_all(p); }
        let _ = std::fs::copy(src, dst);
        return 1;
    }
    let mut n = 0;
    let mut stack = vec![(src.to_path_buf(), dst.to_path_buf())];
    while let Some((s, d)) = stack.pop() {
        let _ = std::fs::create_dir_all(&d);
        if let Ok(rd) = std::fs::read_dir(&s) {
            for e in rd.flatten() {
                let path = e.path();
                let dest = d.join(e.file_name());
                if path.is_dir() { stack.push((path, dest)); }
                else { let _ = std::fs::copy(&path, &dest); n += 1; }
            }
        }
    }
    n
}

fn password_for(store: &Arc<dyn CredentialStore>, spec: &ConnectionSpec) -> Option<String> {
    let key = (spec.host.clone(), spec.user.clone());
    if let Ok(cache) = PASSWORD_CACHE.lock() {
        if let Some(p) = cache.get(&key).cloned() {
            return Some(p); // cached — no Keychain read, no macOS prompt
        }
    }
    tracing::debug!(target: "gmacftp::creds", host = %spec.host, user = %spec.user, "credential lookup (private vault; silent — no Keychain prompt)");
    let p = store
        .get(&spec.host, &spec.user)
        .ok()
        .map(|b| String::from_utf8_lossy(&b).into_owned())?;
    if let Ok(mut cache) = PASSWORD_CACHE.lock() {
        cache.insert(key, p.clone());
    }
    Some(p)
}

// ── connect / remote list ──────────────────────────────────────────────────────

// ── pane-indexed navigation (kind-aware: Local = fs path, Remote = joined remote path) ──

fn navigate_pane(handle: &Handle, store: Arc<dyn CredentialStore>, panes: Panes, ui: Weak<App>, pane: usize, name: String) {
    let next = {
        let p = panes.lock().expect("panes");
        let cwd = p[pane].cwd.clone();
        match p[pane].kind {
            PaneKind::Local => {
                let path = if name == ".." {
                    PathBuf::from(&cwd).parent().map(|x| x.to_path_buf()).unwrap_or_else(|| PathBuf::from(&cwd))
                } else { PathBuf::from(&cwd).join(name.as_str()) };
                path.to_string_lossy().to_string()
            }
            PaneKind::Remote => {
                if name == ".." { join_remote(Path::new(&cwd).parent().map(|x| x.to_path_buf()).unwrap_or_else(|| PathBuf::from("/"))) }
                else { join_remote(PathBuf::from(&cwd).join(name.as_str())) }
            }
        }
    };
    {
        let mut p = panes.lock().expect("panes");
        p[pane].nav.go(next.clone());
        p[pane].cwd = next;
    }
    refresh_pane(handle, store, panes, ui, pane);
}

fn nav_pane_back(handle: &Handle, store: Arc<dyn CredentialStore>, panes: Panes, ui: Weak<App>, pane: usize) {
    let target = { let mut p = panes.lock().expect("panes"); let t = p[pane].nav.back(); if let Some(ref t) = t { p[pane].cwd = t.clone(); } t };
    if target.is_some() { refresh_pane(handle, store, panes, ui, pane); }
}
fn nav_pane_forward(handle: &Handle, store: Arc<dyn CredentialStore>, panes: Panes, ui: Weak<App>, pane: usize) {
    let target = { let mut p = panes.lock().expect("panes"); let t = p[pane].nav.forward(); if let Some(ref t) = t { p[pane].cwd = t.clone(); } t };
    if target.is_some() { refresh_pane(handle, store, panes, ui, pane); }
}
fn nav_pane_up(handle: &Handle, store: Arc<dyn CredentialStore>, panes: Panes, ui: Weak<App>, pane: usize) {
    let parent = {
        let p = panes.lock().expect("panes");
        let cwd = p[pane].cwd.clone();
        match p[pane].kind {
            PaneKind::Local => PathBuf::from(&cwd).parent().map(|x| x.to_string_lossy().to_string()).unwrap_or(cwd),
            PaneKind::Remote => join_remote(Path::new(&cwd).parent().map(|x| x.to_path_buf()).unwrap_or_else(|| PathBuf::from("/"))),
        }
    };
    { let mut p = panes.lock().expect("panes"); p[pane].nav.go(parent.clone()); p[pane].cwd = parent; }
    refresh_pane(handle, store, panes, ui, pane);
}

// ── callback wiring ───────────────────────────────────────────────────────────

/// Connect a server into the ACTIVE pane (used by command palette / manager / auto-connect).
fn do_connect(handle: &Handle, store: Arc<dyn CredentialStore>, conns: ConnList, sessions: Sessions, panes: Panes, ui: Weak<App>, id: i32) {
    let pane = ui.upgrade().map(|u| active_pane_idx(&u)).unwrap_or(1);
    connect_into_pane(handle, store, conns, sessions, panes, ui, pane, id);
}

fn wire_connect(ui: &App, handle: &Handle, store: Arc<dyn CredentialStore>, conns: ConnList, sessions: Sessions, panes: Panes) {
    let (handle, ui_weak) = (handle.clone(), ui.as_weak());
    ui.on_connect_to(move |id| {
        let pane = ui_weak.upgrade().map(|u| active_pane_idx(&u)).unwrap_or(1);
        connect_into_pane(&handle, store.clone(), conns.clone(), sessions.clone(), panes.clone(), ui_weak.clone(), pane, id);
    });
}

fn wire_refresh(ui: &App, handle: &Handle, store: Arc<dyn CredentialStore>, panes: Panes) {
    let (handle, ui_weak) = (handle.clone(), ui.as_weak());
    ui.on_refresh(move || {
        let pane = ui_weak.upgrade().map(|u| active_pane_idx(&u)).unwrap_or(0);
        refresh_pane(&handle, store.clone(), panes.clone(), ui_weak.clone(), pane);
    });
}

/// Wire navigate + back/forward/up for one pane (0 → navigate_local/nav_local_*, 1 → remote).
fn wire_nav_pane(ui: &App, handle: &Handle, store: Arc<dyn CredentialStore>, panes: Panes, pane: usize) {
    {
        let (h, st, pn, uw) = (handle.clone(), store.clone(), panes.clone(), ui.as_weak());
        let cb = move |name: slint::SharedString| navigate_pane(&h, st.clone(), pn.clone(), uw.clone(), pane, name.to_string());
        if pane == 0 { ui.on_navigate_local(cb); } else { ui.on_navigate_remote(cb); }
    }
    {
        let (h, st, pn, uw) = (handle.clone(), store.clone(), panes.clone(), ui.as_weak());
        let cb = move || nav_pane_back(&h, st.clone(), pn.clone(), uw.clone(), pane);
        if pane == 0 { ui.on_nav_local_back(cb); } else { ui.on_nav_remote_back(cb); }
    }
    {
        let (h, st, pn, uw) = (handle.clone(), store.clone(), panes.clone(), ui.as_weak());
        let cb = move || nav_pane_forward(&h, st.clone(), pn.clone(), uw.clone(), pane);
        if pane == 0 { ui.on_nav_local_forward(cb); } else { ui.on_nav_remote_forward(cb); }
    }
    {
        let (h, st, pn, uw) = (handle.clone(), store.clone(), panes.clone(), ui.as_weak());
        let cb = move || nav_pane_up(&h, st.clone(), pn.clone(), uw.clone(), pane);
        if pane == 0 { ui.on_nav_local_up(cb); } else { ui.on_nav_remote_up(cb); }
    }
}

/// Toolbar TLS toggle: flip accept-any-cert, apply to the net layer, persist.
fn wire_toggle_tls(ui: &App) {
    let ui_weak = ui.as_weak();
    ui.on_toggle_tls(move || {
        let Some(ui) = ui_weak.upgrade() else { return };
        let next = !ui.get_accept_any_cert();
        ui.set_accept_any_cert(next);
        net::set_accept_invalid_tls(next);
        let mut s = store::settings::load();
        s.accept_any_cert = next;
        store::settings::save(&s);
    });
}

/// Theme toggle: flip the Tokens.theme global (drives all colors) and persist the choice.
fn wire_toggle_theme(ui: &App) {
    let ui_weak = ui.as_weak();
    ui.on_toggle_theme(move || {
        let Some(ui) = ui_weak.upgrade() else { return };
        let g = crate::Tokens::get(&ui);
        let next = if g.get_theme() == "dark" { "light" } else { "dark" };
        g.set_theme(next.into());
        let mut s = store::settings::load();
        s.theme = next.to_string();
        store::settings::save(&s);
    });
}

/// "Copy Path" context action: surface the absolute path of the right-clicked entry in the
/// status bar. (macOS system clipboard write isn't exposed via Slint's stable API on our
/// backend, so we show it in the status line — copyable from there.)
fn wire_copy_path(ui: &App) {
    let ui_weak = ui.as_weak();
    ui.on_copy_path(move |pane, name| {
        let Some(ui) = ui_weak.upgrade() else { return };
        let pane = pane.to_string();
        let name = name.to_string();
        let cwd = if pane == "local" {
            ui.get_local_cwd().to_string()
        } else {
            ui.get_remote_cwd().to_string()
        };
        let full = if pane == "local" {
            PathBuf::from(&cwd).join(&name).to_string_lossy().into_owned()
        } else {
            join_remote(PathBuf::from(&cwd).join(&name))
        };
        ui.set_status(format!("path: {full}").into());
        ui.set_error("".into());
    });
}

/// "Connect" from the sidebar footer / double-click: open the SELECTED server. Today this
/// binds to the (single) remote pane; the `pane` arg is honored once multi-pane lands.
fn wire_connect_selected(
    ui: &App,
    handle: &Handle,
    store: Arc<dyn CredentialStore>,
    conns: ConnList,
    sessions: Sessions,
    panes: Panes,
) {
    let handle = handle.clone();
    let ui_weak = ui.as_weak();
    ui.on_connect_selected_to_pane(move |_pane| {
        let id = ui_weak.upgrade().map(|u| u.get_selected_connection()).unwrap_or(-1);
        if id >= 0 {
            do_connect(&handle, store.clone(), conns.clone(), sessions.clone(), panes.clone(), ui_weak.clone(), id);
        }
    });
}

/// "Home" button: switch a pane back to the local filesystem.
fn wire_set_pane_local(ui: &App, panes: Panes) {
    let ui_weak = ui.as_weak();
    ui.on_set_pane_local(move |pane| {
        let p = pane as usize;
        set_pane_local(panes.clone(), ui_weak.clone(), p);
    });
}

/// Entry point for "intend to delete" (right-click → Delete, keyboard Del). If the user has
/// ticked "Don't ask again this session" earlier in this connection, delete immediately;
/// otherwise populate the delete-confirmation dialog and open it. The dialog's confirm button
/// routes through `confirm_delete`.
fn request_delete(ui: &App, handle: &Handle, store: Arc<dyn CredentialStore>, panes: Panes, pane: usize, name: String, is_dir: bool) {
    if delete_confirm_skipped(pane) {
        delete_entry(handle, store, panes, ui.as_weak(), pane, name, is_dir);
        return;
    }
    let cwd = if pane == 0 { ui.get_local_cwd().to_string() } else { ui.get_remote_cwd().to_string() };
    let path = if pane == 0 {
        PathBuf::from(&cwd).join(&name).to_string_lossy().into_owned()
    } else {
        join_remote(PathBuf::from(&cwd).join(&name))
    };
    ui.set_delete_pane(if pane == 0 { "local".into() } else { "remote".into() });
    ui.set_delete_name(name.into());
    ui.set_delete_path(path.into());
    ui.set_delete_is_dir(is_dir);
    ui.set_delete_dont_ask(false); // fresh checkbox on every open
    ui.set_delete_open(true);
}

/// Delete-dialog "Delete" button: honour the "don't ask again" checkbox (sticky for the rest of
/// the connection), then perform the delete and close the dialog.
fn confirm_delete(handle: &Handle, store: Arc<dyn CredentialStore>, panes: Panes, ui: Weak<App>) {
    let Some(ui) = ui.upgrade() else { return };
    let pane = if ui.get_delete_pane().as_str() == "remote" { 1 } else { 0 };
    if ui.get_delete_dont_ask() {
        set_skip_delete_confirm(pane, true);
    }
    let name = ui.get_delete_name().to_string();
    let is_dir = ui.get_delete_is_dir();
    ui.set_delete_dont_ask(false);
    ui.set_delete_open(false);
    delete_entry(handle, store, panes, ui.as_weak(), pane, name, is_dir);
}

fn wire_request_delete(ui: &App, handle: &Handle, store: Arc<dyn CredentialStore>, panes: Panes) {
    let (handle, store, panes, ui_weak) = (handle.clone(), store.clone(), panes.clone(), ui.as_weak());
    ui.on_request_delete(move |pane_s, name, is_dir| {
        if let Some(ui) = ui_weak.upgrade() {
            let pane = if pane_s.as_str() == "remote" { 1 } else { 0 };
            request_delete(&ui, &handle, store.clone(), panes.clone(), pane, name.to_string(), is_dir);
        }
    });
}

fn wire_confirm_delete(ui: &App, handle: &Handle, store: Arc<dyn CredentialStore>, panes: Panes) {
    let (handle, store, panes, ui_weak) = (handle.clone(), store.clone(), panes.clone(), ui.as_weak());
    ui.on_confirm_delete(move || {
        confirm_delete(&handle, store.clone(), panes.clone(), ui_weak.clone());
    });
}

// ── keyboard control + sidebar eject ──────────────────────────────────────────

/// Arrow up/down: move the active pane's selection by `delta` (clamped to the list).
fn move_selection(ui: &App, delta: i32) {
    let pane = active_pane_idx(ui);
    let count = if pane == 0 { ui.get_local_count() } else { ui.get_remote_count() };
    if count <= 0 { return; }
    let cur = pane_selected(ui, pane);
    let next = if cur < 0 {
        if delta > 0 { 0 } else { count - 1 }
    } else {
        (cur + delta).max(0).min(count - 1)
    };
    if pane == 0 { ui.set_local_selected(next); } else { ui.set_remote_selected(next); }
    refresh_selected_path(ui);
}

/// Type-ahead: jump to the first entry in the active pane whose name starts with `letter`.
/// Ignores non-single-letter input (so modifier/special keys passing through are no-ops).
fn type_ahead(ui: &App, letter: &str) {
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
                if pane == 0 { ui.set_local_selected(i as i32); } else { ui.set_remote_selected(i as i32); }
                return;
            }
        }
    }
}

/// Enter: copy the active pane's selected entry to the OTHER pane.
fn pane_enter(handle: &Handle, store: Arc<dyn CredentialStore>, panes: Panes, engine: TransferEngine, idx: Arc<Mutex<HashMap<i32, usize>>>, ui: Weak<App>) {
    let Some(ui) = ui.upgrade() else { return };
    let active = active_pane_idx(&ui);
    let (src, dst) = if active == 0 { (0, 1) } else { (1, 0) };
    transfer(&handle, store, panes, engine, idx, ui.as_weak(), src, dst);
}

/// Delete (Del/Backspace): delete the active pane's selected entry — routed through
/// `request_delete` so the confirmation dialog (and "don't ask again") applies to keyboard
/// deletes too, not just the right-click menu.
fn pane_delete(handle: &Handle, store: Arc<dyn CredentialStore>, panes: Panes, ui: Weak<App>) {
    let Some(ui) = ui.upgrade() else { return };
    let pane = active_pane_idx(&ui);
    let sel = pane_selected(&ui, pane);
    if sel < 0 { return; }
    let Some(row) = pane_entries(&ui, pane).row_data(sel as usize) else { return };
    request_delete(&ui, handle, store, panes, pane, row.name.to_string(), row.is_dir);
}

/// Space: Quick Look preview (macOS). Local file → `qlmanage -p`; remote → download to a temp
/// file first, then preview. Folders are skipped (no Quick Look for directories).
fn pane_preview(handle: &Handle, store: Arc<dyn CredentialStore>, panes: Panes, ui: Weak<App>) {
    let Some(ui) = ui.upgrade() else { return };
    let pane = active_pane_idx(&ui);
    let sel = pane_selected(&ui, pane);
    if sel < 0 { return; }
    let Some(row) = pane_entries(&ui, pane).row_data(sel as usize) else { return };
    if row.is_dir { return; }
    let name = row.name.to_string();
    let (kind, conn, cwd) = {
        let p = panes.lock().expect("panes");
        (p[pane].kind.clone(), p[pane].conn.clone(), p[pane].cwd.clone())
    };
    match kind {
        PaneKind::Local => {
            let path = PathBuf::from(&cwd).join(&name);
            let _ = std::process::Command::new("qlmanage").arg("-p").arg(&path).spawn();
        }
        PaneKind::Remote => {
            let Some(spec) = conn else { return };
            let Some(pw) = password_for(&store, &spec) else { return };
            let rp = join_remote(PathBuf::from(&cwd).join(&name));
            let tmp = std::env::temp_dir().join(format!("gmacftp-preview-{}", rand::random::<u64>()));
            handle.spawn(async move {
                let mut s = spec.clone(); s.initial_path = cwd.clone();
                let _ = std::fs::remove_file(&tmp);
                if net::download_file(&s, &pw, &rp, tmp.clone()).await.is_ok() {
                    // M3/MEMO-3: run qlmanage to completion on a dedicated OS thread, then remove
                    // the temp file so remote file contents (id_rsa, *.kdbx, …) don't persist in
                    // $TMPDIR (and Time Machine snapshots of it). .status() blocks until the panel
                    // closes — safe because it's not on the async runtime.
                    std::thread::spawn(move || {
                        let _ = std::process::Command::new("qlmanage").arg("-p").arg(&tmp).status();
                        let _ = std::fs::remove_file(&tmp);
                    });
                }
            });
        }
    }
}

/// Sidebar "eject" / pane-specific disconnect: abort in-flight transfers and return `pane` to
/// the local filesystem.
fn disconnect_pane(engine: TransferEngine, panes: Panes, ui: Weak<App>, pane: usize) {
    set_skip_delete_confirm(pane, false); // THIS pane's connection ended → re-arm it
    // Abort only THIS pane's connection's transfers — not every session's.
    if let Some(id) = panes.lock().expect("panes")[pane].conn.as_ref().map(|c| c.id) {
        engine.abort(id);
    }
    set_pane_local(panes, ui, pane);
}

/// Recompute the bottom-bar path for the active pane. When no entry is selected, show the pane cwd.
fn refresh_selected_path(ui: &App) {
    ui.set_selected_path(current_selected_path(ui).into());
}

fn current_selected_path(ui: &App) -> String {
    let pane = active_pane_idx(ui);
    let sel = pane_selected(ui, pane);
    let cwd = if pane == 0 { ui.get_local_cwd().to_string() } else { ui.get_remote_cwd().to_string() };
    if sel >= 0 {
        pane_entries(ui, pane).row_data(sel as usize).map(|r| {
            let n = r.name.to_string();
            if pane == 0 {
                PathBuf::from(&cwd).join(&n).to_string_lossy().into_owned()
            } else {
                join_remote(PathBuf::from(&cwd).join(&n))
            }
        }).unwrap_or_else(|| cwd.clone())
    } else {
        cwd
    }
}

/// Copy `text` to the macOS clipboard (pbcopy). Best-effort.
fn copy_to_clipboard(text: &str) -> bool {
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
fn apply_sort_field(ui: &App, key: &str) {
    let pane = if ui.get_sort_pane().as_str() == "remote" { 1 } else { 0 };
    if pane == 0 { ui.set_local_sort_key(key.into()); } else { ui.set_remote_sort_key(key.into()); }
    apply_view_pane(ui, pane);
}

/// Sort popover → toggle the targeted pane's asc/desc and re-apply.
fn toggle_sort_dir(ui: &App) {
    let pane = if ui.get_sort_pane().as_str() == "remote" { 1 } else { 0 };
    let next = |cur: &str| if cur == "asc" { "desc" } else { "asc" };
    if pane == 0 {
        ui.set_local_sort_dir(next(&ui.get_local_sort_dir()).into());
    } else {
        ui.set_remote_sort_dir(next(&ui.get_remote_sort_dir()).into());
    }
    apply_view_pane(ui, pane);
}

/// Wire the bottom-bar path + sort-popover callbacks.
fn wire_misc_ui(ui: &App) {
    { let uw = ui.as_weak(); ui.on_update_selected_path(move || { if let Some(ui) = uw.upgrade() { refresh_selected_path(&ui); } }); }
    {
        let uw = ui.as_weak();
        ui.on_copy_selected_path(move || {
            if let Some(ui) = uw.upgrade() {
                let p = current_selected_path(&ui);
                ui.set_selected_path(p.clone().into());
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
    { let uw = ui.as_weak(); ui.on_apply_sort_field(move |key| { if let Some(ui) = uw.upgrade() { apply_sort_field(&ui, &key); } }); }
    { let uw = ui.as_weak(); ui.on_toggle_sort_dir(move || { if let Some(ui) = uw.upgrade() { toggle_sort_dir(&ui); } }); }
}

/// Wire all keyboard + sidebar-eject callbacks.
fn wire_keyboard(
    ui: &App,
    handle: &Handle,
    store: Arc<dyn CredentialStore>,
    panes: Panes,
    engine: TransferEngine,
    idx: Arc<Mutex<HashMap<i32, usize>>>,
) {
    {
        let ui_weak = ui.as_weak();
        ui.on_move_selection(move |delta| { if let Some(ui) = ui_weak.upgrade() { move_selection(&ui, delta); } });
    }
    {
        let ui_weak = ui.as_weak();
        ui.on_type_ahead(move |letter| { if let Some(ui) = ui_weak.upgrade() { type_ahead(&ui, &letter); } });
    }
    {
        let (h, st, pn, en, ix, uw) = (handle.clone(), store.clone(), panes.clone(), engine.clone(), idx.clone(), ui.as_weak());
        ui.on_pane_enter(move || { pane_enter(&h, st.clone(), pn.clone(), en.clone(), ix.clone(), uw.clone()); });
    }
    {
        let (h, st, pn, uw) = (handle.clone(), store.clone(), panes.clone(), ui.as_weak());
        ui.on_pane_delete(move || { pane_delete(&h, st.clone(), pn.clone(), uw.clone()); });
    }
    {
        let (h, st, pn, uw) = (handle.clone(), store.clone(), panes.clone(), ui.as_weak());
        ui.on_pane_preview(move || { pane_preview(&h, st.clone(), pn.clone(), uw.clone()); });
    }
    {
        let (en, pn, uw) = (engine.clone(), panes.clone(), ui.as_weak());
        ui.on_disconnect_pane(move |pane| { disconnect_pane(en.clone(), pn.clone(), uw.clone(), pane as usize); });
    }
}

fn wire_local_favorites(ui: &App, panes: Panes) {
    let ui_weak = ui.as_weak();
    let open_panes = panes.clone();
    ui.on_open_local_favorite(move |path| {
        open_local_favorite(open_panes.clone(), ui_weak.clone(), path.to_string());
    });
    let ui_weak = ui.as_weak();
    let add_panes = panes.clone();
    ui.on_add_local_favorite(move |source, index| {
        if let Some(ui) = ui_weak.upgrade() {
            add_local_favorite_from_pane(&ui, add_panes.clone(), source.to_string(), index);
        }
    });
    let ui_weak = ui.as_weak();
    ui.on_reorder_local_favorite(move |from, to| {
        if let Some(ui) = ui_weak.upgrade() {
            reorder_local_favorite(&ui, from, to);
        }
    });
    let ui_weak = ui.as_weak();
    ui.on_remove_local_favorite(move |index| {
        if let Some(ui) = ui_weak.upgrade() {
            remove_local_favorite(&ui, index);
        }
    });
}

/// Remove finished (done/failed) rows from the transfer panel and rebuild the id→row index.
fn wire_clear_finished(ui: &App, idx: Arc<Mutex<HashMap<i32, usize>>>) {
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
                let finished = jobs.row_data(i).map_or(false, |r| r.state.as_str() == "done" || r.state.as_str() == "failed");
                if finished {
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
fn wire_dismiss_transfer(ui: &App, idx: Arc<Mutex<HashMap<i32, usize>>>) {
    let ui_weak = ui.as_weak();
    ui.on_dismiss_transfer(move |id| {
        TRANSFER_JOBS.with(|jm| {
            let b = jm.borrow();
            let Some(jobs) = b.as_ref() else { return };
            if let Some(i) = (0..jobs.row_count()).find(|&i| jobs.row_data(i).map(|r| r.id == id).unwrap_or(false)) {
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

/// Transfer-panel "Pause all" toggle → engine.set_paused (stops dequeue of new transfers).
fn wire_set_transfers_paused(ui: &App, engine: TransferEngine) {
    ui.on_set_transfers_paused(move |paused| {
        engine.set_paused(paused);
    });
}

/// Disconnect: abort in-flight transfers, then return the ACTIVE pane to the local filesystem.
fn wire_disconnect(ui: &App, panes: Panes, sessions: Sessions, engine: TransferEngine) {
    let ui_weak = ui.as_weak();
    ui.on_disconnect(move || {
        let pane = ui_weak.upgrade().map(|u| active_pane_idx(&u)).unwrap_or(1);
        set_skip_delete_confirm(pane, false); // the active pane's connection ended → re-arm it
        // Toolbar Disconnect = eject the active pane's session from the pool entirely.
        let conn_id = panes.lock().expect("panes")[pane].conn.as_ref().map(|c| c.id.0 as i32);
        if let Some(id) = conn_id {
            disconnect_session(engine.clone(), sessions.clone(), panes.clone(), ui_weak.clone(), id);
        } else {
            // Active pane has no connection (already local — the Disconnect button is disabled
            // in this state). Nothing to abort per-connection; just return it to local.
            set_pane_local(panes.clone(), ui_weak.clone(), pane);
        }
        if let Some(ui) = ui_weak.upgrade() {
            ui.set_transfer_active(false);
            ui.set_transfer_fraction(0.0);
            ui.set_transfer_label("".into());
        }
    });
}

/// CONNECTED sidebar controls: click a session → show it in the active pane; eject → drop it.
fn wire_session_controls(ui: &App, handle: &Handle, store: Arc<dyn CredentialStore>, sessions: Sessions, panes: Panes, engine: TransferEngine) {
    {
        let (h, st, se, pn, uw) = (handle.clone(), store.clone(), sessions.clone(), panes.clone(), ui.as_weak());
        ui.on_switch_to_session(move |id| {
            let pane = uw.upgrade().map(|u| active_pane_idx(&u)).unwrap_or(0);
            switch_to_session(&h, st.clone(), se.clone(), pn.clone(), uw.clone(), pane, id);
        });
    }
    {
        let (se, pn, en, uw) = (sessions.clone(), panes.clone(), engine.clone(), ui.as_weak());
        ui.on_disconnect_session(move |id| {
            disconnect_session(en.clone(), se.clone(), pn.clone(), uw.clone(), id);
        });
    }
}

/// Toggle hidden (dotfile) visibility, re-apply both panes.
fn wire_toggle_hidden(ui: &App) {
    let ui_weak = ui.as_weak();
    ui.on_toggle_hidden(move || {
        if let Some(ui) = ui_weak.upgrade() {
            ui.set_show_hidden(!ui.get_show_hidden());
            apply_view_pane(&ui, 0);
            apply_view_pane(&ui, 1);
        }
    });
}

/// Click a column header (`key` = "name" | "date" | "size"): if it's already the active sort
/// key, flip asc/desc; otherwise make it the active key (ascending). Then re-apply the view.
fn sort_by(ui: &App, pane: usize, key: &str) {
    let (cur_key, cur_dir) = if pane == 0 {
        (ui.get_local_sort_key().to_string(), ui.get_local_sort_dir().to_string())
    } else {
        (ui.get_remote_sort_key().to_string(), ui.get_remote_sort_dir().to_string())
    };
    let (nk, nd) = if cur_key == key {
        (cur_key, if cur_dir == "asc" { "desc".to_string() } else { "asc".to_string() })
    } else {
        (key.to_string(), "asc".to_string())
    };
    if pane == 0 {
        ui.set_local_sort_key(nk.into());
        ui.set_local_sort_dir(nd.into());
    } else {
        ui.set_remote_sort_key(nk.into());
        ui.set_remote_sort_dir(nd.into());
    }
    apply_view_pane(ui, pane);
}

fn wire_sort(ui: &App, pane: usize) {
    let ui_weak = ui.as_weak();
    if pane == 0 {
        ui.on_sort_local(move |key| {
            if let Some(ui) = ui_weak.upgrade() {
                sort_by(&ui, 0, &key);
            }
        });
    } else {
        ui.on_sort_remote(move |key| {
            if let Some(ui) = ui_weak.upgrade() {
                sort_by(&ui, 1, &key);
            }
        });
    }
}

/// Download (←) = copy the selected entry from the RIGHT pane (1) to the LEFT pane (0).
fn wire_transfer_download(
    ui: &App,
    handle: &Handle,
    store: Arc<dyn CredentialStore>,
    panes: Panes,
    engine: TransferEngine,
    idx: Arc<Mutex<HashMap<i32, usize>>>,
) {
    let (handle, store, panes, engine, idx, ui_weak) =
        (handle.clone(), store.clone(), panes.clone(), engine, idx, ui.as_weak());
    ui.on_download(move || {
        transfer(&handle, store.clone(), panes.clone(), engine.clone(), idx.clone(), ui_weak.clone(), 1, 0);
    });
}

/// Upload (→) = copy the selected entry from the LEFT pane (0) to the RIGHT pane (1).
fn wire_transfer_upload(
    ui: &App,
    handle: &Handle,
    store: Arc<dyn CredentialStore>,
    panes: Panes,
    engine: TransferEngine,
    idx: Arc<Mutex<HashMap<i32, usize>>>,
) {
    let (handle, store, panes, engine, idx, ui_weak) =
        (handle.clone(), store.clone(), panes.clone(), engine, idx, ui.as_weak());
    ui.on_upload(move || {
        transfer(&handle, store.clone(), panes.clone(), engine.clone(), idx.clone(), ui_weak.clone(), 0, 1);
    });
}

/// Walk a local directory recursively → `(absolute_local_path, relative_path, size)` for
/// every regular file. Symlinks are followed as dirs only if they resolve to a dir.
fn walk_local(base: &Path) -> Vec<(PathBuf, String, u64)> {
    let mut out = Vec::new();
    fn recurse(dir: &Path, rel: &str, out: &mut Vec<(PathBuf, String, u64)>) {
        let Ok(rd) = std::fs::read_dir(dir) else {
            return;
        };
        for entry in rd.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let path = entry.path();
            let child_rel = if rel.is_empty() {
                name
            } else {
                format!("{rel}/{name}")
            };
            let Ok(md) = entry.metadata() else {
                continue;
            };
            if md.is_dir() {
                recurse(&path, &child_rel, out);
            } else {
                out.push((path, child_rel, md.len()));
            }
        }
    }
    recurse(base, "", &mut out);
    out
}

fn wire_toggle_locale(ui: &App) {
    let ui_weak = ui.as_weak();
    ui.on_toggle_locale(move || {
        if let Some(ui) = ui_weak.upgrade() {
            let g = crate::I18n::get(&ui);
            let next = if g.get_locale() == "pl" { "en" } else { "pl" };
            g.set_locale(next.into());
        }
    });
}

// ── connection manager wiring ─────────────────────────────────────────────────

fn wire_new(ui: &App) {
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
        ui.set_editor_open(true);
    });
}

fn wire_edit(ui: &App, store: Arc<dyn CredentialStore>, conns: ConnList) {
    let ui_weak = ui.as_weak();
    ui.on_edit_connection(move |id| {
        let Some(ui) = ui_weak.upgrade() else { return };
        let spec = conns.lock().expect("connections lock").iter()
            .find(|c| c.id.0 as i32 == id).cloned();
        let Some(spec) = spec else { return };
        let pw = store.get(&spec.host, &spec.user).ok()
            .map(|b| String::from_utf8_lossy(&b).into_owned()).unwrap_or_default();
        ui.set_editor_id(spec.id.0 as i32);
        ui.set_editor_name(spec.name.into());
        ui.set_editor_protocol(spec.protocol.to_string().into());
        ui.set_editor_host(spec.host.into());
        ui.set_editor_port(spec.port.to_string().into());
        ui.set_editor_user(spec.user.into());
        ui.set_editor_password(pw.into());
        ui.set_editor_open(true);
    });
}

fn wire_delete(ui: &App, store: Arc<dyn CredentialStore>, conns: ConnList) {
    let ui_weak = ui.as_weak();
    ui.on_delete_connection(move |id| {
        let Some(ui) = ui_weak.upgrade() else { return };
        let mut g = conns.lock().expect("connections lock");
        if let Some(pos) = g.iter().position(|c| c.id.0 as i32 == id) {
            let removed = g.remove(pos);
            drop(g);
            let _ = store.delete(&removed.host, &removed.user); // clear Keychain entry
            if let Ok(mut c) = PASSWORD_CACHE.lock() {
                c.remove(&(removed.host.clone(), removed.user.clone()));
            }
            let snapshot = conns.lock().expect("connections lock").clone();
            let _ = store::save_metadata(&snapshot);
            refresh_connections_model(&ui, &conns);
            ui.set_manager_message(format!("deleted “{}”", removed.name).into());
        }
    });
}

fn wire_save(ui: &App, store: Arc<dyn CredentialStore>, conns: ConnList) {
    let ui_weak = ui.as_weak();
    ui.on_save_connection(move || {
        let Some(ui) = ui_weak.upgrade() else { return };

        let name = ui.get_editor_name().to_string();
        let host = ui.get_editor_host().trim().to_string();
        let user = ui.get_editor_user().to_string();
        let password = ui.get_editor_password().to_string();
        let protocol: Protocol = ui.get_editor_protocol().trim().to_ascii_lowercase()
            .parse().unwrap_or(Protocol::Ftp);
        let port: u16 = ui.get_editor_port().trim().parse().unwrap_or(protocol.default_port());
        let id = ui.get_editor_id();

        if name.trim().is_empty() || host.is_empty() || user.is_empty() {
            ui.set_manager_message("name, host and user are required".into());
            return;
        }

        // Persist the password (if non-empty) into the Keychain.
        if !password.is_empty() {
            if let Err(e) = store.set(&host, &user, password.as_bytes()) {
                ui.set_manager_message(format!("keychain error: {e}").into());
                return;
            }
            // keep the session cache in sync so the new password is used immediately
            if let Ok(mut c) = PASSWORD_CACHE.lock() {
                c.insert((host.clone(), user.clone()), password.clone());
            }
        }

        let spec = ConnectionSpec {
            id: ConnectionId(if id < 0 { next_id(&conns.lock().expect("lock")) } else { id as usize }),
            name, protocol, host, port, user,
            initial_path: String::new(),
        };
        {
            let mut g = conns.lock().expect("connections lock");
            if id >= 0 {
                if let Some(pos) = g.iter().position(|c| c.id.0 as i32 == id) {
                    g[pos] = spec.clone();
                }
            } else {
                g.push(spec.clone());
            }
            let _ = store::save_metadata(&g);
        }
        refresh_connections_model(&ui, &conns);
        ui.set_editor_open(false);
        ui.set_manager_message(
            if id < 0 { format!("added “{}”", spec.name) } else { format!("saved “{}”", spec.name) }.into(),
        );
    });
}

fn wire_import(ui: &App, handle: &Handle, store: Arc<dyn CredentialStore>, conns: ConnList) {
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
/// Assigns fresh stable ids and persists metadata. Returns the number actually added.
fn merge_new(conns: &ConnList, specs: Vec<ConnectionSpec>) -> usize {
    let mut g = conns.lock().expect("connections lock");
    let mut next = next_id(&g);
    let mut count = 0;
    for s in specs {
        let key = (s.host.clone(), s.user.clone());
        if g.iter().any(|c| (c.host.clone(), c.user.clone()) == key) {
            continue;
        }
        g.push(ConnectionSpec { id: ConnectionId(next), ..s });
        next += 1;
        count += 1;
    }
    let _ = store::save_metadata(&g);
    count
}

/// Import from a user-picked file. Detects the format (FileZilla `sitemanager.xml` vs the
/// a third-party file manager JSON seed) by extension, then by content sniff, loads it, stores passwords in the
/// vault, and merges new (host, user) pairs. Returns a status line for the manager dialog.
fn import_from_path(path: &Path, conns: &ConnList, store: &Arc<dyn CredentialStore>) -> String {
    let label = path
        .file_name()
        .map(|f| f.to_string_lossy().into_owned())
        .unwrap_or_else(|| path.display().to_string());
    let Ok(text) = std::fs::read_to_string(path) else {
        return format!("could not read {label}");
    };
    let ext_is = |e: &str| path.extension().and_then(|x| x.to_str()).map(|x| x.eq_ignore_ascii_case(e)).unwrap_or(false);
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
        Ok(specs) => {
            let n = merge_new(conns, specs);
            if n > 0 {
                format!("imported {n} connection(s) from {label}")
            } else {
                format!("no new connections from {label} (all already present)")
            }
        }
        Err(e) => format!("import failed ({label}): {e}"),
    }
}

fn enqueue(
    engine: &TransferEngine,
    ui: &App,
    idx: &Arc<Mutex<HashMap<i32, usize>>>,
    spec: ConnectionSpec,
    direction: TransferDirection,
    local_path: PathBuf,
    remote_path: String,
    label_name: &str,
    bytes_total: Option<u64>,
) {
    static NEXT_ID: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(1);
    let id = TransferId(NEXT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed));
    let dir_s = match direction { TransferDirection::Download => "download", TransferDirection::Upload => "upload" };
    let verb = match direction { TransferDirection::Download => "Downloading", TransferDirection::Upload => "Uploading" };
    let total_i = bytes_total.unwrap_or(0) as i32;
    let route = match direction {
        TransferDirection::Upload => format!("local -> {}", spec.host),
        TransferDirection::Download => format!("{} -> local", spec.host),
    };

    // add a row to the transfer panel (queue/history) via the UI-thread model
    let row = TransferRow {
        id: id.0 as i32,
        name: label_name.to_string().into(),
        direction: dir_s.into(),
        done: 0,
        total: total_i,
        progress_text: fmt_transfer_progress(0, total_i).into(),
        fraction: 0.0,
        state: "queued".into(),
        message: "".into(),
        route: route.into(),
    };
    jobs_push(row, idx);
    update_transfer_summary(ui);

    // compact bottom bar mirrors the just-queued job
    ui.set_transfer_active(true);
    ui.set_transfer_done(0);
    ui.set_transfer_total(total_i);
    ui.set_transfer_fraction(0.0);
    ui.set_transfer_label(format!("{verb} {label_name}").into());
    ui.set_transfer_progress_text(fmt_transfer_progress(0, total_i).into());
    ui.set_status("".into());
    ui.set_error("".into());

    let job = TransferJob {
        id,
        direction,
        local_path: local_path.to_string_lossy().to_string(),
        remote_path,
        bytes_total,
    };
    if engine.try_enqueue(job, spec).is_err() {
        // M4/CONC-1: the bounded worker channel was full — the job was NOT accepted. Mark
        // the just-inserted row as failed so it never sits on "queued" forever silently.
        jobs_set(id.0 as i32, idx, "failed", 0, total_i, "transfer queue full");
    }
}

fn spawn_progress_forwarder(
    handle: &Handle,
    store: Arc<dyn CredentialStore>,
    panes: Panes,
    mut rx: mpsc::Receiver<TransferUpdate>,
    ui: Weak<App>,
    idx: Arc<Mutex<HashMap<i32, usize>>>,
    eta: Arc<Mutex<HashMap<i32, (Instant, u64)>>>,
) {
    let handle = handle.clone();
    // Trailing-edge debounce: a folder transfer emits one Done per file. (Re)arm a 600ms timer
    // on every Done; only the latest arming fires a pane refresh. Coalesces the burst into one
    // re-list AND guarantees the final file is surfaced (a leading-edge+reset gate dropped it).
    let pending_gen = Arc::new(std::sync::atomic::AtomicU64::new(0));
    handle.clone().spawn(async move {
        while let Some(u) = rx.recv().await {
            let id = u.id.0 as i32;
            let (idx, eta, ui, store, panes, pending_gen, handle) =
                (idx.clone(), eta.clone(), ui.clone(), store.clone(), panes.clone(), pending_gen.clone(), handle.clone());
            let _ = slint::invoke_from_event_loop(move || {
                let Some(ui) = ui.upgrade() else { return };
                let total = u.bytes_total.unwrap_or(0);

                // update the matching transfer-panel row (UI-thread model via thread-local)
                TRANSFER_JOBS.with(|jm| {
                    let b = jm.borrow();
                    let Some(jobs) = b.as_ref() else { return };
                    let Some(i) = idx.lock().ok().and_then(|g| g.get(&id).copied()) else { return };
                    let Some(mut row) = jobs.row_data(i) else { return };
                    match &u.state {
                        TransferState::Active => {
                            row.state = "active".into();
                            row.done = u.bytes_done as i32;
                            row.total = total as i32;
                            row.fraction = if total > 0 { u.bytes_done as f32 / total as f32 } else { 0.0 };
                            row.progress_text = fmt_transfer_progress(row.done, row.total).into();
                            row.message = format_eta(&eta, id, u.bytes_done, total);
                        }
                        TransferState::Done => {
                            row.state = "done".into();
                            row.fraction = 1.0;
                            row.done = row.total;
                            row.progress_text = fmt_transfer_progress(row.done, row.total).into();
                            row.message = "".into();
                        }
                        TransferState::Failed(msg) => {
                            row.state = "failed".into();
                            row.message = msg.clone().into();
                        }
	                    }
	                    jobs.set_row_data(i, row);
	                    update_transfer_summary_from_model(&ui, jobs);
	                });

                // compact bottom bar mirrors the active/done/failed job
                match &u.state {
                    TransferState::Active => {
                        let frac = if total > 0 { u.bytes_done as f32 / total as f32 } else { 0.0 };
                        ui.set_transfer_active(true);
                        ui.set_transfer_done(u.bytes_done as i32);
                        ui.set_transfer_total(total as i32);
                        ui.set_transfer_fraction(frac);
                        ui.set_transfer_progress_text(fmt_transfer_progress(u.bytes_done as i32, total as i32).into());
                    }
                    TransferState::Done => {
                        ui.set_transfer_active(false);
                        ui.set_transfer_fraction(1.0);
                        ui.set_status("transfer complete".into());
                        // (Re)arm a trailing 600ms refresh timer; only the latest arming fires.
                        // This runs on the UI thread; spawn the timer on the runtime, then hop
                        // back to the UI thread for the re-list (Slint models are !Send).
                        let gen = pending_gen.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
                        let (h, st, pn, uw, pg) =
                            (handle.clone(), store.clone(), panes.clone(), ui.as_weak(), pending_gen.clone());
                        handle.spawn(async move {
                            tokio::time::sleep(std::time::Duration::from_millis(600)).await;
                            if pg.load(std::sync::atomic::Ordering::SeqCst) == gen {
                                let _ = slint::invoke_from_event_loop(move || {
                                    if let Some(ui) = uw.upgrade() {
                                        refresh_both_panes(&h, st, pn, ui.as_weak());
                                    }
                                });
                            }
                        });
                    }
                    TransferState::Failed(msg) => {
                        ui.set_transfer_active(false);
                        ui.set_error(msg.clone().into());
                    }
                }
            });
        }
    });
}

/// Crude per-job ETA ("~Ns") from a sampled bytes/sec rate; empty when unknown.
fn format_eta(eta: &Arc<Mutex<HashMap<i32, (Instant, u64)>>>, id: i32, done: u64, total: u64) -> slint::SharedString {
    if total == 0 || done == 0 {
        return "".into();
    }
    let now = Instant::now();
    let rate = match eta.lock().ok() {
        Some(mut g) => {
            let r = match g.get(&id) {
                Some((t, prev)) => {
                    let dt = now.duration_since(*t).as_secs_f32();
                    if dt > 0.05 { (done - prev) as f32 / dt } else { 0.0 }
                }
                None => 0.0,
            };
            g.insert(id, (now, done));
            r
        }
        None => 0.0,
    };
    if rate > 0.0 {
        let secs = (total - done) as f32 / rate;
        if secs > 0.5 {
            return format!("~{}s", secs.round() as u64).into();
        }
    }
    "".into()
}

fn set_err(ui: &Weak<App>, msg: &str) {
    let ui = ui.clone();
    let msg = msg.to_string();
    let _ = slint::invoke_from_event_loop(move || {
        if let Some(ui) = ui.upgrade() {
            ui.set_error(msg.into());
        }
    });
}

fn join_remote(p: PathBuf) -> String {
    let s = p.to_string_lossy().replace('\\', "/");
    // Drop empty segments and ".." (traversal), collapse to a single leading slash with no
    // trailing slash. Neutralizes a malicious server listing "../../etc/passwd": the path can't
    // escape upward. Legitimate remote paths (absolute cwd + single-segment names) have no "..".
    let parts: Vec<&str> = s.split('/').filter(|seg| !seg.is_empty() && *seg != "..").collect();
    if parts.is_empty() { "/".to_string() } else { format!("/{}", parts.join("/")) }
}
