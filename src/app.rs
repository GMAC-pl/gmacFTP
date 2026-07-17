//! App controller: owns the Slint window, the Tokio runtime, the credential store and
//! the transfer engine, and bridges every async result back onto the UI thread via
//! `slint::invoke_from_event_loop`. All Slint callbacks are wired here, including the
//! connection manager (add / edit / delete / import from a third-party file manager).

// Internal UI-controller helpers thread a lot of shared state (handle, store, panes, engine,
// idx, ui) plus per-call args. These wide signatures are deliberate and accepted (see the
// "known lints" note in ci.yml) — collapsing them into a context struct is a separate change.
#![allow(clippy::too_many_arguments)]

#[cfg(target_os = "macos")]
use std::cell::Cell;
use std::cmp::Ordering;
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering as AtomicOrdering};
use std::sync::{Arc, LazyLock, Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime};

use futures::{stream, StreamExt};
use slint::winit_030::WinitWindowAccessor;
use slint::{ComponentHandle, Global, Model, ModelRc, VecModel, Weak};
use tokio::runtime::Handle;
use tokio::sync::mpsc;

use gmacftp::model::{
    ConnectionId, ConnectionSpec, FtpDataMode, FtpFilenameEncoding, FtpTlsMode, Protocol,
    RemoteEntry, SftpAuth, TransferDirection, TransferId, TransferJob, TransferPriority,
};
use gmacftp::net;
use gmacftp::store::{self, CredentialKey, CredentialStore};
use gmacftp::transfer::{TransferEngine, TransferState, TransferUpdate};

use crate::{
    App, ComparisonRow, ConnRow, EntryRow, LocalFavoriteRow, PathRow, SearchRow, SyncRow,
    TransferRow,
};

mod command_controller;
mod connection_controller;
mod drag_drop_controller;
mod pane_controller;
mod settings_controller;
mod state;
mod sync_controller;
mod transfer_controller;
mod update_controller;
use command_controller::*;
use connection_controller::*;
use drag_drop_controller::*;
use pane_controller::*;
use settings_controller::*;
use state::*;
use sync_controller::*;
use transfer_controller::*;
use update_controller::*;

type ConnList = Arc<Mutex<Vec<ConnectionSpec>>>;
type PasswordCache = HashMap<CredentialKey, Zeroizing<String>>;
#[derive(Debug, Clone, Copy)]
struct TransferBatch {
    id: usize,
    pause_on_error: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExistingFilePolicy {
    Ask,
    Overwrite,
    KeepBoth,
    Skip,
}

fn existing_file_policy() -> ExistingFilePolicy {
    match store::settings::load().existing_file_policy.as_str() {
        "overwrite" => ExistingFilePolicy::Overwrite,
        "keep_both" => ExistingFilePolicy::KeepBoth,
        "skip" => ExistingFilePolicy::Skip,
        _ => ExistingFilePolicy::Ask,
    }
}
#[derive(Debug, Clone, PartialEq, Eq)]
struct CopyRequest {
    name: String,
    is_dir: bool,
    total: Option<u64>,
}
type PendingCopy = (usize, usize, String, bool, Option<u64>, TransferBatch);
type PendingExternalUpload = (ConnectionSpec, PathBuf, String, String, Option<u64>, bool);
type PendingHostKeyTrust = (net::HostKeyChallenge, usize);
type PendingTlsCertificateTrust = (net::TlsCertificateChallenge, usize);

#[derive(Clone)]
struct PendingEditorConflict {
    spec: ConnectionSpec,
    pane: usize,
    cwd: String,
    name: String,
    remote_path: String,
    root: PathBuf,
    local_path: PathBuf,
    server_path: PathBuf,
    server_hash: [u8; 32],
    diff_summary: String,
    diff_preview: String,
}

enum RemoteEditOutcome {
    Message(String),
    Conflict(Box<PendingEditorConflict>),
}

/// Per-session password cache: complete endpoint identity -> password. The first read per connection
/// hits the Keychain (one macOS auth prompt); every later connect/navigation/refresh in
/// the same session uses the cached value — so you get prompted ONCE per connection,
/// not on every folder-enter. (Without a paid Developer-ID signature, macOS can't bind
/// "Always Allow" to an ad-hoc-signed app across launches, so this in-memory cache is
/// the fix within a session.)
use zeroize::Zeroizing;
static PASSWORD_CACHE: LazyLock<Mutex<PasswordCache>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

const MAX_LOCAL_FOLDER_STAT_FILES: usize = 3_000;
const MAX_REMOTE_FOLDER_STAT_FILES: usize = 2_000;
const MAX_LOCAL_FOLDER_STATS_CACHE_ENTRIES: usize = 512;
const LOCAL_FOLDER_STATS_CACHE_TTL: Duration = Duration::from_secs(10);
const MAX_REMOTE_FOLDER_STATS_CACHE_ENTRIES: usize = 512;
const REMOTE_FOLDER_STATS_CACHE_TTL: Duration = Duration::from_secs(15);
const REMOTE_METADATA_IDLE_DELAY: Duration = Duration::from_millis(300);
const REMOTE_METADATA_CONCURRENCY: usize = 2;
const MAX_RECURSIVE_METADATA_JOBS: usize = 2;
#[cfg(target_os = "macos")]
const NETWORK_ENVIRONMENT_POLL_INTERVAL: Duration = Duration::from_secs(2);
#[cfg(target_os = "macos")]
const SYSTEM_SUSPENSION_GAP: Duration = Duration::from_secs(8);
static RECURSIVE_METADATA_ACTIVE: AtomicUsize = AtomicUsize::new(0);

#[cfg(target_os = "macos")]
#[derive(Clone, Copy)]
struct EnvironmentChangeDetector {
    last_tick: SystemTime,
    network_available: bool,
}

#[cfg(target_os = "macos")]
impl EnvironmentChangeDetector {
    fn new(now: SystemTime, network_available: bool) -> Self {
        Self {
            last_tick: now,
            network_available,
        }
    }

    fn observe(&mut self, now: SystemTime, network_available: bool) -> bool {
        let resumed_after_gap = now
            .duration_since(self.last_tick)
            .map_or(true, |elapsed| elapsed > SYSTEM_SUSPENSION_GAP);
        let interface_changed = network_available != self.network_available;
        self.last_tick = now;
        self.network_available = network_available;
        resumed_after_gap || interface_changed
    }
}

#[cfg(target_os = "macos")]
fn is_route_capable_interface_name(name: &str) -> bool {
    ["en", "bridge", "bond", "utun", "ppp", "ipsec", "tap", "tun"]
        .iter()
        .any(|prefix| name.starts_with(prefix))
}

/// Inspect local interface state only. `getifaddrs` reads the kernel's current interface table and
/// sends no DNS query or network packet. On an inspection failure we fail open: retaining the
/// normal retry schedule is safer than declaring an otherwise healthy Mac offline.
#[cfg(target_os = "macos")]
fn network_link_available() -> bool {
    use std::ffi::CStr;

    let mut head = std::ptr::null_mut();
    // SAFETY: `getifaddrs` initializes a linked list owned by libc. Every pointer is checked before
    // dereferencing and `freeifaddrs` is called exactly once for a successful allocation.
    if unsafe { libc::getifaddrs(&mut head) } != 0 {
        return true;
    }
    let mut cursor = head;
    let mut available = false;
    while !cursor.is_null() {
        // SAFETY: `cursor` comes from the live list returned by `getifaddrs`.
        let interface = unsafe { &*cursor };
        if !interface.ifa_addr.is_null() && !interface.ifa_name.is_null() {
            let flags = interface.ifa_flags as i32;
            // SAFETY: `ifa_addr` and `ifa_name` were checked and remain valid until freeifaddrs.
            let family = unsafe { (*interface.ifa_addr).sa_family as i32 };
            let name = unsafe { CStr::from_ptr(interface.ifa_name) }.to_string_lossy();
            let has_ip = matches!(family, libc::AF_INET | libc::AF_INET6);
            let is_up = flags & libc::IFF_UP != 0;
            let is_loopback = flags & libc::IFF_LOOPBACK != 0;
            if has_ip && is_up && !is_loopback && is_route_capable_interface_name(&name) {
                available = true;
                break;
            }
        }
        cursor = interface.ifa_next;
    }
    // SAFETY: successful `getifaddrs` returned `head`, including a permitted null empty list.
    unsafe { libc::freeifaddrs(head) };
    available
}

struct RecursiveMetadataPermit;

impl RecursiveMetadataPermit {
    fn try_acquire() -> Option<Self> {
        RECURSIVE_METADATA_ACTIVE
            .fetch_update(AtomicOrdering::AcqRel, AtomicOrdering::Relaxed, |active| {
                (active < MAX_RECURSIVE_METADATA_JOBS).then_some(active + 1)
            })
            .ok()
            .map(|_| Self)
    }
}

impl Drop for RecursiveMetadataPermit {
    fn drop(&mut self) {
        RECURSIVE_METADATA_ACTIVE.fetch_sub(1, AtomicOrdering::Release);
    }
}
/// Bounds for recursive reads of a user-selected local folder. They keep a symlink loop, a
/// pathological tree, or a mounted volume from turning one drag/copy into an unbounded walk.
const MAX_LOCAL_TREE_FILES: usize = 100_000;
const MAX_LOCAL_TREE_DIRS: usize = 20_000;
const MAX_LOCAL_TREE_DEPTH: usize = 64;
/// Remote Finder drags are materialised locally before Finder receives them. Keep that staging
/// area bounded; transfer-queue downloads remain the right path for larger trees.
const MAX_DRAG_STAGING_FILES: usize = 10_000;
const MAX_DRAG_STAGING_BYTES: u64 = 2 * 1024 * 1024 * 1024;
const MAX_IMPORT_BYTES: u64 = 1024 * 1024;
const MIN_SYNC_PASSPHRASE_CHARS: usize = 12;
const MAX_SYNC_PASSPHRASE_BYTES: usize = 1024;

/// Copies blocked on name conflicts, awaiting the user's choices in the overwrite dialog.
/// A batch selected with Command-A can contain several conflicts, so keep a FIFO instead of
/// replacing the previous pending item. The batch policy is retained across the dialog so a
/// later I/O error still pauses the correct group. (src_pane, dst_pane, name, is_dir, total, batch)
static PENDING_COPY: LazyLock<Mutex<VecDeque<PendingCopy>>> =
    LazyLock::new(|| Mutex::new(VecDeque::new()));

/// Finder→server uploads blocked on the overwrite-conflict dialog (the external-drag twin of
/// PENDING_COPY). A FIFO queue: a multi-file drop may contain several conflicting names, confirmed
/// one at a time. (spec, local source path, remote directory, name, byte size, is_dir).
static PENDING_EXTERNAL_UPLOAD: LazyLock<Mutex<VecDeque<PendingExternalUpload>>> =
    LazyLock::new(|| Mutex::new(VecDeque::new()));
static PENDING_EDITOR_CONFLICT: LazyLock<Mutex<Option<PendingEditorConflict>>> =
    LazyLock::new(|| Mutex::new(None));

/// A first-contact SFTP key waiting for the user to verify its displayed SHA-256 fingerprint.
/// The networking layer has already rejected the handshake at this point, so no password has
/// crossed the connection. The dialog can only persist the exact challenge it displays.
static PENDING_HOST_KEY_TRUST: LazyLock<Mutex<Option<PendingHostKeyTrust>>> =
    LazyLock::new(|| Mutex::new(None));
static PENDING_TLS_CERTIFICATE_TRUST: LazyLock<Mutex<Option<PendingTlsCertificateTrust>>> =
    LazyLock::new(|| Mutex::new(None));
static PENDING_KEYBOARD_INTERACTIVE: LazyLock<Mutex<VecDeque<net::KeyboardInteractiveRequest>>> =
    LazyLock::new(|| Mutex::new(VecDeque::new()));

static PENDING_FOLDER_SYNC: LazyLock<Mutex<Option<PreparedFolderSync>>> =
    LazyLock::new(|| Mutex::new(None));
static FOLDER_SYNC_GENERATION: AtomicU64 = AtomicU64::new(0);

enum PendingSettingsCrypto {
    Export {
        path: PathBuf,
        plaintext: Zeroizing<Vec<u8>>,
    },
    Import {
        ciphertext: Vec<u8>,
    },
}

enum SettingsImportOutcome {
    Applied(Box<store::settings::Settings>),
    Retry { error: String, ciphertext: Vec<u8> },
    Failed(String),
}

static PENDING_SETTINGS_CRYPTO: LazyLock<Mutex<Option<PendingSettingsCrypto>>> =
    LazyLock::new(|| Mutex::new(None));

#[derive(serde::Serialize, serde::Deserialize)]
struct SettingsBackupDocument {
    format: String,
    version: u8,
    settings: store::settings::Settings,
}

/// Per-pane "Don't ask again this session" for the delete-confirmation dialog, indexed by pane
/// (0 = left, 1 = right). Keying per-pane (not one global flag) means ticking it while deleting on
/// one connection ONLY silences confirms for that pane — a local-Trash delete on the other pane
/// still asks, and a different server in the other pane is unaffected. Each slot is reset when
/// THAT pane's connection ends (connect / switch / Home / eject / disconnect on that pane), so the
/// suppression is scoped to a single steady connection — closer to how a third-party file manager / Transmit gate
/// "don't ask again", but session-local rather than app-persistent.
static SKIP_DELETE_CONFIRM: LazyLock<Mutex<[bool; 2]>> =
    LazyLock::new(|| Mutex::new([false, false]));

/// A monotonically increasing request id per pane. Folder-size walks finish out of order; this
/// prevents a result started for an old directory (or for a pane that became remote) from being
/// written into the current model.
static LOCAL_LIST_GENERATION: [AtomicU64; 2] = [AtomicU64::new(0), AtomicU64::new(0)];
/// Remote requests need an explicit generation in addition to connection/path matching: two
/// refreshes of the same directory otherwise look identical and the slower, older response can
/// overwrite the newer one. The networking callback also reads this value to stop `READDIR`/LIST
/// reception as soon as the user navigates elsewhere.
static REMOTE_LIST_GENERATION: [AtomicU64; 2] = [AtomicU64::new(0), AtomicU64::new(0)];
static REMOTE_SEARCH_GENERATION: [AtomicU64; 2] = [AtomicU64::new(0), AtomicU64::new(0)];
static REMOTE_SEARCH_CANCEL: LazyLock<Mutex<[Option<Arc<AtomicBool>>; 2]>> =
    LazyLock::new(|| Mutex::new([None, None]));
static REMOTE_SEARCH_CONTEXT: LazyLock<Mutex<[Option<RemoteSearchContext>; 2]>> =
    LazyLock::new(|| Mutex::new([None, None]));

#[derive(Debug, Clone, PartialEq, Eq)]
struct RemoteSearchContext {
    generation: u64,
    connection_id: ConnectionId,
    root: String,
}

enum RemoteSearchTaskResult {
    Completed(Result<net::RemoteSearchReport, net::NetError>),
    TimedOut,
}

static SYNCHRONIZED_BROWSING: LazyLock<Mutex<Option<SynchronizedBrowsing>>> =
    LazyLock::new(|| Mutex::new(None));

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SynchronizedPaneIdentity {
    Local,
    Remote(ConnectionId),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SynchronizedBrowsing {
    anchors: [String; 2],
    identities: [SynchronizedPaneIdentity; 2],
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FileClipboard {
    source_pane: usize,
    source_cwd: String,
    source_identity: SynchronizedPaneIdentity,
    items: Vec<CopyRequest>,
}

static FILE_CLIPBOARD: LazyLock<Mutex<Option<FileClipboard>>> = LazyLock::new(|| Mutex::new(None));

struct IncrementalPaneListing {
    generation: u64,
    full: Rc<VecModel<EntryRow>>,
    visible: Rc<VecModel<EntryRow>>,
    selection: Rc<VecModel<bool>>,
}

#[derive(Debug)]
struct LocalFolderStatsCacheSlot {
    root_modified: Option<SystemTime>,
    value: Arc<OnceLock<CachedLocalFolderStats>>,
}

#[derive(Debug, Clone, Copy)]
struct CachedLocalFolderStats {
    stats: FolderStats,
    cached_at: Instant,
}

/// Folder metadata is requested by both panes at startup and again after navigation. The
/// per-path OnceLock coalesces concurrent walks, while the directory mtime and short TTL keep the
/// cache from hiding normal filesystem changes.
static LOCAL_FOLDER_STATS_CACHE: LazyLock<
    Mutex<HashMap<(PathBuf, usize), LocalFolderStatsCacheSlot>>,
> = LazyLock::new(|| Mutex::new(HashMap::new()));

#[derive(Debug, Clone)]
struct CachedRemoteFolderStats {
    stats: net::RemoteTreeStats,
    cached_at: Instant,
}

type RemoteFolderStatsCache = HashMap<(usize, String, usize), CachedRemoteFolderStats>;
static REMOTE_FOLDER_STATS_CACHE: LazyLock<Mutex<RemoteFolderStatsCache>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

fn delete_confirm_skipped(pane: usize) -> bool {
    SKIP_DELETE_CONFIRM
        .lock()
        .map(|g| g.get(pane).copied().unwrap_or(false))
        .unwrap_or(false)
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
    static TRANSFER_JOBS: std::cell::RefCell<Option<Rc<VecModel<TransferRow>>>> = const {
        std::cell::RefCell::new(None)
    };
    /// Models currently receiving remote-listing batches. They live only on Slint's UI thread;
    /// background workers post owned batches through `invoke_from_event_loop`.
    static INCREMENTAL_PANE_LISTINGS: std::cell::RefCell<[Option<IncrementalPaneListing>; 2]> =
        const { std::cell::RefCell::new([None, None]) };
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

fn fmt_permissions(permissions: Option<u32>) -> String {
    permissions
        .map(|mode| format!("{:04o}", mode & 0o7777))
        .unwrap_or_default()
}

fn fmt_transfer_progress(done: u64, total: u64) -> String {
    if total > 0 {
        format!("{} / {}", fmt_size(done), fmt_size(total))
    } else {
        fmt_size(done)
    }
}

// ── pane model (Tier 2: each of the two panes is independently Local or Remote) ──
#[derive(Clone)]
enum PaneKind {
    Local,
    Remote,
}

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
struct ActiveSession {
    conn: ConnectionSpec,
    cwd: String,
    nav: Nav,
}
type Sessions = Arc<Mutex<Vec<ActiveSession>>>;

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

fn cwd_is_remote_trash(path: &str) -> bool {
    remote_quarantine_restore_context(path).is_ok()
}

fn set_pane_kind_label(ui: &App, pane: usize, p: &PaneState) {
    if ui.get_synchronized_browsing() {
        stop_synchronized_browsing(ui, None);
    }
    let (k, host, proto, conn_id) = match p.kind {
        PaneKind::Local => ("local".to_string(), String::new(), String::new(), -1),
        PaneKind::Remote => (
            "remote".to_string(),
            p.conn.as_ref().map(|c| c.host.clone()).unwrap_or_default(),
            p.conn
                .as_ref()
                .map(|c| c.protocol.to_string().to_uppercase())
                .unwrap_or_default(),
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
const MAX_NAV_HISTORY: usize = 64;

#[derive(Clone)]
struct Nav {
    history: Vec<String>,
    idx: usize,
}
impl Nav {
    fn at(path: String) -> Self {
        Nav {
            history: vec![path],
            idx: 0,
        }
    }
    fn current(&self) -> String {
        self.history
            .get(self.idx)
            .cloned()
            .unwrap_or_else(|| "/".to_string())
    }
    fn go(&mut self, path: String) {
        if self.current() == path {
            return;
        }
        self.history.truncate(self.idx + 1);
        self.history.push(path);
        self.idx = self.history.len() - 1;
        if self.history.len() > MAX_NAV_HISTORY {
            let remove = self.history.len() - MAX_NAV_HISTORY;
            self.history.drain(..remove);
            self.idx = self.idx.saturating_sub(remove);
        }
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
    fn recent(&self, limit: usize) -> Vec<String> {
        let current = self.current();
        let mut unique = HashSet::new();
        self.history
            .iter()
            .rev()
            .filter(|path| path.as_str() != current)
            .filter(|path| unique.insert((*path).clone()))
            .take(limit)
            .cloned()
            .collect()
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

                attributes
                    .with_transparent(true)
                    .with_decorations(true)
                    .with_titlebar_transparent(true)
                    .with_title_hidden(true)
                    .with_titlebar_hidden(true)
                    .with_titlebar_buttons_hidden(true)
                    .with_fullsize_content_view(true)
                    .with_has_shadow(true)
            }

            #[cfg(not(target_os = "macos"))]
            attributes.with_transparent(true)
        })
        .build()
        .expect("failed to build winit backend");
    slint::platform::set_platform(Box::new(backend)).expect("failed to set the slint platform");

    let ui = App::new().expect("failed to construct gmacFTP UI");
    ui.set_app_version(env!("CARGO_PKG_VERSION").into());
    ui.on_localize_runtime(|message, locale| {
        crate::i18n::runtime(message.as_str(), locale.as_str()).into()
    });

    // Native macOS menu bar (App/File/Edit/View/Window/Help). No-op off macOS.
    crate::macos_menu::install(ui.as_weak());

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("failed to build Tokio runtime");
    let handle = runtime.handle().clone();

    // Settings → locale + theme. TLS exceptions live on each ConnectionSpec, never in a global
    // process setting, so concurrent connections cannot inherit one server's exception.
    let settings = store::settings::load();
    apply_locale(&ui, &settings.locale);
    ui.set_transfer_concurrency(settings.transfer_concurrency as i32);
    ui.set_background_folder_metadata(settings.background_folder_metadata);
    ui.set_show_hidden(settings.show_hidden_files);
    ui.set_show_advanced_columns(settings.show_advanced_columns);
    ui.set_sync_comparison(settings.sync_comparison.clone().into());
    ui.set_sync_mtime_tolerance(settings.sync_mtime_tolerance_secs.to_string().into());
    ui.set_sync_exclusions(settings.sync_exclusions.clone().into());
    load_settings_form(&ui, &settings);
    let theme = std::env::var("MACKFTP_THEME").unwrap_or_else(|_| settings.theme.clone());
    crate::Tokens::get(&ui).set_theme(effective_theme(&ui, &theme).into());
    restore_window_geometry(&ui, &settings);
    ui.set_accept_any_cert(false);
    refresh_local_favorites_model(&ui);

    // Upgrade legacy `(host, user)` credentials only for endpoints already present in the local,
    // pre-sync metadata. Doing this before reading an unauthenticated sync-folder metadata file
    // prevents that file from redirecting a legacy password into a new protocol or port.
    let design_demo = use_design_demo_main();
    if !design_demo && !settings.endpoint_credentials_migrated_v2 {
        let migration_store = store::default_store();
        match migrate_saved_passwords(&migration_store) {
            Ok(n) if n > 0 => ui.set_status(
                format!("Migrated {n} saved passwords into the encrypted vault (one-time).").into(),
            ),
            Ok(_) => {}
            Err(error) => {
                ui.set_error(format!("Could not migrate saved passwords: {error}").into())
            }
        }
    }

    // Cross-device sync (before the final store loads local files): pull the newest
    // connections.json / vault.bin from the sync folder (default iCloud Drive) into the local
    // copies. The one-time v1 migration above has already used only trusted local endpoints.
    if !design_demo {
        store::cloud::bootstrap();
    }
    // Create the store AFTER the pull so FileVault::open loads the just-pulled vault (and so
    // is_locked() reflects the post-pull state).
    let store: Arc<dyn CredentialStore> = if design_demo {
        Arc::new(store::InMemoryStore::default())
    } else {
        Arc::new(store::default_store())
    };
    // If the pulled vault is undecryptable (master key absent locally) but a wrapped key exists
    // in the sync folder, prompt for the sync passphrase to unlock it.
    if store.is_locked() {
        ui.set_passphrase_mode("enter".into());
        ui.set_passphrase_open(true);
    } else if store::cloud::enabled() && !settings.sync_passphrase_set {
        // Sync is on but no passphrase set here yet. If a wrapped key already exists in the
        // sync folder, ANOTHER Mac already set up sync → JOIN it (enter that passphrase).
        // Otherwise this is the first Mac → SET a new one.
        let mode = if store::cloud::read_key().is_some() {
            "enter"
        } else {
            "set"
        };
        ui.set_passphrase_mode(mode.into());
        ui.set_passphrase_open(true);
    }

    let connections = if use_design_demo_connections() {
        design_demo_connections()
    } else {
        bootstrap(&store)
    };
    if !design_demo && !ui.get_passphrase_open() {
        offer_legacy_credential_recovery(&ui, store.as_ref(), &connections);
    }
    let conns: ConnList = Arc::new(Mutex::new(connections));

    let home = home_dir();
    let restored_local = |saved: &Option<String>| {
        saved
            .as_ref()
            .filter(|_| settings.restore_workspace)
            .map(PathBuf::from)
            .filter(|path| path.is_dir())
            .unwrap_or_else(|| home.clone())
    };
    let left_start = restored_local(&settings.last_left_local_path);
    let right_start = restored_local(&settings.last_right_local_path);
    let left_start_s = left_start.to_string_lossy().into_owned();
    let right_start_s = right_start.to_string_lossy().into_owned();
    ui.set_pane_split(settings.pane_split_px as f32);
    // Tier 2: two independent panes start locally, optionally at their last clean-session paths.
    let panes: Panes = Arc::new(Mutex::new([
        PaneState {
            kind: PaneKind::Local,
            conn: None,
            cwd: left_start_s.clone(),
            nav: Nav::at(left_start_s.clone()),
        },
        PaneState {
            kind: PaneKind::Local,
            conn: None,
            cwd: right_start_s.clone(),
            nav: Nav::at(right_start_s.clone()),
        },
    ]));
    {
        let p = panes.lock().expect("panes");
        set_pane_kind_label(&ui, 0, &p[0]);
        set_pane_kind_label(&ui, 1, &p[1]);
    }
    list_local_pane(&ui, 0, &left_start, &left_start_s);
    list_local_pane(&ui, 1, &right_start, &right_start_s);
    refresh_connections_model(&ui, &conns);
    // background session pool (CONNECTED sidebar) — empty until the first Connect
    let sessions: Sessions = Arc::new(Mutex::new(Vec::new()));
    ui.set_sessions(ModelRc::from(Rc::new(VecModel::default())));
    refresh_sessions_model(&ui, &sessions);

    let (upd_tx, upd_rx) = mpsc::channel::<TransferUpdate>(64);
    let engine = runtime.block_on(async { TransferEngine::start(store.clone(), upd_tx) });
    let jobs_model: Rc<VecModel<TransferRow>> = Rc::new(VecModel::default());
    let jobs_index: Arc<Mutex<HashMap<i32, usize>>> = Arc::new(Mutex::new(HashMap::new()));
    let eta_samples: Arc<Mutex<HashMap<i32, (Instant, u64)>>> =
        Arc::new(Mutex::new(HashMap::new()));
    ui.set_transfer_jobs(ModelRc::from(jobs_model.clone()));
    let recovered_jobs = engine.recovered_jobs();
    let mut resumed_recovered = 0usize;
    let mut retained_recovered = 0usize;
    for (job, spec) in &recovered_jobs {
        reserve_xfer_ids_after(job.id.0);
        if settings.queue_recovery_policy == "discard" {
            engine.forget_job(job.id);
            continue;
        }
        let mut row = recovered_transfer_row(job, spec);
        if settings.queue_recovery_policy == "resume" && engine.retry_job(job.id).is_ok() {
            row.state = "queued".into();
            row.message = "recovered — resuming safely…".into();
            resumed_recovered += 1;
        } else {
            retained_recovered += 1;
        }
        let row_index = jobs_model.row_count();
        jobs_model.push(row);
        if let Ok(mut index) = jobs_index.lock() {
            index.insert(job.id.0 as i32, row_index);
        }
    }
    if resumed_recovered > 0 {
        ui.set_status(format!("Resuming {resumed_recovered} recovered transfer(s) safely.").into());
    } else if retained_recovered > 0 {
        ui.set_status(
            format!(
                "Recovered {} interrupted transfer(s). Open Transfers to resume or discard them.",
                retained_recovered
            )
            .into(),
        );
    } else if !recovered_jobs.is_empty() {
        ui.set_status(
            format!(
                "Discarded {} recovered transfer(s) according to Settings.",
                recovered_jobs.len()
            )
            .into(),
        );
    }
    let demo_transfers = std::env::var_os("MACKFTP_DEMO_TRANSFERS").is_some();
    if demo_transfers {
        let demo = [
            (
                "backup-06-19.sql.gz",
                "download",
                "ftp.example.com  ->  ~/Downloads",
                "92 / 184 MB",
                92 * 1024 * 1024,
                184 * 1024 * 1024,
                0.50,
                "active",
                "2.1 MB/s · 44s left",
            ),
            (
                "photo-archive.zip",
                "upload",
                "~/Sites  ->  sftp.example.com",
                "47 / 58 MB",
                47 * 1024 * 1024,
                58 * 1024 * 1024,
                0.82,
                "active",
                "3.4 MB/s · 3s left",
            ),
            (
                "report-Q3.pdf",
                "download",
                "ftp.example.com  ->  ~/Downloads",
                "2.4 MB",
                24 * 1024 * 100,
                0,
                0.0,
                "queued",
                "Waiting",
            ),
            (
                "invoice-8871.pdf",
                "download",
                "ftp.example.com  ->  ~/Downloads",
                "412 KB",
                412 * 1024,
                412 * 1024,
                1.0,
                "done",
                "Completed",
            ),
            (
                "deploy.sh",
                "upload",
                "~/Sites  ->  sftp.example.com",
                "5 / 22 MB",
                5 * 1024 * 1024,
                22 * 1024 * 1024,
                0.25,
                "failed",
                "Permission denied",
            ),
        ];
        for (idx, (name, direction, route, progress_text, done, total, fraction, state, message)) in
            demo.into_iter().enumerate()
        {
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
                priority: "normal".into(),
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
    spawn_progress_forwarder(
        &handle,
        store.clone(),
        panes.clone(),
        engine.clone(),
        upd_rx,
        ui.as_weak(),
        jobs_index.clone(),
        eta_samples.clone(),
    );

    // ── callbacks ──
    wire_connect(
        &ui,
        &handle,
        store.clone(),
        conns.clone(),
        sessions.clone(),
        panes.clone(),
    );
    wire_refresh(&ui, &handle, store.clone(), panes.clone());
    wire_nav_pane(&ui, &handle, store.clone(), panes.clone(), 0);
    wire_nav_pane(&ui, &handle, store.clone(), panes.clone(), 1);
    wire_path_editor(&ui, &handle, store.clone(), panes.clone());
    wire_remote_trash(&ui, &handle, store.clone(), panes.clone());
    wire_restore_remote_trash(&ui, &handle, store.clone(), panes.clone());
    wire_file_filters(&ui);
    wire_remote_search(&ui, &handle, store.clone(), panes.clone());
    wire_directory_comparison(&ui);
    wire_synchronized_browsing(&ui, panes.clone());
    wire_transfer_download(
        &ui,
        &handle,
        store.clone(),
        panes.clone(),
        engine.clone(),
        jobs_index.clone(),
    );
    wire_transfer_upload(
        &ui,
        &handle,
        store.clone(),
        panes.clone(),
        engine.clone(),
        jobs_index.clone(),
    );
    wire_folder_sync(
        &ui,
        &handle,
        store.clone(),
        sessions.clone(),
        panes.clone(),
        engine.clone(),
        jobs_index.clone(),
    );
    wire_toggle_locale(&ui);
    wire_toggle_tls(&ui, conns.clone(), sessions.clone(), panes.clone());
    wire_toggle_theme(&ui);
    wire_copy_path(&ui);
    wire_calculate_folder_size(&ui, &handle, store.clone(), panes.clone());
    wire_disconnect(&ui, panes.clone(), sessions.clone(), engine.clone());
    wire_toggle_hidden(&ui);
    wire_toggle_advanced_columns(&ui);
    wire_toggle_background_metadata(&ui, &handle, store.clone(), panes.clone());
    wire_settings(
        &ui,
        &handle,
        store.clone(),
        conns.clone(),
        panes.clone(),
        engine.clone(),
    );
    wire_updates(&ui, settings.check_updates_automatically, !design_demo);
    wire_sort(&ui, 0);
    wire_sort(&ui, 1);
    // connection manager
    wire_new(&ui);
    wire_choose_private_key(&ui, &handle);
    wire_choose_tls_client_identity(&ui, &handle);
    wire_edit(&ui, store.clone(), conns.clone());
    wire_delete(&ui, store.clone(), conns.clone());
    wire_save(&ui, store.clone(), conns.clone());
    wire_test_connection(&ui, &handle, conns.clone());
    wire_reset_editor_tls_trust(&ui);
    wire_import(&ui, &handle, store.clone(), conns.clone());
    wire_connect_selected(
        &ui,
        &handle,
        store.clone(),
        conns.clone(),
        sessions.clone(),
        panes.clone(),
    );
    wire_server_filter(&ui);
    wire_reorder_saved_connections(&ui, conns.clone());
    wire_palette_filter(&ui);
    wire_set_pane_local(&ui, panes.clone());
    wire_local_favorites(&ui, panes.clone());
    wire_clear_finished(&ui, jobs_index.clone(), engine.clone());
    wire_dismiss_transfer(&ui, jobs_index.clone(), engine.clone());
    wire_individual_transfer_controls(&ui, jobs_index.clone(), engine.clone());
    wire_transfer_queue_controls(&ui, jobs_index.clone(), engine.clone());
    wire_export_transfer_report(&ui, &handle);
    wire_set_transfers_paused(&ui, engine.clone());
    wire_set_transfer_concurrency(&ui, engine.clone());
    wire_resolve_transfer_error(&ui, engine.clone());
    wire_window_controls(
        &ui,
        &handle,
        store.clone(),
        panes.clone(),
        engine.clone(),
        jobs_index.clone(),
    );
    wire_external_drag(&ui, &handle, store.clone(), panes.clone());
    wire_request_delete(&ui, &handle, store.clone(), panes.clone());
    wire_confirm_delete(&ui, &handle, store.clone(), panes.clone());
    wire_file_operations(&ui, &handle, store.clone(), panes.clone());
    wire_power_file_operations(
        &ui,
        &handle,
        store.clone(),
        panes.clone(),
        engine.clone(),
        jobs_index.clone(),
    );
    wire_remote_edit(&ui, &handle, store.clone(), panes.clone());
    wire_editor_conflict_resolution(&ui, &handle, store.clone(), panes.clone());
    wire_keyboard(
        &ui,
        &handle,
        store.clone(),
        panes.clone(),
        engine.clone(),
        jobs_index.clone(),
    );
    wire_misc_ui(&ui);
    wire_passphrase(
        &ui,
        &handle,
        store.clone(),
        conns.clone(),
        panes.clone(),
        engine.clone(),
    );
    wire_credential_recovery(&ui, store.clone(), conns.clone());
    wire_keyboard_interactive(&ui, &handle);
    wire_host_key_trust(&ui, &handle, store.clone(), panes.clone());
    wire_tls_certificate_trust(
        &ui,
        &handle,
        store.clone(),
        conns.clone(),
        sessions.clone(),
        panes.clone(),
    );
    wire_send_sync(&ui, store.clone());
    wire_overwrite(
        &ui,
        &handle,
        store.clone(),
        panes.clone(),
        engine.clone(),
        jobs_index.clone(),
    );
    wire_session_controls(
        &ui,
        &handle,
        store.clone(),
        sessions.clone(),
        panes.clone(),
        engine.clone(),
    );
    // Re-assert keyboard focus on every pane/row click — Slint delivers key-pressed only to the
    // focused item, so we focus the root FocusScope whenever a pane becomes active.
    {
        let (uw, pn) = (ui.as_weak(), panes.clone());
        ui.on_activate_pane(move |_| {
            if let Some(ui) = uw.upgrade() {
                focus_root(&ui);
                refresh_selected_path(&ui);
                let active = active_pane_idx(&ui);
                let tls_exception =
                    pn.lock()
                        .ok()
                        .and_then(|states| {
                            states[active].conn.as_ref().map(|spec| {
                                spec.accept_invalid_tls || spec.tls_pinned_sha256.is_some()
                            })
                        })
                        .unwrap_or(false);
                ui.set_accept_any_cert(tls_exception);
            }
        });
    }

    // Focus the root so keyboard control works immediately on launch (before any click).
    focus_root(&ui);

    // Test affordance: MACKFTP_AUTO_CONNECT=<id> auto-connects into the active pane.
    if let Ok(id) = std::env::var("MACKFTP_AUTO_CONNECT") {
        if let Ok(id) = id.trim().parse::<i32>() {
            let (handle2, store2, conns2, sessions2, panes2, ui_weak2) = (
                handle.clone(),
                store.clone(),
                conns.clone(),
                sessions.clone(),
                panes.clone(),
                ui.as_weak(),
            );
            std::thread::spawn(move || {
                std::thread::sleep(std::time::Duration::from_millis(1500));
                let _ = slint::invoke_from_event_loop(move || {
                    do_connect(&handle2, store2, conns2, sessions2, panes2, ui_weak2, id);
                });
            });
        }
    }

    if settings.open_connection_manager_on_launch
        && std::env::var_os("MACKFTP_OPEN_PANEL").is_none()
    {
        ui.set_manager_open(true);
    }

    if let Ok(panel) = std::env::var("MACKFTP_OPEN_PANEL") {
        match panel.trim().to_lowercase().as_str() {
            "transfers" | "transfer" => ui.set_transfer_panel_open(true),
            "servers" | "connections" | "manager" => ui.set_manager_open(true),
            "settings" | "preferences" => {
                ui.set_settings_section("general".into());
                ui.invoke_refresh_storage_stats();
                ui.set_settings_open(true);
            }
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
            "sync" | "folder-sync" => {
                ui.set_sync_direction("upload".into());
                ui.set_sync_summary(
                    "3 to copy; 42 unchanged; 2 target-only kept; 7 excluded. Path+size comparison; no deletions."
                        .into(),
                );
                ui.set_sync_rows(ModelRc::from(Rc::new(VecModel::from(vec![
                    SyncRow {
                        included: true,
                        path: "src/main.rs".into(),
                        action: "UPLOAD".into(),
                        reason: "size differs".into(),
                        size_text: "48 KB".into(),
                    },
                    SyncRow {
                        included: true,
                        path: "assets/app-icon.png".into(),
                        action: "UPLOAD".into(),
                        reason: "missing".into(),
                        size_text: "212 KB".into(),
                    },
                    SyncRow {
                        included: true,
                        path: "README.md".into(),
                        action: "UPLOAD".into(),
                        reason: "size differs".into(),
                        size_text: "9 KB".into(),
                    },
                ]))));
                ui.set_sync_preview_ready(true);
                ui.set_sync_open(true);
            }
            "palette" | "command-palette" => {
                ui.set_palette_query("production".into());
                apply_palette_filter(&ui);
                ui.set_palette_open(true);
            }
            _ => {}
        }
    }

    // A Mac may retain authenticated sockets across sleep even though their TCP routes are no
    // longer valid. Interface transitions and a suspended event-loop gap therefore invalidate
    // only reusable protocol sessions; transfer jobs, resumable fragments, and user pause state
    // stay intact. The probe reads local kernel state and never contacts an external endpoint.
    #[cfg(target_os = "macos")]
    let _network_environment_monitor = {
        let timer = slint::Timer::default();
        let initial_link = network_link_available();
        let detector = Rc::new(Cell::new(EnvironmentChangeDetector::new(
            SystemTime::now(),
            initial_link,
        )));
        let detector_for_tick = detector.clone();
        let engine_for_tick = engine.clone();
        timer.start(
            slint::TimerMode::Repeated,
            NETWORK_ENVIRONMENT_POLL_INTERVAL,
            move || {
                let network_available = network_link_available();
                let mut detector = detector_for_tick.get();
                if detector.observe(SystemTime::now(), network_available) {
                    tracing::info!(
                        network_available,
                        "network environment changed; refreshing transfer sessions"
                    );
                    engine_for_tick.network_environment_changed(network_available);
                }
                detector_for_tick.set(detector);
            },
        );
        timer
    };

    ui.run().expect("gmacFTP event loop exited with error");
    // Persist only non-secret workspace coordinates after a clean event-loop exit. Remote server
    // paths and credentials are deliberately excluded from this lightweight restoration state.
    let mut final_settings = store::settings::load();
    final_settings.pane_split_px = ui.get_pane_split().max(0.0) as u32;
    if !ui.window().is_fullscreen() && !ui.window().is_maximized() {
        let size = ui.window().size();
        let position = ui.window().position();
        final_settings.window_width_px = size.width;
        final_settings.window_height_px = size.height;
        final_settings.window_x_px = Some(position.x);
        final_settings.window_y_px = Some(position.y);
    }
    if final_settings.restore_workspace {
        if let Ok(states) = panes.lock() {
            if matches!(states[0].kind, PaneKind::Local) {
                final_settings.last_left_local_path = Some(states[0].cwd.clone());
            }
            if matches!(states[1].kind, PaneKind::Local) {
                final_settings.last_right_local_path = Some(states[1].cwd.clone());
            }
        }
    }
    if let Err(error) = store::settings::try_save(&final_settings) {
        tracing::warn!(error = %error, "could not persist clean-session workspace state");
    }
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
    let Ok(panel) = std::env::var("MACKFTP_OPEN_PANEL") else {
        return false;
    };
    matches!(
        panel.trim().to_lowercase().as_str(),
        "servers"
            | "connections"
            | "manager"
            | "settings"
            | "preferences"
            | "palette"
            | "command-palette"
    )
}

fn use_design_demo_main() -> bool {
    std::env::var_os("MACKFTP_DEMO_MAIN").is_some()
}

fn design_demo_connections() -> Vec<ConnectionSpec> {
    [
        (
            1,
            "Production",
            Protocol::Ftp,
            "ftp.example.com",
            21,
            "deploy",
        ),
        (
            2,
            "Staging",
            Protocol::Sftp,
            "sftp.example.com",
            22,
            "release",
        ),
        (3, "CDN Edge", Protocol::Ftp, "cdn.example.com", 21, "edge"),
        (
            4,
            "Backups",
            Protocol::Sftp,
            "backup.example.com",
            22,
            "backup",
        ),
        (
            5,
            "Analytics",
            Protocol::Ftp,
            "stats.example.com",
            21,
            "reports",
        ),
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
        group: String::new(),
        tags: Vec::new(),
        timeout_secs: None,
        keepalive_interval_secs: None,
        ftp_data_mode: Default::default(),
        ftp_filename_encoding: Default::default(),
        ftp_tls_mode: Default::default(),
        proxy_url: None,
        use_ssh_config: false,
        ssh_proxy_jump: None,
        allow_plaintext_ftp: false,
        accept_invalid_tls: false,
        tls_pinned_sha256: None,
        tls_client_cert: None,
        tls_client_key: None,
        sftp_auth: Default::default(),
        sftp_private_key: None,
        transfer_concurrency: None,
    })
    .collect()
}

fn demo_entry(
    name: &str,
    is_dir: bool,
    date: &str,
    size_text: &str,
    size: i32,
    mtime: i32,
) -> EntryRow {
    EntryRow {
        name: name.into(),
        is_dir,
        size,
        mtime,
        date: date.into(),
        size_text: size_text.into(),
        permissions: "".into(),
        owner: "".into(),
        group: "".into(),
        metadata_state: "ready".into(),
    }
}

fn set_exact_pane(ui: &App, pane: usize, cwd: &str, rows: Vec<EntryRow>, selected: i32) {
    let count = rows.len() as i32;
    let full = ModelRc::from(Rc::new(VecModel::from(rows.clone())));
    let visible = ModelRc::from(Rc::new(VecModel::from(rows)));
    let mut selection = vec![false; count as usize];
    if selected >= 0 && selected < count {
        selection[selected as usize] = true;
    }
    if pane == 0 {
        ui.set_local_full(full);
        ui.set_local_entries(visible);
        ui.set_local_cwd(cwd.into());
        ui.set_local_path_display(display_path(cwd).into());
        ui.set_left_in_remote_trash(cwd_is_remote_trash(cwd));
        ui.set_local_count(count);
        ui.set_local_selected(selected);
        set_selection_flags(ui, pane, selection);
        clear_range_selection(ui, pane);
    } else {
        ui.set_remote_full(full);
        ui.set_remote_entries(visible);
        ui.set_remote_cwd(cwd.into());
        ui.set_remote_path_display(display_path(cwd).into());
        ui.set_right_in_remote_trash(cwd_is_remote_trash(cwd));
        ui.set_remote_count(count);
        ui.set_remote_selected(selected);
        set_selection_flags(ui, pane, selection);
        clear_range_selection(ui, pane);
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
            demo_entry(
                "report-Q3.pdf",
                false,
                "Jun 12 14:22",
                "2.4 MB",
                2_400_000,
                1,
            ),
            demo_entry(
                "invoice-8871.pdf",
                false,
                "Jun 09 09:10",
                "412 KB",
                412_000,
                2,
            ),
            demo_entry(
                "photo-archive.zip",
                false,
                "May 28 18:44",
                "58 MB",
                58_000_000,
                3,
            ),
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
            demo_entry(
                "backup-06-19.sql.gz",
                false,
                "Jun 19 03:00",
                "184 MB",
                184_000_000,
                3,
            ),
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
    ui.set_transfer_progress_text(fmt_transfer_progress(1_400_000u64, 2_400_000u64).into());
    ui.set_error("".into());
    ui.set_status("".into());
    refresh_sessions_model(ui, sessions);
    refresh_connections_model(ui, conns);
}

/// First-launch import: parse the a third-party file manager seed, store passwords, persist metadata.
fn initial_seed_import(store: &Arc<dyn CredentialStore>) -> Vec<ConnectionSpec> {
    for candidate in seed_candidates() {
        if let Ok(json) = read_bounded_regular_utf8(&candidate, MAX_IMPORT_BYTES) {
            tracing::info!(path = %candidate.display(), "importing connection seed");
            match store::load_seed(&json, store.as_ref()) {
                Ok(specs) => match store::save_metadata(&specs) {
                    Ok(()) => return specs,
                    Err(e) => tracing::warn!(error = %e, "seed metadata save failed"),
                },
                Err(e) => tracing::warn!(error = %e, "seed import failed"),
            }
        }
    }
    Vec::new()
}

fn read_bounded_regular_utf8(path: &Path, limit: u64) -> Result<String, String> {
    let before = std::fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if !before.file_type().is_file() || before.file_type().is_symlink() || before.len() > limit {
        return Err("not a bounded regular file".into());
    }
    let mut file = std::fs::File::open(path).map_err(|e| e.to_string())?;
    let opened = file.metadata().map_err(|e| e.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if before.dev() != opened.dev() || before.ino() != opened.ino() {
            return Err("file changed while opening".into());
        }
    }
    if !opened.file_type().is_file() || opened.len() > limit {
        return Err("file changed type or exceeds the size limit".into());
    }
    let mut bytes = Vec::with_capacity(opened.len() as usize);
    file.by_ref()
        .take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() as u64 > limit {
        return Err("file exceeds the size limit".into());
    }
    String::from_utf8(bytes).map_err(|_| "file is not valid UTF-8".into())
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
        let (uw, handle, store, panes, engine, idx) = (
            ui.as_weak(),
            handle.clone(),
            store.clone(),
            panes.clone(),
            engine.clone(),
            idx.clone(),
        );
        ui.window()
            .on_winit_window_event(move |slint_window, event| {
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
                        slint::winit_030::winit::event::WindowEvent::ThemeChanged(theme)
                            if store::settings::load().theme == "system" =>
                        {
                            crate::Tokens::get(&ui).set_theme(
                                match theme {
                                    slint::winit_030::winit::window::Theme::Dark => "dark",
                                    slint::winit_030::winit::window::Theme::Light => "light",
                                }
                                .into(),
                            );
                        }
                        slint::winit_030::winit::event::WindowEvent::HoveredFile(_) => {
                            let pane = slint_window
                                .with_winit_window(cursor_x_in_window)
                                .flatten()
                                .map(|x| {
                                    if x > 240.0 + ui.get_pane_split() as f64 + 24.0 {
                                        1
                                    } else {
                                        0
                                    }
                                })
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
                                .map(|x| {
                                    if x > 240.0 + ui.get_pane_split() as f64 + 24.0 {
                                        1
                                    } else {
                                        0
                                    }
                                })
                                .unwrap_or_else(|| ui.get_external_drop_pane().max(0) as usize);
                            ui.set_external_drop_active(false);
                            ui.set_external_drop_pane(-1);
                            receive_external_path(
                                &handle,
                                store.clone(),
                                panes.clone(),
                                engine.clone(),
                                idx.clone(),
                                ui.as_weak(),
                                pane.min(1),
                                path.clone(),
                            );
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
            let _ = ui
                .window()
                .with_winit_window(|window| window.set_minimized(true));
        }
    });

    let ui_weak = ui.as_weak();
    ui.on_toggle_window_fullscreen(move || {
        if let Some(ui) = ui_weak.upgrade() {
            let _ = ui.window().with_winit_window(|window| {
                if window.fullscreen().is_some() {
                    window.set_fullscreen(None);
                } else {
                    window.set_fullscreen(Some(
                        slint::winit_030::winit::window::Fullscreen::Borderless(None),
                    ));
                }
            });
        }
    });

    ui.on_close_window(move || {
        let _ = slint::quit_event_loop();
    });
}

fn wire_external_drag(ui: &App, handle: &Handle, store: Arc<dyn CredentialStore>, panes: Panes) {
    cleanup_abandoned_drag_roots_in(&std::env::temp_dir());
    let (uw, handle, panes) = (ui.as_weak(), handle.clone(), panes.clone());
    ui.on_start_external_drag(move |pane_name, row| {
        let Some(ui) = uw.upgrade() else { return };
        let Some(pane) = pane_alias_index(&ui, pane_name.as_str()) else {
            return;
        };
        let entry = if pane == 0 {
            ui.get_local_entries().row_data(row as usize)
        } else {
            ui.get_remote_entries().row_data(row as usize)
        };
        let Some(entry) = entry else { return };
        let state = panes.lock().ok().map(|p| p[pane].clone());
        let Some(state) = state else { return };
        let mut path = PathBuf::from(&state.cwd).join(entry.name.as_str());
        let mut staging_root = None;
        if matches!(state.kind, PaneKind::Remote) {
            let Some(spec) = state.conn else { return };
            let Some(password) = password_for(&store, &spec) else {
                return;
            };
            let remote = join_remote(PathBuf::from(&state.cwd).join(entry.name.as_str()));
            let expected_size = TRUE_SIZE
                .lock()
                .ok()
                .and_then(|sizes| sizes.get(&(pane, entry.name.to_string())).copied())
                .or((entry.size > 0).then_some(entry.size as u64));
            match materialize_remote_drag(
                &handle,
                &spec,
                &password,
                &remote,
                entry.name.as_str(),
                entry.is_dir,
                expected_size,
            ) {
                Ok(staged) => {
                    path = staged.path;
                    staging_root = Some(staged.root);
                }
                Err(e) => {
                    ui.set_error(format!("Could not prepare drag: {e}").into());
                    return;
                }
            };
        }
        let Ok(path) = std::fs::canonicalize(path) else {
            if let Some(root) = staging_root {
                let _ = std::fs::remove_dir_all(root);
            }
            return;
        };
        let image = drag_preview_image().unwrap_or_else(|| drag::Image::File(path.clone()));
        let cleanup_root = staging_root.clone();
        let started = ui.window().with_winit_window(|window| {
            drag::start_drag(
                window,
                drag::DragItem::Files(vec![path]),
                image,
                move |_, _| {
                    if let Some(root) = cleanup_root.as_ref() {
                        let _ = std::fs::remove_dir_all(root);
                    }
                },
                Default::default(),
            )
        });
        if !matches!(started, Some(Ok(()))) {
            if let Some(root) = staging_root {
                let _ = std::fs::remove_dir_all(root);
            }
            ui.set_error("Could not start external drag.".into());
        }
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
    let Some(name) = source
        .file_name()
        .and_then(|n| n.to_str())
        .map(str::to_owned)
    else {
        return;
    };
    let Some(state) = panes.lock().ok().map(|p| p[pane].clone()) else {
        return;
    };
    let is_dir = source.is_dir();
    match state.kind {
        PaneKind::Local => {
            let destination_dir = PathBuf::from(&state.cwd);
            let mut destination = destination_dir.join(&name);
            if destination == source {
                return;
            }
            if destination.exists() {
                match existing_file_policy() {
                    ExistingFilePolicy::Overwrite => {}
                    ExistingFilePolicy::KeepBoth => {
                        let mut taken = std::fs::read_dir(&destination_dir)
                            .ok()
                            .into_iter()
                            .flatten()
                            .filter_map(Result::ok)
                            .filter_map(|entry| entry.file_name().to_str().map(str::to_owned))
                            .collect::<HashSet<_>>();
                        destination =
                            destination_dir.join(unique_name_from_taken(&name, &mut taken));
                    }
                    ExistingFilePolicy::Skip => {
                        if let Some(ui) = ui.upgrade() {
                            ui.set_status(format!("Skipped existing item: {name}").into());
                        }
                        return;
                    }
                    ExistingFilePolicy::Ask => {
                        if let Some(ui) = ui.upgrade() {
                            ui.set_error(
                                "The dropped local item already exists. Use the in-app copy action to choose Overwrite or Keep Both."
                                    .into(),
                            );
                        }
                        return;
                    }
                }
            }
            let (h, st, pn, uw) = (handle.clone(), store, panes, ui.clone());
            if let Some(u) = ui.upgrade() {
                u.set_status(format!("Copying {name}...").into());
            }
            handle.spawn(async move {
                let result = tokio::task::spawn_blocking(move || {
                    if is_dir {
                        fs_copy_tree(&source, &destination)
                    } else {
                        copy_local_file(&source, &destination)
                    }
                })
                .await;
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(u) = uw.upgrade() {
                        match result {
                            Ok(Ok(count)) => {
                                u.set_status(format!("Copied {name} ({count} file(s))").into())
                            }
                            Ok(Err(e)) => u.set_error(format!("Could not copy {name}: {e}").into()),
                            Err(e) => u.set_error(format!("Could not copy {name}: {e}").into()),
                        }
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
            let Some(pw) = password_for(&store, &spec) else {
                set_err(&ui, "missing credential");
                return;
            };
            let (h, engine2, idx2, spec2, source2, name2, size2, ui2, store2) = (
                handle.clone(),
                engine.clone(),
                idx.clone(),
                spec.clone(),
                source.clone(),
                name.clone(),
                size,
                ui.clone(),
                store.clone(),
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
                let policy = existing_file_policy();
                let destination_name = if !exists || policy == ExistingFilePolicy::Overwrite {
                    Some(name2.clone())
                } else if policy == ExistingFilePolicy::KeepBoth {
                    Some(
                        unique_dest_name(
                            &name2,
                            &PaneKind::Remote,
                            Some(&spec2),
                            &remote_dir,
                            &store2,
                        )
                        .await,
                    )
                } else {
                    None
                };
                let _ = slint::invoke_from_event_loop(move || {
                    if exists && policy == ExistingFilePolicy::Ask {
                        // Queue this conflict; only open the dialog if none is already showing.
                        // A multi-file drop with several existing names is confirmed one at a time.
                        let show_now = match PENDING_EXTERNAL_UPLOAD.lock() {
                            Ok(mut g) => {
                                let show = g.is_empty();
                                g.push_back((
                                    spec2,
                                    source2,
                                    remote_dir,
                                    name2.clone(),
                                    size2,
                                    is_dir,
                                ));
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
                    } else if exists && policy == ExistingFilePolicy::Skip {
                        if let Some(u) = ui2.upgrade() {
                            u.set_status(format!("Skipped existing item: {name2}").into());
                        }
                    } else if let Some(destination_name) = destination_name {
                        let remote =
                            join_remote(PathBuf::from(&remote_dir).join(&destination_name));
                        if let Some(u) = ui2.upgrade() {
                            do_external_upload(
                                &h,
                                engine2,
                                idx2,
                                u.as_weak(),
                                spec2,
                                source2,
                                remote,
                                destination_name,
                                size2,
                                is_dir,
                            );
                        }
                    }
                });
            });
        }
    }
}

struct RemoteDragStaging {
    root: PathBuf,
    path: PathBuf,
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

    let current = conns.lock().expect("connections lock").clone();
    let mut candidate = current.clone();
    let Some(from_pos) = candidate.iter().position(|c| c.id.0 as i32 == id) else {
        return;
    };
    let item = candidate.remove(from_pos);

    let insert_pos = if let Some(before_id) = before_id {
        candidate
            .iter()
            .position(|c| c.id.0 as i32 == before_id)
            .unwrap_or(candidate.len())
    } else {
        filtered
            .iter()
            .rev()
            .find(|row| row.id != id)
            .and_then(|row| {
                candidate
                    .iter()
                    .position(|c| c.id.0 as i32 == row.id)
                    .map(|pos| pos + 1)
            })
            .unwrap_or(candidate.len())
    };

    let insert_pos = insert_pos.min(candidate.len());
    candidate.insert(insert_pos, item);

    if let Err(e) = store::save_metadata(&candidate) {
        ui.set_error(format!("Could not save server order: {e}").into());
        ui.set_status("".into());
        return;
    }
    *conns.lock().expect("connections lock") = candidate;
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
                || (demo
                    && &*row.label == "Backups"
                    && "production backups".contains(query.trim().to_lowercase().as_str()))
        })
        .map(|mut row| {
            if demo && &*row.label == "Backups" {
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

/// True i64 mtimes for the current pane views, keyed by (pane, name). Slint's `int` is i32, so
/// EntryRow.mtime truncates files dated after 2038-01-19; this sidecar carries the real i64 so the
/// date sort stays correct for future-dated files. Populated alongside TRUE_SIZE on re-list.
static TRUE_MTIME: LazyLock<Mutex<HashMap<(usize, String), i64>>> =
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
    INCREMENTAL_PANE_LISTINGS.with(|listings| listings.borrow_mut()[pane] = None);
    let empty = ModelRc::from(Rc::new(VecModel::from(Vec::<EntryRow>::new())));
    if let Ok(mut g) = TRUE_SIZE.lock() {
        g.retain(|(p, _), _| *p != pane);
    }
    if let Ok(mut g) = TRUE_MTIME.lock() {
        g.retain(|(p, _), _| *p != pane);
    }
    if pane == 0 {
        ui.set_local_full(empty.clone());
        ui.set_local_entries(empty);
        ui.set_local_count(0);
        ui.set_local_selected(-1);
        set_selection_flags(ui, pane, Vec::new());
        clear_range_selection(ui, pane);
        ui.set_local_cwd(cwd.into());
        ui.set_local_path_display(display_path(cwd).into());
        ui.set_left_in_remote_trash(cwd_is_remote_trash(cwd));
    } else {
        ui.set_remote_full(empty.clone());
        ui.set_remote_entries(empty);
        ui.set_remote_count(0);
        ui.set_remote_selected(-1);
        set_selection_flags(ui, pane, Vec::new());
        clear_range_selection(ui, pane);
        ui.set_remote_cwd(cwd.into());
        ui.set_remote_path_display(display_path(cwd).into());
        ui.set_right_in_remote_trash(cwd_is_remote_trash(cwd));
    }
    refresh_selected_path(ui);
}

fn begin_incremental_pane_listing(ui: &App, pane: usize, cwd: &str, generation: u64) {
    clear_pane_view(ui, pane, cwd);
    let full = Rc::new(VecModel::from(Vec::<EntryRow>::new()));
    let visible = Rc::new(VecModel::from(Vec::<EntryRow>::new()));
    let selection = Rc::new(VecModel::from(Vec::<bool>::new()));
    if pane == 0 {
        ui.set_local_full(ModelRc::from(full.clone()));
        ui.set_local_entries(ModelRc::from(visible.clone()));
        ui.set_local_selection(ModelRc::from(selection.clone()));
        ui.set_local_all_selected(false);
    } else {
        ui.set_remote_full(ModelRc::from(full.clone()));
        ui.set_remote_entries(ModelRc::from(visible.clone()));
        ui.set_remote_selection(ModelRc::from(selection.clone()));
        ui.set_remote_all_selected(false);
    }
    INCREMENTAL_PANE_LISTINGS.with(|listings| {
        listings.borrow_mut()[pane] = Some(IncrementalPaneListing {
            generation,
            full,
            visible,
            selection,
        });
    });
}

fn append_incremental_pane_entries(
    ui: &App,
    pane: usize,
    generation: u64,
    entries: Vec<RemoteEntry>,
    background_metadata: bool,
) {
    let rows = entries
        .into_iter()
        .map(|entry| {
            let mtime = entry.mtime.unwrap_or(0);
            let row = EntryRow {
                name: entry.name.clone().into(),
                is_dir: entry.is_dir,
                size: entry.size as i32,
                mtime: mtime as i32,
                date: fmt_date(mtime).into(),
                size_text: fmt_size(entry.size).into(),
                permissions: fmt_permissions(entry.permissions).into(),
                owner: entry.owner.unwrap_or_default().into(),
                group: entry.group.unwrap_or_default().into(),
                metadata_state: if entry.is_dir {
                    if background_metadata {
                        "loading"
                    } else {
                        "on_demand"
                    }
                } else {
                    "ready"
                }
                .into(),
            };
            (row, entry.name, entry.size, mtime)
        })
        .collect();
    append_incremental_pane_rows(ui, pane, generation, rows);
}

fn append_incremental_pane_rows(
    ui: &App,
    pane: usize,
    generation: u64,
    rows: Vec<(EntryRow, String, u64, i64)>,
) {
    let show_hidden = ui.get_show_hidden();
    let file_filter = pane_file_filter(ui, pane);
    let mut visible_count = None;
    let mut sizes = TRUE_SIZE.lock().ok();
    let mut mtimes = TRUE_MTIME.lock().ok();
    INCREMENTAL_PANE_LISTINGS.with(|listings| {
        let mut listings = listings.borrow_mut();
        let Some(listing) = listings[pane].as_mut() else {
            return;
        };
        if listing.generation != generation {
            return;
        }
        for (row, name, size, mtime) in rows {
            listing.full.push(row.clone());
            if (show_hidden || !name.starts_with('.')) && entry_matches_filter(&row, &file_filter) {
                listing.visible.push(row);
                listing.selection.push(false);
            }
            if let Some(sizes) = sizes.as_mut() {
                sizes.insert((pane, name.clone()), size);
            }
            if let Some(mtimes) = mtimes.as_mut() {
                mtimes.insert((pane, name), mtime);
            }
        }
        visible_count = Some(listing.visible.row_count() as i32);
    });
    if let Some(count) = visible_count {
        if pane == 0 {
            ui.set_local_count(count);
        } else {
            ui.set_remote_count(count);
        }
        // The first batch replaces the blocking placeholder with usable rows. Navigation stays
        // enabled so opening another folder immediately cancels the in-flight listing.
        set_pane_loading(ui, pane, false);
        ui.set_status(format!("Loading directory… {count} entries").into());
    }
}

fn finish_incremental_pane_listing(pane: usize, generation: u64) {
    INCREMENTAL_PANE_LISTINGS.with(|listings| {
        let mut listings = listings.borrow_mut();
        if listings[pane]
            .as_ref()
            .is_some_and(|listing| listing.generation == generation)
        {
            listings[pane] = None;
        }
    });
}

fn set_true_meta(pane: usize, items: &[(String, u64, i64)]) {
    if let (Ok(mut sz), Ok(mut mt)) = (TRUE_SIZE.lock(), TRUE_MTIME.lock()) {
        sz.retain(|(p, _), _| *p != pane);
        mt.retain(|(p, _), _| *p != pane);
        for (n, s, m) in items {
            sz.insert((pane, n.clone()), *s);
            mt.insert((pane, n.clone()), *m);
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
    let Ok(read) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in read.flatten() {
        if stats.truncated {
            break;
        }
        let path = entry.path();
        let Ok(md) = std::fs::symlink_metadata(&path) else {
            continue;
        };
        if md.file_type().is_symlink() {
            continue;
        }
        if md.is_dir() {
            local_folder_stats_inner(&path, max_files, stats, visited);
        } else {
            stats.size = stats.size.saturating_add(md.len());
            stats.files_scanned += 1;
            if let Ok(modified) = md.modified() {
                if let Ok(d) = modified.duration_since(std::time::UNIX_EPOCH) {
                    let mtime = d.as_secs() as i64;
                    stats.newest_mtime =
                        Some(stats.newest_mtime.map_or(mtime, |cur| cur.max(mtime)));
                }
            }
            if max_files > 0 && stats.files_scanned >= max_files {
                stats.truncated = true;
            }
        }
    }
}

fn local_folder_stats_cached(root: &Path, max_files: usize) -> FolderStats {
    let root_modified = std::fs::metadata(root)
        .and_then(|metadata| metadata.modified())
        .ok();
    let key = (root.to_path_buf(), max_files);
    let now = Instant::now();

    let value = match LOCAL_FOLDER_STATS_CACHE.lock() {
        Ok(mut cache) => {
            cache.retain(|_, slot| {
                slot.value.get().is_none_or(|cached| {
                    now.saturating_duration_since(cached.cached_at) <= LOCAL_FOLDER_STATS_CACHE_TTL
                })
            });

            let reusable = cache.get(&key).filter(|slot| {
                slot.root_modified == root_modified
                    && slot.value.get().is_none_or(|cached| {
                        now.saturating_duration_since(cached.cached_at)
                            <= LOCAL_FOLDER_STATS_CACHE_TTL
                    })
            });
            if let Some(slot) = reusable {
                slot.value.clone()
            } else {
                if cache.len() >= MAX_LOCAL_FOLDER_STATS_CACHE_ENTRIES {
                    let oldest = cache
                        .iter()
                        .filter_map(|(key, slot)| {
                            slot.value
                                .get()
                                .map(|cached| (key.clone(), cached.cached_at))
                        })
                        .min_by_key(|(_, cached_at)| *cached_at)
                        .map(|(key, _)| key);
                    if let Some(oldest) = oldest {
                        cache.remove(&oldest);
                    }
                }
                let value = Arc::new(OnceLock::new());
                cache.insert(
                    key,
                    LocalFolderStatsCacheSlot {
                        root_modified,
                        value: value.clone(),
                    },
                );
                value
            }
        }
        // A poisoned performance cache must never make directory listing unavailable.
        Err(_) => return local_folder_stats(root, max_files),
    };

    value
        .get_or_init(|| CachedLocalFolderStats {
            stats: local_folder_stats(root, max_files),
            cached_at: Instant::now(),
        })
        .stats
}

#[derive(Debug)]
struct LocalFolderEnrichment {
    name: String,
    path: PathBuf,
    own_mtime: i64,
}

struct LocalPaneSnapshot {
    rows: Vec<EntryRow>,
    meta: Vec<(String, u64, i64)>,
    folders: Vec<LocalFolderEnrichment>,
}

type IncrementalLocalRow = (EntryRow, String, u64, i64);

/// Read only the immediate directory. Recursive folder sizes are deliberately excluded so the
/// UI can render the listing before any tree walk starts.
fn local_pane_snapshot(
    path: &Path,
    background_metadata: bool,
    mut cancelled: impl FnMut() -> bool,
    mut on_batch: impl FnMut(Vec<IncrementalLocalRow>) -> bool,
) -> std::io::Result<Option<LocalPaneSnapshot>> {
    const LOCAL_LISTING_BATCH_ENTRIES: usize = 256;
    let read = std::fs::read_dir(path)?;
    let mut rows = Vec::new();
    let mut meta = Vec::new();
    let mut folders = Vec::new();
    let mut pending = Vec::with_capacity(LOCAL_LISTING_BATCH_ENTRIES);

    for entry in read.flatten() {
        if cancelled() {
            return Ok(None);
        }
        let name = entry.file_name().to_string_lossy().to_string();
        let is_symlink = entry
            .file_type()
            .map(|file_type| file_type.is_symlink())
            .unwrap_or(false);
        let Ok(metadata) = entry.metadata() else {
            continue;
        };
        let is_dir = metadata.is_dir();
        let size = if is_dir { 0 } else { metadata.len() };
        let mtime = metadata
            .modified()
            .ok()
            .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|duration| duration.as_secs() as i64)
            .unwrap_or(0);

        #[cfg(unix)]
        let (permissions, owner, group) = {
            use std::os::unix::fs::MetadataExt;
            (
                fmt_permissions(Some(metadata.mode() & 0o7777)),
                metadata.uid().to_string(),
                metadata.gid().to_string(),
            )
        };
        #[cfg(not(unix))]
        let (permissions, owner, group) = (String::new(), String::new(), String::new());

        let row = EntryRow {
            name: name.clone().into(),
            is_dir,
            size: size as i32,
            mtime: mtime as i32,
            date: fmt_date(mtime).into(),
            size_text: fmt_size(size).into(),
            permissions: permissions.into(),
            owner: owner.into(),
            group: group.into(),
            metadata_state: if is_dir && is_symlink {
                "unavailable"
            } else if is_dir {
                if background_metadata {
                    "loading"
                } else {
                    "on_demand"
                }
            } else {
                "ready"
            }
            .into(),
        };
        pending.push((row.clone(), name.clone(), size, mtime));
        rows.push(row);
        meta.push((name.clone(), size, mtime));
        if is_dir && !is_symlink {
            folders.push(LocalFolderEnrichment {
                name,
                path: entry.path(),
                own_mtime: mtime,
            });
        }
        if pending.len() >= LOCAL_LISTING_BATCH_ENTRIES && !on_batch(std::mem::take(&mut pending)) {
            return Ok(None);
        }
    }
    if !pending.is_empty() && !on_batch(pending) {
        return Ok(None);
    }

    Ok(Some(LocalPaneSnapshot {
        rows,
        meta,
        folders,
    }))
}

fn local_pane_request_is_current(ui: &App, pane: usize, cwd: &str, generation: u64) -> bool {
    if LOCAL_LIST_GENERATION[pane].load(AtomicOrdering::Relaxed) != generation {
        return false;
    }
    let current_cwd = if pane == 0 {
        ui.get_local_cwd()
    } else {
        ui.get_remote_cwd()
    };
    current_cwd.as_str() == cwd
}

fn list_local_pane(ui: &App, pane: usize, path: &Path, cwd: &str) {
    // A local listing replaces and cancels any FTP/SFTP listing still running in this pane.
    REMOTE_LIST_GENERATION[pane].fetch_add(1, AtomicOrdering::Relaxed);
    let generation = LOCAL_LIST_GENERATION[pane]
        .fetch_add(1, AtomicOrdering::Relaxed)
        .wrapping_add(1);
    let background_metadata = store::settings::load().background_folder_metadata;
    set_pane_loading(ui, pane, true);
    begin_incremental_pane_listing(ui, pane, cwd, generation);
    let ui_weak = ui.as_weak();
    let path = path.to_path_buf();
    let cwd = cwd.to_string();
    let spawn = std::thread::Builder::new()
        .name(format!("local-listing-{pane}"))
        .spawn(move || {
            let started = Instant::now();
            let callback_ui = ui_weak.clone();
            let callback_cwd = cwd.clone();
            let on_batch = move |rows: Vec<IncrementalLocalRow>| {
                if LOCAL_LIST_GENERATION[pane].load(AtomicOrdering::Relaxed) != generation {
                    return false;
                }
                let request_ui = callback_ui.clone();
                let request_cwd = callback_cwd.clone();
                slint::invoke_from_event_loop(move || {
                    let Some(ui) = request_ui.upgrade() else {
                        return;
                    };
                    if local_pane_request_is_current(&ui, pane, &request_cwd, generation) {
                        append_incremental_pane_rows(&ui, pane, generation, rows);
                    }
                })
                .is_ok()
            };
            let snapshot = match local_pane_snapshot(
                &path,
                background_metadata,
                || LOCAL_LIST_GENERATION[pane].load(AtomicOrdering::Relaxed) != generation,
                on_batch,
            ) {
                Ok(Some(snapshot)) => snapshot,
                Ok(None) => return,
                Err(error) => {
                    let request_ui = ui_weak.clone();
                    let request_cwd = cwd.clone();
                    let _ = slint::invoke_from_event_loop(move || {
                        let Some(ui) = request_ui.upgrade() else {
                            return;
                        };
                        if !local_pane_request_is_current(&ui, pane, &request_cwd, generation) {
                            return;
                        }
                        finish_incremental_pane_listing(pane, generation);
                        set_pane_loading(&ui, pane, false);
                        ui.set_error(format!("local: {error}").into());
                        set_true_meta(pane, &[]);
                        set_pane_full(&ui, pane, Vec::new(), &request_cwd);
                    });
                    return;
                }
            };
            let LocalPaneSnapshot {
                rows,
                meta,
                folders,
            } = snapshot;
            let entry_count = rows.len();
            let folder_count = folders.len();
            let request_ui = ui_weak.clone();
            let request_cwd = cwd.clone();
            let _ = slint::invoke_from_event_loop(move || {
                let Some(ui) = request_ui.upgrade() else {
                    return;
                };
                if !local_pane_request_is_current(&ui, pane, &request_cwd, generation) {
                    return;
                }
                finish_incremental_pane_listing(pane, generation);
                set_pane_loading(&ui, pane, false);
                ui.set_error("".into());
                ui.set_status("".into());
                set_true_meta(pane, &meta);
                set_pane_full(&ui, pane, rows, &request_cwd);
            });
            tracing::debug!(
                target: "gmacftp",
                pane,
                entries = entry_count,
                folders = folder_count,
                elapsed_ms = started.elapsed().as_millis(),
                "local directory listed without recursive metadata"
            );

            if folders.is_empty() || !background_metadata {
                return;
            }
            let enrichment_started = Instant::now();
            for folder in folders {
                if LOCAL_LIST_GENERATION[pane].load(AtomicOrdering::Relaxed) != generation {
                    return;
                }
                let _permit = loop {
                    if LOCAL_LIST_GENERATION[pane].load(AtomicOrdering::Relaxed) != generation {
                        return;
                    }
                    if let Some(permit) = RecursiveMetadataPermit::try_acquire() {
                        break permit;
                    }
                    std::thread::sleep(Duration::from_millis(20));
                };
                let stats = local_folder_stats_cached(&folder.path, MAX_LOCAL_FOLDER_STAT_FILES);
                let entry = RemoteEntry {
                    name: folder.name,
                    is_dir: true,
                    size: stats.size,
                    mtime: stats.newest_mtime.or(Some(folder.own_mtime)),
                    permissions: None,
                    owner: None,
                    group: None,
                };
                let request_ui = ui_weak.clone();
                let request_cwd = cwd.clone();
                let _ = slint::invoke_from_event_loop(move || {
                    let Some(ui) = request_ui.upgrade() else {
                        return;
                    };
                    if !local_pane_request_is_current(&ui, pane, &request_cwd, generation) {
                        return;
                    }
                    update_pane_entry_metadata(&ui, pane, &entry, stats.truncated, "ready");
                });
            }
            tracing::debug!(
                target: "gmacftp",
                pane,
                elapsed_ms = enrichment_started.elapsed().as_millis(),
                "local folder metadata enriched"
            );
        });
    if let Err(error) = spawn {
        finish_incremental_pane_listing(pane, generation);
        set_pane_loading(ui, pane, false);
        ui.set_error(format!("local listing worker: {error}").into());
    }
}

fn set_pane_entries(
    ui: &App,
    pane: usize,
    entries: &[RemoteEntry],
    cwd: &str,
    partials: &HashMap<String, bool>,
    metadata_states: &HashMap<String, &'static str>,
) {
    let rows: Vec<EntryRow> = entries
        .iter()
        .map(|e| {
            let mtime = e.mtime.unwrap_or(0);
            let partial = partials.get(&e.name).copied().unwrap_or(false);
            EntryRow {
                name: e.name.clone().into(),
                is_dir: e.is_dir,
                size: e.size as i32,
                mtime: mtime as i32,
                date: fmt_date(mtime).into(),
                size_text: fmt_size_partial(e.size, partial).into(),
                permissions: fmt_permissions(e.permissions).into(),
                owner: e.owner.clone().unwrap_or_default().into(),
                group: e.group.clone().unwrap_or_default().into(),
                metadata_state: metadata_states
                    .get(&e.name)
                    .copied()
                    .unwrap_or("ready")
                    .into(),
            }
        })
        .collect();
    let meta = entries
        .iter()
        .map(|e| (e.name.clone(), e.size, e.mtime.unwrap_or(0)))
        .collect::<Vec<_>>();
    set_true_meta(pane, &meta);
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

    if let Ok(mut sizes) = TRUE_SIZE.lock() {
        sizes.insert((pane, entry.name.clone()), entry.size);
    }
    if let Ok(mut mtimes) = TRUE_MTIME.lock() {
        mtimes.insert((pane, entry.name.clone()), entry.mtime.unwrap_or(0));
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
                .map(|candidate| candidate.name.as_str() == entry.name)
                .unwrap_or(false)
        }) {
            let Some(current) = model.row_data(index) else {
                continue;
            };
            let row = EntryRow {
                name: entry.name.clone().into(),
                is_dir: entry.is_dir,
                size: entry.size as i32,
                mtime: mtime as i32,
                date: fmt_date(mtime).into(),
                size_text: fmt_size_partial(entry.size, partial).into(),
                permissions: entry
                    .permissions
                    .map(|mode| fmt_permissions(Some(mode)).into())
                    .unwrap_or(current.permissions),
                owner: entry
                    .owner
                    .as_deref()
                    .map(Into::into)
                    .unwrap_or(current.owner),
                group: entry
                    .group
                    .as_deref()
                    .map(Into::into)
                    .unwrap_or(current.group),
                metadata_state: metadata_state.into(),
            };
            model.set_row_data(index, row.clone());
        }
    }
}

fn set_pane_entry_metadata_state(ui: &App, pane: usize, name: &str, state: &'static str) {
    let models = if pane == 0 {
        [ui.get_local_full(), ui.get_local_entries()]
    } else {
        [ui.get_remote_full(), ui.get_remote_entries()]
    };
    for model in models {
        if let Some(index) = (0..model.row_count()).find(|&index| {
            model
                .row_data(index)
                .is_some_and(|candidate| candidate.name.as_str() == name)
        }) {
            if let Some(mut row) = model.row_data(index) {
                row.metadata_state = state.into();
                model.set_row_data(index, row);
            }
        }
    }
}

fn existing_entry_mtime(pane: usize, name: &str) -> Option<i64> {
    TRUE_MTIME
        .lock()
        .ok()
        .and_then(|mtimes| mtimes.get(&(pane, name.to_string())).copied())
}

fn remote_pane_request_is_current(
    panes: &Panes,
    pane: usize,
    connection_id: ConnectionId,
    cwd: &str,
) -> bool {
    let Ok(panes) = panes.lock() else {
        return false;
    };
    let Some(state) = panes.get(pane) else {
        return false;
    };
    matches!(state.kind, PaneKind::Remote)
        && state.conn.as_ref().map(|conn| conn.id) == Some(connection_id)
        && state.cwd == cwd
}

fn remote_pane_listing_request_is_current(
    panes: &Panes,
    pane: usize,
    connection_id: ConnectionId,
    cwd: &str,
    generation: u64,
) -> bool {
    REMOTE_LIST_GENERATION[pane].load(AtomicOrdering::Relaxed) == generation
        && remote_pane_request_is_current(panes, pane, connection_id, cwd)
}

fn pane_request_is_current(
    panes: &Panes,
    pane: usize,
    remote: bool,
    connection_id: Option<ConnectionId>,
    cwd: &str,
) -> bool {
    let Ok(panes) = panes.lock() else {
        return false;
    };
    let Some(state) = panes.get(pane) else {
        return false;
    };
    let kind_matches = matches!(state.kind, PaneKind::Remote) == remote;
    kind_matches
        && state.cwd == cwd
        && (!remote || state.conn.as_ref().map(|connection| connection.id) == connection_id)
}

fn cached_remote_folder_stats(
    connection_id: ConnectionId,
    path: &str,
    max_files: usize,
) -> Option<net::RemoteTreeStats> {
    let now = Instant::now();
    let mut cache = REMOTE_FOLDER_STATS_CACHE.lock().ok()?;
    cache.retain(|_, cached| {
        now.saturating_duration_since(cached.cached_at) <= REMOTE_FOLDER_STATS_CACHE_TTL
    });
    cache
        .get(&(connection_id.0, path.to_string(), max_files))
        .map(|cached| cached.stats.clone())
}

fn store_remote_folder_stats(
    connection_id: ConnectionId,
    path: String,
    max_files: usize,
    stats: &net::RemoteTreeStats,
) {
    let Ok(mut cache) = REMOTE_FOLDER_STATS_CACHE.lock() else {
        return;
    };
    if cache.len() >= MAX_REMOTE_FOLDER_STATS_CACHE_ENTRIES {
        if let Some(oldest) = cache
            .iter()
            .min_by_key(|(_, cached)| cached.cached_at)
            .map(|(key, _)| key.clone())
        {
            cache.remove(&oldest);
        }
    }
    cache.insert(
        (connection_id.0, path, max_files),
        CachedRemoteFolderStats {
            stats: stats.clone(),
            cached_at: Instant::now(),
        },
    );
}

/// Re-list a pane at its current cwd (Local → fs read; Remote → connect + list, per-op).
fn refresh_pane(
    handle: &Handle,
    store: Arc<dyn CredentialStore>,
    panes: Panes,
    ui: Weak<App>,
    pane: usize,
) {
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
            let _ = ui.upgrade().map(|ui| {
                set_pane_loading(&ui, pane, false);
                list_local_pane(&ui, pane, Path::new(&cwd), &cwd);
            });
        }
        PaneKind::Remote => {
            let Some(spec) = conn else { return };
            // A remote listing replaces any local listing/enrichment still running in this pane.
            LOCAL_LIST_GENERATION[pane].fetch_add(1, AtomicOrdering::Relaxed);
            let generation = REMOTE_LIST_GENERATION[pane]
                .fetch_add(1, AtomicOrdering::Relaxed)
                .wrapping_add(1);
            let _ = ui.upgrade().map(|ui| {
                set_pane_loading(&ui, pane, true);
                begin_incremental_pane_listing(&ui, pane, &cwd, generation);
            });
            let Some(password) = password_for(&store, &spec) else {
                let _ = ui.upgrade().map(|ui| {
                    finish_incremental_pane_listing(pane, generation);
                    set_pane_loading(&ui, pane, false);
                });
                set_err(&ui, "missing credential");
                return;
            };
            let background_metadata = store::settings::load().background_folder_metadata;
            handle.spawn(async move {
                let mut s = spec.clone();
                s.initial_path = cwd.clone();
                let started = Instant::now();
                let callback_panes = panes.clone();
                let callback_ui = ui.clone();
                let callback_cwd = cwd.clone();
                let connection_id = spec.id;
                let on_batch = move |entries: Vec<RemoteEntry>| {
                    if !remote_pane_listing_request_is_current(
                        &callback_panes,
                        pane,
                        connection_id,
                        &callback_cwd,
                        generation,
                    ) {
                        return false;
                    }
                    let request_panes = callback_panes.clone();
                    let request_ui = callback_ui.clone();
                    let request_cwd = callback_cwd.clone();
                    slint::invoke_from_event_loop(move || {
                        if !remote_pane_listing_request_is_current(
                            &request_panes,
                            pane,
                            connection_id,
                            &request_cwd,
                            generation,
                        ) {
                            return;
                        }
                        if let Some(ui) = request_ui.upgrade() {
                            append_incremental_pane_entries(
                                &ui,
                                pane,
                                generation,
                                entries,
                                background_metadata,
                            );
                        }
                    })
                    .is_ok()
                };
                let (entries, plaintext) =
                    match net::connect_and_list_incremental(&s, &password, on_batch).await {
                        Ok(t) => t,
                        Err(net::NetError::Cancelled) => return,
                        Err(net::NetError::HostKeyTrustRequired(challenge)) => {
                            let request_panes = panes.clone();
                            let request_ui = ui.clone();
                            let request_cwd = cwd.clone();
                            let connection_id = spec.id;
                            let _ = slint::invoke_from_event_loop(move || {
                                if !remote_pane_listing_request_is_current(
                                    &request_panes,
                                    pane,
                                    connection_id,
                                    &request_cwd,
                                    generation,
                                ) {
                                    return;
                                }
                                let Some(ui) = request_ui.upgrade() else {
                                    return;
                                };
                                if let Ok(mut pending) = PENDING_HOST_KEY_TRUST.lock() {
                                    *pending = Some((challenge.clone(), pane));
                                }
                                finish_incremental_pane_listing(pane, generation);
                                set_pane_loading(&ui, pane, false);
                                ui.set_host_key_endpoint(challenge.endpoint().into());
                                ui.set_host_key_fingerprint(challenge.fingerprint().into());
                                ui.set_host_key_open(true);
                            });
                            return;
                        }
                        Err(net::NetError::TlsCertificateTrustRequired(challenge)) => {
                            let request_panes = panes.clone();
                            let request_ui = ui.clone();
                            let request_cwd = cwd.clone();
                            let connection_id = spec.id;
                            let _ = slint::invoke_from_event_loop(move || {
                                if !remote_pane_listing_request_is_current(
                                    &request_panes,
                                    pane,
                                    connection_id,
                                    &request_cwd,
                                    generation,
                                ) {
                                    return;
                                }
                                let Some(ui) = request_ui.upgrade() else {
                                    return;
                                };
                                if let Ok(mut pending) = PENDING_TLS_CERTIFICATE_TRUST.lock() {
                                    *pending = Some((challenge.clone(), pane));
                                }
                                finish_incremental_pane_listing(pane, generation);
                                set_pane_loading(&ui, pane, false);
                                ui.set_tls_cert_endpoint(challenge.endpoint().into());
                                ui.set_tls_cert_fingerprint(challenge.fingerprint().into());
                                ui.set_tls_cert_previous(
                                    challenge.previous_fingerprint().unwrap_or("").into(),
                                );
                                ui.set_tls_cert_open(true);
                            });
                            return;
                        }
                        Err(e) => {
                            let request_panes = panes.clone();
                            let request_ui = ui.clone();
                            let request_cwd = cwd.clone();
                            let connection_id = spec.id;
                            let _ = slint::invoke_from_event_loop(move || {
                                if !remote_pane_listing_request_is_current(
                                    &request_panes,
                                    pane,
                                    connection_id,
                                    &request_cwd,
                                    generation,
                                ) {
                                    return;
                                }
                                let Some(ui) = request_ui.upgrade() else {
                                    return;
                                };
                                finish_incremental_pane_listing(pane, generation);
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
                    .map(|entry| {
                        (
                            entry.name.clone(),
                            if background_metadata {
                                "loading"
                            } else {
                                "on_demand"
                            },
                        )
                    })
                    .collect::<HashMap<_, _>>();
                let request_panes = panes.clone();
                let request_ui = ui.clone();
                let request_cwd = cwd.clone();
                let connection_id = spec.id;
                let _ = slint::invoke_from_event_loop(move || {
                    if !remote_pane_listing_request_is_current(
                        &request_panes,
                        pane,
                        connection_id,
                        &request_cwd,
                        generation,
                    ) {
                        return;
                    }
                    let Some(ui) = request_ui.upgrade() else {
                        return;
                    };
                    finish_incremental_pane_listing(pane, generation);
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
                    // Plain FTP is possible only when the user explicitly enabled it for this
                    // saved legacy connection. Surface that safety-critical state; on FTPS clear
                    // any stale warning left by an earlier connect (status is global).
                    if plaintext {
                        ui.set_status(
                            "Connected via plaintext FTP — password was sent unencrypted.".into(),
                        );
                    } else {
                        ui.set_status("".into());
                    }
                });

                if !background_metadata {
                    return;
                }

                // Give navigation and transfers priority. If the user opens another directory
                // during this short idle window, no recursive metadata connections are started.
                tokio::time::sleep(REMOTE_METADATA_IDLE_DELAY).await;
                if !remote_pane_listing_request_is_current(&panes, pane, spec.id, &cwd, generation)
                {
                    return;
                }

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
                    let panes = panes.clone();
                    let cwd = cwd.clone();
                    async move {
                        if !remote_pane_listing_request_is_current(
                            &panes, pane, spec.id, &cwd, generation,
                        ) {
                            return (index, remote_path, None);
                        }
                        if let Some(stats) = cached_remote_folder_stats(
                            spec.id,
                            &remote_path,
                            MAX_REMOTE_FOLDER_STAT_FILES,
                        ) {
                            return (index, remote_path, Some(Ok(Ok(stats))));
                        }
                        let _permit = loop {
                            if !remote_pane_listing_request_is_current(
                                &panes, pane, spec.id, &cwd, generation,
                            ) {
                                return (index, remote_path, None);
                            }
                            if let Some(permit) = RecursiveMetadataPermit::try_acquire() {
                                break permit;
                            }
                            tokio::time::sleep(Duration::from_millis(20)).await;
                        };
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
                        if let Ok(Ok(stats)) = &result {
                            store_remote_folder_stats(
                                spec.id,
                                remote_path.clone(),
                                MAX_REMOTE_FOLDER_STAT_FILES,
                                stats,
                            );
                        }
                        (index, remote_path, Some(result))
                    }
                }))
                .buffer_unordered(REMOTE_METADATA_CONCURRENCY);
                tokio::pin!(tasks);
                let mut entries = entries;
                while let Some((index, remote_path, result)) = tasks.next().await {
                    let Some(result) = result else {
                        continue;
                    };
                    if !remote_pane_listing_request_is_current(
                        &panes, pane, spec.id, &cwd, generation,
                    ) {
                        return;
                    }
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

                    let Some(updated_entry) = entries.get(index).cloned() else {
                        continue;
                    };
                    let request_panes = panes.clone();
                    let request_ui = ui.clone();
                    let request_cwd = cwd.clone();
                    let connection_id = spec.id;
                    let _ = slint::invoke_from_event_loop(move || {
                        if !remote_pane_listing_request_is_current(
                            &request_panes,
                            pane,
                            connection_id,
                            &request_cwd,
                            generation,
                        ) {
                            return;
                        }
                        let Some(ui) = request_ui.upgrade() else {
                            return;
                        };
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
fn refresh_both_panes(
    handle: &Handle,
    store: Arc<dyn CredentialStore>,
    panes: Panes,
    ui: Weak<App>,
) {
    refresh_pane(handle, store.clone(), panes.clone(), ui.clone(), 0);
    refresh_pane(handle, store, panes, ui, 1);
}

const REMOTE_QUARANTINE_DIR: &str = ".gmacftp-trash";

fn remote_quarantine_available(cwd: &str, name: &str) -> bool {
    name != REMOTE_QUARANTINE_DIR
        && !cwd
            .split('/')
            .any(|component| component == REMOTE_QUARANTINE_DIR)
}

fn remote_quarantine_destination(
    cwd: &str,
    name: &str,
    token: u128,
) -> Result<(String, String, String, String), String> {
    validated_remote_path(cwd)?;
    net::validate_remote_component(name).map_err(|error| error.to_string())?;
    if !remote_quarantine_available(cwd, name) {
        return Err("Items already in Remote Trash require an explicit permanent delete.".into());
    }
    let suffix = format!(".deleted-{token:032x}");
    let prefix = truncate_utf8_bytes(name, 255usize.saturating_sub(suffix.len()));
    let bucket_name = format!("{prefix}{suffix}");
    net::validate_remote_component(&bucket_name).map_err(|error| error.to_string())?;
    let trash_root = join_remote(PathBuf::from(cwd).join(REMOTE_QUARANTINE_DIR));
    let bucket = join_remote(PathBuf::from(&trash_root).join(&bucket_name));
    // The original component lives inside a unique bucket, so its complete name is retained even
    // when it already consumes NAME_MAX. The bucket is the collision-resistant metadata envelope.
    let destination = join_remote(PathBuf::from(&bucket).join(name));
    Ok((trash_root, bucket, destination, bucket_name))
}

fn remote_quarantine_bucket_name(name: &str) -> bool {
    let Some((prefix, token)) = name.rsplit_once(".deleted-") else {
        return false;
    };
    !prefix.is_empty()
        && token.len() == 32
        && token
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn remote_quarantine_restore_context(cwd: &str) -> Result<(String, String, String), String> {
    let cwd = validated_remote_path(cwd)?;
    let components = cwd
        .split('/')
        .filter(|component| !component.is_empty())
        .collect::<Vec<_>>();
    if components.len() < 2
        || components[components.len() - 2] != REMOTE_QUARANTINE_DIR
        || !remote_quarantine_bucket_name(components[components.len() - 1])
    {
        return Err("Open a quarantined item bucket before restoring it.".into());
    }
    let trash_root = format!("/{}", components[..components.len() - 1].join("/"));
    let original_parent = if components.len() == 2 {
        "/".to_string()
    } else {
        format!("/{}", components[..components.len() - 2].join("/"))
    };
    Ok((trash_root, original_parent, cwd))
}

/// Move a remote entry into a hidden sibling quarantine. Every failure is returned to the caller;
/// this function deliberately has no permanent-delete fallback.
async fn quarantine_remote(
    spec: &ConnectionSpec,
    password: &str,
    cwd: &str,
    name: &str,
) -> Result<String, String> {
    let (trash_root, _, _, _) = remote_quarantine_destination(cwd, name, rand::random())?;
    match net::remote_exists(spec, password, cwd, REMOTE_QUARANTINE_DIR).await {
        Ok(false) => {
            if let Err(create_error) = net::create_remote_dir(spec, password, &trash_root).await {
                // A second client may have won the mkdir race. Continue only after a fresh,
                // authoritative listing proves the quarantine directory now exists.
                match net::remote_exists(spec, password, cwd, REMOTE_QUARANTINE_DIR).await {
                    Ok(true) => {}
                    Ok(false) | Err(_) => {
                        return Err(format!(
                            "could not create Remote Trash; nothing was deleted: {create_error}"
                        ));
                    }
                }
            }
        }
        Ok(true) => {}
        Err(error) => {
            return Err(format!(
                "could not verify Remote Trash; nothing was deleted: {error}"
            ));
        }
    }

    let source = join_remote(PathBuf::from(cwd).join(name));
    for _ in 0..8 {
        let (_, bucket, destination, bucket_name) =
            remote_quarantine_destination(cwd, name, rand::random())?;
        match net::remote_exists(spec, password, &trash_root, &bucket_name).await {
            Ok(true) => continue,
            Ok(false) => {
                match net::create_remote_dir(spec, password, &bucket).await {
                    Ok(()) => {}
                    Err(create_error) => {
                        if net::remote_exists(spec, password, &trash_root, &bucket_name)
                            .await
                            .unwrap_or(false)
                        {
                            continue;
                        }
                        return Err(format!(
                            "could not create a Remote Trash bucket; nothing was deleted: {create_error}"
                        ));
                    }
                }
                match net::rename_remote(spec, password, &source, &destination).await {
                    Ok(()) => return Ok(destination),
                    Err(error) => {
                        // The source was not renamed, so removing our newly-created empty bucket is
                        // safe. Cleanup failure is non-destructive and must not trigger a fallback.
                        let _ = net::delete_remote(spec, password, &bucket, true).await;
                        return Err(format!(
                            "could not move item to Remote Trash; nothing was deleted: {error}"
                        ));
                    }
                }
            }
            Err(error) => {
                return Err(format!(
                    "could not verify a Remote Trash destination; nothing was deleted: {error}"
                ));
            }
        }
    }
    Err("could not allocate a unique Remote Trash name; nothing was deleted".into())
}

/// Delete an entry from a pane (right-click → Delete). Local files go to the macOS Trash.
/// Remote entries use quarantine unless `permanent_remote` was explicitly confirmed.
fn delete_entry(
    handle: &Handle,
    store: Arc<dyn CredentialStore>,
    panes: Panes,
    ui: Weak<App>,
    pane: usize,
    name: String,
    is_dir: bool,
    permanent_remote: bool,
) {
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
            let (h, st, pn, uw, nm) = (
                handle.clone(),
                store.clone(),
                panes.clone(),
                ui.clone(),
                name.clone(),
            );
            handle.spawn(async move {
                let res = tokio::task::spawn_blocking(move || trash::delete(&path))
                    .await
                    .map_err(|e| e.to_string())
                    .and_then(|r| r.map_err(|e| e.to_string()));
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(ui) = uw.upgrade() {
                        match &res {
                            Ok(()) => {
                                ui.set_status(format!("moved {nm} to Trash").into());
                                ui.set_error("".into());
                            }
                            Err(e) => ui.set_error(format!("delete failed: {e}").into()),
                        }
                    }
                    refresh_pane(&h, st, pn, uw, pane);
                });
            });
        }
        PaneKind::Remote => {
            let Some(spec) = conn else {
                set_err(&ui, "not connected");
                return;
            };
            let Some(password) = password_for(&store, &spec) else {
                set_err(&ui, "missing credential");
                return;
            };
            let rp = join_remote(PathBuf::from(&cwd).join(&name));
            let (h, st, pn, uw, nm) = (
                handle.clone(),
                store.clone(),
                panes.clone(),
                ui.clone(),
                name.clone(),
            );
            handle.spawn(async move {
                let mut s = spec.clone();
                s.initial_path = cwd.clone();
                let res = if permanent_remote {
                    net::delete_remote(&s, &password, &rp, is_dir)
                        .await
                        .map(|()| None)
                        .map_err(|error| format!("permanent delete failed: {error}"))
                } else {
                    quarantine_remote(&s, &password, &cwd, &nm).await.map(Some)
                };
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(ui) = uw.upgrade() {
                        match &res {
                            Ok(Some(destination)) => {
                                ui.set_status(
                                    format!("moved {nm} to Remote Trash: {destination}").into(),
                                );
                                ui.set_error("".into());
                            }
                            Ok(None) => {
                                ui.set_status(format!("permanently deleted {nm}").into());
                                ui.set_error("".into());
                            }
                            Err(e) => ui.set_error(e.clone().into()),
                        }
                    }
                    refresh_pane(&h, st, pn, uw, pane);
                });
            });
        }
    }
}

/// Bind a pane to a saved server (Remote) and list its initial directory.
fn connect_into_pane(
    handle: &Handle,
    store: Arc<dyn CredentialStore>,
    conns: ConnList,
    sessions: Sessions,
    panes: Panes,
    ui: Weak<App>,
    pane: usize,
    conn_id: i32,
) {
    let Some(spec) = conns
        .lock()
        .expect("connections lock")
        .iter()
        .find(|c| c.id.0 as i32 == conn_id)
        .cloned()
    else {
        return;
    };
    // Connect ADDS a background session (the pane's previous session stays alive in the pool).
    show_session_in_pane(handle, store, sessions, panes, ui, pane, &spec, true);
}

/// Show `spec`'s session in `pane`. With `create_if_missing` (Connect), a session is added to the
/// pool if absent — so connecting never drops the pane's previous session. Without it (switch),
/// only an existing pool session can be shown.
fn show_session_in_pane(
    handle: &Handle,
    store: Arc<dyn CredentialStore>,
    sessions: Sessions,
    panes: Panes,
    ui: Weak<App>,
    pane: usize,
    spec: &ConnectionSpec,
    create_if_missing: bool,
) {
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
            let cwd = if spec.initial_path.trim().is_empty() {
                "/".to_string()
            } else {
                spec.initial_path.clone()
            };
            let nav = Nav::at(cwd.clone());
            g.push(ActiveSession {
                conn: spec.clone(),
                cwd: cwd.clone(),
                nav: nav.clone(),
            });
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
    let label = PaneState {
        kind: PaneKind::Remote,
        conn: Some(spec.clone()),
        cwd,
        nav: Nav::default(),
    };
    let _ = ui.upgrade().map(|ui| {
        set_pane_kind_label(&ui, pane, &label);
        ui.set_active_pane(if pane == 0 {
            "local".into()
        } else {
            "remote".into()
        });
        ui.set_accept_any_cert(spec.accept_invalid_tls || spec.tls_pinned_sha256.is_some());
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
        (
            s.conn.as_ref().map(|c| c.id),
            s.cwd.clone(),
            s.nav.clone(),
            matches!(s.kind, PaneKind::Remote),
        )
    };
    if let (true, Some(id)) = (is_remote, id) {
        if let Some(s) = sessions
            .lock()
            .expect("sessions")
            .iter_mut()
            .find(|s| s.conn.id == id)
        {
            s.cwd = cwd;
            s.nav = nav;
        }
    }
}

/// Refresh the CONNECTED sidebar from the background session pool.
fn refresh_sessions_model(ui: &App, sessions: &Sessions) {
    let demo = use_design_demo_connections();
    let model: Vec<ConnRow> = sessions
        .lock()
        .expect("sessions")
        .iter()
        .map(|s| ConnRow {
            id: s.conn.id.0 as i32,
            label: s.conn.name.clone().into(),
            sub: if demo {
                format!("{}:{}", s.conn.host, s.conn.port)
            } else {
                format!("{}@{}", s.conn.user, s.conn.host)
            }
            .into(),
            protocol: demo_protocol_label(&s.conn, demo).into(),
            connected: true,
        })
        .collect();
    ui.set_sessions(ModelRc::from(Rc::new(VecModel::from(model))));
    apply_server_filter(ui);
}

/// Click a CONNECTED session → swap it into the active pane (the previous session stays alive).
fn switch_to_session(
    handle: &Handle,
    store: Arc<dyn CredentialStore>,
    sessions: Sessions,
    panes: Panes,
    ui: Weak<App>,
    pane: usize,
    conn_id: i32,
) {
    let Some(spec) = sessions
        .lock()
        .expect("sessions")
        .iter()
        .find(|s| s.conn.id.0 as i32 == conn_id)
        .map(|s| s.conn.clone())
    else {
        return;
    };
    show_session_in_pane(handle, store, sessions, panes, ui, pane, &spec, false);
}

/// Eject a session from the background pool entirely. Any pane currently showing it goes local.
fn disconnect_session(
    engine: TransferEngine,
    sessions: Sessions,
    panes: Panes,
    ui: Weak<App>,
    conn_id: i32,
) {
    engine.abort(ConnectionId(conn_id as usize));
    // Evict cached passwords for the ejected session(s) before retain drops them.
    // drops them. PASSWORD_CACHE values are Zeroizing<String> (wiped on drop), and evicting
    // here bounds how long a cleartext password lives after the user ends the session — it does
    // not sit in heap until process exit. (disconnect_pane does NOT evict: the session may still
    // be alive in the background pool / another pane.)
    // Capture the endpoint key of every ejected session AND drop them from the pool in ONE critical
    // section, so the filter and its exact inverse `retain` stay in lockstep. (Two separate locks
    // risked leaving the password cache out of sync with the pool if a panic hit between them.)
    let evicted: Vec<CredentialKey> = {
        let mut g = sessions.lock().expect("sessions");
        let evicted: Vec<_> = g
            .iter()
            .filter(|s| s.conn.id.0 as i32 == conn_id)
            .filter_map(|s| CredentialKey::for_spec(&s.conn).ok())
            .collect();
        g.retain(|s| s.conn.id.0 as i32 != conn_id);
        evicted
    };
    if !evicted.is_empty() {
        if let Ok(mut c) = PASSWORD_CACHE.lock() {
            for k in &evicted {
                c.remove(k);
            }
        }
    }
    for pane in 0..2 {
        let shown = panes.lock().expect("panes")[pane]
            .conn
            .as_ref()
            .map(|c| c.id.0 as i32 == conn_id)
            .unwrap_or(false);
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
    let label = PaneState {
        kind: PaneKind::Local,
        conn: None,
        cwd: cwd.clone(),
        nav: Nav::default(),
    };
    let _ = ui.upgrade().map(|ui| {
        set_pane_kind_label(&ui, pane, &label);
        if active_pane_idx(&ui) == pane {
            ui.set_accept_any_cert(false);
        }
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

    let label = PaneState {
        kind: PaneKind::Local,
        conn: None,
        cwd: cwd.clone(),
        nav: Nav::default(),
    };
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

fn save_local_favorites(paths: Vec<String>) -> Result<(), std::io::Error> {
    let mut settings = store::settings::load();
    settings.local_favorites = paths;
    settings.local_favorites_customized = true;
    store::settings::try_save(&settings)
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
    ui.set_local_favorites(ModelRc::from(Rc::new(VecModel::from(local_favorite_rows(
        &settings,
    )))));
}

fn add_local_favorite_from_pane(ui: &App, panes: Panes, source: String, index: i32) {
    let Ok(pane) = PaneId::try_from(source.as_str()) else {
        ui.set_error("unknown pane identifier".into());
        return;
    };
    let pane = pane.index();
    let Some(row) = (index >= 0)
        .then(|| pane_entries(ui, pane).row_data(index as usize))
        .flatten()
    else {
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
    let existing: HashSet<String> = paths
        .iter()
        .map(|raw| canonical_favorite_key(&expand_local_favorite(raw)))
        .collect();
    if existing.contains(&key) {
        ui.set_error("".into());
        ui.set_status("Favorite already exists.".into());
        return;
    }

    paths.push(path.to_string_lossy().to_string());
    if let Err(error) = save_local_favorites(paths) {
        ui.set_status("".into());
        ui.set_error(format!("Could not save Favorites: {error}").into());
        return;
    }
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
    if let Err(error) = save_local_favorites(paths) {
        ui.set_status("".into());
        ui.set_error(format!("Could not save Favorites order: {error}").into());
        return;
    }
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
    if let Err(error) = save_local_favorites(paths) {
        ui.set_status("".into());
        ui.set_error(format!("Could not remove Favorite: {error}").into());
        return;
    }
    refresh_local_favorites_model(ui);
    ui.set_error("".into());
    ui.set_status(format!("Removed from Favorites: {}", local_favorite_label(&removed)).into());
}

/// Copy the selected entry (or every visible entry after Command-A) from `src_pane` to `dst_pane`.
/// Every item follows the same conflict and path-safety checks as a normal single-item transfer.
fn selected_copy_requests(ui: &App, pane: usize) -> Vec<CopyRequest> {
    let entries = pane_entries(ui, pane);
    selected_transfer_rows(&entries, &pane_selection(ui, pane))
        .into_iter()
        .map(|row| {
            let name = row.name.to_string();
            let total = TRUE_SIZE
                .lock()
                .ok()
                .and_then(|sizes| sizes.get(&(pane, name.clone())).copied())
                .or((row.size > 0).then_some(row.size as u64));
            CopyRequest {
                name,
                is_dir: row.is_dir,
                total,
            }
        })
        .collect()
}

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
    let requests = selected_copy_requests(&ui, src_pane);
    if requests.is_empty() {
        return;
    }
    let batch = fresh_batch(requests.len() > 1);
    if requests.len() > 1 {
        ui.set_status(format!("copying {} selected items…", requests.len()).into());
    }

    let destination_is_remote = panes
        .lock()
        .ok()
        .and_then(|panes| {
            panes
                .get(dst_pane)
                .map(|pane| matches!(pane.kind, PaneKind::Remote))
        })
        .unwrap_or(false);
    if requests.len() > 1 && destination_is_remote {
        start_remote_transfer_batch(
            handle,
            store,
            panes,
            engine,
            idx,
            ui.as_weak(),
            src_pane,
            dst_pane,
            requests,
            batch,
        );
        return;
    }

    for request in requests {
        start_transfer(
            handle,
            store.clone(),
            panes.clone(),
            engine.clone(),
            idx.clone(),
            ui.as_weak(),
            src_pane,
            dst_pane,
            request.name,
            request.is_dir,
            request.total,
            batch,
        );
    }
}

fn split_copy_conflicts(
    requests: Vec<CopyRequest>,
    existing_names: &HashSet<String>,
) -> (Vec<CopyRequest>, Vec<CopyRequest>) {
    requests
        .into_iter()
        .partition(|request| !existing_names.contains(&request.name))
}

fn drain_copy_conflict_group(
    first: PendingCopy,
    pending: &mut VecDeque<PendingCopy>,
    apply_all: bool,
) -> Vec<PendingCopy> {
    let mut selected = vec![first];
    if !apply_all {
        return selected;
    }
    let (src_pane, dst_pane, batch_id) = (selected[0].0, selected[0].1, selected[0].5.id);
    let mut retained = VecDeque::with_capacity(pending.len());
    while let Some(item) = pending.pop_front() {
        if item.0 == src_pane && item.1 == dst_pane && item.5.id == batch_id {
            selected.push(item);
        } else {
            retained.push_back(item);
        }
    }
    *pending = retained;
    selected
}

fn unique_name_from_taken(name: &str, taken: &mut HashSet<String>) -> String {
    let (stem, extension) = match name.rfind('.') {
        Some(index) if index > 0 => (&name[..index], &name[index..]),
        _ => (name, ""),
    };
    for suffix in 1..=10_000u32 {
        let candidate = if suffix == 1 {
            format!("{stem} new{extension}")
        } else {
            format!("{stem} new {suffix}{extension}")
        };
        if taken.insert(candidate.clone()) {
            return candidate;
        }
    }
    // The bounded loop is practically unreachable, but retaining the source name is safer than
    // constructing an unbounded string or silently dropping a selected transfer.
    name.to_string()
}

/// Check a remote destination once for the entire Command/Shift selection. The old per-file
/// path opened and authenticated one connection, then listed the same directory, for every item.
fn start_remote_transfer_batch(
    handle: &Handle,
    store: Arc<dyn CredentialStore>,
    panes: Panes,
    engine: TransferEngine,
    idx: Arc<Mutex<HashMap<i32, usize>>>,
    ui: Weak<App>,
    src_pane: usize,
    dst_pane: usize,
    requests: Vec<CopyRequest>,
    batch: TransferBatch,
) {
    let (spec, cwd, source_remote, source_connection_id, source_cwd) = {
        let Ok(panes) = panes.lock() else {
            set_err(&ui, "could not read destination state");
            return;
        };
        let Some(source) = panes.get(src_pane) else {
            set_err(&ui, "invalid source pane");
            return;
        };
        let Some(destination) = panes.get(dst_pane) else {
            set_err(&ui, "invalid destination pane");
            return;
        };
        let Some(spec) = destination.conn.clone() else {
            set_err(&ui, "destination is not connected");
            return;
        };
        (
            spec,
            destination.cwd.clone(),
            matches!(source.kind, PaneKind::Remote),
            source.conn.as_ref().map(|connection| connection.id),
            source.cwd.clone(),
        )
    };
    let Some(password) = password_for(&store, &spec) else {
        set_err(&ui, "missing credential");
        return;
    };

    let handle = handle.clone();
    handle.clone().spawn(async move {
        let started = Instant::now();
        let mut listing_spec = spec.clone();
        listing_spec.initial_path = cwd.clone();
        let entries = match net::connect_and_list(&listing_spec, &password).await {
            Ok((entries, _)) => entries,
            Err(error) => {
                set_err(&ui, &format!("conflict check failed: {error}"));
                return;
            }
        };
        let mut existing_names = entries
            .into_iter()
            .map(|entry| entry.name)
            .collect::<HashSet<_>>();
        let request_count = requests.len();
        let (ready, conflicts) = split_copy_conflicts(requests, &existing_names);
        let conflict_count = conflicts.len();
        let policy = existing_file_policy();
        let mut resolved_conflicts = Vec::new();
        let mut pending_conflicts = Vec::new();
        let mut skipped_conflicts = 0usize;
        match policy {
            ExistingFilePolicy::Ask => pending_conflicts = conflicts,
            ExistingFilePolicy::Overwrite => {
                resolved_conflicts.extend(
                    conflicts
                        .into_iter()
                        .map(|request| (request.name.clone(), request)),
                );
            }
            ExistingFilePolicy::KeepBoth => {
                resolved_conflicts.extend(conflicts.into_iter().map(|request| {
                    let destination = unique_name_from_taken(&request.name, &mut existing_names);
                    (destination, request)
                }));
            }
            ExistingFilePolicy::Skip => skipped_conflicts = conflicts.len(),
        }
        tracing::info!(
            target: "gmacftp",
            host = %spec.host,
            items = request_count,
            conflicts = conflict_count,
            elapsed_ms = started.elapsed().as_millis(),
            "batch destination checked with one directory listing"
        );

        let request_ui = ui.clone();
        let request_panes = panes.clone();
        let request_cwd = cwd.clone();
        let connection_id = spec.id;
        let _ = slint::invoke_from_event_loop(move || {
            let destination_current = remote_pane_request_is_current(
                &request_panes,
                dst_pane,
                connection_id,
                &request_cwd,
            );
            let source_current = pane_request_is_current(
                &request_panes,
                src_pane,
                source_remote,
                source_connection_id,
                &source_cwd,
            );
            if !destination_current || !source_current {
                if let Some(ui) = request_ui.upgrade() {
                    ui.set_status("".into());
                    ui.set_error(
                        "Source or destination changed; copy was cancelled safely.".into(),
                    );
                }
                return;
            }

            for request in ready {
                do_transfer(
                    &handle,
                    store.clone(),
                    panes.clone(),
                    engine.clone(),
                    idx.clone(),
                    request_ui.clone(),
                    src_pane,
                    dst_pane,
                    request.name.clone(),
                    request.name,
                    request.is_dir,
                    request.total,
                    batch,
                );
            }

            for (destination_name, request) in resolved_conflicts {
                do_transfer(
                    &handle,
                    store.clone(),
                    panes.clone(),
                    engine.clone(),
                    idx.clone(),
                    request_ui.clone(),
                    src_pane,
                    dst_pane,
                    request.name,
                    destination_name,
                    request.is_dir,
                    request.total,
                    batch,
                );
            }

            if !pending_conflicts.is_empty() {
                let Ok(mut pending) = PENDING_COPY.lock() else {
                    if let Some(ui) = request_ui.upgrade() {
                        ui.set_error("Could not queue overwrite decisions.".into());
                    }
                    return;
                };
                pending.extend(pending_conflicts.into_iter().map(|request| {
                    (
                        src_pane,
                        dst_pane,
                        request.name,
                        request.is_dir,
                        request.total,
                        batch,
                    )
                }));
            }
            if let Some(ui) = request_ui.upgrade() {
                if skipped_conflicts > 0 {
                    ui.set_status(
                        format!(
                            "Skipped {skipped_conflicts} existing item(s) according to Settings."
                        )
                        .into(),
                    );
                }
                if !ui.get_overwrite_open()
                    && PENDING_COPY
                        .lock()
                        .map(|pending| !pending.is_empty())
                        .unwrap_or(false)
                {
                    show_next_overwrite(&ui);
                }
            }
        });
    });
}

/// Start a copy: check the destination for a name clash and open the overwrite dialog if there is
/// one (folders too — copying a folder that already exists asks before merging into it); otherwise
/// run the transfer immediately.
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
    batch: TransferBatch,
) {
    let (src_kind, dst_kind, dst_conn, dst_cwd) = {
        let p = panes.lock().expect("panes");
        let src = &p[src_pane];
        let s = &p[dst_pane];
        (
            src.kind.clone(),
            s.kind.clone(),
            s.conn.clone(),
            s.cwd.clone(),
        )
    };
    // Only a server name copied to the local filesystem is untrusted here. Do not sanitise
    // Local→Local/Local→Remote names: besides being unnecessary, doing so can change a valid
    // local filename before it reaches its intended destination.
    let dst_local = if matches!((&src_kind, &dst_kind), (PaneKind::Remote, PaneKind::Local)) {
        match remote_local_target(Path::new(&dst_cwd), &name) {
            Ok(path) => path,
            Err(e) => {
                set_err(&ui, &e.to_string());
                return;
            }
        }
    } else {
        PathBuf::from(&dst_cwd).join(&name)
    };
    let store2 = store.clone();
    let h = handle.clone();
    h.clone().spawn(async move {
        let exists = match &dst_kind {
            PaneKind::Local => dst_local.exists(),
            PaneKind::Remote => match dst_conn.as_ref() {
                Some(spec) => match password_for(&store2, spec) {
                    Some(pw) => match net::remote_exists(spec, &pw, &dst_cwd, &name).await {
                        Ok(b) => b,
                        // A connect/list failure must NOT read as "does not exist" — that would
                        // risk a silent overwrite. Surface the error and abort this copy.
                        Err(e) => {
                            set_err(&ui, &e.to_string());
                            return;
                        }
                    },
                    None => {
                        set_err(&ui, "missing credential");
                        return;
                    }
                },
                None => false,
            },
        };
        let destination_name = if !exists {
            Some(name.clone())
        } else {
            match existing_file_policy() {
                ExistingFilePolicy::Ask => {
                    let nm = name.clone();
                    let uw = ui.clone();
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Ok(mut pending) = PENDING_COPY.lock() {
                            pending.push_back((
                                src_pane,
                                dst_pane,
                                nm.clone(),
                                is_dir,
                                total,
                                batch,
                            ));
                        }
                        if let Some(ui) = uw.upgrade() {
                            if !ui.get_overwrite_open() {
                                show_next_overwrite(&ui);
                            }
                        }
                    });
                    None
                }
                ExistingFilePolicy::Overwrite => Some(name.clone()),
                ExistingFilePolicy::KeepBoth => Some(
                    unique_dest_name(&name, &dst_kind, dst_conn.as_ref(), &dst_cwd, &store2).await,
                ),
                ExistingFilePolicy::Skip => {
                    let skipped = name.clone();
                    let uw = ui.clone();
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(ui) = uw.upgrade() {
                            ui.set_status(format!("Skipped existing item: {skipped}").into());
                        }
                    });
                    None
                }
            }
        };
        if let Some(destination_name) = destination_name {
            let _ = slint::invoke_from_event_loop(move || {
                do_transfer(
                    &h,
                    store2,
                    panes,
                    engine,
                    idx,
                    ui,
                    src_pane,
                    dst_pane,
                    name,
                    destination_name,
                    is_dir,
                    total,
                    batch,
                );
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
    batch: TransferBatch,
) {
    let Some(ui) = ui.upgrade() else { return };
    let (src_kind, src_conn, src_cwd) = {
        let p = panes.lock().expect("panes");
        let s = &p[src_pane];
        (s.kind.clone(), s.conn.clone(), s.cwd.clone())
    };
    let (dst_kind, dst_conn, dst_cwd) = {
        let p = panes.lock().expect("panes");
        let s = &p[dst_pane];
        (s.kind.clone(), s.conn.clone(), s.cwd.clone())
    };
    let src_local = PathBuf::from(&src_cwd).join(&src_name);
    let src_remote = join_remote(PathBuf::from(&src_cwd).join(&src_name));
    // `dst_name` may be a remote directory-listing value (or its auto-suffixed variant).
    // Rebuild the local destination through the same guard here as in `start_transfer`: this
    // function is also called directly after resolving an overwrite dialog.
    let dst_local = if matches!((&src_kind, &dst_kind), (PaneKind::Remote, PaneKind::Local)) {
        match remote_local_target(Path::new(&dst_cwd), &dst_name) {
            Ok(path) => path,
            Err(e) => {
                ui.set_error(e.to_string().into());
                return;
            }
        }
    } else {
        PathBuf::from(&dst_cwd).join(&dst_name)
    };
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
                let result = tokio::task::spawn_blocking(move || fs_copy_tree(&src2, &dst2)).await;
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(ui) = ui_weak.upgrade() {
                        match result {
                            Ok(Ok(n)) => {
                                ui.set_status(format!("copied {n} files").into());
                                // Re-list both panes so the new file is visible immediately. Without this
                                // the Local→Local path (e.g. a "save as new" copy in the same folder)
                                // left the destination invisible until a manual Refresh.
                                refresh_both_panes(&h2, st2, pn2, ui.as_weak());
                            }
                            Ok(Err(e)) => ui.set_error(format!("copy failed: {e}").into()),
                            Err(e) => ui.set_error(format!("copy failed: {e}").into()),
                        }
                    }
                });
            });
        }
        (PaneKind::Local, PaneKind::Remote) => {
            let Some(spec) = dst_conn else { return };
            if !is_dir {
                enqueue(
                    &engine,
                    &ui,
                    &idx,
                    spec,
                    TransferDirection::Upload,
                    src_local,
                    dst_remote,
                    &dst_name,
                    total,
                    batch,
                );
            } else {
                copy_local_to_remote(
                    handle, engine, idx, ui_weak, spec, src_local, dst_remote, batch,
                );
            }
        }
        (PaneKind::Remote, PaneKind::Local) => {
            let Some(spec) = src_conn else { return };
            if !is_dir {
                enqueue(
                    &engine,
                    &ui,
                    &idx,
                    spec,
                    TransferDirection::Download,
                    dst_local,
                    src_remote,
                    &dst_name,
                    total,
                    batch,
                );
            } else {
                copy_remote_to_local(
                    handle, store, engine, idx, ui_weak, spec, src_remote, dst_local, batch,
                );
            }
        }
        (PaneKind::Remote, PaneKind::Remote) => {
            let (Some(src_spec), Some(dst_spec)) = (src_conn, dst_conn) else {
                return;
            };
            // relay through a temp dir: download from src, then upload to dst
            copy_remote_to_remote(
                handle,
                store,
                engine,
                idx,
                ui_weak,
                panes.clone(),
                src_spec,
                dst_spec,
                src_remote,
                dst_remote,
                dst_name.clone(),
                is_dir,
                total.unwrap_or(0),
                batch,
            );
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
    let batch = fresh_batch(false);
    if is_dir {
        copy_local_to_remote(handle, engine, idx, ui, spec, source, remote, batch);
    } else if let Some(u) = ui.upgrade() {
        enqueue(
            &engine,
            &u,
            &idx,
            spec,
            TransferDirection::Upload,
            source,
            remote,
            &name,
            size,
            batch,
        );
    }
}

/// Show the oldest queued overwrite conflict. Finder-drop conflicts retain priority because an
/// already visible dialog can belong to that queue; Command-A conflicts follow in FIFO order.
fn show_next_overwrite(ui: &App) {
    let next = PENDING_EXTERNAL_UPLOAD
        .lock()
        .ok()
        .and_then(|g| g.front().map(|item| item.3.clone()))
        .or_else(|| {
            PENDING_COPY
                .lock()
                .ok()
                .and_then(|g| g.front().map(|item| item.2.clone()))
        });
    if let Some(name) = next {
        ui.set_overwrite_name(name.into());
        ui.set_overwrite_apply_all(false);
        ui.set_overwrite_open(true);
    } else {
        ui.set_overwrite_open(false);
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
    let Ok(decision) = OverwriteDecision::try_from(decision) else {
        if let Some(ui) = ui.upgrade() {
            ui.set_error("Invalid overwrite decision; nothing was changed.".into());
        }
        return;
    };
    let apply_all = ui
        .upgrade()
        .map(|ui| {
            let apply_all = ui.get_overwrite_apply_all();
            ui.set_overwrite_open(false);
            apply_all
        })
        .unwrap_or(false);
    // Finder→server uploads blocked on the dialog are a FIFO queue (a multi-file drop may contain
    // several conflicting names — confirmed one at a time). Pop the one currently shown; after
    // resolving it, show the next if any. Checked before the in-app copy pending.
    let item = PENDING_EXTERNAL_UPLOAD
        .lock()
        .ok()
        .and_then(|mut g| g.pop_front());
    if let Some(item) = item {
        let mut items = vec![item];
        if apply_all {
            if let Ok(mut pending) = PENDING_EXTERNAL_UPLOAD.lock() {
                items.extend(pending.drain(..));
            }
        }
        let item_count = items.len();
        match decision {
            OverwriteDecision::Overwrite => {
                for (spec, source, remote_dir, name, size, is_dir) in items {
                    let remote = join_remote(PathBuf::from(&remote_dir).join(&name));
                    do_external_upload(
                        handle,
                        engine.clone(),
                        idx.clone(),
                        ui.clone(),
                        spec,
                        source,
                        remote,
                        name,
                        size,
                        is_dir,
                    );
                }
            }
            OverwriteDecision::KeepBoth => {
                let (h, en, ix, uw, st) = (
                    handle.clone(),
                    engine.clone(),
                    idx.clone(),
                    ui.clone(),
                    store.clone(),
                );
                handle.spawn(async move {
                    for (spec, source, remote_dir, name, size, is_dir) in items {
                        let new_name = unique_dest_name(
                            &name,
                            &PaneKind::Remote,
                            Some(&spec),
                            &remote_dir,
                            &st,
                        )
                        .await;
                        let remote = join_remote(PathBuf::from(&remote_dir).join(&new_name));
                        let (h, en, ix, uw) = (h.clone(), en.clone(), ix.clone(), uw.clone());
                        let _ = slint::invoke_from_event_loop(move || {
                            do_external_upload(
                                &h, en, ix, uw, spec, source, remote, new_name, size, is_dir,
                            );
                        });
                    }
                });
            }
            OverwriteDecision::Skip => {
                if let Some(u) = ui.upgrade() {
                    u.set_status(format!("Skipped {item_count} conflicting item(s).").into());
                }
            }
        }
        if let Some(u) = ui.upgrade() {
            show_next_overwrite(&u);
        }
        return;
    }
    // in-app copy
    let pending = PENDING_COPY.lock().ok().and_then(|mut g| g.pop_front());
    let Some(first) = pending else {
        return;
    };
    let items = if let Ok(mut pending) = PENDING_COPY.lock() {
        drain_copy_conflict_group(first.clone(), &mut pending, apply_all)
    } else {
        vec![first]
    };
    let item_count = items.len();
    let destination_pane = items[0].1;
    let next_ui = ui.clone();
    match decision {
        OverwriteDecision::Overwrite => {
            for (src_pane, dst_pane, name, is_dir, total, batch) in items {
                do_transfer(
                    handle,
                    store.clone(),
                    panes.clone(),
                    engine.clone(),
                    idx.clone(),
                    ui.clone(),
                    src_pane,
                    dst_pane,
                    name.clone(),
                    name,
                    is_dir,
                    total,
                    batch,
                );
            }
        }
        OverwriteDecision::KeepBoth => {
            let (dst_kind, dst_conn, dst_cwd) = {
                let p = panes.lock().expect("panes");
                let s = &p[destination_pane];
                (s.kind.clone(), s.conn.clone(), s.cwd.clone())
            };
            let store2 = store.clone();
            let h = handle.clone();
            handle.spawn(async move {
                for (src_pane, dst_pane, name, is_dir, total, batch) in items {
                    let new_name =
                        unique_dest_name(&name, &dst_kind, dst_conn.as_ref(), &dst_cwd, &store2)
                            .await;
                    let (h, store, panes, engine, idx, ui) = (
                        h.clone(),
                        store2.clone(),
                        panes.clone(),
                        engine.clone(),
                        idx.clone(),
                        ui.clone(),
                    );
                    let _ = slint::invoke_from_event_loop(move || {
                        do_transfer(
                            &h, store, panes, engine, idx, ui, src_pane, dst_pane, name, new_name,
                            is_dir, total, batch,
                        );
                    });
                }
            });
        }
        OverwriteDecision::Skip => {
            if let Some(ui) = ui.upgrade() {
                ui.set_status(format!("Skipped {item_count} conflicting item(s).").into());
            }
        }
    }
    if let Some(ui) = next_ui.upgrade() {
        show_next_overwrite(&ui);
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
                // A remote source name can reach the "Save as new" branch too. Check exactly
                // the same cleaned, contained path that `do_transfer` will eventually write;
                // otherwise `../report new.pdf` could be tested outside the destination and
                // later be normalised onto an already-existing local file.
                let Ok(clean) = net::sanitize_local_rel(c) else {
                    continue;
                };
                let Ok(target) = remote_local_target(Path::new(dst_cwd), &clean) else {
                    continue;
                };
                if !target.exists() {
                    return clean;
                }
            }
        }
        PaneKind::Remote => {
            if let Some(spec) = dst_conn {
                if let Some(pw) = password_for(store, spec) {
                    let mut s = spec.clone();
                    s.initial_path = dst_cwd.to_string();
                    if let Ok((entries, _)) = net::connect_and_list(&s, &pw).await {
                        let taken: std::collections::HashSet<&str> =
                            entries.iter().map(|e| e.name.as_str()).collect();
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
    let fallback = candidates
        .into_iter()
        .next()
        .unwrap_or_else(|| format!("{} new{}", stem, ext));
    // Local destinations always receive the sanitised form, even after all 99 candidates are
    // occupied. The existing behaviour still returns the first candidate in that rare case;
    // this only prevents that fallback from reintroducing a traversal component.
    if matches!(dst_kind, PaneKind::Local) {
        net::sanitize_local_rel(&fallback).unwrap_or(fallback)
    } else {
        fallback
    }
}

/// Wire the overwrite-conflict dialog buttons.
fn wire_overwrite(
    ui: &App,
    handle: &Handle,
    store: Arc<dyn CredentialStore>,
    panes: Panes,
    engine: TransferEngine,
    idx: Arc<Mutex<HashMap<i32, usize>>>,
) {
    let (h, st, pn, en, ix, uw) = (
        handle.clone(),
        store.clone(),
        panes.clone(),
        engine.clone(),
        idx.clone(),
        ui.as_weak(),
    );
    ui.on_resolve_overwrite(move |decision| {
        resolve_overwrite(
            &h,
            st.clone(),
            pn.clone(),
            en.clone(),
            ix.clone(),
            uw.clone(),
            decision,
        );
    });
}

/// Wire the sync-passphrase dialog: "set" (first time enabling sync) wraps the master key +
/// enables sync; "enter" (a pulled vault that's locked here) unlocks it with the passphrase.
fn offer_legacy_credential_recovery(
    ui: &App,
    store: &dyn CredentialStore,
    specs: &[ConnectionSpec],
) {
    if ui.get_passphrase_open() || ui.get_credential_recovery_open() {
        return;
    }
    match store.credential_health(specs) {
        Ok(health) if health.recoverable_legacy_credentials > 0 => {
            let recoverable =
                i32::try_from(health.recoverable_legacy_credentials).unwrap_or(i32::MAX);
            let ambiguous = i32::try_from(health.ambiguous_legacy_credentials).unwrap_or(i32::MAX);
            ui.set_credential_recovery_count(recoverable);
            ui.set_credential_recovery_ambiguous(ambiguous);
            ui.set_credential_recovery_open(true);
            ui.set_status(
                "Older encrypted credentials were found. Confirm the downloaded server list to recover them."
                    .into(),
            );
            tracing::warn!(
                recoverable = health.recoverable_legacy_credentials,
                ambiguous = health.ambiguous_legacy_credentials,
                "legacy synced credentials require an explicit recovery decision"
            );
        }
        Ok(health) if health.ambiguous_legacy_credentials > 0 => {
            ui.set_status(
                format!(
                    "Ambiguous synced passwords requiring manual re-entry: {}.",
                    health.ambiguous_legacy_credentials
                )
                .into(),
            );
        }
        Ok(_) => {}
        Err(error) => {
            tracing::warn!(%error, "could not inspect encrypted credential consistency");
        }
    }
}

fn wire_credential_recovery(ui: &App, store: Arc<dyn CredentialStore>, conns: ConnList) {
    let (st, cn, uw) = (store, conns, ui.as_weak());
    ui.on_resolve_credential_recovery(move |approved| {
        let Some(ui) = uw.upgrade() else {
            return;
        };
        ui.set_credential_recovery_open(false);
        if !approved {
            ui.set_status(
                "Password recovery was not performed. No credential data was changed.".into(),
            );
            return;
        }
        let specs = match cn.lock() {
            Ok(connections) => connections.clone(),
            Err(_) => {
                ui.set_error("Could not lock saved connections for password recovery.".into());
                return;
            }
        };
        let expected = ui.get_credential_recovery_count().max(0) as usize;
        let before = match st.credential_health(&specs) {
            Ok(health) => health,
            Err(error) => {
                ui.set_error(format!("Could not inspect saved passwords: {error}").into());
                return;
            }
        };
        if before.recoverable_legacy_credentials != expected {
            ui.set_error(
                "The server list or encrypted vault changed before recovery. Review it and try again."
                    .into(),
            );
            return;
        }
        match st.recover_legacy_credentials(&specs) {
            Ok(result) if result.recovered > 0 => {
                let mut settings = store::settings::load();
                settings.endpoint_credentials_migrated_v2 = true;
                if let Err(error) = store::settings::try_save(&settings) {
                    tracing::warn!(%error, "credential recovery succeeded but migration state was not saved");
                }
                ui.set_credential_recovery_count(0);
                ui.set_credential_recovery_ambiguous(0);
                ui.set_error("".into());
                let message = if result.ambiguous == 0 {
                    format!(
                        "Recovered saved passwords: {}. You can connect normally now.",
                        result.recovered
                    )
                } else {
                    format!(
                        "Recovered saved passwords: {}; ambiguous passwords requiring manual re-entry: {}.",
                        result.recovered, result.ambiguous
                    )
                };
                ui.set_status(message.into());
            }
            Ok(_) => ui.set_error(
                "No password could be recovered. The encrypted vault was left unchanged.".into(),
            ),
            Err(error) => {
                ui.set_error(format!("Could not recover saved passwords: {error}").into())
            }
        }
    });
}

fn validate_new_sync_passphrase(value: &str) -> Result<(), String> {
    if value.chars().count() < MIN_SYNC_PASSPHRASE_CHARS || value.len() > MAX_SYNC_PASSPHRASE_BYTES
    {
        return Err(format!(
            "Passphrase must be at least {MIN_SYNC_PASSPHRASE_CHARS} characters and at most {MAX_SYNC_PASSPHRASE_BYTES} bytes."
        ));
    }
    Ok(())
}

fn wire_passphrase(
    ui: &App,
    handle: &Handle,
    store: Arc<dyn CredentialStore>,
    conns: ConnList,
    panes: Panes,
    engine: TransferEngine,
) {
    let (st, cn, pn, en, runtime, uw) = (
        store.clone(),
        conns.clone(),
        panes,
        engine,
        handle.clone(),
        ui.as_weak(),
    );
    ui.on_resolve_passphrase(move |value: slint::SharedString, confirm: slint::SharedString| {
        let value = value.to_string();
        let confirm = confirm.to_string();
        let mode = uw.upgrade().map(|u| u.get_passphrase_mode().to_string()).unwrap_or_default();
        // Clear the inputs + close (re-opened below on a wrong passphrase).
        if let Some(ui) = uw.upgrade() {
            ui.set_passphrase_value("".into());
            ui.set_passphrase_confirm("".into());
            ui.set_passphrase_open(false);
        }
        if value.is_empty() {
            if matches!(mode.as_str(), "backup_export" | "backup_import") {
                if let Ok(mut pending) = PENDING_SETTINGS_CRYPTO.lock() {
                    *pending = None;
                }
                if let Some(ui) = uw.upgrade() {
                    ui.set_settings_message("Encrypted settings operation cancelled.".into());
                }
            } else if let Some(ui) = uw.upgrade() {
                // The master key may already be available through iCloud Keychain even when the
                // local passphrase-setup flag still opened this dialog. Cancelling must not hide
                // a separately recoverable legacy vault until the next launch.
                if let Ok(specs) = cn.lock() {
                    offer_legacy_credential_recovery(&ui, st.as_ref(), &specs);
                }
            }
            return; // Cancel
        }
        if mode == "backup_export" {
            if let Err(error) = validate_new_sync_passphrase(&value) {
                if let Some(ui) = uw.upgrade() {
                    ui.set_error(error.into());
                    ui.set_passphrase_mode("backup_export".into());
                    ui.set_passphrase_open(true);
                }
                return;
            }
            if value != confirm {
                if let Some(ui) = uw.upgrade() {
                    ui.set_error("Passphrases don't match.".into());
                    ui.set_passphrase_mode("backup_export".into());
                    ui.set_passphrase_open(true);
                }
                return;
            }
            let pending = PENDING_SETTINGS_CRYPTO
                .lock()
                .ok()
                .and_then(|mut pending| pending.take());
            let Some(PendingSettingsCrypto::Export { path, plaintext }) = pending else {
                if let Some(ui) = uw.upgrade() {
                    ui.set_error("Encrypted settings export is no longer pending.".into());
                }
                return;
            };
            let passphrase = Zeroizing::new(value);
            let ui = uw.clone();
            runtime.spawn(async move {
                let result = tokio::task::spawn_blocking(move || {
                    let ciphertext = store::backup::encrypt(&plaintext, &passphrase)?;
                    store::write_private_atomic(&path, &ciphertext)
                        .map_err(|error| error.to_string())
                })
                .await
                .map_err(|error| error.to_string())
                .and_then(|result| result);
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(ui) = ui.upgrade() {
                        match result {
                            Ok(()) => {
                                ui.set_settings_message(
                                    "Passphrase-encrypted settings exported; credentials were excluded."
                                        .into(),
                                );
                                ui.set_error("".into());
                            }
                            Err(error) => ui.set_error(
                                format!("Could not export encrypted settings: {error}").into(),
                            ),
                        }
                    }
                });
            });
            return;
        }
        if mode == "backup_import" {
            if value.len() > MAX_SYNC_PASSPHRASE_BYTES {
                if let Some(ui) = uw.upgrade() {
                    ui.set_error(
                        format!("Passphrase exceeds {MAX_SYNC_PASSPHRASE_BYTES} bytes.").into(),
                    );
                    ui.set_passphrase_mode("backup_import".into());
                    ui.set_passphrase_open(true);
                }
                return;
            }
            let pending = PENDING_SETTINGS_CRYPTO
                .lock()
                .ok()
                .and_then(|mut pending| pending.take());
            let Some(PendingSettingsCrypto::Import { ciphertext }) = pending else {
                if let Some(ui) = uw.upgrade() {
                    ui.set_error("Encrypted settings import is no longer pending.".into());
                }
                return;
            };
            let passphrase = Zeroizing::new(value);
            let ui = uw.clone();
            let engine = en.clone();
            let panes = pn.clone();
            let credential_store = st.clone();
            let refresh_handle = runtime.clone();
            runtime.spawn(async move {
                let outcome = tokio::task::spawn_blocking(move || {
                    let plaintext = match store::backup::decrypt(&ciphertext, &passphrase) {
                        Ok(plaintext) => plaintext,
                        Err(error) => {
                            return SettingsImportOutcome::Retry { error, ciphertext };
                        }
                    };
                    let settings = match imported_settings_from_plaintext(&plaintext) {
                        Ok(settings) => settings,
                        Err(error) => return SettingsImportOutcome::Failed(error),
                    };
                    match store::settings::try_save(&settings) {
                        Ok(()) => SettingsImportOutcome::Applied(Box::new(settings)),
                        Err(error) => SettingsImportOutcome::Failed(format!(
                            "could not persist imported settings: {error}"
                        )),
                    }
                })
                .await
                .unwrap_or_else(|error| {
                    SettingsImportOutcome::Failed(format!(
                        "settings import worker failed: {error}"
                    ))
                });
                let _ = slint::invoke_from_event_loop(move || {
                    let Some(ui) = ui.upgrade() else {
                        return;
                    };
                    match outcome {
                        SettingsImportOutcome::Applied(settings) => {
                            apply_locale(&ui, &settings.locale);
                            crate::Tokens::get(&ui)
                                .set_theme(effective_theme(&ui, &settings.theme).into());
                            ui.set_show_hidden(settings.show_hidden_files);
                            ui.set_background_folder_metadata(
                                settings.background_folder_metadata,
                            );
                            ui.set_pane_split(settings.pane_split_px as f32);
                            ui.set_sync_comparison(settings.sync_comparison.clone().into());
                            ui.set_sync_mtime_tolerance(
                                settings.sync_mtime_tolerance_secs.to_string().into(),
                            );
                            ui.set_sync_exclusions(settings.sync_exclusions.clone().into());
                            ui.set_transfer_concurrency(
                                engine.set_endpoint_concurrency(settings.transfer_concurrency)
                                    as i32,
                            );
                            engine.set_default_server_concurrency(
                                settings.per_server_transfer_concurrency,
                            );
                            engine.set_retry_policy(
                                settings.transfer_retry_count,
                                settings.transfer_retry_backoff_ms,
                            );
                            engine.set_bandwidth_limit_kib(
                                settings.transfer_bandwidth_limit_kib,
                            );
                            load_settings_form(&ui, &settings);
                            ui.set_settings_open(true);
                            ui.set_settings_message(
                                "Encrypted settings imported. Passwords, vault keys and cloud security state were unchanged."
                                    .into(),
                            );
                            ui.set_status("Settings imported safely.".into());
                            ui.set_error("".into());
                            refresh_pane(
                                &refresh_handle,
                                credential_store.clone(),
                                panes.clone(),
                                ui.as_weak(),
                                0,
                            );
                            refresh_pane(
                                &refresh_handle,
                                credential_store,
                                panes,
                                ui.as_weak(),
                                1,
                            );
                        }
                        SettingsImportOutcome::Retry { error, ciphertext } => {
                            if let Ok(mut pending) = PENDING_SETTINGS_CRYPTO.lock() {
                                *pending = Some(PendingSettingsCrypto::Import { ciphertext });
                            }
                            ui.set_error(error.into());
                            ui.set_passphrase_mode("backup_import".into());
                            ui.set_passphrase_open(true);
                        }
                        SettingsImportOutcome::Failed(error) => {
                            ui.set_error(format!("Could not import settings: {error}").into());
                        }
                    }
                });
            });
            return;
        }
        if mode == "set" {
            if let Err(error) = validate_new_sync_passphrase(&value) {
                if let Some(ui) = uw.upgrade() {
                    ui.set_error(error.into());
                    ui.set_passphrase_mode("set".into());
                    ui.set_passphrase_open(true);
                }
                return;
            }
            if value != confirm {
                if let Some(ui) = uw.upgrade() {
                    ui.set_error("Passphrases don't match.".into());
                    ui.set_passphrase_mode("set".into());
                    ui.set_passphrase_open(true);
                }
                return;
            }
            match store::vault::enable_sync_passphrase(&value) {
                Ok(()) => match store::cloud::set_sync_enabled(true) {
                    Ok(()) => {
                    crate::macos_menu::refresh_sync_title();
                    if let Some(ui) = uw.upgrade() {
                        ui.set_status(
                            "Sync enabled — servers + the encrypted vault will sync to your other Macs.".into(),
                        );
                    }
                    }
                    Err(e) => {
                        if let Some(ui) = uw.upgrade() {
                            ui.set_error(format!("Passphrase saved, but sync could not be enabled: {e}").into());
                        }
                    }
                },
                Err(e) => {
                    if let Some(ui) = uw.upgrade() {
                        ui.set_error(format!("Failed to set passphrase: {e}").into());
                    }
                }
            }
        } else if value.len() > MAX_SYNC_PASSPHRASE_BYTES {
            if let Some(ui) = uw.upgrade() {
                ui.set_error(format!("Passphrase exceeds {MAX_SYNC_PASSPHRASE_BYTES} bytes.").into());
                ui.set_passphrase_mode("enter".into());
                ui.set_passphrase_open(true);
            }
        } else if st.unlock(&value) {
            if let Some(ui) = uw.upgrade() {
                refresh_connections_model(&ui, &cn);
                ui.set_status("Vault unlocked — passwords are available.".into());
                if let Ok(specs) = cn.lock() {
                    offer_legacy_credential_recovery(&ui, st.as_ref(), &specs);
                }
            }
        } else if let Some(ui) = uw.upgrade() {
            ui.set_error("Wrong passphrase.".into());
            ui.set_passphrase_mode("enter".into());
            ui.set_passphrase_open(true); // let the user retry
        }
    });
}

/// Complete the explicit SFTP first-contact trust flow. The SSH handshake has already failed
/// closed; only an affirmative response after showing the exact endpoint + fingerprint writes a
/// pin, then retries the current pane. Cancel leaves no `known_hosts` record behind.
fn wire_host_key_trust(ui: &App, handle: &Handle, store: Arc<dyn CredentialStore>, panes: Panes) {
    let (h, st, pn, uw) = (handle.clone(), store, panes, ui.as_weak());
    ui.on_resolve_host_key_trust(move |approved| {
        let pending = PENDING_HOST_KEY_TRUST
            .lock()
            .ok()
            .and_then(|mut p| p.take());
        let Some((challenge, pane)) = pending else {
            return;
        };
        let Some(ui) = uw.upgrade() else {
            return;
        };
        ui.set_host_key_open(false);
        ui.set_host_key_endpoint("".into());
        ui.set_host_key_fingerprint("".into());
        if !approved {
            ui.set_error("SFTP host key was not trusted; connection cancelled.".into());
            return;
        }
        match net::sftp::trust_host_key(&challenge) {
            Ok(()) => {
                ui.set_error("".into());
                ui.set_status("SFTP host key trusted for this server. Reconnecting…".into());
                refresh_pane(&h, st.clone(), pn.clone(), ui.as_weak(), pane);
            }
            Err(error) => ui.set_error(error.to_string().into()),
        }
    });
}

fn clear_keyboard_interactive_form(ui: &App) {
    ui.set_ssh_auth_open(false);
    ui.set_ssh_auth_endpoint("".into());
    ui.set_ssh_auth_title("".into());
    ui.set_ssh_auth_instructions("".into());
    ui.set_ssh_auth_prompt_count(0);
    ui.set_ssh_auth_prompt_0("".into());
    ui.set_ssh_auth_prompt_1("".into());
    ui.set_ssh_auth_prompt_2("".into());
    ui.set_ssh_auth_prompt_3("".into());
    ui.set_ssh_auth_echo_0(false);
    ui.set_ssh_auth_echo_1(false);
    ui.set_ssh_auth_echo_2(false);
    ui.set_ssh_auth_echo_3(false);
    // Clear secrets before the next event-loop turn; they are never copied to settings/logs.
    ui.set_ssh_auth_response_0("".into());
    ui.set_ssh_auth_response_1("".into());
    ui.set_ssh_auth_response_2("".into());
    ui.set_ssh_auth_response_3("".into());
}

fn show_next_keyboard_interactive_request(ui: &App) {
    let display = PENDING_KEYBOARD_INTERACTIVE
        .lock()
        .ok()
        .and_then(|mut queue| {
            while queue
                .front()
                .is_some_and(|request| request.response.is_closed())
            {
                queue.pop_front();
            }
            queue.front().map(|request| {
                (
                    request.endpoint.clone(),
                    request.name.clone(),
                    request.instructions.clone(),
                    request.prompts.clone(),
                )
            })
        });
    let Some((endpoint, title, instructions, prompts)) = display else {
        clear_keyboard_interactive_form(ui);
        return;
    };
    clear_keyboard_interactive_form(ui);
    ui.set_ssh_auth_endpoint(endpoint.into());
    ui.set_ssh_auth_title(title.into());
    ui.set_ssh_auth_instructions(instructions.into());
    ui.set_ssh_auth_prompt_count(prompts.len().min(4) as i32);
    for (index, prompt) in prompts.into_iter().take(4).enumerate() {
        match index {
            0 => {
                ui.set_ssh_auth_prompt_0(prompt.text.into());
                ui.set_ssh_auth_echo_0(prompt.echo);
            }
            1 => {
                ui.set_ssh_auth_prompt_1(prompt.text.into());
                ui.set_ssh_auth_echo_1(prompt.echo);
            }
            2 => {
                ui.set_ssh_auth_prompt_2(prompt.text.into());
                ui.set_ssh_auth_echo_2(prompt.echo);
            }
            3 => {
                ui.set_ssh_auth_prompt_3(prompt.text.into());
                ui.set_ssh_auth_echo_3(prompt.echo);
            }
            _ => unreachable!(),
        }
    }
    ui.set_ssh_auth_open(true);
}

fn wire_keyboard_interactive(ui: &App, handle: &Handle) {
    let mut requests = net::install_keyboard_interactive_broker();
    let request_ui = ui.as_weak();
    handle.spawn(async move {
        while let Some(request) = requests.recv().await {
            let show = PENDING_KEYBOARD_INTERACTIVE
                .lock()
                .map(|mut queue| {
                    let show = queue.is_empty();
                    queue.push_back(request);
                    show
                })
                .unwrap_or(false);
            if show {
                let ui = request_ui.clone();
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(ui) = ui.upgrade() {
                        show_next_keyboard_interactive_request(&ui);
                    }
                });
            }
        }
    });

    let response_ui = ui.as_weak();
    ui.on_resolve_keyboard_interactive(move |approved| {
        let Some(ui) = response_ui.upgrade() else {
            return;
        };
        let responses = approved.then(|| {
            Zeroizing::new(vec![
                ui.get_ssh_auth_response_0().to_string(),
                ui.get_ssh_auth_response_1().to_string(),
                ui.get_ssh_auth_response_2().to_string(),
                ui.get_ssh_auth_response_3().to_string(),
            ])
        });
        let request = PENDING_KEYBOARD_INTERACTIVE
            .lock()
            .ok()
            .and_then(|mut queue| queue.pop_front());
        clear_keyboard_interactive_form(&ui);
        if let Some(request) = request {
            let reply = match responses {
                Some(mut responses) => {
                    responses.truncate(request.prompts.len());
                    Ok(responses)
                }
                None => Err("keyboard-interactive authentication cancelled by the user".into()),
            };
            let _ = request.response.send(reply);
        }
        show_next_keyboard_interactive_request(&ui);
    });
}

fn wire_tls_certificate_trust(
    ui: &App,
    handle: &Handle,
    store: Arc<dyn CredentialStore>,
    conns: ConnList,
    sessions: Sessions,
    panes: Panes,
) {
    let (handle, ui_weak) = (handle.clone(), ui.as_weak());
    ui.on_resolve_tls_certificate(move |decision| {
        let pending = PENDING_TLS_CERTIFICATE_TRUST
            .lock()
            .ok()
            .and_then(|mut pending| pending.take());
        let Some((challenge, pane)) = pending else {
            return;
        };
        let Some(ui) = ui_weak.upgrade() else {
            return;
        };
        ui.set_tls_cert_open(false);
        ui.set_tls_cert_endpoint("".into());
        ui.set_tls_cert_fingerprint("".into());
        ui.set_tls_cert_previous("".into());
        if decision == 0 {
            ui.set_error("FTPS certificate was not trusted; connection cancelled.".into());
            return;
        }
        let Some(pin) = net::ftp::normalize_certificate_pin(challenge.fingerprint()) else {
            ui.set_error("The FTPS certificate fingerprint was malformed.".into());
            return;
        };

        let current = panes
            .lock()
            .ok()
            .and_then(|panes| panes.get(pane).and_then(|pane| pane.conn.clone()));
        let Some(mut current) = current else {
            ui.set_error("The connection changed while the certificate dialog was open.".into());
            return;
        };
        let endpoint = format!("{}:{}", current.host, current.effective_port());
        if endpoint != challenge.endpoint() {
            ui.set_error("The connection changed while the certificate dialog was open.".into());
            return;
        }
        current.accept_invalid_tls = false;
        current.tls_pinned_sha256 = Some(pin);

        if decision == 2 {
            let mut updated = match conns.lock() {
                Ok(connections) => connections.clone(),
                Err(_) => {
                    ui.set_error("Could not lock saved connections.".into());
                    return;
                }
            };
            let Some(saved) = updated.iter_mut().find(|saved| saved.id == current.id) else {
                ui.set_error("The saved connection no longer exists.".into());
                return;
            };
            saved.accept_invalid_tls = false;
            saved.tls_pinned_sha256 = current.tls_pinned_sha256.clone();
            if let Err(error) = store::connections::save_metadata(&updated) {
                ui.set_error(format!("Could not save the FTPS certificate pin: {error}").into());
                return;
            }
            if let Ok(mut connections) = conns.lock() {
                *connections = updated;
            }
            refresh_connections_model(&ui, &conns);
        }

        if let Ok(mut pane_states) = panes.lock() {
            if let Some(state) = pane_states.get_mut(pane) {
                state.conn = Some(current.clone());
            }
        }
        if let Ok(mut active_sessions) = sessions.lock() {
            if let Some(session) = active_sessions
                .iter_mut()
                .find(|session| session.conn.id == current.id)
            {
                session.conn = current;
            }
        }
        ui.set_accept_any_cert(true);
        ui.set_error("".into());
        ui.set_status(
            if decision == 2 {
                "FTPS certificate pinned to this server. Reconnecting…"
            } else {
                "FTPS certificate trusted for this session. Reconnecting…"
            }
            .into(),
        );
        refresh_sessions_model(&ui, &sessions);
        refresh_pane(&handle, store.clone(), panes.clone(), ui.as_weak(), pane);
    });
}

/// Fold the app's saved legacy passwords into endpoint-bound v2 records, using only endpoints
/// from the local metadata file. No-op once complete; it never enumerates unrelated Keychain
/// entries and never treats a storage error as successful migration.
fn migrate_saved_passwords(store: &dyn CredentialStore) -> Result<usize, String> {
    if store::settings::load().endpoint_credentials_migrated_v2 {
        return Ok(0);
    }
    let n = store.migrate_from_keychain().map_err(|e| e.to_string())?;
    let mut s = store::settings::load();
    s.endpoint_credentials_migrated_v2 = true;
    store::settings::try_save(&s).map_err(|e| e.to_string())?;
    Ok(n)
}

/// Wire "Send Servers to iCloud": migrate this app's known legacy passwords into the vault,
/// then push the vault + connections.
fn wire_send_sync(ui: &App, store: Arc<dyn CredentialStore>) {
    let (st, uw) = (store.clone(), ui.as_weak());
    ui.on_request_send_sync(move || {
        let migrated = migrate_saved_passwords(st.as_ref());
        let msg = store::cloud::send_now();
        if let Some(ui) = uw.upgrade() {
            let extra = match migrated {
                Ok(n) if n > 0 => {
                    format!(" (migrated {n} passwords into the vault — one-time)")
                }
                Ok(_) => String::new(),
                Err(error) => format!(" (saved-password migration failed: {error})"),
            };
            ui.set_status(format!("{msg}{extra}").into());
        }
    });
}

const MAX_SYNC_PREVIEW_ROWS: usize = 2_000;
const MAX_SYNC_CHECKSUM_FILES: usize = 10_000;
const MAX_SYNC_REPORT_ROWS: usize = 50_000;
const MAX_SYNC_REPORT_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
struct FolderSyncContextKey {
    local_pane: usize,
    remote_pane: usize,
    local_root: PathBuf,
    remote_root: String,
    connection_id: ConnectionId,
}

#[derive(Clone)]
struct FolderSyncContext {
    key: FolderSyncContextKey,
    spec: ConnectionSpec,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FolderSyncCandidate {
    label: String,
    local_path: String,
    remote_path: String,
    bytes: u64,
    included: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FolderSyncDeletion {
    label: String,
    local_path: String,
    remote_path: String,
    metadata: gmacftp::folder_sync::SyncFileMetadata,
    included: bool,
}

#[derive(Clone)]
struct PreparedFolderSync {
    context: FolderSyncContext,
    direction: TransferDirection,
    exclusions: Vec<String>,
    options: gmacftp::folder_sync::SyncOptions,
    preview: gmacftp::folder_sync::SyncPreview,
    candidates: Vec<FolderSyncCandidate>,
    deletions: Vec<FolderSyncDeletion>,
}

#[derive(Clone)]
struct PendingMirrorBatch {
    context: FolderSyncContext,
    direction: TransferDirection,
    job_ids: HashSet<usize>,
    finished: HashSet<usize>,
    failed: bool,
    deletions: Vec<FolderSyncDeletion>,
}

static PENDING_MIRROR_BATCHES: LazyLock<Mutex<HashMap<usize, PendingMirrorBatch>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

enum MirrorBatchOutcome {
    Ready(Box<PendingMirrorBatch>),
    Aborted { deletion_count: usize },
}

/// Track only terminal updates belonging to a mirror batch. A single failed, cancelled or
/// skipped copy permanently prevents the destructive phase, even when the user's normal batch
/// policy continues with later files.
fn observe_mirror_batch(update: &TransferUpdate) -> Option<MirrorBatchOutcome> {
    let succeeded = match &update.state {
        TransferState::Done => true,
        TransferState::Failed(_) | TransferState::Cancelled | TransferState::Skipped(_) => false,
        TransferState::Active | TransferState::Retrying { .. } => return None,
    };
    let mut batches = PENDING_MIRROR_BATCHES.lock().ok()?;
    let pending = batches.get_mut(&update.batch_id)?;
    if !pending.job_ids.contains(&update.id.0) || !pending.finished.insert(update.id.0) {
        return None;
    }
    if !succeeded {
        pending.failed = true;
    }
    if pending.finished.len() != pending.job_ids.len() {
        return None;
    }
    let pending = batches.remove(&update.batch_id)?;
    if pending.failed {
        Some(MirrorBatchOutcome::Aborted {
            deletion_count: pending.deletions.len(),
        })
    } else {
        Some(MirrorBatchOutcome::Ready(Box::new(pending)))
    }
}

#[derive(Clone)]
struct PlannedXfer {
    id: usize,
    label: String,
    local_path: String,
    remote_path: String,
    bytes_total: Option<u64>,
}

/// Push one panel row per planned transfer (on the UI thread, awaited via a oneshot so no engine
/// update can ever race ahead of its row), then stream the jobs into the engine with BACKPRESSURE.
/// The bounded worker channel therefore never overflows for an arbitrarily large folder — the loop
/// simply waits for the engine to drain a slot before handing it the next file. This is what lets a
/// 10 000-file download flow through a small queue with bounded memory (no "transfer queue full").
async fn stream_folder_transfers(
    engine: &TransferEngine,
    ui: Weak<App>,
    idx: Arc<Mutex<HashMap<i32, usize>>>,
    spec: ConnectionSpec,
    direction: TransferDirection,
    host: String,
    plans: Vec<PlannedXfer>,
    status_msg: String,
    batch: TransferBatch,
) {
    let pause_on_error = batch.pause_on_error || plans.len() > 1;
    let dir_s: &'static str = match direction {
        TransferDirection::Download => "download",
        TransferDirection::Upload => "upload",
    };
    let route = match direction {
        TransferDirection::Upload => format!("local -> {host}"),
        TransferDirection::Download => format!("{host} -> local"),
    };
    let plans_for_rows = plans.clone();
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel::<()>();
    let _ = slint::invoke_from_event_loop(move || {
        for p in &plans_for_rows {
            let total_i = p.bytes_total.unwrap_or(0).min(i32::MAX as u64) as i32;
            let row = TransferRow {
                id: p.id as i32,
                name: p.label.clone().into(),
                direction: dir_s.into(),
                done: 0,
                total: total_i,
                progress_text: fmt_transfer_progress(0, p.bytes_total.unwrap_or(0)).into(),
                fraction: 0.0,
                state: "queued".into(),
                priority: "normal".into(),
                message: "".into(),
                route: route.clone().into(),
            };
            jobs_push(row, &idx);
        }
        if let Some(ui) = ui.upgrade() {
            ui.set_status(status_msg.into());
            ui.set_transfer_active(true);
            ui.set_transfer_total(0);
            ui.set_transfer_done(0);
            ui.set_transfer_fraction(0.0);
            update_transfer_summary(&ui);
        }
        let _ = ready_tx.send(());
    });
    // Wait until every row is inserted on the UI thread — guarantees a row exists for each job
    // before the engine can emit its first Active/Done update (else the update is dropped and the
    // row would sit on "queued" forever).
    let _ = ready_rx.await;
    for p in plans {
        let source_modified_unix_nanos = if matches!(direction, TransferDirection::Upload) {
            source_modified_unix_nanos(Path::new(&p.local_path))
        } else {
            None
        };
        let job = TransferJob {
            id: TransferId(p.id),
            batch_id: batch.id,
            pause_on_error,
            priority: Default::default(),
            direction,
            local_path: p.local_path,
            remote_path: p.remote_path,
            bytes_total: p.bytes_total,
            source_modified_unix_nanos,
            resume_token: fresh_resume_token(),
        };
        engine.enqueue(job, spec.clone()).await;
    }
}

/// Local → Remote folder: walk local, enqueue one upload per file (mkdir -p on the server).
fn copy_local_to_remote(
    handle: &Handle,
    engine: TransferEngine,
    idx: Arc<Mutex<HashMap<i32, usize>>>,
    ui: Weak<App>,
    spec: ConnectionSpec,
    local_base: PathBuf,
    remote_base: String,
    batch: TransferBatch,
) {
    let (engine2, idx2, uw) = (engine.clone(), idx.clone(), ui.clone());
    let host = spec.host.clone();
    let _ = ui
        .upgrade()
        .map(|u| u.set_status("preparing folder upload…".into()));
    handle.spawn(async move {
        let tree = match tokio::task::spawn_blocking(move || walk_local(&local_base)).await {
            Ok(Ok(tree)) => tree,
            Ok(Err(e)) => {
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(ui) = uw.upgrade() {
                        ui.set_error(format!("could not prepare folder upload: {e}").into());
                    }
                });
                return;
            }
            Err(e) => {
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(ui) = uw.upgrade() {
                        ui.set_error(format!("could not prepare folder upload: {e}").into());
                    }
                });
                return;
            }
        };
        let mut plans: Vec<PlannedXfer> = Vec::with_capacity(tree.files.len());
        for (lp, rel, size) in &tree.files {
            let rp = join_remote(PathBuf::from(&remote_base).join(rel));
            plans.push(PlannedXfer {
                id: fresh_xfer_id(),
                label: rel.clone(),
                local_path: lp.to_string_lossy().to_string(),
                remote_path: rp,
                bytes_total: if *size > 0 { Some(*size) } else { None },
            });
        }
        if plans.is_empty() {
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(ui) = uw.upgrade() {
                    ui.set_status("folder is empty".into());
                }
            });
            return;
        }
        let n = plans.len();
        stream_folder_transfers(
            &engine2,
            uw,
            idx2,
            spec,
            TransferDirection::Upload,
            host,
            plans,
            format!("uploading {n} files…"),
            batch,
        )
        .await;
    });
}

/// Remote → Local folder: walk remote, enqueue one download per file (mkdir -p local).
fn copy_remote_to_local(
    handle: &Handle,
    store: Arc<dyn CredentialStore>,
    engine: TransferEngine,
    idx: Arc<Mutex<HashMap<i32, usize>>>,
    ui: Weak<App>,
    spec: ConnectionSpec,
    remote_base: String,
    local_base: PathBuf,
    batch: TransferBatch,
) {
    let Some(password) = password_for(&store, &spec) else {
        set_err(&ui, "missing credential");
        return;
    };
    let (engine2, idx2, uw, rb) = (engine.clone(), idx.clone(), ui.clone(), remote_base.clone());
    let host = spec.host.clone();
    let _ = ui
        .upgrade()
        .map(|u| u.set_status("preparing folder download…".into()));
    handle.spawn(async move {
        let files = net::walk_remote(&spec, &password, &rb).await;
        let mut plans: Vec<PlannedXfer> = Vec::new();
        let mut skipped: usize = 0;
        match files {
            Err(e) => {
                let _ = slint::invoke_from_event_loop(move || {
                    if let Some(ui) = uw.upgrade() {
                        ui.set_error(e.to_string().into());
                    }
                });
                return;
            }
            Ok(list) => {
                for (rp, size) in &list {
                    // Contain server-controlled relative paths (PATH-1/2): reject `..`/
                    // absolute/control-byte entries instead of joining them verbatim.
                    let rel = match net::sanitize_local_rel(
                        &rp.strip_prefix(&remote_base)
                            .map(|p| p.to_string())
                            .unwrap_or_default(),
                    ) {
                        Ok(c) => c,
                        Err(e) => {
                            tracing::warn!(remote = %rp, error = %e, "skipping unsafe remote path");
                            skipped += 1;
                            continue;
                        }
                    };
                    // Build through the shared write-boundary helper as well. This includes the
                    // resolved-path/symlink containment check and keeps every remote→local
                    // transfer path on the same policy.
                    let lp = match remote_local_target(&local_base, &rel) {
                        Ok(path) => path,
                        Err(e) => {
                            tracing::warn!(remote = %rp, error = %e, "skipping out-of-root path");
                            skipped += 1;
                            continue;
                        }
                    };
                    plans.push(PlannedXfer {
                        id: fresh_xfer_id(),
                        label: rel,
                        local_path: lp.to_string_lossy().to_string(),
                        remote_path: rp.clone(),
                        bytes_total: if *size > 0 { Some(*size) } else { None },
                    });
                }
            }
        }
        if plans.is_empty() {
            let msg = if skipped > 0 {
                format!("no safe files to download (skipped {skipped} unsafe path(s))")
            } else {
                "folder is empty".to_string()
            };
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(ui) = uw.upgrade() {
                    ui.set_status(msg.into());
                }
            });
            return;
        }
        let n = plans.len();
        let status_msg = if skipped > 0 {
            format!("downloading {n} files… (skipped {skipped} unsafe path(s))")
        } else {
            format!("downloading {n} files…")
        };
        stream_folder_transfers(
            &engine2,
            uw,
            idx2,
            spec,
            TransferDirection::Download,
            host,
            plans,
            status_msg,
            batch,
        )
        .await;
    });
}

/// Remote → Remote folder: relay each file through a temp dir (download then upload).
/// Relay one file: download src→temp (any protocol), then upload temp→dst (any protocol).
/// Retries once after a short delay — many shared-hosting FTP servers limit concurrent
/// sessions and need a moment to release the slot after the browsing connection's quit().
async fn relay_one(
    src_spec: &ConnectionSpec,
    pw_src: &str,
    dst_spec: &ConnectionSpec,
    pw_dst: &str,
    rp: &str,
    tmpf: &Path,
    dst_rp: &str,
) -> Result<(), String> {
    // 1. Download src → temp (retry once)
    let dl = relay_download(src_spec, pw_src, rp, tmpf).await;
    if dl.is_err() {
        tracing::warn!(target: "gmacftp", error = ?dl, "relay download failed, retrying");
        tokio::time::sleep(std::time::Duration::from_millis(800)).await;
        relay_download(src_spec, pw_src, rp, tmpf).await?;
    }
    // Note: a 0-byte temp file here is a LEGITIMATE empty remote file (a failed download
    // already returned Err above), so it must be relayed like any other file — do NOT reject it.
    // 2. Pause to let the src server release the session slot
    tokio::time::sleep(std::time::Duration::from_secs(2)).await;
    // 3. Upload temp → dst (FTPS; plaintext only when explicitly enabled for that destination)
    let ul = relay_upload(dst_spec, pw_dst, tmpf, dst_rp).await;
    if ul.is_err() {
        tracing::warn!(target: "gmacftp", error = ?ul, "relay upload failed, retrying");
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        relay_upload(dst_spec, pw_dst, tmpf, dst_rp).await?;
    }
    Ok(())
}

async fn relay_download(
    spec: &ConnectionSpec,
    pw: &str,
    remote: &str,
    local: &Path,
) -> Result<(), String> {
    match spec.protocol {
        Protocol::Ftp => {
            let (s, p, r, t) = (
                spec.clone(),
                pw.to_string(),
                remote.to_string(),
                local.to_path_buf(),
            );
            tokio::time::timeout(
                std::time::Duration::from_secs(30),
                tokio::task::spawn_blocking(move || {
                    net::ftp::download(&s, &p, &r, &t, |_| {}, None)
                }),
            )
            .await
            .map_err(|_| "download timeout (30s)".to_string())?
            .map_err(|e| e.to_string())?
            .map_err(|e| e.to_string())?;
        }
        Protocol::Sftp => {
            tokio::time::timeout(
                std::time::Duration::from_secs(30),
                net::sftp::download(spec, pw, remote, local, |_| {}, None),
            )
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
async fn relay_upload(
    spec: &ConnectionSpec,
    pw: &str,
    local: &Path,
    remote: &str,
) -> Result<(), String> {
    match spec.protocol {
        Protocol::Ftp => {
            let (s, p, r, t) = (
                spec.clone(),
                pw.to_string(),
                remote.to_string(),
                local.to_path_buf(),
            );
            tokio::time::timeout(
                std::time::Duration::from_secs(30),
                tokio::task::spawn_blocking(move || net::ftp::upload(&s, &p, &t, &r, |_| {}, None)),
            )
            .await
            .map_err(|_| "upload timeout (30s)".to_string())?
            .map_err(|e| e.to_string())?
            .map_err(|e| e.to_string())?;
        }
        Protocol::Sftp => {
            tokio::time::timeout(
                std::time::Duration::from_secs(30),
                net::sftp::upload(spec, pw, local, remote, |_| {}, None),
            )
            .await
            .map_err(|_| "upload timeout (30s)".to_string())?
            .map_err(|e| e.to_string())?;
        }
    }
    Ok(())
}

/// Remote → Remote: relay each file through a temp dir in ONE sequential task (download then
/// upload per file), so the upload always runs after its download — no engine-job-ordering race.
fn copy_remote_to_remote(
    handle: &Handle,
    store: Arc<dyn CredentialStore>,
    _engine: TransferEngine,
    idx: Arc<Mutex<HashMap<i32, usize>>>,
    ui: Weak<App>,
    panes: Panes,
    src_spec: ConnectionSpec,
    dst_spec: ConnectionSpec,
    src_base: String,
    dst_base: String,
    name: String,
    is_dir: bool,
    size: u64,
    _batch: TransferBatch,
) {
    let Some(pw_src) = password_for(&store, &src_spec) else {
        set_err(&ui, "missing src credential");
        return;
    };
    let Some(pw_dst) = password_for(&store, &dst_spec) else {
        set_err(&ui, "missing dst credential");
        return;
    };
    let ui_weak = ui.clone();
    // clones captured by the task so it can refresh both panes once the relay finishes
    let (handle_r, store_r, panes_r) = (handle.clone(), store.clone(), panes.clone());
    let route = format!("{} -> {}", src_spec.host, dst_spec.host);
    handle.spawn(async move {
        // Brief delay so the browsing connection's session slot is released by the server
        // (many shared hosts limit concurrent sessions per FTP user).
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        tracing::info!(target: "gmacftp", "relay: src={} dst={} is_dir={}", src_spec.host, dst_spec.host, is_dir);
        if is_dir {
            let destination_path = Path::new(&dst_base);
            let Some(destination_name) = destination_path.file_name().and_then(|name| name.to_str()) else {
                set_err(&ui_weak, "invalid remote destination folder");
                return;
            };
            let destination_parent = destination_path
                .parent()
                .map(|parent| parent.to_string_lossy().into_owned())
                .filter(|parent| !parent.is_empty())
                .unwrap_or_else(|| "/".into());
            match net::remote_exists(
                &dst_spec,
                &pw_dst,
                &destination_parent,
                destination_name,
            )
            .await
            {
                Ok(true) => {}
                Ok(false) => {
                    if let Err(error) =
                        net::create_remote_dir(&dst_spec, &pw_dst, &dst_base).await
                    {
                        set_err(&ui_weak, &format!("could not create destination folder: {error}"));
                        return;
                    }
                }
                Err(error) => {
                    set_err(
                        &ui_weak,
                        &format!("could not check destination folder: {error}"),
                    );
                    return;
                }
            }
        }
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
                jobs_push(TransferRow { id: row_id, name: label_p.into(), direction: "→".into(), done: 0, total, progress_text: "".into(), fraction: 0.0, state: "active".into(), priority: "normal".into(), message: "relay".into(), route: route_p.into() }, &idx_p);
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

#[derive(Debug, Clone, Copy)]
struct LocalTreeLimits {
    max_files: usize,
    max_dirs: usize,
    max_depth: usize,
}

const DEFAULT_LOCAL_TREE_LIMITS: LocalTreeLimits = LocalTreeLimits {
    max_files: MAX_LOCAL_TREE_FILES,
    max_dirs: MAX_LOCAL_TREE_DIRS,
    max_depth: MAX_LOCAL_TREE_DEPTH,
};

#[derive(Debug)]
struct LocalTree {
    files: Vec<(PathBuf, String, u64)>,
    /// Relative directories below the source root, retained so local copies preserve empty dirs.
    dirs: Vec<String>,
}

/// Canonicalise an existing path, or the nearest existing parent followed by its missing tail.
/// This lets us detect a destination inside its source before that destination is created.
fn canonicalize_local_lenient(path: &Path) -> Result<PathBuf, String> {
    let mut current = path.to_path_buf();
    let mut tail = Vec::new();
    loop {
        if let Ok(canonical) = std::fs::canonicalize(&current) {
            let mut resolved = canonical;
            while let Some(component) = tail.pop() {
                resolved.push(component);
            }
            return Ok(resolved);
        }
        let Some(parent) = current.parent() else {
            return Err(format!("cannot resolve local path {}", path.display()));
        };
        let Some(name) = current.file_name() else {
            return Err(format!("cannot resolve local path {}", path.display()));
        };
        tail.push(name.to_os_string());
        current = parent.to_path_buf();
    }
}

/// Read a local tree without ever following a symlink. Canonical containment plus a visited
/// directory identity set rejects alias/cycle tricks even on filesystems that permit unusual
/// directory links.
fn walk_local_with_limits(base: &Path, limits: LocalTreeLimits) -> Result<LocalTree, String> {
    walk_local_with_limits_and_filter(base, limits, None)
}

fn walk_local_with_limits_and_filter(
    base: &Path,
    limits: LocalTreeLimits,
    excluded: Option<&dyn Fn(&str) -> bool>,
) -> Result<LocalTree, String> {
    let base_metadata = std::fs::symlink_metadata(base)
        .map_err(|e| format!("cannot inspect {}: {e}", base.display()))?;
    if base_metadata.file_type().is_symlink() {
        return Err(format!("refusing to traverse symlink {}", base.display()));
    }
    if !base_metadata.is_dir() {
        return Err(format!("{} is not a directory", base.display()));
    }
    let canonical_root = std::fs::canonicalize(base)
        .map_err(|e| format!("cannot resolve {}: {e}", base.display()))?;
    let mut visited_paths = HashSet::new();
    visited_paths.insert(canonical_root.clone());
    #[cfg(unix)]
    let mut visited_ids = {
        use std::os::unix::fs::MetadataExt;
        let mut ids = HashSet::new();
        ids.insert((base_metadata.dev(), base_metadata.ino()));
        ids
    };

    let mut tree = LocalTree {
        files: Vec::new(),
        dirs: Vec::new(),
    };
    let mut dir_count = 1usize;
    let mut stack = vec![(base.to_path_buf(), String::new(), 0usize)];
    while let Some((dir, relative, depth)) = stack.pop() {
        let entries =
            std::fs::read_dir(&dir).map_err(|e| format!("cannot read {}: {e}", dir.display()))?;
        for entry in entries {
            let entry =
                entry.map_err(|e| format!("cannot read entry in {}: {e}", dir.display()))?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| format!("refusing non-UTF-8 filename in {}", dir.display()))?;
            let path = entry.path();
            let child_relative = if relative.is_empty() {
                name
            } else {
                format!("{relative}/{name}")
            };
            // Exclusions are applied before metadata inspection/traversal. An excluded symlink or
            // special file is never opened and cannot redirect the walk; it is simply out of scope.
            if excluded.is_some_and(|is_excluded| is_excluded(&child_relative)) {
                continue;
            }
            let metadata = std::fs::symlink_metadata(&path)
                .map_err(|e| format!("cannot inspect {}: {e}", path.display()))?;
            if metadata.file_type().is_symlink() {
                return Err(format!("refusing to traverse symlink {}", path.display()));
            }
            if metadata.is_dir() {
                let child_depth = depth + 1;
                if child_depth > limits.max_depth {
                    return Err(format!(
                        "local folder exceeds the maximum depth of {}",
                        limits.max_depth
                    ));
                }
                dir_count += 1;
                if dir_count > limits.max_dirs {
                    return Err(format!(
                        "local folder exceeds the maximum of {} directories",
                        limits.max_dirs
                    ));
                }
                let canonical = std::fs::canonicalize(&path)
                    .map_err(|e| format!("cannot resolve {}: {e}", path.display()))?;
                if !canonical.starts_with(&canonical_root) {
                    return Err(format!("directory escapes source root: {}", path.display()));
                }
                if !visited_paths.insert(canonical) {
                    return Err(format!("directory cycle detected at {}", path.display()));
                }
                #[cfg(unix)]
                {
                    use std::os::unix::fs::MetadataExt;
                    if !visited_ids.insert((metadata.dev(), metadata.ino())) {
                        return Err(format!("directory identity repeated at {}", path.display()));
                    }
                }
                tree.dirs.push(child_relative.clone());
                stack.push((path, child_relative, child_depth));
            } else if metadata.is_file() {
                if tree.files.len() >= limits.max_files {
                    return Err(format!(
                        "local folder exceeds the maximum of {} files",
                        limits.max_files
                    ));
                }
                tree.files.push((path, child_relative, metadata.len()));
            } else {
                return Err(format!("unsupported special file {}", path.display()));
            }
        }
    }
    Ok(tree)
}

/// Walk a local directory recursively for upload. This is deliberately fail-closed: callers can
/// report a readable error instead of silently uploading an incomplete tree.
fn walk_local(base: &Path) -> Result<LocalTree, String> {
    walk_local_with_limits(base, DEFAULT_LOCAL_TREE_LIMITS)
}

fn walk_local_for_sync(base: &Path, exclusions: &[String]) -> Result<LocalTree, String> {
    let excluded = |relative: &str| gmacftp::folder_sync::is_excluded(relative, exclusions);
    walk_local_with_limits_and_filter(base, DEFAULT_LOCAL_TREE_LIMITS, Some(&excluded))
}

struct LocalCopyStage {
    path: Option<PathBuf>,
}

impl LocalCopyStage {
    fn commit(&mut self) {
        self.path = None;
    }
}

impl Drop for LocalCopyStage {
    fn drop(&mut self) {
        if let Some(path) = self.path.take() {
            let _ = std::fs::remove_file(path);
        }
    }
}

fn create_private_copy_stage(dst: &Path) -> Result<(PathBuf, std::fs::File), String> {
    let parent = dst
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    for _ in 0..8 {
        let path = parent.join(format!(".gmacftp-copy-{:032x}", rand::random::<u128>()));
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(&path) {
            Ok(file) => return Ok((path, file)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(format!(
                    "cannot create a private copy next to {}: {error}",
                    dst.display()
                ));
            }
        }
    }
    Err(format!(
        "cannot allocate a unique private copy next to {}",
        dst.display()
    ))
}

fn copy_local_file_with<F>(src: &Path, dst: &Path, copy: F) -> Result<usize, String>
where
    F: FnOnce(&mut std::fs::File, &mut std::fs::File) -> std::io::Result<u64>,
{
    let metadata = std::fs::symlink_metadata(src)
        .map_err(|e| format!("cannot inspect {}: {e}", src.display()))?;
    if metadata.file_type().is_symlink() {
        return Err(format!("refusing to copy symlink {}", src.display()));
    }
    if !metadata.is_file() {
        return Err(format!("{} is not a regular file", src.display()));
    }
    if let Ok(destination_metadata) = std::fs::symlink_metadata(dst) {
        if destination_metadata.file_type().is_symlink() {
            return Err(format!(
                "refusing to overwrite destination symlink {}",
                dst.display()
            ));
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if destination_metadata.dev() == metadata.dev()
                && destination_metadata.ino() == metadata.ino()
            {
                return Err("refusing to copy a file onto itself or one of its hard links".into());
            }
        }
        if !destination_metadata.is_file() {
            return Err(format!(
                "destination is not a regular file: {}",
                dst.display()
            ));
        }
    }
    let source =
        std::fs::canonicalize(src).map_err(|e| format!("cannot resolve {}: {e}", src.display()))?;
    if canonicalize_local_lenient(dst)? == source {
        return Err("refusing to copy a file onto itself".into());
    }
    if let Some(parent) = dst.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
    }

    let mut source_options = std::fs::OpenOptions::new();
    source_options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        source_options.custom_flags(libc::O_NOFOLLOW);
    }
    let mut source_file = source_options
        .open(src)
        .map_err(|e| format!("cannot safely open {}: {e}", src.display()))?;
    let opened_metadata = source_file
        .metadata()
        .map_err(|e| format!("cannot inspect opened source {}: {e}", src.display()))?;
    if !opened_metadata.is_file() {
        return Err(format!("{} is not a regular file", src.display()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if opened_metadata.dev() != metadata.dev() || opened_metadata.ino() != metadata.ino() {
            return Err(format!("source changed while opening {}", src.display()));
        }
    }

    let (stage_path, mut stage_file) = create_private_copy_stage(dst)?;
    let mut stage = LocalCopyStage {
        path: Some(stage_path.clone()),
    };
    let copied = copy(&mut source_file, &mut stage_file)
        .map_err(|e| format!("cannot copy {}: {e}", src.display()))?;
    if copied != opened_metadata.len() {
        return Err(format!(
            "source changed while copying {} (expected {} bytes, copied {copied})",
            src.display(),
            opened_metadata.len()
        ));
    }
    stage_file
        .set_permissions(opened_metadata.permissions())
        .map_err(|e| format!("cannot preserve permissions for {}: {e}", dst.display()))?;
    stage_file
        .sync_all()
        .map_err(|e| format!("cannot flush private copy for {}: {e}", dst.display()))?;
    drop(stage_file);

    std::fs::rename(&stage_path, dst).map_err(|e| {
        format!(
            "cannot atomically install copied file {}: {e}",
            dst.display()
        )
    })?;
    stage.commit();
    // The file content is already durable. Best-effort directory sync also makes the rename durable
    // on filesystems that implement fsync for directories; some mounted filesystems reject it.
    if let Some(parent) = dst.parent() {
        if let Ok(directory) = std::fs::File::open(parent) {
            let _ = directory.sync_all();
        }
    }
    Ok(1)
}

fn copy_local_file(src: &Path, dst: &Path) -> Result<usize, String> {
    copy_local_file_with(src, dst, std::io::copy)
}

/// Recursively copy a local file/tree to a local destination. The full source tree is verified
/// before writing so errors and symlink encounters cannot be reported as a successful copy.
fn fs_copy_tree(src: &Path, dst: &Path) -> Result<usize, String> {
    let metadata = std::fs::symlink_metadata(src)
        .map_err(|e| format!("cannot inspect {}: {e}", src.display()))?;
    if metadata.file_type().is_symlink() {
        return Err(format!("refusing to copy symlink {}", src.display()));
    }
    if !metadata.is_dir() {
        return copy_local_file(src, dst);
    }
    if std::fs::symlink_metadata(dst)
        .map(|metadata| metadata.file_type().is_symlink())
        .unwrap_or(false)
    {
        return Err(format!(
            "refusing to copy into destination symlink {}",
            dst.display()
        ));
    }
    let source =
        std::fs::canonicalize(src).map_err(|e| format!("cannot resolve {}: {e}", src.display()))?;
    let destination = canonicalize_local_lenient(dst)?;
    if destination.starts_with(&source) {
        return Err("refusing to copy a folder into itself or one of its descendants".into());
    }
    let tree = walk_local(src)?;
    // Validate the complete destination tree before creating anything. This prevents a
    // pre-existing symlink/special-file conflict halfway down the tree from leaving a copy that
    // looks successful but is only partially materialised (or from redirecting bytes outside).
    for relative in &tree.dirs {
        let directory = dst.join(relative);
        net::assert_within(dst, &directory).map_err(|error| error.to_string())?;
        if let Ok(metadata) = std::fs::symlink_metadata(&directory) {
            if metadata.file_type().is_symlink() {
                return Err(format!(
                    "refusing destination symlink {}",
                    directory.display()
                ));
            }
            if !metadata.is_dir() {
                return Err(format!(
                    "destination is not a directory: {}",
                    directory.display()
                ));
            }
        }
    }
    for (source, relative, _) in &tree.files {
        let destination = dst.join(relative);
        net::assert_within(dst, &destination).map_err(|error| error.to_string())?;
        if let Ok(destination_metadata) = std::fs::symlink_metadata(&destination) {
            if destination_metadata.file_type().is_symlink() {
                return Err(format!(
                    "refusing destination symlink {}",
                    destination.display()
                ));
            }
            if !destination_metadata.is_file() {
                return Err(format!(
                    "destination is not a regular file: {}",
                    destination.display()
                ));
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::MetadataExt;
                let source_metadata = std::fs::symlink_metadata(source)
                    .map_err(|e| format!("cannot inspect {}: {e}", source.display()))?;
                if destination_metadata.dev() == source_metadata.dev()
                    && destination_metadata.ino() == source_metadata.ino()
                {
                    return Err(format!(
                        "refusing to copy {} onto one of its hard links",
                        source.display()
                    ));
                }
            }
        }
    }

    std::fs::create_dir_all(dst).map_err(|e| format!("cannot create {}: {e}", dst.display()))?;
    for relative in &tree.dirs {
        let directory = dst.join(relative);
        std::fs::create_dir_all(&directory)
            .map_err(|e| format!("cannot create {}: {e}", directory.display()))?;
    }
    for (source, relative, _) in &tree.files {
        let destination = dst.join(relative);
        if let Some(parent) = destination.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| format!("cannot create {}: {e}", parent.display()))?;
        }
        let fresh = std::fs::symlink_metadata(source)
            .map_err(|e| format!("cannot inspect {}: {e}", source.display()))?;
        if fresh.file_type().is_symlink() || !fresh.is_file() {
            return Err(format!("source changed while copying {}", source.display()));
        }
        copy_local_file(source, &destination)?;
    }
    Ok(tree.files.len())
}

fn password_for(store: &Arc<dyn CredentialStore>, spec: &ConnectionSpec) -> Option<String> {
    let key = CredentialKey::for_spec(spec).ok()?;
    if let Ok(cache) = PASSWORD_CACHE.lock() {
        if let Some(p) = cache.get(&key) {
            return Some(p.to_string()); // Zeroizing<String> derefs to String; cached → no Keychain prompt
        }
    }
    tracing::debug!(target: "gmacftp::creds", host = %spec.host, user = %spec.user, "credential lookup (private vault; silent — no Keychain prompt)");
    let p = match store.get_for(&key) {
        Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
        Err(store::CredentialError::NotFound)
            if spec.protocol == Protocol::Sftp && spec.sftp_auth != SftpAuth::Password =>
        {
            String::new()
        }
        Err(_) => return None,
    };
    if let Ok(mut cache) = PASSWORD_CACHE.lock() {
        cache.insert(key, Zeroizing::new(p.clone()));
    }
    Some(p)
}

// ── connect / remote list ──────────────────────────────────────────────────────

// ── pane-indexed navigation (kind-aware: Local = fs path, Remote = joined remote path) ──

fn synchronized_pane_identity(state: &PaneState) -> Option<SynchronizedPaneIdentity> {
    match state.kind {
        PaneKind::Local => Some(SynchronizedPaneIdentity::Local),
        PaneKind::Remote => state
            .conn
            .as_ref()
            .map(|spec| SynchronizedPaneIdentity::Remote(spec.id)),
    }
}

fn stop_synchronized_browsing(ui: &App, message: Option<&str>) {
    if let Ok(mut synchronized) = SYNCHRONIZED_BROWSING.lock() {
        *synchronized = None;
    }
    ui.set_synchronized_browsing(false);
    if let Some(message) = message {
        ui.set_status(message.into());
    }
}

fn synchronized_context(panes: &Panes) -> Option<SynchronizedBrowsing> {
    let context = SYNCHRONIZED_BROWSING.lock().ok()?.clone()?;
    let states = panes.lock().ok()?;
    let current = [
        synchronized_pane_identity(&states[0])?,
        synchronized_pane_identity(&states[1])?,
    ];
    (current == context.identities).then_some(context)
}

fn pane_contains_directory(ui: &App, pane: usize, name: &str) -> bool {
    let model = if pane == 0 {
        ui.get_local_full()
    } else {
        ui.get_remote_full()
    };
    (0..model.row_count()).any(|index| {
        model
            .row_data(index)
            .is_some_and(|entry| entry.is_dir && entry.name.as_str() == name)
    })
}

fn pane_child_path(state: &PaneState, name: &str) -> Result<String, String> {
    match state.kind {
        PaneKind::Local => {
            if name.is_empty()
                || matches!(name, "." | "..")
                || name.contains('/')
                || name.chars().any(char::is_control)
            {
                return Err("The folder name cannot be mirrored safely.".into());
            }
            Ok(PathBuf::from(&state.cwd)
                .join(name)
                .to_string_lossy()
                .into_owned())
        }
        PaneKind::Remote => {
            net::validate_remote_component(name).map_err(|error| error.to_string())?;
            Ok(join_remote(PathBuf::from(&state.cwd).join(name)))
        }
    }
}

fn navigate_synchronized_child(
    ui: &App,
    panes: &Panes,
    pane: usize,
    name: &str,
) -> Result<bool, String> {
    if !ui.get_synchronized_browsing() {
        return Ok(false);
    }
    let Some(_context) = synchronized_context(panes) else {
        stop_synchronized_browsing(
            ui,
            Some("Synchronized browsing stopped because a pane endpoint changed."),
        );
        return Ok(false);
    };
    let other = 1 - pane;
    if !pane_contains_directory(ui, pane, name) || !pane_contains_directory(ui, other, name) {
        return Err(format!(
            "Folder “{name}” must exist in both panes while synchronized browsing is enabled."
        ));
    }
    let targets = {
        let states = panes
            .lock()
            .map_err(|_| "Could not lock pane state.".to_string())?;
        [
            pane_child_path(&states[0], name)?,
            pane_child_path(&states[1], name)?,
        ]
    };
    let mut states = panes
        .lock()
        .map_err(|_| "Could not lock pane state.".to_string())?;
    for index in 0..2 {
        states[index].cwd = targets[index].clone();
        states[index].nav.go(targets[index].clone());
    }
    Ok(true)
}

fn pane_parent_path(state: &PaneState) -> String {
    match state.kind {
        PaneKind::Local => PathBuf::from(&state.cwd)
            .parent()
            .map(|parent| parent.to_string_lossy().into_owned())
            .unwrap_or_else(|| state.cwd.clone()),
        PaneKind::Remote => join_remote(
            Path::new(&state.cwd)
                .parent()
                .map(Path::to_path_buf)
                .unwrap_or_else(|| PathBuf::from("/")),
        ),
    }
}

fn synchronized_parent_is_within(
    identity: SynchronizedPaneIdentity,
    anchor: &str,
    parent: &str,
) -> bool {
    match identity {
        SynchronizedPaneIdentity::Local => Path::new(parent).starts_with(Path::new(anchor)),
        SynchronizedPaneIdentity::Remote(_) => remote_path_is_within(anchor, parent),
    }
}

fn navigate_synchronized_up(ui: &App, panes: &Panes) -> Result<bool, String> {
    if !ui.get_synchronized_browsing() {
        return Ok(false);
    }
    let Some(context) = synchronized_context(panes) else {
        stop_synchronized_browsing(
            ui,
            Some("Synchronized browsing stopped because a pane endpoint changed."),
        );
        return Ok(false);
    };
    let targets = {
        let states = panes
            .lock()
            .map_err(|_| "Could not lock pane state.".to_string())?;
        if (0..2).any(|pane| states[pane].cwd == context.anchors[pane]) {
            return Err("The synchronized browsing root has been reached.".into());
        }
        [pane_parent_path(&states[0]), pane_parent_path(&states[1])]
    };
    if (0..2).any(|pane| {
        !synchronized_parent_is_within(
            context.identities[pane],
            &context.anchors[pane],
            &targets[pane],
        )
    }) {
        return Err("Synchronized browsing cannot move above its paired roots.".into());
    }
    let mut states = panes
        .lock()
        .map_err(|_| "Could not lock pane state.".to_string())?;
    for pane in 0..2 {
        states[pane].cwd = targets[pane].clone();
        states[pane].nav.go(targets[pane].clone());
    }
    Ok(true)
}

fn wire_synchronized_browsing(ui: &App, panes: Panes) {
    let ui_weak = ui.as_weak();
    ui.on_toggle_synchronized_browsing(move || {
        let Some(ui) = ui_weak.upgrade() else { return };
        if ui.get_synchronized_browsing() {
            stop_synchronized_browsing(&ui, Some("Synchronized browsing disabled."));
            ui.set_error("".into());
            return;
        }
        if ui.get_local_loading() || ui.get_remote_loading() {
            ui.set_error("Wait until both directory listings are complete.".into());
            return;
        }
        let context = panes.lock().ok().and_then(|states| {
            Some(SynchronizedBrowsing {
                anchors: [states[0].cwd.clone(), states[1].cwd.clone()],
                identities: [
                    synchronized_pane_identity(&states[0])?,
                    synchronized_pane_identity(&states[1])?,
                ],
            })
        });
        let Some(context) = context else {
            ui.set_error("Both panes must contain an available local folder or server.".into());
            return;
        };
        if let Ok(mut synchronized) = SYNCHRONIZED_BROWSING.lock() {
            *synchronized = Some(context);
            ui.set_synchronized_browsing(true);
            ui.set_status(
                "Synchronized browsing enabled; shared child folders and Up move both panes."
                    .into(),
            );
            ui.set_error("".into());
        } else {
            ui.set_error("Could not enable synchronized browsing.".into());
        }
    });
}

fn navigate_pane(
    handle: &Handle,
    store: Arc<dyn CredentialStore>,
    panes: Panes,
    ui: Weak<App>,
    pane: usize,
    name: String,
) {
    if let Some(app) = ui.upgrade() {
        let synchronized = if name == ".." {
            navigate_synchronized_up(&app, &panes)
        } else {
            navigate_synchronized_child(&app, &panes, pane, &name)
        };
        match synchronized {
            Ok(true) => {
                app.set_error("".into());
                refresh_pane(handle, store.clone(), panes.clone(), ui.clone(), 0);
                refresh_pane(handle, store, panes, ui, 1);
                return;
            }
            Ok(false) => {}
            Err(error) => {
                app.set_error(error.into());
                return;
            }
        }
    }
    let next = {
        let p = panes.lock().expect("panes");
        let cwd = p[pane].cwd.clone();
        match p[pane].kind {
            PaneKind::Local => {
                let path = if name == ".." {
                    PathBuf::from(&cwd)
                        .parent()
                        .map(|x| x.to_path_buf())
                        .unwrap_or_else(|| PathBuf::from(&cwd))
                } else {
                    PathBuf::from(&cwd).join(name.as_str())
                };
                path.to_string_lossy().to_string()
            }
            PaneKind::Remote => {
                if name == ".." {
                    join_remote(
                        Path::new(&cwd)
                            .parent()
                            .map(|x| x.to_path_buf())
                            .unwrap_or_else(|| PathBuf::from("/")),
                    )
                } else {
                    join_remote(PathBuf::from(&cwd).join(name.as_str()))
                }
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

fn nav_pane_back(
    handle: &Handle,
    store: Arc<dyn CredentialStore>,
    panes: Panes,
    ui: Weak<App>,
    pane: usize,
) {
    if let Some(app) = ui.upgrade() {
        if app.get_synchronized_browsing() {
            app.set_error(
                "Back history is disabled while synchronized browsing is active; use Up or turn LINK off."
                    .into(),
            );
            return;
        }
    }
    let target = {
        let mut p = panes.lock().expect("panes");
        let t = p[pane].nav.back();
        if let Some(ref t) = t {
            p[pane].cwd = t.clone();
        }
        t
    };
    if target.is_some() {
        refresh_pane(handle, store, panes, ui, pane);
    }
}
fn nav_pane_forward(
    handle: &Handle,
    store: Arc<dyn CredentialStore>,
    panes: Panes,
    ui: Weak<App>,
    pane: usize,
) {
    if let Some(app) = ui.upgrade() {
        if app.get_synchronized_browsing() {
            app.set_error(
                "Forward history is disabled while synchronized browsing is active; use folders or turn LINK off."
                    .into(),
            );
            return;
        }
    }
    let target = {
        let mut p = panes.lock().expect("panes");
        let t = p[pane].nav.forward();
        if let Some(ref t) = t {
            p[pane].cwd = t.clone();
        }
        t
    };
    if target.is_some() {
        refresh_pane(handle, store, panes, ui, pane);
    }
}
fn nav_pane_up(
    handle: &Handle,
    store: Arc<dyn CredentialStore>,
    panes: Panes,
    ui: Weak<App>,
    pane: usize,
) {
    if let Some(app) = ui.upgrade() {
        match navigate_synchronized_up(&app, &panes) {
            Ok(true) => {
                app.set_error("".into());
                refresh_pane(handle, store.clone(), panes.clone(), ui.clone(), 0);
                refresh_pane(handle, store, panes, ui, 1);
                return;
            }
            Ok(false) => {}
            Err(error) => {
                app.set_error(error.into());
                return;
            }
        }
    }
    let parent = {
        let p = panes.lock().expect("panes");
        let cwd = p[pane].cwd.clone();
        match p[pane].kind {
            PaneKind::Local => PathBuf::from(&cwd)
                .parent()
                .map(|x| x.to_string_lossy().to_string())
                .unwrap_or(cwd),
            PaneKind::Remote => join_remote(
                Path::new(&cwd)
                    .parent()
                    .map(|x| x.to_path_buf())
                    .unwrap_or_else(|| PathBuf::from("/")),
            ),
        }
    };
    {
        let mut p = panes.lock().expect("panes");
        p[pane].nav.go(parent.clone());
        p[pane].cwd = parent;
    }
    refresh_pane(handle, store, panes, ui, pane);
}

// ── callback wiring ───────────────────────────────────────────────────────────

/// Connect a server into the ACTIVE pane (used by command palette / manager / auto-connect).
fn do_connect(
    handle: &Handle,
    store: Arc<dyn CredentialStore>,
    conns: ConnList,
    sessions: Sessions,
    panes: Panes,
    ui: Weak<App>,
    id: i32,
) {
    let pane = ui.upgrade().map(|u| active_pane_idx(&u)).unwrap_or(1);
    connect_into_pane(handle, store, conns, sessions, panes, ui, pane, id);
}

fn wire_connect(
    ui: &App,
    handle: &Handle,
    store: Arc<dyn CredentialStore>,
    conns: ConnList,
    sessions: Sessions,
    panes: Panes,
) {
    let (handle, ui_weak) = (handle.clone(), ui.as_weak());
    ui.on_connect_to(move |id| {
        let pane = ui_weak.upgrade().map(|u| active_pane_idx(&u)).unwrap_or(1);
        connect_into_pane(
            &handle,
            store.clone(),
            conns.clone(),
            sessions.clone(),
            panes.clone(),
            ui_weak.clone(),
            pane,
            id,
        );
    });
}

fn wire_refresh(ui: &App, handle: &Handle, store: Arc<dyn CredentialStore>, panes: Panes) {
    let (handle, ui_weak) = (handle.clone(), ui.as_weak());
    ui.on_refresh(move || {
        let pane = ui_weak.upgrade().map(|u| active_pane_idx(&u)).unwrap_or(0);
        refresh_pane(&handle, store.clone(), panes.clone(), ui_weak.clone(), pane);
    });
}

fn wire_file_filters(ui: &App) {
    let ui_weak = ui.as_weak();
    ui.on_filter_files(move |pane, query| {
        let Some(ui) = ui_weak.upgrade() else { return };
        let pane = usize::try_from(pane)
            .ok()
            .filter(|pane| *pane < 2)
            .unwrap_or(0);
        if pane == 0 {
            ui.set_local_file_filter(query);
        } else {
            ui.set_remote_file_filter(query);
        }
        apply_view_pane(&ui, pane);
        refresh_selected_path(&ui);
    });
}

fn empty_search_model() -> ModelRc<SearchRow> {
    ModelRc::from(Rc::new(VecModel::from(Vec::<SearchRow>::new())))
}

fn clear_remote_search_context(pane: usize) {
    if let Ok(mut contexts) = REMOTE_SEARCH_CONTEXT.lock() {
        contexts[pane] = None;
    }
}

fn remote_path_is_within(root: &str, candidate: &str) -> bool {
    let root = root.trim_end_matches('/');
    root.is_empty()
        || candidate == root
        || candidate
            .strip_prefix(root)
            .is_some_and(|suffix| suffix.starts_with('/'))
}

fn wire_remote_search(ui: &App, handle: &Handle, store: Arc<dyn CredentialStore>, panes: Panes) {
    {
        let runtime = handle.clone();
        let credential_store = store.clone();
        let panes = panes.clone();
        let ui_weak = ui.as_weak();
        ui.on_start_remote_search(move |pane, query| {
            let Some(ui) = ui_weak.upgrade() else { return };
            let Some(pane) = usize::try_from(pane).ok().filter(|pane| *pane < 2) else {
                return;
            };
            let generation = REMOTE_SEARCH_GENERATION[pane]
                .fetch_add(1, AtomicOrdering::Relaxed)
                .wrapping_add(1);
            if let Ok(mut active) = REMOTE_SEARCH_CANCEL.lock() {
                if let Some(previous) = active[pane].take() {
                    previous.store(true, AtomicOrdering::Relaxed);
                }
            }
            clear_remote_search_context(pane);
            let query = query.trim().to_string();
            ui.set_remote_search_open(true);
            ui.set_remote_search_pane(pane as i32);
            ui.set_remote_search_query(query.clone().into());
            ui.set_remote_search_results(empty_search_model());
            if query.chars().count() < 2
                || query.len() > net::MAX_REMOTE_SEARCH_QUERY_BYTES
                || query.chars().any(char::is_control)
            {
                ui.set_remote_search_running(false);
                ui.set_remote_search_summary(
                    "Enter at least 2 printable characters (256 UTF-8 bytes maximum).".into(),
                );
                return;
            }
            let Some((spec, cwd)) = panes.lock().ok().and_then(|states| {
                let state = states.get(pane)?;
                if !matches!(state.kind, PaneKind::Remote) {
                    return None;
                }
                Some((state.conn.clone()?, state.cwd.clone()))
            }) else {
                ui.set_remote_search_running(false);
                ui.set_remote_search_summary(
                    "Recursive search requires a connected remote pane.".into(),
                );
                return;
            };
            let Some(password) = password_for(&credential_store, &spec) else {
                ui.set_remote_search_running(false);
                ui.set_remote_search_summary("The active server credential is unavailable.".into());
                return;
            };

            let cancelled = Arc::new(AtomicBool::new(false));
            if let Ok(mut active) = REMOTE_SEARCH_CANCEL.lock() {
                active[pane] = Some(cancelled.clone());
            }
            if let Ok(mut contexts) = REMOTE_SEARCH_CONTEXT.lock() {
                contexts[pane] = Some(RemoteSearchContext {
                    generation,
                    connection_id: spec.id,
                    root: cwd.clone(),
                });
            }
            ui.set_remote_search_running(true);
            ui.set_remote_search_summary(
                format!("Searching under {cwd}; up to 20,000 entries and 500 results…").into(),
            );
            ui.set_error("".into());

            let request_ui = ui_weak.clone();
            let request_panes = panes.clone();
            runtime.spawn(async move {
                let result = match tokio::time::timeout(
                    Duration::from_secs(45),
                    net::search_remote(&spec, &password, &cwd, &query, cancelled.clone()),
                )
                .await
                {
                    Ok(result) => RemoteSearchTaskResult::Completed(result),
                    Err(_) => {
                        cancelled.store(true, AtomicOrdering::Relaxed);
                        RemoteSearchTaskResult::TimedOut
                    }
                };
                let _ = slint::invoke_from_event_loop(move || {
                    if REMOTE_SEARCH_GENERATION[pane].load(AtomicOrdering::Relaxed) != generation {
                        return;
                    }
                    if let Ok(mut active) = REMOTE_SEARCH_CANCEL.lock() {
                        active[pane] = None;
                    }
                    let Some(ui) = request_ui.upgrade() else {
                        return;
                    };
                    ui.set_remote_search_running(false);
                    if !remote_pane_request_is_current(&request_panes, pane, spec.id, &cwd) {
                        clear_remote_search_context(pane);
                        ui.set_remote_search_results(empty_search_model());
                        ui.set_remote_search_summary(
                            "Search result discarded because the pane changed.".into(),
                        );
                        return;
                    }
                    match result {
                        RemoteSearchTaskResult::Completed(Ok(report)) => {
                            let net::RemoteSearchReport {
                                mut hits,
                                entries_scanned,
                                directories_scanned,
                                truncated,
                            } = report;
                            hits.sort_by(|left, right| {
                                left.path.to_lowercase().cmp(&right.path.to_lowercase())
                            });
                            let count = hits.len();
                            let rows = hits
                                .into_iter()
                                .map(|hit| SearchRow {
                                    path: hit.path.into(),
                                    is_dir: hit.is_dir,
                                    size_text: if hit.is_dir {
                                        "—".into()
                                    } else {
                                        fmt_size(hit.size).into()
                                    },
                                })
                                .collect::<Vec<_>>();
                            ui.set_remote_search_results(ModelRc::from(Rc::new(VecModel::from(
                                rows,
                            ))));
                            ui.set_remote_search_summary(
                                format!(
                                    "{count} result(s); {entries_scanned} entries in {directories_scanned} directories scanned{}.",
                                    if truncated {
                                        "; bounded result — refine the query"
                                    } else {
                                        ""
                                    }
                                )
                                .into(),
                            );
                            ui.set_error("".into());
                        }
                        RemoteSearchTaskResult::Completed(Err(net::NetError::Cancelled)) => {
                            clear_remote_search_context(pane);
                            ui.set_remote_search_results(empty_search_model());
                            ui.set_remote_search_summary("Remote search cancelled.".into());
                        }
                        RemoteSearchTaskResult::Completed(Err(error)) => {
                            clear_remote_search_context(pane);
                            ui.set_remote_search_results(empty_search_model());
                            ui.set_remote_search_summary(
                                format!("Remote search failed safely: {error}").into(),
                            );
                        }
                        RemoteSearchTaskResult::TimedOut => {
                            clear_remote_search_context(pane);
                            ui.set_remote_search_results(empty_search_model());
                            ui.set_remote_search_summary(
                                "Remote search stopped at its 45-second safety deadline.".into(),
                            );
                        }
                    }
                });
            });
        });
    }
    {
        let ui_weak = ui.as_weak();
        ui.on_cancel_remote_search(move || {
            let pane = ui_weak
                .upgrade()
                .and_then(|ui| usize::try_from(ui.get_remote_search_pane()).ok())
                .filter(|pane| *pane < 2)
                .unwrap_or(1);
            if let Ok(active) = REMOTE_SEARCH_CANCEL.lock() {
                if let Some(cancelled) = active[pane].as_ref() {
                    cancelled.store(true, AtomicOrdering::Relaxed);
                }
            }
            if let Some(ui) = ui_weak.upgrade() {
                ui.set_remote_search_summary("Cancelling remote search…".into());
            }
        });
    }
    {
        let runtime = handle.clone();
        let credential_store = store;
        let panes = panes.clone();
        let ui_weak = ui.as_weak();
        ui.on_open_remote_search_result(move |pane, path, is_dir| {
            let Some(ui) = ui_weak.upgrade() else { return };
            let Some(pane) = usize::try_from(pane).ok().filter(|pane| *pane < 2) else {
                return;
            };
            let path = match validated_remote_path(path.as_str()) {
                Ok(path) => path,
                Err(error) => {
                    ui.set_error(format!("Invalid search result: {error}").into());
                    return;
                }
            };
            let context = REMOTE_SEARCH_CONTEXT
                .lock()
                .ok()
                .and_then(|contexts| contexts[pane].clone());
            let Some(context) = context else {
                ui.set_error("This search result is no longer tied to an active server.".into());
                return;
            };
            if !remote_path_is_within(&context.root, &path) {
                clear_remote_search_context(pane);
                ui.set_error("The search result falls outside the searched remote folder.".into());
                return;
            }
            if ui.get_synchronized_browsing() {
                stop_synchronized_browsing(
                    &ui,
                    Some("Synchronized browsing stopped after opening a search result."),
                );
            }
            let (target, file_name) = if is_dir {
                (path, None)
            } else {
                let file_name = Path::new(&path)
                    .file_name()
                    .and_then(|name| name.to_str())
                    .map(str::to_string);
                let parent = Path::new(&path)
                    .parent()
                    .map(Path::to_path_buf)
                    .unwrap_or_else(|| PathBuf::from("/"));
                (join_remote(parent), file_name)
            };
            let changed = panes.lock().ok().is_some_and(|mut states| {
                let Some(state) = states.get_mut(pane) else {
                    return false;
                };
                if !matches!(state.kind, PaneKind::Remote)
                    || state.conn.as_ref().map(|spec| spec.id) != Some(context.connection_id)
                    || state.cwd != context.root
                    || REMOTE_SEARCH_GENERATION[pane].load(AtomicOrdering::Relaxed)
                        != context.generation
                {
                    return false;
                }
                state.cwd = target.clone();
                state.nav.go(target.clone());
                true
            });
            clear_remote_search_context(pane);
            if !changed {
                ui.set_error("The searched server is no longer open in this pane.".into());
                return;
            }
            if pane == 0 {
                ui.set_local_file_filter("".into());
            } else {
                ui.set_remote_file_filter("".into());
            }
            if let Some(file_name) = file_name {
                ui.set_status(format!("Opening the folder containing {file_name}…").into());
            }
            refresh_pane(
                &runtime,
                credential_store.clone(),
                panes.clone(),
                ui_weak.clone(),
                pane,
            );
        });
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DirectoryComparisonEntry {
    name: String,
    is_dir: bool,
    size: u64,
    mtime: Option<i64>,
}

fn compare_directory_entry(
    left: Option<&DirectoryComparisonEntry>,
    right: Option<&DirectoryComparisonEntry>,
) -> &'static str {
    match (left, right) {
        (Some(_), None) => "left_only",
        (None, Some(_)) => "right_only",
        (Some(left), Some(right)) if left.is_dir != right.is_dir => "type",
        (Some(left), Some(_)) if left.is_dir => "same",
        (Some(left), Some(right)) if left.size != right.size => "size",
        (Some(left), Some(right)) => match (left.mtime, right.mtime) {
            (Some(left), Some(right)) if left.abs_diff(right) > 2 && left > right => "left_newer",
            (Some(left), Some(right)) if left.abs_diff(right) > 2 => "right_newer",
            _ => "same",
        },
        (None, None) => "same",
    }
}

fn comparison_status_label(status: &str, polish: bool) -> &'static str {
    match (status, polish) {
        ("left_only", true) => "Tylko po lewej",
        ("left_only", false) => "Left only",
        ("right_only", true) => "Tylko po prawej",
        ("right_only", false) => "Right only",
        ("type", true) => "Inny typ",
        ("type", false) => "Type differs",
        ("size", true) => "Inny rozmiar",
        ("size", false) => "Size differs",
        ("left_newer", true) => "Lewy nowszy",
        ("left_newer", false) => "Left newer",
        ("right_newer", true) => "Prawy nowszy",
        ("right_newer", false) => "Right newer",
        ("same", true) => "Zgodne",
        _ => "Same",
    }
}

fn directory_comparison_snapshot(ui: &App, pane: usize) -> Vec<DirectoryComparisonEntry> {
    let model = if pane == 0 {
        ui.get_local_full()
    } else {
        ui.get_remote_full()
    };
    let sizes = TRUE_SIZE
        .lock()
        .ok()
        .map(|sizes| {
            sizes
                .iter()
                .filter(|((candidate, _), _)| *candidate == pane)
                .map(|((_, name), size)| (name.clone(), *size))
                .collect::<HashMap<_, _>>()
        })
        .unwrap_or_default();
    let mtimes = TRUE_MTIME
        .lock()
        .ok()
        .map(|mtimes| {
            mtimes
                .iter()
                .filter(|((candidate, _), _)| *candidate == pane)
                .map(|((_, name), mtime)| (name.clone(), *mtime))
                .collect::<HashMap<_, _>>()
        })
        .unwrap_or_default();
    (0..model.row_count())
        .filter_map(|index| model.row_data(index))
        .map(|row| {
            let name = row.name.to_string();
            DirectoryComparisonEntry {
                size: sizes
                    .get(&name)
                    .copied()
                    .unwrap_or_else(|| u64::try_from(row.size).unwrap_or(0)),
                mtime: mtimes
                    .get(&name)
                    .copied()
                    .or_else(|| (row.mtime > 0).then_some(row.mtime as i64)),
                name,
                is_dir: row.is_dir,
            }
        })
        .collect()
}

fn comparison_entry_detail(entry: Option<&DirectoryComparisonEntry>, polish: bool) -> String {
    let Some(entry) = entry else {
        return "—".into();
    };
    let kind = if entry.is_dir {
        if polish { "Katalog" } else { "Folder" }.to_string()
    } else {
        fmt_size(entry.size)
    };
    entry
        .mtime
        .filter(|mtime| *mtime > 0)
        .map(|mtime| format!("{kind} · {}", fmt_date(mtime)))
        .unwrap_or(kind)
}

fn populate_directory_comparison(ui: &App) {
    let left = directory_comparison_snapshot(ui, 0)
        .into_iter()
        .map(|entry| (entry.name.clone(), entry))
        .collect::<BTreeMap<_, _>>();
    let right = directory_comparison_snapshot(ui, 1)
        .into_iter()
        .map(|entry| (entry.name.clone(), entry))
        .collect::<BTreeMap<_, _>>();
    let names = left
        .keys()
        .chain(right.keys())
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    let polish = crate::I18n::get(ui).get_locale().as_str() == "pl";
    let differences_only = ui.get_comparison_differences_only();
    let mut differences = 0usize;
    let total = names.len();
    let rows = names
        .into_iter()
        .filter_map(|name| {
            let left = left.get(&name);
            let right = right.get(&name);
            let status = compare_directory_entry(left, right);
            if status != "same" {
                differences += 1;
            }
            if differences_only && status == "same" {
                return None;
            }
            Some(ComparisonRow {
                name: name.into(),
                is_dir: left.or(right).is_some_and(|entry| entry.is_dir),
                left_detail: comparison_entry_detail(left, polish).into(),
                right_detail: comparison_entry_detail(right, polish).into(),
                status: status.into(),
                status_label: comparison_status_label(status, polish).into(),
            })
        })
        .collect::<Vec<_>>();
    ui.set_comparison_results(ModelRc::from(Rc::new(VecModel::from(rows))));
    ui.set_comparison_summary(
        if polish {
            format!("{total} nazw · {differences} różnic · tolerancja czasu 2 s")
        } else {
            format!("{total} names · {differences} differences · 2 s timestamp tolerance")
        }
        .into(),
    );
}

fn wire_directory_comparison(ui: &App) {
    {
        let ui_weak = ui.as_weak();
        ui.on_open_directory_comparison(move || {
            let Some(ui) = ui_weak.upgrade() else { return };
            if ui.get_local_loading() || ui.get_remote_loading() {
                ui.set_error("Wait until both directory listings are complete.".into());
                return;
            }
            populate_directory_comparison(&ui);
            ui.set_comparison_open(true);
            ui.set_error("".into());
        });
    }
    {
        let ui_weak = ui.as_weak();
        ui.on_set_comparison_differences_only(move |differences_only| {
            if let Some(ui) = ui_weak.upgrade() {
                ui.set_comparison_differences_only(differences_only);
                populate_directory_comparison(&ui);
            }
        });
    }
    {
        let ui_weak = ui.as_weak();
        ui.on_reveal_comparison_row(move |name| {
            let Some(ui) = ui_weak.upgrade() else { return };
            ui.set_local_file_filter("".into());
            ui.set_remote_file_filter("".into());
            apply_view_pane(&ui, 0);
            apply_view_pane(&ui, 1);
            let mut found = 0usize;
            for pane in 0..2 {
                let entries = pane_entries(&ui, pane);
                let index = (0..entries.row_count()).find(|index| {
                    entries
                        .row_data(*index)
                        .is_some_and(|entry| entry.name.as_str() == name.as_str())
                });
                if let Some(index) = index {
                    select_entry(&ui, pane, index as i32, false, false);
                    found += 1;
                } else {
                    set_selection_flags(&ui, pane, vec![false; entries.row_count()]);
                    if pane == 0 {
                        ui.set_local_selected(-1);
                    } else {
                        ui.set_remote_selected(-1);
                    }
                }
            }
            refresh_selected_path(&ui);
            ui.set_status(format!("Selected “{}” in {found} pane(s).", name.as_str()).into());
        });
    }
}

fn path_rows(paths: impl IntoIterator<Item = String>) -> ModelRc<PathRow> {
    ModelRc::from(Rc::new(VecModel::from(
        paths
            .into_iter()
            .map(|path| PathRow {
                label: path.clone().into(),
                path: path.into(),
            })
            .collect::<Vec<_>>(),
    )))
}

fn remote_places_for(
    settings: &store::settings::Settings,
    spec: &ConnectionSpec,
) -> Vec<store::settings::RemotePlace> {
    let Ok(fingerprint) = sync_endpoint_fingerprint(spec) else {
        return Vec::new();
    };
    settings
        .remote_places
        .iter()
        .filter(|place| {
            place.connection_id == spec.id.0 && place.endpoint_fingerprint == fingerprint
        })
        .cloned()
        .collect()
}

fn populate_path_editor(ui: &App, panes: &Panes, pane: usize, open: bool) {
    let Some((cwd, recent, kind, spec)) = panes.lock().ok().and_then(|panes| {
        panes.get(pane).map(|state| {
            (
                state.cwd.clone(),
                state.nav.recent(10),
                state.kind.clone(),
                state.conn.clone(),
            )
        })
    }) else {
        return;
    };
    let remote = matches!(kind, PaneKind::Remote);
    let places = spec
        .as_ref()
        .map(|spec| remote_places_for(&store::settings::load(), spec))
        .unwrap_or_default()
        .into_iter()
        .map(|place| place.path)
        .collect::<Vec<_>>();
    ui.set_path_editor_pane(pane as i32);
    ui.set_path_editor_value(cwd.into());
    ui.set_path_editor_remote(remote);
    ui.set_path_recent(path_rows(recent));
    ui.set_path_places(path_rows(places));
    if open {
        ui.set_path_editor_open(true);
        ui.set_error("".into());
    }
}

fn validated_remote_path(raw: &str) -> Result<String, String> {
    let path = raw.trim();
    if path.is_empty()
        || path.len() > 4 * 1024
        || !path.starts_with('/')
        || path.contains('\\')
        || path.chars().any(char::is_control)
        || path
            .split('/')
            .any(|component| matches!(component, "." | ".."))
    {
        return Err(
            "Remote path must be an absolute, bounded path without . or .. segments.".into(),
        );
    }
    Ok(join_remote(PathBuf::from(path)))
}

fn validated_local_path(raw: &str) -> Result<String, String> {
    let raw = raw.trim();
    if raw.is_empty() || raw.len() > 16 * 1024 || raw.chars().any(char::is_control) {
        return Err(
            "Local path is empty, contains control characters, or exceeds its limit.".into(),
        );
    }
    let path = if raw == "~" {
        home_dir()
    } else if let Some(relative) = raw.strip_prefix("~/") {
        home_dir().join(relative)
    } else {
        PathBuf::from(raw)
    };
    if !path.is_absolute() {
        return Err("Local path must be absolute or start with ~/.".into());
    }
    let path = path
        .canonicalize()
        .map_err(|error| format!("Local folder is unavailable: {error}"))?;
    let metadata = std::fs::symlink_metadata(&path)
        .map_err(|error| format!("Could not inspect local folder: {error}"))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err("Local path must resolve to a real directory.".into());
    }
    Ok(path.to_string_lossy().into_owned())
}

fn wire_path_editor(ui: &App, handle: &Handle, store: Arc<dyn CredentialStore>, panes: Panes) {
    {
        let panes = panes.clone();
        let ui_weak = ui.as_weak();
        ui.on_open_path_editor(move |pane| {
            let Some(ui) = ui_weak.upgrade() else { return };
            let pane = usize::try_from(pane)
                .ok()
                .filter(|pane| *pane < 2)
                .unwrap_or(0);
            populate_path_editor(&ui, &panes, pane, true);
        });
    }
    {
        let runtime = handle.clone();
        let credential_store = store.clone();
        let panes = panes.clone();
        let ui_weak = ui.as_weak();
        ui.on_navigate_path(move |pane, raw| {
            let pane = match usize::try_from(pane).ok().filter(|pane| *pane < 2) {
                Some(pane) => pane,
                None => return,
            };
            if let Some(ui) = ui_weak.upgrade() {
                if ui.get_synchronized_browsing() {
                    stop_synchronized_browsing(
                        &ui,
                        Some("Synchronized browsing stopped after direct path navigation."),
                    );
                }
            }
            let raw = raw.to_string();
            let (kind, original_cwd) = match panes.lock() {
                Ok(states) => (states[pane].kind.clone(), states[pane].cwd.clone()),
                Err(_) => return,
            };
            match kind {
                PaneKind::Remote => match validated_remote_path(&raw) {
                    Ok(path) => {
                        if let Ok(mut states) = panes.lock() {
                            states[pane].cwd = path.clone();
                            states[pane].nav.go(path);
                        }
                        refresh_pane(
                            &runtime,
                            credential_store.clone(),
                            panes.clone(),
                            ui_weak.clone(),
                            pane,
                        );
                    }
                    Err(error) => {
                        if let Some(ui) = ui_weak.upgrade() {
                            ui.set_error(error.into());
                            populate_path_editor(&ui, &panes, pane, true);
                        }
                    }
                },
                PaneKind::Local => {
                    let runtime_for_refresh = runtime.clone();
                    let credential_store = credential_store.clone();
                    let panes = panes.clone();
                    let ui = ui_weak.clone();
                    runtime.spawn(async move {
                        let result =
                            tokio::task::spawn_blocking(move || validated_local_path(&raw))
                                .await
                                .map_err(|error| error.to_string())
                                .and_then(|result| result);
                        let _ = slint::invoke_from_event_loop(move || match result {
                            Ok(path) => {
                                let current = panes.lock().ok().and_then(|mut states| {
                                    let state = states.get_mut(pane)?;
                                    if !matches!(state.kind, PaneKind::Local)
                                        || state.cwd != original_cwd
                                    {
                                        return None;
                                    }
                                    state.cwd = path.clone();
                                    state.nav.go(path);
                                    Some(())
                                });
                                if current.is_some() {
                                    refresh_pane(
                                        &runtime_for_refresh,
                                        credential_store,
                                        panes,
                                        ui,
                                        pane,
                                    );
                                }
                            }
                            Err(error) => {
                                if let Some(ui) = ui.upgrade() {
                                    ui.set_error(error.into());
                                    populate_path_editor(&ui, &panes, pane, true);
                                }
                            }
                        });
                    });
                }
            }
        });
    }
    {
        let panes = panes.clone();
        let ui_weak = ui.as_weak();
        ui.on_add_current_remote_place(move |pane| {
            let Some(ui) = ui_weak.upgrade() else { return };
            let Some(pane) = usize::try_from(pane).ok().filter(|pane| *pane < 2) else {
                return;
            };
            let Some((spec, path)) = panes.lock().ok().and_then(|states| {
                let state = states.get(pane)?;
                if !matches!(state.kind, PaneKind::Remote) {
                    return None;
                }
                Some((state.conn.clone()?, state.cwd.clone()))
            }) else {
                ui.set_error("Places are available only for a connected remote pane.".into());
                return;
            };
            let Ok(endpoint_fingerprint) = sync_endpoint_fingerprint(&spec) else {
                ui.set_error("Could not identify the active endpoint safely.".into());
                return;
            };
            let mut settings = store::settings::load();
            if settings.remote_places.iter().any(|place| {
                place.endpoint_fingerprint == endpoint_fingerprint && place.path == path
            }) {
                ui.set_status("This server place is already saved.".into());
                return;
            }
            if settings.remote_places.len() >= store::settings::MAX_REMOTE_PLACES {
                ui.set_error("The saved remote-place limit has been reached.".into());
                return;
            }
            settings.remote_places.push(store::settings::RemotePlace {
                connection_id: spec.id.0,
                endpoint_fingerprint,
                path,
            });
            match store::settings::try_save(&settings) {
                Ok(()) => {
                    ui.set_status("Current remote folder added to Places.".into());
                    ui.set_error("".into());
                    populate_path_editor(&ui, &panes, pane, false);
                }
                Err(error) => ui.set_error(format!("Could not save remote Place: {error}").into()),
            }
        });
    }
    {
        let panes = panes.clone();
        let ui_weak = ui.as_weak();
        ui.on_remove_remote_place(move |index| {
            let Some(ui) = ui_weak.upgrade() else { return };
            let pane = usize::try_from(ui.get_path_editor_pane())
                .ok()
                .filter(|pane| *pane < 2)
                .unwrap_or(0);
            let Some(spec) = panes.lock().ok().and_then(|states| {
                let state = states.get(pane)?;
                matches!(state.kind, PaneKind::Remote)
                    .then(|| state.conn.clone())
                    .flatten()
            }) else {
                return;
            };
            let mut settings = store::settings::load();
            let places = remote_places_for(&settings, &spec);
            let Some(place) = usize::try_from(index)
                .ok()
                .and_then(|index| places.get(index))
                .cloned()
            else {
                return;
            };
            settings
                .remote_places
                .retain(|candidate| candidate != &place);
            match store::settings::try_save(&settings) {
                Ok(()) => {
                    ui.set_status("Remote Place removed.".into());
                    ui.set_error("".into());
                    populate_path_editor(&ui, &panes, pane, false);
                }
                Err(error) => {
                    ui.set_error(format!("Could not remove remote Place: {error}").into())
                }
            }
        });
    }
}

fn wire_remote_trash(ui: &App, handle: &Handle, store: Arc<dyn CredentialStore>, panes: Panes) {
    let runtime = handle.clone();
    let ui_weak = ui.as_weak();
    ui.on_open_remote_trash(move |pane| {
        let Some(pane) = usize::try_from(pane).ok().filter(|pane| *pane < 2) else {
            return;
        };
        let (spec, cwd) = match panes.lock() {
            Ok(states) => match (&states[pane].kind, &states[pane].conn) {
                (PaneKind::Remote, Some(spec)) => (spec.clone(), states[pane].cwd.clone()),
                _ => return,
            },
            Err(_) => return,
        };
        if cwd
            .split('/')
            .any(|component| component == REMOTE_QUARANTINE_DIR)
        {
            if let Some(ui) = ui_weak.upgrade() {
                ui.set_status("Already viewing Remote Trash.".into());
                ui.set_error("".into());
            }
            return;
        }
        let Some(password) = password_for(&store, &spec) else {
            if let Some(ui) = ui_weak.upgrade() {
                ui.set_error("Missing credential; could not open Remote Trash.".into());
            }
            return;
        };
        let task_runtime = runtime.clone();
        let task_store = store.clone();
        let task_panes = panes.clone();
        let task_ui = ui_weak.clone();
        runtime.spawn(async move {
            let exists = net::remote_exists(&spec, &password, &cwd, REMOTE_QUARANTINE_DIR).await;
            if !pane_request_is_current(&task_panes, pane, true, Some(spec.id), &cwd) {
                return;
            }
            match exists {
                Ok(true) => {
                    let trash = join_remote(PathBuf::from(&cwd).join(REMOTE_QUARANTINE_DIR));
                    if let Ok(mut states) = task_panes.lock() {
                        states[pane].cwd = trash.clone();
                        states[pane].nav.go(trash);
                    }
                    refresh_pane(&task_runtime, task_store, task_panes, task_ui, pane);
                }
                Ok(false) => {
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(ui) = task_ui.upgrade() {
                            ui.set_status("Remote Trash is empty.".into());
                            ui.set_error("".into());
                        }
                    });
                }
                Err(error) => {
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(ui) = task_ui.upgrade() {
                            ui.set_error(format!("Could not open Remote Trash: {error}").into());
                        }
                    });
                }
            }
        });
    });
}

fn wire_restore_remote_trash(
    ui: &App,
    handle: &Handle,
    store: Arc<dyn CredentialStore>,
    panes: Panes,
) {
    let runtime = handle.clone();
    let ui_weak = ui.as_weak();
    ui.on_restore_remote_trash(move |pane_alias, name| {
        let Ok(pane) = PaneId::try_from(pane_alias.as_str()) else {
            if let Some(ui) = ui_weak.upgrade() {
                ui.set_error("unknown pane identifier".into());
            }
            return;
        };
        let pane = pane.index();
        let name = name.to_string();
        if net::validate_remote_component(&name).is_err() {
            if let Some(ui) = ui_weak.upgrade() {
                ui.set_error("Invalid quarantined filename; nothing was changed.".into());
            }
            return;
        }
        let (spec, cwd) = match panes.lock() {
            Ok(states) => match (&states[pane].kind, &states[pane].conn) {
                (PaneKind::Remote, Some(spec)) => (spec.clone(), states[pane].cwd.clone()),
                _ => return,
            },
            Err(_) => return,
        };
        let (_, original_parent, bucket) = match remote_quarantine_restore_context(&cwd) {
            Ok(context) => context,
            Err(error) => {
                if let Some(ui) = ui_weak.upgrade() {
                    ui.set_error(error.into());
                }
                return;
            }
        };
        let Some(password) = password_for(&store, &spec) else {
            if let Some(ui) = ui_weak.upgrade() {
                ui.set_error("Missing credential; nothing was restored.".into());
            }
            return;
        };
        let source = join_remote(PathBuf::from(&cwd).join(&name));
        let destination = join_remote(PathBuf::from(&original_parent).join(&name));
        let task_runtime = runtime.clone();
        let task_store = store.clone();
        let task_panes = panes.clone();
        let task_ui = ui_weak.clone();
        runtime.spawn(async move {
            let result = match net::remote_exists(&spec, &password, &original_parent, &name).await {
                Ok(true) => Err(format!(
                    "{name} already exists at the original location; nothing was overwritten"
                )),
                Ok(false) => {
                    match net::rename_remote(&spec, &password, &source, &destination).await {
                        Ok(()) => {
                            let warning = net::delete_remote(&spec, &password, &bucket, true)
                                .await
                                .err()
                                .map(|error| {
                                    format!("restored, but the empty trash bucket remains: {error}")
                                });
                            Ok(warning)
                        }
                        Err(error) => {
                            Err(format!("restore failed; nothing was overwritten: {error}"))
                        }
                    }
                }
                Err(error) => Err(format!(
                    "could not verify the original location; nothing was restored: {error}"
                )),
            };
            if !pane_request_is_current(&task_panes, pane, true, Some(spec.id), &cwd) {
                return;
            }
            match result {
                Ok(warning) => {
                    if let Ok(mut states) = task_panes.lock() {
                        states[pane].cwd = original_parent.clone();
                        states[pane].nav.go(original_parent);
                    }
                    let status_name = name.clone();
                    let status_ui = task_ui.clone();
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(ui) = status_ui.upgrade() {
                            ui.set_status(
                                format!("restored {status_name} from Remote Trash").into(),
                            );
                            ui.set_error(warning.unwrap_or_default().into());
                        }
                    });
                    refresh_pane(&task_runtime, task_store, task_panes, task_ui, pane);
                }
                Err(error) => {
                    let _ = slint::invoke_from_event_loop(move || {
                        if let Some(ui) = task_ui.upgrade() {
                            ui.set_error(error.into());
                        }
                    });
                }
            }
        });
    });
}

/// Wire navigate + back/forward/up for one pane (0 → navigate_local/nav_local_*, 1 → remote).
fn wire_nav_pane(
    ui: &App,
    handle: &Handle,
    store: Arc<dyn CredentialStore>,
    panes: Panes,
    pane: usize,
) {
    {
        let (h, st, pn, uw) = (handle.clone(), store.clone(), panes.clone(), ui.as_weak());
        let cb = move |name: slint::SharedString| {
            navigate_pane(
                &h,
                st.clone(),
                pn.clone(),
                uw.clone(),
                pane,
                name.to_string(),
            )
        };
        if pane == 0 {
            ui.on_navigate_local(cb);
        } else {
            ui.on_navigate_remote(cb);
        }
    }
    {
        let (h, st, pn, uw) = (handle.clone(), store.clone(), panes.clone(), ui.as_weak());
        let cb = move || nav_pane_back(&h, st.clone(), pn.clone(), uw.clone(), pane);
        if pane == 0 {
            ui.on_nav_local_back(cb);
        } else {
            ui.on_nav_remote_back(cb);
        }
    }
    {
        let (h, st, pn, uw) = (handle.clone(), store.clone(), panes.clone(), ui.as_weak());
        let cb = move || nav_pane_forward(&h, st.clone(), pn.clone(), uw.clone(), pane);
        if pane == 0 {
            ui.on_nav_local_forward(cb);
        } else {
            ui.on_nav_remote_forward(cb);
        }
    }
    {
        let (h, st, pn, uw) = (handle.clone(), store.clone(), panes.clone(), ui.as_weak());
        let cb = move || nav_pane_up(&h, st.clone(), pn.clone(), uw.clone(), pane);
        if pane == 0 {
            ui.on_nav_local_up(cb);
        } else {
            ui.on_nav_remote_up(cb);
        }
    }
}

/// Toolbar certificate action. New blanket verification bypasses are forbidden: clicking the
/// shield only removes an existing pin or migrates an old `accept_invalid_tls` exception back to
/// strict platform verification. A self-signed certificate is trusted through the fingerprint
/// dialog, never through an unauthenticated on/off switch.
fn wire_toggle_tls(ui: &App, conns: ConnList, sessions: Sessions, panes: Panes) {
    let ui_weak = ui.as_weak();
    ui.on_toggle_tls(move || {
        let Some(ui) = ui_weak.upgrade() else { return };
        let pane = active_pane_idx(&ui);
        let Some(connection_id) = panes
            .lock()
            .ok()
            .and_then(|states| states[pane].conn.as_ref().map(|spec| spec.id))
        else {
            ui.set_accept_any_cert(false);
            ui.set_error("Select a saved server before changing its TLS policy.".into());
            return;
        };
        let mut candidate = conns.lock().expect("connections lock").clone();
        let Some(position) = candidate.iter().position(|spec| spec.id == connection_id) else {
            ui.set_error("The active server is no longer saved.".into());
            return;
        };
        let had_pin = candidate[position].tls_pinned_sha256.is_some();
        let had_legacy_bypass = candidate[position].accept_invalid_tls;
        if !had_pin && !had_legacy_bypass {
            ui.set_accept_any_cert(false);
            ui.set_error("".into());
            ui.set_status(
                "Strict system certificate verification is active. A rejected self-signed certificate will show a fingerprint confirmation."
                    .into(),
            );
            return;
        }
        candidate[position].accept_invalid_tls = false;
        candidate[position].tls_pinned_sha256 = None;
        if let Err(e) = store::save_metadata(&candidate) {
            ui.set_accept_any_cert(true);
            ui.set_error(format!("Could not reset certificate trust: {e}").into());
            return;
        }
        let updated = candidate[position].clone();
        *conns.lock().expect("connections lock") = candidate;
        if let Ok(mut pool) = sessions.lock() {
            for session in pool
                .iter_mut()
                .filter(|session| session.conn.id == connection_id)
            {
                session.conn = updated.clone();
            }
        }
        if let Ok(mut states) = panes.lock() {
            for state in states.iter_mut() {
                if state
                    .conn
                    .as_ref()
                    .is_some_and(|spec| spec.id == connection_id)
                {
                    state.conn = Some(updated.clone());
                }
            }
        }
        ui.set_accept_any_cert(false);
        ui.set_error("".into());
        ui.set_status(
            if had_pin {
                "Saved certificate pin removed. Strict system verification will be used on reconnect."
            } else {
                "Legacy unsafe certificate bypass removed. Strict verification is active."
            }
            .into(),
        );
    });
}

/// Theme toggle: flip the Tokens.theme global (drives all colors) and persist the choice.
fn wire_toggle_theme(ui: &App) {
    let ui_weak = ui.as_weak();
    ui.on_toggle_theme(move || {
        let Some(ui) = ui_weak.upgrade() else { return };
        let g = crate::Tokens::get(&ui);
        let next = if g.get_theme() == "dark" {
            "light"
        } else {
            "dark"
        };
        let mut s = store::settings::load();
        s.theme = next.to_string();
        match store::settings::try_save(&s) {
            Ok(()) => {
                g.set_theme(next.into());
                ui.set_settings_theme(next.into());
                ui.set_error("".into());
            }
            Err(error) => ui.set_error(format!("Could not save theme: {error}").into()),
        }
    });
}

/// "Copy Path" context action: surface the absolute path of the right-clicked entry in the
/// status bar. (macOS system clipboard write isn't exposed via Slint's stable API on our
/// backend, so we show it in the status line — copyable from there.)
fn wire_copy_path(ui: &App) {
    let ui_weak = ui.as_weak();
    ui.on_copy_path(move |pane, name| {
        let Some(ui) = ui_weak.upgrade() else { return };
        let Some(pane) = pane_alias_index(&ui, pane.as_str()) else {
            return;
        };
        let name = name.to_string();
        let cwd = if pane == PaneId::Left.index() {
            ui.get_local_cwd().to_string()
        } else {
            ui.get_remote_cwd().to_string()
        };
        let full = if pane == PaneId::Left.index() {
            PathBuf::from(&cwd)
                .join(&name)
                .to_string_lossy()
                .into_owned()
        } else {
            join_remote(PathBuf::from(&cwd).join(&name))
        };
        ui.set_status(format!("path: {full}").into());
        ui.set_error("".into());
    });
}

fn wire_calculate_folder_size(
    ui: &App,
    handle: &Handle,
    store: Arc<dyn CredentialStore>,
    panes: Panes,
) {
    let handle = handle.clone();
    let ui_weak = ui.as_weak();
    ui.on_calculate_folder_size(move |pane_alias, name| {
        let Ok(pane) = PaneId::try_from(pane_alias.as_str()) else {
            if let Some(ui) = ui_weak.upgrade() {
                ui.set_error("unknown pane identifier".into());
            }
            return;
        };
        let pane = pane.index();
        let name = name.to_string();
        if net::validate_remote_component(&name).is_err() {
            if let Some(ui) = ui_weak.upgrade() {
                ui.set_error("Invalid folder name.".into());
            }
            return;
        }
        let (kind, spec, cwd) = match panes.lock() {
            Ok(states) => {
                let state = &states[pane];
                (state.kind.clone(), state.conn.clone(), state.cwd.clone())
            }
            Err(_) => return,
        };
        if let Some(ui) = ui_weak.upgrade() {
            set_pane_entry_metadata_state(&ui, pane, &name, "loading");
            ui.set_status("Calculating folder size...".into());
            ui.set_error("".into());
        }

        match kind {
            PaneKind::Local => {
                let path = PathBuf::from(&cwd).join(&name);
                let panes = panes.clone();
                let request_ui = ui_weak.clone();
                handle.spawn(async move {
                    let _permit = loop {
                        if !pane_request_is_current(&panes, pane, false, None, &cwd) {
                            return;
                        }
                        if let Some(permit) = RecursiveMetadataPermit::try_acquire() {
                            break permit;
                        }
                        tokio::time::sleep(Duration::from_millis(20)).await;
                    };
                    let stats = match tokio::task::spawn_blocking(move || {
                        local_folder_stats_cached(&path, MAX_LOCAL_FOLDER_STAT_FILES)
                    })
                    .await
                    {
                        Ok(stats) => stats,
                        Err(error) => {
                            let message = error.to_string();
                            let panes = panes.clone();
                            let cwd = cwd.clone();
                            let _ = slint::invoke_from_event_loop(move || {
                                if !pane_request_is_current(&panes, pane, false, None, &cwd) {
                                    return;
                                }
                                if let Some(ui) = request_ui.upgrade() {
                                    set_pane_entry_metadata_state(&ui, pane, &name, "unavailable");
                                    ui.set_error(
                                        format!("Could not calculate folder size: {message}")
                                            .into(),
                                    );
                                }
                            });
                            return;
                        }
                    };
                    let panes = panes.clone();
                    let request_cwd = cwd.clone();
                    let _ = slint::invoke_from_event_loop(move || {
                        if !pane_request_is_current(&panes, pane, false, None, &request_cwd) {
                            return;
                        }
                        let Some(ui) = request_ui.upgrade() else {
                            return;
                        };
                        let entry = RemoteEntry {
                            name: name.clone(),
                            is_dir: true,
                            size: stats.size,
                            mtime: stats
                                .newest_mtime
                                .or_else(|| existing_entry_mtime(pane, &name)),
                            permissions: None,
                            owner: None,
                            group: None,
                        };
                        update_pane_entry_metadata(&ui, pane, &entry, stats.truncated, "ready");
                        ui.set_status(format!("Folder size: {}", fmt_size(stats.size)).into());
                    });
                });
            }
            PaneKind::Remote => {
                let Some(spec) = spec else {
                    return;
                };
                let Some(password) = password_for(&store, &spec) else {
                    if let Some(ui) = ui_weak.upgrade() {
                        set_pane_entry_metadata_state(&ui, pane, &name, "unavailable");
                        ui.set_error("Missing credential.".into());
                    }
                    return;
                };
                let remote_path = join_remote(PathBuf::from(&cwd).join(&name));
                let panes = panes.clone();
                let request_ui = ui_weak.clone();
                handle.spawn(async move {
                    let _permit = loop {
                        if !pane_request_is_current(&panes, pane, true, Some(spec.id), &cwd) {
                            return;
                        }
                        if let Some(permit) = RecursiveMetadataPermit::try_acquire() {
                            break permit;
                        }
                        tokio::time::sleep(Duration::from_millis(20)).await;
                    };
                    let result = if let Some(stats) = cached_remote_folder_stats(
                        spec.id,
                        &remote_path,
                        MAX_REMOTE_FOLDER_STAT_FILES,
                    ) {
                        Ok(stats)
                    } else {
                        match tokio::time::timeout(
                            Duration::from_secs(30),
                            net::remote_tree_stats(
                                &spec,
                                &password,
                                &remote_path,
                                MAX_REMOTE_FOLDER_STAT_FILES,
                            ),
                        )
                        .await
                        {
                            Ok(Ok(stats)) => {
                                store_remote_folder_stats(
                                    spec.id,
                                    remote_path,
                                    MAX_REMOTE_FOLDER_STAT_FILES,
                                    &stats,
                                );
                                Ok(stats)
                            }
                            Ok(Err(error)) => Err(error.to_string()),
                            Err(_) => Err("folder-size request timed out".to_string()),
                        }
                    };
                    let panes = panes.clone();
                    let request_cwd = cwd.clone();
                    let connection_id = spec.id;
                    let _ = slint::invoke_from_event_loop(move || {
                        if !pane_request_is_current(
                            &panes,
                            pane,
                            true,
                            Some(connection_id),
                            &request_cwd,
                        ) {
                            return;
                        }
                        let Some(ui) = request_ui.upgrade() else {
                            return;
                        };
                        match result {
                            Ok(stats) => {
                                let entry = RemoteEntry {
                                    name: name.clone(),
                                    is_dir: true,
                                    size: stats.size,
                                    mtime: stats
                                        .newest_mtime
                                        .or_else(|| existing_entry_mtime(pane, &name)),
                                    permissions: None,
                                    owner: None,
                                    group: None,
                                };
                                update_pane_entry_metadata(
                                    &ui,
                                    pane,
                                    &entry,
                                    stats.truncated,
                                    "ready",
                                );
                                ui.set_status(
                                    format!("Folder size: {}", fmt_size(stats.size)).into(),
                                );
                            }
                            Err(error) => {
                                set_pane_entry_metadata_state(&ui, pane, &name, "unavailable");
                                ui.set_error(
                                    format!("Could not calculate folder size: {error}").into(),
                                );
                            }
                        }
                    });
                });
            }
        }
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
        let id = ui_weak
            .upgrade()
            .map(|u| u.get_selected_connection())
            .unwrap_or(-1);
        if id >= 0 {
            do_connect(
                &handle,
                store.clone(),
                conns.clone(),
                sessions.clone(),
                panes.clone(),
                ui_weak.clone(),
                id,
            );
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

/// Entry point for delete intent. Confirmation can be skipped only for reversible operations
/// (local Trash or remote quarantine). A permanent remote delete always opens the dialog.
fn request_delete(
    ui: &App,
    handle: &Handle,
    store: Arc<dyn CredentialStore>,
    panes: Panes,
    pane: usize,
    name: String,
    is_dir: bool,
) {
    let (kind, cwd) = match panes.lock() {
        Ok(states) if pane < states.len() => (states[pane].kind.clone(), states[pane].cwd.clone()),
        _ => return,
    };
    let is_remote = matches!(kind, PaneKind::Remote);
    if is_remote && net::validate_remote_component(&name).is_err() {
        ui.set_error("Invalid remote filename; nothing was deleted.".into());
        return;
    }
    let settings = store::settings::load();
    let quarantine =
        is_remote && settings.remote_quarantine_deletes && remote_quarantine_available(&cwd, &name);
    let reversible = !is_remote || quarantine;
    if reversible && (!settings.confirm_deletes || delete_confirm_skipped(pane)) {
        delete_entry(
            handle,
            store,
            panes,
            ui.as_weak(),
            pane,
            name,
            is_dir,
            false,
        );
        return;
    }
    let path = if is_remote {
        join_remote(PathBuf::from(&cwd).join(&name))
    } else {
        PathBuf::from(&cwd)
            .join(&name)
            .to_string_lossy()
            .into_owned()
    };
    ui.set_delete_pane(if is_remote {
        "remote".into()
    } else {
        "local".into()
    });
    ui.set_delete_pane_index(pane as i32);
    ui.set_delete_name(name.into());
    ui.set_delete_path(path.into());
    ui.set_delete_is_dir(is_dir);
    ui.set_delete_remote_quarantine(quarantine);
    ui.set_delete_dont_ask(false); // fresh checkbox on every open
    ui.set_delete_open(true);
}

/// Delete-dialog action. `permanent_remote` is set only by the separately labelled destructive
/// button. The session-skip preference is never recorded for a permanent operation.
fn confirm_delete(
    handle: &Handle,
    store: Arc<dyn CredentialStore>,
    panes: Panes,
    ui: Weak<App>,
    permanent_remote: bool,
) {
    let Some(ui) = ui.upgrade() else { return };
    let pane = usize::try_from(ui.get_delete_pane_index())
        .ok()
        .filter(|pane| *pane < 2)
        .unwrap_or(0);
    let is_remote = panes
        .lock()
        .ok()
        .and_then(|states| {
            states
                .get(pane)
                .map(|state| matches!(state.kind, PaneKind::Remote))
        })
        .unwrap_or(false);
    let permanent_remote = is_remote && (permanent_remote || !ui.get_delete_remote_quarantine());
    if ui.get_delete_dont_ask() && !permanent_remote {
        set_skip_delete_confirm(pane, true);
    }
    let name = ui.get_delete_name().to_string();
    let is_dir = ui.get_delete_is_dir();
    ui.set_delete_dont_ask(false);
    ui.set_delete_open(false);
    delete_entry(
        handle,
        store,
        panes,
        ui.as_weak(),
        pane,
        name,
        is_dir,
        permanent_remote,
    );
}

fn wire_request_delete(ui: &App, handle: &Handle, store: Arc<dyn CredentialStore>, panes: Panes) {
    let (handle, store, panes, ui_weak) =
        (handle.clone(), store.clone(), panes.clone(), ui.as_weak());
    ui.on_request_delete(move |pane_s, name, is_dir| {
        if let Some(ui) = ui_weak.upgrade() {
            let Some(pane) = pane_alias_index(&ui, pane_s.as_str()) else {
                return;
            };
            request_delete(
                &ui,
                &handle,
                store.clone(),
                panes.clone(),
                pane,
                name.to_string(),
                is_dir,
            );
        }
    });
}

fn wire_confirm_delete(ui: &App, handle: &Handle, store: Arc<dyn CredentialStore>, panes: Panes) {
    let (handle, store, panes, ui_weak) =
        (handle.clone(), store.clone(), panes.clone(), ui.as_weak());
    ui.on_confirm_delete(move |permanent_remote| {
        confirm_delete(
            &handle,
            store.clone(),
            panes.clone(),
            ui_weak.clone(),
            permanent_remote,
        );
    });
}

fn validate_file_operation_name(value: &str) -> Result<String, String> {
    let value = value.trim();
    if value.is_empty()
        || matches!(value, "." | "..")
        || value.len() > 255
        || value.contains(['/', '\\'])
        || value.chars().any(char::is_control)
    {
        return Err("Name must be a single safe path component (1–255 bytes).".into());
    }
    Ok(value.to_string())
}

fn parse_permission_mode(value: &str) -> Result<u32, String> {
    let value = value.trim().trim_start_matches("0o");
    if value.len() != 3 || !value.bytes().all(|byte| matches!(byte, b'0'..=b'7')) {
        return Err("Permissions must be three octal digits, for example 644 or 755.".into());
    }
    u32::from_str_radix(value, 8).map_err(|_| "Invalid permission mode.".into())
}

/// Finder-style rename must not silently replace an item created between the UI's existence check
/// and the filesystem operation. macOS exposes an atomic no-replace rename for exactly this case.
#[cfg(target_os = "macos")]
fn rename_local_noreplace(source: &Path, destination: &Path) -> std::io::Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let source = CString::new(source.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "NUL in source path"))?;
    let destination = CString::new(destination.as_os_str().as_bytes()).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "NUL in destination path")
    })?;
    // SAFETY: both C strings are NUL-terminated and remain alive for the call. `AT_FDCWD` makes
    // the absolute/relative path semantics identical to std::fs::rename; RENAME_EXCL is atomic.
    let result = unsafe {
        libc::renameatx_np(
            libc::AT_FDCWD,
            source.as_ptr(),
            libc::AT_FDCWD,
            destination.as_ptr(),
            libc::RENAME_EXCL,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(not(target_os = "macos"))]
fn rename_local_noreplace(source: &Path, destination: &Path) -> std::io::Result<()> {
    if std::fs::symlink_metadata(destination).is_ok() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "destination already exists",
        ));
    }
    std::fs::rename(source, destination)
}

fn wire_file_operations(ui: &App, handle: &Handle, store: Arc<dyn CredentialStore>, panes: Panes) {
    let (handle, ui_weak) = (handle.clone(), ui.as_weak());
    ui.on_confirm_file_operation(move |mode, pane_alias, old_name, value, _is_dir| {
        let Ok(pane) = PaneId::try_from(pane_alias.as_str()) else {
            if let Some(ui) = ui_weak.upgrade() {
                ui.set_error("unknown pane identifier".into());
            }
            return;
        };
        let pane = pane.index();
        let Ok(mode) = FileOperationMode::try_from(mode.as_str()) else {
            if let Some(ui) = ui_weak.upgrade() {
                ui.set_error("Unknown file operation; nothing was changed.".into());
            }
            return;
        };
        let old_name = old_name.to_string();
        let value = value.to_string();
        let old_name = if mode.needs_source_name() {
            match validate_file_operation_name(&old_name) {
                Ok(name) => name,
                Err(error) => {
                    if let Some(ui) = ui_weak.upgrade() {
                        ui.set_error(error.into());
                    }
                    return;
                }
            }
        } else {
            old_name
        };
        let parsed_name = if mode.needs_destination_name() {
            match validate_file_operation_name(&value) {
                Ok(name) => Some(name),
                Err(error) => {
                    if let Some(ui) = ui_weak.upgrade() {
                        ui.set_error(error.into());
                    }
                    return;
                }
            }
        } else {
            None
        };
        let parsed_mode = if mode == FileOperationMode::ChangePermissions {
            match parse_permission_mode(&value) {
                Ok(mode) => Some(mode),
                Err(error) => {
                    if let Some(ui) = ui_weak.upgrade() {
                        ui.set_error(error.into());
                    }
                    return;
                }
            }
        } else {
            None
        };

        let (kind, spec, cwd) = {
            let states = panes.lock().expect("panes");
            (
                states[pane].kind.clone(),
                states[pane].conn.clone(),
                states[pane].cwd.clone(),
            )
        };
        let request_remote = matches!(kind, PaneKind::Remote);
        let connection_id = spec.as_ref().map(|spec| spec.id);
        let request_panes = panes.clone();
        let request_ui = ui_weak.clone();
        let request_handle = handle.clone();
        let request_store = store.clone();
        let request_cwd = cwd.clone();

        handle.spawn(async move {
            let result: Result<String, String> = async {
                match kind {
                    PaneKind::Local => {
                        let cwd = PathBuf::from(&cwd);
                        tokio::task::spawn_blocking(move || match mode {
                            FileOperationMode::Rename => {
                                let new_name = parsed_name.expect("validated rename name");
                                let source = cwd.join(&old_name);
                                let destination = cwd.join(&new_name);
                                net::assert_within(&cwd, &source).map_err(|e| e.to_string())?;
                                net::assert_within(&cwd, &destination)
                                    .map_err(|e| e.to_string())?;
                                if source == destination {
                                    return Ok("Name is unchanged.".into());
                                }
                                rename_local_noreplace(&source, &destination).map_err(|e| {
                                    if e.kind() == std::io::ErrorKind::AlreadyExists {
                                        format!("{new_name} already exists.")
                                    } else {
                                        format!("rename failed: {e}")
                                    }
                                })?;
                                Ok(format!("Renamed {old_name} to {new_name}."))
                            }
                            FileOperationMode::CreateDirectory => {
                                let name = parsed_name.expect("validated folder name");
                                let path = cwd.join(&name);
                                net::assert_within(&cwd, &path).map_err(|e| e.to_string())?;
                                std::fs::create_dir(&path)
                                    .map_err(|e| format!("could not create folder: {e}"))?;
                                Ok(format!("Created folder {name}."))
                            }
                            FileOperationMode::ChangePermissions => {
                                let path = cwd.join(&old_name);
                                net::assert_within(&cwd, &path).map_err(|e| e.to_string())?;
                                let metadata = std::fs::symlink_metadata(&path)
                                    .map_err(|e| format!("could not inspect item: {e}"))?;
                                if metadata.file_type().is_symlink() {
                                    return Err("Refusing to chmod a symlink.".into());
                                }
                                #[cfg(unix)]
                                {
                                    use std::os::unix::fs::PermissionsExt;
                                    let mode = parsed_mode.expect("validated permission mode");
                                    std::fs::set_permissions(
                                        &path,
                                        std::fs::Permissions::from_mode(mode),
                                    )
                                    .map_err(|e| format!("chmod failed: {e}"))?;
                                    Ok(format!("Permissions changed to {mode:03o}."))
                                }
                                #[cfg(not(unix))]
                                Err("Permission editing is unavailable on this platform.".into())
                            }
                        })
                        .await
                        .map_err(|error| error.to_string())?
                    }
                    PaneKind::Remote => {
                        let spec = spec.ok_or_else(|| "Pane is not connected.".to_string())?;
                        let password = password_for(&request_store, &spec)
                            .ok_or_else(|| "Missing credential.".to_string())?;
                        match mode {
                            FileOperationMode::Rename => {
                                let new_name = parsed_name.expect("validated rename name");
                                if new_name == old_name {
                                    Ok("Name is unchanged.".into())
                                } else if net::remote_exists(&spec, &password, &cwd, &new_name)
                                    .await
                                    .map_err(|e| e.to_string())?
                                {
                                    Err(format!("{new_name} already exists."))
                                } else {
                                    let from = join_remote(PathBuf::from(&cwd).join(&old_name));
                                    let to = join_remote(PathBuf::from(&cwd).join(&new_name));
                                    net::rename_remote(&spec, &password, &from, &to)
                                        .await
                                        .map_err(|e| e.to_string())?;
                                    Ok(format!("Renamed {old_name} to {new_name}."))
                                }
                            }
                            FileOperationMode::CreateDirectory => {
                                let name = parsed_name.expect("validated folder name");
                                let path = join_remote(PathBuf::from(&cwd).join(&name));
                                net::create_remote_dir(&spec, &password, &path)
                                    .await
                                    .map_err(|e| e.to_string())?;
                                Ok(format!("Created folder {name}."))
                            }
                            FileOperationMode::ChangePermissions => {
                                let permission = parsed_mode.expect("validated permission mode");
                                let path = join_remote(PathBuf::from(&cwd).join(&old_name));
                                net::chmod_remote(&spec, &password, &path, permission)
                                    .await
                                    .map_err(|e| e.to_string())?;
                                Ok(format!("Permissions changed to {permission:03o}."))
                            }
                        }
                    }
                }
            }
            .await;

            let _ = slint::invoke_from_event_loop(move || {
                let Some(ui) = request_ui.upgrade() else {
                    return;
                };
                match result {
                    Ok(message) => {
                        ui.set_error("".into());
                        ui.set_status(message.into());
                        if pane_request_is_current(
                            &request_panes,
                            pane,
                            request_remote,
                            connection_id,
                            &request_cwd,
                        ) {
                            refresh_pane(
                                &request_handle,
                                request_store,
                                request_panes,
                                ui.as_weak(),
                                pane,
                            );
                        }
                    }
                    Err(error) => ui.set_error(error.into()),
                }
            });
        });
    });
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct BatchRenameItem {
    from: String,
    to: String,
}

fn build_batch_rename_plan(
    selected: &[CopyRequest],
    existing_names: &HashSet<String>,
    find: &str,
    replacement: &str,
) -> Result<Vec<BatchRenameItem>, String> {
    if find.is_empty()
        || find.len() > 255
        || replacement.len() > 255
        || find.chars().any(char::is_control)
        || replacement.chars().any(char::is_control)
    {
        return Err("Find text must be non-empty; both fields are limited to 255 bytes.".into());
    }
    let mut plan = selected
        .iter()
        .filter(|item| item.name.contains(find))
        .map(|item| {
            let to = item.name.replace(find, replacement);
            validate_file_operation_name(&to).map(|to| BatchRenameItem {
                from: item.name.clone(),
                to,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    plan.retain(|item| item.from != item.to);
    if plan.is_empty() {
        return Err("None of the selected names would change.".into());
    }
    let sources = plan
        .iter()
        .map(|item| item.from.as_str())
        .collect::<HashSet<_>>();
    let mut destinations = HashSet::new();
    for item in &plan {
        if !destinations.insert(item.to.clone()) {
            return Err(format!("Several items would become “{}”.", item.to));
        }
        if existing_names.contains(&item.to) && !sources.contains(item.to.as_str()) {
            return Err(format!(
                "{} already exists and is not being renamed.",
                item.to
            ));
        }
    }
    Ok(plan)
}

fn rollback_local_batch_rename(
    cwd: &Path,
    staged: &[(BatchRenameItem, String)],
    promoted: usize,
) -> Vec<String> {
    let mut errors = Vec::new();
    for (item, _) in staged[..promoted].iter().rev() {
        if let Err(error) = rename_local_noreplace(&cwd.join(&item.to), &cwd.join(&item.from)) {
            errors.push(format!("{}: {error}", item.to));
        }
    }
    for (item, staging) in staged[promoted..].iter().rev() {
        if let Err(error) = rename_local_noreplace(&cwd.join(staging), &cwd.join(&item.from)) {
            errors.push(format!("{staging}: {error}"));
        }
    }
    errors
}

fn execute_local_batch_rename(cwd: &Path, plan: &[BatchRenameItem]) -> Result<usize, String> {
    let mut staged = Vec::with_capacity(plan.len());
    for (index, item) in plan.iter().enumerate() {
        let staging = format!(".gmacftp-rename-{:016x}-{index}", rand::random::<u64>());
        let source = cwd.join(&item.from);
        let temporary = cwd.join(&staging);
        net::assert_within(cwd, &source).map_err(|error| error.to_string())?;
        net::assert_within(cwd, &temporary).map_err(|error| error.to_string())?;
        if let Err(error) = rename_local_noreplace(&source, &temporary) {
            let rollback_errors = rollback_local_batch_rename(cwd, &staged, 0);
            return Err(format!(
                "Could not stage {}: {error}{}",
                item.from,
                if rollback_errors.is_empty() {
                    String::new()
                } else {
                    format!("; rollback problems: {}", rollback_errors.join(", "))
                }
            ));
        }
        staged.push((item.clone(), staging));
    }
    for (index, (item, staging)) in staged.iter().enumerate() {
        let destination = cwd.join(&item.to);
        net::assert_within(cwd, &destination).map_err(|error| error.to_string())?;
        if let Err(error) = rename_local_noreplace(&cwd.join(staging), &destination) {
            let rollback_errors = rollback_local_batch_rename(cwd, &staged, index);
            return Err(format!(
                "Could not finalize {}: {error}{}",
                item.to,
                if rollback_errors.is_empty() {
                    String::new()
                } else {
                    format!("; rollback problems: {}", rollback_errors.join(", "))
                }
            ));
        }
    }
    Ok(staged.len())
}

async fn rollback_remote_batch_rename(
    spec: &ConnectionSpec,
    password: &str,
    cwd: &str,
    staged: &[(BatchRenameItem, String)],
    promoted: usize,
) -> Vec<String> {
    let mut errors = Vec::new();
    for (item, _) in staged[..promoted].iter().rev() {
        let from = join_remote(PathBuf::from(cwd).join(&item.to));
        let to = join_remote(PathBuf::from(cwd).join(&item.from));
        if let Err(error) = net::rename_remote(spec, password, &from, &to).await {
            errors.push(format!("{}: {error}", item.to));
        }
    }
    for (item, staging) in staged[promoted..].iter().rev() {
        let from = join_remote(PathBuf::from(cwd).join(staging));
        let to = join_remote(PathBuf::from(cwd).join(&item.from));
        if let Err(error) = net::rename_remote(spec, password, &from, &to).await {
            errors.push(format!("{staging}: {error}"));
        }
    }
    errors
}

async fn execute_remote_batch_rename(
    spec: &ConnectionSpec,
    password: &str,
    cwd: &str,
    plan: &[BatchRenameItem],
) -> Result<usize, String> {
    let mut staged = Vec::with_capacity(plan.len());
    for (index, item) in plan.iter().enumerate() {
        let staging = format!(".gmacftp-rename-{:016x}-{index}", rand::random::<u64>());
        match net::remote_exists(spec, password, cwd, &staging).await {
            Ok(false) => {}
            Ok(true) => {
                let rollback = rollback_remote_batch_rename(spec, password, cwd, &staged, 0).await;
                return Err(format!(
                    "A private staging name unexpectedly exists{}",
                    if rollback.is_empty() {
                        String::new()
                    } else {
                        format!("; rollback problems: {}", rollback.join(", "))
                    }
                ));
            }
            Err(error) => {
                let rollback = rollback_remote_batch_rename(spec, password, cwd, &staged, 0).await;
                return Err(format!(
                    "Could not verify a private staging name: {error}{}",
                    if rollback.is_empty() {
                        String::new()
                    } else {
                        format!("; rollback problems: {}", rollback.join(", "))
                    }
                ));
            }
        }
        let from = join_remote(PathBuf::from(cwd).join(&item.from));
        let temporary = join_remote(PathBuf::from(cwd).join(&staging));
        if let Err(error) = net::rename_remote(spec, password, &from, &temporary).await {
            let rollback = rollback_remote_batch_rename(spec, password, cwd, &staged, 0).await;
            return Err(format!(
                "Could not stage {}: {error}{}",
                item.from,
                if rollback.is_empty() {
                    String::new()
                } else {
                    format!("; rollback problems: {}", rollback.join(", "))
                }
            ));
        }
        staged.push((item.clone(), staging));
    }
    for (index, (item, staging)) in staged.iter().enumerate() {
        let destination_exists = match net::remote_exists(spec, password, cwd, &item.to).await {
            Ok(exists) => exists,
            Err(error) => {
                let rollback =
                    rollback_remote_batch_rename(spec, password, cwd, &staged, index).await;
                return Err(format!(
                    "Could not recheck {}: {error}{}",
                    item.to,
                    if rollback.is_empty() {
                        String::new()
                    } else {
                        format!("; rollback problems: {}", rollback.join(", "))
                    }
                ));
            }
        };
        if destination_exists {
            let rollback = rollback_remote_batch_rename(spec, password, cwd, &staged, index).await;
            return Err(format!(
                "{} appeared during the operation; no overwrite was attempted{}",
                item.to,
                if rollback.is_empty() {
                    String::new()
                } else {
                    format!("; rollback problems: {}", rollback.join(", "))
                }
            ));
        }
        let from = join_remote(PathBuf::from(cwd).join(staging));
        let to = join_remote(PathBuf::from(cwd).join(&item.to));
        if let Err(error) = net::rename_remote(spec, password, &from, &to).await {
            let rollback = rollback_remote_batch_rename(spec, password, cwd, &staged, index).await;
            return Err(format!(
                "Could not finalize {}: {error}{}",
                item.to,
                if rollback.is_empty() {
                    String::new()
                } else {
                    format!("; rollback problems: {}", rollback.join(", "))
                }
            ));
        }
    }
    Ok(staged.len())
}

#[derive(Debug)]
struct InspectorMetadata {
    kind: String,
    size: u64,
    modified: Option<i64>,
    permissions: Option<u32>,
    owner: Option<String>,
    group: Option<String>,
}

fn local_inspector_metadata(path: &Path) -> Result<InspectorMetadata, String> {
    let metadata = std::fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    let modified = metadata
        .modified()
        .ok()
        .and_then(|value| value.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|value| value.as_secs() as i64);
    #[cfg(unix)]
    let (permissions, owner, group) = {
        use std::os::unix::fs::MetadataExt;
        (
            Some(metadata.mode() & 0o7777),
            Some(metadata.uid().to_string()),
            Some(metadata.gid().to_string()),
        )
    };
    #[cfg(not(unix))]
    let (permissions, owner, group) = (None, None, None);
    Ok(InspectorMetadata {
        kind: if metadata.file_type().is_symlink() {
            "symlink"
        } else if metadata.is_dir() {
            "folder"
        } else if metadata.is_file() {
            "file"
        } else {
            "special"
        }
        .into(),
        size: metadata.len(),
        modified,
        permissions,
        owner,
        group,
    })
}

fn apply_inspector_metadata(ui: &App, metadata: InspectorMetadata) {
    ui.set_inspector_kind(metadata.kind.into());
    ui.set_inspector_size(fmt_size(metadata.size).into());
    ui.set_inspector_modified(
        metadata
            .modified
            .filter(|modified| *modified > 0)
            .map(fmt_date)
            .unwrap_or_default()
            .into(),
    );
    ui.set_inspector_permissions(
        metadata
            .permissions
            .map(|permissions| format!("{permissions:04o}"))
            .unwrap_or_default()
            .into(),
    );
    ui.set_inspector_owner(metadata.owner.unwrap_or_default().into());
    ui.set_inspector_group(metadata.group.unwrap_or_default().into());
    ui.set_inspector_loading(false);
}

fn pane_alias_index(ui: &App, alias: &str) -> Option<usize> {
    match PaneId::try_from(alias) {
        Ok(pane) => Some(pane.index()),
        Err(error) => {
            ui.set_error(error.into());
            None
        }
    }
}

fn wire_power_file_operations(
    ui: &App,
    handle: &Handle,
    store: Arc<dyn CredentialStore>,
    panes: Panes,
    engine: TransferEngine,
    jobs_index: Arc<Mutex<HashMap<i32, usize>>>,
) {
    {
        let panes = panes.clone();
        let ui_weak = ui.as_weak();
        ui.on_copy_file_selection(move |pane_alias| {
            let Some(ui) = ui_weak.upgrade() else { return };
            let Some(pane) = pane_alias_index(&ui, pane_alias.as_str()) else {
                return;
            };
            let items = selected_copy_requests(&ui, pane);
            if items.is_empty() {
                ui.set_error("Select at least one item to copy.".into());
                return;
            }
            let clipboard = panes.lock().ok().and_then(|states| {
                Some(FileClipboard {
                    source_pane: pane,
                    source_cwd: states[pane].cwd.clone(),
                    source_identity: synchronized_pane_identity(&states[pane])?,
                    items,
                })
            });
            let Some(clipboard) = clipboard else {
                ui.set_error("The source pane is unavailable.".into());
                return;
            };
            let count = clipboard.items.len();
            if let Ok(mut stored) = FILE_CLIPBOARD.lock() {
                *stored = Some(clipboard);
                ui.set_file_clipboard_count(count as i32);
                ui.set_status(format!("Copied {count} item(s) to the gmacFTP clipboard.").into());
                ui.set_error("".into());
            }
        });
    }
    {
        let handle = handle.clone();
        let store = store.clone();
        let panes = panes.clone();
        let engine = engine.clone();
        let jobs_index = jobs_index.clone();
        let ui_weak = ui.as_weak();
        ui.on_paste_file_selection(move |pane_alias| {
            let Some(ui) = ui_weak.upgrade() else { return };
            let Some(destination) = pane_alias_index(&ui, pane_alias.as_str()) else {
                return;
            };
            let clipboard = FILE_CLIPBOARD.lock().ok().and_then(|stored| stored.clone());
            let Some(clipboard) = clipboard else {
                ui.set_error("The gmacFTP file clipboard is empty.".into());
                return;
            };
            let source_current = panes.lock().ok().is_some_and(|states| {
                states[clipboard.source_pane].cwd == clipboard.source_cwd
                    && synchronized_pane_identity(&states[clipboard.source_pane])
                        == Some(clipboard.source_identity)
            });
            if !source_current {
                ui.set_error(
                    "The copied source pane changed; copy the items again before pasting.".into(),
                );
                return;
            }
            if destination == clipboard.source_pane {
                ui.set_error(
                    "Paste into the same pane is ambiguous; use Duplicate (Command-D) instead."
                        .into(),
                );
                return;
            }
            let batch = fresh_batch(clipboard.items.len() > 1);
            let destination_remote = panes
                .lock()
                .ok()
                .is_some_and(|states| matches!(states[destination].kind, PaneKind::Remote));
            if clipboard.items.len() > 1 && destination_remote {
                start_remote_transfer_batch(
                    &handle,
                    store.clone(),
                    panes.clone(),
                    engine.clone(),
                    jobs_index.clone(),
                    ui.as_weak(),
                    clipboard.source_pane,
                    destination,
                    clipboard.items,
                    batch,
                );
            } else {
                for item in clipboard.items {
                    start_transfer(
                        &handle,
                        store.clone(),
                        panes.clone(),
                        engine.clone(),
                        jobs_index.clone(),
                        ui.as_weak(),
                        clipboard.source_pane,
                        destination,
                        item.name,
                        item.is_dir,
                        item.total,
                        batch,
                    );
                }
            }
            ui.set_status("Paste started with normal conflict checks.".into());
            ui.set_error("".into());
        });
    }
    {
        let handle = handle.clone();
        let store = store.clone();
        let panes = panes.clone();
        let engine = engine.clone();
        let jobs_index = jobs_index.clone();
        let ui_weak = ui.as_weak();
        ui.on_duplicate_selection(move |pane_alias| {
            let Some(ui) = ui_weak.upgrade() else { return };
            let Some(pane) = pane_alias_index(&ui, pane_alias.as_str()) else {
                return;
            };
            let items = selected_copy_requests(&ui, pane);
            if items.is_empty() {
                ui.set_error("Select at least one item to duplicate.".into());
                return;
            }
            let full = if pane == 0 {
                ui.get_local_full()
            } else {
                ui.get_remote_full()
            };
            let mut taken = (0..full.row_count())
                .filter_map(|index| full.row_data(index))
                .map(|entry| entry.name.to_string())
                .collect::<HashSet<_>>();
            let batch = fresh_batch(items.len() > 1);
            for item in items {
                let destination = unique_name_from_taken(&item.name, &mut taken);
                do_transfer(
                    &handle,
                    store.clone(),
                    panes.clone(),
                    engine.clone(),
                    jobs_index.clone(),
                    ui.as_weak(),
                    pane,
                    pane,
                    item.name,
                    destination,
                    item.is_dir,
                    item.total,
                    batch,
                );
            }
            ui.set_status("Duplicating selected item(s) under unique names…".into());
            ui.set_error("".into());
        });
    }
    {
        let handle = handle.clone();
        let store = store.clone();
        let panes = panes.clone();
        let ui_weak = ui.as_weak();
        ui.on_move_selection_other_pane(move |pane_alias| {
            let Some(ui) = ui_weak.upgrade() else { return };
            let Some(source_id) = PaneId::try_from(pane_alias.as_str()).ok() else {
                ui.set_error("unknown pane identifier".into());
                return;
            };
            let source = source_id.index();
            let destination = source_id.other().index();
            let items = selected_copy_requests(&ui, source);
            if items.is_empty() {
                ui.set_error("Select at least one item to move.".into());
                return;
            }
            let context = panes.lock().ok().and_then(|states| {
                let source_state = &states[source];
                let destination_state = &states[destination];
                let source_spec = source_state.conn.clone()?;
                let destination_spec = destination_state.conn.as_ref()?;
                if !matches!(source_state.kind, PaneKind::Remote)
                    || !matches!(destination_state.kind, PaneKind::Remote)
                    || source_spec.id != destination_spec.id
                    || source_state.cwd == destination_state.cwd
                {
                    return None;
                }
                Some((
                    source_spec,
                    source_state.cwd.clone(),
                    destination_state.cwd.clone(),
                ))
            });
            let Some((spec, source_cwd, destination_cwd)) = context else {
                ui.set_error(
                    "Move requires two different folders on the same connected server.".into(),
                );
                return;
            };
            if items.iter().any(|item| {
                item.is_dir
                    && remote_path_is_within(
                        &join_remote(PathBuf::from(&source_cwd).join(&item.name)),
                        &destination_cwd,
                    )
            }) {
                ui.set_error("A folder cannot be moved into itself or its descendant.".into());
                return;
            }
            let Some(password) = password_for(&store, &spec) else {
                ui.set_error("Missing credential.".into());
                return;
            };
            ui.set_status(format!("Moving {} item(s) on the server…", items.len()).into());
            ui.set_error("".into());
            let request_ui = ui.as_weak();
            let request_panes = panes.clone();
            let request_handle = handle.clone();
            let request_store = store.clone();
            handle.spawn(async move {
                let mut destination_spec = spec.clone();
                destination_spec.initial_path = destination_cwd.clone();
                let result: Result<usize, String> = async {
                    let (destination_entries, _) =
                        net::connect_and_list(&destination_spec, &password)
                            .await
                            .map_err(|error| error.to_string())?;
                    let existing = destination_entries
                        .into_iter()
                        .map(|entry| entry.name)
                        .collect::<HashSet<_>>();
                    if let Some(conflict) = items.iter().find(|item| existing.contains(&item.name))
                    {
                        return Err(format!(
                            "{} already exists in the destination; nothing was moved.",
                            conflict.name
                        ));
                    }
                    let mut moved: Vec<(String, String)> = Vec::new();
                    for item in &items {
                        if !remote_pane_request_is_current(
                            &request_panes,
                            source,
                            spec.id,
                            &source_cwd,
                        ) || !remote_pane_request_is_current(
                            &request_panes,
                            destination,
                            spec.id,
                            &destination_cwd,
                        ) {
                            let mut rollback_errors = Vec::new();
                            for (from, to) in moved.iter().rev() {
                                if let Err(error) =
                                    net::rename_remote(&spec, &password, to, from).await
                                {
                                    rollback_errors.push(error.to_string());
                                }
                            }
                            return Err(format!(
                                "Pane changed while moving; rollback {}.",
                                if rollback_errors.is_empty() {
                                    "completed"
                                } else {
                                    "had errors"
                                }
                            ));
                        }
                        let from = join_remote(PathBuf::from(&source_cwd).join(&item.name));
                        let to = join_remote(PathBuf::from(&destination_cwd).join(&item.name));
                        if let Err(error) = net::rename_remote(&spec, &password, &from, &to).await {
                            let mut rollback_errors = Vec::new();
                            for (rollback_from, rollback_to) in moved.iter().rev() {
                                if let Err(rollback_error) =
                                    net::rename_remote(&spec, &password, rollback_to, rollback_from)
                                        .await
                                {
                                    rollback_errors.push(rollback_error.to_string());
                                }
                            }
                            return Err(format!(
                                "Move failed at {}: {error}{}",
                                item.name,
                                if rollback_errors.is_empty() {
                                    String::new()
                                } else {
                                    format!("; rollback problems: {}", rollback_errors.join(", "))
                                }
                            ));
                        }
                        moved.push((from, to));
                    }
                    Ok(moved.len())
                }
                .await;
                let _ = slint::invoke_from_event_loop(move || {
                    let Some(ui) = request_ui.upgrade() else {
                        return;
                    };
                    match result {
                        Ok(count) => {
                            ui.set_status(format!("Moved {count} item(s) on the server.").into());
                            ui.set_error("".into());
                            refresh_both_panes(
                                &request_handle,
                                request_store,
                                request_panes,
                                ui.as_weak(),
                            );
                        }
                        Err(error) => ui.set_error(error.into()),
                    }
                });
            });
        });
    }
    {
        let ui_weak = ui.as_weak();
        ui.on_open_batch_rename(move |pane_alias| {
            let Some(ui) = ui_weak.upgrade() else { return };
            let Some(pane) = pane_alias_index(&ui, pane_alias.as_str()) else {
                return;
            };
            let count = selected_copy_requests(&ui, pane).len();
            if count < 2 {
                ui.set_error("Select at least two items for batch rename.".into());
                return;
            }
            ui.set_batch_rename_pane(pane_alias);
            ui.set_batch_rename_find("".into());
            ui.set_batch_rename_replace("".into());
            ui.set_batch_rename_summary(
                format!("{count} selected items; collisions abort safely.").into(),
            );
            ui.set_batch_rename_open(true);
            ui.set_error("".into());
        });
    }
    {
        let handle = handle.clone();
        let store = store.clone();
        let panes = panes.clone();
        let ui_weak = ui.as_weak();
        ui.on_apply_batch_rename(move |pane_alias, find, replacement| {
            let Some(ui) = ui_weak.upgrade() else { return };
            let Some(pane) = pane_alias_index(&ui, pane_alias.as_str()) else {
                return;
            };
            let selected = selected_copy_requests(&ui, pane);
            let full = if pane == 0 {
                ui.get_local_full()
            } else {
                ui.get_remote_full()
            };
            let existing = (0..full.row_count())
                .filter_map(|index| full.row_data(index))
                .map(|entry| entry.name.to_string())
                .collect::<HashSet<_>>();
            let plan = match build_batch_rename_plan(
                &selected,
                &existing,
                find.as_str(),
                replacement.as_str(),
            ) {
                Ok(plan) => plan,
                Err(error) => {
                    ui.set_error(error.into());
                    return;
                }
            };
            let Some((kind, spec, cwd)) = panes.lock().ok().and_then(|states| {
                let state = states.get(pane)?;
                Some((state.kind.clone(), state.conn.clone(), state.cwd.clone()))
            }) else {
                return;
            };
            let remote = matches!(kind, PaneKind::Remote);
            let connection_id = spec.as_ref().map(|spec| spec.id);
            let password = if let Some(spec) = spec.as_ref() {
                match password_for(&store, spec) {
                    Some(password) => Some(password),
                    None => {
                        ui.set_error("Missing credential.".into());
                        return;
                    }
                }
            } else {
                None
            };
            ui.set_status(format!("Renaming {} item(s) transactionally…", plan.len()).into());
            ui.set_error("".into());
            let request_ui = ui.as_weak();
            let request_panes = panes.clone();
            let request_handle = handle.clone();
            let request_store = store.clone();
            handle.spawn(async move {
                let result: Result<usize, String> = async {
                    match kind {
                        PaneKind::Local => {
                            let cwd = PathBuf::from(&cwd);
                            tokio::task::spawn_blocking(move || {
                                execute_local_batch_rename(&cwd, &plan)
                            })
                            .await
                            .map_err(|error| error.to_string())?
                        }
                        PaneKind::Remote => {
                            execute_remote_batch_rename(
                                &spec.expect("remote pane has spec"),
                                password.as_deref().expect("remote pane has credential"),
                                &cwd,
                                &plan,
                            )
                            .await
                        }
                    }
                }
                .await;
                let _ = slint::invoke_from_event_loop(move || {
                    let Some(ui) = request_ui.upgrade() else {
                        return;
                    };
                    match result {
                        Ok(count) => {
                            ui.set_status(format!("Renamed {count} item(s).").into());
                            ui.set_error("".into());
                            if pane_request_is_current(
                                &request_panes,
                                pane,
                                remote,
                                connection_id,
                                &cwd,
                            ) {
                                refresh_pane(
                                    &request_handle,
                                    request_store,
                                    request_panes,
                                    ui.as_weak(),
                                    pane,
                                );
                            }
                        }
                        Err(error) => ui.set_error(error.into()),
                    }
                });
            });
        });
    }
    {
        let handle = handle.clone();
        let store = store.clone();
        let panes = panes.clone();
        let ui_weak = ui.as_weak();
        ui.on_open_inspector(move |pane_alias, name| {
            let Some(ui) = ui_weak.upgrade() else { return };
            let Some(pane) = pane_alias_index(&ui, pane_alias.as_str()) else {
                return;
            };
            let name = match validate_file_operation_name(name.as_str()) {
                Ok(name) => name,
                Err(error) => {
                    ui.set_error(error.into());
                    return;
                }
            };
            let Some((kind, spec, cwd)) = panes.lock().ok().and_then(|states| {
                let state = states.get(pane)?;
                Some((state.kind.clone(), state.conn.clone(), state.cwd.clone()))
            }) else {
                return;
            };
            let path = match kind {
                PaneKind::Local => PathBuf::from(&cwd)
                    .join(&name)
                    .to_string_lossy()
                    .into_owned(),
                PaneKind::Remote => join_remote(PathBuf::from(&cwd).join(&name)),
            };
            ui.set_inspector_name(name.clone().into());
            ui.set_inspector_path(path.clone().into());
            ui.set_inspector_kind("".into());
            ui.set_inspector_size("".into());
            ui.set_inspector_modified("".into());
            ui.set_inspector_permissions("".into());
            ui.set_inspector_owner("".into());
            ui.set_inspector_group("".into());
            ui.set_inspector_loading(true);
            ui.set_inspector_open(true);
            ui.set_error("".into());
            let request_ui = ui.as_weak();
            let request_panes = panes.clone();
            let request_store = store.clone();
            handle.spawn(async move {
                let result: Result<InspectorMetadata, String> = async {
                    match kind {
                        PaneKind::Local => {
                            let path = PathBuf::from(path);
                            tokio::task::spawn_blocking(move || local_inspector_metadata(&path))
                                .await
                                .map_err(|error| error.to_string())?
                        }
                        PaneKind::Remote => {
                            let spec = spec.ok_or_else(|| "Pane is not connected.".to_string())?;
                            let password = password_for(&request_store, &spec)
                                .ok_or_else(|| "Missing credential.".to_string())?;
                            net::inspect_remote(&spec, &password, &path)
                                .await
                                .map(|metadata| InspectorMetadata {
                                    kind: if metadata.is_dir { "folder" } else { "file" }.into(),
                                    size: metadata.size,
                                    modified: metadata.mtime,
                                    permissions: metadata.permissions,
                                    owner: metadata.owner,
                                    group: metadata.group,
                                })
                                .map_err(|error| error.to_string())
                        }
                    }
                }
                .await;
                let _ = slint::invoke_from_event_loop(move || {
                    let Some(ui) = request_ui.upgrade() else {
                        return;
                    };
                    let still_current = request_panes
                        .lock()
                        .ok()
                        .and_then(|states| states.get(pane).map(|state| state.cwd == cwd))
                        .unwrap_or(false);
                    if !still_current || ui.get_inspector_name().as_str() != name {
                        return;
                    }
                    match result {
                        Ok(metadata) => apply_inspector_metadata(&ui, metadata),
                        Err(error) => {
                            ui.set_inspector_loading(false);
                            ui.set_error(format!("Could not inspect metadata: {error}").into());
                        }
                    }
                });
            });
        });
    }
}

fn sha256_file(path: &Path) -> Result<[u8; 32], String> {
    use sha2::Digest;
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| format!("could not inspect file for SHA-256: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err("SHA-256 input is no longer a regular file".into());
    }
    let mut file = std::fs::File::open(path)
        .map_err(|error| format!("could not open file for SHA-256: {error}"))?;
    let mut hasher = sha2::Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| format!("could not read file for SHA-256: {error}"))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hasher.finalize().into())
}

const MAX_EDITOR_DIFF_INPUT_BYTES: usize = 256 * 1024;
const MAX_EDITOR_DIFF_OUTPUT_BYTES: usize = 32 * 1024;
const MAX_EDITOR_DIFF_CHANGED_LINES: usize = 120;

fn read_editor_diff_input(path: &Path) -> Result<(Vec<u8>, bool), String> {
    let metadata = std::fs::symlink_metadata(path)
        .map_err(|error| format!("could not inspect diff input: {error}"))?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err("diff input is no longer a regular file".into());
    }
    let mut file =
        std::fs::File::open(path).map_err(|error| format!("could not open diff input: {error}"))?;
    let mut bytes = Vec::with_capacity(
        (metadata.len() as usize).min(MAX_EDITOR_DIFF_INPUT_BYTES.saturating_add(1)),
    );
    file.by_ref()
        .take(MAX_EDITOR_DIFF_INPUT_BYTES.saturating_add(1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("could not read diff input: {error}"))?;
    let truncated = bytes.len() > MAX_EDITOR_DIFF_INPUT_BYTES;
    bytes.truncate(MAX_EDITOR_DIFF_INPUT_BYTES);
    Ok((bytes, truncated))
}

fn sanitize_diff_line(line: &str) -> String {
    line.chars()
        .map(|character| {
            if character == '\t' || !character.is_control() {
                character
            } else {
                '�'
            }
        })
        .collect()
}

fn editor_diff_preview(server_path: &Path, local_path: &Path) -> Result<(String, String), String> {
    let (server_bytes, server_truncated) = read_editor_diff_input(server_path)?;
    let (local_bytes, local_truncated) = read_editor_diff_input(local_path)?;
    if server_bytes.contains(&0) || local_bytes.contains(&0) {
        return Ok((
            "Binary content detected; the internal text preview is intentionally disabled. Both versions remain preserved until you choose an action."
                .into(),
            format!(
                "Binary conflict · server preview {} · local preview {}{}",
                fmt_size(server_bytes.len() as u64),
                fmt_size(local_bytes.len() as u64),
                if server_truncated || local_truncated {
                    " · preview bounded to 256 KiB per version"
                } else {
                    ""
                }
            ),
        ));
    }
    let server = std::str::from_utf8(&server_bytes);
    let local = std::str::from_utf8(&local_bytes);
    let (Ok(server), Ok(local)) = (server, local) else {
        return Ok((
            "Non-UTF-8 content detected; the internal text preview is intentionally disabled. Both versions remain preserved until you choose an action."
                .into(),
            "Non-UTF-8 conflict · use Keep Local or upload a separate copy".into(),
        ));
    };
    let server_lines = server.lines().collect::<Vec<_>>();
    let local_lines = local.lines().collect::<Vec<_>>();
    let mut prefix = 0usize;
    while prefix < server_lines.len()
        && prefix < local_lines.len()
        && server_lines[prefix] == local_lines[prefix]
    {
        prefix += 1;
    }
    let mut suffix = 0usize;
    while suffix < server_lines.len().saturating_sub(prefix)
        && suffix < local_lines.len().saturating_sub(prefix)
        && server_lines[server_lines.len() - 1 - suffix]
            == local_lines[local_lines.len() - 1 - suffix]
    {
        suffix += 1;
    }
    let server_end = server_lines.len().saturating_sub(suffix);
    let local_end = local_lines.len().saturating_sub(suffix);
    let removed = &server_lines[prefix..server_end];
    let added = &local_lines[prefix..local_end];
    let mut preview = String::from("--- latest server version\n+++ your local edit\n");
    let context_start = prefix.saturating_sub(3);
    for line in &server_lines[context_start..prefix] {
        preview.push(' ');
        preview.push_str(&sanitize_diff_line(line));
        preview.push('\n');
    }
    for line in removed.iter().take(MAX_EDITOR_DIFF_CHANGED_LINES) {
        preview.push('-');
        preview.push_str(&sanitize_diff_line(line));
        preview.push('\n');
    }
    if removed.len() > MAX_EDITOR_DIFF_CHANGED_LINES {
        preview.push_str("-… additional server lines omitted …\n");
    }
    for line in added.iter().take(MAX_EDITOR_DIFF_CHANGED_LINES) {
        preview.push('+');
        preview.push_str(&sanitize_diff_line(line));
        preview.push('\n');
    }
    if added.len() > MAX_EDITOR_DIFF_CHANGED_LINES {
        preview.push_str("+… additional local lines omitted …\n");
    }
    for line in server_lines.iter().skip(server_end).take(3) {
        preview.push(' ');
        preview.push_str(&sanitize_diff_line(line));
        preview.push('\n');
    }
    let output_truncated = preview.len() > MAX_EDITOR_DIFF_OUTPUT_BYTES;
    if output_truncated {
        preview = truncate_utf8_bytes(&preview, MAX_EDITOR_DIFF_OUTPUT_BYTES).to_string();
        preview.push_str("\n… diff output truncated …");
    }
    let summary = format!(
        "Server: {} changed line(s) · Local: {} changed line(s){}",
        removed.len(),
        added.len(),
        if server_truncated || local_truncated || output_truncated {
            " · bounded preview"
        } else {
            ""
        }
    );
    Ok((preview, summary))
}

fn editor_application_for(
    file_name: &str,
    mappings: &[store::settings::EditorMapping],
) -> Option<String> {
    let file_name = file_name.to_ascii_lowercase();
    mappings
        .iter()
        .filter(|mapping| file_name.ends_with(&format!(".{}", mapping.extension)))
        .max_by_key(|mapping| mapping.extension.len())
        .map(|mapping| mapping.application.clone())
}

fn truncate_utf8_bytes(value: &str, max_bytes: usize) -> &str {
    if value.len() <= max_bytes {
        return value;
    }
    let mut end = max_bytes;
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    &value[..end]
}

fn editor_conflict_copy_name(file_name: &str, token: u64) -> String {
    const MAX_FILE_NAME_BYTES: usize = 255;
    let suffix = format!(" (gmacFTP conflict {token:016x})");
    let (stem, extension) = file_name
        .rsplit_once('.')
        .filter(|(stem, extension)| !stem.is_empty() && !extension.is_empty())
        .map(|(stem, extension)| (stem, format!(".{extension}")))
        .unwrap_or((file_name, String::new()));
    if suffix.len().saturating_add(extension.len()) >= MAX_FILE_NAME_BYTES {
        return format!("gmacftp-conflict-{token:016x}");
    }
    let stem = truncate_utf8_bytes(stem, MAX_FILE_NAME_BYTES - suffix.len() - extension.len());
    format!("{stem}{suffix}{extension}")
}

fn wire_remote_edit(ui: &App, handle: &Handle, store: Arc<dyn CredentialStore>, panes: Panes) {
    let (handle, ui_weak) = (handle.clone(), ui.as_weak());
    ui.on_edit_remote_file(move |pane_alias, name| {
        let Ok(pane) = PaneId::try_from(pane_alias.as_str()) else {
            if let Some(ui) = ui_weak.upgrade() {
                ui.set_error("unknown pane identifier".into());
            }
            return;
        };
        let pane = pane.index();
        let name = match validate_file_operation_name(name.as_str()) {
            Ok(name) => name,
            Err(error) => {
                if let Some(ui) = ui_weak.upgrade() {
                    ui.set_error(error.into());
                }
                return;
            }
        };
        let (spec, cwd) = {
            let states = panes.lock().expect("panes");
            if !matches!(states[pane].kind, PaneKind::Remote) {
                if let Some(ui) = ui_weak.upgrade() {
                    ui.set_error("Remote editing requires a connected server pane.".into());
                }
                return;
            }
            let Some(spec) = states[pane].conn.clone() else {
                return;
            };
            (spec, states[pane].cwd.clone())
        };
        let Some(password) = password_for(&store, &spec) else {
            if let Some(ui) = ui_weak.upgrade() {
                ui.set_error("Missing credential.".into());
            }
            return;
        };
        let edit_settings = store::settings::load();
        let max_edit_bytes = (edit_settings.editor_max_download_mib as u64)
            .saturating_mul(1024 * 1024)
            .min(
                (store::settings::MAX_EDITOR_DOWNLOAD_MIB as u64).saturating_mul(1024 * 1024),
            );
        let auto_upload = edit_settings.editor_auto_upload;
        let conflict_action = edit_settings.editor_conflict_action.clone();
        let temp_retention = edit_settings.editor_temp_retention.clone();
        let editor_application = editor_application_for(&name, &edit_settings.editor_mappings);
        if let Some(ui) = ui_weak.upgrade() {
            ui.set_error("".into());
            ui.set_status(format!("Downloading {name} for editing…").into());
        }
        let request_ui = ui_weak.clone();
        let request_panes = panes.clone();
        let request_handle = handle.clone();
        let request_store = store.clone();
        handle.spawn(async move {
            let result: Result<RemoteEditOutcome, String> = async {
                let root = create_private_drag_root()?;
                let local = remote_local_target(&root, &name).map_err(|e| e.to_string())?;
                let remote = join_remote(PathBuf::from(&cwd).join(&name));
                let mut retain_root = false;
                let operation: Result<RemoteEditOutcome, String> = async {
                    let mut listing_spec = spec.clone();
                    listing_spec.initial_path = cwd.clone();
                    let (entries, _) = net::connect_and_list(&listing_spec, &password)
                        .await
                        .map_err(|e| format!("could not inspect remote file: {e}"))?;
                    let snapshot = entries
                        .iter()
                        .find(|entry| entry.name == name && !entry.is_dir)
                        .ok_or_else(|| "Remote file no longer exists or is not a file.".to_string())?;
                    if snapshot.size > max_edit_bytes {
                        return Err(format!(
                            "Remote editing is limited to {}; download the file for larger changes.",
                            fmt_size(max_edit_bytes)
                        ));
                    }
                    net::download_file_limited(
                        &spec,
                        &password,
                        &remote,
                        local.clone(),
                        max_edit_bytes,
                    )
                        .await
                        .map_err(|e| format!("edit download failed: {e}"))?;
                    let before = tokio::task::spawn_blocking({
                        let local = local.clone();
                        move || sha256_file(&local)
                    })
                    .await
                    .map_err(|e| e.to_string())??;
                    let editor_status = tokio::task::spawn_blocking({
                        let local = local.clone();
                        let editor_application = editor_application.clone();
                        move || {
                            let mut command = std::process::Command::new("open");
                            command.arg("-W");
                            if let Some(application) = editor_application {
                                command.arg("-a").arg(application);
                            }
                            command.arg("--").arg(local).status()
                        }
                    })
                    .await
                    .map_err(|e| e.to_string())?
                    .map_err(|e| format!("could not open the default editor: {e}"))?;
                    if !editor_status.success() {
                        return Err("The default editor exited with an error; nothing was uploaded."
                            .into());
                    }
                    let after = tokio::task::spawn_blocking({
                        let local = local.clone();
                        move || sha256_file(&local)
                    })
                    .await
                    .map_err(|e| e.to_string())??;
                    if before == after {
                        return Ok(RemoteEditOutcome::Message(format!(
                            "{name} was not changed."
                        )));
                    }
                    if !auto_upload {
                        retain_root = true;
                        return Ok(RemoteEditOutcome::Message(format!(
                            "Edited {name} retained locally at {}; automatic upload is disabled.",
                            local.display()
                        )));
                    }

                    // Optimistic concurrency check using exact bytes, not just LIST size/mtime.
                    // FTP timestamps are often coarse and a same-size edit must still be caught.
                    let current_copy = root.join(".gmacftp-server-current");
                    net::download_file_limited(
                        &spec,
                        &password,
                        &remote,
                        current_copy.clone(),
                        max_edit_bytes,
                    )
                        .await
                        .map_err(|e| format!("could not verify remote version: {e}"))?;
                    let current_hash = tokio::task::spawn_blocking({
                        let current_copy = current_copy.clone();
                        move || sha256_file(&current_copy)
                    })
                    .await
                    .map_err(|e| e.to_string())??;
                    if current_hash != before {
                        match conflict_action.as_str() {
                            "upload_copy" => {
                                let mut conflict_name = None;
                                for _ in 0..8 {
                                    let candidate =
                                        editor_conflict_copy_name(&name, rand::random::<u64>());
                                    let exists = net::remote_exists(
                                        &spec,
                                        &password,
                                        &cwd,
                                        &candidate,
                                    )
                                    .await
                                    .map_err(|error| {
                                        format!("could not check conflict-copy name: {error}")
                                    })?;
                                    if !exists {
                                        conflict_name = Some(candidate);
                                        break;
                                    }
                                }
                                let conflict_name = conflict_name.ok_or_else(|| {
                                    "could not allocate a unique remote conflict-copy name"
                                        .to_string()
                                })?;
                                let conflict_remote =
                                    join_remote(PathBuf::from(&cwd).join(&conflict_name));
                                net::upload_file(
                                    &spec,
                                    &password,
                                    local.clone(),
                                    &conflict_remote,
                                )
                                .await
                                .map_err(|error| {
                                    format!("conflict-copy upload failed: {error}")
                                })?;
                                let _ = std::fs::remove_file(&current_copy);
                                return Ok(RemoteEditOutcome::Message(format!(
                                    "Remote {name} changed; uploaded the local edit as {conflict_name}."
                                )));
                            }
                            "overwrite" => {
                                net::upload_file(&spec, &password, local.clone(), &remote)
                                    .await
                                    .map_err(|error| {
                                        format!("conflict overwrite failed: {error}")
                                    })?;
                                let _ = std::fs::remove_file(&current_copy);
                                return Ok(RemoteEditOutcome::Message(format!(
                                    "Remote {name} changed and was overwritten with the local edit by policy."
                                )));
                            }
                            _ => {
                                retain_root = true;
                                let (diff_preview, diff_summary) = tokio::task::spawn_blocking({
                                    let current_copy = current_copy.clone();
                                    let local = local.clone();
                                    move || editor_diff_preview(&current_copy, &local)
                                })
                                .await
                                .map_err(|error| error.to_string())??;
                                return Ok(RemoteEditOutcome::Conflict(Box::new(
                                    PendingEditorConflict {
                                        spec: spec.clone(),
                                        pane,
                                        cwd: cwd.clone(),
                                        name: name.clone(),
                                        remote_path: remote.clone(),
                                        root: root.clone(),
                                        local_path: local.clone(),
                                        server_path: current_copy,
                                        server_hash: current_hash,
                                        diff_summary,
                                        diff_preview,
                                    },
                                )));
                            }
                        }
                    }
                    let _ = std::fs::remove_file(&current_copy);
                    net::upload_file(&spec, &password, local.clone(), &remote)
                        .await
                        .map_err(|e| format!("edited file upload failed: {e}"))?;
                    Ok(RemoteEditOutcome::Message(format!(
                        "Uploaded edited {name}."
                    )))
                }
                .await;
                if operation.is_err() && temp_retention == "on_error" && local.is_file() {
                    retain_root = true;
                }
                if temp_retention == "always" && local.is_file() {
                    retain_root = true;
                }
                let retained_path = local.display().to_string();
                let operation = operation.map(|outcome| match outcome {
                    RemoteEditOutcome::Message(message) => {
                        if temp_retention == "always" && !message.contains(&retained_path) {
                            RemoteEditOutcome::Message(format!(
                                "{message} Local edit retained at {retained_path}."
                            ))
                        } else {
                            RemoteEditOutcome::Message(message)
                        }
                    }
                    RemoteEditOutcome::Conflict(conflict) => {
                        RemoteEditOutcome::Conflict(conflict)
                    }
                });
                let operation = operation.map_err(|error| {
                    if retain_root {
                        if error.contains(&retained_path) {
                            error
                        } else {
                            format!("{error} Local edit retained at {retained_path}.")
                        }
                    } else {
                        error
                    }
                });
                if !retain_root {
                    let _ = std::fs::remove_dir_all(&root);
                }
                operation
            }
            .await;

            let _ = slint::invoke_from_event_loop(move || {
                let Some(ui) = request_ui.upgrade() else { return };
                match result {
                    Ok(RemoteEditOutcome::Message(message)) => {
                        ui.set_error("".into());
                        ui.set_status(message.into());
                        if remote_pane_request_is_current(
                            &request_panes,
                            pane,
                            spec.id,
                            &cwd,
                        ) {
                            refresh_pane(
                                &request_handle,
                                request_store,
                                request_panes,
                                ui.as_weak(),
                                pane,
                            );
                        }
                    }
                    Ok(RemoteEditOutcome::Conflict(conflict)) => {
                        let conflict = *conflict;
                        let retained_path = conflict.local_path.to_string_lossy().into_owned();
                        let mut stored = false;
                        if let Ok(mut pending) = PENDING_EDITOR_CONFLICT.lock() {
                            if pending.is_none() {
                                ui.set_edit_conflict_name(conflict.name.clone().into());
                                ui.set_edit_conflict_summary(
                                    conflict.diff_summary.clone().into(),
                                );
                                ui.set_edit_conflict_preview(
                                    conflict.diff_preview.clone().into(),
                                );
                                ui.set_edit_conflict_local_path(
                                    conflict.local_path.to_string_lossy().into_owned().into(),
                                );
                                *pending = Some(conflict);
                                stored = true;
                            }
                        }
                        ui.set_edit_conflict_busy(false);
                        ui.set_status("".into());
                        if stored {
                            ui.set_error("".into());
                            ui.set_edit_conflict_open(true);
                        } else {
                            ui.set_error(
                                format!(
                                    "Another edit conflict is already open. This local edit was retained at {retained_path}."
                                )
                                .into(),
                            );
                        }
                    }
                    Err(error) => {
                        ui.set_status("".into());
                        ui.set_error(error.into());
                    }
                }
            });
        });
    });
}

enum EditorConflictActionResult {
    Completed(String),
    ChangedAgain(Box<PendingEditorConflict>),
}

fn show_editor_conflict(ui: &App, conflict: &PendingEditorConflict) {
    ui.set_edit_conflict_name(conflict.name.clone().into());
    ui.set_edit_conflict_summary(conflict.diff_summary.clone().into());
    ui.set_edit_conflict_preview(conflict.diff_preview.clone().into());
    ui.set_edit_conflict_local_path(conflict.local_path.to_string_lossy().into_owned().into());
    ui.set_edit_conflict_busy(false);
    ui.set_edit_conflict_open(true);
}

async fn perform_editor_conflict_action(
    mut conflict: PendingEditorConflict,
    password: String,
    decision: i32,
) -> Result<EditorConflictActionResult, String> {
    match decision {
        1 => {
            let mut copy_name = None;
            for _ in 0..8 {
                let candidate = editor_conflict_copy_name(&conflict.name, rand::random::<u64>());
                let exists =
                    net::remote_exists(&conflict.spec, &password, &conflict.cwd, &candidate)
                        .await
                        .map_err(|error| format!("could not check conflict-copy name: {error}"))?;
                if !exists {
                    copy_name = Some(candidate);
                    break;
                }
            }
            let copy_name = copy_name.ok_or_else(|| {
                "could not allocate a unique name for the edited copy".to_string()
            })?;
            let copy_remote = join_remote(PathBuf::from(&conflict.cwd).join(&copy_name));
            net::upload_file(
                &conflict.spec,
                &password,
                conflict.local_path.clone(),
                &copy_remote,
            )
            .await
            .map_err(|error| format!("could not upload edited copy: {error}"))?;
            let mut message = format!("Uploaded the local edit as {copy_name}.");
            if store::settings::load().editor_temp_retention == "always" {
                message.push_str(&format!(
                    " Local edit retained at {}.",
                    conflict.local_path.display()
                ));
            } else {
                let _ = std::fs::remove_dir_all(&conflict.root);
            }
            Ok(EditorConflictActionResult::Completed(message))
        }
        2 => {
            let max_bytes = (store::settings::load().editor_max_download_mib as u64)
                .saturating_mul(1024 * 1024)
                .min((store::settings::MAX_EDITOR_DOWNLOAD_MIB as u64).saturating_mul(1024 * 1024));
            let verification = conflict.root.join(".gmacftp-server-recheck");
            net::download_file_limited(
                &conflict.spec,
                &password,
                &conflict.remote_path,
                verification.clone(),
                max_bytes,
            )
            .await
            .map_err(|error| format!("could not recheck the server version: {error}"))?;
            let verified_hash = tokio::task::spawn_blocking({
                let verification = verification.clone();
                move || sha256_file(&verification)
            })
            .await
            .map_err(|error| error.to_string())??;
            if verified_hash != conflict.server_hash {
                std::fs::rename(&verification, &conflict.server_path).map_err(|error| {
                    format!("could not preserve the latest server version: {error}")
                })?;
                conflict.server_hash = verified_hash;
                let (preview, summary) = tokio::task::spawn_blocking({
                    let server_path = conflict.server_path.clone();
                    let local_path = conflict.local_path.clone();
                    move || editor_diff_preview(&server_path, &local_path)
                })
                .await
                .map_err(|error| error.to_string())??;
                conflict.diff_preview = preview;
                conflict.diff_summary =
                    format!("Server changed again during conflict resolution. {summary}");
                return Ok(EditorConflictActionResult::ChangedAgain(Box::new(conflict)));
            }
            let _ = std::fs::remove_file(&verification);
            net::upload_file(
                &conflict.spec,
                &password,
                conflict.local_path.clone(),
                &conflict.remote_path,
            )
            .await
            .map_err(|error| format!("could not overwrite after recheck: {error}"))?;
            let mut message = format!(
                "Overwrote {} only after confirming the server version was unchanged.",
                conflict.name
            );
            if store::settings::load().editor_temp_retention == "always" {
                message.push_str(&format!(
                    " Local edit retained at {}.",
                    conflict.local_path.display()
                ));
            } else {
                let _ = std::fs::remove_dir_all(&conflict.root);
            }
            Ok(EditorConflictActionResult::Completed(message))
        }
        _ => Err("invalid editor conflict action".into()),
    }
}

fn wire_editor_conflict_resolution(
    ui: &App,
    handle: &Handle,
    store: Arc<dyn CredentialStore>,
    panes: Panes,
) {
    let ui_weak = ui.as_weak();
    let handle = handle.clone();
    ui.on_resolve_editor_conflict(move |decision| {
        let pending = PENDING_EDITOR_CONFLICT
            .lock()
            .ok()
            .and_then(|mut pending| pending.take());
        let Some(conflict) = pending else {
            if let Some(ui) = ui_weak.upgrade() {
                ui.set_edit_conflict_open(false);
                ui.set_edit_conflict_busy(false);
            }
            return;
        };
        if decision == 0 {
            let _ = std::fs::remove_file(&conflict.server_path);
            if let Some(ui) = ui_weak.upgrade() {
                ui.set_edit_conflict_open(false);
                ui.set_edit_conflict_busy(false);
                ui.set_error("".into());
                ui.set_status(
                    format!(
                        "Local edit kept at {}; the server was not changed.",
                        conflict.local_path.display()
                    )
                    .into(),
                );
            }
            return;
        }
        let Some(password) = password_for(&store, &conflict.spec) else {
            if let Ok(mut pending) = PENDING_EDITOR_CONFLICT.lock() {
                *pending = Some(conflict.clone());
            }
            if let Some(ui) = ui_weak.upgrade() {
                ui.set_edit_conflict_busy(false);
                ui.set_error("Missing credential; both edit versions remain preserved.".into());
            }
            return;
        };
        if let Some(ui) = ui_weak.upgrade() {
            ui.set_edit_conflict_busy(true);
            ui.set_error("".into());
        }
        let backup = conflict.clone();
        let request_ui = ui_weak.clone();
        let request_store = store.clone();
        let request_panes = panes.clone();
        let request_handle = handle.clone();
        handle.spawn(async move {
            let result = perform_editor_conflict_action(conflict, password, decision).await;
            let _ = slint::invoke_from_event_loop(move || {
                let Some(ui) = request_ui.upgrade() else {
                    return;
                };
                ui.set_edit_conflict_busy(false);
                match result {
                    Ok(EditorConflictActionResult::Completed(message)) => {
                        ui.set_edit_conflict_open(false);
                        ui.set_error("".into());
                        ui.set_status(message.into());
                        if remote_pane_request_is_current(
                            &request_panes,
                            backup.pane,
                            backup.spec.id,
                            &backup.cwd,
                        ) {
                            refresh_pane(
                                &request_handle,
                                request_store,
                                request_panes,
                                ui.as_weak(),
                                backup.pane,
                            );
                        }
                    }
                    Ok(EditorConflictActionResult::ChangedAgain(updated)) => {
                        let updated = *updated;
                        if let Ok(mut pending) = PENDING_EDITOR_CONFLICT.lock() {
                            *pending = Some(updated.clone());
                        }
                        show_editor_conflict(&ui, &updated);
                        ui.set_error(
                            "The server file changed again. Review the refreshed diff before choosing another action."
                                .into(),
                        );
                    }
                    Err(error) => {
                        if let Ok(mut pending) = PENDING_EDITOR_CONFLICT.lock() {
                            *pending = Some(backup.clone());
                        }
                        show_editor_conflict(&ui, &backup);
                        ui.set_error(
                            format!("Conflict resolution failed safely: {error}").into(),
                        );
                    }
                }
            });
        });
    });
}

// ── keyboard control + sidebar eject ──────────────────────────────────────────

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

/// Remove finished rows from the transfer panel and release their retry/resume records.
fn wire_disconnect(ui: &App, panes: Panes, sessions: Sessions, engine: TransferEngine) {
    let ui_weak = ui.as_weak();
    ui.on_disconnect(move || {
        let pane = ui_weak.upgrade().map(|u| active_pane_idx(&u)).unwrap_or(1);
        set_skip_delete_confirm(pane, false); // the active pane's connection ended → re-arm it
                                              // Toolbar Disconnect = eject the active pane's session from the pool entirely.
        let conn_id = panes.lock().expect("panes")[pane]
            .conn
            .as_ref()
            .map(|c| c.id.0 as i32);
        if let Some(id) = conn_id {
            disconnect_session(
                engine.clone(),
                sessions.clone(),
                panes.clone(),
                ui_weak.clone(),
                id,
            );
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
fn wire_session_controls(
    ui: &App,
    handle: &Handle,
    store: Arc<dyn CredentialStore>,
    sessions: Sessions,
    panes: Panes,
    engine: TransferEngine,
) {
    {
        let (h, st, se, pn, uw) = (
            handle.clone(),
            store.clone(),
            sessions.clone(),
            panes.clone(),
            ui.as_weak(),
        );
        ui.on_switch_to_session(move |id| {
            let pane = uw.upgrade().map(|u| active_pane_idx(&u)).unwrap_or(0);
            switch_to_session(&h, st.clone(), se.clone(), pn.clone(), uw.clone(), pane, id);
        });
    }
    {
        let (se, pn, en, uw) = (
            sessions.clone(),
            panes.clone(),
            engine.clone(),
            ui.as_weak(),
        );
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
            let show_hidden = !ui.get_show_hidden();
            let mut settings = store::settings::load();
            settings.show_hidden_files = show_hidden;
            if let Err(error) = store::settings::try_save(&settings) {
                ui.set_error(format!("Could not save hidden-file preference: {error}").into());
                return;
            }
            ui.set_show_hidden(show_hidden);
            ui.set_settings_show_hidden(show_hidden);
            apply_view_pane(&ui, 0);
            apply_view_pane(&ui, 1);
        }
    });
}

fn set_advanced_columns_visibility(ui: &App, show: bool) {
    ui.set_show_advanced_columns(show);
    ui.set_settings_show_advanced_columns(show);
    if show {
        return;
    }

    for pane in 0..2 {
        let key = if pane == 0 {
            ui.get_local_sort_key().to_string()
        } else {
            ui.get_remote_sort_key().to_string()
        };
        if !matches!(key.as_str(), "owner" | "group" | "permissions") {
            continue;
        }
        if pane == 0 {
            ui.set_local_sort_key("name".into());
            ui.set_local_sort_dir("asc".into());
        } else {
            ui.set_remote_sort_key("name".into());
            ui.set_remote_sort_dir("asc".into());
        }
        apply_view_pane(ui, pane);
    }
}

fn wire_toggle_advanced_columns(ui: &App) {
    let ui_weak = ui.as_weak();
    ui.on_toggle_advanced_columns(move || {
        let Some(ui) = ui_weak.upgrade() else {
            return;
        };
        let show = !ui.get_show_advanced_columns();
        let mut settings = store::settings::load();
        settings.show_advanced_columns = show;
        if let Err(error) = store::settings::try_save(&settings) {
            ui.set_error(format!("Could not save column preference: {error}").into());
            return;
        }
        set_advanced_columns_visibility(&ui, show);
    });
}

fn wire_toggle_background_metadata(
    ui: &App,
    handle: &Handle,
    store: Arc<dyn CredentialStore>,
    panes: Panes,
) {
    let ui_weak = ui.as_weak();
    let handle = handle.clone();
    ui.on_toggle_background_metadata(move || {
        let Some(ui) = ui_weak.upgrade() else {
            return;
        };
        let enabled = !ui.get_background_folder_metadata();
        let mut settings = store::settings::load();
        settings.background_folder_metadata = enabled;
        if let Err(error) = store::settings::try_save(&settings) {
            ui.set_error(format!("Could not save folder-size preference: {error}").into());
            return;
        }
        ui.set_background_folder_metadata(enabled);
        ui.set_settings_background_metadata(enabled);
        ui.set_status(
            if enabled {
                "Background folder sizes enabled (bounded to two recursive scans)."
            } else {
                "Background folder sizes disabled; use Calculate Size on demand."
            }
            .into(),
        );
        refresh_pane(&handle, store.clone(), panes.clone(), ui.as_weak(), 0);
        refresh_pane(&handle, store.clone(), panes.clone(), ui.as_weak(), 1);
    });
}

#[derive(Debug, Clone, Copy, Default, serde::Serialize)]
struct StorageStats {
    config_bytes: u64,
    cache_bytes_approx: u64,
    cache_entries: usize,
    fragment_bytes: u64,
    fragment_count: usize,
    temporary_bytes: u64,
    temporary_directories: usize,
    persistent_log_bytes: u64,
    scan_truncated: bool,
}

fn sort_by(ui: &App, pane: usize, key: &str) {
    let Ok(pane_id) = PaneId::try_from(pane as i32) else {
        ui.set_error("pane index is out of range".into());
        return;
    };
    let Ok(requested_key) = SortKey::try_from(key) else {
        ui.set_error("Invalid sort field.".into());
        return;
    };
    let (cur_key, cur_dir) = if pane == 0 {
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
    let Ok(cur_key) = SortKey::try_from(cur_key.as_str()) else {
        ui.set_error("Stored sort field is invalid.".into());
        return;
    };
    let Ok(cur_dir) = SortDirection::try_from(cur_dir.as_str()) else {
        ui.set_error("Stored sort direction is invalid.".into());
        return;
    };
    let (next_key, next_dir) = if cur_key == requested_key {
        (cur_key, cur_dir.reversed())
    } else {
        (requested_key, SortDirection::Ascending)
    };
    if pane_id == PaneId::Left {
        ui.set_local_sort_key(next_key.as_str().into());
        ui.set_local_sort_dir(next_dir.as_str().into());
    } else {
        ui.set_remote_sort_key(next_key.as_str().into());
        ui.set_remote_sort_dir(next_dir.as_str().into());
    }
    ui.set_error("".into());
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
    let (handle, store, panes, engine, idx, ui_weak) = (
        handle.clone(),
        store.clone(),
        panes.clone(),
        engine,
        idx,
        ui.as_weak(),
    );
    ui.on_download(move || {
        transfer(
            &handle,
            store.clone(),
            panes.clone(),
            engine.clone(),
            idx.clone(),
            ui_weak.clone(),
            1,
            0,
        );
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
    let (handle, store, panes, engine, idx, ui_weak) = (
        handle.clone(),
        store.clone(),
        panes.clone(),
        engine,
        idx,
        ui.as_weak(),
    );
    ui.on_upload(move || {
        transfer(
            &handle,
            store.clone(),
            panes.clone(),
            engine.clone(),
            idx.clone(),
            ui_weak.clone(),
            0,
            1,
        );
    });
}

fn wire_toggle_locale(ui: &App) {
    let ui_weak = ui.as_weak();
    ui.on_toggle_locale(move || {
        if let Some(ui) = ui_weak.upgrade() {
            let g = crate::I18n::get(&ui);
            let next = if g.get_locale() == "pl" { "en" } else { "pl" };
            let mut settings = store::settings::load();
            settings.locale = next.to_string();
            match store::settings::try_save(&settings) {
                Ok(()) => {
                    apply_locale(&ui, next);
                    ui.set_settings_locale(next.into());
                    ui.set_error("".into());
                }
                Err(error) => ui.set_error(format!("Could not save language: {error}").into()),
            }
        }
    });
}

// ── connection manager wiring ─────────────────────────────────────────────────

fn recovered_transfer_row(job: &TransferJob, spec: &ConnectionSpec) -> TransferRow {
    let direction = match job.direction {
        TransferDirection::Download => "download",
        TransferDirection::Upload => "upload",
    };
    let name = match job.direction {
        TransferDirection::Upload => Path::new(&job.local_path)
            .file_name()
            .map(|name| name.to_string_lossy().into_owned()),
        TransferDirection::Download => job
            .remote_path
            .trim_end_matches('/')
            .rsplit('/')
            .next()
            .filter(|name| !name.is_empty())
            .map(str::to_string),
    }
    .unwrap_or_else(|| job.remote_path.clone());
    let route = match job.direction {
        TransferDirection::Upload => format!("local -> {}", spec.host),
        TransferDirection::Download => format!("{} -> local", spec.host),
    };
    let total = job.bytes_total.unwrap_or(0);
    TransferRow {
        id: job.id.0 as i32,
        name: name.into(),
        direction: direction.into(),
        route: route.into(),
        done: 0,
        total: total.min(i32::MAX as u64) as i32,
        progress_text: fmt_transfer_progress(0, total).into(),
        fraction: 0.0,
        state: "recovered".into(),
        priority: match job.priority {
            TransferPriority::Low => "low",
            TransferPriority::Normal => "normal",
            TransferPriority::High => "high",
        }
        .into(),
        message: if job.direction == TransferDirection::Download {
            "Resume or discard"
        } else {
            "Resume safely (or restart) / discard"
        }
        .into(),
    }
}

fn fresh_resume_token() -> u64 {
    loop {
        let token = rand::random::<u64>();
        if token != 0 {
            return token;
        }
    }
}

fn source_modified_unix_nanos(path: &Path) -> Option<u64> {
    let elapsed = std::fs::metadata(path)
        .ok()?
        .modified()
        .ok()?
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?;
    u64::try_from(elapsed.as_nanos()).ok()
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
    batch: TransferBatch,
) {
    let id = TransferId(fresh_xfer_id());
    let dir_s = match direction {
        TransferDirection::Download => "download",
        TransferDirection::Upload => "upload",
    };
    let verb = match direction {
        TransferDirection::Download => "Downloading",
        TransferDirection::Upload => "Uploading",
    };
    // Cap at i32::MAX (not wrap) for the Slint int fields — a >2 GiB file would otherwise wrap to
    // a negative transfer-total and hide the bottom progress bar (gated on transfer-total > 0).
    // The true u64 total still drives the progress TEXT via fmt_transfer_progress(u64).
    let total_i = bytes_total.unwrap_or(0).min(i32::MAX as u64) as i32;
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
        progress_text: fmt_transfer_progress(0, bytes_total.unwrap_or(0)).into(),
        fraction: 0.0,
        state: "queued".into(),
        priority: "normal".into(),
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
    ui.set_transfer_progress_text(fmt_transfer_progress(0, bytes_total.unwrap_or(0)).into());
    ui.set_status("".into());
    ui.set_error("".into());

    let source_modified_unix_nanos = matches!(direction, TransferDirection::Upload)
        .then(|| source_modified_unix_nanos(&local_path))
        .flatten();
    let job = TransferJob {
        id,
        batch_id: batch.id,
        pause_on_error: batch.pause_on_error,
        priority: Default::default(),
        direction,
        local_path: local_path.to_string_lossy().to_string(),
        remote_path,
        bytes_total,
        source_modified_unix_nanos,
        resume_token: fresh_resume_token(),
    };
    if engine.try_enqueue(job, spec).is_err() {
        // M4/CONC-1: the bounded worker channel was full — the job was NOT accepted. Mark
        // the just-inserted row as failed so it never sits on "queued" forever silently.
        jobs_set(
            id.0 as i32,
            idx,
            "failed",
            0,
            total_i,
            "transfer queue full",
        );
    }
}

fn spawn_progress_forwarder(
    handle: &Handle,
    store: Arc<dyn CredentialStore>,
    panes: Panes,
    engine: TransferEngine,
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
            let mirror_outcome = observe_mirror_batch(&u);
            let mirror_deletion_started = matches!(mirror_outcome, Some(MirrorBatchOutcome::Ready(_)));
            let mirror_deletion_aborted = match &mirror_outcome {
                Some(MirrorBatchOutcome::Aborted { deletion_count }) => Some(*deletion_count),
                _ => None,
            };
            let mirror_task = match mirror_outcome {
                Some(MirrorBatchOutcome::Ready(pending)) => Some((
                    handle.clone(),
                    store.clone(),
                    panes.clone(),
                    ui.clone(),
                    pending,
                )),
                _ => None,
            };
            let (idx, eta, ui, store, panes, engine, pending_gen, handle) = (
                idx.clone(),
                eta.clone(),
                ui.clone(),
                store.clone(),
                panes.clone(),
                engine.clone(),
                pending_gen.clone(),
                handle.clone(),
            );
            let _ = slint::invoke_from_event_loop(move || {
                let Some(ui) = ui.upgrade() else { return };
                let total = u.bytes_total.unwrap_or(0);
                let mut failed_name = String::new();

                // update the matching transfer-panel row (UI-thread model via thread-local)
                TRANSFER_JOBS.with(|jm| {
                    let b = jm.borrow();
                    let Some(jobs) = b.as_ref() else { return };
                    let Some(i) = idx.lock().ok().and_then(|g| g.get(&id).copied()) else {
                        return;
                    };
                    let Some(mut row) = jobs.row_data(i) else {
                        return;
                    };
                    match &u.state {
                        TransferState::Active => {
                            row.state = "active".into();
                            row.done = u.bytes_done as i32;
                            row.total = total.min(i32::MAX as u64) as i32;
                            row.fraction = if total > 0 {
                                u.bytes_done as f32 / total as f32
                            } else {
                                0.0
                            };
                            row.progress_text = fmt_transfer_progress(u.bytes_done, total).into();
                            row.message = format_eta(&eta, id, u.bytes_done, total);
                            // Mirror the file currently being copied into the compact bottom bar
                            // — otherwise a fast batch leaves it stuck on the initial label.
                            ui.set_transfer_label(row.name.clone());
                        }
                        TransferState::Retrying {
                            attempt,
                            max_attempts,
                            delay_ms,
                            error,
                        } => {
                            row.state = "queued".into();
                            row.message = format!(
                                "retry {attempt}/{max_attempts} in {} — {error}",
                                format_retry_delay(*delay_ms)
                            )
                            .into();
                        }
                        TransferState::Done => {
                            row.state = "done".into();
                            row.fraction = 1.0;
                            row.done = row.total;
                            row.progress_text = fmt_transfer_progress(total, total).into();
                            row.message = "".into();
                        }
                        TransferState::Failed(msg) => {
                            row.state = "failed".into();
                            row.message = msg.clone().into();
                            failed_name = row.name.to_string();
                        }
                        TransferState::Cancelled => {
                            row.state = "cancelled".into();
                            row.message = if row.direction.as_str() == "download" {
                                "cancelled — Resume available"
                            } else {
                                "cancelled — Retry available"
                            }
                            .into();
                        }
                        TransferState::Skipped(msg) => {
                            row.state = "failed".into();
                            row.message = format!("skipped — {msg}").into();
                        }
                    }
                    jobs.set_row_data(i, row);
                    update_transfer_summary_from_model(&ui, jobs);
                });

                // compact bottom bar mirrors the active/done/failed job
                match &u.state {
                    TransferState::Active => {
                        let frac = if total > 0 {
                            u.bytes_done as f32 / total as f32
                        } else {
                            0.0
                        };
                        ui.set_transfer_active(true);
                        ui.set_transfer_done(u.bytes_done as i32);
                        ui.set_transfer_total(total.min(i32::MAX as u64) as i32);
                        ui.set_transfer_fraction(frac);
                        ui.set_transfer_progress_text(
                            fmt_transfer_progress(u.bytes_done, total).into(),
                        );
                    }
                    TransferState::Retrying {
                        attempt,
                        max_attempts,
                        delay_ms,
                        error,
                    } => {
                        ui.set_transfer_active(false);
                        ui.set_status(
                            format!(
                                "temporary transfer error; retry {attempt}/{max_attempts} in {}",
                                format_retry_delay(*delay_ms)
                            )
                            .into(),
                        );
                        ui.set_error(error.clone().into());
                    }
                    TransferState::Done => {
                        ui.set_transfer_active(false);
                        ui.set_transfer_fraction(1.0);
                        // Only announce completion once the WHOLE batch is finished. Setting this on
                        // every file's Done made "transfer complete" flash between files and overlap
                        // the bottom-bar filename; mid-batch we clear it (and the bar hides status
                        // while transfer-active anyway). transfer-pending-count was just refreshed.
                        if ui.get_transfer_pending_count() == 0 {
                            ui.set_status("transfer complete".into());
                            if store::settings::load().notify_transfer_completion {
                                crate::notifications::send(
                                    "gmacFTP — transfer complete",
                                    "All queued transfers finished.",
                                );
                            }
                        } else {
                            ui.set_status("".into());
                        }
                        // (Re)arm a trailing 600ms refresh timer; only the latest arming fires.
                        // This runs on the UI thread; spawn the timer on the runtime, then hop
                        // back to the UI thread for the re-list (Slint models are !Send).
                        let gen = pending_gen.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
                        let (h, st, pn, uw, pg) = (
                            handle.clone(),
                            store.clone(),
                            panes.clone(),
                            ui.as_weak(),
                            pending_gen.clone(),
                        );
                        handle.spawn(async move {
                            tokio::time::sleep(std::time::Duration::from_millis(600)).await;
                            if pg.load(std::sync::atomic::Ordering::SeqCst) == gen {
                                let _ = slint::invoke_from_event_loop(move || {
                                    if let Some(ui) = uw.upgrade() {
                                        // Suppress the re-list while a batch (folder) transfer is
                                        // still in flight — otherwise each file's Done fires its
                                        // own pane refresh (flicker + size recalculation). Refresh
                                        // only once the panel has no active/queued rows left.
                                        let busy = TRANSFER_JOBS.with(|jm| {
                                            jm.borrow()
                                                .as_ref()
                                                .map(|jobs| {
                                                    (0..jobs.row_count()).any(|i| {
                                                        jobs.row_data(i).is_some_and(|r| {
                                                            matches!(&*r.state, "active" | "queued")
                                                        })
                                                    })
                                                })
                                                .unwrap_or(false)
                                        });
                                        if !busy {
                                            refresh_both_panes(&h, st, pn, ui.as_weak());
                                        }
                                    }
                                });
                            }
                        });
                    }
                    TransferState::Failed(msg) => {
                        ui.set_transfer_active(false);
                        if store::settings::load().notify_transfer_failure {
                            crate::notifications::send(
                                "gmacFTP — transfer failed",
                                "A file transfer failed. Open Transfers for details.",
                            );
                        }
                        ui.set_transfer_error_name(failed_name.into());
                        ui.set_transfer_error_message(msg.clone().into());
                        if u.requires_decision {
                            match store::settings::load().batch_error_policy.as_str() {
                                "skip" => {
                                    engine.resolve_batch_failure(u.batch_id, true);
                                    ui.set_transfer_error_open(false);
                                    ui.set_transfer_error_needs_decision(false);
                                    ui.set_transfer_error_batch("".into());
                                    ui.set_status(
                                        "failed file skipped — continuing batch by policy".into(),
                                    );
                                    ui.set_error(msg.clone().into());
                                }
                                "stop" => {
                                    engine.resolve_batch_failure(u.batch_id, false);
                                    ui.set_transfer_error_open(false);
                                    ui.set_transfer_error_needs_decision(false);
                                    ui.set_transfer_error_batch("".into());
                                    ui.set_status(
                                        "stopping batch after a file error by policy".into(),
                                    );
                                    ui.set_error(msg.clone().into());
                                }
                                _ => {
                                    ui.set_transfer_error_needs_decision(true);
                                    ui.set_transfer_error_open(true);
                                    ui.set_transfer_error_batch(u.batch_id.to_string().into());
                                    ui.set_status("copy paused after a file error".into());
                                    ui.set_error("".into());
                                }
                            }
                        } else {
                            ui.set_transfer_error_needs_decision(false);
                            ui.set_transfer_error_open(true);
                            ui.set_transfer_error_batch("".into());
                            ui.set_status("file transfer failed".into());
                            ui.set_error(msg.clone().into());
                        }
                    }
                    TransferState::Cancelled => {
                        ui.set_transfer_active(false);
                        ui.set_status("transfer cancelled — use Resume/Retry in Transfers".into());
                        ui.set_error("".into());
                    }
                    TransferState::Skipped(_) => {
                        ui.set_transfer_active(false);
                        ui.set_status("remaining item skipped — batch stopped".into());
                    }
                }
                if mirror_deletion_started {
                    ui.set_status(
                        "all mirror copies succeeded; rechecking selected deletions…".into(),
                    );
                    ui.set_error("".into());
                } else if let Some(deletion_count) = mirror_deletion_aborted {
                    ui.set_status(
                        format!(
                            "mirror deletion cancelled: a copy did not finish successfully; {deletion_count} target file(s) kept"
                        )
                        .into(),
                    );
                }
            });
            if let Some((runtime, store, panes, ui, pending)) = mirror_task {
                let task_handle = runtime.clone();
                runtime.spawn(run_mirror_deletions(
                    task_handle,
                    store,
                    panes,
                    ui,
                    *pending,
                ));
            }
        }
    });
}

fn format_retry_delay(delay_ms: u64) -> String {
    if delay_ms < 1_000 {
        format!("{delay_ms} ms")
    } else if delay_ms.is_multiple_of(1_000) {
        format!("{} s", delay_ms / 1_000)
    } else {
        format!("{:.1} s", delay_ms as f64 / 1_000.0)
    }
}

/// Crude per-job ETA ("~Ns") from a sampled bytes/sec rate; empty when unknown.
fn format_eta(
    eta: &Arc<Mutex<HashMap<i32, (Instant, u64)>>>,
    id: i32,
    done: u64,
    total: u64,
) -> slint::SharedString {
    if total == 0 || done == 0 {
        return "".into();
    }
    let now = Instant::now();
    let rate = match eta.lock().ok() {
        Some(mut g) => {
            let r = match g.get(&id) {
                Some((t, prev)) => {
                    let dt = now.duration_since(*t).as_secs_f32();
                    if dt > 0.05 {
                        (done - prev) as f32 / dt
                    } else {
                        0.0
                    }
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
    let parts: Vec<&str> = s
        .split('/')
        .filter(|seg| !seg.is_empty() && *seg != "..")
        .collect();
    if parts.is_empty() {
        "/".to_string()
    } else {
        format!("/{}", parts.join("/"))
    }
}

/// Build a local destination from a server-controlled relative name.
///
/// `PathBuf::join` accepts an absolute second operand and preserves `..`, so this must be the
/// only route for remote → local names. `sanitize_local_rel` handles lexical traversal; the
/// resolved-path check additionally catches a pre-existing symlink below the chosen root.
fn remote_local_target(root: &Path, remote_name: &str) -> Result<PathBuf, net::NetError> {
    let clean = net::sanitize_local_rel(remote_name)?;
    let target = root.join(clean);
    net::assert_within(root, &target)?;
    Ok(target)
}

#[cfg(test)]
mod path_safety_tests {
    use super::*;
    use std::cell::{Cell, RefCell};
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn scratch_dir() -> PathBuf {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::temp_dir().join(format!(
            "gmacftp-app-path-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn environment_detector_distinguishes_polling_network_changes_and_wake_gaps() {
        let start = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);
        let mut detector = EnvironmentChangeDetector::new(start, true);
        assert!(!detector.observe(start + Duration::from_secs(2), true));
        assert!(detector.observe(start + Duration::from_secs(4), false));
        assert!(!detector.observe(start + Duration::from_secs(6), false));
        assert!(detector.observe(start + Duration::from_secs(8), true));
        assert!(detector.observe(start + Duration::from_secs(20), true));
        assert!(detector.observe(start, true));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn only_route_capable_macos_interfaces_drive_transfer_recovery() {
        for name in ["en0", "bridge100", "utun3", "ppp0", "ipsec0"] {
            assert!(is_route_capable_interface_name(name));
        }
        for name in ["lo0", "awdl0", "llw0", "anpi0", "gif0"] {
            assert!(!is_route_capable_interface_name(name));
        }
    }

    fn send_key(ui: &App, key: impl Into<slint::SharedString>, pressed: bool) {
        let text = key.into();
        ui.window().dispatch_event(if pressed {
            slint::platform::WindowEvent::KeyPressed { text }
        } else {
            slint::platform::WindowEvent::KeyReleased { text }
        });
    }

    #[test]
    fn keyboard_only_shortcuts_and_focus_activation_reach_ui_actions() {
        i_slint_backend_testing::init_no_event_loop();
        let ui = App::new().unwrap();
        apply_locale(&ui, "en");
        ui.set_active_pane("local".into());

        let select_calls = Rc::new(RefCell::new(Vec::new()));
        let recorded = select_calls.clone();
        ui.on_select_all(move |pane, selected| {
            recorded.borrow_mut().push((pane.to_string(), selected));
        });
        let moves = Rc::new(RefCell::new(Vec::new()));
        let recorded = moves.clone();
        ui.on_move_selection(move |delta, extend| {
            recorded.borrow_mut().push((delta, extend));
        });
        let entered = Rc::new(Cell::new(0));
        let recorded = entered.clone();
        ui.on_pane_enter(move || recorded.set(recorded.get() + 1));
        let closed = Rc::new(Cell::new(false));
        let recorded = closed.clone();
        ui.on_close_window(move || recorded.set(true));

        focus_root(&ui);
        send_key(&ui, slint::platform::Key::Control, true);
        send_key(&ui, "a", true);
        send_key(&ui, "a", false);
        send_key(&ui, slint::platform::Key::Control, false);
        assert_eq!(select_calls.borrow().as_slice(), &[("local".into(), true)]);

        send_key(&ui, slint::platform::Key::Shift, true);
        send_key(&ui, slint::platform::Key::DownArrow, true);
        send_key(&ui, slint::platform::Key::DownArrow, false);
        send_key(&ui, slint::platform::Key::Shift, false);
        assert_eq!(moves.borrow().as_slice(), &[(1, true)]);

        send_key(&ui, slint::platform::Key::Return, true);
        send_key(&ui, slint::platform::Key::Return, false);
        assert_eq!(entered.get(), 1);

        // Tab leaves the root pane FocusScope and reaches the first custom toolbar control.
        // Space must activate it through KeyboardActionArea, without any pointer event.
        focus_root(&ui);
        send_key(&ui, slint::platform::Key::Tab, true);
        send_key(&ui, slint::platform::Key::Tab, false);
        send_key(&ui, " ", true);
        send_key(&ui, " ", false);
        assert!(closed.get());

        // Exercise the same semantic surface used by VoiceOver, not just raw key dispatch.
        use i_slint_backend_testing::{AccessibleRole, ElementHandle};

        let close = ElementHandle::find_by_accessible_label(&ui, "Close window")
            .next()
            .expect("the window close control must have an accessible label");
        assert_eq!(close.accessible_role(), Some(AccessibleRole::Button));
        assert_eq!(close.accessible_enabled(), Some(true));

        // Exercise the real pointer route as well as the semantic accessibility action. Custom
        // controls wrap their mouse and keyboard handling in KeyboardActionArea; a zero-sized
        // inner TouchArea leaves the controls keyboard/VoiceOver accessible but ignores physical
        // mouse clicks (the v0.2.0 release regression).
        closed.set(false);
        close.mock_single_click(slint::platform::PointerEventButton::Left);
        assert!(
            closed.get(),
            "a physical pointer click must reach custom toolbar controls"
        );

        // Compact sidebar actions deliberately keep a 28 px hit target around a 12 px glyph.
        // Guard both the geometry and the physical event path: visual refinement must never make
        // the server action hard to hit or reintroduce the v0.2.0 click-through regression.
        ui.set_filtered_connections(ModelRc::from(Rc::new(VecModel::from(vec![ConnRow {
            id: 17,
            label: "Demo".into(),
            sub: "ftp.example.com".into(),
            protocol: "FTP".into(),
            connected: false,
        }]))));
        let sidebar_connects = Rc::new(RefCell::new(Vec::new()));
        let recorded = sidebar_connects.clone();
        ui.on_connect_selected_to_pane(move |pane| recorded.borrow_mut().push(pane.to_string()));
        let sidebar_connect = ElementHandle::find_by_accessible_label(&ui, "Connect to Demo")
            .next()
            .expect("the compact saved-server action must be exposed");
        let sidebar_size = sidebar_connect.size();
        assert_eq!((sidebar_size.width, sidebar_size.height), (28.0, 28.0));
        sidebar_connect.mock_single_click(slint::platform::PointerEventButton::Left);
        assert_eq!(sidebar_connects.borrow().as_slice(), &["local"]);

        let filter = ElementHandle::find_by_accessible_label(&ui, "Filter files in left pane")
            .next()
            .expect("the left file filter must be exposed as a text field");
        assert_eq!(filter.accessible_role(), Some(AccessibleRole::TextInput));
        assert_eq!(
            filter.accessible_placeholder_text().as_deref(),
            Some("Filter this folder…")
        );

        ui.set_local_all_selected(true);
        let select_all =
            ElementHandle::find_by_accessible_label(&ui, "Select all items in left pane")
                .next()
                .expect("the pane selection checkbox must be exposed");
        assert_eq!(select_all.accessible_role(), Some(AccessibleRole::Checkbox));
        assert_eq!(select_all.accessible_checkable(), Some(true));
        assert_eq!(select_all.accessible_checked(), Some(true));
        select_all.invoke_accessible_default_action();
        assert_eq!(select_calls.borrow().last(), Some(&("local".into(), false)));

        let divider = ElementHandle::find_by_accessible_label(&ui, "Pane divider position")
            .next()
            .expect("the pane divider must be exposed as a slider");
        assert_eq!(divider.accessible_role(), Some(AccessibleRole::Slider));
        assert_eq!(divider.accessible_value_minimum(), Some(220.0));
        assert_eq!(divider.accessible_value_step(), Some(20.0));
        assert!(divider
            .accessible_value_maximum()
            .is_some_and(|max| max > 220.0));
        assert!(divider
            .accessible_value()
            .and_then(|value| value.parse::<f32>().ok())
            .is_some_and(|value| value >= 220.0));

        // The updater is a full-window overlay. Its two actions must remain physically clickable;
        // this specifically guards the failure mode where a transparent scrim or a zero-sized
        // custom action area leaves the dialog visible but inert.
        let update_downloads = Rc::new(Cell::new(0));
        let recorded = update_downloads.clone();
        ui.on_download_update(move || recorded.set(recorded.get() + 1));
        let update_dismisses = Rc::new(Cell::new(0));
        let recorded = update_dismisses.clone();
        ui.on_dismiss_update(move || recorded.set(recorded.get() + 1));
        ui.set_update_version("0.2.2".into());
        ui.set_update_notes("Pointer regression check".into());
        ui.set_update_open(true);

        let download = ElementHandle::find_by_accessible_label(&ui, "Download & Verify")
            .next()
            .expect("the updater download action must be exposed");
        let download_size = download.size();
        assert!(download_size.width > 0.0 && download_size.height > 0.0);
        download.mock_single_click(slint::platform::PointerEventButton::Left);
        assert_eq!(
            update_downloads.get(),
            1,
            "the updater download action must receive a physical pointer click"
        );

        let later = ElementHandle::find_by_accessible_label(&ui, "Later")
            .next()
            .expect("the updater dismiss action must be exposed");
        let later_size = later.size();
        assert!(later_size.width > 0.0 && later_size.height > 0.0);
        later.mock_single_click(slint::platform::PointerEventButton::Left);
        assert_eq!(
            update_dismisses.get(),
            1,
            "the updater dismiss action must receive a physical pointer click"
        );

        // Legacy-vault recovery is another full-window security prompt. Both choices must stay
        // reachable by a real pointer event so the user can recover or safely defer.
        ui.set_update_open(false);
        let recovery_decisions = Rc::new(RefCell::new(Vec::new()));
        let recorded = recovery_decisions.clone();
        ui.on_resolve_credential_recovery(move |approved| recorded.borrow_mut().push(approved));
        ui.set_credential_recovery_count(2);
        ui.set_credential_recovery_open(true);

        let recover = ElementHandle::find_by_accessible_label(&ui, "Trust & Recover")
            .next()
            .expect("the credential recovery action must be exposed");
        let recover_size = recover.size();
        assert!(recover_size.width > 0.0 && recover_size.height > 0.0);
        recover.mock_single_click(slint::platform::PointerEventButton::Left);
        assert_eq!(recovery_decisions.borrow().as_slice(), &[true]);

        let defer = ElementHandle::find_by_accessible_label(&ui, "Not Now")
            .next()
            .expect("the credential recovery defer action must be exposed");
        let defer_size = defer.size();
        assert!(defer_size.width > 0.0 && defer_size.height > 0.0);
        defer.mock_single_click(slint::platform::PointerEventButton::Left);
        assert_eq!(recovery_decisions.borrow().as_slice(), &[true, false]);
    }

    #[test]
    fn remote_quarantine_destination_is_bounded_and_stays_below_cwd() {
        let original = "ż".repeat(127);
        let (directory, bucket, destination, quarantined_name) =
            remote_quarantine_destination("/incoming/reports", &original, 0x1234).unwrap();
        assert_eq!(directory, "/incoming/reports/.gmacftp-trash");
        assert!(destination.starts_with("/incoming/reports/.gmacftp-trash/"));
        assert!(bucket.ends_with(&quarantined_name));
        assert!(destination.ends_with(&format!("/{original}")));
        assert!(quarantined_name.len() <= 255);
        assert!(quarantined_name.ends_with(".deleted-00000000000000000000000000001234"));
        net::validate_remote_component(&quarantined_name).unwrap();
        assert_eq!(
            remote_quarantine_restore_context(&bucket).unwrap(),
            (directory, "/incoming/reports".into(), bucket)
        );
    }

    #[test]
    fn remote_quarantine_refuses_nested_trash_and_unsafe_names() {
        assert!(remote_quarantine_destination("/incoming/.gmacftp-trash", "file.txt", 1).is_err());
        assert!(remote_quarantine_destination("/incoming", REMOTE_QUARANTINE_DIR, 1).is_err());
        assert!(remote_quarantine_destination("/incoming", "../secret", 1).is_err());
        assert!(remote_quarantine_destination("/incoming/../escape", "safe.txt", 1).is_err());
        assert!(remote_quarantine_restore_context("/incoming/.gmacftp-trash").is_err());
        assert!(
            remote_quarantine_restore_context("/incoming/.gmacftp-trash/not-a-valid-bucket")
                .is_err()
        );
        assert_eq!(
            remote_quarantine_restore_context(
                "/.gmacftp-trash/file.deleted-00000000000000000000000000000001"
            )
            .unwrap()
            .1,
            "/"
        );
    }

    #[test]
    fn selection_mask_collects_all_range_and_disjoint_entries() {
        let rows = vec![
            demo_entry("folder", true, "", "—", 0, 0),
            demo_entry("file.txt", false, "", "3 B", 3, 0),
            demo_entry("photo.jpg", false, "", "4 B", 4, 0),
        ];
        let model = ModelRc::from(Rc::new(VecModel::from(rows)));

        let all_selection = ModelRc::from(Rc::new(VecModel::from(vec![true, true, true])));
        let all = selected_transfer_rows(&model, &all_selection);
        assert_eq!(all.len(), 3);
        assert!(all[0].is_dir);
        assert!(!all[1].is_dir);

        let one_selection = ModelRc::from(Rc::new(VecModel::from(vec![false, true, false])));
        let one = selected_transfer_rows(&model, &one_selection);
        assert_eq!(one.len(), 1);
        assert_eq!(one[0].name.as_str(), "file.txt");

        let range_selection = ModelRc::from(Rc::new(VecModel::from(vec![true, true, false])));
        let range = selected_transfer_rows(&model, &range_selection);
        assert_eq!(range.len(), 2);

        let disjoint_selection = ModelRc::from(Rc::new(VecModel::from(vec![true, false, true])));
        let disjoint = selected_transfer_rows(&model, &disjoint_selection);
        assert_eq!(
            disjoint
                .iter()
                .map(|row| row.name.as_str())
                .collect::<Vec<_>>(),
            ["folder", "photo.jpg"]
        );

        let none = ModelRc::from(Rc::new(VecModel::from(vec![false; 3])));
        assert!(selected_transfer_rows(&model, &none).is_empty());
    }

    #[test]
    fn current_directory_filter_is_case_insensitive_and_supports_multiple_terms() {
        let row = demo_entry("Quarterly Report FINAL.pdf", false, "", "1 KB", 1024, 0);
        assert!(entry_matches_filter(&row, ""));
        assert!(entry_matches_filter(&row, "report"));
        assert!(entry_matches_filter(&row, "FINAL quarterly"));
        assert!(!entry_matches_filter(&row, "final draft"));
    }

    fn comparison_entry(
        name: &str,
        is_dir: bool,
        size: u64,
        mtime: Option<i64>,
    ) -> DirectoryComparisonEntry {
        DirectoryComparisonEntry {
            name: name.into(),
            is_dir,
            size,
            mtime,
        }
    }

    #[test]
    fn directory_comparison_distinguishes_type_size_and_newer_side() {
        let left = comparison_entry("file.bin", false, 10, Some(100));
        let mut right = left.clone();
        assert_eq!(compare_directory_entry(Some(&left), Some(&right)), "same");
        right.mtime = Some(102);
        assert_eq!(
            compare_directory_entry(Some(&left), Some(&right)),
            "same",
            "two-second clock skew is tolerated"
        );
        right.mtime = Some(104);
        assert_eq!(
            compare_directory_entry(Some(&left), Some(&right)),
            "right_newer"
        );
        right.size = 11;
        assert_eq!(compare_directory_entry(Some(&left), Some(&right)), "size");
        right.is_dir = true;
        assert_eq!(compare_directory_entry(Some(&left), Some(&right)), "type");
        assert_eq!(compare_directory_entry(Some(&left), None), "left_only");
        assert_eq!(compare_directory_entry(None, Some(&right)), "right_only");
    }

    #[test]
    fn batch_rename_plan_rejects_collisions_and_local_commit_can_swap_names() {
        let selected = ["draft-a.txt", "draft-b.txt"]
            .into_iter()
            .map(|name| CopyRequest {
                name: name.into(),
                is_dir: false,
                total: Some(1),
            })
            .collect::<Vec<_>>();
        let existing = selected
            .iter()
            .map(|item| item.name.clone())
            .collect::<HashSet<_>>();
        let plan = build_batch_rename_plan(&selected, &existing, "draft", "final").unwrap();
        assert_eq!(plan[0].to, "final-a.txt");
        assert!(build_batch_rename_plan(&selected, &existing, "-a", "-b").is_err());

        let temp = scratch_dir();
        std::fs::write(temp.join("a.txt"), b"A").unwrap();
        std::fs::write(temp.join("b.txt"), b"B").unwrap();
        execute_local_batch_rename(
            &temp,
            &[
                BatchRenameItem {
                    from: "a.txt".into(),
                    to: "b.txt".into(),
                },
                BatchRenameItem {
                    from: "b.txt".into(),
                    to: "a.txt".into(),
                },
            ],
        )
        .unwrap();
        assert_eq!(std::fs::read(temp.join("a.txt")).unwrap(), b"B");
        assert_eq!(std::fs::read(temp.join("b.txt")).unwrap(), b"A");
        let _ = std::fs::remove_dir_all(temp);
    }

    #[test]
    fn failed_local_batch_rename_rolls_staged_sources_back() {
        let temp = scratch_dir();
        std::fs::write(temp.join("source.txt"), b"source").unwrap();
        std::fs::write(temp.join("occupied.txt"), b"occupied").unwrap();
        let error = execute_local_batch_rename(
            &temp,
            &[BatchRenameItem {
                from: "source.txt".into(),
                to: "occupied.txt".into(),
            }],
        )
        .unwrap_err();
        assert!(error.contains("Could not finalize"));
        assert_eq!(std::fs::read(temp.join("source.txt")).unwrap(), b"source");
        assert_eq!(
            std::fs::read(temp.join("occupied.txt")).unwrap(),
            b"occupied"
        );
        assert_eq!(
            std::fs::read_dir(&temp)
                .unwrap()
                .filter_map(Result::ok)
                .filter(|entry| entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".gmacftp-rename-"))
                .count(),
            0
        );
        let _ = std::fs::remove_dir_all(temp);
    }

    #[test]
    fn synchronized_roots_use_component_boundaries() {
        assert!(remote_path_is_within("/site", "/site/assets"));
        assert!(remote_path_is_within("/", "/anything"));
        assert!(!remote_path_is_within("/site", "/site-backup/assets"));
        assert!(synchronized_parent_is_within(
            SynchronizedPaneIdentity::Local,
            "/tmp/site",
            "/tmp/site/assets"
        ));
        assert!(!synchronized_parent_is_within(
            SynchronizedPaneIdentity::Local,
            "/tmp/site",
            "/tmp/site-backup"
        ));
    }

    #[test]
    fn batch_conflict_partition_preserves_selection_order() {
        let requests = ["one.txt", "two.txt", "three.txt"]
            .into_iter()
            .map(|name| CopyRequest {
                name: name.to_string(),
                is_dir: false,
                total: Some(1),
            })
            .collect();
        let existing = HashSet::from(["two.txt".to_string()]);

        let (ready, conflicts) = split_copy_conflicts(requests, &existing);
        assert_eq!(
            ready
                .iter()
                .map(|request| request.name.as_str())
                .collect::<Vec<_>>(),
            ["one.txt", "three.txt"]
        );
        assert_eq!(conflicts[0].name, "two.txt");
    }

    #[test]
    fn apply_all_conflict_decision_is_scoped_to_one_copy_batch() {
        let make = |name: &str, src: usize, dst: usize, batch_id: usize| -> PendingCopy {
            (
                src,
                dst,
                name.to_string(),
                false,
                Some(1),
                TransferBatch {
                    id: batch_id,
                    pause_on_error: true,
                },
            )
        };
        let first = make("first.txt", 0, 1, 10);
        let mut pending = VecDeque::from([
            make("second.txt", 0, 1, 10),
            make("other-batch.txt", 0, 1, 11),
            make("other-route.txt", 1, 0, 10),
        ]);
        let selected = drain_copy_conflict_group(first, &mut pending, true);
        assert_eq!(selected.len(), 2);
        assert_eq!(selected[1].2, "second.txt");
        assert_eq!(pending.len(), 2);
        assert_eq!(pending[0].2, "other-batch.txt");
        assert_eq!(pending[1].2, "other-route.txt");
    }

    #[test]
    fn keep_both_names_are_unique_within_the_same_batch() {
        let mut taken = HashSet::from(["report.pdf".to_string(), "report new.pdf".to_string()]);
        assert_eq!(
            unique_name_from_taken("report.pdf", &mut taken),
            "report new 2.pdf"
        );
        assert_eq!(
            unique_name_from_taken("report.pdf", &mut taken),
            "report new 3.pdf"
        );
        assert!(taken.contains("report new 3.pdf"));
    }

    #[test]
    fn remote_local_target_contains_lexical_and_symlink_escapes() {
        let temp = scratch_dir();
        let root = temp.join("downloads");
        let target = remote_local_target(&root, "../../.ssh/authorized_keys").unwrap();
        assert_eq!(target, root.join(".ssh/authorized_keys"));
        assert_eq!(
            remote_local_target(&root, "/Users/demo/evil.plist").unwrap(),
            root.join("Users/demo/evil.plist")
        );
        assert!(remote_local_target(&root, "bad\rname").is_err());

        std::fs::create_dir_all(&root).unwrap();
        let outside = temp.join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, root.join("escape")).unwrap();
        assert!(remote_local_target(&root, "escape/payload").is_err());

        let _ = std::fs::remove_dir_all(temp);
    }

    #[test]
    fn local_tree_refuses_symlinks_and_honours_file_limit() {
        let temp = scratch_dir();
        let root = temp.join("source");
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("one.txt"), b"one").unwrap();
        let outside = temp.join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, root.join("escape")).unwrap();
        assert!(
            walk_local(&root).is_err(),
            "a source symlink must fail closed"
        );

        std::fs::remove_file(root.join("escape")).unwrap();
        std::fs::write(root.join("two.txt"), b"two").unwrap();
        assert!(walk_local_with_limits(
            &root,
            LocalTreeLimits {
                max_files: 1,
                max_dirs: 10,
                max_depth: 10,
            },
        )
        .is_err());

        let _ = std::fs::remove_dir_all(temp);
    }

    #[test]
    fn local_snapshot_defers_recursive_folder_metadata() {
        let temp = scratch_dir();
        let nested = temp.join("nested");
        std::fs::create_dir_all(&nested).unwrap();
        std::fs::write(nested.join("payload.bin"), vec![7_u8; 4096]).unwrap();
        std::fs::write(temp.join("visible.txt"), b"visible").unwrap();
        std::os::unix::fs::symlink(&nested, temp.join("linked-folder")).unwrap();

        let snapshot = local_pane_snapshot(&temp, true, || false, |_| true)
            .unwrap()
            .unwrap();
        let folder = snapshot
            .rows
            .iter()
            .find(|row| row.name.as_str() == "nested")
            .unwrap();
        assert!(folder.is_dir);
        assert_eq!(
            folder.size, 0,
            "the initial snapshot must not walk the tree"
        );
        assert_eq!(folder.metadata_state.as_str(), "loading");
        assert_eq!(snapshot.folders.len(), 1);
        let linked = snapshot
            .rows
            .iter()
            .find(|row| row.name.as_str() == "linked-folder")
            .unwrap();
        assert!(
            !linked.is_dir,
            "directory symlinks are never traversed as folders"
        );
        assert_eq!(linked.metadata_state.as_str(), "ready");

        let file = snapshot
            .rows
            .iter()
            .find(|row| row.name.as_str() == "visible.txt")
            .unwrap();
        assert!(!file.is_dir);
        assert_eq!(file.size, 7);
        assert_eq!(file.metadata_state.as_str(), "ready");
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let metadata = std::fs::metadata(temp.join("visible.txt")).unwrap();
            assert_eq!(
                file.permissions.as_str(),
                fmt_permissions(Some(metadata.mode() & 0o7777))
            );
            assert_eq!(file.owner.as_str(), metadata.uid().to_string());
            assert_eq!(file.group.as_str(), metadata.gid().to_string());
        }

        let enriched = local_folder_stats(&nested, MAX_LOCAL_FOLDER_STAT_FILES);
        assert_eq!(enriched.size, 4096);
        let _ = std::fs::remove_dir_all(temp);
    }

    #[test]
    fn local_snapshot_stops_after_cancelled_incremental_batch() {
        let temp = scratch_dir();
        for index in 0..300 {
            std::fs::write(temp.join(format!("entry-{index:03}")), b"x").unwrap();
        }
        let mut batches = Vec::new();
        let snapshot = local_pane_snapshot(
            &temp,
            false,
            || false,
            |batch| {
                batches.push(batch.len());
                false
            },
        )
        .unwrap();

        assert!(snapshot.is_none());
        assert_eq!(batches, vec![256]);
        let _ = std::fs::remove_dir_all(temp);
    }

    #[test]
    fn local_copy_rejects_own_descendant_before_writing() {
        let temp = scratch_dir();
        let source = temp.join("source");
        std::fs::create_dir_all(&source).unwrap();
        std::fs::write(source.join("document.txt"), b"contents").unwrap();
        let destination = source.join("nested-copy");
        assert!(fs_copy_tree(&source, &destination).is_err());
        assert!(!destination.exists());
        let _ = std::fs::remove_dir_all(temp);
    }

    #[test]
    fn local_copy_refuses_destination_symlink_and_hard_link() {
        let temp = scratch_dir();
        let source = temp.join("source");
        let destination = temp.join("destination");
        let outside = temp.join("outside");
        std::fs::create_dir_all(source.join("nested")).unwrap();
        std::fs::create_dir_all(&destination).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::write(source.join("nested/document.txt"), b"contents").unwrap();
        std::os::unix::fs::symlink(&outside, destination.join("nested")).unwrap();
        assert!(fs_copy_tree(&source, &destination).is_err());
        assert!(!outside.join("document.txt").exists());

        let file = temp.join("file.txt");
        let hard_link = temp.join("same-file.txt");
        std::fs::write(&file, b"preserve me").unwrap();
        std::fs::hard_link(&file, &hard_link).unwrap();
        assert!(copy_local_file(&file, &hard_link).is_err());
        assert_eq!(std::fs::read(&file).unwrap(), b"preserve me");
        let _ = std::fs::remove_dir_all(temp);
    }

    #[test]
    fn transactional_local_copy_preserves_destination_on_partial_write_failure() {
        let temp = scratch_dir();
        let source = temp.join("source.bin");
        let destination = temp.join("destination.bin");
        std::fs::write(&source, vec![0x42; 128 * 1024]).unwrap();
        std::fs::write(&destination, b"old complete data").unwrap();

        let result = copy_local_file_with(&source, &destination, |input, output| {
            let mut prefix = [0_u8; 4096];
            std::io::Read::read_exact(input, &mut prefix)?;
            std::io::Write::write_all(output, &prefix)?;
            Err(std::io::Error::other("injected disk failure"))
        });

        assert!(result.is_err());
        assert_eq!(std::fs::read(&destination).unwrap(), b"old complete data");
        assert_eq!(
            std::fs::read_dir(&temp)
                .unwrap()
                .filter_map(Result::ok)
                .filter(|entry| entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".gmacftp-copy-"))
                .count(),
            0,
            "failed copies must not leave private staging files"
        );
        let _ = std::fs::remove_dir_all(temp);
    }

    #[test]
    fn transactional_local_copy_replaces_only_after_full_flush() {
        let temp = scratch_dir();
        let source = temp.join("source.bin");
        let destination = temp.join("destination.bin");
        let expected = vec![0x24; 96 * 1024 + 13];
        std::fs::write(&source, &expected).unwrap();
        std::fs::write(&destination, b"old complete data").unwrap();

        assert_eq!(copy_local_file(&source, &destination).unwrap(), 1);
        assert_eq!(std::fs::read(&destination).unwrap(), expected);
        assert_eq!(
            std::fs::read_dir(&temp)
                .unwrap()
                .filter_map(Result::ok)
                .filter(|entry| entry
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".gmacftp-copy-"))
                .count(),
            0
        );
        let _ = std::fs::remove_dir_all(temp);
    }

    #[test]
    fn drag_budget_and_staging_permissions_are_bounded() {
        assert!(validate_drag_budget(MAX_DRAG_STAGING_FILES + 1, 0).is_err());
        assert!(validate_drag_budget(1, MAX_DRAG_STAGING_BYTES + 1).is_err());
        assert!(validate_drag_budget(1, MAX_DRAG_STAGING_BYTES).is_ok());

        let root = create_private_drag_root().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&root).unwrap().permissions().mode() & 0o777,
                0o700
            );
        }
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn abandoned_drag_roots_are_cleaned_without_touching_live_ones() {
        let temp = scratch_dir();
        let stale = temp.join("gmacftp-drag-2147483647-stale");
        let live = temp.join(format!("gmacftp-drag-{}-live", std::process::id()));
        std::fs::create_dir_all(&stale).unwrap();
        std::fs::create_dir_all(&live).unwrap();
        cleanup_abandoned_drag_roots_in(&temp);
        assert!(!stale.exists());
        assert!(live.exists());
        let _ = std::fs::remove_dir_all(temp);
    }

    #[test]
    fn new_sync_passphrase_has_a_reasonable_bound() {
        assert!(validate_new_sync_passphrase("short").is_err());
        assert!(validate_new_sync_passphrase(&"x".repeat(MAX_SYNC_PASSPHRASE_BYTES + 1)).is_err());
        assert!(validate_new_sync_passphrase("correct horse battery staple").is_ok());
    }

    #[test]
    fn file_operation_inputs_reject_traversal_and_invalid_permissions() {
        assert_eq!(
            validate_file_operation_name(" report.txt ").unwrap(),
            "report.txt"
        );
        for invalid in [
            "",
            ".",
            "..",
            "../secret",
            "folder/file",
            "bad\\name",
            "bad\nname",
        ] {
            assert!(
                validate_file_operation_name(invalid).is_err(),
                "{invalid:?}"
            );
        }
        assert_eq!(parse_permission_mode("644").unwrap(), 0o644);
        assert_eq!(parse_permission_mode("0o755").unwrap(), 0o755);
        for invalid in ["64", "0644", "888", "u+rwx"] {
            assert!(parse_permission_mode(invalid).is_err(), "{invalid:?}");
        }
    }

    #[test]
    fn direct_path_navigation_is_bounded_and_rejects_remote_traversal() {
        assert_eq!(
            validated_remote_path(" /srv/www//assets ").unwrap(),
            "/srv/www/assets"
        );
        for invalid in [
            "relative/path",
            "/srv/../private",
            "/srv/./private",
            "/bad\\path",
            "/bad\npath",
        ] {
            assert!(validated_remote_path(invalid).is_err(), "{invalid:?}");
        }

        let temp = scratch_dir();
        let nested = temp.join("folder");
        std::fs::create_dir_all(&nested).unwrap();
        assert_eq!(
            validated_local_path(nested.to_str().unwrap()).unwrap(),
            nested.canonicalize().unwrap().to_string_lossy()
        );
        assert!(validated_local_path("relative/folder").is_err());
        assert!(validated_local_path(temp.join("missing").to_str().unwrap()).is_err());
        let _ = std::fs::remove_dir_all(temp);
    }

    #[test]
    fn navigation_history_is_bounded_and_recent_paths_are_unique() {
        let mut nav = Nav::at("/start".into());
        for index in 0..MAX_NAV_HISTORY + 20 {
            nav.go(format!("/folder/{index}"));
        }
        assert_eq!(nav.history.len(), MAX_NAV_HISTORY);
        let current = nav.current();
        nav.go(current.clone());
        assert_eq!(nav.history.len(), MAX_NAV_HISTORY);
        assert!(!nav.recent(10).contains(&current));
        assert_eq!(nav.recent(10).len(), 10);
    }

    #[test]
    fn atomic_local_rename_never_clobbers_an_existing_item() {
        let temp = scratch_dir();
        let source = temp.join("source.txt");
        let destination = temp.join("destination.txt");
        std::fs::write(&source, b"source").unwrap();
        std::fs::write(&destination, b"destination").unwrap();
        assert!(rename_local_noreplace(&source, &destination).is_err());
        assert_eq!(std::fs::read(&source).unwrap(), b"source");
        assert_eq!(std::fs::read(&destination).unwrap(), b"destination");

        let free_destination = temp.join("renamed.txt");
        rename_local_noreplace(&source, &free_destination).unwrap();
        assert!(!source.exists());
        assert_eq!(std::fs::read(&free_destination).unwrap(), b"source");
        let _ = std::fs::remove_dir_all(temp);
    }

    #[test]
    fn sync_walk_prunes_excluded_trees_before_following_links() {
        let temp = scratch_dir();
        let root = temp.join("source");
        let outside = temp.join("outside");
        std::fs::create_dir_all(root.join(".git")).unwrap();
        std::fs::create_dir_all(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, root.join(".git/escape")).unwrap();
        std::fs::write(root.join("keep.txt"), b"keep").unwrap();
        let rules =
            gmacftp::folder_sync::parse_exclusions(gmacftp::folder_sync::DEFAULT_EXCLUSIONS)
                .unwrap();
        let tree = walk_local_for_sync(&root, &rules).unwrap();
        assert_eq!(tree.files.len(), 1);
        assert_eq!(tree.files[0].1, "keep.txt");
        assert_eq!(
            remote_sync_relative("/site", "/site/nested/file.txt").unwrap(),
            "nested/file.txt"
        );
        assert!(remote_sync_relative("/site", "/site-other/file.txt").is_err());
        let _ = std::fs::remove_dir_all(temp);
    }

    #[test]
    fn sync_comparison_settings_are_bounded_and_directional() {
        let upload = parse_folder_sync_options(
            TransferDirection::Upload,
            "size_mtime",
            "2",
            "3600",
            "one_way",
        )
        .unwrap();
        assert_eq!(upload.source_time_adjustment_seconds, 0);
        assert_eq!(upload.target_time_adjustment_seconds, -3600);

        let download = parse_folder_sync_options(
            TransferDirection::Download,
            "checksum",
            "0",
            "-60",
            "mirror",
        )
        .unwrap();
        assert_eq!(
            download.comparison,
            gmacftp::folder_sync::SyncComparison::Checksum
        );
        assert_eq!(download.source_time_adjustment_seconds, 60);
        assert_eq!(download.mode, gmacftp::folder_sync::SyncMode::Mirror);
        assert!(parse_folder_sync_options(
            TransferDirection::Upload,
            "size_mtime",
            "86401",
            "0",
            "one_way",
        )
        .is_err());
        assert!(parse_folder_sync_options(
            TransferDirection::Upload,
            "unknown",
            "2",
            "0",
            "one_way",
        )
        .is_err());
        assert!(parse_folder_sync_options(
            TransferDirection::Upload,
            "size_mtime",
            "2",
            "0",
            "unknown",
        )
        .is_err());
    }

    fn report_test_context() -> FolderSyncContext {
        let spec = design_demo_connections().remove(0);
        FolderSyncContext {
            key: FolderSyncContextKey {
                local_pane: 0,
                remote_pane: 1,
                local_root: PathBuf::from("/Users/private-account/never-export-this"),
                remote_root: "/private-remote-root".into(),
                connection_id: spec.id,
            },
            spec,
        }
    }

    #[test]
    fn sync_report_contains_only_relative_paths_and_no_endpoint_identity() {
        let context = report_test_context();
        let prepared = PreparedFolderSync {
            context: context.clone(),
            direction: TransferDirection::Upload,
            exclusions: vec![".git".into()],
            options: gmacftp::folder_sync::SyncOptions {
                mode: gmacftp::folder_sync::SyncMode::Mirror,
                ..Default::default()
            },
            preview: gmacftp::folder_sync::SyncPreview {
                actions: vec![gmacftp::folder_sync::SyncAction {
                    relative_path: "assets/public.txt".into(),
                    bytes: 17,
                    reason: gmacftp::folder_sync::SyncReason::DifferentSize,
                }],
                deletions: vec![gmacftp::folder_sync::SyncAction {
                    relative_path: "stale.txt".into(),
                    bytes: 4,
                    reason: gmacftp::folder_sync::SyncReason::TargetOnly,
                }],
                unchanged: 2,
                target_only: 1,
                excluded: 3,
            },
            candidates: vec![FolderSyncCandidate {
                label: "assets/public.txt".into(),
                local_path: "/Users/private-account/never-export-this/assets/public.txt".into(),
                remote_path: "/private-remote-root/assets/public.txt".into(),
                bytes: 17,
                included: true,
            }],
            deletions: vec![FolderSyncDeletion {
                label: "stale.txt".into(),
                local_path: String::new(),
                remote_path: "/private-remote-root/stale.txt".into(),
                metadata: gmacftp::folder_sync::SyncFileMetadata {
                    bytes: 4,
                    modified: Some(10),
                    sha256: None,
                },
                included: false,
            }],
        };

        let report = String::from_utf8(folder_sync_report_bytes(&prepared).unwrap()).unwrap();
        assert!(report.contains("assets/public.txt"));
        assert!(report.contains("stale.txt"));
        assert!(!report.contains(&context.spec.host));
        assert!(!report.contains(&context.spec.user));
        assert!(!report.contains("private-account"));
        assert!(!report.contains("private-remote-root"));
        let json: serde_json::Value = serde_json::from_str(&report).unwrap();
        assert_eq!(json["items"][1]["included"], false);
        assert_eq!(json["items"][1]["action"], "delete");
    }

    #[test]
    fn mirror_batch_requires_every_copy_to_succeed_before_deletion() {
        let deletion = FolderSyncDeletion {
            label: "stale.txt".into(),
            local_path: String::new(),
            remote_path: "/target/stale.txt".into(),
            metadata: gmacftp::folder_sync::SyncFileMetadata {
                bytes: 1,
                modified: Some(1),
                sha256: None,
            },
            included: true,
        };
        let failed_batch = fresh_batch(false).id;
        let failed_ids = [fresh_xfer_id(), fresh_xfer_id()];
        PENDING_MIRROR_BATCHES.lock().unwrap().insert(
            failed_batch,
            PendingMirrorBatch {
                context: report_test_context(),
                direction: TransferDirection::Upload,
                job_ids: failed_ids.into_iter().collect(),
                finished: HashSet::new(),
                failed: false,
                deletions: vec![deletion.clone()],
            },
        );
        let update = |id, batch_id, state| TransferUpdate {
            id: TransferId(id),
            batch_id,
            requires_decision: false,
            bytes_done: 1,
            bytes_total: Some(1),
            state,
        };
        assert!(
            observe_mirror_batch(&update(failed_ids[0], failed_batch, TransferState::Done,))
                .is_none()
        );
        assert!(matches!(
            observe_mirror_batch(&update(
                failed_ids[1],
                failed_batch,
                TransferState::Failed("blocked".into()),
            )),
            Some(MirrorBatchOutcome::Aborted { deletion_count: 1 })
        ));

        let successful_batch = fresh_batch(false).id;
        let successful_id = fresh_xfer_id();
        PENDING_MIRROR_BATCHES.lock().unwrap().insert(
            successful_batch,
            PendingMirrorBatch {
                context: report_test_context(),
                direction: TransferDirection::Download,
                job_ids: HashSet::from([successful_id]),
                finished: HashSet::new(),
                failed: false,
                deletions: vec![deletion],
            },
        );
        assert!(matches!(
            observe_mirror_batch(&update(
                successful_id,
                successful_batch,
                TransferState::Done,
            )),
            Some(MirrorBatchOutcome::Ready(_))
        ));
    }

    #[test]
    fn edited_file_hash_detects_same_size_changes() {
        let temp = scratch_dir();
        let file = temp.join("edit.txt");
        std::fs::write(&file, b"first").unwrap();
        let before = sha256_file(&file).unwrap();
        std::fs::write(&file, b"other").unwrap();
        assert_ne!(before, sha256_file(&file).unwrap());
        let _ = std::fs::remove_dir_all(temp);
    }

    #[test]
    fn editor_conflict_diff_is_bounded_and_handles_binary_files() {
        let temp = scratch_dir();
        let server = temp.join("server.txt");
        let local = temp.join("local.txt");
        std::fs::write(&server, b"same\nserver value\ntail\n").unwrap();
        std::fs::write(&local, b"same\nlocal value\ntail\n").unwrap();
        let (preview, summary) = editor_diff_preview(&server, &local).unwrap();
        assert!(preview.contains("-server value"));
        assert!(preview.contains("+local value"));
        assert!(summary.contains("Server: 1 changed line(s)"));
        assert!(preview.len() <= MAX_EDITOR_DIFF_OUTPUT_BYTES + 64);

        std::fs::write(&server, [0_u8, 1, 2, 3]).unwrap();
        std::fs::write(&local, [0_u8, 1, 9, 3]).unwrap();
        let (preview, summary) = editor_diff_preview(&server, &local).unwrap();
        assert!(preview.contains("Binary content detected"));
        assert!(summary.contains("Binary conflict"));
        let _ = std::fs::remove_dir_all(temp);
    }

    #[test]
    fn editor_mapping_prefers_the_longest_extension_and_conflict_names_are_bounded() {
        let mappings = store::settings::parse_editor_mappings(
            "gz=Archive Utility; tar.gz=Better Archiver; rs=Visual Studio Code",
        )
        .unwrap();
        assert_eq!(
            editor_application_for("backup.TAR.GZ", &mappings).as_deref(),
            Some("Better Archiver")
        );
        assert_eq!(editor_application_for("README", &mappings), None);

        let original = format!("{}.txt", "ż".repeat(200));
        let conflict = editor_conflict_copy_name(&original, 0x1234);
        assert!(conflict.len() <= 255);
        assert!(conflict.is_char_boundary(conflict.len()));
        assert!(conflict.ends_with(".txt"));
        assert_eq!(validate_file_operation_name(&conflict).unwrap(), conflict);
        assert_ne!(
            editor_conflict_copy_name("file.txt", 1),
            editor_conflict_copy_name("file.txt", 2)
        );
    }

    #[test]
    fn transfer_report_redacts_names_endpoints_paths_and_raw_errors() {
        let rows = vec![TransferRow {
            id: 7,
            name: "private-client-list.csv".into(),
            direction: "upload".into(),
            route: "/Users/alice/Secret -> secret.example.test".into(),
            done: 12,
            total: 42,
            progress_text: "12 B / 42 B".into(),
            fraction: 0.25,
            state: "failed".into(),
            priority: "high".into(),
            message: "Permission denied for /srv/private/client-list.csv".into(),
        }];
        let report = String::from_utf8(transfer_report_bytes(&rows).unwrap()).unwrap();
        assert!(!report.contains("private-client-list"));
        assert!(!report.contains("alice"));
        assert!(!report.contains("secret.example"));
        assert!(!report.contains("/srv/private"));
        assert!(!report.contains("Permission denied"));
        assert!(report.contains("\"error_category\": \"permission\""));
        assert!(report.contains("gmacftp-redacted-transfer-report-v1"));
    }

    #[test]
    fn encrypted_settings_import_preserves_local_security_state() {
        let exported = store::settings::Settings {
            theme: "dark".into(),
            show_hidden_files: true,
            sync_via_icloud: false,
            sync_folder: Some("/untrusted/exported/folder".into()),
            sync_passphrase_set: false,
            keychain_migrated_v2: false,
            endpoint_credentials_migrated_v2: false,
            ..Default::default()
        };
        let plaintext = settings_backup_plaintext(&exported).unwrap();
        let current = store::settings::Settings {
            sync_via_icloud: true,
            sync_folder: Some("/Users/local/Library/CloudStorage/gmacFTP".into()),
            sync_passphrase_set: true,
            keychain_migrated_v2: true,
            endpoint_credentials_migrated_v2: true,
            ..Default::default()
        };

        let imported = imported_settings_from_plaintext_with_current(&plaintext, &current).unwrap();
        assert_eq!(imported.theme, "dark");
        assert!(imported.show_hidden_files);
        assert!(imported.sync_via_icloud);
        assert_eq!(imported.sync_folder, current.sync_folder);
        assert!(imported.sync_passphrase_set);
        assert!(imported.keychain_migrated_v2);
        assert!(imported.endpoint_credentials_migrated_v2);
    }

    #[test]
    fn redacted_diagnostics_never_serialize_endpoint_identity_or_paths() {
        let secrets = [
            "super-secret-host.internal",
            "private-login",
            "/Users/private-account/Client Files",
            "/srv/private-customer",
            "secret-proxy.internal",
        ];
        let mut settings = store::settings::Settings {
            locale: secrets[2].into(),
            sync_folder: Some(secrets[2].into()),
            local_favorites: vec![secrets[2].into()],
            last_left_local_path: Some(secrets[2].into()),
            ..Default::default()
        };
        settings.sync_exclusions = "private-project-name".into();
        let mut connection = design_demo_connections().remove(0);
        connection.host = secrets[0].into();
        connection.user = secrets[1].into();
        connection.initial_path = secrets[3].into();
        connection.proxy_url = Some(format!("http://{}:8080", secrets[4]));
        connection.sftp_private_key = Some(format!("{}/id_private", secrets[2]));

        let bytes = redacted_diagnostics(
            &settings,
            &[connection],
            StorageStats {
                config_bytes: 42,
                ..Default::default()
            },
            3,
        )
        .unwrap();
        let report = String::from_utf8(bytes).unwrap();
        for secret in secrets {
            assert!(!report.contains(secret), "diagnostics leaked {secret:?}");
        }
        assert!(!report.contains("private-project-name"));
        assert!(report.contains("aggregate counts only"));
        assert!(report.contains("\"locale_mode\": \"invalid\""));
    }

    #[test]
    fn oversized_import_is_rejected_before_reading() {
        let temp = scratch_dir();
        let path = temp.join("oversized.json");
        let file = std::fs::File::create(&path).unwrap();
        file.set_len(MAX_IMPORT_BYTES + 1).unwrap();
        let conns: ConnList = Arc::new(Mutex::new(Vec::new()));
        let store: Arc<dyn CredentialStore> = Arc::new(store::InMemoryStore::default());
        let result = import_from_path(&path, &conns, &store);
        assert!(result.contains("limit"));
        let _ = std::fs::remove_dir_all(temp);
    }
}
