//! Transfer engine: a background worker that runs queued download/upload jobs and
//! streams throttled progress updates. The UI subscribes to the updates channel and
//! marshals them onto the Slint event loop (invoke_from_event_loop).

mod persistence;
pub mod progress;

pub use progress::{TransferState, TransferUpdate};

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use tokio::sync::{mpsc, Notify};

use crate::model::{
    ConnectionId, ConnectionSpec, Protocol, SftpAuth, TransferDirection, TransferId, TransferJob,
    TransferPriority,
};
use crate::net::{ftp, sftp};
use crate::store::{CredentialKey, CredentialStore};
use persistence::{PersistedState, QueuePersistence};

const MAX_QUEUED_TRANSFERS: usize = 8_192;
pub const MIN_ENDPOINT_CONCURRENCY: usize = crate::store::settings::MIN_TRANSFER_CONCURRENCY;
pub const MAX_ENDPOINT_CONCURRENCY: usize = crate::store::settings::MAX_TRANSFER_CONCURRENCY;
pub const DEFAULT_ENDPOINT_CONCURRENCY: usize =
    crate::store::settings::DEFAULT_TRANSFER_CONCURRENCY;
pub const MIN_SERVER_CONCURRENCY: usize = crate::store::settings::MIN_SERVER_TRANSFER_CONCURRENCY;
pub const MAX_SERVER_CONCURRENCY: usize = crate::store::settings::MAX_SERVER_TRANSFER_CONCURRENCY;
const TRANSFER_SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(60);

struct QueuedTransfer {
    job: TransferJob,
    spec: ConnectionSpec,
    epoch: u64,
}

enum Cmd {
    Run(Box<QueuedTransfer>),
    Abort(ConnectionId),
}

#[derive(Debug, Clone, Copy)]
struct QueueControl {
    priority: TransferPriority,
    order: u64,
    paused: bool,
    queued: bool,
}

#[derive(Default)]
struct QueueControls {
    jobs: Mutex<HashMap<usize, QueueControl>>,
    next_order: AtomicU64,
}

impl QueueControls {
    fn register(&self, job: &TransferJob) {
        let order = self.next_order.fetch_add(1, Ordering::Relaxed);
        if let Ok(mut jobs) = self.jobs.lock() {
            let control = jobs.entry(job.id.0).or_insert(QueueControl {
                priority: job.priority,
                order,
                paused: false,
                queued: true,
            });
            control.priority = job.priority;
            control.order = order;
            control.paused = false;
            control.queued = true;
        }
    }

    fn take_best(&self, pending: &[QueuedTransfer]) -> Option<usize> {
        let mut jobs = self.jobs.lock().ok()?;
        let index = pending
            .iter()
            .enumerate()
            .filter_map(|(index, queued)| {
                let control = jobs.get(&queued.job.id.0)?;
                (control.queued && !control.paused)
                    .then_some((index, (control.priority.scheduling_rank(), control.order)))
            })
            .min_by_key(|(_, key)| *key)
            .map(|(index, _)| index)?;
        if let Some(control) = jobs.get_mut(&pending[index].job.id.0) {
            control.queued = false;
        }
        Some(index)
    }

    fn set_paused(&self, id: TransferId, paused: bool) -> bool {
        let Ok(mut jobs) = self.jobs.lock() else {
            return false;
        };
        let Some(control) = jobs.get_mut(&id.0) else {
            return false;
        };
        if !control.queued {
            return false;
        }
        control.paused = paused;
        true
    }

    fn set_priority(&self, id: TransferId, priority: TransferPriority) -> bool {
        let Ok(mut jobs) = self.jobs.lock() else {
            return false;
        };
        let Some(control) = jobs.get_mut(&id.0) else {
            return false;
        };
        if !control.queued {
            return false;
        }
        control.priority = priority;
        true
    }

    fn swap(&self, first: TransferId, second: TransferId) -> bool {
        if first == second {
            return true;
        }
        let Ok(mut jobs) = self.jobs.lock() else {
            return false;
        };
        let Some(first_control) = jobs.get(&first.0).copied() else {
            return false;
        };
        let Some(second_control) = jobs.get(&second.0).copied() else {
            return false;
        };
        if !first_control.queued
            || !second_control.queued
            || first_control.priority != second_control.priority
        {
            return false;
        }
        if let Some(control) = jobs.get_mut(&first.0) {
            control.order = second_control.order;
        }
        if let Some(control) = jobs.get_mut(&second.0) {
            control.order = first_control.order;
        }
        true
    }

    fn remove(&self, id: TransferId) {
        if let Ok(mut jobs) = self.jobs.lock() {
            jobs.remove(&id.0);
        }
    }
}

enum EndpointQueueEvent {
    Run(Box<QueuedTransfer>),
    Abort,
}

struct EndpointQueue {
    pending: Mutex<Vec<QueuedTransfer>>,
    controls: Arc<QueueControls>,
    globally_paused: Arc<AtomicBool>,
    desired_lanes: AtomicUsize,
    abort_serial: AtomicU64,
    notify: Notify,
}

impl EndpointQueue {
    fn new(controls: Arc<QueueControls>, globally_paused: Arc<AtomicBool>) -> Arc<Self> {
        Arc::new(Self {
            pending: Mutex::new(Vec::new()),
            controls,
            globally_paused,
            desired_lanes: AtomicUsize::new(1),
            abort_serial: AtomicU64::new(0),
            notify: Notify::new(),
        })
    }

    fn push(&self, queued: Box<QueuedTransfer>) {
        if let Ok(mut pending) = self.pending.lock() {
            pending.push(*queued);
        }
        self.notify.notify_waiters();
    }

    fn set_desired_lanes(&self, desired: usize) {
        self.desired_lanes.store(desired, Ordering::Relaxed);
        self.notify.notify_waiters();
    }

    fn abort(&self) {
        self.abort_serial.fetch_add(1, Ordering::Relaxed);
        self.notify.notify_waiters();
    }

    fn wake(&self) {
        self.notify.notify_waiters();
    }

    async fn next(&self, lane: usize, seen_abort: &mut u64) -> EndpointQueueEvent {
        loop {
            // Register before inspecting state so a wake between inspection and await is retained.
            let notified = self.notify.notified();
            let abort_serial = self.abort_serial.load(Ordering::Relaxed);
            if abort_serial != *seen_abort {
                *seen_abort = abort_serial;
                return EndpointQueueEvent::Abort;
            }
            if lane < self.desired_lanes.load(Ordering::Relaxed)
                && !self.globally_paused.load(Ordering::Relaxed)
            {
                if let Ok(mut pending) = self.pending.lock() {
                    if let Some(index) = self.controls.take_best(&pending) {
                        return EndpointQueueEvent::Run(Box::new(pending.remove(index)));
                    }
                }
            }
            notified.await;
        }
    }
}

type EndpointQueues = Arc<Mutex<HashMap<usize, Weak<EndpointQueue>>>>;

fn wake_endpoint_queues(queues: &EndpointQueues) {
    if let Ok(mut queues) = queues.lock() {
        queues.retain(|_, queue| {
            if let Some(queue) = queue.upgrade() {
                queue.wake();
                true
            } else {
                false
            }
        });
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SessionIdentity {
    credential: CredentialKey,
    allow_plaintext_ftp: bool,
    accept_invalid_tls: bool,
    tls_pinned_sha256: Option<String>,
    sftp_auth: SftpAuth,
    sftp_private_key: Option<String>,
    timeout_secs: Option<u64>,
    keepalive_interval_secs: Option<u64>,
    ftp_data_mode: crate::model::FtpDataMode,
    ftp_filename_encoding: crate::model::FtpFilenameEncoding,
    proxy_url: Option<String>,
    use_ssh_config: bool,
    ssh_proxy_jump: Option<String>,
}

impl SessionIdentity {
    fn for_spec(spec: &ConnectionSpec) -> Result<Self, crate::store::CredentialError> {
        Ok(Self {
            credential: CredentialKey::for_spec(spec)?,
            allow_plaintext_ftp: spec.allow_plaintext_ftp,
            accept_invalid_tls: spec.accept_invalid_tls,
            tls_pinned_sha256: spec.tls_pinned_sha256.clone(),
            sftp_auth: spec.sftp_auth,
            sftp_private_key: spec.sftp_private_key.clone(),
            timeout_secs: spec.timeout_secs,
            keepalive_interval_secs: spec.keepalive_interval_secs,
            ftp_data_mode: spec.ftp_data_mode,
            ftp_filename_encoding: spec.ftp_filename_encoding,
            proxy_url: spec.proxy_url.clone(),
            use_ssh_config: spec.use_ssh_config,
            ssh_proxy_jump: spec.ssh_proxy_jump.clone(),
        })
    }
}

enum ActiveTransferSession {
    Ftp(SessionIdentity, ftp::TransferSession),
    Sftp(SessionIdentity, sftp::TransferSession),
}

impl ActiveTransferSession {
    fn identity(&self) -> &SessionIdentity {
        match self {
            Self::Ftp(identity, _) | Self::Sftp(identity, _) => identity,
        }
    }

    async fn close(self) {
        match self {
            Self::Ftp(_, session) => {
                let _ = tokio::task::spawn_blocking(move || session.close()).await;
            }
            Self::Sftp(_, session) => session.close("transfer-session-closed").await,
        }
    }
}

/// `(job_id, batch_id, cancel_flag)` of one endpoint lane's currently running job.
type InFlight = (TransferId, usize, Arc<AtomicBool>);
type InFlightByEndpoint = HashMap<usize, HashMap<usize, InFlight>>;

enum JobOutcome {
    Done,
    Failed { message: String, retryable: bool },
    Suppressed,
}

impl JobOutcome {
    fn permanent(message: impl Into<String>) -> Self {
        Self::Failed {
            message: message.into(),
            retryable: false,
        }
    }

    fn from_net_error(error: crate::net::NetError) -> Self {
        Self::Failed {
            retryable: error.is_retryable(),
            message: error.to_string(),
        }
    }
}

#[derive(Default)]
struct FailureDecisions {
    values: Mutex<HashMap<usize, bool>>,
    notify: Notify,
}

impl FailureDecisions {
    fn resolve(&self, batch_id: usize, should_continue: bool) {
        if let Ok(mut values) = self.values.lock() {
            values.insert(batch_id, should_continue);
        }
        self.notify.notify_waiters();
    }

    async fn wait(&self, batch_id: usize) -> bool {
        loop {
            // Register before checking the map so a decision arriving between the check and await
            // cannot be lost.
            let notified = self.notify.notified();
            if let Ok(values) = self.values.lock() {
                if let Some(decision) = values.get(&batch_id).copied() {
                    return decision;
                }
            }
            notified.await;
        }
    }
}

struct OutstandingGuard(Arc<AtomicUsize>);

impl Drop for OutstandingGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

struct EndpointLimiter {
    limit: AtomicUsize,
    active: AtomicUsize,
    notify: Notify,
}

impl EndpointLimiter {
    fn new(limit: usize) -> Self {
        Self {
            limit: AtomicUsize::new(
                limit.clamp(MIN_ENDPOINT_CONCURRENCY, MAX_ENDPOINT_CONCURRENCY),
            ),
            active: AtomicUsize::new(0),
            notify: Notify::new(),
        }
    }

    fn set_limit(&self, limit: usize) -> usize {
        let limit = limit.clamp(MIN_ENDPOINT_CONCURRENCY, MAX_ENDPOINT_CONCURRENCY);
        self.limit.store(limit, Ordering::Relaxed);
        self.notify.notify_waiters();
        limit
    }

    async fn acquire(self: &Arc<Self>) -> EndpointPermit {
        loop {
            let notified = self.notify.notified();
            let active = self.active.load(Ordering::Relaxed);
            let limit = self.limit.load(Ordering::Relaxed);
            if active < limit
                && self
                    .active
                    .compare_exchange_weak(active, active + 1, Ordering::Acquire, Ordering::Relaxed)
                    .is_ok()
            {
                return EndpointPermit(self.clone());
            }
            notified.await;
        }
    }
}

struct EndpointPermit(Arc<EndpointLimiter>);

impl Drop for EndpointPermit {
    fn drop(&mut self) {
        self.0.active.fetch_sub(1, Ordering::Release);
        self.0.notify.notify_one();
    }
}

struct BandwidthLimiter {
    limit_kib_per_sec: AtomicU64,
    next_available: Mutex<Instant>,
}

impl BandwidthLimiter {
    fn new(limit_kib_per_sec: u64) -> Self {
        Self {
            limit_kib_per_sec: AtomicU64::new(normalize_bandwidth_limit(limit_kib_per_sec)),
            next_available: Mutex::new(Instant::now()),
        }
    }

    fn set_limit(&self, limit_kib_per_sec: u64) -> u64 {
        let limit = normalize_bandwidth_limit(limit_kib_per_sec);
        self.limit_kib_per_sec.store(limit, Ordering::Relaxed);
        if let Ok(mut next) = self.next_available.lock() {
            *next = Instant::now();
        }
        limit
    }

    fn throttle(&self, bytes: u64, cancelled: &AtomicBool) {
        let limit_kib = self.limit_kib_per_sec.load(Ordering::Relaxed);
        if limit_kib == 0 || bytes == 0 || cancelled.load(Ordering::Relaxed) {
            return;
        }
        let bytes_per_second = limit_kib.saturating_mul(1_024).max(1);
        // Protocol callbacks normally report one 32–128 KiB chunk. The clamp prevents a corrupt
        // cumulative callback from reserving hours of sleep while preserving the configured rate
        // for every normal transfer chunk (1 MiB / 64 KiB/s = 16 seconds maximum).
        let bytes = bytes.min(1_048_576);
        let nanos = (u128::from(bytes) * 1_000_000_000u128 / u128::from(bytes_per_second))
            .min(u128::from(u64::MAX)) as u64;
        let cost = Duration::from_nanos(nanos);
        let wake_at = {
            let Ok(mut next) = self.next_available.lock() else {
                return;
            };
            let now = Instant::now();
            if *next < now {
                *next = now;
            }
            *next += cost;
            *next
        };
        loop {
            if cancelled.load(Ordering::Relaxed) {
                return;
            }
            let now = Instant::now();
            if now >= wake_at {
                return;
            }
            std::thread::sleep((wake_at - now).min(Duration::from_millis(50)));
        }
    }
}

fn normalize_bandwidth_limit(limit_kib_per_sec: u64) -> u64 {
    if limit_kib_per_sec == 0 {
        0
    } else {
        limit_kib_per_sec.clamp(
            crate::store::settings::MIN_BANDWIDTH_LIMIT_KIB,
            crate::store::settings::MAX_BANDWIDTH_LIMIT_KIB,
        )
    }
}

#[derive(Clone)]
struct EndpointWorkerContext {
    store: Arc<dyn CredentialStore>,
    updates: mpsc::Sender<TransferUpdate>,
    connection_epochs: Arc<Mutex<HashMap<usize, u64>>>,
    current: Arc<Mutex<InFlightByEndpoint>>,
    paused: Arc<AtomicBool>,
    failure_decisions: Arc<FailureDecisions>,
    stopped_batches: Arc<Mutex<HashSet<usize>>>,
    cancelled_jobs: Arc<Mutex<HashSet<usize>>>,
    outstanding: Arc<AtomicUsize>,
    endpoint_limiter: Arc<EndpointLimiter>,
    retry_count: Arc<AtomicUsize>,
    retry_backoff_ms: Arc<AtomicU64>,
    bandwidth_limiter: Arc<BandwidthLimiter>,
    persistence: Arc<QueuePersistence>,
}

/// `try_enqueue` rejection reason: the bounded worker channel was full, so the job was NOT
/// accepted (it must be marked failed by the caller rather than left on "queued" forever).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueueFull;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetryError {
    NotFound,
    QueueFull,
}

/// Owns the queue. Cheap to clone-share via the returned handle.
#[derive(Clone)]
pub struct TransferEngine {
    tx: mpsc::Sender<Cmd>,
    /// Disconnect increments one endpoint's epoch. Already queued jobs carry the previous value
    /// and can never resume accidentally if the user reconnects quickly.
    connection_epochs: Arc<Mutex<HashMap<usize, u64>>>,
    /// In-flight jobs grouped by endpoint. Each configured lane reuses its own authenticated
    /// session while unrelated servers and multiple files on one server progress independently.
    current: Arc<Mutex<InFlightByEndpoint>>,
    /// Pause-all toggle (transfer panel): when set, the worker holds a freshly dequeued job
    /// without starting it until cleared. An in-flight transfer finishes normally first.
    paused: Arc<AtomicBool>,
    /// User decisions are shared because any endpoint worker may be waiting for its batch.
    failure_decisions: Arc<FailureDecisions>,
    /// The dispatcher drains quickly into endpoint queues, so a separate global counter keeps the
    /// original hard memory bound meaningful.
    outstanding: Arc<AtomicUsize>,
    endpoint_limiter: Arc<EndpointLimiter>,
    default_server_concurrency: Arc<AtomicUsize>,
    retry_count: Arc<AtomicUsize>,
    retry_backoff_ms: Arc<AtomicU64>,
    bandwidth_limiter: Arc<BandwidthLimiter>,
    cancelled_jobs: Arc<Mutex<HashSet<usize>>>,
    jobs: Arc<Mutex<HashMap<usize, (TransferJob, ConnectionSpec)>>>,
    queue_controls: Arc<QueueControls>,
    endpoint_queues: EndpointQueues,
    retry_sequence: Arc<AtomicUsize>,
    persistence: Arc<QueuePersistence>,
    store: Arc<dyn CredentialStore>,
}

impl TransferEngine {
    /// Spawn the dispatcher and endpoint workers. Must be called from within a Tokio runtime.
    /// `updates` is where progress/final events land — the UI reads the other end.
    pub fn start(store: Arc<dyn CredentialStore>, updates: mpsc::Sender<TransferUpdate>) -> Self {
        let (tx, mut rx) = mpsc::channel::<Cmd>(MAX_QUEUED_TRANSFERS);
        let connection_epochs = Arc::new(Mutex::new(HashMap::new()));
        let current = Arc::new(Mutex::new(HashMap::new()));
        let paused = Arc::new(AtomicBool::new(false));
        let failure_decisions = Arc::new(FailureDecisions::default());
        let stopped_batches = Arc::new(Mutex::new(HashSet::new()));
        let cancelled_jobs = Arc::new(Mutex::new(HashSet::new()));
        let persistence = QueuePersistence::load_default();
        let recovered = persistence.recovered();
        let jobs = Arc::new(Mutex::new(
            recovered
                .into_iter()
                .map(|transfer| (transfer.job.id.0, (transfer.job, transfer.spec)))
                .collect(),
        ));
        persistence.spawn_writer();
        let retry_sequence = Arc::new(AtomicUsize::new(0));
        let outstanding = Arc::new(AtomicUsize::new(0));
        let settings = crate::store::settings::load();
        let endpoint_limiter = Arc::new(EndpointLimiter::new(settings.transfer_concurrency));
        let default_server_concurrency = Arc::new(AtomicUsize::new(
            settings
                .per_server_transfer_concurrency
                .clamp(MIN_SERVER_CONCURRENCY, MAX_SERVER_CONCURRENCY),
        ));
        let retry_count = Arc::new(AtomicUsize::new(settings.transfer_retry_count));
        let retry_backoff_ms = Arc::new(AtomicU64::new(settings.transfer_retry_backoff_ms));
        let bandwidth_limiter =
            Arc::new(BandwidthLimiter::new(settings.transfer_bandwidth_limit_kib));
        let queue_controls = Arc::new(QueueControls::default());
        let endpoint_queues: EndpointQueues = Arc::new(Mutex::new(HashMap::new()));
        let worker_context = EndpointWorkerContext {
            store: store.clone(),
            updates: updates.clone(),
            connection_epochs: connection_epochs.clone(),
            current: current.clone(),
            paused: paused.clone(),
            failure_decisions: failure_decisions.clone(),
            stopped_batches,
            cancelled_jobs: cancelled_jobs.clone(),
            outstanding: outstanding.clone(),
            endpoint_limiter: endpoint_limiter.clone(),
            retry_count: retry_count.clone(),
            retry_backoff_ms: retry_backoff_ms.clone(),
            bandwidth_limiter: bandwidth_limiter.clone(),
            persistence: persistence.clone(),
        };
        let dispatcher_default_server_concurrency = default_server_concurrency.clone();
        let dispatcher_controls = queue_controls.clone();
        let dispatcher_paused = paused.clone();
        let dispatcher_queues = endpoint_queues.clone();
        tokio::spawn(async move {
            struct EndpointPool {
                queue: Arc<EndpointQueue>,
                lanes: usize,
            }
            let mut workers: HashMap<usize, EndpointPool> = HashMap::new();
            while let Some(command) = rx.recv().await {
                let queued = match command {
                    Cmd::Abort(connection_id) => {
                        if let Some(pool) = workers.get(&connection_id.0) {
                            pool.queue.abort();
                        }
                        continue;
                    }
                    Cmd::Run(queued) => queued,
                };
                let cid = queued.spec.id.0;
                let desired = queued
                    .spec
                    .transfer_concurrency
                    .unwrap_or_else(|| {
                        dispatcher_default_server_concurrency.load(Ordering::Relaxed)
                    })
                    .clamp(MIN_SERVER_CONCURRENCY, MAX_SERVER_CONCURRENCY);
                let pool = workers.entry(cid).or_insert_with(|| {
                    let queue =
                        EndpointQueue::new(dispatcher_controls.clone(), dispatcher_paused.clone());
                    if let Ok(mut queues) = dispatcher_queues.lock() {
                        queues.insert(cid, Arc::downgrade(&queue));
                    }
                    EndpointPool { queue, lanes: 0 }
                });
                pool.queue.set_desired_lanes(desired);
                while pool.lanes < desired {
                    spawn_endpoint_worker(worker_context.clone(), pool.queue.clone(), pool.lanes);
                    pool.lanes += 1;
                }
                pool.queue.push(queued);
            }
        });
        Self {
            tx,
            connection_epochs,
            current,
            paused,
            failure_decisions,
            outstanding,
            endpoint_limiter,
            default_server_concurrency,
            retry_count,
            retry_backoff_ms,
            bandwidth_limiter,
            cancelled_jobs,
            jobs,
            queue_controls,
            endpoint_queues,
            retry_sequence,
            persistence,
            store,
        }
    }

    fn reserve_queue_slot(&self) -> bool {
        self.outstanding
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
                (count < MAX_QUEUED_TRANSFERS).then_some(count + 1)
            })
            .is_ok()
    }

    fn connection_epoch(&self, connection_id: ConnectionId) -> u64 {
        self.connection_epochs
            .lock()
            .ok()
            .and_then(|epochs| epochs.get(&connection_id.0).copied())
            .unwrap_or(0)
    }

    /// Sync enqueue — safe to call from a UI callback (no .await). The global counter preserves
    /// the 8192-job memory bound even though the dispatcher has independent endpoint queues.
    pub fn try_enqueue(&self, job: TransferJob, spec: ConnectionSpec) -> Result<(), QueueFull> {
        if !self.reserve_queue_slot() {
            return Err(QueueFull);
        }
        let job_id = job.id.0;
        if let Ok(mut jobs) = self.jobs.lock() {
            jobs.insert(job_id, (job.clone(), spec.clone()));
        }
        self.queue_controls.register(&job);
        self.persistence
            .set(job.clone(), spec.clone(), PersistedState::Queued);
        let epoch = self.connection_epoch(spec.id);
        if self
            .tx
            .try_send(Cmd::Run(Box::new(QueuedTransfer { job, spec, epoch })))
            .is_err()
        {
            self.outstanding.fetch_sub(1, Ordering::Relaxed);
            if let Ok(mut jobs) = self.jobs.lock() {
                jobs.remove(&job_id);
            }
            self.queue_controls.remove(TransferId(job_id));
            self.persistence.remove(job_id);
            return Err(QueueFull);
        }
        Ok(())
    }

    pub async fn enqueue(&self, job: TransferJob, spec: ConnectionSpec) {
        while !self.reserve_queue_slot() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let job_id = job.id.0;
        if let Ok(mut jobs) = self.jobs.lock() {
            jobs.insert(job_id, (job.clone(), spec.clone()));
        }
        self.queue_controls.register(&job);
        self.persistence
            .set(job.clone(), spec.clone(), PersistedState::Queued);
        let epoch = self.connection_epoch(spec.id);
        if self
            .tx
            .send(Cmd::Run(Box::new(QueuedTransfer { job, spec, epoch })))
            .await
            .is_err()
        {
            self.outstanding.fetch_sub(1, Ordering::Relaxed);
            if let Ok(mut jobs) = self.jobs.lock() {
                jobs.remove(&job_id);
            }
            self.queue_controls.remove(TransferId(job_id));
            self.persistence.remove(job_id);
        }
    }

    /// Abort a single connection's transfers: its pending jobs are skipped, and its in-flight
    /// job's terminal update is suppressed (a timed-out orphan over a dead session never
    /// surfaces as a confusing "Operation timed out"). Other sessions are left untouched.
    pub fn abort(&self, conn_id: ConnectionId) {
        let cid = conn_id.0;
        if let Ok(mut epochs) = self.connection_epochs.lock() {
            let epoch = epochs.entry(cid).or_default();
            *epoch = epoch.saturating_add(1);
        }
        if let Ok(g) = self.current.lock() {
            if let Some(transfers) = g.get(&cid) {
                for (_, batch_id, flag) in transfers.values() {
                    flag.store(true, Ordering::Relaxed);
                    self.failure_decisions.resolve(*batch_id, false);
                }
            }
        }
        let _ = self.tx.try_send(Cmd::Abort(conn_id));
    }

    /// Pause/resume dequeue of new transfers (the transfer-panel "Pause all" toggle). An
    /// in-flight transfer finishes first; the next job is held until resumed.
    pub fn set_paused(&self, paused: bool) {
        self.paused.store(paused, Ordering::Relaxed);
        wake_endpoint_queues(&self.endpoint_queues);
    }

    /// Pause or resume one transfer that has not started. Active protocol operations are never
    /// frozen mid-command; they retain the existing explicit Cancel/Resume behavior.
    pub fn set_job_paused(&self, id: TransferId, paused: bool) -> bool {
        let changed = self.queue_controls.set_paused(id, paused);
        if changed {
            wake_endpoint_queues(&self.endpoint_queues);
        }
        changed
    }

    /// Change one queued job's scheduling class without affecting active work.
    pub fn set_job_priority(&self, id: TransferId, priority: TransferPriority) -> bool {
        if !self.queue_controls.set_priority(id, priority) {
            return false;
        }
        let persisted = self.jobs.lock().ok().and_then(|mut jobs| {
            let (job, spec) = jobs.get_mut(&id.0)?;
            job.priority = priority;
            Some((job.clone(), spec.clone()))
        });
        if let Some((job, spec)) = persisted {
            self.persistence.set(job, spec, PersistedState::Queued);
        }
        wake_endpoint_queues(&self.endpoint_queues);
        true
    }

    /// Swap two queued jobs inside the same priority class.
    pub fn swap_queued_jobs(&self, first: TransferId, second: TransferId) -> bool {
        let changed = self.queue_controls.swap(first, second);
        if changed {
            wake_endpoint_queues(&self.endpoint_queues);
        }
        changed
    }

    /// Change the number of endpoints allowed to transfer at once. Lowering the value never
    /// interrupts active files; it takes effect as their permits are released.
    pub fn set_endpoint_concurrency(&self, limit: usize) -> usize {
        self.endpoint_limiter.set_limit(limit)
    }

    /// Change the default number of lanes used by connections without an explicit override.
    /// Existing pools retain already-created idle lanes but new jobs are routed only across the
    /// current bounded default.
    pub fn set_default_server_concurrency(&self, limit: usize) -> usize {
        let limit = limit.clamp(MIN_SERVER_CONCURRENCY, MAX_SERVER_CONCURRENCY);
        self.default_server_concurrency
            .store(limit, Ordering::Relaxed);
        limit
    }

    /// Apply the validated automatic retry policy to new failures without restarting workers.
    pub fn set_retry_policy(&self, count: usize, initial_backoff_ms: u64) -> (usize, u64) {
        let count = count.min(crate::store::settings::MAX_TRANSFER_RETRIES);
        let initial_backoff_ms = initial_backoff_ms.clamp(
            crate::store::settings::MIN_RETRY_BACKOFF_MS,
            crate::store::settings::MAX_RETRY_BACKOFF_MS,
        );
        self.retry_count.store(count, Ordering::Relaxed);
        self.retry_backoff_ms
            .store(initial_backoff_ms, Ordering::Relaxed);
        (count, initial_backoff_ms)
    }

    /// Set an aggregate ceiling shared by every endpoint lane. Zero disables throttling.
    pub fn set_bandwidth_limit_kib(&self, limit_kib_per_sec: u64) -> u64 {
        self.bandwidth_limiter.set_limit(limit_kib_per_sec)
    }

    pub fn cancel_job(&self, id: TransferId) {
        let _ = self.queue_controls.set_paused(id, false);
        if let Ok(mut cancelled) = self.cancelled_jobs.lock() {
            cancelled.insert(id.0);
        }
        if let Ok(current) = self.current.lock() {
            for transfers in current.values() {
                if let Some((_, _, flag)) = transfers.get(&id.0) {
                    flag.store(true, Ordering::Relaxed);
                }
            }
        }
        wake_endpoint_queues(&self.endpoint_queues);
    }

    pub fn retry_job(&self, id: TransferId) -> Result<(), RetryError> {
        let (mut job, spec) = self
            .jobs
            .lock()
            .ok()
            .and_then(|jobs| jobs.get(&id.0).cloned())
            .ok_or(RetryError::NotFound)?;
        if !self.reserve_queue_slot() {
            return Err(RetryError::QueueFull);
        }
        if let Ok(mut cancelled) = self.cancelled_jobs.lock() {
            cancelled.remove(&id.0);
        }
        let sequence = self.retry_sequence.fetch_add(1, Ordering::Relaxed);
        job.batch_id = usize::MAX.saturating_sub(sequence);
        job.pause_on_error = false;
        self.queue_controls.register(&job);
        let epoch = self.connection_epoch(spec.id);
        self.persistence
            .set(job.clone(), spec.clone(), PersistedState::Queued);
        if self
            .tx
            .try_send(Cmd::Run(Box::new(QueuedTransfer { job, spec, epoch })))
            .is_err()
        {
            self.outstanding.fetch_sub(1, Ordering::Relaxed);
            self.queue_controls.remove(id);
            self.persistence.set_state(id.0, PersistedState::Retryable);
            return Err(RetryError::QueueFull);
        }
        Ok(())
    }

    pub fn forget_job(&self, id: TransferId) {
        self.queue_controls.remove(id);
        let was_recoverable = self.persistence.contains(id.0);
        let removed = self
            .jobs
            .lock()
            .ok()
            .and_then(|mut jobs| jobs.remove(&id.0));
        if let Some((job, spec)) = removed {
            self.persistence.remove(job.id.0);
            if job.direction == TransferDirection::Download && job.resume_token != 0 {
                crate::net::discard_download_fragment(
                    std::path::Path::new(&job.local_path),
                    job.resume_token,
                );
            }
            if was_recoverable
                && job.direction == TransferDirection::Upload
                && job.resume_token != 0
                && job.bytes_total.is_some()
                && job.source_modified_unix_nanos.is_some()
            {
                self.discard_upload_fragment(job, spec);
            }
        }
        if let Ok(mut cancelled) = self.cancelled_jobs.lock() {
            cancelled.remove(&id.0);
        }
    }

    fn discard_upload_fragment(&self, job: TransferJob, spec: ConnectionSpec) {
        let store = self.store.clone();
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            tracing::warn!("could not schedule resumable upload fragment cleanup");
            return;
        };
        handle.spawn(async move {
            let key = match CredentialKey::for_spec(&spec) {
                Ok(key) => key,
                Err(error) => {
                    tracing::warn!(%error, "could not identify credential for upload cleanup");
                    return;
                }
            };
            let password = match store.get_for(&key) {
                Ok(password) => String::from_utf8_lossy(&password).into_owned(),
                Err(crate::store::CredentialError::NotFound)
                    if spec.protocol == Protocol::Sftp && spec.sftp_auth != SftpAuth::Password =>
                {
                    String::new()
                }
                Err(error) => {
                    tracing::warn!(%error, "could not load credential for upload cleanup");
                    return;
                }
            };
            let result = match spec.protocol {
                Protocol::Ftp => {
                    let remote_path = job.remote_path;
                    tokio::task::spawn_blocking(move || {
                        ftp::discard_resumable_upload(
                            &spec,
                            &password,
                            &remote_path,
                            job.resume_token,
                        )
                    })
                    .await
                    .map_err(|error| crate::net::NetError::Join(error.to_string()))
                    .and_then(|result| result)
                }
                Protocol::Sftp => {
                    sftp::discard_resumable_upload(
                        &spec,
                        &password,
                        &job.remote_path,
                        job.resume_token,
                    )
                    .await
                }
            };
            if let Err(error) = result {
                tracing::warn!(%error, "could not discard resumable upload fragment");
            }
        });
    }

    /// Resolve the modal shown after one file in a multi-file batch fails.
    pub fn resolve_batch_failure(&self, batch_id: usize, should_continue: bool) {
        self.failure_decisions.resolve(batch_id, should_continue);
    }

    /// Work left by a previous process. It is registered for Retry/Resume but never starts until
    /// the user explicitly chooses it in the transfer panel.
    pub fn recovered_jobs(&self) -> Vec<(TransferJob, ConnectionSpec)> {
        self.persistence
            .recovered()
            .into_iter()
            .map(|transfer| (transfer.job, transfer.spec))
            .collect()
    }
}

fn connection_epoch_is_current(
    epochs: &Mutex<HashMap<usize, u64>>,
    connection_id: usize,
    expected: u64,
) -> bool {
    epochs
        .lock()
        .map(|epochs| epochs.get(&connection_id).copied().unwrap_or(0) == expected)
        .unwrap_or(false)
}

async fn report_skipped(
    updates: &mpsc::Sender<TransferUpdate>,
    job: &TransferJob,
    reason: &'static str,
) {
    let _ = updates
        .send(TransferUpdate {
            id: job.id,
            batch_id: job.batch_id,
            requires_decision: false,
            bytes_done: 0,
            bytes_total: job.bytes_total,
            state: TransferState::Skipped(reason.into()),
        })
        .await;
}

fn take_cancelled(cancelled_jobs: &Mutex<HashSet<usize>>, id: TransferId) -> bool {
    cancelled_jobs
        .lock()
        .map(|mut cancelled| cancelled.remove(&id.0))
        .unwrap_or(false)
}

async fn report_cancelled(updates: &mpsc::Sender<TransferUpdate>, job: &TransferJob) {
    let _ = updates
        .send(TransferUpdate {
            id: job.id,
            batch_id: job.batch_id,
            requires_decision: false,
            bytes_done: 0,
            bytes_total: job.bytes_total,
            state: TransferState::Cancelled,
        })
        .await;
}

fn spawn_endpoint_worker(context: EndpointWorkerContext, queue: Arc<EndpointQueue>, lane: usize) {
    tokio::spawn(async move {
        let mut active_session: Option<ActiveTransferSession> = None;
        let mut seen_abort = queue.abort_serial.load(Ordering::Relaxed);
        loop {
            let event = if active_session.is_some() {
                match tokio::time::timeout(
                    TRANSFER_SESSION_IDLE_TIMEOUT,
                    queue.next(lane, &mut seen_abort),
                )
                .await
                {
                    Ok(event) => event,
                    Err(_) => {
                        if let Some(session) = active_session.take() {
                            session.close().await;
                        }
                        continue;
                    }
                }
            } else {
                queue.next(lane, &mut seen_abort).await
            };

            let (job, spec, epoch) = match event {
                EndpointQueueEvent::Abort => {
                    if let Some(session) = active_session.take() {
                        session.close().await;
                    }
                    continue;
                }
                EndpointQueueEvent::Run(queued) => (queued.job, queued.spec, queued.epoch),
            };
            let _outstanding = OutstandingGuard(context.outstanding.clone());
            let connection_id = spec.id.0;

            if take_cancelled(&context.cancelled_jobs, job.id) {
                context
                    .persistence
                    .set_state(job.id.0, PersistedState::Retryable);
                report_cancelled(&context.updates, &job).await;
                continue;
            }

            let batch_stopped = context
                .stopped_batches
                .lock()
                .map(|stopped| stopped.contains(&job.batch_id))
                .unwrap_or(true);
            if batch_stopped {
                context
                    .persistence
                    .set_state(job.id.0, PersistedState::Retryable);
                report_skipped(
                    &context.updates,
                    &job,
                    "batch stopped after an earlier file error",
                )
                .await;
                continue;
            }

            if !connection_epoch_is_current(&context.connection_epochs, connection_id, epoch) {
                if let Some(session) = active_session.take() {
                    session.close().await;
                }
                context
                    .persistence
                    .set_state(job.id.0, PersistedState::Retryable);
                report_skipped(&context.updates, &job, "connection was disconnected").await;
                continue;
            }

            // Pause-all holds only jobs that have not started. Other endpoint workers and an
            // already active operation are unaffected until their current file completes.
            while context.paused.load(Ordering::Relaxed) {
                if !connection_epoch_is_current(&context.connection_epochs, connection_id, epoch) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            if !connection_epoch_is_current(&context.connection_epochs, connection_id, epoch) {
                if let Some(session) = active_session.take() {
                    session.close().await;
                }
                context
                    .persistence
                    .set_state(job.id.0, PersistedState::Retryable);
                report_skipped(&context.updates, &job, "connection was disconnected").await;
                continue;
            }

            let permit = context.endpoint_limiter.acquire().await;
            // An abort can arrive while this endpoint waits for the global concurrency slot.
            if !connection_epoch_is_current(&context.connection_epochs, connection_id, epoch) {
                drop(permit);
                if let Some(session) = active_session.take() {
                    session.close().await;
                }
                context
                    .persistence
                    .set_state(job.id.0, PersistedState::Retryable);
                report_skipped(&context.updates, &job, "connection was disconnected").await;
                continue;
            }
            if take_cancelled(&context.cancelled_jobs, job.id) {
                drop(permit);
                context
                    .persistence
                    .set_state(job.id.0, PersistedState::Retryable);
                report_cancelled(&context.updates, &job).await;
                continue;
            }

            let flag = Arc::new(AtomicBool::new(false));
            if let Ok(mut current) = context.current.lock() {
                current
                    .entry(connection_id)
                    .or_default()
                    .insert(job.id.0, (job.id, job.batch_id, flag.clone()));
            }
            context
                .persistence
                .set_state(job.id.0, PersistedState::Running);
            let job_for_update = job.clone();
            let batch_id = job.batch_id;
            let pause_on_error = job.pause_on_error;
            let mut permit = Some(permit);
            let mut retry_number = 0usize;
            let outcome = loop {
                let outcome = run_one(
                    &context.store,
                    &context.updates,
                    &job,
                    &spec,
                    &flag,
                    &context.bandwidth_limiter,
                    &mut active_session,
                )
                .await;
                let (message, retryable) = match &outcome {
                    JobOutcome::Failed { message, retryable } => (message.clone(), *retryable),
                    JobOutcome::Done | JobOutcome::Suppressed => break outcome,
                };
                let max_retries = context
                    .retry_count
                    .load(Ordering::Relaxed)
                    .min(crate::store::settings::MAX_TRANSFER_RETRIES);
                if !retryable || retry_number >= max_retries || flag.load(Ordering::Relaxed) {
                    break outcome;
                }

                retry_number += 1;
                let delay_ms = retry_delay_ms(
                    context.retry_backoff_ms.load(Ordering::Relaxed),
                    retry_number,
                );
                let _ = context
                    .updates
                    .send(TransferUpdate {
                        id: job.id,
                        batch_id,
                        requires_decision: false,
                        bytes_done: 0,
                        bytes_total: job.bytes_total,
                        state: TransferState::Retrying {
                            attempt: retry_number,
                            max_attempts: max_retries,
                            delay_ms,
                            error: message,
                        },
                    })
                    .await;

                // A sleeping retry must not occupy one of the global transfer slots. The job stays
                // registered so Disconnect/Cancel remains immediate during the backoff.
                drop(permit.take());
                if !wait_for_retry(
                    Duration::from_millis(delay_ms),
                    &context,
                    &flag,
                    connection_id,
                    epoch,
                )
                .await
                {
                    break JobOutcome::Suppressed;
                }
                let next_permit = context.endpoint_limiter.acquire().await;
                if flag.load(Ordering::Relaxed)
                    || !connection_epoch_is_current(
                        &context.connection_epochs,
                        connection_id,
                        epoch,
                    )
                {
                    drop(next_permit);
                    break JobOutcome::Suppressed;
                }
                permit = Some(next_permit);
                context
                    .persistence
                    .set_state(job.id.0, PersistedState::Running);
                let _ = context
                    .updates
                    .send(TransferUpdate {
                        id: job.id,
                        batch_id,
                        requires_decision: false,
                        bytes_done: 0,
                        bytes_total: job.bytes_total,
                        state: TransferState::Active,
                    })
                    .await;
            };
            if let Ok(mut current) = context.current.lock() {
                let remove_endpoint = if let Some(transfers) = current.get_mut(&connection_id) {
                    transfers.remove(&job_for_update.id.0);
                    transfers.is_empty()
                } else {
                    false
                };
                if remove_endpoint {
                    current.remove(&connection_id);
                }
            }
            drop(permit);

            let individually_cancelled = take_cancelled(&context.cancelled_jobs, job_for_update.id);
            let failed = matches!(outcome, JobOutcome::Failed { .. }) && !individually_cancelled;
            match &outcome {
                JobOutcome::Done if !individually_cancelled => {
                    context.persistence.remove(job_for_update.id.0)
                }
                JobOutcome::Done | JobOutcome::Failed { .. } | JobOutcome::Suppressed => context
                    .persistence
                    .set_state(job_for_update.id.0, PersistedState::Retryable),
            }
            if individually_cancelled {
                report_cancelled(&context.updates, &job_for_update).await;
            } else {
                let state = match outcome {
                    JobOutcome::Done => Some(TransferState::Done),
                    JobOutcome::Failed { message, .. } => Some(TransferState::Failed(message)),
                    JobOutcome::Suppressed => None,
                };
                if let Some(state) = state {
                    let _ = context
                        .updates
                        .send(TransferUpdate {
                            id: job_for_update.id,
                            batch_id,
                            requires_decision: failed && pause_on_error,
                            bytes_done: 0,
                            bytes_total: job_for_update.bytes_total,
                            state,
                        })
                        .await;
                }
            }

            if failed && pause_on_error {
                let should_continue = context.failure_decisions.wait(batch_id).await;
                if !should_continue {
                    if let Ok(mut stopped) = context.stopped_batches.lock() {
                        stopped.insert(batch_id);
                    }
                }
            }
        }
    });
}

fn retry_delay_ms(initial_ms: u64, retry_number: usize) -> u64 {
    let initial_ms = initial_ms.clamp(
        crate::store::settings::MIN_RETRY_BACKOFF_MS,
        crate::store::settings::MAX_RETRY_BACKOFF_MS,
    );
    let shift = retry_number.saturating_sub(1).min(16) as u32;
    initial_ms
        .saturating_mul(1_u64 << shift)
        .min(crate::store::settings::MAX_RETRY_BACKOFF_MS)
}

async fn wait_for_retry(
    delay: Duration,
    context: &EndpointWorkerContext,
    flag: &AtomicBool,
    connection_id: usize,
    epoch: u64,
) -> bool {
    let deadline = tokio::time::Instant::now() + delay;
    loop {
        if flag.load(Ordering::Relaxed)
            || !connection_epoch_is_current(&context.connection_epochs, connection_id, epoch)
        {
            return false;
        }
        if tokio::time::Instant::now() >= deadline && !context.paused.load(Ordering::Relaxed) {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn run_one(
    store: &Arc<dyn CredentialStore>,
    updates: &mpsc::Sender<TransferUpdate>,
    job: &TransferJob,
    spec: &ConnectionSpec,
    flag: &Arc<AtomicBool>,
    bandwidth_limiter: &Arc<BandwidthLimiter>,
    active_session: &mut Option<ActiveTransferSession>,
) -> JobOutcome {
    let session_identity = match SessionIdentity::for_spec(spec) {
        Ok(identity) => identity,
        Err(error) => return JobOutcome::permanent(error.to_string()),
    };
    let password = match store.get_for(&session_identity.credential) {
        Ok(b) => String::from_utf8_lossy(&b).into_owned(),
        Err(crate::store::CredentialError::NotFound)
            if spec.protocol == Protocol::Sftp && spec.sftp_auth != SftpAuth::Password =>
        {
            String::new()
        }
        Err(error) => return JobOutcome::permanent(error.to_string()),
    };
    let settings = crate::store::settings::load();
    let metadata_policy = crate::net::MetadataPreservation {
        timestamps: settings.preserve_transfer_timestamps,
        permissions: settings.preserve_transfer_permissions,
    };

    if active_session
        .as_ref()
        .is_some_and(|session| session.identity() != &session_identity)
    {
        if let Some(session) = active_session.take() {
            session.close().await;
        }
    }

    let execution = ProtocolJobExecution {
        identity: session_identity,
        spec: spec.clone(),
        password,
        job,
        updates,
        flag,
        bandwidth_limiter,
        metadata_policy,
    };
    let result = match spec.protocol {
        Protocol::Ftp => run_ftp_job(active_session, execution).await,
        Protocol::Sftp => run_sftp_job(active_session, execution).await,
    };

    // After this job's connection was disconnected (abort), don't surface the orphaned
    // outcome — it would read as a confusing "transfer complete" / "Operation timed out"
    // over a dead session. `flag` is this job's own cancel flag (set by abort(conn_id)).
    if flag.load(Ordering::Relaxed) {
        return JobOutcome::Suppressed;
    }
    match result {
        Ok(()) => JobOutcome::Done,
        Err(error) => JobOutcome::from_net_error(error),
    }
}

struct ProtocolJobExecution<'a> {
    identity: SessionIdentity,
    spec: ConnectionSpec,
    password: String,
    job: &'a TransferJob,
    updates: &'a mpsc::Sender<TransferUpdate>,
    flag: &'a Arc<AtomicBool>,
    bandwidth_limiter: &'a Arc<BandwidthLimiter>,
    metadata_policy: crate::net::MetadataPreservation,
}

async fn run_ftp_job(
    active_session: &mut Option<ActiveTransferSession>,
    execution: ProtocolJobExecution<'_>,
) -> Result<(), crate::net::NetError> {
    let ProtocolJobExecution {
        identity,
        spec,
        password,
        job,
        updates,
        flag,
        bandwidth_limiter,
        metadata_policy,
    } = execution;
    let existing = match active_session.take() {
        Some(ActiveTransferSession::Ftp(existing_identity, session))
            if existing_identity == identity =>
        {
            Some(session)
        }
        Some(other) => {
            other.close().await;
            None
        }
        None => None,
    };
    let reused = existing.is_some();
    let direction = job.direction;
    let local = std::path::PathBuf::from(&job.local_path);
    let remote = job.remote_path.clone();
    let resume = (direction == TransferDirection::Download && job.resume_token != 0).then_some(
        crate::net::DownloadResume {
            token: job.resume_token,
            expected_total: job.bytes_total,
        },
    );
    let upload_resume = upload_resume(job);
    let progress = throttled(
        updates.clone(),
        job.id,
        job.batch_id,
        job.bytes_total,
        bandwidth_limiter.clone(),
        flag.clone(),
    );
    let flag = flag.clone();

    let (session, result) = tokio::task::spawn_blocking(move || {
        let mut session = match existing {
            Some(session) => session,
            None => match ftp::TransferSession::connect(&spec, &password) {
                Ok(session) => session,
                Err(error) => return (None, Err(error)),
            },
        };
        let transfer = |session: &mut ftp::TransferSession| match direction {
            TransferDirection::Download => session.download_resumable_with_metadata(
                &remote,
                &local,
                &progress,
                Some(&*flag),
                resume,
                metadata_policy,
            ),
            TransferDirection::Upload => session.upload_resumable_with_metadata(
                &local,
                &remote,
                &progress,
                Some(&*flag),
                upload_resume,
                metadata_policy,
            ),
        };
        let mut result = transfer(&mut session);
        if reused && result.is_err() && !flag.load(Ordering::Relaxed) {
            tracing::debug!(
                host = %spec.host,
                "reused FTP session failed; reconnecting once"
            );
            session.close();
            session = match ftp::TransferSession::connect(&spec, &password) {
                Ok(session) => session,
                Err(error) => return (None, Err(error)),
            };
            result = transfer(&mut session);
        }
        if result.is_ok() {
            (Some(session), result)
        } else {
            session.close();
            (None, result)
        }
    })
    .await
    .map_err(|error| crate::net::NetError::Join(error.to_string()))?;

    if let Some(session) = session {
        *active_session = Some(ActiveTransferSession::Ftp(identity, session));
    }
    result.map(|_| ())
}

async fn run_sftp_job(
    active_session: &mut Option<ActiveTransferSession>,
    execution: ProtocolJobExecution<'_>,
) -> Result<(), crate::net::NetError> {
    let ProtocolJobExecution {
        identity,
        spec,
        password,
        job,
        updates,
        flag,
        bandwidth_limiter,
        metadata_policy,
    } = execution;
    let existing = match active_session.take() {
        Some(ActiveTransferSession::Sftp(existing_identity, session))
            if existing_identity == identity =>
        {
            Some(session)
        }
        Some(other) => {
            other.close().await;
            None
        }
        None => None,
    };
    let reused = existing.is_some();
    let mut session = match existing {
        Some(session) => session,
        None => sftp::TransferSession::connect(&spec, &password).await?,
    };
    let local = std::path::PathBuf::from(&job.local_path);
    let progress = throttled(
        updates.clone(),
        job.id,
        job.batch_id,
        job.bytes_total,
        bandwidth_limiter.clone(),
        flag.clone(),
    );
    let mut result =
        perform_sftp_transfer(&session, job, &local, &progress, flag, metadata_policy).await;
    if reused && result.is_err() && !flag.load(Ordering::Relaxed) {
        tracing::debug!(
            host = %spec.host,
            "reused SFTP session failed; reconnecting once"
        );
        session.close("stale-transfer-session").await;
        session = sftp::TransferSession::connect(&spec, &password).await?;
        result =
            perform_sftp_transfer(&session, job, &local, &progress, flag, metadata_policy).await;
    }
    if result.is_ok() {
        *active_session = Some(ActiveTransferSession::Sftp(identity, session));
    } else {
        session.close("failed-transfer-session").await;
    }
    result.map(|_| ())
}

async fn perform_sftp_transfer<F>(
    session: &sftp::TransferSession,
    job: &TransferJob,
    local: &std::path::Path,
    progress: &F,
    flag: &AtomicBool,
    metadata_policy: crate::net::MetadataPreservation,
) -> Result<u64, crate::net::NetError>
where
    F: Fn(u64) + Send + Sync,
{
    match job.direction {
        TransferDirection::Download => {
            let resume = (job.resume_token != 0).then_some(crate::net::DownloadResume {
                token: job.resume_token,
                expected_total: job.bytes_total,
            });
            session
                .download_resumable_with_metadata(
                    &job.remote_path,
                    local,
                    progress,
                    Some(flag),
                    resume,
                    metadata_policy,
                )
                .await
        }
        TransferDirection::Upload => {
            session
                .upload_resumable_with_metadata(
                    local,
                    &job.remote_path,
                    progress,
                    Some(flag),
                    upload_resume(job),
                    metadata_policy,
                )
                .await
        }
    }
}

fn upload_resume(job: &TransferJob) -> Option<crate::net::UploadResume> {
    if job.direction != TransferDirection::Upload || job.resume_token == 0 {
        return None;
    }
    Some(crate::net::UploadResume {
        token: job.resume_token,
        expected_total: job.bytes_total?,
        expected_modified_unix_nanos: job.source_modified_unix_nanos?,
    })
}

/// Build a progress callback that emits at most ~30×/s to avoid flooding the UI.
fn throttled(
    updates: mpsc::Sender<TransferUpdate>,
    id: TransferId,
    batch_id: usize,
    total: Option<u64>,
    bandwidth_limiter: Arc<BandwidthLimiter>,
    cancelled: Arc<AtomicBool>,
) -> impl Fn(u64) + Send + Sync + 'static {
    let last = Arc::new(std::sync::Mutex::new(
        Instant::now() - Duration::from_secs(1),
    ));
    let previous_bytes = Arc::new(Mutex::new(None::<u64>));
    move |done: u64| {
        let bytes = previous_bytes
            .lock()
            .ok()
            .map(|mut previous| {
                let delta = previous
                    .map(|value| done.saturating_sub(value))
                    .unwrap_or_else(|| done.min(128 * 1_024));
                *previous = Some(done);
                delta
            })
            .unwrap_or(0);
        bandwidth_limiter.throttle(bytes, &cancelled);
        let should_emit = {
            let mut g = match last.lock() {
                Ok(g) => g,
                Err(_) => return,
            };
            if g.elapsed() >= Duration::from_millis(33) {
                *g = Instant::now();
                true
            } else {
                false
            }
        };
        if should_emit {
            let _ = updates.try_send(TransferUpdate {
                id,
                batch_id,
                requires_decision: false,
                bytes_done: done,
                bytes_total: total,
                state: TransferState::Active,
            });
        }
    }
}

#[cfg(test)]
mod batch_failure_tests {
    use super::*;
    use crate::model::{ConnectionId, Protocol};
    use crate::store::memory::InMemoryStore;

    #[test]
    fn retry_backoff_is_exponential_and_safely_capped() {
        assert_eq!(retry_delay_ms(1_000, 1), 1_000);
        assert_eq!(retry_delay_ms(1_000, 2), 2_000);
        assert_eq!(retry_delay_ms(1_000, 3), 4_000);
        assert_eq!(retry_delay_ms(30_000, 3), 60_000);
        assert_eq!(retry_delay_ms(0, 1), 100);
        assert_eq!(retry_delay_ms(u64::MAX, usize::MAX), 60_000);
    }

    #[test]
    fn bandwidth_limit_supports_unlimited_and_safe_bounds() {
        assert_eq!(normalize_bandwidth_limit(0), 0);
        assert_eq!(
            normalize_bandwidth_limit(1),
            crate::store::settings::MIN_BANDWIDTH_LIMIT_KIB
        );
        assert_eq!(
            normalize_bandwidth_limit(u64::MAX),
            crate::store::settings::MAX_BANDWIDTH_LIMIT_KIB
        );
        let limiter = BandwidthLimiter::new(512);
        assert_eq!(limiter.set_limit(0), 0);
        assert_eq!(limiter.set_limit(1), 64);
    }
    use crate::store::{CredentialError, CredentialStore};
    use std::sync::Condvar;

    struct ConcurrentProbeStore {
        gate: (Mutex<usize>, Condvar),
        active: AtomicUsize,
        max_active: AtomicUsize,
    }

    impl ConcurrentProbeStore {
        fn new() -> Self {
            Self {
                gate: (Mutex::new(0), Condvar::new()),
                active: AtomicUsize::new(0),
                max_active: AtomicUsize::new(0),
            }
        }
    }

    impl CredentialStore for ConcurrentProbeStore {
        fn get(&self, _host: &str, _user: &str) -> Result<Vec<u8>, CredentialError> {
            Err(CredentialError::NotFound)
        }

        fn set(&self, _host: &str, _user: &str, _secret: &[u8]) -> Result<(), CredentialError> {
            Ok(())
        }

        fn delete(&self, _host: &str, _user: &str) -> Result<(), CredentialError> {
            Ok(())
        }

        fn get_for(&self, _key: &CredentialKey) -> Result<Vec<u8>, CredentialError> {
            let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
            self.max_active.fetch_max(active, Ordering::SeqCst);
            let (lock, ready) = &self.gate;
            let mut arrived = lock.lock().unwrap();
            *arrived += 1;
            if *arrived >= 2 {
                ready.notify_all();
            } else {
                let (guard, _) = ready.wait_timeout(arrived, Duration::from_secs(1)).unwrap();
                arrived = guard;
            }
            drop(arrived);
            self.active.fetch_sub(1, Ordering::SeqCst);
            Err(CredentialError::NotFound)
        }

        fn set_for(&self, _key: &CredentialKey, _secret: &[u8]) -> Result<(), CredentialError> {
            Ok(())
        }

        fn delete_for(&self, _key: &CredentialKey) -> Result<(), CredentialError> {
            Ok(())
        }
    }

    fn spec() -> ConnectionSpec {
        ConnectionSpec {
            id: ConnectionId(77),
            name: "test".into(),
            protocol: Protocol::Sftp,
            host: "example.invalid".into(),
            port: 22,
            user: "nobody".into(),
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
            transfer_concurrency: Some(1),
        }
    }

    fn job(id: usize, batch_id: usize, pause_on_error: bool) -> TransferJob {
        TransferJob {
            id: TransferId(id),
            batch_id,
            pause_on_error,
            priority: Default::default(),
            direction: TransferDirection::Upload,
            local_path: "/missing".into(),
            remote_path: "/missing".into(),
            bytes_total: None,
            source_modified_unix_nanos: None,
            resume_token: 0,
        }
    }

    #[test]
    fn scheduler_honours_priority_pause_and_manual_order() {
        let controls = QueueControls::default();
        let mut first = job(1, 1, false);
        let second = job(2, 2, false);
        let mut high = job(3, 3, false);
        first.priority = TransferPriority::Normal;
        high.priority = TransferPriority::High;
        controls.register(&first);
        controls.register(&second);
        controls.register(&high);
        assert!(controls.set_paused(first.id, true));

        let connection = spec();
        let mut pending = vec![
            QueuedTransfer {
                job: first.clone(),
                spec: connection.clone(),
                epoch: 0,
            },
            QueuedTransfer {
                job: second.clone(),
                spec: connection.clone(),
                epoch: 0,
            },
            QueuedTransfer {
                job: high,
                spec: connection,
                epoch: 0,
            },
        ];
        let high_index = controls.take_best(&pending).unwrap();
        assert_eq!(pending.remove(high_index).job.id, TransferId(3));

        assert!(controls.set_paused(first.id, false));
        assert!(controls.swap(first.id, second.id));
        let next_index = controls.take_best(&pending).unwrap();
        assert_eq!(pending[next_index].job.id, TransferId(2));
    }

    #[tokio::test]
    async fn stop_marks_remaining_batch_jobs_as_skipped() {
        let (updates, mut rx) = mpsc::channel(8);
        let engine = TransferEngine::start(Arc::new(InMemoryStore::default()), updates);
        engine.enqueue(job(1, 42, true), spec()).await;
        engine.enqueue(job(2, 42, true), spec()).await;

        let failed = rx.recv().await.expect("first failure");
        assert!(matches!(failed.state, TransferState::Failed(_)));
        assert!(failed.requires_decision);
        engine.resolve_batch_failure(42, false);

        let skipped = rx.recv().await.expect("skipped remaining job");
        assert_eq!(skipped.id, TransferId(2));
        assert!(matches!(skipped.state, TransferState::Skipped(_)));
        assert!(!skipped.requires_decision);
    }

    #[tokio::test]
    async fn skip_failed_file_allows_the_next_batch_job_to_run() {
        let (updates, mut rx) = mpsc::channel(8);
        let engine = TransferEngine::start(Arc::new(InMemoryStore::default()), updates);
        engine.enqueue(job(1, 43, true), spec()).await;
        engine.enqueue(job(2, 43, false), spec()).await;

        let failed = rx.recv().await.expect("first failure");
        assert!(matches!(failed.state, TransferState::Failed(_)));
        engine.resolve_batch_failure(43, true);

        let next = rx.recv().await.expect("next job result");
        assert_eq!(next.id, TransferId(2));
        assert!(matches!(next.state, TransferState::Failed(_)));
        assert!(!next.requires_decision);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn different_endpoints_reach_independent_workers_concurrently() {
        let (updates, mut rx) = mpsc::channel(8);
        let store = Arc::new(ConcurrentProbeStore::new());
        let engine = TransferEngine::start(store.clone(), updates);
        engine.set_endpoint_concurrency(2);
        let first = spec();
        let mut second = spec();
        second.id = ConnectionId(78);
        second.host = "other.example.invalid".into();

        engine.enqueue(job(1, 100, false), first).await;
        engine.enqueue(job(2, 101, false), second).await;
        for _ in 0..2 {
            let update = tokio::time::timeout(Duration::from_secs(3), rx.recv())
                .await
                .expect("endpoint workers should not block each other")
                .expect("result");
            assert!(matches!(update.state, TransferState::Failed(_)));
        }
        assert!(store.max_active.load(Ordering::SeqCst) >= 2);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn one_endpoint_uses_its_configured_parallel_lanes() {
        let (updates, mut rx) = mpsc::channel(8);
        let store = Arc::new(ConcurrentProbeStore::new());
        let engine = TransferEngine::start(store.clone(), updates);
        engine.set_endpoint_concurrency(2);
        let mut connection = spec();
        connection.transfer_concurrency = Some(2);

        engine.enqueue(job(1, 102, false), connection.clone()).await;
        engine.enqueue(job(2, 103, false), connection).await;
        for _ in 0..2 {
            let update = tokio::time::timeout(Duration::from_secs(3), rx.recv())
                .await
                .expect("per-server lanes should not serialize both jobs")
                .expect("result");
            assert!(matches!(update.state, TransferState::Failed(_)));
        }
        assert!(store.max_active.load(Ordering::SeqCst) >= 2);
    }

    #[tokio::test]
    async fn abort_epoch_skips_old_jobs_but_allows_new_ones() {
        let (updates, mut rx) = mpsc::channel(8);
        let engine = TransferEngine::start(Arc::new(InMemoryStore::default()), updates);
        let connection = spec();
        engine.set_paused(true);
        engine.enqueue(job(1, 110, false), connection.clone()).await;
        engine.abort(connection.id);
        engine.set_paused(false);

        let old = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(old.state, TransferState::Skipped(_)));

        engine.enqueue(job(2, 111, false), connection).await;
        let new = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(new.id, TransferId(2));
        assert!(matches!(new.state, TransferState::Failed(_)));
    }

    #[tokio::test]
    async fn individual_cancel_can_be_retried_with_the_same_job_id() {
        let (updates, mut rx) = mpsc::channel(8);
        let engine = TransferEngine::start(Arc::new(InMemoryStore::default()), updates);
        engine.set_paused(true);
        engine.enqueue(job(9, 120, false), spec()).await;
        engine.cancel_job(TransferId(9));
        engine.set_paused(false);

        let cancelled = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(cancelled.id, TransferId(9));
        assert!(matches!(cancelled.state, TransferState::Cancelled));

        engine.retry_job(TransferId(9)).unwrap();
        let retried = tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(retried.id, TransferId(9));
        assert!(matches!(retried.state, TransferState::Failed(_)));

        engine.forget_job(TransferId(9));
        assert_eq!(engine.retry_job(TransferId(9)), Err(RetryError::NotFound));
    }

    #[tokio::test]
    async fn endpoint_limit_can_grow_without_interrupting_active_permits() {
        let limiter = Arc::new(EndpointLimiter::new(2));
        let first = limiter.acquire().await;
        let second = limiter.acquire().await;
        let waiting_limiter = limiter.clone();
        let waiting = tokio::spawn(async move { waiting_limiter.acquire().await });
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(!waiting.is_finished());

        assert_eq!(limiter.set_limit(3), 3);
        let third = tokio::time::timeout(Duration::from_secs(1), waiting)
            .await
            .unwrap()
            .unwrap();

        assert_eq!(limiter.set_limit(0), MIN_ENDPOINT_CONCURRENCY);
        drop(first);
        drop(second);
        drop(third);
        let _single = tokio::time::timeout(Duration::from_secs(1), limiter.acquire())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn live_default_server_limit_is_safely_bounded() {
        let (updates, _rx) = mpsc::channel(8);
        let engine = TransferEngine::start(Arc::new(InMemoryStore::default()), updates);
        assert_eq!(
            engine.set_default_server_concurrency(0),
            MIN_SERVER_CONCURRENCY
        );
        assert_eq!(
            engine.set_default_server_concurrency(usize::MAX),
            MAX_SERVER_CONCURRENCY
        );
    }
}
