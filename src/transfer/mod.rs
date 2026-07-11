//! Transfer engine: a background worker that runs queued download/upload jobs and
//! streams throttled progress updates. The UI subscribes to the updates channel and
//! marshals them onto the Slint event loop (invoke_from_event_loop).

pub mod progress;

pub use progress::{TransferState, TransferUpdate};

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::{mpsc, Notify};

use crate::model::{
    ConnectionId, ConnectionSpec, Protocol, SftpAuth, TransferDirection, TransferId, TransferJob,
};
use crate::net::{ftp, sftp};
use crate::store::{CredentialKey, CredentialStore};

const MAX_QUEUED_TRANSFERS: usize = 8_192;
pub const MIN_ENDPOINT_CONCURRENCY: usize = crate::store::settings::MIN_TRANSFER_CONCURRENCY;
pub const MAX_ENDPOINT_CONCURRENCY: usize = crate::store::settings::MAX_TRANSFER_CONCURRENCY;
pub const DEFAULT_ENDPOINT_CONCURRENCY: usize =
    crate::store::settings::DEFAULT_TRANSFER_CONCURRENCY;
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct SessionIdentity {
    credential: CredentialKey,
    allow_plaintext_ftp: bool,
    accept_invalid_tls: bool,
    sftp_auth: SftpAuth,
    sftp_private_key: Option<String>,
}

impl SessionIdentity {
    fn for_spec(spec: &ConnectionSpec) -> Result<Self, crate::store::CredentialError> {
        Ok(Self {
            credential: CredentialKey::for_spec(spec)?,
            allow_plaintext_ftp: spec.allow_plaintext_ftp,
            accept_invalid_tls: spec.accept_invalid_tls,
            sftp_auth: spec.sftp_auth,
            sftp_private_key: spec.sftp_private_key.clone(),
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

/// `(job_id, batch_id, cancel_flag)` of one endpoint worker's currently running job.
type InFlight = (TransferId, usize, Arc<AtomicBool>);

enum JobOutcome {
    Done,
    Failed(String),
    Suppressed,
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
            if let Ok(mut values) = self.values.lock() {
                if let Some(decision) = values.remove(&batch_id) {
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

#[derive(Clone)]
struct EndpointWorkerContext {
    store: Arc<dyn CredentialStore>,
    updates: mpsc::Sender<TransferUpdate>,
    connection_epochs: Arc<Mutex<HashMap<usize, u64>>>,
    current: Arc<Mutex<HashMap<usize, InFlight>>>,
    paused: Arc<AtomicBool>,
    failure_decisions: Arc<FailureDecisions>,
    stopped_batches: Arc<Mutex<HashSet<usize>>>,
    cancelled_jobs: Arc<Mutex<HashSet<usize>>>,
    outstanding: Arc<AtomicUsize>,
    endpoint_limiter: Arc<EndpointLimiter>,
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
    /// One in-flight job per endpoint. Separate workers allow unrelated servers to progress in
    /// parallel while preserving ordered, session-reusing transfers on each individual server.
    current: Arc<Mutex<HashMap<usize, InFlight>>>,
    /// Pause-all toggle (transfer panel): when set, the worker holds a freshly dequeued job
    /// without starting it until cleared. An in-flight transfer finishes normally first.
    paused: Arc<AtomicBool>,
    /// User decisions are shared because any endpoint worker may be waiting for its batch.
    failure_decisions: Arc<FailureDecisions>,
    /// The dispatcher drains quickly into endpoint queues, so a separate global counter keeps the
    /// original hard memory bound meaningful.
    outstanding: Arc<AtomicUsize>,
    endpoint_limiter: Arc<EndpointLimiter>,
    cancelled_jobs: Arc<Mutex<HashSet<usize>>>,
    jobs: Arc<Mutex<HashMap<usize, (TransferJob, ConnectionSpec)>>>,
    retry_sequence: Arc<AtomicUsize>,
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
        let jobs = Arc::new(Mutex::new(HashMap::new()));
        let retry_sequence = Arc::new(AtomicUsize::new(0));
        let outstanding = Arc::new(AtomicUsize::new(0));
        let endpoint_limiter = Arc::new(EndpointLimiter::new(
            crate::store::settings::load().transfer_concurrency,
        ));
        let worker_context = EndpointWorkerContext {
            store,
            updates: updates.clone(),
            connection_epochs: connection_epochs.clone(),
            current: current.clone(),
            paused: paused.clone(),
            failure_decisions: failure_decisions.clone(),
            stopped_batches,
            cancelled_jobs: cancelled_jobs.clone(),
            outstanding: outstanding.clone(),
            endpoint_limiter: endpoint_limiter.clone(),
        };
        tokio::spawn(async move {
            let mut workers: HashMap<usize, mpsc::UnboundedSender<Cmd>> = HashMap::new();
            while let Some(command) = rx.recv().await {
                let cid = match &command {
                    Cmd::Run(queued) => queued.spec.id.0,
                    Cmd::Abort(connection_id) => connection_id.0,
                };
                let worker = workers
                    .entry(cid)
                    .or_insert_with(|| spawn_endpoint_worker(worker_context.clone()));
                if let Err(error) = worker.send(command) {
                    workers.remove(&cid);
                    if let Cmd::Run(queued) = error.0 {
                        let job = queued.job;
                        worker_context.outstanding.fetch_sub(1, Ordering::Relaxed);
                        let _ = updates
                            .send(TransferUpdate {
                                id: job.id,
                                batch_id: job.batch_id,
                                requires_decision: job.pause_on_error,
                                bytes_done: 0,
                                bytes_total: job.bytes_total,
                                state: TransferState::Failed(
                                    "endpoint transfer worker stopped unexpectedly".into(),
                                ),
                            })
                            .await;
                    }
                }
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
            cancelled_jobs,
            jobs,
            retry_sequence,
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
            if let Some((_, batch_id, flag)) = g.get(&cid) {
                flag.store(true, Ordering::Relaxed);
                self.failure_decisions.resolve(*batch_id, false);
            }
        }
        let _ = self.tx.try_send(Cmd::Abort(conn_id));
    }

    /// Pause/resume dequeue of new transfers (the transfer-panel "Pause all" toggle). An
    /// in-flight transfer finishes first; the next job is held until resumed.
    pub fn set_paused(&self, paused: bool) {
        self.paused.store(paused, Ordering::Relaxed);
    }

    /// Change the number of endpoints allowed to transfer at once. Lowering the value never
    /// interrupts active files; it takes effect as their permits are released.
    pub fn set_endpoint_concurrency(&self, limit: usize) -> usize {
        self.endpoint_limiter.set_limit(limit)
    }

    pub fn cancel_job(&self, id: TransferId) {
        if let Ok(mut cancelled) = self.cancelled_jobs.lock() {
            cancelled.insert(id.0);
        }
        if let Ok(current) = self.current.lock() {
            for (job_id, _, flag) in current.values() {
                if *job_id == id {
                    flag.store(true, Ordering::Relaxed);
                }
            }
        }
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
        let epoch = self.connection_epoch(spec.id);
        if self
            .tx
            .try_send(Cmd::Run(Box::new(QueuedTransfer { job, spec, epoch })))
            .is_err()
        {
            self.outstanding.fetch_sub(1, Ordering::Relaxed);
            return Err(RetryError::QueueFull);
        }
        Ok(())
    }

    pub fn forget_job(&self, id: TransferId) {
        let removed = self
            .jobs
            .lock()
            .ok()
            .and_then(|mut jobs| jobs.remove(&id.0));
        if let Some((job, _)) = removed {
            if job.direction == TransferDirection::Download && job.resume_token != 0 {
                crate::net::discard_download_fragment(
                    std::path::Path::new(&job.local_path),
                    job.resume_token,
                );
            }
        }
        if let Ok(mut cancelled) = self.cancelled_jobs.lock() {
            cancelled.remove(&id.0);
        }
    }

    /// Resolve the modal shown after one file in a multi-file batch fails.
    pub fn resolve_batch_failure(&self, batch_id: usize, should_continue: bool) {
        self.failure_decisions.resolve(batch_id, should_continue);
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

fn spawn_endpoint_worker(context: EndpointWorkerContext) -> mpsc::UnboundedSender<Cmd> {
    let (tx, mut rx) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        let mut active_session: Option<ActiveTransferSession> = None;
        loop {
            let command = if active_session.is_some() {
                match tokio::time::timeout(TRANSFER_SESSION_IDLE_TIMEOUT, rx.recv()).await {
                    Ok(command) => command,
                    Err(_) => {
                        if let Some(session) = active_session.take() {
                            session.close().await;
                        }
                        continue;
                    }
                }
            } else {
                rx.recv().await
            };
            let Some(command) = command else {
                break;
            };

            let (job, spec, epoch) = match command {
                Cmd::Abort(_) => {
                    if let Some(session) = active_session.take() {
                        session.close().await;
                    }
                    continue;
                }
                Cmd::Run(queued) => (queued.job, queued.spec, queued.epoch),
            };
            let _outstanding = OutstandingGuard(context.outstanding.clone());
            let connection_id = spec.id.0;

            if take_cancelled(&context.cancelled_jobs, job.id) {
                report_cancelled(&context.updates, &job).await;
                continue;
            }

            let batch_stopped = context
                .stopped_batches
                .lock()
                .map(|stopped| stopped.contains(&job.batch_id))
                .unwrap_or(true);
            if batch_stopped {
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
                report_skipped(&context.updates, &job, "connection was disconnected").await;
                continue;
            }
            if take_cancelled(&context.cancelled_jobs, job.id) {
                drop(permit);
                report_cancelled(&context.updates, &job).await;
                continue;
            }

            let flag = Arc::new(AtomicBool::new(false));
            if let Ok(mut current) = context.current.lock() {
                current.insert(connection_id, (job.id, job.batch_id, flag.clone()));
            }
            let job_for_update = job.clone();
            let batch_id = job.batch_id;
            let pause_on_error = job.pause_on_error;
            let outcome = run_one(
                &context.store,
                &context.updates,
                job,
                spec,
                &flag,
                &mut active_session,
            )
            .await;
            if let Ok(mut current) = context.current.lock() {
                current.remove(&connection_id);
            }
            drop(permit);

            let individually_cancelled = take_cancelled(&context.cancelled_jobs, job_for_update.id);
            let failed = matches!(outcome, JobOutcome::Failed(_)) && !individually_cancelled;
            if individually_cancelled {
                report_cancelled(&context.updates, &job_for_update).await;
            } else {
                let state = match outcome {
                    JobOutcome::Done => Some(TransferState::Done),
                    JobOutcome::Failed(error) => Some(TransferState::Failed(error)),
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
        if let Some(session) = active_session.take() {
            session.close().await;
        }
    });
    tx
}

async fn run_one(
    store: &Arc<dyn CredentialStore>,
    updates: &mpsc::Sender<TransferUpdate>,
    job: TransferJob,
    spec: ConnectionSpec,
    flag: &Arc<AtomicBool>,
    active_session: &mut Option<ActiveTransferSession>,
) -> JobOutcome {
    let session_identity = match SessionIdentity::for_spec(&spec) {
        Ok(identity) => identity,
        Err(error) => return JobOutcome::Failed(error.to_string()),
    };
    let password = match store.get_for(&session_identity.credential) {
        Ok(b) => String::from_utf8_lossy(&b).into_owned(),
        Err(crate::store::CredentialError::NotFound)
            if spec.protocol == Protocol::Sftp && spec.sftp_auth != SftpAuth::Password =>
        {
            String::new()
        }
        Err(error) => return JobOutcome::Failed(error.to_string()),
    };

    if active_session
        .as_ref()
        .is_some_and(|session| session.identity() != &session_identity)
    {
        if let Some(session) = active_session.take() {
            session.close().await;
        }
    }

    let result = match spec.protocol {
        Protocol::Ftp => {
            run_ftp_job(
                active_session,
                session_identity,
                spec,
                password,
                &job,
                updates,
                flag,
            )
            .await
        }
        Protocol::Sftp => {
            run_sftp_job(
                active_session,
                session_identity,
                spec,
                password,
                &job,
                updates,
                flag,
            )
            .await
        }
    }
    .map_err(|error| error.to_string());

    // After this job's connection was disconnected (abort), don't surface the orphaned
    // outcome — it would read as a confusing "transfer complete" / "Operation timed out"
    // over a dead session. `flag` is this job's own cancel flag (set by abort(conn_id)).
    if flag.load(Ordering::Relaxed) {
        return JobOutcome::Suppressed;
    }
    match result {
        Ok(()) => JobOutcome::Done,
        Err(error) => JobOutcome::Failed(error),
    }
}

async fn run_ftp_job(
    active_session: &mut Option<ActiveTransferSession>,
    identity: SessionIdentity,
    spec: ConnectionSpec,
    password: String,
    job: &TransferJob,
    updates: &mpsc::Sender<TransferUpdate>,
    flag: &Arc<AtomicBool>,
) -> Result<(), crate::net::NetError> {
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
    let progress = throttled(updates.clone(), job.id, job.batch_id, job.bytes_total);
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
            TransferDirection::Download => {
                session.download_resumable(&remote, &local, &progress, Some(&*flag), resume)
            }
            TransferDirection::Upload => session.upload(&local, &remote, &progress, Some(&*flag)),
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
    identity: SessionIdentity,
    spec: ConnectionSpec,
    password: String,
    job: &TransferJob,
    updates: &mpsc::Sender<TransferUpdate>,
    flag: &Arc<AtomicBool>,
) -> Result<(), crate::net::NetError> {
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
    let progress = throttled(updates.clone(), job.id, job.batch_id, job.bytes_total);
    let mut result = perform_sftp_transfer(&session, job, &local, &progress, flag).await;
    if reused && result.is_err() && !flag.load(Ordering::Relaxed) {
        tracing::debug!(
            host = %spec.host,
            "reused SFTP session failed; reconnecting once"
        );
        session.close("stale-transfer-session").await;
        session = sftp::TransferSession::connect(&spec, &password).await?;
        result = perform_sftp_transfer(&session, job, &local, &progress, flag).await;
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
                .download_resumable(&job.remote_path, local, progress, Some(flag), resume)
                .await
        }
        TransferDirection::Upload => {
            session
                .upload(local, &job.remote_path, progress, Some(flag))
                .await
        }
    }
}

/// Build a progress callback that emits at most ~30×/s to avoid flooding the UI.
fn throttled(
    updates: mpsc::Sender<TransferUpdate>,
    id: TransferId,
    batch_id: usize,
    total: Option<u64>,
) -> impl Fn(u64) + Send + Sync + 'static {
    let last = Arc::new(std::sync::Mutex::new(
        Instant::now() - Duration::from_secs(1),
    ));
    move |done: u64| {
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
            allow_plaintext_ftp: false,
            accept_invalid_tls: false,
            sftp_auth: Default::default(),
            sftp_private_key: None,
        }
    }

    fn job(id: usize, batch_id: usize, pause_on_error: bool) -> TransferJob {
        TransferJob {
            id: TransferId(id),
            batch_id,
            pause_on_error,
            direction: TransferDirection::Upload,
            local_path: "/missing".into(),
            remote_path: "/missing".into(),
            bytes_total: None,
            resume_token: 0,
        }
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
}
