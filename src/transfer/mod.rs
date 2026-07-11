//! Transfer engine: a background worker that runs queued download/upload jobs and
//! streams throttled progress updates. The UI subscribes to the updates channel and
//! marshals them onto the Slint event loop (invoke_from_event_loop).

pub mod progress;

pub use progress::{TransferState, TransferUpdate};

use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::mpsc;

use crate::model::{
    ConnectionId, ConnectionSpec, Protocol, TransferDirection, TransferId, TransferJob,
};
use crate::net::{ftp, sftp};
use crate::store::{CredentialKey, CredentialStore};

enum Cmd {
    Run(TransferJob, ConnectionSpec),
}

/// `(conn_id, batch_id, cancel_flag)` of the job the worker is currently running.
type InFlight = (usize, usize, Arc<AtomicBool>);

/// `try_enqueue` rejection reason: the bounded worker channel was full, so the job was NOT
/// accepted (it must be marked failed by the caller rather than left on "queued" forever).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueueFull;

/// Owns the queue. Cheap to clone-share via the returned handle.
#[derive(Clone)]
pub struct TransferEngine {
    tx: mpsc::Sender<Cmd>,
    /// Connection ids whose pending jobs should be skipped (set by `abort(conn_id)` on
    /// disconnect). Scoped per-connection so ejecting ONE server no longer cancels the
    /// transfers of every other session. Cleared for a conn when a new job for it is
    /// enqueued, so reconnecting the same server resumes its transfers.
    aborted_conns: Arc<Mutex<HashSet<usize>>>,
    /// The currently in-flight job's `(conn_id, cancel_flag)`. `abort(conn_id)` sets the flag
    /// when it matches, so the orphan's terminal update is suppressed — independent of the
    /// pending-skip set, which avoids the abort/re-enqueue race the global flag had.
    current: Arc<Mutex<Option<InFlight>>>,
    /// Pause-all toggle (transfer panel): when set, the worker holds a freshly dequeued job
    /// without starting it until cleared. An in-flight transfer finishes normally first.
    paused: Arc<AtomicBool>,
    /// User decision for a batch paused after a failed file: true=skip/continue, false=stop batch.
    failure_decision: mpsc::UnboundedSender<(usize, bool)>,
}

impl TransferEngine {
    /// Spawn the worker. Must be called from within a Tokio runtime.
    /// `updates` is where progress/final events land — the UI reads the other end.
    pub fn start(store: Arc<dyn CredentialStore>, updates: mpsc::Sender<TransferUpdate>) -> Self {
        // CONC-1: capacity large enough that a folder transfer (one Cmd per file) plus any
        // in-flight single-file job never overflows try_send. 8192 covers large folders (a web
        // build with thousands of hashed assets); a Cmd is ~200 bytes so the buffer is ~1.6 MB.
        let (tx, mut rx) = mpsc::channel::<Cmd>(8192);
        let (failure_decision, mut failure_rx) = mpsc::unbounded_channel::<(usize, bool)>();
        let aborted_conns: Arc<Mutex<HashSet<usize>>> = Arc::new(Mutex::new(HashSet::new()));
        let current: Arc<Mutex<Option<InFlight>>> = Arc::new(Mutex::new(None));
        let paused = Arc::new(AtomicBool::new(false));
        let (aborted_w, current_w, paused_w) =
            (aborted_conns.clone(), current.clone(), paused.clone());
        tokio::spawn(async move {
            let mut stopped_batches = HashSet::new();
            while let Some(Cmd::Run(job, spec)) = rx.recv().await {
                // Pause-all: hold the dequeued job without starting it until cleared.
                while paused_w.load(Ordering::Relaxed) {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                let cid = spec.id.0;
                if stopped_batches.contains(&job.batch_id) {
                    let _ = updates
                        .send(TransferUpdate {
                            id: job.id,
                            batch_id: job.batch_id,
                            requires_decision: false,
                            bytes_done: 0,
                            bytes_total: job.bytes_total,
                            state: TransferState::Skipped(
                                "batch stopped after an earlier file error".into(),
                            ),
                        })
                        .await;
                    continue;
                }
                // Skip jobs whose connection was disconnected while still queued.
                let skipped = aborted_w.lock().map(|g| g.contains(&cid)).unwrap_or(false);
                if skipped {
                    continue;
                }
                // Run with a fresh per-job cancel flag, remembered as the in-flight job.
                let flag = Arc::new(AtomicBool::new(false));
                if let Ok(mut g) = current_w.lock() {
                    *g = Some((cid, job.batch_id, flag.clone()));
                }
                let batch_id = job.batch_id;
                let pause_on_error = job.pause_on_error;
                let failed = run_one(&store, &updates, job, spec, &flag).await;
                if let Ok(mut g) = current_w.lock() {
                    *g = None;
                }
                if failed && pause_on_error {
                    while let Some((decision_batch, should_continue)) = failure_rx.recv().await {
                        if decision_batch != batch_id {
                            continue;
                        }
                        if !should_continue {
                            stopped_batches.insert(batch_id);
                        }
                        break;
                    }
                }
            }
        });
        Self {
            tx,
            aborted_conns,
            current,
            paused,
            failure_decision,
        }
    }

    /// Sync enqueue — safe to call from a UI callback (no .await). Returns Err(()) only
    /// if the worker channel is full (the job was not accepted). A fresh job for a connection
    /// clears any stale per-conn abort for it (reconnect resumes transfers). This does NOT
    /// touch an in-flight orphan's per-job flag, so there is no abort/re-enqueue race.
    pub fn try_enqueue(&self, job: TransferJob, spec: ConnectionSpec) -> Result<(), QueueFull> {
        if let Ok(mut g) = self.aborted_conns.lock() {
            g.remove(&spec.id.0);
        }
        self.tx.try_send(Cmd::Run(job, spec)).map_err(|_| QueueFull)
    }

    pub async fn enqueue(&self, job: TransferJob, spec: ConnectionSpec) {
        if let Ok(mut g) = self.aborted_conns.lock() {
            g.remove(&spec.id.0);
        }
        let _ = self.tx.send(Cmd::Run(job, spec)).await;
    }

    /// Abort a single connection's transfers: its pending jobs are skipped, and its in-flight
    /// job's terminal update is suppressed (a timed-out orphan over a dead session never
    /// surfaces as a confusing "Operation timed out"). Other sessions are left untouched.
    pub fn abort(&self, conn_id: ConnectionId) {
        let cid = conn_id.0;
        if let Ok(mut g) = self.aborted_conns.lock() {
            g.insert(cid);
        }
        if let Ok(g) = self.current.lock() {
            if let Some((c, batch_id, flag)) = g.as_ref() {
                if *c == cid {
                    flag.store(true, Ordering::Relaxed);
                    let _ = self.failure_decision.send((*batch_id, false));
                }
            }
        }
    }

    /// Pause/resume dequeue of new transfers (the transfer-panel "Pause all" toggle). An
    /// in-flight transfer finishes first; the next job is held until resumed.
    pub fn set_paused(&self, paused: bool) {
        self.paused.store(paused, Ordering::Relaxed);
    }

    /// Resolve the modal shown after one file in a multi-file batch fails.
    pub fn resolve_batch_failure(&self, batch_id: usize, should_continue: bool) {
        let _ = self.failure_decision.send((batch_id, should_continue));
    }
}

async fn run_one(
    store: &Arc<dyn CredentialStore>,
    updates: &mpsc::Sender<TransferUpdate>,
    job: TransferJob,
    spec: ConnectionSpec,
    flag: &Arc<AtomicBool>,
) -> bool {
    let id = job.id;
    let batch_id = job.batch_id;
    let pause_on_error = job.pause_on_error;
    let total = job.bytes_total;
    let credential_key = match CredentialKey::for_spec(&spec) {
        Ok(key) => key,
        Err(error) => {
            let _ = updates
                .send(TransferUpdate {
                    id,
                    batch_id,
                    requires_decision: pause_on_error,
                    bytes_done: 0,
                    bytes_total: None,
                    state: TransferState::Failed(error.to_string()),
                })
                .await;
            return true;
        }
    };
    let password = match store.get_for(&credential_key) {
        Ok(b) => String::from_utf8_lossy(&b).into_owned(),
        Err(_) => {
            let _ = updates
                .send(TransferUpdate {
                    id,
                    batch_id,
                    requires_decision: pause_on_error,
                    bytes_done: 0,
                    bytes_total: None,
                    state: TransferState::Failed("missing credential".into()),
                })
                .await;
            return true;
        }
    };

    let result: Result<(), String> = match (job.direction, spec.protocol) {
        (TransferDirection::Download, Protocol::Ftp) => {
            let (spec, password, remote, local) = (
                spec.clone(),
                password.clone(),
                job.remote_path.clone(),
                std::path::PathBuf::from(&job.local_path),
            );
            let progress = throttled(updates.clone(), id, batch_id, total);
            let flag = flag.clone(); // Arc clone for the 'static spawn_blocking closure (M1)
            tokio::task::spawn_blocking(move || {
                ftp::download(&spec, &password, &remote, &local, progress, Some(&*flag))
            })
            .await
            .map_err(|e| e.to_string())
            .and_then(|r| r.map(|_| ()).map_err(|e| e.to_string()))
        }
        (TransferDirection::Upload, Protocol::Ftp) => {
            let (spec, password, remote, local) = (
                spec.clone(),
                password.clone(),
                job.remote_path.clone(),
                std::path::PathBuf::from(&job.local_path),
            );
            let progress = throttled(updates.clone(), id, batch_id, total);
            let flag = flag.clone(); // M1
            tokio::task::spawn_blocking(move || {
                ftp::upload(&spec, &password, &local, &remote, progress, Some(&*flag))
            })
            .await
            .map_err(|e| e.to_string())
            .and_then(|r| r.map(|_| ()).map_err(|e| e.to_string()))
        }
        (TransferDirection::Download, Protocol::Sftp) => {
            let progress = throttled(updates.clone(), id, batch_id, total);
            let local = std::path::PathBuf::from(&job.local_path);
            sftp::download(
                &spec,
                &password,
                &job.remote_path,
                &local,
                progress,
                Some(&**flag),
            )
            .await
            .map(|_| ())
            .map_err(|e| e.to_string())
        }
        (TransferDirection::Upload, Protocol::Sftp) => {
            let progress = throttled(updates.clone(), id, batch_id, total);
            let local = std::path::PathBuf::from(&job.local_path);
            sftp::upload(
                &spec,
                &password,
                &local,
                &job.remote_path,
                progress,
                Some(&**flag),
            )
            .await
            .map(|_| ())
            .map_err(|e| e.to_string())
        }
    };

    // After this job's connection was disconnected (abort), don't surface the orphaned
    // outcome — it would read as a confusing "transfer complete" / "Operation timed out"
    // over a dead session. `flag` is this job's own cancel flag (set by abort(conn_id)).
    if flag.load(Ordering::Relaxed) {
        return false;
    }
    let failed = result.is_err();
    let _ = updates
        .send(TransferUpdate {
            id,
            batch_id,
            requires_decision: failed && pause_on_error,
            bytes_done: 0,
            bytes_total: total,
            state: match result {
                Ok(()) => TransferState::Done,
                Err(e) => TransferState::Failed(e),
            },
        })
        .await;
    failed
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
}
