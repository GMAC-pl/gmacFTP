//! Crash-safe persistence for resumable and queued transfers.
//!
//! The manifest deliberately contains only transfer paths and connection metadata. Credentials
//! remain in the encrypted credential store and are looked up again only after the user resumes.

use std::collections::{BTreeMap, HashSet};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::sync::Notify;

use crate::model::{ConnectionSpec, TransferJob};

const QUEUE_VERSION: u32 = 1;
const MAX_QUEUE_FILE_BYTES: usize = 16 * 1024 * 1024;
const MAX_QUEUE_ENTRIES: usize = super::MAX_QUEUED_TRANSFERS;
const MAX_LOCAL_PATH_BYTES: usize = 32 * 1024;
const MAX_REMOTE_PATH_BYTES: usize = 16 * 1024;

#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum PersistedState {
    Queued,
    Running,
    Retryable,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub(super) struct PersistedTransfer {
    pub job: TransferJob,
    pub spec: ConnectionSpec,
    pub state: PersistedState,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
struct QueueManifest {
    version: u32,
    jobs: Vec<PersistedTransfer>,
}

pub(super) struct QueuePersistence {
    path: Option<PathBuf>,
    entries: Mutex<BTreeMap<usize, PersistedTransfer>>,
    dirty: Notify,
}

impl QueuePersistence {
    pub(super) fn load_default() -> Arc<Self> {
        #[cfg(test)]
        {
            Self::load_at(None)
        }
        #[cfg(not(test))]
        {
            let path = directories::ProjectDirs::from(
                env!("MACKFTP_CONFIG_QUALIFIER"),
                env!("MACKFTP_CONFIG_ORGANIZATION"),
                env!("MACKFTP_CONFIG_APPLICATION"),
            )
            .map(|directories| directories.config_dir().join("transfer-queue.json"));
            Self::load_at(path)
        }
    }

    fn load_at(path: Option<PathBuf>) -> Arc<Self> {
        let manifest = match path.as_deref() {
            Some(path) => match load_manifest(path) {
                Ok(manifest) => manifest,
                Err(error) => {
                    tracing::warn!(%error, "transfer recovery manifest was rejected");
                    None
                }
            },
            None => None,
        };
        let entries = manifest
            .map(|manifest| manifest.jobs)
            .unwrap_or_default()
            .into_iter()
            .map(|mut transfer| {
                // A previous process cannot still own this work. Every persisted state becomes an
                // explicit user-controlled retry instead of running automatically at launch.
                transfer.state = PersistedState::Retryable;
                (transfer.job.id.0, transfer)
            })
            .collect();
        Arc::new(Self {
            path,
            entries: Mutex::new(entries),
            dirty: Notify::new(),
        })
    }

    pub(super) fn spawn_writer(self: &Arc<Self>) {
        let persistence = self.clone();
        tokio::spawn(async move {
            loop {
                persistence.dirty.notified().await;
                let persistence_for_write = persistence.clone();
                let result =
                    tokio::task::spawn_blocking(move || persistence_for_write.flush_now()).await;
                match result {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => {
                        tracing::warn!(%error, "could not persist transfer recovery manifest")
                    }
                    Err(error) => tracing::warn!(%error, "transfer manifest writer stopped"),
                }
                // Coalesce notifications from a large folder batch before the next rewrite while
                // still persisting the first accepted item without an artificial delay.
                tokio::time::sleep(Duration::from_millis(75)).await;
            }
        });
        if self
            .entries
            .lock()
            .map(|entries| !entries.is_empty())
            .unwrap_or(false)
        {
            self.dirty.notify_one();
        }
    }

    pub(super) fn set(&self, job: TransferJob, spec: ConnectionSpec, state: PersistedState) {
        if let Ok(mut entries) = self.entries.lock() {
            entries.insert(job.id.0, PersistedTransfer { job, spec, state });
        }
        self.dirty.notify_one();
    }

    pub(super) fn set_state(&self, id: usize, state: PersistedState) {
        if let Ok(mut entries) = self.entries.lock() {
            if let Some(entry) = entries.get_mut(&id) {
                entry.state = state;
            }
        }
        self.dirty.notify_one();
    }

    pub(super) fn remove(&self, id: usize) {
        if let Ok(mut entries) = self.entries.lock() {
            entries.remove(&id);
        }
        self.dirty.notify_one();
    }

    pub(super) fn contains(&self, id: usize) -> bool {
        self.entries
            .lock()
            .map(|entries| entries.contains_key(&id))
            .unwrap_or(false)
    }

    pub(super) fn recovered(&self) -> Vec<PersistedTransfer> {
        self.entries
            .lock()
            .map(|entries| entries.values().cloned().collect())
            .unwrap_or_default()
    }

    fn flush_now(&self) -> Result<(), std::io::Error> {
        let Some(path) = self.path.as_deref() else {
            return Ok(());
        };
        let jobs = self
            .entries
            .lock()
            .map_err(|_| std::io::Error::other("transfer queue lock poisoned"))?
            .values()
            .cloned()
            .collect();
        let manifest = QueueManifest {
            version: QUEUE_VERSION,
            jobs,
        };
        let payload = serde_json::to_vec_pretty(&manifest).map_err(|error| {
            std::io::Error::other(format!("queue serialization failed: {error}"))
        })?;
        if payload.len() > MAX_QUEUE_FILE_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "transfer recovery manifest exceeds its size limit",
            ));
        }
        crate::store::vault::atomic_write(path, &payload)
    }
}

fn load_manifest(path: &Path) -> Result<Option<QueueManifest>, std::io::Error> {
    let before = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    if !before.file_type().is_file()
        || before.file_type().is_symlink()
        || before.len() > MAX_QUEUE_FILE_BYTES as u64
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "transfer recovery manifest is not a bounded regular file",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if before.permissions().mode() & 0o077 != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "transfer recovery manifest is not private (expected mode 0600)",
            ));
        }
    }
    let mut file = std::fs::File::open(path)?;
    let opened = file.metadata()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if before.dev() != opened.dev() || before.ino() != opened.ino() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "transfer recovery manifest changed while opening",
            ));
        }
    }
    let mut payload = Vec::with_capacity(opened.len() as usize);
    file.by_ref()
        .take(MAX_QUEUE_FILE_BYTES.saturating_add(1) as u64)
        .read_to_end(&mut payload)?;
    if payload.len() > MAX_QUEUE_FILE_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "transfer recovery manifest exceeds its size limit",
        ));
    }
    let manifest: QueueManifest = serde_json::from_slice(&payload).map_err(|error| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid transfer recovery manifest: {error}"),
        )
    })?;
    validate_manifest(&manifest)?;
    Ok(Some(manifest))
}

fn validate_manifest(manifest: &QueueManifest) -> Result<(), std::io::Error> {
    if manifest.version != QUEUE_VERSION || manifest.jobs.len() > MAX_QUEUE_ENTRIES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "unsupported or oversized transfer recovery manifest",
        ));
    }
    let mut ids = HashSet::with_capacity(manifest.jobs.len());
    for transfer in &manifest.jobs {
        let job = &transfer.job;
        if !ids.insert(job.id.0)
            || job.id.0 > i32::MAX as usize
            || job.local_path.is_empty()
            || job.local_path.len() > MAX_LOCAL_PATH_BYTES
            || job.local_path.contains('\0')
            || job.remote_path.is_empty()
            || job.remote_path.len() > MAX_REMOTE_PATH_BYTES
            || job.remote_path.chars().any(char::is_control)
            || transfer.spec.host.is_empty()
            || transfer.spec.host.len() > 1_024
            || transfer.spec.user.len() > 1_024
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "transfer recovery manifest contains an invalid entry",
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{ConnectionId, Protocol, TransferDirection, TransferId};

    struct TestDir(PathBuf);
    impl TestDir {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!(
                "gmacftp-transfer-persistence-{}-{}",
                std::process::id(),
                rand::random::<u64>()
            ));
            std::fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for TestDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn transfer() -> PersistedTransfer {
        PersistedTransfer {
            job: TransferJob {
                id: TransferId(7),
                batch_id: 3,
                pause_on_error: true,
                priority: Default::default(),
                direction: TransferDirection::Download,
                local_path: "/tmp/destination.bin".into(),
                remote_path: "/site/source.bin".into(),
                bytes_total: Some(42),
                source_modified_unix_nanos: None,
                resume_token: 99,
            },
            spec: ConnectionSpec {
                id: ConnectionId(2),
                name: "server".into(),
                protocol: Protocol::Sftp,
                host: "example.test".into(),
                port: 22,
                user: "alice".into(),
                initial_path: "/site".into(),
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
            },
            state: PersistedState::Running,
        }
    }

    #[test]
    fn queue_roundtrip_is_private_versioned_and_credential_free() {
        let dir = TestDir::new();
        let path = dir.0.join("transfer-queue.json");
        let persistence = QueuePersistence::load_at(Some(path.clone()));
        let transfer = transfer();
        persistence.set(transfer.job.clone(), transfer.spec.clone(), transfer.state);
        persistence.flush_now().unwrap();

        let payload = std::fs::read_to_string(&path).unwrap();
        assert!(payload.contains("\"version\": 1"));
        assert!(!payload.contains("\"password\":"));
        assert!(!payload.contains("\"secret\":"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        let loaded = QueuePersistence::load_at(Some(path));
        let recovered = loaded.recovered();
        assert_eq!(recovered.len(), 1);
        assert_eq!(recovered[0].job.id.0, 7);
        assert!(matches!(recovered[0].state, PersistedState::Retryable));
    }

    #[cfg(unix)]
    #[test]
    fn queue_loader_rejects_symlinks_and_world_readable_manifests() {
        use std::os::unix::fs::PermissionsExt;
        let dir = TestDir::new();
        let target = dir.0.join("target.json");
        let link = dir.0.join("queue.json");
        std::fs::write(&target, b"{}").unwrap();
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(load_manifest(&link).is_err());

        std::fs::remove_file(&link).unwrap();
        let manifest = QueueManifest {
            version: QUEUE_VERSION,
            jobs: vec![transfer()],
        };
        std::fs::write(&link, serde_json::to_vec(&manifest).unwrap()).unwrap();
        std::fs::set_permissions(&link, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(load_manifest(&link).is_err());
    }
}
