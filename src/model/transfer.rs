//! A queued file transfer (download or upload) and its progress.

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct TransferId(pub usize);

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransferDirection {
    Download, // remote -> local
    Upload,   // local -> remote
}

#[derive(
    Debug, Default, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum TransferPriority {
    Low,
    #[default]
    Normal,
    High,
}

impl TransferPriority {
    pub fn scheduling_rank(self) -> u8 {
        match self {
            Self::High => 0,
            Self::Normal => 1,
            Self::Low => 2,
        }
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct TransferJob {
    pub id: TransferId,
    /// Groups files started by one user action so an error can stop only that copy batch.
    pub batch_id: usize,
    /// Pause this batch on failure and ask whether to skip or stop. Disabled for a lone file.
    pub pause_on_error: bool,
    /// User-controlled scheduling priority. Older persisted queues migrate to Normal.
    #[serde(default)]
    pub priority: TransferPriority,
    pub direction: TransferDirection,
    pub local_path: String,
    pub remote_path: String,
    /// Total size in bytes, if known before the transfer starts.
    pub bytes_total: Option<u64>,
    /// Modification time captured when a local upload was queued. Together with `bytes_total`,
    /// this prevents appending a changed local file to an older remote upload fragment.
    #[serde(default)]
    pub source_modified_unix_nanos: Option<u64>,
    /// Random per-job token for a private resumable download or upload fragment. Zero disables
    /// resume and remains supported for manifests written by older versions.
    pub resume_token: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_transfer_jobs_migrate_to_normal_priority() {
        let job: TransferJob = serde_json::from_str(
            r#"{"id":1,"batch_id":2,"pause_on_error":false,"direction":"upload","local_path":"/tmp/a","remote_path":"/a","bytes_total":null,"source_modified_unix_nanos":null,"resume_token":3}"#,
        )
        .unwrap();
        assert_eq!(job.priority, TransferPriority::Normal);
    }
}
