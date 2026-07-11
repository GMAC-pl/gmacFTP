//! A queued file transfer (download or upload) and its progress.

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct TransferId(pub usize);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferDirection {
    Download, // remote -> local
    Upload,   // local -> remote
}

#[derive(Debug, Clone)]
pub struct TransferJob {
    pub id: TransferId,
    /// Groups files started by one user action so an error can stop only that copy batch.
    pub batch_id: usize,
    /// Pause this batch on failure and ask whether to skip or stop. Disabled for a lone file.
    pub pause_on_error: bool,
    pub direction: TransferDirection,
    pub local_path: String,
    pub remote_path: String,
    /// Total size in bytes, if known before the transfer starts.
    pub bytes_total: Option<u64>,
}
