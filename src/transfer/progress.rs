//! Live transfer progress events streamed from the worker to the UI bridge.

use crate::model::TransferId;

#[derive(Debug, Clone)]
pub enum TransferState {
    Active,
    Done,
    Failed(String),
    /// Never started because the user stopped this batch after an earlier file failed.
    Skipped(String),
}

#[derive(Debug, Clone)]
pub struct TransferUpdate {
    pub id: TransferId,
    pub batch_id: usize,
    pub requires_decision: bool,
    pub bytes_done: u64,
    pub bytes_total: Option<u64>,
    pub state: TransferState,
}
