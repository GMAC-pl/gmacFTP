//! Pure domain types — no I/O, no UI, no async. The foundation both the net/transfer
//! layers and the Slint UI build on. Deliberately dependency-light and easy to unit-test.

pub mod connection;
pub mod entry;
pub mod protocol;
pub mod transfer;

pub use connection::{ConnectionId, ConnectionSpec, SftpAuth};
pub use entry::{sort_entries, RemoteEntry};
pub use protocol::Protocol;
pub use transfer::{TransferDirection, TransferId, TransferJob};
