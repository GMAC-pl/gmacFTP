//! gmacFTP — library core: domain model, credential store, and protocol clients
//! (FTP/FTPS via suppaftp, SFTP via russh). The Slint GUI in `src/main.rs` is a thin
//! shell over this library. Keeping the core a library enables `examples/` smoke tests
//! and `tests/` integration tests against local servers.

pub mod folder_sync;
pub mod model;
pub mod net;
pub mod store;
pub mod transfer;
pub mod updater;
