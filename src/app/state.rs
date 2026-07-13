//! Validated values crossing the string/integer boundary between Slint and Rust.

use gmacftp::model::TransferDirection;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(super) enum PaneId {
    #[default]
    Left,
    Right,
}

impl PaneId {
    pub(super) const fn index(self) -> usize {
        match self {
            Self::Left => 0,
            Self::Right => 1,
        }
    }

    pub(super) const fn other(self) -> Self {
        match self {
            Self::Left => Self::Right,
            Self::Right => Self::Left,
        }
    }
}

impl TryFrom<&str> for PaneId {
    type Error = &'static str;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "local" => Ok(Self::Left),
            "remote" => Ok(Self::Right),
            _ => Err("unknown pane identifier"),
        }
    }
}

impl TryFrom<i32> for PaneId {
    type Error = &'static str;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Left),
            1 => Ok(Self::Right),
            _ => Err("pane index is out of range"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum FileOperationMode {
    Rename,
    CreateDirectory,
    ChangePermissions,
}

impl FileOperationMode {
    pub(super) const fn needs_source_name(self) -> bool {
        matches!(self, Self::Rename | Self::ChangePermissions)
    }

    pub(super) const fn needs_destination_name(self) -> bool {
        matches!(self, Self::Rename | Self::CreateDirectory)
    }
}

impl TryFrom<&str> for FileOperationMode {
    type Error = &'static str;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "rename" => Ok(Self::Rename),
            "mkdir" => Ok(Self::CreateDirectory),
            "chmod" => Ok(Self::ChangePermissions),
            _ => Err("unknown file operation"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SortKey {
    Name,
    Date,
    Size,
    Owner,
    Group,
    Permissions,
}

impl SortKey {
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::Name => "name",
            Self::Date => "date",
            Self::Size => "size",
            Self::Owner => "owner",
            Self::Group => "group",
            Self::Permissions => "permissions",
        }
    }
}

impl TryFrom<&str> for SortKey {
    type Error = &'static str;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "name" => Ok(Self::Name),
            "date" => Ok(Self::Date),
            "size" => Ok(Self::Size),
            "owner" => Ok(Self::Owner),
            "group" => Ok(Self::Group),
            "permissions" => Ok(Self::Permissions),
            _ => Err("unknown sort key"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SortDirection {
    Ascending,
    Descending,
}

impl SortDirection {
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::Ascending => "asc",
            Self::Descending => "desc",
        }
    }

    pub(super) const fn reversed(self) -> Self {
        match self {
            Self::Ascending => Self::Descending,
            Self::Descending => Self::Ascending,
        }
    }
}

impl TryFrom<&str> for SortDirection {
    type Error = &'static str;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "asc" => Ok(Self::Ascending),
            "desc" => Ok(Self::Descending),
            _ => Err("unknown sort direction"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SyncDirection {
    Upload,
    Download,
}

impl From<SyncDirection> for TransferDirection {
    fn from(value: SyncDirection) -> Self {
        match value {
            SyncDirection::Upload => Self::Upload,
            SyncDirection::Download => Self::Download,
        }
    }
}

impl TryFrom<&str> for SyncDirection {
    type Error = &'static str;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "upload" => Ok(Self::Upload),
            "download" => Ok(Self::Download),
            _ => Err("unknown synchronization direction"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum OverwriteDecision {
    Skip,
    Overwrite,
    KeepBoth,
}

impl TryFrom<i32> for OverwriteDecision {
    type Error = &'static str;

    fn try_from(value: i32) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(Self::Skip),
            1 => Ok(Self::Overwrite),
            2 => Ok(Self::KeepBoth),
            _ => Err("unknown overwrite decision"),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum TransferRowState {
    Active,
    Queued,
    Paused,
    Done,
    Failed,
    Cancelled,
    Recovered,
}

impl TryFrom<&str> for TransferRowState {
    type Error = &'static str;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        match value {
            "active" => Ok(Self::Active),
            "queued" => Ok(Self::Queued),
            "paused" => Ok(Self::Paused),
            "done" => Ok(Self::Done),
            "failed" => Ok(Self::Failed),
            "cancelled" => Ok(Self::Cancelled),
            "recovered" => Ok(Self::Recovered),
            _ => Err("unknown transfer-row state"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ui_state_parsers_reject_unknown_values() {
        assert_eq!(PaneId::try_from("local").unwrap(), PaneId::Left);
        assert_eq!(PaneId::try_from("remote").unwrap().other(), PaneId::Left);
        assert!(PaneId::try_from("server").is_err());
        assert!(FileOperationMode::try_from("delete").is_err());
        assert!(SortKey::try_from("path").is_err());
        assert!(SortDirection::try_from("up").is_err());
        assert!(SyncDirection::try_from("both").is_err());
        assert!(OverwriteDecision::try_from(99).is_err());
        assert!(TransferRowState::try_from("waiting-ish").is_err());
    }
}
