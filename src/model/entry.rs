//! A filesystem entry (remote or local) as the UI renders it.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteEntry {
    pub name: String,
    pub is_dir: bool,
    /// Size in bytes (0 for directories).
    pub size: u64,
    /// Modification time as a Unix timestamp (seconds), if reported.
    pub mtime: Option<i64>,
    /// Unix permission bits, when exposed by the server listing.
    pub permissions: Option<u32>,
    /// Owner name or numeric uid, when exposed by the server listing.
    pub owner: Option<String>,
    /// Group name or numeric gid, when exposed by the server listing.
    pub group: Option<String>,
}

impl RemoteEntry {
    /// Sort key: directories first, then case-insensitive by name (Warp-style listing).
    pub fn sort_key(&self) -> (bool, String) {
        (!self.is_dir, self.name.to_lowercase())
    }
}

/// Sort a list Warp-style (directories on top, then alphabetic, case-insensitive).
pub fn sort_entries(entries: &mut [RemoteEntry]) {
    entries.sort_by_key(|e| e.sort_key());
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dirs_first_then_alpha() {
        let mut e = vec![
            RemoteEntry {
                name: "zfile".into(),
                is_dir: false,
                size: 1,
                mtime: None,
                permissions: None,
                owner: None,
                group: None,
            },
            RemoteEntry {
                name: "adir".into(),
                is_dir: true,
                size: 0,
                mtime: None,
                permissions: None,
                owner: None,
                group: None,
            },
            RemoteEntry {
                name: "Bdir".into(),
                is_dir: true,
                size: 0,
                mtime: None,
                permissions: None,
                owner: None,
                group: None,
            },
            RemoteEntry {
                name: "afile".into(),
                is_dir: false,
                size: 1,
                mtime: None,
                permissions: None,
                owner: None,
                group: None,
            },
        ];
        sort_entries(&mut e);
        let names: Vec<_> = e.iter().map(|x| x.name.as_str()).collect();
        assert_eq!(names, vec!["adir", "Bdir", "afile", "zfile"]);
    }
}
