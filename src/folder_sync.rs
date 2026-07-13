//! Pure planning for one-way folder synchronization.
//!
//! The planner never mutates either side and never schedules deletions. Callers provide safe,
//! relative file paths and metadata collected from the local and remote trees, then explicitly
//! apply the returned actions after showing a dry-run preview.

use std::collections::BTreeMap;

pub const DEFAULT_EXCLUSIONS: &str = ".git, .DS_Store, *.part, *.tmp";
pub const DEFAULT_MTIME_TOLERANCE_SECONDS: u64 = 2;
const MAX_RULES: usize = 128;
const MAX_RULE_BYTES: usize = 256;
const MAX_RULESET_BYTES: usize = 8 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncReason {
    Missing,
    DifferentSize,
    DifferentModificationTime,
    ModificationTimeUnavailable,
    DifferentChecksum,
    ChecksumUnavailable,
    TargetOnly,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncMode {
    #[default]
    OneWay,
    Mirror,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncComparison {
    SizeOnly,
    #[default]
    SizeAndModificationTime,
    Checksum,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SyncOptions {
    pub mode: SyncMode,
    pub comparison: SyncComparison,
    pub mtime_tolerance_seconds: u64,
    /// Adjustment applied before source timestamp comparison. A server known to report one hour
    /// ahead is normalized with `-3600` when it is the source.
    pub source_time_adjustment_seconds: i64,
    /// Equivalent normalization for the target side.
    pub target_time_adjustment_seconds: i64,
}

impl Default for SyncOptions {
    fn default() -> Self {
        Self {
            mode: SyncMode::OneWay,
            comparison: SyncComparison::SizeAndModificationTime,
            mtime_tolerance_seconds: DEFAULT_MTIME_TOLERANCE_SECONDS,
            source_time_adjustment_seconds: 0,
            target_time_adjustment_seconds: 0,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SyncFileMetadata {
    pub bytes: u64,
    pub modified: Option<i64>,
    pub sha256: Option<[u8; 32]>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncAction {
    pub relative_path: String,
    pub bytes: u64,
    pub reason: SyncReason,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SyncPreview {
    pub actions: Vec<SyncAction>,
    /// Target-only files scheduled for deletion only in explicit mirror mode.
    pub deletions: Vec<SyncAction>,
    pub unchanged: usize,
    /// Files found only on the target. They are deliberately retained: folder sync never deletes.
    pub target_only: usize,
    pub excluded: usize,
}

pub fn parse_exclusions(input: &str) -> Result<Vec<String>, String> {
    if input.len() > MAX_RULESET_BYTES {
        return Err(format!("exclude rules exceed {MAX_RULESET_BYTES} bytes"));
    }
    let mut rules = Vec::new();
    for raw in input.split([',', ';', '\n', '\r']) {
        let rule = raw.trim().trim_start_matches("./").trim_end_matches('/');
        if rule.is_empty() {
            continue;
        }
        if rule.len() > MAX_RULE_BYTES
            || rule.starts_with('/')
            || rule.split('/').any(|component| component == "..")
            || rule.chars().any(char::is_control)
        {
            return Err(format!("invalid exclude rule: {raw:?}"));
        }
        if !rules.iter().any(|existing| existing == rule) {
            rules.push(rule.to_string());
        }
        if rules.len() > MAX_RULES {
            return Err(format!("at most {MAX_RULES} exclude rules are allowed"));
        }
    }
    Ok(rules)
}

/// Match either a complete relative path (rules containing `/`) or any path component. `*` and
/// `?` have their conventional single-component meanings. A plain `.git` therefore excludes the
/// directory and everything below it without requiring a recursive glob.
pub fn is_excluded(relative_path: &str, rules: &[String]) -> bool {
    let path = relative_path.trim_matches('/');
    if path.is_empty() {
        return false;
    }
    rules.iter().any(|rule| {
        if rule.contains('/') {
            glob_matches(rule.as_bytes(), path.as_bytes())
                || path
                    .strip_prefix(rule)
                    .is_some_and(|suffix| suffix.starts_with('/'))
        } else {
            path.split('/')
                .any(|component| glob_matches(rule.as_bytes(), component.as_bytes()))
        }
    })
}

/// Linear wildcard matcher with bounded backtracking. Rules are already capped at 256 bytes.
fn glob_matches(pattern: &[u8], value: &[u8]) -> bool {
    let (mut p, mut v) = (0usize, 0usize);
    let (mut star, mut star_value) = (None, 0usize);
    while v < value.len() {
        if p < pattern.len() && (pattern[p] == b'?' || pattern[p] == value[v]) {
            p += 1;
            v += 1;
        } else if p < pattern.len() && pattern[p] == b'*' {
            star = Some(p);
            p += 1;
            star_value = v;
        } else if let Some(star_index) = star {
            p = star_index + 1;
            star_value += 1;
            v = star_value;
        } else {
            return false;
        }
    }
    while p < pattern.len() && pattern[p] == b'*' {
        p += 1;
    }
    p == pattern.len()
}

pub fn build_preview(
    source: &BTreeMap<String, SyncFileMetadata>,
    target: &BTreeMap<String, SyncFileMetadata>,
    rules: &[String],
    options: SyncOptions,
) -> SyncPreview {
    let mut preview = SyncPreview::default();
    for (path, source_metadata) in source {
        if is_excluded(path, rules) {
            preview.excluded += 1;
            continue;
        }
        match target.get(path) {
            None => preview.actions.push(SyncAction {
                relative_path: path.clone(),
                bytes: source_metadata.bytes,
                reason: SyncReason::Missing,
            }),
            Some(target_metadata) if target_metadata.bytes != source_metadata.bytes => {
                preview.actions.push(SyncAction {
                    relative_path: path.clone(),
                    bytes: source_metadata.bytes,
                    reason: SyncReason::DifferentSize,
                })
            }
            Some(target_metadata) => {
                let reason = comparison_reason(source_metadata, target_metadata, options);
                if let Some(reason) = reason {
                    preview.actions.push(SyncAction {
                        relative_path: path.clone(),
                        bytes: source_metadata.bytes,
                        reason,
                    });
                } else {
                    preview.unchanged += 1;
                }
            }
        }
    }
    for path in target.keys() {
        if is_excluded(path, rules) {
            preview.excluded += 1;
        } else if !source.contains_key(path) {
            preview.target_only += 1;
            if options.mode == SyncMode::Mirror {
                let metadata = target
                    .get(path)
                    .expect("path came from the target map iterator");
                preview.deletions.push(SyncAction {
                    relative_path: path.clone(),
                    bytes: metadata.bytes,
                    reason: SyncReason::TargetOnly,
                });
            }
        }
    }
    preview
}

fn comparison_reason(
    source: &SyncFileMetadata,
    target: &SyncFileMetadata,
    options: SyncOptions,
) -> Option<SyncReason> {
    match options.comparison {
        SyncComparison::SizeOnly => None,
        SyncComparison::SizeAndModificationTime => match (source.modified, target.modified) {
            (Some(source), Some(target)) => {
                let source = source.saturating_add(options.source_time_adjustment_seconds);
                let target = target.saturating_add(options.target_time_adjustment_seconds);
                // One-way sync treats the selected source as authoritative. A freshly copied
                // target commonly receives a newer filesystem timestamp when the protocol cannot
                // preserve mtimes; comparing absolute difference would therefore copy it forever.
                // Copy only when the source is materially newer. Checksum mode remains available
                // for archived/restored files whose timestamps intentionally move backwards.
                (source > target && source.abs_diff(target) > options.mtime_tolerance_seconds)
                    .then_some(SyncReason::DifferentModificationTime)
            }
            _ => Some(SyncReason::ModificationTimeUnavailable),
        },
        SyncComparison::Checksum => match (source.sha256, target.sha256) {
            (Some(source), Some(target)) if source == target => None,
            (Some(_), Some(_)) => Some(SyncReason::DifferentChecksum),
            _ => Some(SyncReason::ChecksumUnavailable),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exclusions_prune_components_and_support_wildcards() {
        let rules = parse_exclusions(".git, *.part, cache/**").unwrap();
        assert!(is_excluded(".git/objects/aa", &rules));
        assert!(is_excluded("nested/file.part", &rules));
        assert!(is_excluded("cache/a/b", &rules));
        assert!(!is_excluded("src/git.rs", &rules));
    }

    #[test]
    fn dry_run_is_one_way_and_never_deletes_target_only_files() {
        let source = BTreeMap::from([
            ("same.txt".into(), metadata(10, 100)),
            ("changed.txt".into(), metadata(20, 100)),
            ("new.txt".into(), metadata(30, 100)),
            (".git/config".into(), metadata(40, 100)),
        ]);
        let target = BTreeMap::from([
            ("same.txt".into(), metadata(10, 100)),
            ("changed.txt".into(), metadata(19, 100)),
            ("target-only.txt".into(), metadata(50, 100)),
        ]);
        let rules = parse_exclusions(DEFAULT_EXCLUSIONS).unwrap();
        let preview = build_preview(&source, &target, &rules, SyncOptions::default());

        assert_eq!(preview.unchanged, 1);
        assert_eq!(preview.target_only, 1);
        assert!(preview.deletions.is_empty());
        assert_eq!(preview.excluded, 1);
        assert_eq!(
            preview.actions,
            vec![
                SyncAction {
                    relative_path: "changed.txt".into(),
                    bytes: 20,
                    reason: SyncReason::DifferentSize,
                },
                SyncAction {
                    relative_path: "new.txt".into(),
                    bytes: 30,
                    reason: SyncReason::Missing,
                }
            ]
        );
    }

    #[test]
    fn mirror_mode_lists_target_only_files_as_explicit_deletions() {
        let source = BTreeMap::from([("same.txt".into(), metadata(10, 100))]);
        let target = BTreeMap::from([
            ("same.txt".into(), metadata(10, 100)),
            ("old.txt".into(), metadata(25, 90)),
            ("cache/ignored.tmp".into(), metadata(4, 80)),
        ]);
        let preview = build_preview(
            &source,
            &target,
            &parse_exclusions("*.tmp").unwrap(),
            SyncOptions {
                mode: SyncMode::Mirror,
                ..SyncOptions::default()
            },
        );
        assert_eq!(preview.target_only, 1);
        assert_eq!(preview.deletions.len(), 1);
        assert_eq!(preview.deletions[0].relative_path, "old.txt");
        assert_eq!(preview.deletions[0].reason, SyncReason::TargetOnly);
    }

    fn metadata(bytes: u64, modified: i64) -> SyncFileMetadata {
        SyncFileMetadata {
            bytes,
            modified: Some(modified),
            sha256: None,
        }
    }

    #[test]
    fn same_size_timestamp_change_is_not_silently_skipped() {
        let source = BTreeMap::from([("changed.txt".into(), metadata(10, 200))]);
        let target = BTreeMap::from([("changed.txt".into(), metadata(10, 100))]);
        let preview = build_preview(&source, &target, &[], SyncOptions::default());
        assert_eq!(preview.actions.len(), 1);
        assert_eq!(
            preview.actions[0].reason,
            SyncReason::DifferentModificationTime
        );
    }

    #[test]
    fn timestamp_tolerance_and_clock_adjustment_are_applied() {
        let source = BTreeMap::from([("same.txt".into(), metadata(10, 100))]);
        let target = BTreeMap::from([("same.txt".into(), metadata(10, 3_701))]);
        let preview = build_preview(
            &source,
            &target,
            &[],
            SyncOptions {
                target_time_adjustment_seconds: -3_600,
                ..SyncOptions::default()
            },
        );
        assert_eq!(preview.unchanged, 1);
    }

    #[test]
    fn newer_target_does_not_create_an_endless_one_way_sync_loop() {
        let source = BTreeMap::from([("same.txt".into(), metadata(10, 100))]);
        let target = BTreeMap::from([("same.txt".into(), metadata(10, 200))]);
        let preview = build_preview(&source, &target, &[], SyncOptions::default());
        assert_eq!(preview.unchanged, 1);
        assert!(preview.actions.is_empty());
    }

    #[test]
    fn unavailable_timestamp_and_checksum_fail_safe_to_copy() {
        let source = BTreeMap::from([(
            "uncertain.txt".into(),
            SyncFileMetadata {
                bytes: 10,
                ..SyncFileMetadata::default()
            },
        )]);
        let target = source.clone();
        let timestamp = build_preview(&source, &target, &[], SyncOptions::default());
        assert_eq!(
            timestamp.actions[0].reason,
            SyncReason::ModificationTimeUnavailable
        );
        let checksum = build_preview(
            &source,
            &target,
            &[],
            SyncOptions {
                comparison: SyncComparison::Checksum,
                ..SyncOptions::default()
            },
        );
        assert_eq!(checksum.actions[0].reason, SyncReason::ChecksumUnavailable);
    }

    #[test]
    fn unsafe_or_unbounded_rules_are_rejected() {
        assert!(parse_exclusions("../secret").is_err());
        assert!(parse_exclusions("ok, /absolute").is_err());
        assert!(parse_exclusions(&"x".repeat(MAX_RULE_BYTES + 1)).is_err());
    }
}
