//! Pure planning for one-way folder synchronization.
//!
//! The planner never mutates either side and never schedules deletions. Callers provide safe,
//! relative file paths and sizes collected from the local and remote trees, then explicitly apply
//! the returned actions after showing a dry-run preview.

use std::collections::BTreeMap;

pub const DEFAULT_EXCLUSIONS: &str = ".git, .DS_Store, *.part, *.tmp";
const MAX_RULES: usize = 128;
const MAX_RULE_BYTES: usize = 256;
const MAX_RULESET_BYTES: usize = 8 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncReason {
    Missing,
    DifferentSize,
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
    source: &BTreeMap<String, u64>,
    target: &BTreeMap<String, u64>,
    rules: &[String],
) -> SyncPreview {
    let mut preview = SyncPreview::default();
    for (path, bytes) in source {
        if is_excluded(path, rules) {
            preview.excluded += 1;
            continue;
        }
        match target.get(path) {
            None => preview.actions.push(SyncAction {
                relative_path: path.clone(),
                bytes: *bytes,
                reason: SyncReason::Missing,
            }),
            Some(target_bytes) if target_bytes != bytes => preview.actions.push(SyncAction {
                relative_path: path.clone(),
                bytes: *bytes,
                reason: SyncReason::DifferentSize,
            }),
            Some(_) => preview.unchanged += 1,
        }
    }
    for path in target.keys() {
        if is_excluded(path, rules) {
            preview.excluded += 1;
        } else if !source.contains_key(path) {
            preview.target_only += 1;
        }
    }
    preview
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
            ("same.txt".into(), 10),
            ("changed.txt".into(), 20),
            ("new.txt".into(), 30),
            (".git/config".into(), 40),
        ]);
        let target = BTreeMap::from([
            ("same.txt".into(), 10),
            ("changed.txt".into(), 19),
            ("target-only.txt".into(), 50),
        ]);
        let rules = parse_exclusions(DEFAULT_EXCLUSIONS).unwrap();
        let preview = build_preview(&source, &target, &rules);

        assert_eq!(preview.unchanged, 1);
        assert_eq!(preview.target_only, 1);
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
    fn unsafe_or_unbounded_rules_are_rejected() {
        assert!(parse_exclusions("../secret").is_err());
        assert!(parse_exclusions("ok, /absolute").is_err());
        assert!(parse_exclusions(&"x".repeat(MAX_RULE_BYTES + 1)).is_err());
    }
}
