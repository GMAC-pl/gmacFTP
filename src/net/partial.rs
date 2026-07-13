//! Secure local staging files for resumable downloads.

use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};

/// Stable for one persisted queued job, including across application restarts. The random token
/// makes the staging name unguessable; `expected_total` prevents a corrupt/foreign oversized
/// fragment from being used.
#[derive(Debug, Clone, Copy)]
pub struct DownloadResume {
    pub token: u64,
    pub expected_total: Option<u64>,
}

pub(crate) struct DownloadPart {
    pub path: PathBuf,
    pub file: File,
    pub offset: u64,
    pub keep_on_error: bool,
}

pub fn resumable_part_path(destination: &Path, token: u64) -> PathBuf {
    let parent = destination.parent().unwrap_or_else(|| Path::new("."));
    let mut name = std::ffi::OsString::from(".");
    name.push(
        destination
            .file_name()
            .unwrap_or_else(|| std::ffi::OsStr::new("download")),
    );
    name.push(format!(".gmacftp-{token:016x}.part"));
    parent.join(name)
}

fn unique_part(destination: &Path) -> Result<(PathBuf, File), std::io::Error> {
    for _ in 0..16 {
        let path = resumable_part_path(destination, rand::random::<u64>());
        match crate::store::vault::create_exclusive(&path) {
            Ok(file) => return Ok((path, file)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error),
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        "could not allocate a unique download temp file",
    ))
}

fn open_existing_regular(path: &Path) -> Result<File, std::io::Error> {
    let before = std::fs::symlink_metadata(path)?;
    if !before.file_type().is_file() || before.file_type().is_symlink() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "download fragment is not a regular file",
        ));
    }

    let mut options = OpenOptions::new();
    options.read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let file = options.open(path)?;
    let opened = file.metadata()?;
    if !opened.file_type().is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "download fragment changed type while opening",
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if before.dev() != opened.dev()
            || before.ino() != opened.ino()
            || opened.nlink() != 1
            || opened.mode() & 0o077 != 0
        {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "download fragment failed ownership/link safety checks",
            ));
        }
    }
    Ok(file)
}

pub(crate) fn open_download_part(
    destination: &Path,
    resume: Option<DownloadResume>,
) -> Result<DownloadPart, std::io::Error> {
    let Some(resume) = resume else {
        let (path, file) = unique_part(destination)?;
        return Ok(DownloadPart {
            path,
            file,
            offset: 0,
            keep_on_error: false,
        });
    };

    let path = resumable_part_path(destination, resume.token);
    match crate::store::vault::create_exclusive(&path) {
        Ok(file) => Ok(DownloadPart {
            path,
            file,
            offset: 0,
            keep_on_error: true,
        }),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let file = open_existing_regular(&path)?;
            let offset = file.metadata()?.len();
            if resume.expected_total.is_some_and(|total| offset > total) {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "download fragment is larger than the expected remote file",
                ));
            }
            Ok(DownloadPart {
                path,
                file,
                offset,
                keep_on_error: true,
            })
        }
        Err(error) => Err(error),
    }
}

pub(crate) fn discard_download_fragment(destination: &Path, token: u64) {
    if token == 0 {
        return;
    }
    let path = resumable_part_path(destination, token);
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => tracing::debug!(%error, "could not remove resumable download fragment"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch() -> PathBuf {
        std::env::temp_dir().join(format!(
            "gmacftp-partial-test-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ))
    }

    #[test]
    fn resumable_fragment_reopens_at_existing_length() {
        let dir = scratch();
        std::fs::create_dir_all(&dir).unwrap();
        let destination = dir.join("report.bin");
        let resume = DownloadResume {
            token: 42,
            expected_total: Some(10),
        };
        let first = open_download_part(&destination, Some(resume)).unwrap();
        std::fs::write(&first.path, b"1234").unwrap();
        drop(first);

        let reopened = open_download_part(&destination, Some(resume)).unwrap();
        assert_eq!(reopened.offset, 4);
        assert!(reopened.keep_on_error);
        assert!(!reopened
            .path
            .file_name()
            .unwrap()
            .to_string_lossy()
            .contains(&format!("-{}-", std::process::id())));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[cfg(unix)]
    #[test]
    fn resumable_fragment_rejects_symlinks_and_hardlinks() {
        let dir = scratch();
        std::fs::create_dir_all(&dir).unwrap();
        let destination = dir.join("report.bin");
        let resume = DownloadResume {
            token: 7,
            expected_total: None,
        };
        let path = resumable_part_path(&destination, resume.token);
        let target = dir.join("target");
        std::fs::write(&target, b"secret").unwrap();
        std::os::unix::fs::symlink(&target, &path).unwrap();
        assert!(open_download_part(&destination, Some(resume)).is_err());

        std::fs::remove_file(&path).unwrap();
        std::fs::hard_link(&target, &path).unwrap();
        assert!(open_download_part(&destination, Some(resume)).is_err());
        let _ = std::fs::remove_dir_all(dir);
    }
}
