//! Bounded Finder drag staging, cleanup, preview, and native window helpers.

use super::*;

#[cfg(unix)]
pub(super) fn drag_owner_process_is_running(pid: u32) -> bool {
    if pid == std::process::id() {
        return true;
    }
    std::process::Command::new("/bin/kill")
        .arg("-0")
        .arg(pid.to_string())
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(true)
}

#[cfg(not(unix))]
pub(super) fn drag_owner_process_is_running(_pid: u32) -> bool {
    true
}

/// Remove private staging directories left behind when a previous app process crashed. Live
/// processes are never touched, symlinks are never followed, and scanning is bounded so a crowded
/// system temp directory cannot delay starting a drag indefinitely.
pub(super) fn cleanup_abandoned_drag_roots_in(temp_dir: &Path) -> usize {
    let Ok(entries) = std::fs::read_dir(temp_dir) else {
        return 0;
    };
    let mut removed = 0usize;
    for entry in entries.take(512).flatten() {
        let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
            continue;
        };
        let Some(owner) = name
            .strip_prefix("gmacftp-drag-")
            .and_then(|tail| tail.split_once('-'))
            .and_then(|(pid, nonce)| (!nonce.is_empty()).then_some(pid))
            .and_then(|pid| pid.parse::<u32>().ok())
        else {
            continue;
        };
        if drag_owner_process_is_running(owner) {
            continue;
        }
        let path = entry.path();
        let is_real_directory = std::fs::symlink_metadata(&path)
            .map(|metadata| metadata.file_type().is_dir() && !metadata.file_type().is_symlink())
            .unwrap_or(false);
        if is_real_directory && std::fs::remove_dir_all(path).is_ok() {
            removed += 1;
        }
    }
    removed
}

pub(super) fn create_private_drag_root() -> Result<PathBuf, String> {
    let temp_dir = std::env::temp_dir();
    cleanup_abandoned_drag_roots_in(&temp_dir);
    for _ in 0..16 {
        let root = temp_dir.join(format!(
            "gmacftp-drag-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        ));
        let created = {
            let mut builder = std::fs::DirBuilder::new();
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            builder.create(&root)
        };
        match created {
            Ok(()) => {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    if let Err(e) =
                        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
                    {
                        let _ = std::fs::remove_dir_all(&root);
                        return Err(format!("could not secure drag staging directory: {e}"));
                    }
                }
                return Ok(root);
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(format!("could not create drag staging directory: {e}")),
        }
    }
    Err("could not allocate a unique drag staging directory".into())
}

/// Download one staging file with an enforced byte ceiling. Metadata from a remote listing is
/// only a hint, so the progress callback cancels on actual bytes as well. Both network backends
/// remove their `.part` file when cancellation is observed.
pub(super) fn download_drag_file_bounded(
    handle: &Handle,
    spec: &ConnectionSpec,
    password: &str,
    remote: &str,
    target: &Path,
    max_bytes: u64,
) -> Result<u64, String> {
    let result = match spec.protocol {
        Protocol::Ftp => {
            let (spec, password, remote, target) = (
                spec.clone(),
                password.to_string(),
                remote.to_string(),
                target.to_path_buf(),
            );
            let cancelled = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let progress_cancel = cancelled.clone();
            let operation_cancel = cancelled.clone();
            handle
                .block_on(async move {
                    tokio::task::spawn_blocking(move || {
                        net::ftp::download(
                            &spec,
                            &password,
                            &remote,
                            &target,
                            move |done| {
                                if done > max_bytes {
                                    progress_cancel
                                        .store(true, std::sync::atomic::Ordering::Relaxed);
                                }
                            },
                            Some(operation_cancel.as_ref()),
                        )
                    })
                    .await
                })
                .map_err(|error| error.to_string())?
        }
        Protocol::Sftp => {
            let cancelled = std::sync::atomic::AtomicBool::new(false);
            handle.block_on(net::sftp::download(
                spec,
                password,
                remote,
                target,
                |done| {
                    if done > max_bytes {
                        cancelled.store(true, std::sync::atomic::Ordering::Relaxed);
                    }
                },
                Some(&cancelled),
            ))
        }
    };
    match result {
        Ok(bytes) if bytes <= max_bytes => Ok(bytes),
        Ok(_) | Err(net::NetError::Cancelled) => Err(format!(
            "drag staging is limited to {}; use the transfer queue instead",
            fmt_size(MAX_DRAG_STAGING_BYTES)
        )),
        Err(error) => Err(error.to_string()),
    }
}

pub(super) fn validate_drag_budget(files: usize, bytes: u64) -> Result<(), String> {
    if files > MAX_DRAG_STAGING_FILES {
        return Err(format!(
            "drag staging is limited to {MAX_DRAG_STAGING_FILES} files; use the transfer queue instead"
        ));
    }
    if bytes > MAX_DRAG_STAGING_BYTES {
        return Err(format!(
            "drag staging is limited to {}; use the transfer queue instead",
            fmt_size(MAX_DRAG_STAGING_BYTES)
        ));
    }
    Ok(())
}

pub(super) fn materialize_remote_drag(
    handle: &Handle,
    spec: &ConnectionSpec,
    password: &str,
    remote: &str,
    name: &str,
    is_dir: bool,
    expected_size: Option<u64>,
) -> Result<RemoteDragStaging, String> {
    if !is_dir {
        validate_drag_budget(1, expected_size.unwrap_or(0))?;
    }
    let root = create_private_drag_root()?;
    let result = (|| -> Result<PathBuf, String> {
        // `name` came from the server listing. Never let an absolute path or `..` escape the
        // private drag staging directory before handing the materialised file to Finder.
        let target = remote_local_target(&root, name).map_err(|e| e.to_string())?;
        std::fs::create_dir_all(if is_dir { &target } else { &root }).map_err(|e| e.to_string())?;
        if !is_dir {
            let actual = download_drag_file_bounded(
                handle,
                spec,
                password,
                remote,
                &target,
                MAX_DRAG_STAGING_BYTES,
            )?;
            validate_drag_budget(1, actual)?;
            return Ok(target);
        }
        let files = handle
            .block_on(net::walk_remote(spec, password, remote))
            .map_err(|e| e.to_string())?;
        let advertised_bytes = files.iter().try_fold(0u64, |sum, (_, size)| {
            sum.checked_add(*size)
                .ok_or_else(|| "drag staging size overflow".to_string())
        })?;
        validate_drag_budget(files.len(), advertised_bytes)?;
        let mut actual_bytes = 0u64;
        for (remote_file, _) in files {
            let rel = remote_file
                .strip_prefix(remote)
                .unwrap_or(&remote_file)
                .trim_start_matches('/');
            // A recursive listing is server-controlled too. Re-apply the containment guard for
            // every entry, rather than relying on the top-level directory having been safe.
            let local = remote_local_target(&target, rel).map_err(|e| e.to_string())?;
            if let Some(parent) = local.parent() {
                std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            }
            let remaining = MAX_DRAG_STAGING_BYTES.saturating_sub(actual_bytes);
            let downloaded = download_drag_file_bounded(
                handle,
                spec,
                password,
                &remote_file,
                &local,
                remaining,
            )?;
            actual_bytes = actual_bytes
                .checked_add(downloaded)
                .ok_or_else(|| "drag staging size overflow".to_string())?;
            validate_drag_budget(0, actual_bytes)?;
        }
        Ok(target)
    })();
    match result {
        Ok(path) => Ok(RemoteDragStaging { root, path }),
        Err(e) => {
            let _ = std::fs::remove_dir_all(&root);
            Err(e)
        }
    }
}

pub(super) fn drag_preview_image() -> Option<drag::Image> {
    let exe = std::env::current_exe().ok()?;
    let bundled = exe.parent()?.parent()?.join("Resources/icon.icns");
    // Dev fallback only (the shipped .app always has the bundled icon). A RELATIVE path keeps the
    // developer's absolute CARGO_MANIFEST_DIR out of the compiled binary.
    let path = if bundled.exists() {
        bundled
    } else {
        PathBuf::from("assets/icon-preview.png")
    };
    path.exists().then_some(drag::Image::File(path))
}

#[cfg(target_os = "macos")]
pub(super) fn cursor_x_in_window(window: &slint::winit_030::winit::window::Window) -> Option<f64> {
    use objc2::{msg_send, runtime::AnyObject};
    use objc2_foundation::NSPoint;
    use raw_window_handle::{HasWindowHandle, RawWindowHandle};
    let RawWindowHandle::AppKit(appkit) = window.window_handle().ok()?.as_raw() else {
        return None;
    };
    unsafe {
        let view = &*appkit.ns_view.as_ptr().cast::<AnyObject>();
        let ns_window: *mut AnyObject = msg_send![view, window];
        let ns_window = ns_window.as_ref()?;
        let point: NSPoint = msg_send![ns_window, mouseLocationOutsideOfEventStream];
        Some(point.x)
    }
}

#[cfg(target_os = "macos")]
pub(super) fn configure_macos_window_shape(window: &slint::winit_030::winit::window::Window) {
    use objc2::{msg_send, runtime::AnyObject};
    use raw_window_handle::{HasWindowHandle, RawWindowHandle};

    let Ok(handle) = window.window_handle() else {
        return;
    };
    let RawWindowHandle::AppKit(appkit) = handle.as_raw() else {
        return;
    };

    window.set_transparent(true);

    unsafe {
        let view = &*appkit.ns_view.as_ptr().cast::<AnyObject>();
        let _: () = msg_send![view, setWantsLayer: true];
        let layer: *mut AnyObject = msg_send![view, layer];
        if let Some(layer) = layer.as_ref() {
            let _: () = msg_send![layer, setCornerRadius: 10.0_f64];
            let _: () = msg_send![layer, setMasksToBounds: true];
        }
    }

    window.request_redraw();
}
