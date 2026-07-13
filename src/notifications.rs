//! Privacy-preserving local notifications for completed and failed transfers.
//!
//! Authorization is requested only after the user explicitly enables notifications in
//! Settings. Notification bodies intentionally contain no endpoint, account, path or file name.

#[cfg(target_os = "macos")]
mod platform {
    use std::cell::RefCell;
    use std::sync::atomic::{AtomicU64, Ordering};

    use block2::RcBlock;
    use objc2::rc::{autoreleasepool, Retained};
    use objc2::runtime::Bool;
    use objc2::{MainThreadMarker, MainThreadOnly};
    use objc2_app_kit::{
        NSApplication, NSImageView, NSProgressIndicator, NSProgressIndicatorStyle, NSView,
    };
    use objc2_foundation::{NSError, NSPoint, NSRect, NSSize, NSString};
    use objc2_user_notifications::{
        UNAuthorizationOptions, UNMutableNotificationContent, UNNotificationRequest,
        UNUserNotificationCenter,
    };

    static NEXT_NOTIFICATION_ID: AtomicU64 = AtomicU64::new(1);

    struct DockProgress {
        _content: Retained<NSView>,
        indicator: Retained<NSProgressIndicator>,
    }

    thread_local! {
        /// AppKit views are main-thread-only. Keeping them in thread-local storage both encodes
        /// that constraint and avoids rebuilding the Dock tile for every transfer chunk.
        static DOCK_PROGRESS: RefCell<Option<DockProgress>> = const { RefCell::new(None) };
    }

    /// Ask macOS for alert permission. Call this only in response to an explicit user action.
    pub fn request_authorization() {
        autoreleasepool(|_| {
            let center = UNUserNotificationCenter::currentNotificationCenter();
            let completion = RcBlock::new(|granted: Bool, error: *mut NSError| {
                if granted.as_bool() {
                    tracing::info!(target: "gmacftp", "local notifications authorized");
                } else if error.is_null() {
                    tracing::info!(target: "gmacftp", "local notifications declined");
                } else {
                    // NSError descriptions can contain environmental details. Log only the
                    // category here; the setting remains reversible regardless of the outcome.
                    tracing::warn!(target: "gmacftp", "local notification authorization failed");
                }
            });
            center.requestAuthorizationWithOptions_completionHandler(
                UNAuthorizationOptions::Alert | UNAuthorizationOptions::Sound,
                &completion,
            );
        });
    }

    /// Queue a local notification whose caller-provided text is already privacy-safe.
    pub fn send(title: &str, body: &str) {
        autoreleasepool(|_| {
            let content = UNMutableNotificationContent::new();
            content.setTitle(&NSString::from_str(title));
            content.setBody(&NSString::from_str(body));

            let sequence = NEXT_NOTIFICATION_ID.fetch_add(1, Ordering::Relaxed);
            let identifier = NSString::from_str(&format!(
                "gmacftp.transfer.{}.{}",
                std::process::id(),
                sequence
            ));
            let request = UNNotificationRequest::requestWithIdentifier_content_trigger(
                &identifier,
                &content,
                None,
            );
            UNUserNotificationCenter::currentNotificationCenter()
                .addNotificationRequest_withCompletionHandler(&request, None);
        });
    }

    /// Reflect transfer activity in the Dock without exposing filenames, paths or endpoints.
    /// `progress` is the aggregate fraction of currently active transfers.
    pub fn update_dock(pending: usize, progress: Option<f64>) {
        autoreleasepool(|_| {
            let Some(mtm) = MainThreadMarker::new() else {
                return;
            };
            let application = NSApplication::sharedApplication(mtm);
            let tile = application.dockTile();
            if pending == 0 {
                tile.setBadgeLabel(None);
                tile.setContentView(None);
                tile.display();
                DOCK_PROGRESS.with(|state| *state.borrow_mut() = None);
                return;
            }

            let badge = NSString::from_str(&pending.min(999).to_string());
            tile.setBadgeLabel(Some(&badge));
            DOCK_PROGRESS.with(|state| {
                let mut state = state.borrow_mut();
                if state.is_none() {
                    let size = tile.size();
                    let frame = NSRect::new(NSPoint::new(0.0, 0.0), size);
                    let content = NSView::initWithFrame(NSView::alloc(mtm), frame);
                    if let Some(icon) = application.applicationIconImage() {
                        let image = NSImageView::imageViewWithImage(&icon, mtm);
                        image.setFrame(frame);
                        content.addSubview(&image);
                    }
                    let indicator_frame = NSRect::new(
                        NSPoint::new(8.0, 5.0),
                        NSSize::new((size.width - 16.0).max(1.0), 14.0),
                    );
                    let indicator = NSProgressIndicator::initWithFrame(
                        NSProgressIndicator::alloc(mtm),
                        indicator_frame,
                    );
                    indicator.setStyle(NSProgressIndicatorStyle::Bar);
                    indicator.setIndeterminate(false);
                    indicator.setMinValue(0.0);
                    indicator.setMaxValue(1.0);
                    indicator.setDisplayedWhenStopped(true);
                    content.addSubview(&indicator);
                    tile.setContentView(Some(&content));
                    *state = Some(DockProgress {
                        _content: content,
                        indicator,
                    });
                }
                if let Some(state) = state.as_ref() {
                    state
                        .indicator
                        .setDoubleValue(progress.unwrap_or(0.0).clamp(0.0, 1.0));
                }
            });
            tile.display();
        });
    }
}

#[cfg(not(target_os = "macos"))]
mod platform {
    pub fn request_authorization() {}
    pub fn send(_title: &str, _body: &str) {}
    pub fn update_dock(_pending: usize, _progress: Option<f64>) {}
}

pub use platform::{request_authorization, send, update_dock};
