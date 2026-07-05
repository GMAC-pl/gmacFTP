//! Native macOS menu bar (the system menu at the top of the screen, next to the   logo),
//! like every native Mac app has. Standard items (Quit/Hide/Close/Minimize/Edit ops/About)
//! use nil-target + system selectors handled by the responder chain / NSApplication. The
//! custom actions (iCloud Sync toggle, New Connection, Connection Manager, Help, Pull from
//! iCloud) dispatch to Rust through a `GmacMenuTarget` object that re-enters the Slint event
//! loop.
//!
//! This file lives in the binary crate (next to `main.rs`) because it references the
//! generated `App` type; `store::cloud` comes from the library.
//!
//! Timing: Slint's winit backend installs its own (minimal/default) main menu when the event
//! loop launches inside `ui.run()`. Installing ours *before* `run()` therefore gets wiped. We
//! install immediately AND re-assert the full menu shortly after the event loop has started
//! (via `invoke_from_event_loop` from a delayed background thread), which reliably wins the
//! race. `install_once` is idempotent so the repeated calls are safe.

#[cfg(target_os = "macos")]
mod imp {
    use std::ptr;
    use std::sync::atomic::{AtomicPtr, Ordering};
    use std::sync::{Mutex, OnceLock};

    use objc2::rc::Retained;
    use objc2::runtime::{AnyObject, NSObject, Sel};
    use objc2::{define_class, msg_send, sel, ClassType, MainThreadMarker};
    use objc2_app_kit::{
        NSApplication, NSApplicationActivationPolicy, NSEventModifierFlags, NSMenu, NSMenuItem,
    };
    use objc2_foundation::NSString;

    use slint::Weak;

    use crate::App;
    use gmacftp::store::cloud;

    // The Slint UI handle. The sync menu item + the target object are held by raw pointers
    // (NSMenuItem / NSObject aren't `Send`, so they can't live behind a `static` `Mutex`); they
    // are only ever touched on the main thread, where menu actions fire.
    static APP: OnceLock<Mutex<Option<Weak<App>>>> = OnceLock::new();
    static SYNC_ITEM_PTR: AtomicPtr<NSMenuItem> = AtomicPtr::new(ptr::null_mut());
    static TARGET_PTR: AtomicPtr<AnyObject> = AtomicPtr::new(ptr::null_mut());

    fn app_weak() -> Option<Weak<App>> {
        APP.get()?.lock().ok()?.clone()
    }

    /// Run a closure on the Slint event loop with a live `App` handle.
    fn on_ui<F: FnOnce(&App) + Send + 'static>(f: F) {
        let Some(weak) = app_weak() else { return };
        let _ = slint::invoke_from_event_loop(move || {
            if let Some(ui) = weak.upgrade() {
                f(&ui);
            }
        });
    }

    fn sync_title() -> String {
        // Show the CURRENT state + what clicking does, so it's unambiguous.
        if cloud::enabled() {
            "iCloud Sync: ON  (click to turn off)".to_string()
        } else {
            "iCloud Sync: OFF  (click to turn on)".to_string()
        }
    }

    pub fn refresh_sync_title() {
        let ptr_item = SYNC_ITEM_PTR.load(Ordering::SeqCst);
        if !ptr_item.is_null() {
            // SAFETY: the pointer is valid for the app lifetime (set in install_once, only
            // accessed from the main thread where menu actions fire).
            unsafe { (&*ptr_item).setTitle(&NSString::from_str(&sync_title())) };
        }
    }

    // ── the ObjC class that owns the custom menu actions ──

    define_class!(
        #[unsafe(super(NSObject))]
        #[name = "GmacMenuTarget"]
        struct GmacMenuTarget;

        impl GmacMenuTarget {
            #[unsafe(method(toggleSync:))]
            fn toggle_sync(&self, _sender: Option<&AnyObject>) {
                let enabling = !cloud::enabled();
                // First-time enable: prompt for a sync passphrase before enabling (the
                // passphrase wraps the master key so the synced vault decrypts cross-device).
                // Re-enabling / disabling toggles directly.
                if enabling && !gmacftp::store::settings::load().sync_passphrase_set {
                    on_ui(|ui| {
                        ui.set_passphrase_mode("set".into());
                        ui.set_passphrase_value("".into());
                        ui.set_passphrase_confirm("".into());
                        ui.set_passphrase_open(true);
                    });
                    return;
                }
                cloud::set_sync_enabled(enabling);
                refresh_sync_title();
                tracing::info!(target: "gmacftp::menu", "iCloud sync toggled from menu bar");
            }

            #[unsafe(method(newConnection:))]
            fn new_connection(&self, _sender: Option<&AnyObject>) {
                on_ui(|ui| ui.invoke_new_connection());
            }

            #[unsafe(method(openManager:))]
            fn open_manager(&self, _sender: Option<&AnyObject>) {
                on_ui(|ui| ui.set_manager_open(true));
            }

            #[unsafe(method(openPalette:))]
            fn open_palette(&self, _sender: Option<&AnyObject>) {
                on_ui(|ui| ui.set_palette_open(true));
            }

            #[unsafe(method(openHelp:))]
            fn open_help(&self, _sender: Option<&AnyObject>) {
                let _ = std::process::Command::new("open")
                    .arg("https://github.com/GMAC-pl/gmacftp")
                    .spawn();
            }

            #[unsafe(method(sendToICloud:))]
            fn send_to_icloud(&self, _sender: Option<&AnyObject>) {
                tracing::info!(target: "gmacftp::menu", "manual iCloud send (migrate all + sync)");
                // Migrate every saved password into the vault (one-time per Keychain-legacy
                // server), then push the complete vault + connections to iCloud.
                on_ui(|ui| ui.invoke_request_send_sync());
            }

            #[unsafe(method(pullFromICloud:))]
            fn pull_from_icloud(&self, _sender: Option<&AnyObject>) {
                let applied = cloud::pull_and_apply();
                let remote = cloud::remote_connections_ts();
                tracing::info!(target: "gmacftp::menu", applied, remote, "manual iCloud pull");
                let msg = match (applied, remote) {
                    (true, Some(t)) => format!(
                        "Pulled servers from iCloud ({}) — restart to see all changes.",
                        cloud::fmt_ts(t)
                    ),
                    (false, Some(t)) => format!("Already up to date (iCloud: {}).", cloud::fmt_ts(t)),
                    _ => "Nothing in iCloud yet. Turn on iCloud Sync and Send from your other Mac first."
                        .into(),
                };
                on_ui(|ui| ui.set_status(msg.into()));
            }

            #[unsafe(method(checkUpdates:))]
            fn check_updates(&self, _sender: Option<&AnyObject>) {
                // Check for a newer release on GitHub, off the UI thread (blocking HTTP).
                // If one exists, download the notarized DMG to ~/Downloads and open it in Finder
                // (the user drags gmacFTP to Applications — the standard DMG install).
                std::thread::spawn(|| {
                    on_ui(|ui| ui.set_status("Checking for updates…".into()));
                    match gmacftp::updater::check() {
                        Ok(Some(upd)) => {
                            let v = upd.version.clone();
                            match gmacftp::updater::download(&upd.dmg_url, &upd.version) {
                                Ok(path) => {
                                    gmacftp::updater::open_in_finder(&path);
                                    on_ui(move |ui| {
                                        ui.set_status(
                                            format!(
                                                "Update {v} downloaded — drag gmacFTP to Applications, then relaunch."
                                            )
                                            .into(),
                                        )
                                    });
                                }
                                Err(e) => on_ui(move |ui| ui.set_error(format!("Update download failed: {e}").into())),
                            }
                        }
                        Ok(None) => on_ui(|ui| {
                            ui.set_status(format!("gmacFTP is up to date (v{}).", gmacftp::updater::CURRENT).into())
                        }),
                        Err(e) => on_ui(move |ui| ui.set_error(format!("Update check failed: {e}").into())),
                    }
                });
            }
        }
    );

    /// The single target object owning every custom action. Created once, leaked for the
    /// process lifetime, and reused across `install_once` re-asserts. Main-thread only — the
    /// `MainThreadMarker` argument enforces that contract at the call site.
    fn ensure_target(_mtm: MainThreadMarker) -> &'static AnyObject {
        let existing = TARGET_PTR.load(Ordering::SeqCst);
        if !existing.is_null() {
            // SAFETY: set once on the main thread, valid for the process lifetime.
            return unsafe { &*existing };
        }
        let cls = GmacMenuTarget::class();
        let target_typed: Retained<GmacMenuTarget> = unsafe { msg_send![cls, new] };
        let target: Retained<AnyObject> =
            unsafe { Retained::cast_unchecked::<AnyObject>(target_typed) };
        let raw = Retained::into_raw(target); // leak
                                              // First writer wins; a late loser leaks a second tiny object (harmless, once).
        let _ =
            TARGET_PTR.compare_exchange(ptr::null_mut(), raw, Ordering::SeqCst, Ordering::SeqCst);
        // SAFETY: non-null after the exchange above.
        unsafe { &*TARGET_PTR.load(Ordering::SeqCst) }
    }

    // ── menu-item builders ──

    fn s(text: &str) -> Retained<NSString> {
        NSString::from_str(text)
    }

    /// Standard menu item: nil target + system selector (responder chain handles it).
    fn sys_item(
        mtm: MainThreadMarker,
        title: &str,
        action: Option<Sel>,
        key: &str,
    ) -> Retained<NSMenuItem> {
        let item = NSMenuItem::new(mtm);
        item.setTitle(&s(title));
        if let Some(sel) = action {
            // SAFETY: setting an action selector; only fires on user click.
            unsafe { item.setAction(Some(sel)) };
        }
        if !key.is_empty() {
            item.setKeyEquivalent(&s(key));
        }
        item
    }

    trait WithMask {
        fn shift_cmd(self) -> Self;
    }
    impl WithMask for Retained<NSMenuItem> {
        fn shift_cmd(self) -> Self {
            self.setKeyEquivalentModifierMask(
                NSEventModifierFlags::Shift | NSEventModifierFlags::Command,
            );
            self
        }
    }

    /// Custom menu item bound to the target object + a GmacMenuTarget selector.
    fn custom_item(
        mtm: MainThreadMarker,
        title: &str,
        target: &AnyObject,
        action: Sel,
        key: &str,
    ) -> Retained<NSMenuItem> {
        let item = NSMenuItem::new(mtm);
        item.setTitle(&s(title));
        // SAFETY: target/action wiring; both live for the app lifetime.
        unsafe {
            item.setTarget(Some(target));
            item.setAction(Some(action));
        }
        if !key.is_empty() {
            item.setKeyEquivalent(&s(key));
        }
        item
    }

    fn submenu(
        mtm: MainThreadMarker,
        title: &str,
        items: Vec<Retained<NSMenuItem>>,
    ) -> Retained<NSMenuItem> {
        let menu = NSMenu::new(mtm);
        menu.setTitle(&s(title));
        for it in items {
            menu.addItem(&it);
        }
        let header = NSMenuItem::new(mtm);
        header.setTitle(&s(title));
        header.setSubmenu(Some(&menu));
        header
    }

    /// Build the full menu bar and assign it to NSApplication. Idempotent: safe to call many
    /// times (the target object is created once; the menu is rebuilt cheaply). Must run on the
    /// main thread (it does — `app::run` is main, and the deferred calls arrive via the event
    /// loop which is also the main thread).
    fn install_once(ui: Weak<App>) {
        let mtm = match MainThreadMarker::new() {
            Some(m) => m,
            None => {
                tracing::warn!("menu bar install skipped: not on the main thread");
                return;
            }
        };
        let _ = APP.set(Mutex::new(Some(ui)));
        let target = ensure_target(mtm);
        let target_ref: &AnyObject = target;

        let sep = || NSMenuItem::separatorItem(mtm);

        // ── App menu (gmacFTP) ──
        let sync_item = NSMenuItem::new(mtm);
        sync_item.setTitle(&s(&sync_title()));
        unsafe {
            sync_item.setTarget(Some(target_ref));
            sync_item.setAction(Some(sel!(toggleSync:)));
        }
        // Keep a raw pointer to the item so the toggle action can update its title. Updated
        // every call; only read on the main thread.
        SYNC_ITEM_PTR.store(Retained::into_raw(sync_item.clone()), Ordering::SeqCst);

        let app_items = vec![
            sys_item(
                mtm,
                "About gmacFTP",
                Some(sel!(orderFrontStandardAboutPanel:)),
                "",
            ),
            custom_item(
                mtm,
                "Check for Updates…",
                target_ref,
                sel!(checkUpdates:),
                "",
            ),
            sep(),
            sync_item,
            custom_item(
                mtm,
                "Send Servers to iCloud",
                target_ref,
                sel!(sendToICloud:),
                "",
            ),
            custom_item(
                mtm,
                "Pull Servers from iCloud",
                target_ref,
                sel!(pullFromICloud:),
                "",
            ),
            sep(),
            sys_item(mtm, "Hide gmacFTP", Some(sel!(hide:)), "h"),
            sys_item(mtm, "Hide Others", Some(sel!(hideOtherApplications:)), "h").shift_cmd(),
            sys_item(mtm, "Show All", Some(sel!(unhideAllApplications:)), ""),
            sep(),
            sys_item(mtm, "Quit gmacFTP", Some(sel!(terminate:)), "q"),
        ];
        let app_header = submenu(mtm, "gmacFTP", app_items);

        // ── File menu ──
        let file_items = vec![
            custom_item(mtm, "New Connection", target_ref, sel!(newConnection:), "n"),
            custom_item(
                mtm,
                "Open Connection Manager…",
                target_ref,
                sel!(openManager:),
                "l",
            ),
            sep(),
            sys_item(mtm, "Close Window", Some(sel!(performClose:)), "w"),
        ];
        let file_header = submenu(mtm, "File", file_items);

        // ── Edit menu (enables Cut/Copy/Paste/Select-All in Slint text fields) ──
        let edit_items = vec![
            sys_item(mtm, "Undo", Some(sel!(undo:)), "z"),
            sys_item(mtm, "Redo", Some(sel!(redo:)), "z").shift_cmd(),
            sep(),
            sys_item(mtm, "Cut", Some(sel!(cut:)), "x"),
            sys_item(mtm, "Copy", Some(sel!(copy:)), "c"),
            sys_item(mtm, "Paste", Some(sel!(paste:)), "v"),
            sys_item(mtm, "Select All", Some(sel!(selectAll:)), "a"),
        ];
        let edit_header = submenu(mtm, "Edit", edit_items);

        // ── View menu ──
        let view_items =
            vec![
                custom_item(mtm, "Command Palette…", target_ref, sel!(openPalette:), "p")
                    .shift_cmd(),
            ];
        let view_header = submenu(mtm, "View", view_items);

        // ── Window menu ──
        let window_items = vec![
            sys_item(mtm, "Minimize", Some(sel!(performMiniaturize:)), "m"),
            sys_item(mtm, "Zoom", Some(sel!(performZoom:)), ""),
            sep(),
            sys_item(mtm, "Bring All to Front", Some(sel!(arrangeInFront:)), ""),
        ];
        let window_header = submenu(mtm, "Window", window_items);

        // ── Help menu ──
        let help_items = vec![custom_item(
            mtm,
            "gmacFTP on GitHub",
            target_ref,
            sel!(openHelp:),
            "",
        )];
        let help_header = submenu(mtm, "Help", help_items);

        let main_menu = NSMenu::new(mtm);
        for header in [
            app_header,
            file_header,
            edit_header,
            view_header,
            window_header,
            help_header,
        ] {
            main_menu.addItem(&header);
        }
        let shared = NSApplication::sharedApplication(mtm);
        // Force a "regular" application: a real dock icon + the app-name menu bar. Slint's winit
        // backend can leave the activation policy at the (non-regular) default for an unbundled
        // launch, in which case the app menu — and therefore our iCloud item — never appears.
        // Idempotent and safe across the repeated install_once calls.
        shared.setActivationPolicy(NSApplicationActivationPolicy::Regular);
        // `activateIgnoringOtherApps` is deprecated in macOS 14+ but is the only activation API
        // available across our full supported range (macOS 11+); the newer `-activate` is 14+ only.
        #[allow(deprecated)]
        shared.activateIgnoringOtherApps(true);
        shared.setMainMenu(Some(&main_menu));
        tracing::info!(target: "gmacftp::menu", "main menu installed; activation policy = regular");
    }

    /// Install immediately (before `ui.run()`). `app::run` also calls [`reassert`] on the first
    /// winit window event — that second pass runs once the event loop (and any default menu the
    /// winit backend installs during launch) is live, so our menu reliably wins the race.
    pub fn install(ui: Weak<App>) {
        install_once(ui);
    }

    /// Re-build + re-set the full menu. Idempotent. Called from `app::run` on the first winit
    /// window event (after the event loop has started) to re-assert our menu over any default
    /// menu the winit backend installs during launch.
    pub fn reassert(ui: Weak<App>) {
        install_once(ui);
    }
}

#[cfg(target_os = "macos")]
pub fn install(ui: slint::Weak<crate::App>) {
    imp::install(ui);
}

#[cfg(not(target_os = "macos"))]
pub fn install(_ui: slint::Weak<crate::App>) {}

#[cfg(target_os = "macos")]
pub fn reassert(ui: slint::Weak<crate::App>) {
    imp::reassert(ui);
}

#[cfg(not(target_os = "macos"))]
pub fn reassert(_ui: slint::Weak<crate::App>) {}

/// Re-read cloud::enabled() and update the menu item's ON/OFF title. Called after the sync
/// state changes from outside the menu (e.g. the set-passphrase dialog enabling sync).
#[cfg(target_os = "macos")]
pub fn refresh_sync_title() {
    imp::refresh_sync_title();
}
#[cfg(not(target_os = "macos"))]
pub fn refresh_sync_title() {}
