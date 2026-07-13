//! Deterministic, privacy-safe screenshots of the real gmacFTP Slint component.
//!
//! Run through `scripts/check-ui-render.sh`; the script enables software-renderer resource
//! embedding and writes all output below a disposable directory. No application controller,
//! network connection, credential store, Keychain, or user configuration is opened.

slint::include_modules!();

use std::collections::HashSet;
use std::error::Error;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use slint::platform::software_renderer::{MinimalSoftwareWindow, RepaintBufferType};
use slint::platform::{Platform, PlatformError, WindowAdapter};
use slint::{ComponentHandle, ModelRc, PhysicalSize, VecModel};

const LOGICAL_WIDTH: u32 = 1180;
const LOGICAL_HEIGHT: u32 = 740;

struct HeadlessPlatform;

impl Platform for HeadlessPlatform {
    fn create_window_adapter(&self) -> Result<Rc<dyn WindowAdapter>, PlatformError> {
        Ok(MinimalSoftwareWindow::new(RepaintBufferType::NewBuffer))
    }
}

fn model<T: Clone + 'static>(rows: Vec<T>) -> ModelRc<T> {
    ModelRc::from(Rc::new(VecModel::from(rows)))
}

fn entry(name: &str, is_dir: bool, date: &str, size_text: &str, size: i32) -> EntryRow {
    EntryRow {
        name: name.into(),
        is_dir,
        size,
        mtime: 0,
        date: date.into(),
        size_text: size_text.into(),
        permissions: if is_dir { "drwxr-xr-x" } else { "-rw-r--r--" }.into(),
        owner: "demo".into(),
        group: "staff".into(),
        metadata_state: "ready".into(),
    }
}

fn render_scale() -> Result<u32, Box<dyn Error>> {
    let scale = std::env::var("MACKFTP_RENDER_SCALE")
        .unwrap_or_else(|_| "1".into())
        .parse::<u32>()?;
    if !matches!(scale, 1 | 2) {
        return Err("MACKFTP_RENDER_SCALE must be 1 or 2".into());
    }
    Ok(scale)
}

fn configure_base(ui: &App, locale: &str, theme: &str) -> Result<u32, Box<dyn Error>> {
    slint::select_bundled_translation(if locale == "pl" { "pl" } else { "" })?;
    ui.global::<I18n>().set_locale(locale.into());
    ui.global::<Tokens>().set_theme(theme.into());
    ui.set_app_version(env!("CARGO_PKG_VERSION").into());
    ui.set_snapshot_mode(true);
    ui.on_localize_runtime(|message, _| message);
    let scale = render_scale()?;
    ui.window()
        .dispatch_event(slint::platform::WindowEvent::ScaleFactorChanged {
            scale_factor: scale as f32,
        });
    ui.window().set_size(PhysicalSize::new(
        LOGICAL_WIDTH * scale,
        LOGICAL_HEIGHT * scale,
    ));

    let connections = vec![
        ConnRow {
            id: 1,
            label: "Production".into(),
            sub: "ftp.example.com".into(),
            protocol: "FTPS".into(),
            connected: true,
        },
        ConnRow {
            id: 2,
            label: "Staging".into(),
            sub: "sftp.example.com".into(),
            protocol: "SFTP".into(),
            connected: true,
        },
        ConnRow {
            id: 3,
            label: "Backups".into(),
            sub: "backup.example.com".into(),
            protocol: "SFTP".into(),
            connected: false,
        },
    ];
    ui.set_connections(model(connections.clone()));
    ui.set_filtered_connections(model(connections.clone()));
    ui.set_palette_connections(model(connections.clone()));
    ui.set_sessions(model(connections[..2].to_vec()));
    ui.set_filtered_sessions(model(connections[..2].to_vec()));
    ui.set_selected_connection(1);
    ui.set_active_connection(1);
    ui.set_active_host("ftp.example.com".into());
    ui.set_local_favorites(model(vec![LocalFavoriteRow {
        label: "Sites".into(),
        path: "/Users/demo/Sites".into(),
    }]));

    let local = vec![
        entry("Projects", true, "Today 18:20", "--", 0),
        entry("Assets", true, "Today 17:42", "--", 0),
        entry("README.md", false, "Today 16:10", "12 KB", 12 * 1024),
        entry("deploy.sh", false, "Yesterday", "4 KB", 4 * 1024),
    ];
    let remote = vec![
        entry("public", true, "Today 18:18", "--", 0),
        entry("releases", true, "Today 17:08", "--", 0),
        entry("index.html", false, "Today 16:44", "24 KB", 24 * 1024),
        entry("app.css", false, "Yesterday", "18 KB", 18 * 1024),
    ];
    ui.set_local_full(model(local.clone()));
    ui.set_local_entries(model(local.clone()));
    ui.set_remote_full(model(remote.clone()));
    ui.set_remote_entries(model(remote.clone()));
    ui.set_local_selection(model(vec![false, false, true, false]));
    ui.set_remote_selection(model(vec![false, false, false, false]));
    ui.set_local_count(local.len() as i32);
    ui.set_remote_count(remote.len() as i32);
    ui.set_local_selected(2);
    ui.set_remote_selected(-1);
    ui.set_local_cwd("/Users/demo/Sites".into());
    ui.set_local_path_display("~/Sites".into());
    ui.set_remote_cwd("/var/www/html".into());
    ui.set_remote_path_display("/var/www/html".into());
    ui.set_left_kind("local".into());
    ui.set_right_kind("remote".into());
    ui.set_right_host("ftp.example.com".into());
    ui.set_right_protocol("FTPS".into());
    ui.set_right_conn_id(1);
    ui.set_active_pane("local".into());
    ui.set_status("Ready — privacy-safe render fixture".into());

    let transfers = vec![
        TransferRow {
            id: 1,
            name: "release.zip".into(),
            direction: "upload".into(),
            route: "~/Sites → ftp.example.com".into(),
            done: 48 * 1024 * 1024,
            total: 96 * 1024 * 1024,
            progress_text: "48 / 96 MB".into(),
            fraction: 0.5,
            state: "active".into(),
            priority: "high".into(),
            message: "2.4 MB/s · 20s left".into(),
        },
        TransferRow {
            id: 2,
            name: "report.pdf".into(),
            direction: "download".into(),
            route: "sftp.example.com → ~/Downloads".into(),
            done: 0,
            total: 3 * 1024 * 1024,
            progress_text: "Waiting".into(),
            fraction: 0.0,
            state: "queued".into(),
            priority: "normal".into(),
            message: "Queued".into(),
        },
    ];
    ui.set_transfer_jobs(model(transfers));
    ui.set_transfer_summary("1 active · 1 queued".into());
    ui.set_transfer_pending_count(2);
    Ok(scale)
}

fn render_scenario(output: &Path, name: &str) -> Result<(), Box<dyn Error>> {
    let locale = if name == "pl" { "pl" } else { "en" };
    let theme = if name == "dark" { "dark" } else { "light" };
    let ui = App::new()?;
    let scale = configure_base(&ui, locale, theme)?;

    match name {
        "manager" => ui.set_manager_open(true),
        "editor" => {
            ui.set_editor_id(1);
            ui.set_editor_name("Production".into());
            ui.set_editor_protocol("ftp".into());
            ui.set_editor_host("ftp.example.com".into());
            ui.set_editor_port("21".into());
            ui.set_editor_user("demo".into());
            ui.set_editor_ftp_tls_mode("explicit".into());
            ui.set_editor_open(true);
        }
        "ctx" => {
            ui.set_ctx_pane("local".into());
            ui.set_ctx_index(2);
            ui.set_ctx_name("README.md".into());
            ui.set_ctx_is_dir(false);
            ui.set_ctx_x(520.0);
            ui.set_ctx_y(330.0);
            ui.set_ctx_open(true);
        }
        "panel" => ui.set_transfer_panel_open(true),
        "drag" => {
            ui.set_drag_source("local".into());
            ui.set_drag_name("README.md".into());
            ui.set_drag_is_dir(false);
            ui.set_drag_x(720.0);
            ui.set_drag_y(420.0);
            ui.set_drag_active(true);
        }
        "update" => {
            ui.set_update_version("0.2.2".into());
            ui.set_update_notes(
                "Stability update\n\n• Polished macOS visual system\n• Safe recovery after sleep and network changes\n• Deterministic UI checks"
                    .into(),
            );
            ui.set_update_open(true);
        }
        "en" | "pl" | "dark" => {}
        other => return Err(format!("unknown render scenario: {other}").into()),
    }

    ui.show()?;
    let pixels = ui.window().take_snapshot()?;
    let expected_width = LOGICAL_WIDTH * scale;
    let expected_height = LOGICAL_HEIGHT * scale;
    if pixels.width() != expected_width || pixels.height() != expected_height {
        return Err(format!(
            "{name}: unexpected snapshot size {}x{}",
            pixels.width(),
            pixels.height()
        )
        .into());
    }
    // Slint's software snapshot is rendered through an RGB target and exposes an RGBA buffer with
    // an unspecified alpha channel. Documentation PNGs must be opaque on both light and dark web
    // pages, so preserve the rendered RGB values and explicitly set alpha to 255.
    let mut encoded_pixels = pixels.as_bytes().to_vec();
    for rgba in encoded_pixels.chunks_exact_mut(4) {
        rgba[3] = 255;
    }
    let colors = encoded_pixels
        .chunks_exact(4)
        .map(|rgba| [rgba[0], rgba[1], rgba[2], rgba[3]])
        .collect::<HashSet<_>>();
    if colors.len() < 16 {
        return Err(format!("{name}: render appears blank ({} colors)", colors.len()).into());
    }

    let path = output.join(format!("gmacftp_render_{name}.png"));
    image::save_buffer_with_format(
        &path,
        &encoded_pixels,
        pixels.width(),
        pixels.height(),
        image::ColorType::Rgba8,
        image::ImageFormat::Png,
    )?;
    if std::fs::metadata(&path)?.len() < 10_000 {
        return Err(format!("{name}: encoded snapshot is unexpectedly small").into());
    }
    println!("{}", path.display());
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    slint::platform::set_platform(Box::new(HeadlessPlatform))?;
    let mut args = std::env::args_os().skip(1);
    let output = args
        .next()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/tmp/gmacftp-render-check"));
    std::fs::create_dir_all(&output)?;
    let all_scenarios = [
        "en", "pl", "manager", "editor", "ctx", "panel", "drag", "dark", "update",
    ];
    if let Some(scenario) = args.next() {
        render_scenario(&output, &scenario.to_string_lossy())?;
    } else {
        for scenario in all_scenarios {
            render_scenario(&output, scenario)?;
        }
    }
    Ok(())
}
