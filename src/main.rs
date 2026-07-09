// src/main.rs — gmacFTP entry point. The Slint UI module + the app controller.
slint::include_modules!();

mod app;
mod macos_menu;

fn main() {
    // suppaftp logs complete control-channel commands at trace level, including `PASS <secret>`.
    // Do NOT use `SubscriberInitExt::try_init()` here: it installs `tracing_log::LogTracer`,
    // which would forward those legacy `log` records whenever the user starts with
    // `RUST_LOG=trace`. Installing the tracing subscriber directly keeps our structured tracing
    // diagnostics while deliberately leaving the `log` facade unregistered (and therefore
    // drops suppaftp's unsafe wire-level logs).
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn"));
    let subscriber = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .finish();
    let _ = tracing::subscriber::set_global_default(subscriber);

    tracing::info!(target: "gmacftp", "starting");
    app::run();
}
