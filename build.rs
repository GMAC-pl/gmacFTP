// build.rs — compiles ui/app.slint and stamps the app identity used by storage.
// Build scripts may override these values for private/public bundles without
// committing private identifiers into the public source tree.
fn main() {
    println!("cargo:rerun-if-env-changed=MACKFTP_BUNDLE_ID");
    println!("cargo:rerun-if-env-changed=MACKFTP_CONFIG_QUALIFIER");
    println!("cargo:rerun-if-env-changed=MACKFTP_CONFIG_ORGANIZATION");
    println!("cargo:rerun-if-env-changed=MACKFTP_CONFIG_APPLICATION");
    println!("cargo:rerun-if-env-changed=MACKFTP_RENDER_CHECK");

    let bundle_id =
        std::env::var("MACKFTP_BUNDLE_ID").unwrap_or_else(|_| "app.mackftp.client".to_string());
    let qualifier = std::env::var("MACKFTP_CONFIG_QUALIFIER").unwrap_or_else(|_| "app".to_string());
    // Preserve the legacy storage identity so saved servers survive the product rename.
    let organization =
        std::env::var("MACKFTP_CONFIG_ORGANIZATION").unwrap_or_else(|_| "mackftp".to_string());
    let application =
        std::env::var("MACKFTP_CONFIG_APPLICATION").unwrap_or_else(|_| "client".to_string());

    println!("cargo:rustc-env=MACKFTP_BUNDLE_ID={bundle_id}");
    println!("cargo:rustc-env=MACKFTP_CONFIG_QUALIFIER={qualifier}");
    println!("cargo:rustc-env=MACKFTP_CONFIG_ORGANIZATION={organization}");
    println!("cargo:rustc-env=MACKFTP_CONFIG_APPLICATION={application}");

    println!("cargo:rerun-if-changed=translations");
    // Slint's UI-tree test API needs compiler metadata. Keep it in development/test builds only;
    // signed release binaries do not carry this introspection data.
    let include_ui_debug_info = std::env::var("PROFILE").is_ok_and(|profile| profile != "release");
    let mut config = slint_build::CompilerConfiguration::new()
        .with_bundled_translations("translations")
        .with_default_translation_context(slint_build::DefaultTranslationContext::None)
        .with_debug_info(include_ui_debug_info);
    // The tracked render-check example uses Slint's headless software renderer. Optimize and
    // embed fonts only for that explicit development command; public release builds keep the
    // normal FemtoVG/wgpu resource path and binary footprint.
    if std::env::var_os("MACKFTP_RENDER_CHECK").is_some() {
        config = config.embed_resources(slint_build::EmbedResourcesKind::EmbedForSoftwareRenderer);
    }
    slint_build::compile_with_config("ui/app.slint", config).expect("Slint UI compilation failed");
}
