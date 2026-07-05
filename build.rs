// build.rs — compiles ui/app.slint and stamps the app identity used by storage.
// Build scripts may override these values for private/public bundles without
// committing private identifiers into the public source tree.
fn main() {
    println!("cargo:rerun-if-env-changed=MACKFTP_BUNDLE_ID");
    println!("cargo:rerun-if-env-changed=MACKFTP_CONFIG_QUALIFIER");
    println!("cargo:rerun-if-env-changed=MACKFTP_CONFIG_ORGANIZATION");
    println!("cargo:rerun-if-env-changed=MACKFTP_CONFIG_APPLICATION");

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

    slint_build::compile("ui/app.slint").expect("Slint UI compilation failed");
}
