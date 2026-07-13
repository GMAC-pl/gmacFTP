//! Opt-in protocol compatibility round trip.
//!
//! The normal test suite skips safely unless `GMACFTP_COMPAT_SERVER` is set. The companion
//! `run-compatibility-matrix.sh` supplies isolated localhost servers and credentials.

use std::path::PathBuf;

use gmacftp::model::{ConnectionId, ConnectionSpec, Protocol};
use gmacftp::net::{ftp, sftp, NetError};

const PASSWORD: &str = "testpass";

fn spec(protocol: Protocol, port: u16) -> ConnectionSpec {
    ConnectionSpec {
        id: ConnectionId(0),
        name: "localhost compatibility fixture".into(),
        protocol,
        host: "127.0.0.1".into(),
        port,
        user: "testuser".into(),
        initial_path: if protocol == Protocol::Ftp {
            "/".into()
        } else {
            "/home/testuser".into()
        },
        group: String::new(),
        tags: Vec::new(),
        timeout_secs: Some(10),
        keepalive_interval_secs: None,
        ftp_data_mode: Default::default(),
        ftp_filename_encoding: Default::default(),
        ftp_tls_mode: Default::default(),
        proxy_url: None,
        use_ssh_config: false,
        ssh_proxy_jump: None,
        // The three FTP fixtures intentionally exercise the explicit per-connection legacy
        // plaintext exception. FTPS trust and pin changes have separate deterministic tests.
        allow_plaintext_ftp: protocol == Protocol::Ftp,
        accept_invalid_tls: false,
        tls_pinned_sha256: None,
        tls_client_cert: None,
        tls_client_key: None,
        sftp_auth: Default::default(),
        sftp_private_key: None,
        transfer_concurrency: None,
    }
}

fn fixture_paths(server: &str, remote_root: &str) -> (String, String, String, PathBuf, PathBuf) {
    let suffix = format!(
        "{}-{}",
        server.replace(|c: char| !c.is_ascii_alphanumeric(), "-"),
        std::process::id()
    );
    let directory = format!(
        "{}/gmacftp-compat-{suffix}",
        remote_root.trim_end_matches('/')
    );
    let uploaded = format!("{directory}/source.bin");
    let renamed = format!("{directory}/renamed.bin");
    let local = std::env::temp_dir().join(format!("gmacftp-compat-{suffix}-source.bin"));
    let downloaded = std::env::temp_dir().join(format!("gmacftp-compat-{suffix}-download.bin"));
    (directory, uploaded, renamed, local, downloaded)
}

fn ftp_round_trip(server: &str, port: u16) -> Result<(), NetError> {
    let spec = spec(Protocol::Ftp, port);
    let (directory, uploaded, renamed, local, downloaded) = fixture_paths(server, "/");
    let payload = format!("gmacFTP compatibility fixture: {server}\n").repeat(1_024);
    std::fs::write(&local, payload.as_bytes())?;

    let result = (|| {
        let (_, plaintext) = ftp::connect_and_list(&spec, PASSWORD)
            .map_err(|error| NetError::Ftp(format!("list: {error}")))?;
        if !plaintext {
            return Err(NetError::Ftp(
                "plaintext fixture unexpectedly negotiated TLS".into(),
            ));
        }
        ftp::create_dir(&spec, PASSWORD, &directory)
            .map_err(|error| NetError::Ftp(format!("create directory: {error}")))?;
        ftp::upload(&spec, PASSWORD, &local, &uploaded, |_| {}, None)
            .map_err(|error| NetError::Ftp(format!("upload: {error}")))?;
        ftp::rename(&spec, PASSWORD, &uploaded, &renamed)
            .map_err(|error| NetError::Ftp(format!("rename: {error}")))?;
        ftp::download(&spec, PASSWORD, &renamed, &downloaded, |_| {}, None)
            .map_err(|error| NetError::Ftp(format!("download: {error}")))?;
        let actual = std::fs::read(&downloaded)?;
        if actual != payload.as_bytes() {
            return Err(NetError::Ftp("FTP round-trip content mismatch".into()));
        }
        ftp::delete(&spec, PASSWORD, &renamed, false)
            .map_err(|error| NetError::Ftp(format!("delete file: {error}")))?;
        ftp::delete(&spec, PASSWORD, &directory, true)
            .map_err(|error| NetError::Ftp(format!("delete directory: {error}")))?;
        Ok(())
    })();

    let _ = std::fs::remove_file(local);
    let _ = std::fs::remove_file(downloaded);
    result
}

async fn list_sftp_with_explicit_trust(
    spec: &ConnectionSpec,
) -> Result<Vec<gmacftp::model::RemoteEntry>, NetError> {
    match sftp::connect_and_list(spec, PASSWORD).await {
        Err(NetError::HostKeyTrustRequired(challenge)) => {
            // This is a localhost-only disposable fixture. Production still requires the user to
            // verify this fingerprint before the exact same trust operation is called.
            sftp::trust_host_key(&challenge)?;
            sftp::connect_and_list(spec, PASSWORD).await
        }
        result => result,
    }
}

async fn sftp_round_trip(server: &str, port: u16) -> Result<(), NetError> {
    let spec = spec(Protocol::Sftp, port);
    let (directory, uploaded, renamed, local, downloaded) = fixture_paths(server, "/home/testuser");
    let payload = format!("gmacFTP compatibility fixture: {server}\n").repeat(1_024);
    std::fs::write(&local, payload.as_bytes())?;

    let result = async {
        list_sftp_with_explicit_trust(&spec).await?;
        sftp::create_dir(&spec, PASSWORD, &directory).await?;
        sftp::upload(&spec, PASSWORD, &local, &uploaded, |_| {}, None).await?;
        sftp::rename(&spec, PASSWORD, &uploaded, &renamed).await?;
        sftp::download(&spec, PASSWORD, &renamed, &downloaded, |_| {}, None).await?;
        let actual = std::fs::read(&downloaded)?;
        if actual != payload.as_bytes() {
            return Err(NetError::Ssh("SFTP round-trip content mismatch".into()));
        }
        sftp::delete(&spec, PASSWORD, &renamed, false).await?;
        sftp::delete(&spec, PASSWORD, &directory, true).await?;
        Ok(())
    }
    .await;

    let _ = std::fs::remove_file(local);
    let _ = std::fs::remove_file(downloaded);
    result
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn protocol_server_round_trip() {
    let Ok(server) = std::env::var("GMACFTP_COMPAT_SERVER") else {
        eprintln!("skipping: GMACFTP_COMPAT_SERVER is not set");
        return;
    };
    let protocol = std::env::var("GMACFTP_COMPAT_PROTOCOL").unwrap_or_else(|_| "ftp".into());
    let default_port = if protocol == "sftp" { 22 } else { 21 };
    let port = std::env::var("GMACFTP_COMPAT_PORT")
        .ok()
        .and_then(|value| value.parse::<u16>().ok())
        .unwrap_or(default_port);

    let result = match protocol.as_str() {
        "ftp" => ftp_round_trip(&server, port),
        "sftp" => sftp_round_trip(&server, port).await,
        value => panic!("unsupported GMACFTP_COMPAT_PROTOCOL {value:?}"),
    };
    result.unwrap_or_else(|error| panic!("{server} compatibility round trip failed: {error}"));
}
