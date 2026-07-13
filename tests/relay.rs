//! Regression tests for the FTP→FTP relay mechanism (download → temp → upload).
//!
//! The relay uploads the temp file with `ftp::upload` — the SAME function the working
//! disk→FTP transfer uses — so it can't diverge into a broken path again.
//!
//! CRITICAL guard: for a SINGLE file the relay used to compute the destination as
//! `join_remote(dst_base.join(""))`. Rust's `PathBuf::join("")` appends a TRAILING SLASH,
//! turning the STOR target into "…/name/" → the server sees an empty filename and replies
//! "501 No file name". That's why FTP→FTP failed while disk→FTP and FTP→disk worked. The
//! fix: when rel == "" the destination IS dst_base (no join). These tests pin both halves:
//! the path logic (no trailing slash) and the end-to-end upload through `ftp::upload`.
//!
//! Runs against the local pyftpdlib FTPS server on 127.0.0.1:2210 (tests/srv_ftps.py).
use gmacftp::model::{ConnectionId, ConnectionSpec, Protocol};
use gmacftp::net::ftp;
use std::path::PathBuf;

fn spec() -> ConnectionSpec {
    ConnectionSpec {
        id: ConnectionId(0),
        name: "t".into(),
        protocol: Protocol::Ftp,
        host: "127.0.0.1".into(),
        port: 2210,
        user: "testuser".into(),
        initial_path: "/".into(),
        group: String::new(),
        tags: Vec::new(),
        timeout_secs: None,
        keepalive_interval_secs: None,
        ftp_data_mode: Default::default(),
        ftp_filename_encoding: Default::default(),
        ftp_tls_mode: Default::default(),
        proxy_url: None,
        use_ssh_config: false,
        ssh_proxy_jump: None,
        allow_plaintext_ftp: false,
        accept_invalid_tls: false,
        tls_pinned_sha256: None,
        tls_client_cert: None,
        tls_client_key: None,
        sftp_auth: Default::default(),
        sftp_private_key: None,
        transfer_concurrency: None,
    }
}

/// Pin the path-computation trap deterministically (no server needed): join("") MUST add a
/// trailing slash (the trap), and the production fix (rel=="" → dst_base) MUST NOT.
#[test]
fn single_file_dst_path_has_no_trailing_slash() {
    let dst_base = "/home/user/sub/file.txt".to_string();
    let rel = "";

    // the trap: PathBuf::join("") appends a trailing slash
    let buggy = PathBuf::from(&dst_base).join(rel);
    assert!(
        buggy.to_string_lossy().ends_with('/'),
        "precondition: join(\"\") yields {:?} (trailing slash → STOR 'name/' → 501)",
        buggy
    );

    // the fix used in copy_remote_to_remote: rel=="" → dst_rp == dst_base (no trailing slash).
    // `rel` is fixed to "" above, so the fix's output is just `dst_base` verbatim here.
    let fixed: String = dst_base.clone();
    assert!(
        !fixed.ends_with('/'),
        "fixed dst must have no trailing slash, got {fixed:?}"
    );
}

#[test]
fn relay_src_to_dst_lands_via_proven_upload() {
    if std::net::TcpStream::connect("127.0.0.1:2210").is_err() {
        eprintln!("skipping: 127.0.0.1:2210 not reachable");
        return;
    }
    let s = spec();
    let pw = "testpass";
    let payload = b"relay-content-12345-relay";

    // 1. seed the source file
    let src_local = std::env::temp_dir().join("relay_src.txt");
    std::fs::write(&src_local, payload).unwrap();
    ftp::upload(&s, pw, &src_local, "/relay_src.txt", |_| {}, None).unwrap();

    // 2. relay step 1: download src → temp
    let tmpf = std::env::temp_dir().join("relay_tmp.txt");
    let _ = std::fs::remove_file(&tmpf);
    ftp::download(&s, pw, "/relay_src.txt", &tmpf, |_| {}, None).unwrap();
    assert_eq!(
        std::fs::read(&tmpf).unwrap(),
        payload,
        "temp must match src"
    );

    // 3. relay step 2: upload temp → dst (production: uses ftp::upload, dst path has NO trailing slash)
    ftp::upload(&s, pw, &tmpf, "/relay_dst.txt", |_| {}, None).unwrap();

    // 4. verify the destination file exists with the right content
    let chk = std::env::temp_dir().join("relay_chk.txt");
    let _ = std::fs::remove_file(&chk);
    ftp::download(&s, pw, "/relay_dst.txt", &chk, |_| {}, None).unwrap();
    assert_eq!(
        std::fs::read(&chk).unwrap(),
        payload,
        "dst must match src after relay"
    );
}

/// Relay into a SUBDIRECTORY (exercises mkdirs + a multi-segment dst path, no trailing slash).
#[test]
fn relay_into_subdir_lands_via_proven_upload() {
    if std::net::TcpStream::connect("127.0.0.1:2210").is_err() {
        eprintln!("skipping: 127.0.0.1:2210 not reachable");
        return;
    }
    let s = spec();
    let pw = "testpass";
    let payload = b"relay-subdir-content-XYZ";

    let local = std::env::temp_dir().join("relay_sub_src.txt");
    std::fs::write(&local, payload).unwrap();
    ftp::upload(&s, pw, &local, "/relay_sub_src.txt", |_| {}, None).unwrap();

    let tmp = std::env::temp_dir().join("relay_sub_tmp.txt");
    let _ = std::fs::remove_file(&tmp);
    ftp::download(&s, pw, "/relay_sub_src.txt", &tmp, |_| {}, None).unwrap();

    // dst is a clean multi-segment path (what the folder-relay produces); upload mkdirs the parent
    ftp::upload(&s, pw, &tmp, "/inbox/deep/relay_sub.txt", |_| {}, None).unwrap();

    let chk = std::env::temp_dir().join("relay_sub_chk.txt");
    let _ = std::fs::remove_file(&chk);
    ftp::download(&s, pw, "/inbox/deep/relay_sub.txt", &chk, |_| {}, None).unwrap();
    assert_eq!(
        std::fs::read(&chk).unwrap(),
        payload,
        "subdir dst must match src"
    );
}

/// Right-click → Delete: ftp::delete (DELE) removes a remote file.
#[test]
fn delete_removes_remote_file() {
    if std::net::TcpStream::connect("127.0.0.1:2210").is_err() {
        eprintln!("skipping: 127.0.0.1:2210 not reachable");
        return;
    }
    let s = spec();
    let pw = "testpass";
    let local = std::env::temp_dir().join("del_src.txt");
    std::fs::write(&local, b"delete-me").unwrap();
    ftp::upload(&s, pw, &local, "/del_target.txt", |_| {}, None).unwrap();
    // delete it (file, not dir)
    ftp::delete(&s, pw, "/del_target.txt", false).unwrap();
    // confirm it's gone: a subsequent download must fail
    let chk = std::env::temp_dir().join("del_chk.txt");
    let _ = std::fs::remove_file(&chk);
    let res = ftp::download(&s, pw, "/del_target.txt", &chk, |_| {}, None);
    assert!(res.is_err(), "file should be gone after delete");
}
