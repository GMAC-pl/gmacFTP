//! Connection metadata: import the a third-party file manager seed (passwords -> Keychain) and persist
//! the password-free metadata to the config dir so the app remembers connections.

use std::fs;
use std::io::Read;
use std::path::PathBuf;

use crate::model::{ConnectionId, ConnectionSpec, Protocol};

use super::creds::{CredentialError, CredentialKey, CredentialStore};
use zeroize::Zeroize;

const MAX_IMPORT_BYTES: usize = 1_048_576;
const MAX_IMPORT_CONNECTIONS: usize = 10_000;

#[derive(Debug, thiserror::Error)]
pub enum ImportError {
    #[error("invalid JSON: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid XML: {0}")]
    Xml(#[from] roxmltree::Error),
    #[error("credential store: {0}")]
    Credential(#[from] CredentialError),
    #[error("bad protocol: {0}")]
    Protocol(String),
    #[error("unsupported import entry: {0}")]
    Unsupported(String),
    #[error("import is too large")]
    TooLarge,
    #[error("invalid connection metadata: {0}")]
    Metadata(String),
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

/// a third-party file manager seed file: `data/connections.json`.
#[derive(serde::Deserialize)]
struct SeedFile {
    #[serde(default)]
    connections: Vec<SeedConnection>,
}

#[derive(serde::Deserialize)]
#[serde(untagged)]
enum SeedDocument {
    Wrapped(SeedFile),
    Array(Vec<SeedConnection>),
}

#[derive(serde::Deserialize)]
struct SeedConnection {
    name: String,
    protocol: String,
    host: String,
    port: u16,
    username: String,
    password: String,
    #[serde(default)]
    path: String,
}

/// Parse the seed JSON, push every password into the credential store (Keychain in
/// production, in-memory in tests), zeroize it, and return the password-free specs.
/// Hosts are trimmed (some a third-party file manager favorites carried a stray leading space).
pub fn load_seed(
    json: &str,
    store: &dyn CredentialStore,
) -> Result<Vec<ConnectionSpec>, ImportError> {
    if json.len() > MAX_IMPORT_BYTES {
        return Err(ImportError::TooLarge);
    }
    let connections = match serde_json::from_str::<SeedDocument>(json)? {
        SeedDocument::Wrapped(seed) => seed.connections,
        SeedDocument::Array(connections) => connections,
    };
    if connections.len() > MAX_IMPORT_CONNECTIONS {
        return Err(ImportError::TooLarge);
    }
    let mut specs = Vec::with_capacity(connections.len());
    for (i, s) in connections.into_iter().enumerate() {
        let host = s.host.trim().to_string();
        let protocol: Protocol = s.protocol.parse().map_err(ImportError::Protocol)?;
        let port = if s.port == 0 {
            protocol.default_port()
        } else {
            s.port
        };

        // Secret -> Keychain/vault, then wipe the buffer. Never retained in app state.
        // M12: never OVERWRITE an existing credential from a seed import — only seed if the
        // store does not already hold one for this (host, user). Prevents a modified/dropped
        // seed file from clobbering a password the user changed in-app.
        let credential_key = CredentialKey::new(protocol, &host, port, &s.username)?;
        let mut pw = s.password.into_bytes();
        let password_result = store_password_if_absent(store, &credential_key, &pw);
        pw.zeroize();
        password_result?;

        let initial_path = if s.path.trim().is_empty() {
            String::new()
        } else {
            s.path
        };

        specs.push(ConnectionSpec {
            id: ConnectionId(i),
            name: s.name,
            protocol,
            host,
            port,
            user: s.username,
            initial_path,
            allow_plaintext_ftp: false,
            accept_invalid_tls: false,
        });
    }
    Ok(specs)
}

/// FileZilla `sitemanager.xml` import (root `<FileZilla3>` → nested `<Folder>`/`<Server>`).
/// Each `<Server>` becomes a `ConnectionSpec`; the `<Pass>` text is stored as the password.
/// FileZilla stores plaintext when no master password is set (the common case) — with a master
/// password it is encrypted and the user re-enters it after import.
///
/// `<Protocol>` mapping (FileZilla): 0 = FTP, 1 = SFTP (SSH2), 3 = explicit FTPS and 4 =
/// implicit FTPS. gmacFTP supports FTP/explicit FTPS through `Protocol::Ftp`; implicit FTPS is
/// rejected instead of being silently connected with the wrong transport. Other unsupported
/// protocols (WebDAV/S3/HTTP, etc.) are skipped.
pub fn load_filezilla(
    xml: &str,
    store: &dyn CredentialStore,
) -> Result<Vec<ConnectionSpec>, ImportError> {
    if xml.len() > MAX_IMPORT_BYTES {
        return Err(ImportError::TooLarge);
    }
    let doc = roxmltree::Document::parse(xml)?;
    let mut specs = Vec::new();
    let mut idx = 0usize;
    for server in doc
        .descendants()
        .filter(|n| n.tag_name().name() == "Server")
    {
        if idx >= MAX_IMPORT_CONNECTIONS {
            return Err(ImportError::TooLarge);
        }
        let host = child_text(&server, "Host");
        if host.is_empty() {
            continue;
        }
        let user = child_text(&server, "User");
        let port: u16 = child_text(&server, "Port").trim().parse().unwrap_or(0);
        let protocol = match child_text(&server, "Protocol").trim() {
            "1" => Protocol::Sftp,
            "0" | "3" | "" => Protocol::Ftp, // "" defaults to FTP (FileZilla omits it)
            "4" => {
                return Err(ImportError::Unsupported(
                    "implicit FTPS is not supported; use explicit FTPS".to_string(),
                ))
            }
            _ => continue, // WebDAV/S3/HTTP etc. — gmacFTP can't speak these; skip
        };
        let port = if port == 0 {
            protocol.default_port()
        } else {
            port
        };
        let name = {
            let n = child_text(&server, "Name");
            if n.is_empty() {
                host.clone()
            } else {
                n
            }
        };

        // Secret -> vault, then wipe the buffer. Never retained on the spec. Just like the
        // seed import, an import must not replace a saved password: this server may be skipped
        // later by `merge_new` because the (host, user) connection already exists.
        let credential_key = CredentialKey::new(protocol, &host, port, &user)?;
        let mut pass = filezilla_password(&server)?;
        let password_result = if pass.is_empty() {
            Ok(())
        } else {
            store_password_if_absent(store, &credential_key, &pass)
        };
        pass.zeroize();
        password_result?;

        specs.push(ConnectionSpec {
            id: ConnectionId(idx),
            name,
            protocol,
            host,
            port,
            user,
            initial_path: String::new(),
            allow_plaintext_ftp: false,
            accept_invalid_tls: false,
        });
        idx += 1;
    }
    Ok(specs)
}

/// Add an imported password only when this exact `(host, user)` has no saved credential.
///
/// Import callers merge the returned connection specs only afterwards. Writing unconditionally
/// here would therefore let a duplicate FileZilla/JSON record overwrite the password for an
/// existing connection that is subsequently rejected by that merge. Errors other than
/// `NotFound` are propagated: an inaccessible vault is not evidence that a credential is absent.
fn store_password_if_absent(
    store: &dyn CredentialStore,
    key: &CredentialKey,
    password: &[u8],
) -> Result<(), ImportError> {
    match store.get_for(key) {
        Ok(_) => Ok(()),
        Err(CredentialError::NotFound) => store.set_for(key, password).map_err(Into::into),
        Err(e) => Err(e.into()),
    }
}

/// Decode FileZilla's optional base64 representation without ever retaining a plaintext
/// password in the `ConnectionSpec`. Other FileZilla password encodings are encrypted with the
/// user's master password and cannot be safely imported as a usable secret.
fn filezilla_password(server: &roxmltree::Node) -> Result<Vec<u8>, ImportError> {
    use base64::{engine::general_purpose::STANDARD as B64, Engine};

    let Some(pass) = server
        .children()
        .find(|c| c.is_element() && c.tag_name().name() == "Pass")
    else {
        return Ok(Vec::new());
    };
    let value = pass.text().unwrap_or("").trim();
    match pass.attribute("encoding") {
        None | Some("") => Ok(value.as_bytes().to_vec()),
        Some(encoding) if encoding.eq_ignore_ascii_case("base64") => B64
            .decode(value)
            .map_err(|_| ImportError::Unsupported("invalid FileZilla base64 password".into())),
        Some(encoding) => Err(ImportError::Unsupported(format!(
            "FileZilla password encoding {encoding:?} requires FileZilla to decrypt it first"
        ))),
    }
}

/// Trimmed text of a direct child element, or "" when absent/empty.
fn child_text(parent: &roxmltree::Node, tag: &str) -> String {
    parent
        .children()
        .find(|c| c.is_element() && c.tag_name().name() == tag)
        .and_then(|c| c.text())
        .unwrap_or("")
        .trim()
        .to_string()
}

/// Where password-free connection metadata lives: `<config_dir>/connections.json`.
fn metadata_path() -> Option<PathBuf> {
    let pd = directories::ProjectDirs::from(
        env!("MACKFTP_CONFIG_QUALIFIER"),
        env!("MACKFTP_CONFIG_ORGANIZATION"),
        env!("MACKFTP_CONFIG_APPLICATION"),
    )?;
    Some(pd.config_dir().join("connections.json"))
}

/// Persist connection metadata (no passwords — those are in the Keychain).
pub fn save_metadata(specs: &[ConnectionSpec]) -> Result<(), ImportError> {
    let Some(path) = metadata_path() else {
        return Ok(());
    };
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    validate_specs(specs)?;
    let json = serde_json::to_string_pretty(specs)?;
    crate::store::vault::atomic_write(&path, json.as_bytes())?;
    // Mirror to iCloud (no-op if sync disabled) so the connection list appears on the user's
    // other Macs. See src/store/cloud.rs.
    crate::store::cloud::push_state();
    Ok(())
}

/// Load previously-saved metadata. `Ok(None)` = nothing saved yet (first launch).
pub fn load_metadata() -> Result<Option<Vec<ConnectionSpec>>, ImportError> {
    let Some(path) = metadata_path() else {
        return Ok(None);
    };
    match read_regular_limited(&path, MAX_IMPORT_BYTES) {
        Ok(bytes) if bytes.iter().all(u8::is_ascii_whitespace) => Ok(None),
        Ok(bytes) => {
            let specs: Vec<ConnectionSpec> = serde_json::from_slice(&bytes)?;
            validate_specs(&specs)?;
            Ok(Some(specs))
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

/// Read persisted metadata without following a swapped symlink and without allocating past the
/// same limit enforced for imported/synced connection documents.
fn read_regular_limited(path: &std::path::Path, limit: usize) -> std::io::Result<Vec<u8>> {
    let before = fs::symlink_metadata(path)?;
    if !before.file_type().is_file()
        || before.file_type().is_symlink()
        || before.len() > limit as u64
    {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "connection metadata is not a bounded regular file",
        ));
    }
    let mut file = fs::File::open(path)?;
    let opened = file.metadata()?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if before.dev() != opened.dev() || before.ino() != opened.ino() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "connection metadata changed while opening",
            ));
        }
    }
    if !opened.file_type().is_file() || opened.len() > limit as u64 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "connection metadata changed type or size",
        ));
    }
    let mut bytes = Vec::with_capacity(opened.len() as usize);
    file.by_ref()
        .take(limit.saturating_add(1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "connection metadata exceeds its size limit",
        ));
    }
    Ok(bytes)
}

/// Parse and validate a metadata payload before cloud sync overwrites the local copy. The file
/// deliberately stays a plain JSON array for backwards compatibility; it is not authenticated.
/// V2 credential lookup binds every password to protocol+host+port+user, while cloud sync also
/// clears transport-security exceptions before use (see [`normalize_sync_metadata_bytes`]).
pub(crate) fn validate_metadata_bytes(bytes: &[u8]) -> Result<(), ImportError> {
    if bytes.len() > MAX_IMPORT_BYTES {
        return Err(ImportError::TooLarge);
    }
    let specs: Vec<ConnectionSpec> = serde_json::from_slice(bytes)?;
    validate_specs(&specs)
}

/// Produce the safe cross-device representation of plaintext metadata. Trust exceptions are a
/// local, deliberate decision; syncing them would allow anyone who can tamper with the plain
/// sync folder to weaken TLS or re-enable plaintext FTP on another Mac.
pub(crate) fn normalize_sync_metadata_bytes(bytes: &[u8]) -> Result<Vec<u8>, ImportError> {
    validate_metadata_bytes(bytes)?;
    let mut specs: Vec<ConnectionSpec> = serde_json::from_slice(bytes)?;
    for spec in &mut specs {
        spec.allow_plaintext_ftp = false;
        spec.accept_invalid_tls = false;
    }
    serde_json::to_vec_pretty(&specs).map_err(ImportError::Json)
}

fn validate_specs(specs: &[ConnectionSpec]) -> Result<(), ImportError> {
    if specs.len() > MAX_IMPORT_CONNECTIONS {
        return Err(ImportError::TooLarge);
    }
    for spec in specs {
        if spec.name.len() > 1024 || spec.initial_path.len() > 4096 {
            return Err(ImportError::Metadata(
                "connection field exceeds limit".to_string(),
            ));
        }
        CredentialKey::new(spec.protocol, &spec.host, spec.port, &spec.user)
            .map_err(|e| ImportError::Metadata(e.to_string()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::InMemoryStore;

    struct InaccessibleStore;

    fn key(protocol: Protocol, host: &str, port: u16, user: &str) -> CredentialKey {
        CredentialKey::new(protocol, host, port, user).unwrap()
    }

    impl CredentialStore for InaccessibleStore {
        fn get(&self, _host: &str, _user: &str) -> Result<Vec<u8>, CredentialError> {
            Err(CredentialError::NoStorageAccess)
        }

        fn set(&self, _host: &str, _user: &str, _secret: &[u8]) -> Result<(), CredentialError> {
            panic!("an inaccessible credential store must not be written to")
        }

        fn delete(&self, _host: &str, _user: &str) -> Result<(), CredentialError> {
            Ok(())
        }

        fn get_for(&self, _key: &CredentialKey) -> Result<Vec<u8>, CredentialError> {
            Err(CredentialError::NoStorageAccess)
        }

        fn set_for(&self, _key: &CredentialKey, _secret: &[u8]) -> Result<(), CredentialError> {
            panic!("an inaccessible credential store must not be written to")
        }

        fn delete_for(&self, _key: &CredentialKey) -> Result<(), CredentialError> {
            Ok(())
        }
    }

    const SAMPLE: &str = r#"{
      "source":"a third-party file manager","count":2,
      "connections":[
        {"name":"a","protocol":"ftp","host":"ftp.example.com","port":21,"username":"u1","password":"p1","path":"","id":0},
        {"name":"b","protocol":"sftp","host":" sftp.example.com ","port":2222,"username":"u2","password":"p2","path":"","id":1}
      ]
    }"#;

    #[test]
    fn imports_and_stores_passwords() {
        let store = InMemoryStore::default();
        let specs = load_seed(SAMPLE, &store).unwrap();
        assert_eq!(specs.len(), 2);
        assert_eq!(specs[0].host, "ftp.example.com");
        // leading-space host is trimmed
        assert_eq!(specs[1].host, "sftp.example.com");
        assert_eq!(specs[1].port, 2222);
        // passwords went to the store
        assert_eq!(
            store
                .get_for(&key(Protocol::Ftp, "ftp.example.com", 21, "u1"))
                .unwrap(),
            b"p1"
        );
        assert_eq!(
            store
                .get_for(&key(Protocol::Sftp, "sftp.example.com", 2222, "u2"))
                .unwrap(),
            b"p2"
        );
        // and are NOT carried on the spec
        let json = serde_json::to_string(&specs[0]).unwrap();
        assert!(!json.contains("p1"));
    }

    #[test]
    fn seed_import_never_replaces_an_existing_credential() {
        let store = InMemoryStore::default();
        store
            .set_for(
                &key(Protocol::Ftp, "ftp.example.com", 21, "u1"),
                b"password-changed-in-gmacftp",
            )
            .unwrap();

        let specs = load_seed(SAMPLE, &store).unwrap();

        // `merge_new` may reject this spec as a duplicate later; the import layer must have
        // already preserved the existing password by then.
        assert_eq!(specs[0].host, "ftp.example.com");
        assert_eq!(
            store
                .get_for(&key(Protocol::Ftp, "ftp.example.com", 21, "u1"))
                .unwrap(),
            b"password-changed-in-gmacftp"
        );
        // A genuinely new pair is still seeded as before.
        assert_eq!(
            store
                .get_for(&key(Protocol::Sftp, "sftp.example.com", 2222, "u2"))
                .unwrap(),
            b"p2"
        );
    }

    #[test]
    fn imports_do_not_treat_storage_failures_as_missing_passwords() {
        let store = InaccessibleStore;
        assert!(matches!(
            load_seed(SAMPLE, &store),
            Err(ImportError::Credential(CredentialError::NoStorageAccess))
        ));
        assert!(matches!(
            load_filezilla(FZ_SAMPLE, &store),
            Err(ImportError::Credential(CredentialError::NoStorageAccess))
        ));
    }

    #[test]
    fn metadata_roundtrip_in_temp() {
        // save_metadata writes to the real config dir; just exercise load of empty/missing.
        assert!(matches!(load_metadata(), Ok(None)) || load_metadata().is_ok());
    }

    const FZ_SAMPLE: &str = r#"<?xml version="1.0"?>
<FileZilla3><Servers>
  <Folder name="prod">
    <Server>
      <Host>ftp.example.com</Host><Port>21</Port><Protocol>0</Protocol>
      <Type>0</Type><Logontype>1</Logontype><User>u1</User><Pass>secret1</Pass><Name>Ex1</Name>
    </Server>
    <Server>
      <Host> sftp.example.com </Host><Port>0</Port><Protocol>1</Protocol>
      <User>u2</User><Pass>secret2</Pass>
    </Server>
    <Server>
      <Host>webdav.example.com</Host><Protocol>6</Protocol><User>u3</User>
    </Server>
  </Folder>
</Servers></FileZilla3>"#;

    #[test]
    fn imports_filezilla_sitemanager() {
        let store = InMemoryStore::default();
        let specs = load_filezilla(FZ_SAMPLE, &store).unwrap();
        // WebDAV (Protocol 6) is skipped → 2 specs
        assert_eq!(specs.len(), 2);
        assert_eq!(specs[0].host, "ftp.example.com");
        assert_eq!(specs[0].protocol, Protocol::Ftp);
        assert_eq!(specs[0].port, 21);
        // trimmed host + name falls back to host when <Name> empty + port defaults to 22
        assert_eq!(specs[1].host, "sftp.example.com");
        assert_eq!(specs[1].protocol, Protocol::Sftp);
        assert_eq!(specs[1].port, 22);
        assert_eq!(specs[1].name, "sftp.example.com");
        // passwords went to the store
        assert_eq!(
            store
                .get_for(&key(Protocol::Ftp, "ftp.example.com", 21, "u1"))
                .unwrap(),
            b"secret1"
        );
        assert_eq!(
            store
                .get_for(&key(Protocol::Sftp, "sftp.example.com", 22, "u2"))
                .unwrap(),
            b"secret2"
        );
        // and are NOT carried on the spec
        assert!(!serde_json::to_string(&specs[0])
            .unwrap()
            .contains("secret1"));
    }

    #[test]
    fn imports_filezilla_base64_password_and_rejects_implicit_ftps() {
        let base64 = r#"<FileZilla3><Servers><Server>
          <Host>ftp.example.com</Host><Port>21</Port><Protocol>3</Protocol>
          <User>u</User><Pass encoding="base64">c2VjcmV0</Pass>
        </Server></Servers></FileZilla3>"#;
        let store = InMemoryStore::default();
        let specs = load_filezilla(base64, &store).unwrap();
        assert_eq!(specs.len(), 1);
        assert_eq!(
            store
                .get_for(&key(Protocol::Ftp, "ftp.example.com", 21, "u"))
                .unwrap(),
            b"secret"
        );

        let implicit = base64.replace("<Protocol>3</Protocol>", "<Protocol>4</Protocol>");
        assert!(matches!(
            load_filezilla(&implicit, &store),
            Err(ImportError::Unsupported(_))
        ));
    }

    #[test]
    fn imports_json_array_format() {
        let array = r#"[
          {"name":"array","protocol":"sftp","host":"example.com","port":0,
           "username":"alice","password":"p","path":""}
        ]"#;
        let store = InMemoryStore::default();
        let specs = load_seed(array, &store).unwrap();
        assert_eq!(specs[0].port, 22);
        assert_eq!(
            store
                .get_for(&key(Protocol::Sftp, "example.com", 22, "alice"))
                .unwrap(),
            b"p"
        );
    }

    #[test]
    fn sync_metadata_clears_transport_security_exceptions() {
        let specs = vec![ConnectionSpec {
            id: ConnectionId(0),
            name: "legacy".into(),
            protocol: Protocol::Ftp,
            host: "example.com".into(),
            port: 21,
            user: "alice".into(),
            initial_path: String::new(),
            allow_plaintext_ftp: true,
            accept_invalid_tls: true,
        }];
        let normalized =
            normalize_sync_metadata_bytes(&serde_json::to_vec(&specs).unwrap()).unwrap();
        let decoded: Vec<ConnectionSpec> = serde_json::from_slice(&normalized).unwrap();
        assert!(!decoded[0].allow_plaintext_ftp);
        assert!(!decoded[0].accept_invalid_tls);
    }

    #[test]
    fn filezilla_import_never_replaces_an_existing_credential() {
        let store = InMemoryStore::default();
        store
            .set_for(
                &key(Protocol::Ftp, "ftp.example.com", 21, "u1"),
                b"password-changed-in-gmacftp",
            )
            .unwrap();

        let specs = load_filezilla(FZ_SAMPLE, &store).unwrap();

        // This is the regression case for a duplicate connection: app.rs merges (and rejects)
        // the spec only after `load_filezilla` returns, so FileZilla's <Pass> must not clobber
        // the credential while parsing.
        assert_eq!(specs[0].host, "ftp.example.com");
        assert_eq!(
            store
                .get_for(&key(Protocol::Ftp, "ftp.example.com", 21, "u1"))
                .unwrap(),
            b"password-changed-in-gmacftp"
        );
        assert_eq!(
            store
                .get_for(&key(Protocol::Sftp, "sftp.example.com", 22, "u2"))
                .unwrap(),
            b"secret2"
        );
    }

    #[test]
    fn imports_real_sitemanager_xml_when_present() {
        // Exercises the actual FileZilla export (nested <Folder>, XML decl, attributes) when the
        // dev data file exists. Skips gracefully otherwise (no file in a clean checkout / CI).
        let Ok(xml) = std::fs::read_to_string("data/sitemanager.xml") else {
            return;
        };
        let store = InMemoryStore::default();
        let specs = load_filezilla(&xml, &store).unwrap();
        assert!(
            specs.len() > 1,
            "expected multiple servers, got {}",
            specs.len()
        );
        // every spec has a host + a protocol we support
        assert!(specs.iter().all(|s| !s.host.is_empty()));
        assert!(specs
            .iter()
            .all(|s| matches!(s.protocol, Protocol::Ftp | Protocol::Sftp)));
    }

    #[test]
    fn metadata_reader_rejects_oversized_files_and_symlinks() {
        let dir = std::env::temp_dir().join(format!(
            "gmacftp-connections-test-{}-{:016x}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let oversized = dir.join("oversized.json");
        let file = std::fs::File::create(&oversized).unwrap();
        file.set_len(MAX_IMPORT_BYTES as u64 + 1).unwrap();
        assert_eq!(
            read_regular_limited(&oversized, MAX_IMPORT_BYTES)
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::InvalidData
        );

        #[cfg(unix)]
        {
            let target = dir.join("target.json");
            std::fs::write(&target, b"[]").unwrap();
            let link = dir.join("connections.json");
            std::os::unix::fs::symlink(&target, &link).unwrap();
            assert_eq!(
                read_regular_limited(&link, MAX_IMPORT_BYTES)
                    .unwrap_err()
                    .kind(),
                std::io::ErrorKind::InvalidData
            );
        }
        let _ = std::fs::remove_dir_all(dir);
    }
}
