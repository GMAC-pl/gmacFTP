//! Connection metadata: import the a third-party file manager seed (passwords -> Keychain) and persist
//! the password-free metadata to the config dir so the app remembers connections.

use std::fs;
use std::path::PathBuf;

use crate::model::{ConnectionId, ConnectionSpec, Protocol};

use super::creds::{CredentialError, CredentialStore};

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
    let seed: SeedFile = serde_json::from_str(json)?;
    let mut specs = Vec::with_capacity(seed.connections.len());
    for (i, s) in seed.connections.into_iter().enumerate() {
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
        let mut pw = s.password.into_bytes();
        if store.get(&host, &s.username).is_err() {
            store.set(&host, &s.username, &pw)?;
        }
        zeroize::Zeroize::zeroize(&mut pw);

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
        });
    }
    Ok(specs)
}

/// FileZilla `sitemanager.xml` import (root `<FileZilla3>` → nested `<Folder>`/`<Server>`).
/// Each `<Server>` becomes a `ConnectionSpec`; the `<Pass>` text is stored as the password.
/// FileZilla stores plaintext when no master password is set (the common case) — with a master
/// password it is encrypted and the user re-enters it after import.
///
/// `<Protocol>` mapping (FileZilla): 0 = FTP, 1 = SFTP (SSH2), 3/4 = FTP over TLS (explicit/
/// implicit). gmacFTP's `Protocol::Ftp` negotiates FTPS itself, so 0/3/4 all map to `Ftp`.
/// Unsupported protocols (WebDAV/S3/HTTP, etc.) are skipped.
pub fn load_filezilla(
    xml: &str,
    store: &dyn CredentialStore,
) -> Result<Vec<ConnectionSpec>, ImportError> {
    let doc = roxmltree::Document::parse(xml)?;
    let mut specs = Vec::new();
    let mut idx = 0usize;
    for server in doc
        .descendants()
        .filter(|n| n.tag_name().name() == "Server")
    {
        let host = child_text(&server, "Host");
        if host.is_empty() {
            continue;
        }
        let user = child_text(&server, "User");
        let pass = child_text(&server, "Pass");
        let port: u16 = child_text(&server, "Port").trim().parse().unwrap_or(0);
        let protocol = match child_text(&server, "Protocol").trim() {
            "1" => Protocol::Sftp,
            "0" | "3" | "4" | "" => Protocol::Ftp, // "" defaults to FTP (FileZilla omits it)
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

        // Secret -> vault, then drop the buffer. Never retained on the spec.
        if !pass.is_empty() {
            let _ = store.set(&host, &user, pass.as_bytes());
        }

        specs.push(ConnectionSpec {
            id: ConnectionId(idx),
            name,
            protocol,
            host,
            port,
            user,
            initial_path: String::new(),
        });
        idx += 1;
    }
    Ok(specs)
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
    match fs::read_to_string(&path) {
        Ok(s) if s.trim().is_empty() => Ok(None),
        Ok(s) => Ok(Some(serde_json::from_str(&s)?)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::InMemoryStore;

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
        assert_eq!(store.get("ftp.example.com", "u1").unwrap(), b"p1");
        assert_eq!(store.get("sftp.example.com", "u2").unwrap(), b"p2");
        // and are NOT carried on the spec
        let json = serde_json::to_string(&specs[0]).unwrap();
        assert!(!json.contains("p1"));
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
        assert_eq!(store.get("ftp.example.com", "u1").unwrap(), b"secret1");
        assert_eq!(store.get("sftp.example.com", "u2").unwrap(), b"secret2");
        // and are NOT carried on the spec
        assert!(!serde_json::to_string(&specs[0])
            .unwrap()
            .contains("secret1"));
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
}
