//! Wire protocols gmacFTP speaks.
//!
//! Optional seed data labels every remote as either `"ftp"` or `"sftp"` — there is no
//! explicit `"ftps"` label. `Protocol::Ftp` negotiates explicit FTPS (AUTH TLS) first;
//! a refused upgrade is an error unless the user has deliberately enabled plaintext mode for
//! that exact legacy connection. Every connection is secure by default without dropping
//! compatibility for explicitly approved LAN/legacy servers.

use std::fmt;
use std::str::FromStr;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Ftp,
    Sftp,
}

impl Protocol {
    pub fn default_port(self) -> u16 {
        match self {
            Protocol::Ftp => 21,
            Protocol::Sftp => 22,
        }
    }
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Protocol::Ftp => "ftp",
            Protocol::Sftp => "sftp",
        })
    }
}

impl FromStr for Protocol {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.trim().to_ascii_lowercase().as_str() {
            "ftp" | "ftps" => Ok(Protocol::Ftp), // "ftps" -> secure-by-default FTP
            "sftp" | "ssh" => Ok(Protocol::Sftp),
            other => Err(format!("unknown protocol: {other:?}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_seed_protocols() {
        assert_eq!("ftp".parse::<Protocol>().unwrap(), Protocol::Ftp);
        assert_eq!("ftps".parse::<Protocol>().unwrap(), Protocol::Ftp);
        assert_eq!("SFTP".parse::<Protocol>().unwrap(), Protocol::Sftp);
        assert!("webdav".parse::<Protocol>().is_err());
    }

    #[test]
    fn roundtrips_serde() {
        let json = serde_json::to_string(&Protocol::Sftp).unwrap();
        assert_eq!(json, "\"sftp\"");
        let back: Protocol = serde_json::from_str(&json).unwrap();
        assert_eq!(back, Protocol::Sftp);
    }
}
