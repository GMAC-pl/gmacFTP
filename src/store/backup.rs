//! Passphrase-encrypted settings export format.
//!
//! The format is intentionally independent from the credential vault: settings backups never
//! contain passwords or vault keys, and importing one cannot replace or unlock credentials.

use aes_gcm::{
    aead::{consts::U12, Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use rand::RngCore;
use zeroize::Zeroizing;

const MAGIC: &[u8; 8] = b"GMFTPSET";
const VERSION: u8 = 1;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const MEMORY_KIB: u32 = 19 * 1024;
const TIME_COST: u32 = 2;
const PARALLELISM: u32 = 1;
const HEADER_LEN: usize = MAGIC.len() + 1 + 4 + 4 + 4 + SALT_LEN;
const PREFIX_LEN: usize = HEADER_LEN + NONCE_LEN;
pub const MAX_PLAINTEXT_BYTES: usize = 2 * 1024 * 1024;
pub const MAX_BACKUP_BYTES: usize = MAX_PLAINTEXT_BYTES + PREFIX_LEN + 16;

fn derive_key(
    passphrase: &str,
    salt: &[u8],
    memory_kib: u32,
    time_cost: u32,
    parallelism: u32,
) -> Result<[u8; 32], String> {
    if salt.len() != SALT_LEN
        || !(8 * 1024..=256 * 1024).contains(&memory_kib)
        || !(1..=10).contains(&time_cost)
        || !(1..=8).contains(&parallelism)
    {
        return Err("invalid settings-backup KDF parameters".into());
    }
    let params = argon2::Params::new(memory_kib, time_cost, parallelism, Some(32))
        .map_err(|error| error.to_string())?;
    let argon2 = argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);
    let mut key = [0_u8; 32];
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|error| error.to_string())?;
    Ok(key)
}

/// Encrypt a bounded serialized Settings document with Argon2id + AES-256-GCM. The complete
/// version/KDF/salt header is authenticated as AAD, so parameter tampering fails closed.
pub fn encrypt(plaintext: &[u8], passphrase: &str) -> Result<Vec<u8>, String> {
    if plaintext.len() > MAX_PLAINTEXT_BYTES {
        return Err("settings backup plaintext exceeds its size limit".into());
    }
    let mut salt = [0_u8; SALT_LEN];
    let mut nonce_bytes = [0_u8; NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut salt);
    rand::rngs::OsRng.fill_bytes(&mut nonce_bytes);

    let mut header = Vec::with_capacity(HEADER_LEN);
    header.extend_from_slice(MAGIC);
    header.push(VERSION);
    header.extend_from_slice(&MEMORY_KIB.to_be_bytes());
    header.extend_from_slice(&TIME_COST.to_be_bytes());
    header.extend_from_slice(&PARALLELISM.to_be_bytes());
    header.extend_from_slice(&salt);
    debug_assert_eq!(header.len(), HEADER_LEN);

    let key = Zeroizing::new(derive_key(
        passphrase,
        &salt,
        MEMORY_KIB,
        TIME_COST,
        PARALLELISM,
    )?);
    let cipher = Aes256Gcm::new_from_slice(&key[..]).map_err(|error| error.to_string())?;
    let nonce = Nonce::<U12>::try_from(nonce_bytes.as_slice())
        .expect("a 12-byte AES-GCM nonce must convert");
    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad: &header,
            },
        )
        .map_err(|_| "could not encrypt settings backup".to_string())?;
    let mut output = header;
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

pub fn decrypt(blob: &[u8], passphrase: &str) -> Result<Zeroizing<Vec<u8>>, String> {
    if blob.len() < PREFIX_LEN + 16 || blob.len() > MAX_BACKUP_BYTES {
        return Err("encrypted settings backup has an invalid size".into());
    }
    if &blob[..MAGIC.len()] != MAGIC || blob[MAGIC.len()] != VERSION {
        return Err("unsupported encrypted settings backup format".into());
    }
    let mut cursor = MAGIC.len() + 1;
    let read_u32 = |bytes: &[u8], offset: &mut usize| -> Result<u32, String> {
        let end = offset.saturating_add(4);
        let value = bytes
            .get(*offset..end)
            .and_then(|bytes| bytes.try_into().ok())
            .map(u32::from_be_bytes)
            .ok_or_else(|| "truncated settings-backup header".to_string())?;
        *offset = end;
        Ok(value)
    };
    let memory_kib = read_u32(blob, &mut cursor)?;
    let time_cost = read_u32(blob, &mut cursor)?;
    let parallelism = read_u32(blob, &mut cursor)?;
    let salt_end = cursor.saturating_add(SALT_LEN);
    let salt = blob
        .get(cursor..salt_end)
        .ok_or_else(|| "truncated settings-backup salt".to_string())?;
    cursor = salt_end;
    debug_assert_eq!(cursor, HEADER_LEN);
    let nonce_end = cursor.saturating_add(NONCE_LEN);
    let nonce_bytes = blob
        .get(cursor..nonce_end)
        .ok_or_else(|| "truncated settings-backup nonce".to_string())?;
    let ciphertext = blob
        .get(nonce_end..)
        .ok_or_else(|| "truncated settings-backup ciphertext".to_string())?;

    let key = Zeroizing::new(derive_key(
        passphrase,
        salt,
        memory_kib,
        time_cost,
        parallelism,
    )?);
    let cipher = Aes256Gcm::new_from_slice(&key[..]).map_err(|error| error.to_string())?;
    let nonce = Nonce::<U12>::try_from(nonce_bytes)
        .map_err(|_| "invalid settings-backup nonce".to_string())?;
    let plaintext = cipher
        .decrypt(
            &nonce,
            Payload {
                msg: ciphertext,
                aad: &blob[..HEADER_LEN],
            },
        )
        .map_err(|_| "wrong passphrase or damaged settings backup".to_string())?;
    if plaintext.len() > MAX_PLAINTEXT_BYTES {
        return Err("decrypted settings backup exceeds its size limit".into());
    }
    Ok(Zeroizing::new(plaintext))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypted_settings_round_trip_and_tampering_fail_closed() {
        let plaintext = br#"{"format":"gmacftp-settings","version":1}"#;
        let encrypted = encrypt(plaintext, "correct horse battery staple").unwrap();
        assert!(!encrypted
            .windows(plaintext.len())
            .any(|window| window == plaintext));
        assert_eq!(
            &*decrypt(&encrypted, "correct horse battery staple").unwrap(),
            plaintext
        );
        assert!(decrypt(&encrypted, "wrong passphrase").is_err());

        let mut damaged_header = encrypted.clone();
        damaged_header[10] ^= 1;
        assert!(decrypt(&damaged_header, "correct horse battery staple").is_err());
        let mut damaged_ciphertext = encrypted;
        *damaged_ciphertext.last_mut().unwrap() ^= 1;
        assert!(decrypt(&damaged_ciphertext, "correct horse battery staple").is_err());
    }

    #[test]
    fn encrypted_settings_are_strictly_bounded() {
        assert!(encrypt(
            &vec![0_u8; MAX_PLAINTEXT_BYTES + 1],
            "correct horse battery staple"
        )
        .is_err());
        assert!(decrypt(&vec![0_u8; MAX_BACKUP_BYTES + 1], "anything").is_err());
    }
}
