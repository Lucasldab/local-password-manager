use anyhow::{anyhow, Result};
use argon2::{Argon2 as Argon2Hasher, Params, Version};
use chacha20poly1305::{aead::Aead, KeyInit, XChaCha20Poly1305, XNonce};
use rand::rngs::OsRng;
use rand::RngCore;
// no DB types needed here currently

pub const KEY_LENGTH: usize = 32; // 256-bit key
pub const AEAD_ALGORITHM: &str = "xchacha20poly1305";

/// Generate a cryptographically-secure random salt with the given length
pub fn generate_salt(num_bytes: usize) -> Vec<u8> {
    let mut salt = vec![0u8; num_bytes];
    OsRng.fill_bytes(&mut salt);
    salt
}

/// Derives an AEAD key from a passphrase using Argon2id
pub fn derive_key(
    passphrase: &str,
    salt: &[u8],
    iterations: u32,
    memory_kib: u32,
    parallelism: u32,
) -> Result<[u8; KEY_LENGTH]> {
    let params = Params::new(memory_kib, iterations, parallelism, Some(KEY_LENGTH))
        .map_err(|e| anyhow!("Invalid Argon2 parameters: {e}"))?;

    let argon2 = Argon2Hasher::new(argon2::Algorithm::Argon2id, Version::V0x13, params);

    let mut output = [0u8; KEY_LENGTH];
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, &mut output)
        .map_err(|e| anyhow!("Failed to derive raw key bytes: {e}"))?;

    Ok(output)
}

/// Encrypt plaintext password bytes with XChaCha20-Poly1305.
/// Returns (ciphertext, nonce)
pub fn encrypt_password(key: &[u8; KEY_LENGTH], plaintext: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    let cipher = XChaCha20Poly1305::new(key.as_slice().into());
    let mut nonce_bytes = vec![0u8; 24];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| anyhow!("AEAD encryption failed: {e}"))?;
    Ok((ciphertext, nonce_bytes))
}

/// Decrypt ciphertext with XChaCha20-Poly1305.
pub fn decrypt_password(
    key: &[u8; KEY_LENGTH],
    nonce: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(key.as_slice().into());
    let nonce = XNonce::from_slice(nonce);
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| anyhow!("AEAD decryption failed: {e}"))?;
    Ok(plaintext)
}

