use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    ChaCha20Poly1305, Nonce};
use argon2::Argon2;
use rand::RngCore;

pub fn generate_salt() -> [u8; 16] {
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    salt
}

pub fn derive_key(password: &str, salt: &[u8; 16]) -> [u8; 32] {
    let mut key = [0u8; 32];
    Argon2::default()
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .unwrap();
    key
}

pub fn encrypt(plaintext: &str, key: &[u8; 32]) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce  = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ciphertext = cipher.encrypt(&nonce, plaintext.as_bytes()).unwrap();

    let mut result = Vec::new();
    result.extend_from_slice(&nonce);
    result.extend_from_slice(&ciphertext);
    result
}

pub fn decrypt(data: &[u8], key: &[u8; 32]) -> Result<String, Box<dyn std::error::Error>> {
    let (nonce_bytes, ciphertext) = data.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);

    let cipher = ChaCha20Poly1305::new(key.into());
    let plaintext = cipher.decrypt(nonce, ciphertext)?;

    Ok(String::from_utf8(plaintext)?)
}