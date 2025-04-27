// src/encrypt.rs
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;
use getrandom::getrandom;

use crate::args::CodecType;

const PBKDF2_ITERATIONS: u32 = 100_000;
const SALT: &[u8] = b"fs-encrypt-salt";

pub struct Cipher {
    cipher: Aes256Gcm,
}

impl Cipher {
    pub fn new(password: &str) -> Self {
        // Derive a 256-bit key from the password
        let mut key_bytes = [0u8; 32];
        pbkdf2_hmac::<Sha256>(
            password.as_bytes(),
            SALT,
            PBKDF2_ITERATIONS,
            &mut key_bytes,
        );
        // AES-256-GCM key
        let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
        let cipher = Aes256Gcm::new(key);
        Cipher { cipher }
    }

    pub fn apply_codec(&self, data: Vec<u8>, mode: &CodecType) -> Vec<u8> {
        match mode {
            CodecType::Encrypt => {
                // Generate a random 96-bit nonce
                let mut nonce_bytes = [0u8; 12];
                getrandom(&mut nonce_bytes).expect("random failure");
                let nonce = Nonce::from_slice(&nonce_bytes);
                // Encrypt and prepend nonce
                let ciphertext = self.cipher.encrypt(nonce, data.as_ref())
                    .expect("encryption failure");
                [nonce_bytes.to_vec(), ciphertext].concat()
            }
            CodecType::Decrypt => {
                // Split nonce and ciphertext
                let (nonce_bytes, ciphertext) = data.split_at(12);
                let nonce = Nonce::from_slice(nonce_bytes);
                self.cipher.decrypt(nonce, ciphertext)
                    .expect("decryption failure")
            }
        }
    }
}
