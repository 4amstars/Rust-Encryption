use aes_gcm_siv::{
    aead::{Aead, KeyInit, generic_array::GenericArray},
    Aes256GcmSiv, Nonce,
};
use argon2::{Argon2, PasswordHasher};
use argon2::password_hash::SaltString;
use rand_core::OsRng;
use rand::RngCore;
use std::{env, fs, process};

const NONCE_SIZE: usize = 12;
const SALT_SIZE: usize = 16;

fn derive_key(password: &str, salt: &[u8]) -> [u8; 32] {
    let argon2 = Argon2::default();
    let salt = SaltString::encode_b64(salt).expect("Failed to encode salt");

    let hash = argon2.hash_password(password.as_bytes(), &salt)
        .expect("Key derivation failed")
        .hash
        .expect("Hash missing");

    let hash_bytes = hash.as_bytes();
    let mut key = [0u8; 32];
    key.copy_from_slice(&hash_bytes[..32]);
    key
}

fn encrypt_file_atomic(filename: &str, password: &str) {
    let data = fs::read(filename).expect("Failed to read input file");

    let mut salt = [0u8; SALT_SIZE];
    let mut nonce_bytes = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce_bytes);

    let key = GenericArray::from(derive_key(password, &salt));
    let cipher = Aes256GcmSiv::new(&key);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher.encrypt(nonce, data.as_ref())
        .expect("Encryption failed");

    let mut result = Vec::new();
    result.extend_from_slice(&salt);        // 16 bytes
    result.extend_from_slice(&nonce_bytes); // 12 bytes
    result.extend_from_slice(&ciphertext);  // payload

    let temp_path = format!("{}.tmp", filename);
    fs::write(&temp_path, result).expect("Failed to write temporary file");
    fs::rename(temp_path, filename).expect("Failed to overwrite original file");

    println!("Encrypted (in-place): {}", filename);
}

fn decrypt_file_atomic(filename: &str, password: &str) {
    let data = fs::read(filename).expect("Failed to read encrypted file");

    if data.len() < SALT_SIZE + NONCE_SIZE {
        eprintln!("File too short to contain salt and nonce");
        process::exit(1);
    }

    let salt = &data[..SALT_SIZE];
    let nonce_bytes = &data[SALT_SIZE..SALT_SIZE + NONCE_SIZE];
    let ciphertext = &data[SALT_SIZE + NONCE_SIZE..];

    let key = GenericArray::from(derive_key(password, salt));
    let cipher = Aes256GcmSiv::new(&key);
    let nonce = Nonce::from_slice(nonce_bytes);

    let plaintext = cipher.decrypt(nonce, ciphertext)
        .expect("Decryption failed. Wrong password or corrupted file.");

    let temp_path = format!("{}.tmp", filename);
    fs::write(&temp_path, plaintext).expect("Failed to write temporary file");
    fs::rename(temp_path, filename).expect("Failed to overwrite original file");

    println!("Decrypted (in-place): {}", filename);
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() != 4 {
        eprintln!("Usage:\n  {} E|D <filename> <password>", args[0]);
        process::exit(1);
    }

    let command = args[1].to_uppercase();
    let filename = &args[2];
    let password = &args[3];

    match command.as_str() {
        "E" => encrypt_file_atomic(filename, password),
        "D" => decrypt_file_atomic(filename, password),
        _ => {
            eprintln!("Unknown command '{}'. Use E (encrypt) or D (decrypt).", command);
            process::exit(1);
        }
    }
}


