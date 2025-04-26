use eax::{Eax, aead::{Aead, KeyInit, generic_array::GenericArray}};
use serpent::Serpent;
use argon2::{Argon2, PasswordHasher};
use argon2::password_hash::SaltString;
use rand_core::OsRng;
use rand::RngCore;
use std::{env, fs, process};

const SALT_SIZE: usize = 16;
const NONCE_SIZE: usize = 16;

/// Derives a 256-bit key using Argon2 and a salt
fn derive_key(password: &str, salt: &[u8]) -> [u8; 32] {
    let argon2 = Argon2::default();
    let salt = SaltString::encode_b64(salt).expect("Salt encoding failed");

    let hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .expect("Argon2 failed")
        .hash
        .expect("Hash missing");

    let hash_bytes = hash.as_bytes();
    let mut key = [0u8; 32];
    key.copy_from_slice(&hash_bytes[..32]);
    key
}

fn encrypt_file(filename: &str, password: &str) {
    let data = fs::read(filename).expect("Failed to read file");

    let mut salt = [0u8; SALT_SIZE];
    let mut nonce = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce);

    let key = derive_key(password, &salt);
    let cipher = Eax::<Serpent>::new(GenericArray::from_slice(&key));
    let ciphertext = cipher.encrypt(GenericArray::from_slice(&nonce), data.as_ref())
        .expect("Encryption failed");

    let mut output = Vec::new();
    output.extend_from_slice(&salt);
    output.extend_from_slice(&nonce);
    output.extend_from_slice(&ciphertext);

    let tmp_path = format!("{}.tmp", filename);
    fs::write(&tmp_path, &output).expect("Failed to write temporary file");
    fs::rename(tmp_path, filename).expect("Failed to replace original file");

    println!("Encrypted (in-place): {}", filename);
}

fn decrypt_file(filename: &str, password: &str) {
    let data = fs::read(filename).expect("Failed to read file");

    if data.len() < SALT_SIZE + NONCE_SIZE {
        eprintln!("File too short");
        process::exit(1);
    }

    let salt = &data[..SALT_SIZE];
    let nonce = &data[SALT_SIZE..SALT_SIZE + NONCE_SIZE];
    let ciphertext = &data[SALT_SIZE + NONCE_SIZE..];

    let key = derive_key(password, salt);
    let cipher = Eax::<Serpent>::new(GenericArray::from_slice(&key));
    let plaintext = cipher.decrypt(GenericArray::from_slice(nonce), ciphertext)
        .expect("Decryption failed: wrong password or corrupted file");

    let tmp_path = format!("{}.tmp", filename);
    fs::write(&tmp_path, &plaintext).expect("Failed to write temporary file");
    fs::rename(tmp_path, filename).expect("Failed to replace original file");

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
        "E" => encrypt_file(filename, password),
        "D" => decrypt_file(filename, password),
        _ => {
            eprintln!("Unknown command '{}'. Use E (encrypt) or D (decrypt).", command);
            process::exit(1);
        }
    }
}
