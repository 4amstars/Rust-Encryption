use std::{env, fs, process};
use rand::{rngs::OsRng, RngCore};


use aead::{Aead, KeyInit, generic_array::GenericArray};
use eax::Eax;
use camellia::Camellia256;
use argon2::{Argon2, PasswordHasher};
use argon2::password_hash::SaltString;

const KEY_SIZE: usize = 32;
const NONCE_SIZE: usize = 16;
const SALT_SIZE: usize = 16;

type CamelliaEax = Eax<Camellia256>;

fn derive_key(password: &str, salt: &[u8]) -> [u8; KEY_SIZE] {
    let argon2 = Argon2::default();
    let salt = SaltString::encode_b64(salt).unwrap();
    let hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .unwrap()
        .hash
        .unwrap();
    let mut key = [0u8; KEY_SIZE];
    key.copy_from_slice(&hash.as_bytes()[..KEY_SIZE]);
    key
}

fn encrypt_file(filename: &str, password: &str) {
    let data = fs::read(filename).expect("Failed to read input file");

    let mut salt = [0u8; SALT_SIZE];
    let mut nonce = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce);

    let key = derive_key(password, &salt);
    let cipher = CamelliaEax::new(GenericArray::from_slice(&key));
    let ciphertext = cipher.encrypt(GenericArray::from_slice(&nonce), data.as_ref())
        .expect("Encryption failed");

    let mut final_output = Vec::new();
    final_output.extend_from_slice(&salt);
    final_output.extend_from_slice(&nonce);
    final_output.extend_from_slice(&ciphertext);

    let tmp_path = format!("{}.tmp", filename);
    fs::write(&tmp_path, &final_output).expect("Failed to write temp file");
    fs::rename(tmp_path, filename).expect("Failed to overwrite original file");

    println!("Encrypted: {}", filename);
}

fn decrypt_file(filename: &str, password: &str) {
    let data = fs::read(filename).expect("Failed to read file");

    if data.len() < SALT_SIZE + NONCE_SIZE {
        eprintln!("Invalid file format");
        process::exit(1);
    }

    let salt = &data[..SALT_SIZE];
    let nonce = &data[SALT_SIZE..SALT_SIZE + NONCE_SIZE];
    let ciphertext = &data[SALT_SIZE + NONCE_SIZE..];

    let key = derive_key(password, salt);
    let cipher = CamelliaEax::new(GenericArray::from_slice(&key));
    let plaintext = cipher.decrypt(GenericArray::from_slice(nonce), ciphertext)
        .expect("Decryption failed: wrong password or corrupted file");

    let tmp_path = format!("{}.tmp", filename);
    fs::write(&tmp_path, &plaintext).expect("Failed to write file");
    fs::rename(tmp_path, filename).expect("Failed to overwrite file");

    println!("Decrypted: {}", filename);
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() != 4 {
        eprintln!("Usage:\n  {} E|D <filename> <password>", args[0]);
        process::exit(1);
    }

    let cmd = args[1].to_uppercase();
    let file = &args[2];
    let pass = &args[3];

    match cmd.as_str() {
        "E" => encrypt_file(file, pass),
        "D" => decrypt_file(file, pass),
        _ => {
            eprintln!("Unknown command '{}'. Use E (encrypt) or D (decrypt)", cmd);
            process::exit(1);
        }
    }
}
