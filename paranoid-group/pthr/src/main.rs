use std::{env, fs, process};
use std::convert::TryInto;
use rand::{rngs::OsRng, RngCore};

use threefish::Threefish1024;
use threefish::cipher::{BlockEncrypt, BlockDecrypt}; // Required traits for block ops
use argon2::{Argon2, PasswordHasher};
use argon2::password_hash::SaltString;
use hmac::{Hmac, Mac}; // HMAC + trait for new_from_slice
use sha2::Sha512;

const BLOCK_SIZE: usize = 128;
const KEY_SIZE: usize = 128;
const TWEAK_SIZE: usize = 16;
const SALT_SIZE: usize = 16;

type HmacSha512 = Hmac<Sha512>;

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
    let mut data = fs::read(filename).expect("Failed to read input file");

    // Padding (PKCS#7-style)
    let pad_len = BLOCK_SIZE - (data.len() % BLOCK_SIZE);
    data.extend(vec![pad_len as u8; pad_len]);

    let mut salt = [0u8; SALT_SIZE];
    let mut tweak = [0u8; TWEAK_SIZE];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut tweak);

    let key = derive_key(password, &salt);
    let tweak_array: [u8; 16] = tweak.try_into().expect("Invalid tweak length");
    let cipher = Threefish1024::new_with_tweak(&key.into(), &tweak_array);

    let mut encrypted = Vec::with_capacity(data.len());
    let mut block = [0u8; BLOCK_SIZE];

    for chunk in data.chunks(BLOCK_SIZE) {
        block.copy_from_slice(chunk);
        cipher.encrypt_block(&mut block.into());
        encrypted.extend_from_slice(&block);
    }

    let mut mac = <HmacSha512 as Mac>::new_from_slice(&key[..64]).unwrap();
    mac.update(&encrypted);
    let tag = mac.finalize().into_bytes();

    let mut final_output = Vec::new();
    final_output.extend_from_slice(&salt);
    final_output.extend_from_slice(&tweak);
    final_output.extend_from_slice(&tag);
    final_output.extend_from_slice(&encrypted);

    let tmp_path = format!("{}.tmp", filename);
    fs::write(&tmp_path, &final_output).expect("Failed to write temp file");
    fs::rename(tmp_path, filename).expect("Failed to overwrite file");

    println!("Encrypted: {}", filename);
}

fn decrypt_file(filename: &str, password: &str) {
    let data = fs::read(filename).expect("Failed to read file");

    if data.len() < SALT_SIZE + TWEAK_SIZE + 64 {
        eprintln!("Invalid file format");
        process::exit(1);
    }

    let salt = &data[..SALT_SIZE];
    let tweak = &data[SALT_SIZE..SALT_SIZE + TWEAK_SIZE];
    let tag = &data[SALT_SIZE + TWEAK_SIZE..SALT_SIZE + TWEAK_SIZE + 64];
    let ciphertext = &data[SALT_SIZE + TWEAK_SIZE + 64..];

    let key = derive_key(password, salt);
    let mut mac = <HmacSha512 as Mac>::new_from_slice(&key[..64]).unwrap();
    mac.update(ciphertext);

    if mac.verify_slice(tag).is_err() {
        eprintln!("Authentication failed. Wrong password or corrupted file.");
        process::exit(1);
    }

    let tweak_array: [u8; 16] = tweak.try_into().expect("Invalid tweak length");
    let cipher = Threefish1024::new_with_tweak(&key.into(), &tweak_array);

    let mut decrypted = Vec::with_capacity(ciphertext.len());
    let mut block = [0u8; BLOCK_SIZE];

    for chunk in ciphertext.chunks(BLOCK_SIZE) {
        block.copy_from_slice(chunk);
        cipher.decrypt_block(&mut block.into());
        decrypted.extend_from_slice(&block);
    }

    let pad_len = *decrypted.last().unwrap_or(&0) as usize;
    if pad_len <= BLOCK_SIZE {
        decrypted.truncate(decrypted.len() - pad_len);
    }

    let tmp_path = format!("{}.tmp", filename);
    fs::write(&tmp_path, &decrypted).expect("Failed to write file");
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
