use std::{
    fs::File,
    io::{Read, Write, BufReader, BufWriter},
};

use anyhow::{Result, anyhow};
use argon2::Argon2;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce, Key,
};
use rpassword::read_password;
use rand::{RngCore, rng};
use zeroize::Zeroizing;

const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const HEADER_MAGIC: &[u8; 4] = b"PC01";
const CHUNK_SIZE: usize = 1024 * 1024;

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();

    if args.len() != 4 {
        eprintln!("Usage:\n  aipcrypt enc <input> <output>\n  aipcrypt dec <input> <output>");
        std::process::exit(1);
    }

    let cmd = args[1].as_str();
    let input = &args[2];
    let output = &args[3];

    match cmd {
        "enc" => encrypt_file(input, output),
        "dec" => decrypt_file(input, output),
        _ => {
            eprintln!("Unknown command: {}", cmd);
            std::process::exit(1);
        }
    }
}

fn encrypt_file(input: &str, output: &str) -> Result<()> {
    println!("🔐 Password:");
    let password = read_password()?.into_bytes();

    println!("🔁 Confirm Password:");
    let confirm = read_password()?.into_bytes();

    if password != confirm {
        return Err(anyhow!("❌ Passwords do not match."));
    }

    Zeroizing::new(confirm);

    let mut salt = [0u8; SALT_LEN];
    rng().fill_bytes(&mut salt);

    let argon2 = Argon2::default();
    let mut key_bytes = [0u8; 32];
    argon2
        .hash_password_into(&password, &salt, &mut key_bytes)
        .map_err(|e| anyhow!("KDF failed: {:?}", e))?;
    Zeroizing::new(password);

    let key = Key::from_slice(&key_bytes);
    let cipher = XChaCha20Poly1305::new(key);

    let mut nonce_bytes = [0u8; NONCE_LEN];
    rng().fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);

    let mut reader = BufReader::new(File::open(input)?);
    let mut writer = BufWriter::new(File::create(output)?);

    writer.write_all(HEADER_MAGIC)?;
    writer.write_all(&salt)?;
    writer.write_all(&nonce_bytes)?;

    let mut buffer = vec![0u8; CHUNK_SIZE];

    while let Ok(n) = reader.read(&mut buffer) {
        if n == 0 {
            break;
        }
        let chunk = &buffer[..n];
        let ciphertext = cipher.encrypt(nonce, chunk)
            .map_err(|e| anyhow!("Encryption failed: {:?}", e))?;
        writer.write_all(&(ciphertext.len() as u64).to_le_bytes())?;
        writer.write_all(&ciphertext)?;
    }

    writer.flush()?;
    println!("✅ Encrypted → {}", output);
    Ok(())
}

fn decrypt_file(input: &str, output: &str) -> Result<()> {
    let mut reader = BufReader::new(File::open(input)?);

    let mut magic = [0u8; 4];
    reader.read_exact(&mut magic)?;
    if &magic != HEADER_MAGIC {
        return Err(anyhow!("❌ Invalid file format."));
    }

    let mut salt = [0u8; SALT_LEN];
    reader.read_exact(&mut salt)?;

    let mut nonce_bytes = [0u8; NONCE_LEN];
    reader.read_exact(&mut nonce_bytes)?;
    let nonce = XNonce::from_slice(&nonce_bytes);

    println!("🔐 Password:");
    let password = read_password()?.into_bytes();
    let argon2 = Argon2::default();
    let mut key_bytes = [0u8; 32];
    argon2
        .hash_password_into(&password, &salt, &mut key_bytes)
        .map_err(|e| anyhow!("KDF failed: {:?}", e))?;
    Zeroizing::new(password);

    let key = Key::from_slice(&key_bytes);
    let cipher = XChaCha20Poly1305::new(key);

    let mut writer = BufWriter::new(File::create(output)?);

    loop {
        let mut len_buf = [0u8; 8];
        if reader.read_exact(&mut len_buf).is_err() {
            break; // EOF
        }

        let chunk_len = u64::from_le_bytes(len_buf) as usize;
        let mut ciphertext = vec![0u8; chunk_len];
        reader.read_exact(&mut ciphertext)?;

        let plaintext = cipher
            .decrypt(nonce, ciphertext.as_ref())
            .map_err(|e| anyhow!("Decryption failed or data was tampered: {:?}", e))?;
        writer.write_all(&plaintext)?;
    }

    writer.flush()?;
    println!("✅ Decrypted → {}", output);
    Ok(())
}
