use std::{
    fs::{self, File},
    io::{Read, Write, BufReader, BufWriter},
};

use anyhow::{Result, anyhow};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    XChaCha20Poly1305, XNonce, Key,
};
use rand::{RngCore, rng};

const NONCE_LEN: usize = 24;
const HEADER_MAGIC: &[u8; 4] = b"KC01";
const KEY_FILE: &str = "key.key";
const CHUNK_SIZE: usize = 1024 * 1024;

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();

    if args.len() != 4 {
        eprintln!("Usage:\n  aicrypt enc <input> <output>\n  aicrypt dec <input> <output>");
        std::process::exit(1);
    }

    // Check for keyfile up front
    let key_bytes = fs::read(KEY_FILE)
        .map_err(|_| anyhow!("🚫 Missing or unreadable key file: {}", KEY_FILE))?;
    if key_bytes.len() != 32 {
        return Err(anyhow!("🚫 Key file must be exactly 32 bytes"));
    }

    let cmd = args[1].as_str();
    let input = &args[2];
    let output = &args[3];

    match cmd {
        "enc" => encrypt_file(input, output, &key_bytes),
        "dec" => decrypt_file(input, output, &key_bytes),
        _ => {
            eprintln!("Unknown command: {}", cmd);
            std::process::exit(1);
        }
    }
}

fn encrypt_file(input: &str, output: &str, key_bytes: &[u8]) -> Result<()> {
    let key = Key::from_slice(key_bytes);
    let cipher = XChaCha20Poly1305::new(key);

    let mut nonce_bytes = [0u8; NONCE_LEN];
    rng().fill_bytes(&mut nonce_bytes);
    let nonce = XNonce::from_slice(&nonce_bytes);

    let mut reader = BufReader::new(File::open(input)?);
    let mut writer = BufWriter::new(File::create(output)?);

    writer.write_all(HEADER_MAGIC)?;
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

fn decrypt_file(input: &str, output: &str, key_bytes: &[u8]) -> Result<()> {
    let mut reader = BufReader::new(File::open(input)?);

    let mut magic = [0u8; 4];
    reader.read_exact(&mut magic)?;
    if &magic != HEADER_MAGIC {
        return Err(anyhow!("❌ Invalid file format."));
    }

    let mut nonce_bytes = [0u8; NONCE_LEN];
    reader.read_exact(&mut nonce_bytes)?;
    let nonce = XNonce::from_slice(&nonce_bytes);

    let key = Key::from_slice(key_bytes);
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
