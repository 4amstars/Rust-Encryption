use aes_gcm_siv::{
    Aes256GcmSiv,
    aead::{Aead, KeyInit, OsRng, rand_core::RngCore, generic_array::GenericArray}
};
use anyhow::{Result, Context};
use std::{fs, process::exit, io::Write, path::Path};
use tempfile::NamedTempFile;

const NONCE_LEN: usize = 12;
const KEY_FILE: &str = "key.key";
// Magic header to detect encrypted files
const HEADER: &[u8] = b"AESGCM-SIVv1";

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 2 {
        eprintln!("Usage: {} <file>", args[0]);
        exit(1);
    }
    let path = Path::new(&args[1]);

    // load key
    let key_bytes = fs::read(KEY_FILE)
        .context("Failed to read key.key file")?;
    if key_bytes.len() != 32 {
        anyhow::bail!("Key file must be exactly 32 bytes (256-bit)");
    }
    let key = GenericArray::from_slice(&key_bytes);
    let cipher = Aes256GcmSiv::new(key);

    // read entire file
    let data = fs::read(path)
        .with_context(|| format!("Failed to read '{}'", path.display()))?;
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let mut tmp = NamedTempFile::new_in(dir)
        .context("Failed to create temp file")?;

    if data.starts_with(HEADER) {
        // --- DECRYPT ---
        let rest = &data[HEADER.len()..];
        if rest.len() < NONCE_LEN {
            anyhow::bail!("Encrypted file is too short");
        }
        let (nonce_bytes, ciphertext) = rest.split_at(NONCE_LEN);
        let nonce = GenericArray::from_slice(nonce_bytes);
        let plaintext = cipher.decrypt(nonce, ciphertext)
            .map_err(|e| anyhow::anyhow!("Decryption failed: {:?}", e))?;
        tmp.write_all(&plaintext)?;
        tmp.persist(path)
            .with_context(|| format!("Failed to overwrite '{}'", path.display()))?;
        println!("✅ Decrypted in place → {}", path.display());
    } else {
        // --- ENCRYPT ---
        let plaintext = data;
        let mut nonce_bytes = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = GenericArray::from_slice(&nonce_bytes);
        let ciphertext = cipher.encrypt(nonce, plaintext.as_ref())
            .map_err(|e| anyhow::anyhow!("Encryption failed: {:?}", e))?;
        tmp.write_all(HEADER)?;
        tmp.write_all(&nonce_bytes)?;
        tmp.write_all(&ciphertext)?;
        tmp.persist(path)
            .with_context(|| format!("Failed to overwrite '{}'", path.display()))?;
        println!("✅ Encrypted in place → {}", path.display());
    }

    Ok(())
}
