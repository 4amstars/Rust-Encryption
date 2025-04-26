use aes_gcm_siv::aead::{Aead, KeyInit, OsRng};
use aes_gcm_siv::{Aes256GcmSiv, Nonce}; // 96-bit (12 byte) nonce
use clap::{Parser, Subcommand};
use rand::RngCore;
use std::{fs, path::PathBuf};
use anyhow::{Context, Result};
use zeroize::Zeroize;

/// AES-256-GCM-SIV file encryption CLI
#[derive(Parser)]
#[command(name = "securefile")]
#[command(about = "AES-256-GCM-SIV File Encryptor", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Encrypt a file (in-place)
    Encrypt {
        /// File to encrypt
        file: PathBuf,
    },
    /// Decrypt a file (in-place)
    Decrypt {
        /// File to decrypt
        file: PathBuf,
    },
}

/// Reads a 32-byte key from key.key file in the same directory
fn read_key(path: &PathBuf) -> Result<[u8; 32]> {
    let key_data = fs::read(path).context("Failed to read key.key file")?;
    anyhow::ensure!(key_data.len() == 32, "Key must be exactly 32 bytes long");

    let mut key = [0u8; 32];
    key.copy_from_slice(&key_data);
    Ok(key)
}

/// Encrypts the file in-place
fn encrypt_file(file: &PathBuf, key: &[u8; 32]) -> Result<()> {
    let cipher = Aes256GcmSiv::new(key.into());

    let content = fs::read(file).context("Failed to read input file")?;

    // Generate a random nonce
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Encrypt content
    let ciphertext = cipher.encrypt(nonce, content.as_ref())
        .map_err(|_| anyhow::anyhow!("Encryption failed"))?;

    // Write: [nonce || ciphertext]
    let mut output = nonce_bytes.to_vec();
    output.extend_from_slice(&ciphertext);

    fs::write(file, &output).context("Failed to write encrypted file")?;
    Ok(())
}

/// Decrypts the file in-place
fn decrypt_file(file: &PathBuf, key: &[u8; 32]) -> Result<()> {
    let cipher = Aes256GcmSiv::new(key.into());

    let data = fs::read(file).context("Failed to read encrypted file")?;
    anyhow::ensure!(data.len() > 12, "Invalid file: too short to contain nonce");

    let (nonce_bytes, ciphertext) = data.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);

    let plaintext = cipher.decrypt(nonce, ciphertext)
        .map_err(|_| anyhow::anyhow!("Decryption failed"))?;

    fs::write(file, &plaintext).context("Failed to write decrypted file")?;
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    let key_path = PathBuf::from("key.key");
    let mut key = read_key(&key_path)?;

    let result = match cli.command {
        Commands::Encrypt { file } => encrypt_file(&file, &key),
        Commands::Decrypt { file } => decrypt_file(&file, &key),
    };

    // Zero key from memory after use
    key.zeroize();

    result
}
