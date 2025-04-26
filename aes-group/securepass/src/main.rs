use aes_gcm_siv::aead::{Aead, KeyInit, OsRng};
use aes_gcm_siv::{Aes256GcmSiv, Nonce}; // 96-bit (12 byte) nonce
use anyhow::{anyhow, Context, Result};
use argon2::Argon2;
use clap::{Parser, Subcommand};
use rand::RngCore;
use rpassword::prompt_password;
use std::{fs, path::PathBuf};
use zeroize::Zeroize;

/// AES-256-GCM-SIV file encryption CLI using password-derived key
#[derive(Parser)]
#[command(name = "securepass")]
#[command(about = "Password-Based File Encryptor", long_about = None)]
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

/// Derives a 256-bit key from a password and salt using Argon2id
fn derive_key(password: &str, salt: &[u8]) -> Result<[u8; 32]> {
    let mut key = [0u8; 32];
    Argon2::default()
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| anyhow!("Key derivation failed: {}", e))?;
    Ok(key)
}

/// Encrypts a file in-place using a password-derived key
fn encrypt_file(file: &PathBuf) -> Result<()> {
    // Prompt and confirm password
    let password1 = prompt_password("Enter password: ")?;
    let password2 = prompt_password("Confirm password: ")?;
    anyhow::ensure!(password1 == password2, "Passwords do not match");

    // Generate a random salt and nonce
    let mut salt = [0u8; 16];
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce_bytes);

    let key = derive_key(&password1, &salt)?;
    let cipher = Aes256GcmSiv::new(key.as_ref().into());

    let content = fs::read(file).context("Failed to read input file")?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, content.as_ref())
        .map_err(|_| anyhow!("Encryption failed"))?;

    // Format: [salt || nonce || ciphertext]
    let mut output = Vec::with_capacity(16 + 12 + ciphertext.len());
    output.extend_from_slice(&salt);
    output.extend_from_slice(&nonce_bytes);
    output.extend_from_slice(&ciphertext);

    fs::write(file, &output).context("Failed to write encrypted file")?;

    // Zero sensitive data
    let mut password1 = password1;
    let mut password2 = password2;
    password1.zeroize();
    password2.zeroize();

    Ok(())
}

/// Decrypts a file in-place using a password-derived key
fn decrypt_file(file: &PathBuf) -> Result<()> {
    let password = prompt_password("Enter password: ")?;

    let data = fs::read(file).context("Failed to read encrypted file")?;
    anyhow::ensure!(data.len() > 28, "Invalid file format");

    // Extract salt and nonce
    let (salt, rest) = data.split_at(16);
    let (nonce_bytes, ciphertext) = rest.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);

    let key = derive_key(&password, salt)?;
    let cipher = Aes256GcmSiv::new(key.as_ref().into());

    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| anyhow!("Decryption failed - incorrect password or corrupted file"))?;

    fs::write(file, &plaintext).context("Failed to write decrypted file")?;

    // Zero sensitive data
    let mut password = password;
    password.zeroize();

    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Encrypt { file } => encrypt_file(&file),
        Commands::Decrypt { file } => decrypt_file(&file),
    }
}
